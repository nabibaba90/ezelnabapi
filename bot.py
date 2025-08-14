# bot.py
"""
Güncel korumalı proxy sunucusu (apiler eklendi, input validation ve DDoS/IP reputation kontrolü var).

Ortam değişkenleri önerisi:
export ADMIN_TOKEN="çok-gizli-token"
export ABUSEIPDB_KEY="..."
export IPQS_KEY="..."
export RATE_LIMIT_STORAGE="redis://localhost:6379"  # veya memory://
export BLOCK_THRESHOLD_ABUSE="50"
export PORT=5000
"""

import os
import time
import json
import re
import html
from functools import wraps
from flask import Flask, request, Response, jsonify
import requests
from tabulate import tabulate  # pip install tabulate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Optional Redis client
try:
    import redis
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

app = Flask(__name__)

# ---------------- CONFIG (ENV üzerinden ayarla production'da) ----------------
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")   # AbuseIPDB API key (opsiyonel)
IPQS_KEY = os.environ.get("IPQS_KEY", "")             # IPQualityScore key (opsiyonel)
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")       # admin endpointler için token (zorunlu yap)
BLOCK_THRESHOLD_ABUSE = int(os.environ.get("BLOCK_THRESHOLD_ABUSE", "50"))
RATE_LIMIT_STORAGE = os.environ.get("RATE_LIMIT_STORAGE", "memory://")  # veya redis://...
CACHE_TTL = int(os.environ.get("CACHE_TTL", 300))  # IP reputation cache (saniye)
MAX_PARAM_LENGTH = int(os.environ.get("MAX_PARAM_LENGTH", 200))

# ---------------- Redis setup (opsiyonel) ----------------
redis_client = None
if REDIS_AVAILABLE and RATE_LIMIT_STORAGE.startswith("redis://"):
    try:
        redis_url = RATE_LIMIT_STORAGE
        redis_client = redis.from_url(redis_url, decode_responses=True)
    except Exception as exc:
        redis_client = None
        print("Redis bağlantısı kurulamadı, fallback in-memory kullanılıyor:", exc)
else:
    redis_client = None

# ---------------- RATE LIMITER ----------------
# Yeni Flask-Limiter kullanım: önce Limiter oluştur, sonra init_app(app)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"],   # genel fallback limit
    storage_uri=RATE_LIMIT_STORAGE
)
limiter.init_app(app)

# ---------------- In-memory fallback structures ----------------
IP_BLOCKLIST_MEM = {}   # ip -> unblock_timestamp (0 = permanent)
IP_CHECK_CACHE_MEM = {} # ip -> (is_bad, expires_ts)

# ---------------- API sözlüğü (kullanıcının sağladığı tam dict) ----------------
apis = {
    "tc_sorgulama": {
        "desc": "TC Sorgulama",
        "url": "https://api.kahin.org/kahinapi/tc",
        "params": ["tc"]
    },
    "tc_pro_sorgulama": {
        "desc": "TC PRO Sorgulama",
        "url": "https://api.kahin.org/kahinapi/tcpro",
        "params": ["tc"]
    },
    "hayat_hikayesi": {
        "desc": "Hayat Hikayesi Sorgulama",
        "url": "https://api.kahin.org/kahinapi/hayathikayesi.php",
        "params": ["tc"]
    },
    "ad_soyad": {
        "desc": "Ad Soyad Sorgulama",
        "url": "https://api.kahin.org/kahinapi/adsoyad",
        "params": ["ad", "soyad", "il", "ilce"]
    },
    "ad_soyad_pro": {
        "desc": "Ad Soyad PRO Sorgulama",
        "url": "https://api.kahin.org/kahinapi/tapu",
        "params": ["tc"]
    },
    "is_yeri": {
        "desc": "İş Yeri Sorgulama",
        "url": "https://api.kahin.org/kahinapi/isyeri",
        "params": ["tc"]
    },
    "vergi_no": {
        "desc": "Vergi No Sorgulama",
        "url": "https://api.kahin.org/kahinapi/vergino",
        "params": ["vergi"]
    },
    "yas": {
        "desc": "Yaş Sorgulama",
        "url": "https://api.kahin.org/kahinapi/yas",
        "params": ["tc"]
    },
    "tc_gsm": {
        "desc": "TC GSM Sorgulama",
        "url": "https://api.kahin.org/kahinapi/tcgsm",
        "params": ["tc"]
    },
    "gsm_tc": {
        "desc": "GSM TC Sorgulama",
        "url": "https://api.kahin.org/kahinapi/gsmtc",
        "params": ["gsm"]
    },
    "adres": {
        "desc": "Adres Sorgulama",
        "url": "https://api.kahin.org/kahinapi/adres.php",
        "params": ["tc"]
    },
    "hane": {
        "desc": "Hane Sorgulama",
        "url": "https://api.kahin.org/kahinapi/hane",
        "params": ["tc"]
    },
    "apartman": {
        "desc": "Apartman Sorgulama",
        "url": "https://api.kahin.org/kahinapi/apartman",
        "params": ["tc"]
    },
    "ada_parsel": {
        "desc": "Ada Parsel Sorgulama",
        "url": "https://api.kahin.org/kahinapi/adaparsel",
        "params": ["il", "ada", "parsel"]
    },
    "adi_il_ilce": {
        "desc": "Adı İl İlçe Sorgulama",
        "url": "https://api.kahin.org/kahinapi/adililce.php",
        "params": ["ad", "il"]
    },
    "aile": {
        "desc": "Aile Sorgulama",
        "url": "https://api.kahin.org/kahinapi/aile",
        "params": ["tc"]
    },
    "aile_pro": {
        "desc": "Aile PRO Sorgulama",
        "url": "https://api.kahin.org/kahinapi/ailepro",
        "params": ["tc"]
    },
    "es": {
        "desc": "Eş Sorgulama",
        "url": "https://api.kahin.org/kahinapi/es",
        "params": ["tc"]
    },
    "sulale": {
        "desc": "Sulale Sorgulama",
        "url": "https://api.kahin.org/kahinapi/sulale",
        "params": ["tc"]
    },
    "lgs": {
        "desc": "LGS Sorgulama",
        "url": "https://api.kahin.org/kahinapi/lgs",
        "params": ["tc"]
    },
    "e_kurs": {
        "desc": "E-Kurs Sorgulama",
        "url": "https://api.kahin.org/kahinapi/ekurs",
        "params": ["tc", "okulno"]
    },
    "ip": {
        "desc": "IP Sorgulama",
        "url": "https://api.kahin.org/kahinapi/ip",
        "params": ["domain"]
    },
    "dns": {
        "desc": "DNS Sorgulama",
        "url": "https://api.kahin.org/kahinapi/dns",
        "params": ["domain"]
    },
    "whois": {
        "desc": "Whois Sorgulama",
        "url": "https://api.kahin.org/kahinapi/whois",
        "params": ["domain"]
    },
    "subdomain": {
        "desc": "Subdomain Sorgulama",
        "url": "https://api.kahin.org/kahinapi/subdomain.php",
        "params": ["url"]
    },
    "leak": {
        "desc": "Leak Sorgulama",
        "url": "https://api.kahin.org/kahinapi/leak.php",
        "params": ["query"]
    },
    "telegram": {
        "desc": "Telegram Sorgulama",
        "url": "https://api.kahin.org/kahinapi/telegram.php",
        "params": ["kullanici"]
    },
    "sifre_encrypt": {
        "desc": "Şifre Encrypt",
        "url": "https://api.kahin.org/kahinapi/encrypt",
        "params": ["method", "password"]
    },
    "prem_ad": {
        "desc": "Prem Ad Sorgulama",
        "url": "https://api.hexnox.pro/sowixapi/premad.php",
        "params": ["ad", "il", "ilce"]
    },
    "mhrs_randevu": {
        "desc": "MHRS Randevu Sorgulama",
        "url": "https://hexnox.pro/sowixfree/mhrs/mhrs.php",
        "params": ["tc"]
    },
    "prem_adres": {
        "desc": "Prem Adres Sorgulama",
        "url": "https://hexnox.pro/sowixfree/premadres.php",
        "params": ["tc"]
    },
    "sgk_pro": {
        "desc": "SGK PRO Sorgulama",
        "url": "https://api.hexnox.pro/sowixapi/sgkpro.php",
        "params": ["tc"]
    },
    "vergi_levhasi": {
        "desc": "Vergi Levhası Sorgulama",
        "url": "https://hexnox.pro/sowixfree/vergi/vergi.php",
        "params": ["tc"]
    },
    "facebook": {
        "desc": "Facebook Sorgulama",
        "url": "https://hexnox.pro/sowixfree/facebook.php",
        "params": ["numara"]
    },
    "diploma": {
        "desc": "Diploma Sorgulama",
        "url": "https://hexnox.pro/sowixfree/diploma/diploma.php",
        "params": ["tc"]
    },
    "basvuru": {
        "desc": "Başvuru Sorgulama",
        "url": "https://hexnox.pro/sowixfree/basvuru/basvuru.php",
        "params": ["tc"]
    },
    "nobetci_eczane": {
        "desc": "Nöbetçi Eczane Sorgulama",
        "url": "https://hexnox.pro/sowixfree/nezcane.php",
        "params": ["il", "ilce"]
    },
    "randevu": {
        "desc": "Randevu Sorgulama",
        "url": "https://hexnox.pro/sowixfree/nvi.php",
        "params": ["tc"]
    },
    "internet": {
        "desc": "İnternet Sorgulama",
        "url": "https://hexnox.pro/sowixfree/internet.php",
        "params": ["tc"]
    },
    "personel": {
        "desc": "Personel Sorgulama",
        "url": "https://hexnox.pro/sowixfree/personel.php",
        "params": ["tc"]
    },
    "interpol": {
        "desc": "Interpol Arananlar Sorgulama",
        "url": "https://hexnox.pro/sowixfree/interpol.php",
        "params": ["ad", "soyad"]
    },
    "sehit": {
        "desc": "Şehit Sorgulama",
        "url": "https://hexnox.pro/sowixfree/şehit.php",
        "params": ["Ad", "Soyad"]
    },
    "arac_parca": {
        "desc": "Araç Parça Sorgulama",
        "url": "https://hexnox.pro/sowixfree/aracparca.php",
        "params": ["plaka"]
    },
    "universite": {
        "desc": "Üniversite Sorgulama",
        "url": "http://hexnox.pro/sowixfree/%C3%BCni.php",
        "params": ["tc"]
    },
    "sertifika": {
        "desc": "Sertifika Sorgulama",
        "url": "http://hexnox.pro/sowixfree/sertifika.php",
        "params": ["tc"]
    },
    "nude": {
        "desc": "Nude API",
        "url": "http://hexnox.pro/sowixfree/nude.php",
        "params": []
    },
    "arac_borc": {
        "desc": "Araç Borç Sorgulama",
        "url": "http://hexnox.pro/sowixfree/plaka.php",
        "params": ["plaka"]
    },
    "lgs_2": {
        "desc": "LGS Sorgulama (2)",
        "url": "http://hexnox.pro/sowixfree/lgs/lgs.php",
        "params": ["tc"]
    },
    "muhalle": {
        "desc": "Mahalle Sorgulama",
        "url": "https://api.hexnox.pro/sowixapi/muhallev.php",
        "params": ["tc"]
    },
    "vesika": {
        "desc": "Vesika Sorgulama",
        "url": "https://hexnox.pro/sowix/vesika.php",
        "params": ["tc"]
    },
    "ehliyet": {
        "desc": "Ehliyet API",
        "url": "http://api.hexnox.pro/sowixapi/ehlt.php",
        "params": ["tc"]
    },
    "hava_durumu": {
        "desc": "Hava Durumu Sorgulama",
        "url": "http://api.hexnox.pro/sowixapi/havadurumu.php",
        "params": ["sehir"]
    },
    "email": {
        "desc": "Email Sorgulama",
        "url": "http://api.hexnox.pro/sowixapi/email_sorgu.php",
        "params": ["email"]
    },
    "boy": {
        "desc": "Boy API",
        "url": "http://api.hexnox.pro/sowixapi/boy.php",
        "params": ["tc"]
    },
    "ayak_no": {
        "desc": "Ayak No API",
        "url": "http://api.hexnox.pro/sowixapi/ayak.php",
        "params": ["tc"]
    },
    "cm": {
        "desc": "CM API",
        "url": "http://api.hexnox.pro/sowixapi/cm.php",
        "params": ["tc"]
    },
    "burc": {
        "desc": "Burç Sorgulama",
        "url": "http://api.hexnox.pro/sowixapi/burc.php",
        "params": ["tc"]
    },
    "cocuk": {
        "desc": "Çocuk Sorgulama",
        "url": "http://api.hexnox.pro/sowixapi/cocuk.php",
        "params": ["tc"]
    },
    "imei": {
        "desc": "IMEI Sorgulama",
        "url": "https://api.hexnox.pro/sowixapi/imei.php",
        "params": ["imei"]
    },
    "baba": {
        "desc": "Baba Sorgulama",
        "url": "http://hexnox.pro/sowixfree/baba.php",
        "params": ["tc"]
    },
    "anne": {
        "desc": "Anne Sorgulama",
        "url": "http://hexnox.pro/sowixfree/anne.php",
        "params": ["tc"]
    },
    "operator": {
        "desc": "Operatör Sorgulama",
        "url": "https://api.hexnox.pro/sowixapi/operator.php",
        "params": ["gsm"]
    },
}

# ---------------- PARAMETER VALIDATION RULES (whitelist regex) ----------------
_PARAM_PATTERNS = {
    'tc': r'^[0-9]{10,11}$',
    'gsm': r'^[0-9\+]{7,15}$',
    'imei': r'^[0-9]{14,16}$',
    'vergi': r'^[0-9]{6,12}$',
    'okulno': r'^[0-9]{1,10}$',
    'plaka': r'^[A-ZÇĞİÖŞÜ0-9\- ]{2,10}$',
    'email': r'^[^@\s]+@[^@\s]+\.[^@\s]+$',
    'domain': r'^[A-Za-z0-9\.\-]{3,255}$',
    'url': r'^[A-Za-z0-9:/._\?\=\&#\-]{3,2048}$',
    'ad': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{2,60}$',
    'soyad': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{2,60}$',
    'il': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{2,60}$',
    'ilce': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{2,60}$',
    'kullanici': r'^[A-Za-z0-9_\-]{2,50}$',
    'query': r'^[A-Za-z0-9_\-\.@ ]{1,200}$',
    'method': r'^[A-Za-z0-9_\-]{1,50}$',
    'password': r'^.{1,200}$',
}
_GENERIC_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.@\s]{1,' + str(MAX_PARAM_LENGTH) + r'}$')

def validate_and_sanitize_param(name, value):
    if value is None:
        return ''
    if not isinstance(value, str):
        value = str(value)
    val = value.strip()
    if len(val) > MAX_PARAM_LENGTH:
        raise ValueError(f"Parametre çok uzun: {name}")
    lowname = name.lower()
    pattern = _PARAM_PATTERNS.get(lowname)
    if pattern:
        if not re.match(pattern, val):
            raise ValueError(f"Parametre formatı geçersiz: {name}")
        return val
    if not _GENERIC_PATTERN.match(val):
        raise ValueError(f"Parametre içerik olarak geçersiz veya tehlikeli: {name}")
    return val

# ---------------- Helper: redis-backed or memory getters/setters ----------------
def _redis_set(key, value, ex=None):
    if redis_client:
        try:
            redis_client.set(key, json.dumps(value), ex=ex)
            return True
        except Exception:
            return False
    else:
        return False

def _redis_get(key):
    if redis_client:
        try:
            v = redis_client.get(key)
            return json.loads(v) if v else None
        except Exception:
            return None
    else:
        return None

def _redis_delete(key):
    if redis_client:
        try:
            redis_client.delete(key)
            return True
        except Exception:
            return False
    else:
        return False

BLOCKLIST_KEY = "bot:blocklist"
CACHE_PREFIX = "bot:ipcache:"

def add_block_ip(ip, seconds=0):
    now = time.time()
    until = 0 if seconds == 0 else int(now + seconds)
    if redis_client:
        try:
            redis_client.hset(BLOCKLIST_KEY, ip, until)
            return True
        except Exception:
            pass
    IP_BLOCKLIST_MEM[ip] = until
    return True

def remove_block_ip(ip):
    if redis_client:
        try:
            redis_client.hdel(BLOCKLIST_KEY, ip)
            return True
        except Exception:
            pass
    if ip in IP_BLOCKLIST_MEM:
        del IP_BLOCKLIST_MEM[ip]
        return True
    return False

def list_blocked():
    now = time.time()
    results = {}
    if redis_client:
        try:
            data = redis_client.hgetall(BLOCKLIST_KEY) or {}
            for ip, until in data.items():
                until_int = int(until)
                if until_int == 0 or until_int > now:
                    results[ip] = until_int
                else:
                    redis_client.hdel(BLOCKLIST_KEY, ip)
        except Exception:
            pass
    for ip, until in list(IP_BLOCKLIST_MEM.items()):
        if until == 0 or until > now:
            results[ip] = until
        else:
            del IP_BLOCKLIST_MEM[ip]
    return results

def get_cache(ip):
    now = time.time()
    if redis_client:
        v = _redis_get(CACHE_PREFIX + ip)
        if v and isinstance(v, dict) and v.get("until", 0) > now:
            return v.get("is_bad")
        return None
    else:
        v = IP_CHECK_CACHE_MEM.get(ip)
        if v and v[1] > now:
            return v[0]
        return None

def set_cache(ip, is_bad, ttl=CACHE_TTL):
    now = time.time()
    until = now + ttl
    if redis_client:
        _redis_set(CACHE_PREFIX + ip, {"is_bad": bool(is_bad), "until": until}, ex=ttl)
    else:
        IP_CHECK_CACHE_MEM[ip] = (bool(is_bad), until)

# ---------------- External IP checks ----------------
def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return False, None
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=4)
        r.raise_for_status()
        j = r.json()
        score = j.get("data", {}).get("abuseConfidenceScore")
        is_bad = score is not None and int(score) >= BLOCK_THRESHOLD_ABUSE
        return is_bad, score
    except Exception:
        return False, None

def check_ipqs(ip):
    if not IPQS_KEY:
        return False, None
    try:
        url = f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"
        r = requests.get(url, timeout=4)
        r.raise_for_status()
        j = r.json()
        fraud_score = j.get('fraud_score')
        proxy = j.get('proxy')
        tor = j.get('tor')
        vpn = j.get('vpn')
        is_bad = bool(proxy or tor or vpn or (fraud_score and fraud_score > 70))
        return is_bad, j
    except Exception:
        return False, None

def is_ip_blocked(ip):
    now = time.time()
    if redis_client:
        try:
            until_raw = redis_client.hget(BLOCKLIST_KEY, ip)
            if until_raw is not None:
                until = int(until_raw)
                if until == 0 or until > now:
                    return True
                else:
                    redis_client.hdel(BLOCKLIST_KEY, ip)
        except Exception:
            pass
    if ip in IP_BLOCKLIST_MEM:
        until = IP_BLOCKLIST_MEM[ip]
        if until == 0 or until > now:
            return True
        else:
            del IP_BLOCKLIST_MEM[ip]
    cached = get_cache(ip)
    if cached is not None:
        return bool(cached)

    bad_abuse, score = check_abuseipdb(ip)
    if bad_abuse:
        set_cache(ip, True)
        return True
    bad_ipqs, _ = check_ipqs(ip)
    if bad_ipqs:
        set_cache(ip, True)
        return True

    set_cache(ip, False)
    return False

# ---------------- Helper: admin auth decorator ----------------
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-ADMIN-TOKEN") or request.form.get("admin_token") or request.args.get("admin_token")
        if not ADMIN_TOKEN:
            return jsonify({"error": "ADMIN_TOKEN server side ayarlanmadı"}), 500
        if not token or token != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ---------------- Admin endpoints to manage blocklist ----------------
@app.route("/admin/block_ip", methods=["POST"])
@require_admin
def admin_block_ip():
    ip = request.form.get("ip")
    if not ip:
        return jsonify({"error": "ip gerekli"}), 400
    try:
        dur = int(request.form.get("seconds", "0"))
    except ValueError:
        return jsonify({"error": "seconds integer olmalı"}), 400
    if dur < 0 or dur > 60*60*24*30:
        return jsonify({"error": "seconds aralığı: 0-2592000"}), 400
    add_block_ip(ip, dur)
    return jsonify({"result": f"{ip} bloklandı", "until": "kalıcı" if dur == 0 else time.time() + dur}), 200

@app.route("/admin/unblock_ip", methods=["POST"])
@require_admin
def admin_unblock_ip():
    ip = request.form.get("ip")
    if not ip:
        return jsonify({"error": "ip gerekli"}), 400
    if remove_block_ip(ip):
        return jsonify({"result": f"{ip} serbest"}), 200
    return jsonify({"error": "bulunamadı"}), 404

@app.route("/admin/list_blocked", methods=["GET"])
@require_admin
def admin_list_blocked():
    return jsonify(list_blocked())

# ---------------- ddos_check endpoint ----------------
@app.route("/ezelnabi/ddos_check")
@limiter.limit("30 per minute")
def ddos_check():
    ip = request.args.get("ip") or request.remote_addr
    blocked = is_ip_blocked(ip)
    return jsonify({"ip": ip, "blocked": blocked})

# ---------------- Main proxy endpoint (korumalı + input validation) ----------------
@app.route("/ezelnabi/<api_name>")
@limiter.limit("60 per minute")
def api_proxy(api_name):
    if api_name not in apis:
        return "API bulunamadı", 404

    ip = request.remote_addr
    if is_ip_blocked(ip):
        return Response("<h3>❌ Erişim engellendi (IP şüpheli).</h3>", status=403, mimetype="text/html")

    api = apis[api_name]
    query_params = {}
    # Validate and sanitize each expected param
    try:
        for p in api.get("params", []):
            raw = request.args.get(p, "")
            sanitized = validate_and_sanitize_param(p, raw)
            query_params[p] = sanitized
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    try:
        resp = requests.get(api["url"], params=query_params, timeout=15)
        resp.raise_for_status()

        # Bazı servisler text dönebilir. Önce json dene.
        try:
            data = resp.json()
        except ValueError:
            safe_text = html.escape(resp.text)[:2000]
            return Response(safe_text, mimetype='text/plain')

        # Kayıtları çek
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict) and isinstance(data.get("data"), dict):
            records = list(data["data"].values())
        elif isinstance(data, dict) and isinstance(data.get("data"), list):
            records = data["data"]
        else:
            if isinstance(data, dict) and any(k in data for k in ("TC","ADI","SOYADI")):
                records = [data]
            else:
                records = []

        if not records:
            return "<h3>❌ Kayıt bulunamadı.</h3>"

        # Tabloya verileri hazırla (HTML escape ile XSS koruması)
        table_data = []
        for person in records:
            if not isinstance(person, dict):
                continue
            table_data.append([
                html.escape(str(person.get("TC", "")))[:50],
                html.escape(str(person.get("ADI", "")))[:60],
                html.escape(str(person.get("SOYADI", "")))[:60],
                html.escape(str(person.get("ANNEADI", "")))[:60],
                html.escape(str(person.get("BABAADI", "")))[:60],
                html.escape(str(person.get("DOGUMTARIHI", "")))[:30],
                html.escape(str(person.get("NUFUSIL", "")))[:40],
                html.escape(str(person.get("NUFUSILCE", "")))[:40]
            ])

        headers = ["TC", "Adı", "Soyadı", "Anne Adı", "Baba Adı", "Doğum Tarihi", "İl", "İlçe"]

        html_table = tabulate(table_data, headers=headers, tablefmt="html")

        title = html.escape(api.get('desc', 'Sorgu'))
        html_page = f"""
        <html>
            <head>
                <meta charset="utf-8" />
                <title>{title}</title>
                <style>
                    table {{border-collapse: collapse; width: 100%;}}
                    th, td {{border: 1px solid #ccc; padding: 8px; text-align: left;}}
                    th {{background-color: #f2f2f2;}}
                </style>
            </head>
            <body>
                <h2>{title}</h2>
                {html_table}
            </body>
        </html>
        """

        return Response(html_page, mimetype='text/html')

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return "<h3>❌ Kayıt bulunamadı.</h3>", 404
        else:
            return f"<h3>API isteği başarısız: {html.escape(str(e))}</h3>", getattr(e.response, "status_code", 500)
    except Exception as e:
        return f"<h3>API isteği başarısız: {html.escape(str(e))}</h3>", 500

# ---------------- Run ----------------
if __name__ == "__main__":
    if not ADMIN_TOKEN:
        print("UYARI: ADMIN_TOKEN ayarlı değil. Admin endpointleri çalışmayacaktır.")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
