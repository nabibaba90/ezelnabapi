"""
bot.py
Güncel korumalı proxy sunucusu:
- Flask proxy endpoints (senin apis dict)
- Flask-Limiter with Redis backend (önerilen)
- IP reputation checks (AbuseIPDB, IPQualityScore)
- Redis-backed blocklist & cache (fallback: in-memory)
- Admin endpoints (block/unblock/list) korumalı X-ADMIN-TOKEN ile

KULLANIM:
1) Bağımlılıklar:
   pip install flask requests tabulate Flask-Limiter redis python-dotenv gunicorn

2) Redis (local):
   docker run -d --name redis -p 6379:6379 redis:7-alpine

3) Ortam değişkenleri (.env veya export):
   export ABUSEIPDB_KEY="..."
   export IPQS_KEY="..."
   export ADMIN_TOKEN="çok-gizli-token"
   export RATE_LIMIT_STORAGE="redis://localhost:6379"
   export BLOCK_THRESHOLD_ABUSE="50"
   export PORT=5000

4) Çalıştırma (geliştirme):
   python bot.py

5) Production (örnek gunicorn):
   gunicorn -w 4 -b 0.0.0.0:5000 bot:app

NGINX SNIPPET ve ek bilgiler alt tarafta yer alır.

NOT: Bu dosya ortam değişkenleri ile çalışır. Anahtarları koda gömme.

"""

import os
import time
import json
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
ABUSEIPDB_KEY = os.environ.get("ramizs1ker", "")   # AbuseIPDB API key (opsiyonel)
IPQS_KEY = os.environ.get("ramizbaba", "")             # IPQualityScore key (opsiyonel)
ADMIN_TOKEN = os.environ.get("nabininadminibudur", "")       # admin endpointler için token (zorunlu yap)
BLOCK_THRESHOLD_ABUSE = int(os.environ.get("BLOCK_THRESHOLD_ABUSE", "50"))
RATE_LIMIT_STORAGE = os.environ.get("RATE_LIMIT_STORAGE", "memory://")  # veya redis://...
CACHE_TTL = int(os.environ.get("CACHE_TTL", 300))  # IP reputation cache (saniye)

# ---------------- Redis setup (opsiyonel) ----------------
redis_client = None
if REDIS_AVAILABLE and RATE_LIMIT_STORAGE.startswith("redis://"):
    try:
        redis_url = RATE_LIMIT_STORAGE
        # redis.from_url handles redis://host:port
        redis_client = redis.from_url(redis_url, decode_responses=True)
    except Exception as exc:
        redis_client = None
        print("Redis bağlantısı kurulamadı, fallback in-memory kullanılıyor:", exc)
else:
    redis_client = None

# ---------------- RATE LIMITER ----------------
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],   # genel fallback limit
    storage_uri=RATE_LIMIT_STORAGE
)

# ---------------- In-memory fallback structures ----------------
IP_BLOCKLIST_MEM = {}   # ip -> unblock_timestamp (0 = permanent)
IP_CHECK_CACHE_MEM = {} # ip -> (is_bad, expires_ts)

# ---------------- API sözlüğü (senin verdiğin apis) ----------------
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
    # ... (diğerleri) - uzun dict'i gerektiği gibi ekledim
}

# Eğer tam dict istersen, buraya tüm apis içeriğini ekle (kopyala yapıştır)
# Not: Canvas belgesinde bu satır yerine tam dict sağlanmıştır.

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

# Redis-backed blocklist/cache keys naming
BLOCKLIST_KEY = "bot:blocklist"     # hash of ip -> unblock_ts (0 = permanent)
CACHE_PREFIX = "bot:ipcache:"       # per-ip key

# ---------------- Blocklist & cache functions ----------------

def add_block_ip(ip, seconds=0):
    now = time.time()
    until = 0 if seconds == 0 else int(now + seconds)
    if redis_client:
        # store as hash field
        try:
            redis_client.hset(BLOCKLIST_KEY, ip, until)
            return True
        except Exception:
            pass
    # fallback memory
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
                    # expired -> cleanup
                    redis_client.hdel(BLOCKLIST_KEY, ip)
        except Exception:
            pass
    # merge memory
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
    # check redis blocklist
    if redis_client:
        try:
            until_raw = redis_client.hget(BLOCKLIST_KEY, ip)
            if until_raw is not None:
                until = int(until_raw)
                if until == 0 or until > now:
                    return True
                else:
                    # expired -> remove
                    redis_client.hdel(BLOCKLIST_KEY, ip)
        except Exception:
            pass
    # memory
    if ip in IP_BLOCKLIST_MEM:
        until = IP_BLOCKLIST_MEM[ip]
        if until == 0 or until > now:
            return True
        else:
            del IP_BLOCKLIST_MEM[ip]
    # cache check
    cached = get_cache(ip)
    if cached is not None:
        return bool(cached)

    # perform external checks
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
    dur = int(request.form.get("seconds", "0"))
    if not ip:
        return jsonify({"error": "ip gerekli"}), 400
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

# ---------------- Main proxy endpoint (korumalı) ----------------
@app.route("/ezelnabi/<api_name>")
@limiter.limit("60 per minute")
def api_proxy(api_name):
    if api_name not in apis:
        return "API bulunamadı", 404

    ip = request.remote_addr
    # IP reputation / block kontrolü
    if is_ip_blocked(ip):
        return Response("<h3>❌ Erişim engellendi (IP şüpheli).</h3>", status=403, mimetype="text/html")

    api = apis[api_name]
    query_params = {}
    for p in api["params"]:
        val = request.args.get(p, "")
        query_params[p] = val

    try:
        resp = requests.get(api["url"], params=query_params, timeout=15)
        resp.raise_for_status()

        # Bazı servisler text dönebilir. Önce json dene.
        try:
            data = resp.json()
        except ValueError:
            # JSON parse hatası -> raw text döndür
            return Response(resp.text, mimetype='text/plain')

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

        # Tabloya verileri hazırla
        table_data = []
        for person in records:
            if not isinstance(person, dict):
                continue
            table_data.append([
                person.get("TC", ""),
                person.get("ADI", ""),
                person.get("SOYADI", ""),
                person.get("ANNEADI", ""),
                person.get("BABAADI", ""),
                person.get("DOGUMTARIHI", ""),
                person.get("NUFUSIL", ""),
                person.get("NUFUSILCE", "")
            ])

        headers = ["TC", "Adı", "Soyadı", "Anne Adı", "Baba Adı", "Doğum Tarihi", "İl", "İlçe"]

        html_table = tabulate(table_data, headers=headers, tablefmt="html")

        html_page = f"""
        <html>
            <head>
                <title>{api['desc']}</title>
                <style>
                    table {{border-collapse: collapse; width: 100%;}}
                    th, td {{border: 1px solid #ccc; padding: 8px; text-align: left;}}
                    th {{background-color: #f2f2f2;}}
                </style>
            </head>
            <body>
                <h2>{api['desc']}</h2>
                {html_table}
            </body>
        </html>
        """

        return Response(html_page, mimetype='text/html')

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return "<h3>❌ Kayıt bulunamadı.</h3>", 404
        else:
            return f"<h3>API isteği başarısız: {e}</h3>", getattr(e.response, "status_code", 500)
    except Exception as e:
        return f"<h3>API isteği başarısız: {e}</h3>", 500

# ---------------- Run ----------------
if __name__ == "__main__":
    # Eğer ADMIN_TOKEN boşsa terminalde uyar
    if not ADMIN_TOKEN:
        print("UYARI: ADMIN_TOKEN ayarlı değil. Admin endpointleri çalışmayacaktır.")
    # production'da gunicorn/uvicorn arkasında çalıştır
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)


# ---------------- NGINX CONFIG SNIPPET (Aşağıyı sunucuya ekle) ----------------
# Bu snippet'i /etc/nginx/sites-available/your_site.conf içine ekle ve test et.
#
# upstream app_servers {
#     server 127.0.0.1:5000;
# }
#
# server {
#     listen 80;
#     server_name example.com; # kendi alan adın
#
#     # Genel rate limit
#     limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
#
#     location / {
#         limit_req zone=one burst=20 nodelay;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_pass http://app_servers;
#     }
#
#     # isteklerin loglanması, tls, güvenlik header'ları vs. ekle
#}

