#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# b.py - VIP Sorgu Paneli (Güncelleme: JSON çıktı, scrub, /ezelnabi rota)

from flask import Flask, request, jsonify, Response
import requests
import threading, time, re, os, logging, json
from functools import wraps
from collections import defaultdict

app = Flask(__name__)
app.secret_key = "supersecretkey123"

# ----------------------
# Rate Limit Ayarı (IP başına dakika 15 istek)
# ----------------------
RATE_LIMIT = 15
rate_cache = defaultdict(list)

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = time.time()
        # cache temizleme (son 60s)
        rate_cache[ip] = [t for t in rate_cache[ip] if now - t < 60]
        if len(rate_cache[ip]) >= RATE_LIMIT:
            return jsonify({"error": "Rate limit aşıldı (dakikada 15 istek)"}), 429
        rate_cache[ip].append(now)
        return f(*args, **kwargs)
    return decorated

# ----------------------
# Basit SQL Injection / tehlikeli karakter temizleme
# ----------------------
def sanitize(val: str) -> str:
    if val is None:
        return val
    return re.sub(r"[\"\'=;]", "", str(val))

# ----------------------
# Hassas / sahip bilgilerini maskeleme (rekürsif)
# ----------------------
SENSITIVE_TOKENS = [
    r"keneviz", r"hexnox", r"kahin", r"sowix", r"owner", r"developer", r"channel", r"maker"
]
REPLACEMENT = "ezel_nabi"

def scrub_obj(obj):
    """Rekürsif olarak dict/list/str içindeki hassas kelimeleri değiştirir."""
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            lk = k.lower() if isinstance(k, str) else k
            # anahtar isimleri saklama/maskeleme
            if isinstance(k, str) and any(tok in lk for tok in ["owner", "developer", "channel", "maker"]):
                new[k] = REPLACEMENT
            else:
                new[k] = scrub_obj(v)
        return new
    elif isinstance(obj, list):
        return [scrub_obj(i) for i in obj]
    elif isinstance(obj, str):
        s = obj
        for tok in SENSITIVE_TOKENS:
            s = re.sub(tok, REPLACEMENT, s, flags=re.IGNORECASE)
        return s
    else:
        return obj

# ----------------------
# Tüm API Tanımları
# ----------------------
APIS = {
    "tc_sorgulama": {"desc": "TC Sorgulama", "url": "https://api.kahin.org/kahinapi/tc", "params": ["tc"]},
    "tc_pro_sorgulama": {"desc": "TC PRO Sorgulama", "url": "https://api.kahin.org/kahinapi/tcpro", "params": ["tc"]},
    "hayat_hikayesi": {"desc": "Hayat Hikayesi Sorgulama", "url": "https://api.kahin.org/kahinapi/hayathikayesi.php", "params": ["tc"]},
    "ad_soyad": {"desc": "Ad Soyad Sorgulama", "url": "https://api.kahin.org/kahinapi/adsoyad", "params": ["ad", "soyad", "il", "ilce"]},
    "ad_soyad_pro": {"desc": "Ad Soyad PRO Sorgulama", "url": "https://api.kahin.org/kahinapi/tapu", "params": ["tc"]},
    "is_yeri": {"desc": "İş Yeri Sorgulama", "url": "https://api.kahin.org/kahinapi/isyeri", "params": ["tc"]},
    "vergi_no": {"desc": "Vergi No Sorgulama", "url": "https://api.kahin.org/kahinapi/vergino", "params": ["vergi"]},
    "yas": {"desc": "Yaş Sorgulama", "url": "https://api.kahin.org/kahinapi/yas", "params": ["tc"]},
    "tc_gsm": {"desc": "TC GSM Sorgulama", "url": "https://api.kahin.org/kahinapi/tcgsm", "params": ["tc"]},
    "gsm_tc": {"desc": "GSM TC Sorgulama", "url": "https://api.kahin.org/kahinapi/gsmtc", "params": ["gsm"]},
    "adres": {"desc": "Adres Sorgulama", "url": "https://api.kahin.org/kahinapi/adres.php", "params": ["tc"]},
    "hane": {"desc": "Hane Sorgulama", "url": "https://api.kahin.org/kahinapi/hane", "params": ["tc"]},
    "apartman": {"desc": "Apartman Sorgulama", "url": "https://api.kahin.org/kahinapi/apartman", "params": ["tc"]},
    "ada_parsel": {"desc": "Ada Parsel Sorgulama", "url": "https://api.kahin.org/kahinapi/adaparsel", "params": ["il", "ada", "parsel"]},
    "adi_il_ilce": {"desc": "Adı İl İlçe Sorgulama", "url": "https://api.kahin.org/kahinapi/adililce.php", "params": ["ad", "il"]},
    "aile": {"desc": "Aile Sorgulama", "url": "https://api.kahin.org/kahinapi/aile", "params": ["tc"]},
    "aile_pro": {"desc": "Aile PRO Sorgulama", "url": "https://api.kahin.org/kahinapi/ailepro", "params": ["tc"]},
    "es": {"desc": "Eş Sorgulama", "url": "https://api.kahin.org/kahinapi/es", "params": ["tc"]},
    "sulale": {"desc": "Sulale Sorgulama", "url": "https://api.kahin.org/kahinapi/sulale", "params": ["tc"]},
    "lgs": {"desc": "LGS Sorgulama", "url": "https://api.kahin.org/kahinapi/lgs", "params": ["tc"]},
    "e_kurs": {"desc": "E-Kurs Sorgulama", "url": "https://api.kahin.org/kahinapi/ekurs", "params": ["tc", "okulno"]},
    "ip": {"desc": "IP Sorgulama", "url": "https://api.kahin.org/kahinapi/ip", "params": ["domain"]},
    "dns": {"desc": "DNS Sorgulama", "url": "https://api.kahin.org/kahinapi/dns", "params": ["domain"]},
    "whois": {"desc": "Whois Sorgulama", "url": "https://api.kahin.org/kahinapi/whois", "params": ["domain"]},
    "subdomain": {"desc": "Subdomain Sorgulama", "url": "https://api.kahin.org/kahinapi/subdomain.php", "params": ["url"]},
    "leak": {"desc": "Leak Sorgulama", "url": "https://api.kahin.org/kahinapi/leak.php", "params": ["query"]},
    "telegram": {"desc": "Telegram Sorgulama", "url": "https://api.kahin.org/kahinapi/telegram.php", "params": ["kullanici"]},
    "sifre_encrypt": {"desc": "Şifre Encrypt", "url": "https://api.kahin.org/kahinapi/encrypt", "params": ["method", "password"]},
    "prem_ad": {"desc": "Prem Ad Sorgulama", "url": "https://api.hexnox.pro/sowixapi/premad.php", "params": ["ad", "il", "ilce"]},
    "mhrs_randevu": {"desc": "MHRS Randevu Sorgulama", "url": "https://hexnox.pro/sowixfree/mhrs/mhrs.php", "params": ["tc"]},
    "prem_adres": {"desc": "Prem Adres Sorgulama", "url": "https://hexnox.pro/sowixfree/premadres.php", "params": ["tc"]},
    "sgk_pro": {"desc": "SGK PRO Sorgulama", "url": "https://api.hexnox.pro/sowixapi/sgkpro.php", "params": ["tc"]},
    "vergi_levhasi": {"desc": "Vergi Levhası Sorgulama", "url": "https://hexnox.pro/sowixfree/vergi/vergi.php", "params": ["tc"]},
    "facebook": {"desc": "Facebook Sorgulama", "url": "https://hexnox.pro/sowixfree/facebook.php", "params": ["numara"]},
    "diploma": {"desc": "Diploma Sorgulama", "url": "https://hexnox.pro/sowixfree/diploma/diploma.php", "params": ["tc"]},
    "basvuru": {"desc": "Başvuru Sorgulama", "url": "https://hexnox.pro/sowixfree/basvuru/basvuru.php", "params": ["tc"]},
    "nobetci_eczane": {"desc": "Nöbetçi Eczane Sorgulama", "url": "https://hexnox.pro/sowixfree/nezcane.php", "params": ["il", "ilce"]},
    "randevu": {"desc": "Randevu Sorgulama", "url": "https://hexnox.pro/sowixfree/nvi.php", "params": ["tc"]},
    "internet": {"desc": "İnternet Sorgulama", "url": "https://hexnox.pro/sowixfree/internet.php", "params": ["tc"]},
    "personel": {"desc": "Personel Sorgulama", "url": "https://hexnox.pro/sowixfree/personel.php", "params": ["tc"]},
    "interpol": {"desc": "Interpol Arananlar Sorgulama", "url": "https://hexnox.pro/sowixfree/interpol.php", "params": ["ad", "soyad"]},
    "sehit": {"desc": "Şehit Sorgulama", "url": "https://hexnox.pro/sowixfree/şehit.php", "params": ["Ad", "Soyad"]},
    "arac_parca": {"desc": "Araç Parça Sorgulama", "url": "https://hexnox.pro/sowixfree/aracparca.php", "params": ["plaka"]},
    "universite": {"desc": "Üniversite Sorgulama", "url": "http://hexnox.pro/sowixfree/%C3%BCni.php", "params": ["tc"]},
    "sertifika": {"desc": "Sertifika Sorgulama", "url": "http://hexnox.pro/sowixfree/sertifika.php", "params": ["tc"]},
    "nude": {"desc": "Nude API", "url": "http://hexnox.pro/sowixfree/nude.php", "params": []},
    "arac_borc": {"desc": "Araç Borç Sorgulama", "url": "http://hexnox.pro/sowixfree/plaka.php", "params": ["plaka"]},
    "lgs_2": {"desc": "LGS Sorgulama (2)", "url": "http://hexnox.pro/sowixfree/lgs/lgs.php", "params": ["tc"]},
    "muhalle": {"desc": "Mahalle Sorgulama", "url": "https://api.hexnox.pro/sowixapi/muhallev.php", "params": ["tc"]},
    "vesika": {"desc": "Vesika Sorgulama", "url": "https://api.hexnox.pro/sowix/vesika.php", "params": ["tc"]},
    "ehliyet": {"desc": "Ehliyet API", "url": "http://api.hexnox.pro/sowixapi/ehlt.php", "params": ["tc"]},
    "hava_durumu": {"desc": "Hava Durumu Sorgulama", "url": "http://api.hexnox.pro/sowixapi/havadurumu.php", "params": ["sehir"]},
    "email": {"desc": "Email Sorgulama", "url": "http://api.hexnox.pro/sowixapi/email_sorgu.php", "params": ["email"]},
    "boy": {"desc": "Boy API", "url": "http://api.hexnox.pro/sowixapi/boy.php", "params": ["tc"]},
    "ayak_no": {"desc": "Ayak No API", "url": "http://api.hexnox.pro/sowixapi/ayak.php", "params": ["tc"]},
    "cm": {"desc": "CM API", "url": "https://api.hexnox.pro/sowixapi/cm.php", "params": ["tc"]},
    "burc": {"desc": "Burç Sorgulama", "url": "https://api.hexnox.pro/sowixapi/burc.php", "params": ["tc"]},
    "cocuk": {"desc": "Çocuk Sorgulama", "url": "https://api.hexnox.pro/sowixapi/cocuk.php", "params": ["tc"]},
    "imei": {"desc": "IMEI Sorgulama", "url": "https://api.hexnox.pro/sowixapi/imei.php", "params": ["imei"]},
    "baba": {"desc": "Baba Sorgulama", "url": "http://api.hexnox.pro/sowixapi/baba.php", "params": ["tc"]},
    "anne": {"desc": "Anne Sorgulama", "url": "http://api.hexnox.pro/sowixfree/anne.php", "params": ["tc"]},
    "operator": {"desc": "Operatör Sorgulama", "url": "https://api.hexnox.pro/sowixapi/operator.php", "params": ["gsm"]}
}

def pretty_json_response(obj, status_code=200):
    return Response(json.dumps(obj, ensure_ascii=False, indent=2), mimetype='application/json', status=status_code)

# ----------------------
# API Proxy Route (hem /api hem /ezelnabi)
# ----------------------
@app.route("/api/<api_name>", methods=["GET"])
@app.route("/ezelnabi/<api_name>", methods=["GET"])
@rate_limit
def api_proxy(api_name):
    if api_name not in APIS:
        return pretty_json_response({"error": "API bulunamadı", "requested": api_name}, status_code=404)

    api = APIS[api_name]

    # Sadece gönderilmiş ve boş olmayan paramları al (boş stringleri at)
    query_params = {}
    for p in api.get("params", []):
        if p in request.args:
            val = request.args.get(p, "")
            if val != "":
                query_params[p] = sanitize(val)

    # Eğer hiç param sağlanmadıysa, bunu response içinde belirt (zorunlu kılmıyoruz)
    if not query_params and api.get("params"):
        note = "Not: API için parametre sağlanmadı; mümkünse ilgili sorgu parametrelerini gönderin."
    else:
        note = None

    try:
        r = requests.get(api["url"], params=query_params if query_params else None, timeout=12)
        r.raise_for_status()

        # JSON parse etmeye çalış; başarısızsa ham text al
        try:
            data = r.json()
        except ValueError:
            data = r.text

        # Eğer dict içindeyse bazı alanları maskele
        data = scrub_obj(data)

        # Eğer 'info' alanı varsa, içeriğini kibar bir uyarıya çevir
        if isinstance(data, dict) and "info" in data:
            data["info"] = "Hata alırsanız ezel_nabi ile iletişime geçin."

        response_payload = {
            "api": api_name,
            "desc": api.get("desc"),
            "requested_params": query_params,
            "note": note,
            "response": data
        }
        return pretty_json_response(response_payload, status_code=r.status_code)

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else 500
        detail = None
        try:
            detail = e.response.text
        except Exception:
            detail = str(e)
        payload = {
            "error": "API isteği başarısız",
            "status": status,
            "detail": scrub_obj(detail),
            "api": api_name,
            "requested_params": query_params
        }
        return pretty_json_response(payload, status_code=status)

    except Exception as e:
        payload = {
            "error": "İç hata",
            "detail": scrub_obj(str(e)),
            "api": api_name,
            "requested_params": query_params
        }
        return pretty_json_response(payload, status_code=500)

# ----------------------
# Ana Sayfa
# ----------------------
@app.route("/")
def index():
    return pretty_json_response({"status": "VIP Sorgu Paneli Çalışıyor", "routes": ["/api/<api_name>", "/ezelnabi/<api_name>"]})

# ----------------------
# Çalıştır
# ----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
