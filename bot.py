#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# b.py - VIP Sorgu Paneli (Tüm API + Neon HTML + Güvenlik Katmanları)

from flask import Flask, request, jsonify, render_template_string, session
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
        ip = request.remote_addr
        now = time.time()
        # cache temizleme
        rate_cache[ip] = [t for t in rate_cache[ip] if now - t < 60]
        if len(rate_cache[ip]) >= RATE_LIMIT:
            return jsonify({"error": "Rate limit aşıldı (dakikada 15 istek)"}), 429
        rate_cache[ip].append(now)
        return f(*args, **kwargs)
    return decorated

# ----------------------
# Basit SQL Injection Önleme
# ----------------------
def sanitize(val):
    return re.sub(r"[\"\'=;]", "", val)

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
    "vesika": {"desc": "Vesika Sorgulama", "url": "https://hexnox.pro/sowix/vesika.php", "params": ["tc"]},
    "ehliyet": {"desc": "Ehliyet API", "url": "http://api.hexnox.pro/sowixapi/ehlt.php", "params": ["tc"]},
    "hava_durumu": {"desc": "Hava Durumu Sorgulama", "url": "http://api.hexnox.pro/sowixapi/havadurumu.php", "params": ["sehir"]},
    "email": {"desc": "Email Sorgulama", "url": "http://api.hexnox.pro/sowixapi/email_sorgu.php", "params": ["email"]},
    "boy": {"desc": "Boy API", "url": "http://api.hexnox.pro/sowixapi/boy.php", "params": ["tc"]},
    "ayak_no": {"desc": "Ayak No API", "url": "http://api.hexnox.pro/sowixapi/ayak.php", "params": ["tc"]},
    "cm": {"desc": "CM API", "url": "http://api.hexnox.pro/sowixapi/cm.php", "params": ["tc"]},
    "burc": {"desc": "Burç Sorgulama", "url": "http://api.hexnox.pro/sowixapi/burc.php", "params": ["tc"]},
    "cocuk": {"desc": "Çocuk Sorgulama", "url": "http://api.hexnox.pro/sowixapi/cocuk.php", "params": ["tc"]},
    "imei": {"desc": "IMEI Sorgulama", "url": "https://api.hexnox.pro/sowixapi/imei.php", "params": ["imei"]},
    "baba": {"desc": "Baba Sorgulama", "url": "http://hexnox.pro/sowixfree/baba.php", "params": ["tc"]},
    "anne": {"desc": "Anne Sorgulama", "url": "http://hexnox.pro/sowixfree/anne.php", "params": ["tc"]},
    "operator": {"desc": "Operatör Sorgulama", "url": "https://api.hexnox.pro/sowixapi/operator.php", "params": ["gsm"]}
}

# ----------------------
# HTML Template (Neon & VIP)
# ----------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VIP Sorgu Sonucu</title>
<style>
body {
    background-color: #0f0f0f;
    color: #00fff0;
    font-family: 'Courier New', monospace;
    padding: 20px;
}
pre {
    background: #111;
    padding: 15px;
    border-radius: 12px;
    box-shadow: 0 0 15px #00fff0;
    overflow-x: auto;
}
h1 {
    text-align: center;
    color: #ff00ff;
    text-shadow: 0 0 8px #ff00ff, 0 0 15px #00ffff;
}
</style>
</head>
<body>
<h1>VIP Sorgu Sonucu</h1>
<pre>{{ content }}</pre>
</body>
</html>
"""

# ----------------------
# API Proxy Route
# ----------------------
@app.route("/api/<api_name>", methods=["GET"])
@rate_limit
def api_proxy(api_name):
    if api_name not in APIS:
        return jsonify({"error": "API bulunamadı"}), 404

    api = APIS[api_name]
    params = {}
    for p in api["params"]:
        if p not in request.args:
            return jsonify({"error": f"Parametre eksik: {p}"}), 400
        params[p] = sanitize(request.args[p])

    try:
        r = requests.get(api["url"], params=params, timeout=10)
        data = r.json()

        # Özel mesaj engelleme: info varsa değiştir
        if "info" in data:
            data["info"] = "Hata alırsanız @Keneviz Telegram’dan ulaşabilirsiniz."
    except:
        data = {"error": "Kayıt bulunamadı", "info": "Hata alırsanız @Keneviz Telegram’dan ulaşabilirsiniz."}

    return render_template_string(HTML_TEMPLATE, content=json.dumps(data, indent=4, ensure_ascii=False))

# ----------------------
# Ana Sayfa
# ----------------------
@app.route("/")
def index():
    return "<h1>VIP Sorgu Paneli Çalışıyor</h1>"

# ----------------------
# Çalıştır
# ----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
