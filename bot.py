#!/usr/bin/env python3
# b.py - Güncel tüm API’ler + HTML çıktı + ad_soyad zorunlu + dış host kontrolü kaldırıldı

import os, re, html, requests
from flask import Flask, request, Response, render_template_string
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
MAX_PARAM_LENGTH = 200

# ---------------- RATE LIMIT ----------------
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)
limiter.init_app(app)

# ---------------- API tanımları ----------------
apis = {
    "tc_sorgulama": {"desc":"TC Sorgulama","url":"https://api.kahin.org/kahinapi/tc","params":["tc"]},
    "tc_pro_sorgulama": {"desc":"TC PRO Sorgulama","url":"https://api.kahin.org/kahinapi/tcpro","params":["tc"]},
    "hayat_hikayesi": {"desc":"Hayat Hikayesi Sorgulama","url":"https://api.kahin.org/kahinapi/hayathikayesi.php","params":["tc"]},
    "ad_soyad": {"desc":"Ad Soyad Sorgulama","url":"https://api.kahin.org/kahinapi/adsoyad","params":["ad","soyad","il","ilce"]},
    "ad_soyad_pro": {"desc":"Ad Soyad PRO Sorgulama","url":"https://api.kahin.org/kahinapi/tapu","params":["tc"]},
    "is_yeri": {"desc":"İş Yeri Sorgulama","url":"https://api.kahin.org/kahinapi/isyeri","params":["tc"]},
    "vergi_no": {"desc":"Vergi No Sorgulama","url":"https://api.kahin.org/kahinapi/vergino","params":["vergi"]},
    "yas": {"desc":"Yaş Sorgulama","url":"https://api.kahin.org/kahinapi/yas","params":["tc"]},
    "tc_gsm": {"desc":"TC GSM Sorgulama","url":"https://api.kahin.org/kahinapi/tcgsm","params":["tc"]},
    "gsm_tc": {"desc":"GSM TC Sorgulama","url":"https://api.kahin.org/kahinapi/gsmtc","params":["gsm"]},
    "adres": {"desc":"Adres Sorgulama","url":"https://api.kahin.org/kahinapi/adres.php","params":["tc"]},
    "hane": {"desc":"Hane Sorgulama","url":"https://api.kahin.org/kahinapi/hane","params":["tc"]},
    "apartman": {"desc":"Apartman Sorgulama","url":"https://api.kahin.org/kahinapi/apartman","params":["tc"]},
    "ada_parsel": {"desc":"Ada Parsel Sorgulama","url":"https://api.kahin.org/kahinapi/adaparsel","params":["il","ada","parsel"]},
    "adi_il_ilce": {"desc":"Adı İl İlçe Sorgulama","url":"https://api.kahin.org/kahinapi/adililce.php","params":["ad","il"]},
    "aile": {"desc":"Aile Sorgulama","url":"https://api.kahin.org/kahinapi/aile","params":["tc"]},
    "aile_pro": {"desc":"Aile PRO Sorgulama","url":"https://api.kahin.org/kahinapi/ailepro","params":["tc"]},
    "es": {"desc":"Eş Sorgulama","url":"https://api.kahin.org/kahinapi/es","params":["tc"]},
    "sulale": {"desc":"Sulale Sorgulama","url":"https://api.kahin.org/kahinapi/sulale","params":["tc"]},
    "lgs": {"desc":"LGS Sorgulama","url":"https://api.kahin.org/kahinapi/lgs","params":["tc"]},
    "e_kurs": {"desc":"E-Kurs Sorgulama","url":"https://api.kahin.org/kahinapi/ekurs","params":["tc","okulno"]},
    "ip": {"desc":"IP Sorgulama","url":"https://api.kahin.org/kahinapi/ip","params":["domain"]},
    "dns": {"desc":"DNS Sorgulama","url":"https://api.kahin.org/kahinapi/dns","params":["domain"]},
    "whois": {"desc":"Whois Sorgulama","url":"https://api.kahin.org/kahinapi/whois","params":["domain"]},
    "subdomain": {"desc":"Subdomain Sorgulama","url":"https://api.kahin.org/kahinapi/subdomain.php","params":["url"]},
    "leak": {"desc":"Leak Sorgulama","url":"https://api.kahin.org/kahinapi/leak.php","params":["query"]},
    "telegram": {"desc":"Telegram Sorgulama","url":"https://api.kahin.org/kahinapi/telegram.php","params":["kullanici"]},
    "sifre_encrypt": {"desc":"Şifre Encrypt","url":"https://api.kahin.org/kahinapi/encrypt","params":["method","password"]},
    "prem_ad": {"desc":"Prem Ad Sorgulama","url":"https://api.hexnox.pro/sowixapi/premad.php","params":["ad","il","ilce"]},
    "mhrs_randevu": {"desc":"MHRS Randevu Sorgulama","url":"https://hexnox.pro/sowixfree/mhrs/mhrs.php","params":["tc"]},
    "prem_adres": {"desc":"Prem Adres Sorgulama","url":"https://hexnox.pro/sowixfree/premadres.php","params":["tc"]},
    "sgk_pro": {"desc":"SGK PRO Sorgulama","url":"https://api.hexnox.pro/sowixapi/sgkpro.php","params":["tc"]},
    "vergi_levhasi": {"desc":"Vergi Levhası Sorgulama","url":"https://hexnox.pro/sowixfree/vergi/vergi.php","params":["tc"]},
    "facebook": {"desc":"Facebook Sorgulama","url":"https://hexnox.pro/sowixfree/facebook.php","params":["numara"]},
    "diploma": {"desc":"Diploma Sorgulama","url":"https://hexnox.pro/sowixfree/diploma/diploma.php","params":["tc"]},
    "basvuru": {"desc":"Başvuru Sorgulama","url":"https://hexnox.pro/sowixfree/basvuru/basvuru.php","params":["tc"]},
    "nobetci_eczane": {"desc":"Nöbetçi Eczane Sorgulama","url":"https://hexnox.pro/sowixfree/nezcane.php","params":["il","ilce"]},
    "randevu": {"desc":"Randevu Sorgulama","url":"https://hexnox.pro/sowixfree/nvi.php","params":["tc"]},
    "internet": {"desc":"İnternet Sorgulama","url":"https://hexnox.pro/sowixfree/internet.php","params":["tc"]},
    "personel": {"desc":"Personel Sorgulama","url":"https://hexnox.pro/sowixfree/personel.php","params":["tc"]},
    "interpol": {"desc":"Interpol Arananlar Sorgulama","url":"https://hexnox.pro/sowixfree/interpol.php","params":["ad","soyad"]},
    "sehit": {"desc":"Şehit Sorgulama","url":"https://hexnox.pro/sowixfree/şehit.php","params":["Ad","Soyad"]},
    "arac_parca": {"desc":"Araç Parça Sorgulama","url":"https://hexnox.pro/sowixfree/aracparca.php","params":["plaka"]},
    "universite": {"desc":"Üniversite Sorgulama","url":"http://hexnox.pro/sowixfree/%C3%BCni.php","params":["tc"]},
    "sertifika": {"desc":"Sertifika Sorgulama","url":"http://hexnox.pro/sowixfree/sertifika.php","params":["tc"]},
    "nude": {"desc":"Nude API","url":"http://hexnox.pro/sowixfree/nude.php","params":[]},
    "arac_borc": {"desc":"Araç Borç Sorgulama","url":"http://hexnox.pro/sowixfree/plaka.php","params":["plaka"]},
    "lgs_2": {"desc":"LGS Sorgulama (2)","url":"http://hexnox.pro/sowixfree/lgs/lgs.php","params":["tc"]},
    "muhalle": {"desc":"Mahalle Sorgulama","url":"https://api.hexnox.pro/sowixapi/muhallev.php","params":["tc"]},
    "vesika": {"desc":"Vesika Sorgulama","url":"https://hexnox.pro/sowix/vesika.php","params":["tc"]},
    "ehliyet": {"desc":"Ehliyet API","url":"http://api.hexnox.pro/sowixapi/ehlt.php","params":["tc"]},
    "hava_durumu": {"desc":"Hava Durumu Sorgulama","url":"http://api.hexnox.pro/sowixapi/havadurumu.php","params":["sehir"]},
    "email": {"desc":"Email Sorgulama","url":"http://api.hexnox.pro/sowixapi/email_sorgu.php","params":["email"]},
    "boy": {"desc":"Boy API","url":"http://api.hexnox.pro/sowixapi/boy.php","params":["tc"]},
    "ayak_no": {"desc":"Ayak No API","url":"http://api.hexnox.pro/sowixapi/ayak.php","params":["tc"]},
    "cm": {"desc":"CM API","url":"http://api.hexnox.pro/sowixapi/cm.php","params":["tc"]},
    "burc": {"desc":"Burç Sorgulama","url":"http://api.hexnox.pro/sowixapi/burc.php","params":["tc"]},
    "cocuk": {"desc":"Çocuk Sorgulama","url":"http://api.hexnox.pro/sowixapi/cocuk.php","params":["tc"]},
    "imei": {"desc":"IMEI Sorgulama","url":"https://api.hexnox.pro/sowixapi/imei.php","params":["imei"]},
    "baba": {"desc":"Baba Sorgulama","url":"http://hexnox.pro/sowixfree/baba.php","params":["tc"]},
    "anne": {"desc":"Anne Sorgulama","url":"http://hexnox.pro/sowixfree/anne.php","params":["tc"]},
    "operator": {"desc":"Operatör Sorgulama","url":"https://api.hexnox.pro/sowixapi/operator.php","params":["gsm"]}
}

# ---------------- PARAMETRE KONTROL ----------------
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
    'soyad': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{0,60}$',
    'il': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{2,60}$',
    'ilce': r'^[A-Za-zÇĞİÖŞÜçğıöşü \-]{0,60}$',
    'kullanici': r'^[A-Za-z0-9_\-]{2,50}$',
    'query': r'^[A-Za-z0-9_\-\.@ ]{1,200}$',
    'method': r'^[A-Za-z0-9_\-]{1,50}$',
    'password': r'^.{1,200}$',
}
_GENERIC_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.@\s]{1,' + str(MAX_PARAM_LENGTH) + r'}$')

def validate_and_sanitize_param(name, value):
    if value is None:
        value = ''
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
        if lowname == "ad" and val == "":
            raise ValueError("Ad parametresi zorunludur.")
        return val
    if not _GENERIC_PATTERN.match(val):
        raise ValueError(f"Parametre içerik olarak geçersiz: {name}")
    return val

# ---------------- HTML TABLE DÖNÜŞ ----------------
def to_html_table(json_data):
    if isinstance(json_data, dict):
        rows = ""
        for k,v in json_data.items():
            rows += f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        return f"<table border='1' cellpadding='5'>{rows}</table>"
    elif isinstance(json_data, list):
        rows = ""
        if all(isinstance(i, dict) for i in json_data):
            headers = json_data[0].keys()
            rows += "<tr>" + "".join(f"<th>{html.escape(str(h))}</th>" for h in headers) + "</tr>"
            for entry in json_data:
                rows += "<tr>" + "".join(f"<td>{html.escape(str(entry.get(h,'')))}</td>" for h in headers) + "</tr>"
        else:
            rows += "".join(f"<tr><td>{html.escape(str(i))}</td></tr>" for i in json_data)
        return f"<table border='1' cellpadding='5'>{rows}</table>"
    else:
        return f"<p>{html.escape(str(json_data))}</p>"

# ---------------- API PROXY ----------------
@app.route("/api/<api_name>")
@limiter.limit("60 per minute")
def api_proxy(api_name):
    if api_name not in apis:
        return "API bulunamadı", 404

    api = apis[api_name]
    query_params = {}
    try:
        for p in api.get("params", []):
            raw = request.args.get(p, "")
            sanitized = validate_and_sanitize_param(p, raw)
            query_params[p] = sanitized
    except ValueError as ve:
        return f"<h3>Hata: {html.escape(str(ve))}</h3>", 400

    try:
        resp = requests.get(api["url"], params=query_params, timeout=15)
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            return f"<pre>{html.escape(resp.text)}</pre>"
        return to_html_table(data)
    except Exception as e:
        return f"<h3>Hata: {html.escape(str(e))}</h3>", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
