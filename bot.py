from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# API tanımları
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
        "url": "http://api.hexnox.pro/sowixapi/baba.php",
        "params": ["tc"]
    },
    "anne": {
        "desc": "Anne Sorgulama",
        "url": "http://api.hexnox.pro/sowixapi/anne.php",
        "params": ["tc"]
    },
    "operator": {
        "desc": "Operatör Sorgulama",
        "url": "https://api.hexnox.pro/sowixapi/operator.php",
        "params": ["gsm"]
    },
}

@app.route("/ezelnab/<api_name>", methods=["GET"])
def api_proxy(api_name):
    if api_name not in apis:
        return jsonify({
            "nabiapi_sunar": True,
            "info": {
                "mesaj": "Hata alırsanız Telegram üzerinden @Nabi_backend hesabına yazınız :)"
            },
            "success": False,
            "description": "API bulunamadı"
        }), 404

    api = apis[api_name]
    query_params = {}

    for p in api["params"]:
        val = request.args.get(p)
        if val is None:
            return jsonify({
                "nabiapi_sunar": True,
                "info": {
                    "mesaj": "Hata alırsanız Telegram üzerinden @Nabi_backend hesabına yazınız :)"
                },
                "success": False,
                "description": f"'{p}' parametresi eksik"
            }), 400
        query_params[p] = val

    try:
        headers = {
            "User-Agent": request.headers.get(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
            )
        }

        response = requests.get(api["url"], params=query_params, headers=headers, timeout=15)
        response.raise_for_status()

        if 'application/json' in response.headers.get('Content-Type', ''):
            data = response.json()
        else:
            data = response.text

        if isinstance(data, dict) and "info" in data:
            del data["info"]

        return jsonify({
            "nabiapi_sunar": True,
            "info": {
                "mesaj": "Hata alırsanız Telegram üzerinden @Nabi_backend hesabına yazınız :)"
            },
            "success": True,
            "description": api["desc"],
            "data": data
        })

    except requests.RequestException as e:
        return jsonify({
            "nabiapi_sunar": True,
            "info": {
                "mesaj": "Hata alırsanız Telegram üzerinden @Nabi_backend hesabına yazınız :)"
            },
            "success": False,
            "description": f"API isteği başarısız: {str(e)}"
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
