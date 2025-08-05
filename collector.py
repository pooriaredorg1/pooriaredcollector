import requests
import base64
import json
import re
import os
import subprocess
import time
import random
from urllib.parse import urlparse, unquote, quote, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- تنظیمات اصلی ---
# لینک‌های اشتراک شما
SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/pooriaredorg1/pooria/refs/heads/main/configs/proxy_configs.txt#POORIA-mixpro%20pooriaredorg1",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs.txt"
]
# آدرس برای تست اتصال و پینگ
PING_TEST_URL = "http://www.gstatic.com/generate_204"
# حداکثر زمان انتظار برای هر تست (ثانیه)
REQUEST_TIMEOUT = 4
# تعداد کارگرها (Threads) برای تست همزمان کانفیگ‌ها
MAX_WORKERS = 100
# نام پیشوند برای تگ‌گذاری کانفیگ‌های نهایی
TAG_PREFIX = "POORIA"
# پورت SOCKS5 محلی که Xray برای تست استفاده می‌کند (یک عدد پایه)
BASE_SOCKS_PORT = 10800

# --- متغیرهای گلوبال ---
ip_location_cache = {}  # برای کش کردن موقعیت جغرافیایی IP ها

def get_geolocation(ip_address):
    """کشور مربوط به IP را با استفاده از API و کش دریافت می‌کند."""
    if ip_address in ip_location_cache:
        return ip_location_cache[ip_address]
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=countryCode", timeout=REQUEST_TIMEOUT, headers=headers)
        if response.status_code == 200:
            country_code = response.json().get("countryCode", "N/A")
            ip_location_cache[ip_address] = country_code
            return country_code
    except requests.RequestException:
        return "N/A"
    return "N/A"

def decode_base64_content(content):
    """محتوای Base64 را با مدیریت خطا دیکود می‌کند."""
    try:
        # اضافه کردن padding در صورت نیاز
        padding = '=' * (4 - len(content) % 4)
        return base64.b64decode(content + padding).decode('utf-8')
    except Exception:
        return None

def fetch_subscription_content(url):
    """محتوای لینک اشتراک را دانلود و دیکود می‌کند."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        
        # تلاش برای دیکود Base64 و در صورت شکست، بازگرداندن محتوای اصلی
        decoded_content = decode_base64_content(content)
        return (decoded_content or content).splitlines()
    except requests.RequestException as e:
        print(f"❌ خطا در دریافت لینک {url.split('#')[0]}: {e}")
        return []

def generate_xray_config(proxy_config, local_port):
    """یک فایل کانفیگ موقت برای Xray بر اساس نوع پروتکل ایجاد می‌کند."""
    try:
        protocol = proxy_config.split("://")[0]
        
        # ساختار پایه کانفیگ Xray
        xray_config = {
            "inbounds": [{
                "port": local_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": { "auth": "noauth", "udp": True }
            }],
            "outbounds": []
        }

        # پارس کردن کانفیگ و ساختن outbound مربوطه
        if protocol == "vmess":
            decoded_str = decode_base64_content(proxy_config.replace("vmess://", ""))
            if not decoded_str: return None
            vmess_data = json.loads(decoded_str)
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": vmess_data.get("add"),
                        "port": int(vmess_data.get("port", 443)),
                        "users": [{"id": vmess_data.get("id"), "alterId": int(vmess_data.get("aid", 0))}]
                    }]
                },
                "streamSettings": {
                    "network": vmess_data.get("net", "tcp"),
                    "security": vmess_data.get("tls", ""),
                    "wsSettings": {"path": vmess_data.get("path")} if vmess_data.get("net") == "ws" else None,
                    "tcpSettings": {"header": {"type": vmess_data.get("type")}} if vmess_data.get("net") == "tcp" else None,
                }
            }
            xray_config["outbounds"].append(outbound)

        elif protocol in ["vless", "trojan"]:
            parsed_url = urlparse(proxy_config)
            params = parse_qs(parsed_url.query)
            outbound = {
                "protocol": protocol,
                "settings": {
                    "vnext": [{
                        "address": parsed_url.hostname,
                        "port": parsed_url.port or 443,
                        "users": [{"id": parsed_url.username}] if protocol == "vless" else [{"password": parsed_url.username}]
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", ["tcp"])[0],
                    "security": params.get("security", ["none"])[0],
                    "tlsSettings": {"serverName": params.get("sni", [parsed_url.hostname])[0]} if params.get("security") == "tls" else None,
                    "wsSettings": {"path": params.get("path", ["/"])[0]} if params.get("type") == ["ws"] else None,
                }
            }
            if protocol == "vless":
                outbound["settings"]["vnext"][0]["users"][0]["flow"] = params.get("flow", [""])[0]
            xray_config["outbounds"].append(outbound)

        else:
            return None # پروتکل پشتیبانی نمی‌شود

        return xray_config

    except Exception:
        return None

def test_config_with_xray(config, worker_id):
    """یک کانفیگ را با استفاده از یک نمونه Xray واقعی تست می‌کند."""
    local_port = BASE_SOCKS_PORT + worker_id
    config_file_path = f"temp_config_{worker_id}.json"
    xray_proc = None

    try:
        # ۱. ساخت فایل کانفیگ Xray
        xray_json_config = generate_xray_config(config, local_port)
        if not xray_json_config:
            return None

        with open(config_file_path, 'w') as f:
            json.dump(xray_json_config, f)

        # ۲. اجرای Xray به عنوان یک فرآیند جداگانه
        xray_proc = subprocess.Popen(['./xray', '-c', config_file_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5) # زمان برای بالا آمدن Xray

        # ۳. تست اتصال از طریق پراکسی SOCKS5 محلی
        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}
        start_time = time.time()
        response = requests.get(PING_TEST_URL, proxies=proxies, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 204:
            latency = int((time.time() - start_time) * 1000)
            
            # دریافت موقعیت جغرافیایی
            server_ip = urlparse(config).hostname
            location = get_geolocation(server_ip)
            
            print(f"✅ کانفیگ سالم: {config[:30]}... | پینگ: {latency}ms | موقعیت: {location}")
            return {"config": config, "latency": latency, "location": location}

    except (requests.RequestException, subprocess.SubprocessError):
        return None
    finally:
        # ۴. خاتمه دادن به فرآیند Xray و پاک کردن فایل موقت
        if xray_proc:
            xray_proc.kill()
        if os.path.exists(config_file_path):
            os.remove(config_file_path)
            
    return None

def rename_config(config, new_name):
    """نام (fragment/#) کانفیگ را با نام جدید جایگزین می‌کند."""
    try:
        # برای VMess که Base64 است
        if config.startswith("vmess://"):
            decoded_str = decode_base64_content(config.replace("vmess://", ""))
            if not decoded_str: return config # اگر دیکود نشد، همان را برگردان
            vmess_data = json.loads(decoded_str)
            vmess_data['ps'] = new_name
            encoded_str = base64.b64encode(json.dumps(vmess_data, separators=(',', ':')).encode()).decode()
            return f"vmess://{encoded_str}"
        
        # برای VLESS, Trojan, SS
        else:
            # جدا کردن بخش اصلی از fragment
            base_url = config.split("#")[0]
            return f"{base_url}#{quote(new_name)}"
            
    except Exception:
        # در صورت بروز هرگونه خطا، نام جدید را به انتهای لینک اضافه کن
        return f"{config.split('#')[0]}#{quote(new_name)}"

def main():
    print("🚀 شروع فرآیند جمع‌آوری و تست واقعی کانفیگ‌ها...")
    all_configs = set()

    # مرحله ۱: دریافت کانفیگ‌ها از تمام لینک‌ها
    for url in SUBSCRIPTION_URLS:
        configs = fetch_subscription_content(url)
        print(f"📥 {len(configs)} کانفیگ از {url.split('#')[0]} دریافت شد.")
        for config in configs:
            if config.strip() and any(proto in config for proto in ["vless://", "vmess://", "trojan://"]):
                all_configs.add(config.strip())

    print(f"\n🔬 {len(all_configs)} کانفیگ یکتا برای تست یافت شد. شروع تست واقعی با Xray...")

    # مرحله ۲: تست همزمان کانفیگ‌ها با Xray
    working_configs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_config = {executor.submit(test_config_with_xray, config, i): config for i, config in enumerate(list(all_configs))}
        for future in as_completed(future_to_config):
            result = future.result()
            if result:
                working_configs.append(result)

    print(f"\n🏁 تست کامل شد. {len(working_configs)} کانفیگ ۱۰۰٪ سالم یافت شد.")

    if not working_configs:
        print("هیچ کانفیگ سالمی یافت نشد. خروج.")
        return

    # مرحله ۳: مرتب‌سازی بر اساس کمترین پینگ
    working_configs.sort(key=lambda x: x['latency'])

    # مرحله ۴: تغییر نام و ساخت لیست نهایی
    final_configs_list = []
    for i, item in enumerate(working_configs):
        new_name = f"{TAG_PREFIX}{i+1} | {item['location']} | {item['latency']}ms"
        renamed_config = rename_config(item['config'], new_name)
        final_configs_list.append(renamed_config)

    # مرحله ۵: ذخیره خروجی‌ها
    final_sub_content = "\n".join(final_configs_list)
    final_sub_base64 = base64.b64encode(final_sub_content.encode()).decode()

    with open("sub.txt", "w") as f:
        f.write(final_sub_content)
    with open("sub_base64.txt", "w") as f:
        f.write(final_sub_base64)

    print("\n" + "="*40)
    print("✅ فرآیند با موفقیت به پایان رسید.")
    print(f"📄 {len(final_configs_list)} کانفیگ سالم در فایل‌های sub.txt و sub_base64.txt ذخیره شد.")
    print("🔗 می‌توانید از لینک raw این فایل‌ها به عنوان لینک اشتراک استفاده کنید.")
    print("="*40)

if __name__ == "__main__":
    if not os.path.exists('./xray'):
        print("❌ فایل اجرایی xray یافت نشد! لطفاً ابتدا آن را در کنار اسکریپت قرار دهید.")
        print("   در GitHub Action این کار به صورت خودکار انجام می‌شود.")
    else:
        main()

