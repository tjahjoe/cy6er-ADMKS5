import json
import requests
from dotenv import load_dotenv
import os

load_dotenv()

rest_api_key = os.getenv("ONE_SIGNAL_API_KEY")
app_id = os.getenv("ONE_SIGNAL_APP_ID")

if not rest_api_key or not app_id:
    raise ValueError("ONESIGNAL_REST_API_KEY atau ONESIGNAL_APP_ID tidak ditemukan.")

payload = {
    "app_id": app_id,
    "included_segments": ["All"],  
    "headings": {"en": "Test Notif"},
    "contents": {"en": "Halo ini notifikasi dari Python dengan gambar & badge!"},
    "url": "https://upload.wikimedia.org/wikipedia/commons/thumb/b/b3/ASUS_ROG_2007_logo.svg/2048px-ASUS_ROG_2007_logo.svg.png",
    "chrome_web_image": "https://dlcdnrog.asus.com/rog/media/1754608766999.webp",
    "chrome_web_badge": "https://dlcdnrog.asus.com/rog/media/1754608766999.webp",
    "chrome_web_icon": "https://i.imgur.com/9QFB20F_d.webp?maxwidth=760&fidelity=grand"
}

headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Authorization": f"Basic {rest_api_key}"
}

url = "https://onesignal.com/api/v1/notifications"

response = requests.post(url, headers=headers, data=json.dumps(payload))

if response.status_code >= 400:
    print(f"Error Code: {response.status_code}")
    print(f"Error Response: {response.text}")
    raise Exception("Gagal mengirim notifikasi OneSignal.")

print("Response:", response.text)
