from systemd import journal
import requests
import re
from datetime import datetime

SERVER_URL = "http://127.0.0.1:8000/logs"  

pattern = re.compile(
    r"(Failed|Accepted) password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def send_event(ip, user, status):
    data = {
        "ip": ip,
        "user": user,
        "status": status.lower(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        r = requests.post(SERVER_URL, json=data, timeout=2)
        print("Sent:", data, "Response:", r.status_code)
    except Exception as e:
        print("Error sending:", e)

def main():
    j = journal.Reader()
    j.log_level(journal.LOG_INFO)
    j.add_match(_SYSTEMD_UNIT="ssh.service")
    j.seek_tail()     
    j.get_previous()   

    print("Monitoring SSH logs...")

    while True:
        j.wait(1000)  
        for entry in j:
            message = entry.get("MESSAGE", "")
            match = pattern.search(message)

            if match:
                status = "failed" if "Failed" in message else "success"
                ip = match.group("ip")
                user = match.group("user")
                send_event(ip, user, status)

if __name__ == "__main__":
    main()
