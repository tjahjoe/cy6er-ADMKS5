import os
import json
import asyncio
import subprocess
from typing import Any, Dict, List
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import mysql.connector
from dotenv import load_dotenv
import requests

from models import SSHLog

print("MAIN VERSION TERBARU JALAN")

load_dotenv()
ONE_SIGNAL_API_KEY = os.getenv("ONE_SIGNAL_API_KEY")
ONE_SIGNAL_APP_ID = os.getenv("ONE_SIGNAL_APP_ID")

def normalize_ip(ip: str) -> str:
    if not isinstance(ip, str):
        ip = str(ip)
    ip = ip.strip()
    if ip.startswith("::ffff:"):
        ip = ip.replace("::ffff:", "")
    return ip

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", "cy6er"),
        database=os.getenv("DB_NAME", "cy6er"),
        autocommit=True
    )

def safe_get(d, path, default="N/A"):
    try:
        for key in path.split("."):
            if isinstance(d, list):
                key = int(key)
            d = d[key]
        if d in ["", None]:
            return default
        return d
    except:
        return default
    
def format_timestamp_for_mysql(ts: str) -> str:
    if not ts or ts in ["", "N/A", None]:
        return None
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return ts

def _set_ip_status_db_blocking(ip: str) -> bool:
    """
    Insert IP if belum ada. Return True jika benar-benar baru.
    Menggunakan INSERT IGNORE + rowcount untuk menghindari race condition.
    """
    ip = normalize_ip(ip)
    conn = get_connection()
    cursor = conn.cursor()
    is_new = False
    try:
        cursor.execute(
            "INSERT IGNORE INTO ip_status (ip, is_blocked) VALUES (%s, 0)",
            (ip,)
        )

        if cursor.rowcount == 1:
            is_new = True

        try:
            conn.commit()
        except Exception:
            pass
    except Exception as e:
        print("[ERROR] _set_ip_status_db_blocking:", e)
    finally:
        cursor.close()
        conn.close()
    return is_new

async def set_ip_status_db(ip: str):
    try:
        is_new = await asyncio.to_thread(_set_ip_status_db_blocking, ip)
        if is_new:
            await send_notification(f"IP baru terdeteksi:\n{normalize_ip(ip)}")
    except Exception as e:
        print("[ERROR] set_ip_status_db:", e)

def _update_block_status_db_blocking(ip: str, blocked: int):
    ip = normalize_ip(ip)
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE ip_status SET is_blocked = %s WHERE ip = %s", (blocked, ip))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

async def update_block_status_db(ip: str, blocked: int):
    await asyncio.to_thread(_update_block_status_db_blocking, ip, blocked)

def _insert_log_db_blocking(data: Dict):
    """
    Hanya memasukkan record ke ssh_logs.
    Jangan lagi meng-insert ke ip_status di sini (agar set_ip_status_db menjadi sumber kebenaran).
    """
    ip = normalize_ip(data.get("ip", ""))
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = """
            INSERT INTO ssh_logs (ip, user, status, timestamp)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (
            ip,
            data.get("user"),
            data.get("status"),
            data.get("timestamp")
        ))
        conn.commit()
    except Exception as e:
        print("[ERROR] _insert_log_db_blocking:", e)
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cursor.close()
        conn.close()

def _insert_wazuh_log_blocking(data: Dict):
    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO wazuh_logs 
        (rule_id, rule_desc, severity, target, agent_ip, attacker_ip, log_raw, timestamp, monitor)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    values = (
        data.get("rule_id"),
        data.get("rule_desc"),
        data.get("severity"),
        data.get("target"),
        data.get("agent_ip"),
        data.get("attacker_ip"),
        data.get("log_raw"),
        data.get("timestamp"),
        data.get("monitor")
    )
    try:
        cursor.execute(query, values)
        conn.commit()
    except Exception as e:
        print("[ERROR] _insert_wazuh_log_blocking:", e)
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cursor.close()
        conn.close()

async def insert_log_db(data: Dict):
    await asyncio.to_thread(_insert_log_db_blocking, data)

async def insert_wazuh_log(data: Dict):
    await asyncio.to_thread(_insert_wazuh_log_blocking, data)

def _get_last_n_statuses_blocking(ip: str, n: int = 6):
    ip = normalize_ip(ip)
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT status FROM ssh_logs WHERE ip = %s ORDER BY id DESC LIMIT %s"
        cursor.execute(query, (ip, n))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

async def get_last_n_statuses(ip: str, n: int = 6):
    return await asyncio.to_thread(_get_last_n_statuses_blocking, ip, n)

def _get_all_ip_status_blocking():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM ip_status ORDER BY ip ASC")
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

async def get_all_ip_status():
    return await asyncio.to_thread(_get_all_ip_status_blocking)

def _get_recent_logs_blocking(limit=100):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT l.ip, l.user, l.status, l.timestamp
            FROM ssh_logs l
            LEFT JOIN ip_status s ON l.ip = s.ip
            ORDER BY l.timestamp
            LIMIT %s
        """
        cursor.execute(query, (limit,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

async def get_recent_logs(limit=100):
    return await asyncio.to_thread(_get_recent_logs_blocking, limit)

def _send_notification_blocking(message: str):
    if not ONE_SIGNAL_API_KEY or not ONE_SIGNAL_APP_ID:
        print("OneSignal not configured, skip notify")
        return
    payload = {
        "app_id": ONE_SIGNAL_APP_ID,
        "included_segments": ["All"],
        "headings": {"en": "Attack"},
        "contents": {"en": message}
    }
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Basic {ONE_SIGNAL_API_KEY}"
    }
    try:
        resp = requests.post("https://onesignal.com/api/v1/notifications", headers=headers, json=payload, timeout=10)
        print("Notification:", resp.status_code, resp.text)
    except Exception as e:
        print("Notification error:", e)

async def send_notification(message: str):
    await asyncio.to_thread(_send_notification_blocking, message)

def _is_ip_blocked_iptables_blocking(ip: str) -> bool:
    ip = normalize_ip(ip)
    try:
        subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def _block_ip_iptables_blocking(ip: str) -> None:
    ip = normalize_ip(ip)
    if not _is_ip_blocked_iptables_blocking(ip):
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)

def _unblock_ip_iptables_blocking(ip: str) -> None:
    ip = normalize_ip(ip)
    while True:
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            break

async def is_ip_blocked_iptables(ip: str) -> bool:
    return await asyncio.to_thread(_is_ip_blocked_iptables_blocking, ip)

async def block_ip_iptables(ip: str) -> None:
    return await asyncio.to_thread(_block_ip_iptables_blocking, ip)

async def unblock_ip_iptables(ip: str) -> None:
    return await asyncio.to_thread(_unblock_ip_iptables_blocking, ip)

clients: List[asyncio.Queue] = []

async def push_event(event_type: str, data: Any):
    payload = {"type": event_type, "data": data}
    for q in clients.copy():
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            print("client queue full, dropping event for a client")

async def async_block_ip_workflow(ip: str):
    try:
        await set_ip_status_db(ip)
        await block_ip_iptables(ip)
        await update_block_status_db(ip, 1)
        ip_rows = await get_all_ip_status()
        await push_event("ip_status", ip_rows)
        await send_notification(f"ip : {ip}\ncontent : Berhasil diblokir")
        print(f"[BLOCK] {ip} blocked and broadcasted")
    except Exception as e:
        print("Error in async_block_ip_workflow:", e)
        await push_event("system", {"message": f"Error blocking {ip}: {str(e)}"})

async def async_unblock_ip_workflow(ip: str):
    try:
        await unblock_ip_iptables(ip)
        await update_block_status_db(ip, 0)
        ip_rows = await get_all_ip_status()
        await push_event("ip_status", ip_rows)
        await send_notification(f"ip : {ip}\ncontent : Berhasil di-unblock")
        print(f"[UNBLOCK] {ip} unblocked and broadcasted")
    except Exception as e:
        print("Error in async_unblock_ip_workflow:", e)
        await push_event("system", {"message": f"Error unblocking {ip}: {str(e)}"})

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "SSH Log Receiver Running"}

@app.post("/logs")
async def receive_logs(log: SSHLog):
    log_dict = log.dict()
    log_dict["ip"] = normalize_ip(log_dict.get("ip", ""))

    try:
        await set_ip_status_db(log_dict["ip"])
        await insert_log_db(log_dict)
        statuses = await get_last_n_statuses(log_dict["ip"], 6)
        if len(statuses) == 6 and all(r["status"] == "failed" for r in statuses):
            asyncio.create_task(async_block_ip_workflow(log_dict["ip"]))

        await push_event("log", log_dict)
        ip_rows = await get_all_ip_status()
        await push_event("ip_status", ip_rows)

        print("Log diterima:", log_dict)
        return {"message": "received", "data": log_dict}
    except Exception as e:
        print("[ERROR] receive_logs:", e)
        return JSONResponse({"message": "error", "detail": str(e)}, status_code=500)

@app.get("/logs")
async def get_logs():
    rows = await get_recent_logs(limit=100)
    return {"count": len(rows), "data": rows}

@app.post("/block/{ip}")
async def manual_block(ip: str):
    ip = normalize_ip(ip)
    asyncio.create_task(async_block_ip_workflow(ip))
    return JSONResponse({"message": f"IP {ip} blocking scheduled"}, status_code=202)

@app.post("/unblock/{ip}")
async def manual_unblock(ip: str):
    ip = normalize_ip(ip)
    asyncio.create_task(async_unblock_ip_workflow(ip))
    return JSONResponse({"message": f"IP {ip} unblock scheduled"}, status_code=202)

@app.get("/ip-status")
async def list_ip_status():
    rows = await get_all_ip_status()
    return rows

@app.post("/webhook/wazuh")
async def receive_wazuh_webhook(request: Request):
    try:
        raw_body = await request.body()
        try:
            payload = json.loads(raw_body)
        except:
            return JSONResponse(
                status_code=200,
                content={"status": "failed", "message": "Invalid JSON"}
            )
        
        data = payload.get("alert_data", {})
        
        rule_id = (
            data.get("rule_id")
            or safe_get(payload, "alert.rule.id")
            or safe_get(payload, "results.0.hits.hits.0._source.rule.id")
        )
        rule_desc = (
            data.get("rule_desc")
            or safe_get(payload, "alert.rule.description")
            or safe_get(payload, "results.0.hits.hits.0._source.rule.description")
        )
        severity = (
            data.get("severity")
            or safe_get(payload, "alert.rule.level", 0)
            or safe_get(payload, "results.0.hits.hits.0._source.rule.level", 0)
        )
        target = (
            data.get("target_server")
            or safe_get(payload, "alert.agent.name")
            or safe_get(payload, "results.0.hits.hits.0._source.agent.name")
        )
        agent_ip = (
            data.get("agent_ip")
            or safe_get(payload, "alert.agent.ip")
            or safe_get(payload, "results.0.hits.hits.0._source.agent.ip")
        )
        attacker_ip = (
            data.get("ip_penyerang")
            or safe_get(payload, "alert.data.srcip")
            or safe_get(payload, "results.0.hits.hits.0._source.data.srcip")
        )
        log_raw = (
            data.get("log_mentah")
            or safe_get(payload, "alert.full_log")
            or safe_get(payload, "results.0.hits.hits.0._source.full_log")
        )
        timestamp = (
            data.get("timestamp_alert")
            or safe_get(payload, "alert.timestamp")
            or safe_get(payload, "results.0.hits.hits.0._source.@timestamp")
        )
        timestamp = format_timestamp_for_mysql(timestamp)
        monitor = data.get("monitor_name") or "parrot"

        clean_alert = {
            "rule_id": rule_id,
            "rule_desc": rule_desc,
            "severity": severity,
            "target": target,
            "agent_ip": agent_ip,
            "attacker_ip": attacker_ip,
            "log_raw": log_raw,
            "timestamp": timestamp,
            "monitor": monitor
        }

        await insert_wazuh_log(clean_alert)
        if attacker_ip not in ["N/A", None, ""]:
            await set_ip_status_db(attacker_ip)

        return JSONResponse(status_code=200, content={"status": "success", "alert": clean_alert})

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@app.get("/wazuh/logs")
def api_logs(limit: int = 100):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT w.id, w.rule_id, w.rule_desc, w.severity, w.target,
               w.agent_ip, w.attacker_ip, w.log_raw, w.timestamp, w.monitor,
               IFNULL(i.is_blocked, 0) AS is_blocked
        FROM wazuh_logs w
        LEFT JOIN ip_status i ON w.attacker_ip = i.ip
        ORDER BY w.id DESC
        LIMIT %s
    """
    cursor.execute(query, (limit,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return {"total": len(rows), "data": rows}

@app.get("/stream")
async def stream_logs(request: Request):
    """
    Each client gets its own asyncio.Queue. push_event broadcasts to all client queues.
    """
    client_q: asyncio.Queue = asyncio.Queue(maxsize=100)
    clients.append(client_q)

    try:
        ip_rows = await get_all_ip_status()
        try:
            client_q.put_nowait({"type": "ip_status", "data": ip_rows})
        except asyncio.QueueFull:
            print("client queue full on initial push")
    except Exception:
        pass

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    print("Client disconnected")
                    break
                try:
                    event = await client_q.get()
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    print("Error while getting event for client:", e)
                    await asyncio.sleep(0.1)
        finally:
            try:
                clients.remove(client_q)
            except ValueError:
                pass

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})
