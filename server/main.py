import os
import json
import asyncio
import subprocess
from typing import Any, Dict, List

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

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", "cy6er"),
        database=os.getenv("DB_NAME", "cy6er"),
    )

def _set_ip_status_db_blocking(ip: str):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT ip FROM ip_status WHERE ip = %s", (ip,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO ip_status (ip, is_blocked) VALUES (%s, 0)", (ip,))
            conn.commit()
    finally:
        cursor.close()
        conn.close()

async def set_ip_status_db(ip: str):
    await asyncio.to_thread(_set_ip_status_db_blocking, ip)

def _update_block_status_db_blocking(ip: str, blocked: int):
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
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT INTO ssh_logs (ip, user, status, timestamp) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (data["ip"], data["user"], data["status"], data["timestamp"]))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

async def insert_log_db(data: Dict):
    await asyncio.to_thread(_insert_log_db_blocking, data)

def _get_last_n_statuses_blocking(ip: str, n: int = 6):
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
    try:
        subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def _block_ip_iptables_blocking(ip: str) -> None:
    if not _is_ip_blocked_iptables_blocking(ip):
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)

def _unblock_ip_iptables_blocking(ip: str) -> None:
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
    await insert_log_db(log_dict)
    await set_ip_status_db(log.ip)

    statuses = await get_last_n_statuses(log.ip, 6)
    if len(statuses) == 6 and all(r["status"] == "failed" for r in statuses):
        asyncio.create_task(async_block_ip_workflow(log.ip))

    await push_event("log", log_dict)
    print("Log diterima:", log_dict)
    return {"message": "received", "data": log_dict}

@app.get("/logs")
async def get_logs():
    rows = await get_recent_logs(limit=100)
    return {"count": len(rows), "data": rows}

@app.post("/block/{ip}")
async def manual_block(ip: str):
    asyncio.create_task(async_block_ip_workflow(ip))
    return JSONResponse({"message": f"IP {ip} blocking scheduled"}, status_code=202)

@app.post("/unblock/{ip}")
async def manual_unblock(ip: str):
    asyncio.create_task(async_unblock_ip_workflow(ip))
    return JSONResponse({"message": f"IP {ip} unblock scheduled"}, status_code=202)

@app.get("/ip-status")
async def list_ip_status():
    rows = await get_all_ip_status()
    return rows

@app.get("/stream")
async def stream_logs(request: Request):
    """
    Each client gets its own asyncio.Queue. push_event broadcasts to all client queues.
    """
    client_q: asyncio.Queue = asyncio.Queue(maxsize=100)  
    clients.append(client_q)

    try:
        ip_rows = await get_all_ip_status()
        client_q.put_nowait({"type": "ip_status", "data": ip_rows})
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
