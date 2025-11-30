from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from mysql.connector import Error
from models import SSHLog
import mysql.connector
import asyncio
import json
import requests
import subprocess
from dotenv import load_dotenv
import os

load_dotenv()

rest_api_key = os.getenv("ONE_SIGNAL_API_KEY")
app_id = os.getenv("ONE_SIGNAL_APP_ID")

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="cy6er",
        database="cy6er"
    )

def notification(message):
    payload = {
        "app_id": app_id,
        "included_segments": ["All"],
        "headings": {"en": "Attack"},
        "contents": {"en": message}
    }

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Basic {rest_api_key}"
    }

    response = requests.post(
        "https://onesignal.com/api/v1/notifications",
        headers=headers,
        data=json.dumps(payload)
    )

    print("Notification:", response.text)

def set_ip_status(ip: str):
    """Tambahkan IP ke ip_status jika belum ada."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT ip FROM ip_status WHERE ip = %s", (ip,))
    exists = cursor.fetchone()

    if not exists:
        cursor.execute(
            "INSERT INTO ip_status (ip, is_blocked) VALUES (%s, 0)",
            (ip,)
        )
        conn.commit()

    cursor.close()
    conn.close()


def update_block_status(ip: str):
    """Update ip_status.is_blocked = 1 setelah diblokir."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE ip_status SET is_blocked = 1 WHERE ip = %s", (ip,))
    conn.commit()

    cursor.close()
    conn.close()


def block_ip(ip: str):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        update_block_status(ip)
        notification(f"ip : {ip}\ncontent : Berhasil diblokir")
    except Exception as e:
        print("Error blocking:", e)


def get_last_6_logs(ip: str):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT status FROM ssh_logs
        WHERE ip = %s
        ORDER BY id DESC
        LIMIT 6
    """
    cursor.execute(query, (ip,))
    rows = cursor.fetchall()

    cursor.close()
    conn.close()
    return rows


def insert_log(data: SSHLog):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO ssh_logs (ip, user, status, timestamp)
        VALUES (%s, %s, %s, %s)
    """
    cursor.execute(query, (data.ip, data.user, data.status, data.timestamp))
    conn.commit()

    cursor.close()
    conn.close()


def check_ip(data: SSHLog):
    ip = data.ip

    set_ip_status(ip)

    insert_log(data)

    logs = get_last_6_logs(ip)

    if len(logs) == 6:
        if all(row["status"] == "failed" for row in logs):
            block_ip(ip)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ssh_logs = []
log_queue = asyncio.Queue()


@app.get("/")
def home():
    return {"message": "SSH Log Receiver Running"}


@app.post("/logs")
async def receive_logs(log: SSHLog):

    ssh_logs.append(log.dict())

    check_ip(log)

    print("Log diterima:", log.dict())

    await log_queue.put(log.dict())

    return {"message": "received", "data": log.dict()}


@app.get("/logs")
def get_logs():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT l.ip, l.user, l.status, l.timestamp, s.is_blocked
        FROM ssh_logs l
        LEFT JOIN ip_status s ON l.ip = s.ip
        ORDER BY l.id DESC
        LIMIT 100
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return {"count": len(rows), "data": rows}

@app.post("/block/{ip}")
def manual_block(ip: str):
    block_ip(ip)
    return {"message": f"IP {ip} diblokir secara manual"}


@app.post("/unblock/{ip}")
def manual_unblock(ip: str):
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE ip_status SET is_blocked = 0 WHERE ip = %s", (ip,))
        conn.commit()
        cursor.close()
        conn.close()

        notification(f"ip : {ip}\ncontent : Berhasil di-unblock")

        return {"message": f"IP {ip} telah di-unblock"}

    except Exception as e:
        return {"error": str(e)}


@app.get("/ip-status")
def list_ip_status():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM ip_status ORDER BY ip ASC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

@app.get("/stream")
async def stream_logs(request: Request):

    async def event_generator():
        while True:
            if await request.is_disconnected():
                print("Client SSE terputus")
                break

            data = await log_queue.get()
            yield f"data: {json.dumps(data)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
