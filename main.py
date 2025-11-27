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

    response = requests.post("https://onesignal.com/api/v1/notifications",
                             headers=headers, data=json.dumps(payload))

    print("Notification:", response.text)


def block_ip(ip: str):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        notification(f"ip : {ip}\ncontent : Berhasil diblokir")
    except:
        pass


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


def ip_not_exists(ip: str):
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT COUNT(*) FROM ssh_logs WHERE ip = %s"
    cursor.execute(query, (ip,))
    (count,) = cursor.fetchone()

    cursor.close()
    conn.close()
    return count == 0


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

    if ip_not_exists(ip):
        notification(f"ip : {ip}\ncontent : Waspada IP baru")
    else:
        logs = get_last_6_logs(ip)

        if len(logs) == 6:
            if all(row["status"] == "failed" for row in logs):
                block_ip(ip)

    insert_log(data)


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

    query = "SELECT ip, user, status, timestamp FROM ssh_logs ORDER BY id DESC LIMIT 100"
    cursor.execute(query)
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return {"count": len(rows), "data": rows}



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
