from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
import mysql.connector
import os
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

def insert_wazuh_log(data: dict):
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
    cursor.execute(query, values)
    cursor.close()
    conn.close()

def upsert_ip_status(ip: str, blocked: int = 0):
    if not ip or ip in ["N/A", None, ""]:
        return
    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO ip_status (ip, is_blocked)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE ip = ip
    """
    cursor.execute(query, (ip, blocked))
    cursor.close()
    conn.close()

@app.post("/webhook/wazuh")
async def receive_wazuh_alert(request: Request):
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

        insert_wazuh_log(clean_alert)
        if attacker_ip not in ["N/A", None, ""]:
            upsert_ip_status(attacker_ip, 0)

        return JSONResponse(status_code=200, content={"status": "success", "alert": clean_alert})

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@app.get("/api/logs")
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

@app.get("/")
def root():
    return {"status": "Wazuh Webhook Running"}
