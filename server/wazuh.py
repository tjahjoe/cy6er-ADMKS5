from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json

app = FastAPI(title="Wazuh Webhook Receiver - Clean Mode")

alert_storage = []


def safe_get(d, path, default="N/A"):
    """Ambil nested dict value dengan aman: 'a.b.c' """
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

        if "raw" in payload:
            data["raw_ctx"] = payload["raw"]

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

        monitor = (
            data.get("monitor_name")
            or safe_get(payload, "monitor.name")
            or "unknown"
        )

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

        alert_storage.append(clean_alert)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "alert": clean_alert
            }
        )

    except Exception:
        return JSONResponse(
            status_code=500,
            content={"status": "error"}
        )


@app.get("/alerts")
def get_alerts():
    return {
        "total": len(alert_storage),
        "data": alert_storage
    }


@app.get("/")
def root():
    return {"status": "Wazuh Webhook Running"}
