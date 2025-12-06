from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
import logging

app = FastAPI(title="Wazuh Webhook - Raw CTX Only")

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("wazuh_webhook")

ctx_storage = []  # Menyimpan semua ctx yang diterima

@app.post("/webhook/wazuh")
async def receive_wazuh_ctx(request: Request):
    raw_body = await request.body()
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        logger.error("Invalid JSON received")
        return JSONResponse(
            status_code=200,
            content={"status": "failed", "message": "Invalid JSON"}
        )

    # Ambil field 'raw' dari payload
    ctx_raw = payload.get("raw", payload)

    # Simpan ke memory
    ctx_storage.append(ctx_raw)

    # Tampilkan di terminal
    logger.info("===== CTX DARI WAZUH =====")
    logger.info(json.dumps(ctx_raw, indent=2))

    # Kembalikan response JSON
    return JSONResponse(
        status_code=200,
        content={"status": "success", "raw": ctx_raw}
    )

@app.get("/ctx")
def get_all_ctx():
    return {"total": len(ctx_storage), "data": ctx_storage}

@app.get("/")
def root():
    return {"status": "Wazuh Webhook Running - Raw CTX Mode"}
