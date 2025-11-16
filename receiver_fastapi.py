# save as receiver_fastapi.py
import os
import json
import logging
from typing import Any, Dict, Union

from fastapi import FastAPI, Request, Header, Response
import uvicorn

log = logging.getLogger("webhook")
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

app = FastAPI(title="Webhook Receiver")

@app.post("/email-webhook")
async def email_webhook(
    request: Request,
    x_mailhook_token: Union[str, None] = Header(default=None)  # optional: read shared secret header
) -> Response:
    # Read raw body bytes
    raw = await request.body()

    # Print headers (as a normal dict)
    headers: Dict[str, Any] = dict(request.headers)
    log.info("Headers: %s", headers)

    # Try JSON first, otherwise treat as text (utf-8)
    try:
        body = json.loads(raw)
    except Exception:
        body = raw.decode("utf-8", "ignore")
    log.info("Body: %s", body)

    # Return 204 No Content like the original
    return Response(status_code=204)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    print(f"Webhook receiver on :{port}")
    uvicorn.run("receiver_fastapi:app", host="0.0.0.0", port=port)
