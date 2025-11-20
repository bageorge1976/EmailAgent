# save as receiver_fastapi.py  
import io
import contextlib
import os
import json
import logging
import asyncio
from typing import Any, Dict, Union

from fastapi import FastAPI, Request, Header, Response
import uvicorn

import os
#from kaggle_secrets import UserSecretsClient

# Import ADK components (silently during module load)
try:
    from google.adk.agents import Agent
    from google.adk.runners import InMemoryRunner
    from google.adk.tools import google_search
    from google.genai import types
except ImportError as e:
    print(f"❌ ADK Import Error: {e}")
    raise

# Initialize runner only once
runner = None

def get_runner():
    global runner
    if runner is None:
        # Set up Google GenAI configuration (only once)
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "FALSE"
        print("✅ Google GenAI configuration set.")
        print("✅ ADK components imported successfully.")
        
        root_agent = Agent(
            name="helpful_assistant",
            model="gemini-2.5-flash-lite",
            description="A simple agent that can answer general questions.",
            instruction="You are a helpful assistant. Use Google Search for current info or if unsure.",
            tools=[google_search],
        )
        print("✅ Root Agent defined.")
        
        runner = InMemoryRunner(agent=root_agent, app_name="agents")
        print("✅ Runner created.")
    return runner


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
    log.info("Text from Body: %s", body["text"])

    # Process the text with Google ADK agent
    try:
        # Get the runner (creates it only once)
        current_runner = get_runner()
        
        # Use run_debug with the prompt
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            events = await current_runner.run_debug(body["text"])

        # Take the last event and extract plain text from its parts
        if events:
            last_event = events[-1]
            agent_text = "".join(
                (getattr(part, "text", "") or "")
                for part in last_event.content.parts
            )
            log.info("Agent response: %s", agent_text)
        else:
            log.warning("No events received from ADK runner")
            
    except Exception as e:
        log.error("ADK processing error: %s", str(e))

    # Return 204 No Content like the original
    return Response(status_code=204)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    print(f"Webhook receiver on :{port}")
    uvicorn.run("receiver_fastapi:app", host="0.0.0.0", port=port, reload=False)
