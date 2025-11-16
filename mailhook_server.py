
#!/usr/bin/env python3
"""
A tiny SMTP server that triggers an HTTP request for every received email.

Features
- Async SMTP server with aiosmtpd
- Parses message with email.policy.default
- Extracts plain text + HTML + basic headers
- Posts JSON to a configurable webhook
- Optional shared-secret header
- Optional TLS (STARTTLS) if cert/key provided
- Graceful logging & retries (exponential backoff)
"""
import argparse
import asyncio
import json
import logging
import ssl
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

import httpx
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer
from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage

LOG = logging.getLogger("mailhook")


def _extract_bodies(msg: EmailMessage) -> Tuple[Optional[str], Optional[str]]:
    """Return (text_body, html_body) if present."""
    text_body = None
    html_body = None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and text_body is None:
                try:
                    text_body = part.get_content()
                except Exception:
                    pass
            elif ctype == "text/html" and html_body is None:
                try:
                    html_body = part.get_content()
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            text_body = msg.get_content()
        elif ctype == "text/html":
            html_body = msg.get_content()

    return text_body, html_body


class WebhookHandler:
    def __init__(
        self,
        webhook_url: str,
        token: Optional[str] = None,
        timeout_s: float = 8.0,
        verify_tls: bool = True,
        max_retry: int = 4,
        retry_base_seconds: float = 0.75,
        extra_headers: Optional[Dict[str, str]] = None,
        allow_any_recipient: bool = True,
        allowed_rcpt_domains: Optional[list[str]] = None,
    ):
        self.webhook_url = webhook_url
        self.token = token
        self.timeout_s = timeout_s
        self.verify_tls = verify_tls
        self.max_retry = max_retry
        self.retry_base_seconds = retry_base_seconds
        self.extra_headers = extra_headers or {}
        self.allow_any_recipient = allow_any_recipient
        self.allowed_rcpt_domains = set(allowed_rcpt_domains or [])

        self._client = httpx.AsyncClient(timeout=self.timeout_s, verify=self.verify_tls)

    async def close(self):
        await self._client.aclose()

    async def _post_with_retry(self, payload: Dict[str, Any]) -> None:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Mailhook-Token"] = self.token
        headers.update(self.extra_headers)

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retry + 1):
            try:
                resp = await self._client.post(
                    self.webhook_url, headers=headers, content=json.dumps(payload)
                )
                if resp.status_code < 500:
                    # Consider <500 a final outcome (2xx/4xx)
                    if 200 <= resp.status_code < 300:
                        LOG.info("Webhook delivered (%s)", resp.status_code)
                    else:
                        LOG.warning(
                            "Webhook responded with non-2xx (%s): %s",
                            resp.status_code,
                            resp.text[:500],
                        )
                    return
                else:
                    # 5xx -> retry
                    raise httpx.HTTPStatusError(
                        f"Server error {resp.status_code}", request=resp.request, response=resp
                    )
            except Exception as e:
                last_exc = e
                delay = (2 ** attempt) * self.retry_base_seconds
                if attempt < self.max_retry:
                    LOG.warning("Webhook attempt %d failed: %s; retrying in %.2fs", attempt + 1, e, delay)
                    await asyncio.sleep(delay)
                else:
                    LOG.error("Webhook delivery failed after %d attempts: %s", attempt + 1, e)
        if last_exc:
            raise last_exc

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if self.allow_any_recipient:
            envelope.rcpt_tos.append(address)
            return "250 OK"

        # Restrict by recipient domain if configured
        try:
            domain = address.split("@", 1)[1].lower()
        except Exception:
            return "550 Invalid recipient"
        if domain in self.allowed_rcpt_domains:
            envelope.rcpt_tos.append(address)
            return "250 OK"
        return "550 Recipient domain not allowed"

    async def handle_DATA(self, server, session, envelope):
        try:
            # Check if content is bytes or string and parse accordingly
            if isinstance(envelope.content, bytes):
                msg = BytesParser(policy=policy.default).parsebytes(envelope.content)
            else:
                # Content is already decoded as string, use Parser instead
                msg = Parser(policy=policy.default).parsestr(envelope.content)
        except Exception as e:
            LOG.exception("Failed to parse message: %s", e)
            return "550 Failed to parse message"

        text_body, html_body = _extract_bodies(msg)

        payload = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "peer": session.peer,  # (ip, port)
            "mail_from": envelope.mail_from,
            "rcpt_tos": envelope.rcpt_tos,
            "headers": {k: v for (k, v) in msg.items()},
            "subject": msg.get("Subject", ""),
            "message_id": msg.get("Message-Id", ""),
            "in_reply_to": msg.get("In-Reply-To", ""),
            "references": msg.get("References", ""),
            "from": msg.get("From", ""),
            "to": msg.get("To", ""),
            "cc": msg.get("Cc", ""),
            "bcc": msg.get("Bcc", ""),
            "text": text_body,
            "html": html_body,
            "raw_size_bytes": len(envelope.content),
        }

        try:
            await self._post_with_retry(payload)
        except Exception as e:
            # We accept the mail (return 250) to avoid bouncing/loops, but log failure.
            LOG.error("Error posting webhook: %s", e)

        return "250 Message accepted"

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        LOG.info("MAIL FROM: %s; peer=%s", address, session.peer)
        envelope.mail_from = address
        return "250 OK"



    async def handle_NOOP(self, server, session, envelope):
        return "250 OK"

    async def handle_QUIT(self, server, session, envelope):
        LOG.info("QUIT received from %s", session.peer)
        return "221 Bye"

    async def handle_RSET(self, server, session, envelope):
        LOG.info("RSET received from %s", session.peer)
        return "250 OK"


def build_tls_context(certfile: Optional[str], keyfile: Optional[str]) -> Optional[ssl.SSLContext]:
    if not certfile or not keyfile:
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def main():
    parser = argparse.ArgumentParser(description="Email → Webhook SMTP server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=2525, help="Listen port (default: 2525)")
    parser.add_argument("--webhook-url", required=True, help="HTTP(S) endpoint to POST JSON to")
    parser.add_argument("--token", default=None, help="Shared secret sent as X-Mailhook-Token header")
    parser.add_argument("--timeout", type=float, default=8.0, help="Webhook timeout seconds")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification for webhook (not recommended)")
    parser.add_argument("--max-retry", type=int, default=4, help="Max webhook retries (default 4)")
    parser.add_argument("--retry-base", type=float, default=0.75, help="Base seconds for exponential backoff")
    parser.add_argument("--header", action="append", default=[], help="Extra header for webhook, format: Key=Value (can repeat)")
    parser.add_argument("--tls-cert", default=None, help="Path to TLS cert (enables STARTTLS)")
    parser.add_argument("--tls-key", default=None, help="Path to TLS key (enables STARTTLS)")
    parser.add_argument("--allowed-rcpt-domain", action="append", default=[], help="Restrict RCPT TO to these domains (can repeat)")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    extra_headers = {}
    for h in args.header:
        if "=" not in h:
            LOG.error("Invalid --header %r (need Key=Value)", h)
            sys.exit(2)
        k, v = h.split("=", 1)
        extra_headers[k.strip()] = v.strip()

    handler = WebhookHandler(
        webhook_url=args.webhook_url,
        token=args.token,
        timeout_s=args.timeout,
        verify_tls=not args.no_verify_tls,
        max_retry=args.max_retry,
        retry_base_seconds=args.retry_base,
        extra_headers=extra_headers,
        allow_any_recipient=(len(args.allowed_rcpt_domain) == 0),
        allowed_rcpt_domains=args.allowed_rcpt_domain or None,
    )

    tls_context = build_tls_context(args.tls_cert, args.tls_key)

    class _Controller(Controller):
        # Enables STARTTLS if tls_context present
        def factory(self):
            return SMTPServer(
                handler, 
                require_starttls=bool(tls_context), 
                tls_context=tls_context,
                decode_data=True,
                enable_SMTPUTF8=True
            )

    controller = _Controller(handler, hostname=args.host, port=args.port)
    LOG.info("Starting SMTP server on %s:%s", args.host, args.port)
    controller.start()

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down…")
    finally:
        controller.stop()
        asyncio.get_event_loop().run_until_complete(handler.close())


if __name__ == "__main__":
    main()
