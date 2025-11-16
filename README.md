
# Mailhook SMTP → Webhook

A tiny SMTP server (Python) that posts every received email to an HTTP webhook.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python mailhook_server.py \
  --webhook-url "http://localhost:8080/email-webhook" \
  --token "supersecret" \
  --port 2525 \
  --log-level DEBUG
```

Test with `swaks`:
```bash
swaks --to you@example.com \
      --from test@sender.net \
      --server 127.0.0.1:2525 \
      --data "Subject: Hello\n\nThis is a test."
```

Run a simple webhook receiver (for testing):
```bash
python webhook_receiver.py 8080
```

## Docker

```bash
docker build -t mailhook .
docker run --rm -p 2525:2525 mailhook
```

## TLS (STARTTLS)

Provide both `--tls-cert` and `--tls-key` to enable STARTTLS. You can also terminate TLS upstream.

## Security

- Protect your webhook with `--token` (sent as `X-Mailhook-Token`).
- Restrict recipients with `--allowed-rcpt-domain example.com` (repeatable).
- Prefer HTTPS webhooks; avoid `--no-verify-tls` in production.
