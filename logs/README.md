# LoKey logs — barebones starter

A minimal Python service for the **Person 3: Log, alerts & web** workstream:
append-only JSONL events, a Merkle root, an Ed25519-signed tree head,
and inclusion-proof endpoints.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The service listens on `http://127.0.0.1:5000`. Data and the generated signing
key are stored in `./data/`.

## Try it

```bash
curl -X POST http://127.0.0.1:5000/events \
  -H 'Content-Type: application/json' \
  -d '{"domain":"victim.test","change":"DS_REPLACED","risk":"high","reasons":["demo event"]}'

curl http://127.0.0.1:5000/events
curl http://127.0.0.1:5000/tree-head
curl http://127.0.0.1:5000/proof/0
```

## Tests

```bash
pytest
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/events` | Append one event JSON object |
| GET | `/events` | List stored events |
| GET | `/tree-head` | Current root, tree size and Ed25519 signature |
| GET | `/proof/<index>` | Event plus Merkle inclusion path |

## Event format

The collector can POST the shared event object, for example:

```json
{
  "domain": "victim.test",
  "observed_at": "2026-11-14T10:32:05Z",
  "change": "DS_REPLACED",
  "ns_before": ["ns1.provider.test"],
  "ns_after": ["ns1.attacker.test"],
  "ds_before": ["12345 13 2 ab12..."],
  "ds_after": ["54321 13 2 cd34..."],
  "risk": "high",
  "reasons": ["DS swapped with no prior trail"]
}
```

## Important starter limitations

- This is hackathon/demo scaffolding, not production-grade transparency infrastructure.
- The signing private key is generated locally and stored in `data/`; protect it.
- There is no authentication, authorization, rate limiting, or webhook delivery yet.
- Inclusion proofs are implemented. **Consistency proofs and a public-key
  verification CLI are intentionally left as the next tasks.**
- The JSONL file is append-oriented, but filesystem permissions alone do not
  make it tamper-proof. Back up and externally publish/checkpoint tree heads.
- Run only against your isolated `.test` lab and synthetic events, as specified
  in the project plan.




## Telegram notifications

LoKey optionally supports Telegram alerts for high-risk DNS events.

1. Create a Telegram bot using @BotFather.
2. Start a conversation with your bot.
3. Obtain your chat ID using the Telegram getUpdates API.
4. Copy the example configuration:

   cp .env.example .env

5. Configure TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
6. Set TELEGRAM_ENABLED=true.

Start LoKey:

docker compose up -d --build

Without Telegram configuration, LoKey continues operating
normally without sending notifications.