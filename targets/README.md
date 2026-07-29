# Target files

A target file tells the dynamic engine how to talk to the endpoint under test,
so the scanner works against any chat API shape without code changes.

| Key | Meaning |
|---|---|
| `url` | Endpoint to probe. Required. |
| `method` | HTTP method, default `POST`. |
| `headers` | Extra headers. `Content-Type: application/json` is added automatically. |
| `body_template` | Request body. The literal string `{{PROMPT}}` is replaced with each probe's payload, at any depth. |
| `response_path` | Dotted path to the assistant text, e.g. `choices.0.message.content`. Leave empty to search the whole raw body. |
| `timeout` | Per-request timeout in seconds, default 60. |
| `delay_seconds` | Pause between probes, default 0.5. |

`{{PROMPT}}` can sit anywhere in `body_template`, including nested inside a
messages array:

```json
{
  "body_template": {
    "model": "gpt-4o",
    "messages": [
      { "role": "user", "content": "{{PROMPT}}" }
    ]
  },
  "response_path": "choices.0.message.content"
}
```

## Before you run this

The dynamic engine sends adversarial payloads: instruction-override attempts,
credential-extraction requests, oversized inputs, and a burst of requests to
test for rate limiting. Only point it at a system you own or have written
authorization to test. Prefer a staging environment — the burst probe will
consume real inference budget against a production endpoint.

Do not commit target files containing real tokens; `.gitignore` excludes
everything here except the example and this README.
