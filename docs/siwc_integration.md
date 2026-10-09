# Official SIWC contract and future pilot

Audited against the official documentation on 2026-10-09. Real authentication,
model access and inference remain unverified.

## OAuth

The loopback listener starts before the system browser. Every attempt gets fresh
state, nonce and S256 verifier. The URI uses `127.0.0.1` and `/auth/callback`; the
exact port is preserved for code exchange. Initial registration uses
`dynamic_agent_client`, the app name and a persisted host ID. Only the returned
issued ID is retained. Incomplete code exchange retains a non-active client
mapping so a user can restart authorization with that ID rather than register
another client. Returning flows reject mismatched client or verified subject.

The request includes `openid profile email offline_access resource.invoke
chatgpt.tokens.use.direct` and the public API resource. Returned grants are checked
separately from signed identity. RS256 signature, issuer, client audience,
expiration and attempt nonce must pass before activating the registration.
Scopes alone do not prove actual future model access.

Rotating refresh is serialized and atomically stored; no scope is added to the
refresh grant. An uncertainty marker requires reauthorization if refresh completion
is unknown. Refresh is user initiated in this version, never a background retry.
Logout clears local tokens and attempts remote revocation once; this stricter
research retry policy reports uncertain revocation instead of retrying. Client
and host mappings remain. ChatGPT's Disconnect operation is separate.

## Inference

Only the formal account-bound model catalog can allow `gpt-6.1-sol`. An absent or
hidden slug stops the request. Public `POST https://api.openai.com/v1/responses`
uses the formal OAuth bearer with `store=false`, `stream=true`, array input,
Medium/High reasoning, and a newly authored Structured Outputs schema.
Images use original JPEG/PNG bytes and `detail=high`. No preview bitmap enters
the request. Unsupported preview fields, API keys and alternate endpoints are
omitted. No retry or model fallback exists.

The parser checks SSE framing and UTF-8, response identity/model/status, duplicate
and out-of-order event identifiers, text deltas versus completed output, refusal,
failed/incomplete events, JSON/schema and image/frame/hash evidence. Tokens and
timing are recorded when available. Completed-invalid output is distinguished
from an unknown server completion; both remain unusable and cannot be resent
under the same task ID. Server-internal image representation is unverified.

## Service and publication gates

Local personal projects and open-source tools are described in the official
Cookbook. This source publication preparation is not an entitlement promise.
Actual account/workspace consent, granted scopes and available models must still
be checked. The official DevKit has a distinct noncommercial license; this app
does not use or redistribute it. MIT applies only to this newly authored code.

The owner must approve the exact publication manifest/license/security report
before creating any public repository. Configure a private security contact and
review the current sign-in button branding before release. No credentials, real
images, private research, runtime dependencies, logs or old histories may be added.

After publication, obtain separate authorization for each stage:

1. **A: registration.** Confirm current terms, app privacy notice, account/workspace,
   plan sharing, an app cap below 100%, credits OFF and automatic purchases OFF.
   Use the actual app name and inspect issued client ID, grants and DPAPI storage.
2. **B: catalog.** Use that OAuth session to query the formal catalog once. Stop
   unless the visible exact `gpt-6.1-sol` slug is granted.
3. **C: text.** Separately approve one fixed harmless text request, Medium,
   `store=false`, `stream=true`, retry zero. Retain the ledger even on failure;
   verify `response.completed`, output, tokens and timing. No repair request.
4. **D: image.** Only after C passes, separately approve a specific rights-cleared
   original image and its hash/subject/frame ID. Verify evidence and human visual
   identity. Never advance automatically to batch benchmarks.

No qualification inquiry is part of this plan.

## Primary sources

- [Registration and sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [Accounts and sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
- [Models and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- [Preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
- [Token reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference)
- [Official Cookbook](https://developers.openai.com/cookbook/articles/sign-in-with-chatgpt)
- [UI/UX guidelines](https://developers.openai.com/siwc/ui-ux-guidelines)
- [Plan/credits controls](https://help.openai.com/en/articles/20001542-using-your-chatgpt-plan-in-other-apps-and-sites)
- [GPT-6.1 Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol)
