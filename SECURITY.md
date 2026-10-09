# Security

This preview has static review and synthetic tests, including Windows DPAPI and
cross-process locks. It has not completed real-service interoperability testing,
independent penetration testing, or formal OpenAI certification.

## Boundaries

- Network access is disabled by default. A live launch flag, an explicit login
  operation, and a separate per-image confirmation are required.
- Public-client OAuth uses one-time state, nonce and PKCE S256. The callback
  binds only `127.0.0.1` at `/auth/callback`; access logs are disabled.
- Issued registration IDs and verified subjects remain associated. ID-token
  verification allows RS256 with published RSA keys, exact issuer/audience,
  expiry and nonce checks. Unsupported signing algorithms fail closed.
- Tokens are encrypted with Windows CurrentUser DPAPI. The directory DACL is
  replaced with protected owner-only access. Atomic replacement and an OS file
  lock protect rotating-token updates. An in-flight refresh marker prevents
  reusing a token whose refresh outcome is unknown.
- TLS certificate/hostname validation is enabled. Requests use fixed OpenAI
  endpoints; only same-host HTTPS identity discovery endpoints are added.
  Redirects and environment proxies are disabled. No API key, cookies, client
  secret, managed credential server or alternative provider is supported.
- The dispatch ledger is reserved before POST and marks possible dispatch before
  the network call. Every reserved task remains blocked for resending after
  restart, including failed tasks. This bounds client attempts; it cannot prove
  exactly-once execution at the server.
- Receiving text is insufficient. HTTP/SSE metadata, terminal completion,
  output consistency, strict JSON, schema and image evidence must all validate.
  Unknown completion never causes automatic retry. No raw response is logged.
- Local image decoding has byte/pixel/frame limits. Original input bytes are
  retained; preview resizing is independent. Avoid untrusted media and keep
  dependencies patched.

## Limitations and reporting

An attacker with access to this Windows user's process or DPAPI account can
compromise data. Endpoint security remains the user's responsibility. Synthetic
tests do not prove safety against every race, crash, parsing input or dependency
vulnerability. Dependency license review is not a complete vulnerability scan.
The initial revision uses custom OIDC glue around maintained cryptography; review
it again before any production or multi-user distribution.

Use GitHub's private vulnerability reporting for this repository:
https://github.com/bluestartateyama/equine-motion-observer/security/advisories/new
If private reporting is unavailable, do not disclose the vulnerability in a
public issue. Do not post credentials, credential files, private media or raw
authorization URLs. For a breach
affecting SIWC users, the maintainer must follow the notification duties in
[OpenAI's SIWC terms](https://openai.com/policies/sign-in-with-chatgpt-terms/).

The prototype has no betting, database, financial, health-diagnosis, or production
system integration. Do not add token forwarding or downstream gambling exports.
