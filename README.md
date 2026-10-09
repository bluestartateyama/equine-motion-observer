# Equine Motion Observer

A standalone Windows image notebook for describing visible equine features.
It works without an AI account: select a JPEG or PNG, preview it, record what
you can see and why, and save a local JSON observation. The interface is Japanese.

This is a local research application. It has no race database, performance
scores, outcome predictions, betting advice, automated purchases, or downstream
integration. A still image often cannot establish gait or coordination; leave
those features unavailable rather than guessing.

## Run on Windows 11

Install Python 3.12 with Tcl/Tk. In this source checkout:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -B run.py
```

When a prepared local environment is already present, only the last command is
needed. Dependencies are installed separately; no dependency code is vendored.
Default startup is offline, and does not initialize credential storage or send
network requests. `.env` is not loaded. No API key is needed or supported.

1. Choose a local JPEG / PNG. Two wholly synthetic examples are under `examples/`.
2. Enter an arbitrary subject ID and image/frame ID. Changing the frame ID requires
   selecting the image again so evidence remains bound to the input.
3. For each feature choose `observed`, `unknown`, or `unobservable`.
4. An observed feature requires a description and visual evidence. Confidence
   is optional, between 0 and 1. Unavailable features require a reason and empty
   description/confidence; they are saved as JSON `null`.
5. Save. The application reports the saved location.

Results are stored under `%LOCALAPPDATA%/EquineMotionObserver/observations`.
They retain the original filename, dimensions, SHA-256, frame ID, schema version,
unique result ID, timestamp, evidence, and provenance. Original image files are
not modified or copied to that directory. A small display preview is independent
of the original bytes. The application currently accepts one image per observation.

## Optional ChatGPT connection: preview implementation

The official SIWC OAuth and Direct Responses adapter are implemented and tested
using synthetic credentials and responses. **Real service interoperability and
account/model eligibility have not been verified.** Publication does not grant
OpenAI access. The application itself is free; use remains subject to OpenAI's
terms, account permissions and usage limits.

For a separately approved future pilot, launching with `--enable-siwc` enables
the connection controls. This flag does not log in or send an image by itself.
Continue with ChatGPT opens the official authorization page after confirmation.
Saved registrations are distinct; reauthorization uses their issued client IDs.
The catalog must grant exactly `gpt-6.1-sol`; no alternate model is selected.

Before an image request, verify plan sharing and a suitable weekly app limit in
ChatGPT settings, disable credit use and automatic purchases separately, confirm
external-AI image rights, and approve the selected image in the send dialog.
For initial research, keep the app's weekly limit below 100% as an additional
credit-use control. The checkboxes are user attestations, not server-side settings.
The request body has no credit-disable parameter.

The adapter uses `store=false`, `stream=true`, Medium by default (High optional),
image `detail=high`, no automatic retry, and no fallback. Only a completed,
validated observation is shown. Human evidence review is required before saving.
The manual stop button closes local reception and discards the result; it cannot
prove that server execution stopped. SSE milestones and safe error states appear
on screen. Saved metrics include preparation, first event/text, server completion,
local validation, total time, and reasoning tokens when supplied by the service.
No automatic request repair occurs after an uncertain completion. A deliberate
new user action is a new task and can consume usage; do not use it to repair an
uncertain pilot without a new approval.

See [SIWC integration](docs/siwc_integration.md), [privacy](PRIVACY.md),
[security](SECURITY.md), [usage policy](USAGE_POLICY.md), and
[architecture](docs/architecture.md).

## Synthetic tests

```powershell
.\.venv\Scripts\python.exe -B tests/run_tests.py
```

The suite exercises image fidelity, null/evidence validation, PKCE and signed
OIDC tokens, rotation, revocation, Windows DPAPI/ACL, cross-process locks,
dispatch restart protection, SSE failures, and offline GUI-to-JSON behavior.
Tests generate ephemeral keys and geometric images locally. They never log in,
acquire real tokens, or call OpenAI services. Temporary test data stays in the
ignored `.runtime/` directory and is removed after each test.

## License and release status

Newly authored source, documentation, tests and synthetic examples use the MIT
license. Dependencies keep their own licenses. The official SIWC DevKit is not
included or linked. The small official sign-in mark is used only on its sign-in
button and is excluded from the MIT grant; see NOTICE.
No external security assessment or real OAuth certification is claimed.

The project is not affiliated with or endorsed by OpenAI. Names identify the
supported service. OpenAI's sign-in mark does not imply endorsement.
