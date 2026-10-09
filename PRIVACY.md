# Privacy

This application runs locally. There is no application-operated backend,
telemetry, analytics, cloud sync, scheduler, or general API proxy.

Offline use reads the JPEG/PNG selected by the user. Display previews remain in
memory. The saved observation contains a filename (not an absolute source path),
dimensions, image hash, arbitrary subject/frame IDs, descriptions, evidence,
confidence, provenance and timestamp. These records are private user data; do not
commit them. The original image is neither modified nor copied into result storage.

When the user explicitly enables the future live mode and starts sign-in, the
system browser communicates with OpenAI. The application receives the issued
client identifier, signed account identity and credentials. It retains the verified
subject, a stable anonymous registration label, host identifier and tokens in
Windows CurrentUser DPAPI storage with an owner-only directory ACL. It does not
retain separate email, name or profile-picture fields, nor interpret opaque
OpenAI authentication metadata. A retained ID token can contain basic account
claims. The authorization URL can contain an ID-token hint on returning sign-in;
it is never logged by the application. The browser and operating system have
their own handling of such URLs.

Credential storage is `%LOCALAPPDATA%/EquineMotionObserver/auth`. It is intended
for a local, user-controlled, non-cloud-backed folder. DPAPI is not protection
against malware already running as the same Windows user or an administrator.
The application refuses a visibly OneDrive-backed default location.

Before each image request, the user confirms the exact selected image and its
external-AI transmission rights. OpenAI receives the **original bytes, including
any embedded image metadata**, along with local subject/frame IDs and image hash.
Avoid identifying filenames and IDs. Descriptions and evidence returned by the
service become local observations only after validation and user review.
`store=false` controls Responses storage; it is not a promise of no provider
processing or retention. OpenAI's own terms and privacy rules still apply.
Server-side image representations cannot be verified by this client.

Token counts and timing are recorded only when supplied or measured. The durable
dispatch ledger contains a task ID, request hash, state, attempt count, elapsed
time, HTTP status, completion flag and available token counts; it does not contain
tokens, images, raw responses or prompts. Request/response IDs may be
retained in observations for troubleshooting. There is no automatic log upload.

Logout clears local access, refresh and ID tokens and attempts one remote session
revocation. Unknown revocation is shown explicitly. Registration identity and host
mapping remain for reauthorization. Disconnect the application in ChatGPT settings
to withdraw its connection. These are different operations. To delete local
records, close the application and remove the desired files in its local data
directory. Removing the ledger also removes duplicate-dispatch protection; never
do so to recover a request with an unknown server outcome.

No real credentials, research images or observations are distributed with the
source. Synthetic examples are newly generated geometry. Future privacy-sensitive
feature additions require review before use.
