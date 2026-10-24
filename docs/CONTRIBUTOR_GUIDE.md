# SafeApply Backend: New Contributor Guide

Welcome! This guide gets you from "I just cloned the repo" to "I can explain how it works and change it safely".

It complements, and does not repeat, [ARCHITECTURE.md](ARCHITECTURE.md). The architecture document has the diagrams (request pipeline, login, encryption, lifecycle, data model). This guide covers:

- how to get a working local setup and see every role in action,
- how to **trace a feature through the code**,
- **why** the main design choices were made, and their trade-offs,
- **quirks in the current code** that will otherwise cost you an afternoon,
- a manual test checklist (the repo has no automated tests yet),
- questions you should be able to answer once you know the codebase, and ideas for first contributions.

The React client has a matching [Frontend Contributor Guide](https://github.com/USER1043/ScholarshipSystem-Frontend/blob/main/docs/CONTRIBUTOR_GUIDE.md).

## Contents

1. [The project in one minute](#1-the-project-in-one-minute)
2. [Run it locally](#2-run-it-locally)
3. [Three ideas that explain most of the code](#3-three-ideas-that-explain-most-of-the-code)
4. [Trace one application through the code](#4-trace-one-application-through-the-code)
5. [Design decisions and trade-offs](#5-design-decisions-and-trade-offs)
6. [Quirks and gotchas in the current code](#6-quirks-and-gotchas-in-the-current-code)
7. [Testing your change](#7-testing-your-change)
8. [Questions you should be able to answer](#8-questions-you-should-be-able-to-answer)
9. [Ideas for first contributions](#9-ideas-for-first-contributions)
10. [Pull request checklist](#10-pull-request-checklist)

---

## 1. The project in one minute

SafeApply is a scholarship application system with three roles:

| Role | Can do |
| --- | --- |
| **Student** | Self-register, submit one or more applications with documents, track status, view the QR code and integrity check for an approved application |
| **Verifier** | See all applications (a limited set of decrypted fields) and mark them `Verified` |
| **Admin** | Approve (sign) a `Verified` application, reject any non-approved one, onboard staff, list and remove users |

The interesting engineering is in four places:

1. **Hybrid encryption**: sensitive fields are encrypted in the browser (AES-256-GCM, so tampering is detected on decryption), and the AES key is wrapped with the server's RSA-4096 public key. The database never holds plaintext.
2. **Least-privilege decryption**: the server decrypts, but each role's endpoint asks for only the fields that role needs.
3. **Two-factor login** for everyone: email OTP for students, authenticator app (TOTP) for staff.
4. **Digital signatures**: an approval is signed (RSA-SHA256) so later changes to the record can be detected.

**Stack:** Node.js, Express 5, MongoDB with Mongoose 9, JWT (HS256), bcryptjs, Helmet, express-rate-limit, express-validator, Multer, Speakeasy, qrcode, Node's built-in `crypto`. Email goes through Brevo's HTTP API.

## 2. Run it locally

You need Node.js 20.19+ (required by Mongoose 9) and a MongoDB instance (local, or a free Atlas cluster). The full environment variable list is in the [README](../README.md#environment-variables).

```bash
npm install
mkdir uploads                      # Multer will not create it
# create .env with the variables from the README
node scripts/seedAdmin.js          # creates the super admin
npm run dev                        # http://localhost:5000
```

Notes that save time:

- **Run commands from the repository root.** Multer saves to the relative path `uploads/`, so the working directory matters (see [section 6](#6-quirks-and-gotchas-in-the-current-code)).
- **You need working email to log in.** Every login needs an OTP or an authenticator code, and students receive the OTP by email. Without `BREVO_API_KEY` the send fails, the error is only logged, and the API still answers normally (see section 6). The simplest option is a free Brevo account with your own verified sender address.
- **Your first run generates a new RSA key pair.** `config/public.pem` is tracked in git but `config/private.pem` is not, so on a fresh clone the key helper sees a missing private key and generates a **new pair, overwriting `public.pem`** the first time a key is needed (for example in `seedAdmin.js`). `git status` will then show `config/public.pem` as modified: **do not commit it**. Keep your `private.pem`; if you lose it, everything you stored becomes undecryptable.
- `seedAdmin.js` writes `scripts/admin_qr.html` containing the super admin's authenticator QR code and secret. Scan it, then **delete the file and never commit it**.

### See every role working (about 10 minutes)

1. Start the [frontend](https://github.com/USER1043/ScholarshipSystem-Frontend) (`npm run dev`, port 5173).
2. Log in as the super admin with `SUPER_ADMIN_EMAIL` and `SUPER_ADMIN_PASSWORD`, then enter the code from the authenticator app you scanned.
3. In the admin dashboard, onboard a verifier. Open the emailed link, set a password, log in, and scan the new QR code. **Scan it the first time**; it is not shown again (section 6).
4. In a private window, register a student, enter the OTP from the email, and submit an application with three small PDFs or images.
5. As the verifier, mark it `Verified`. As the admin, approve it.
6. As the student, open the status page: you should see a QR code and be able to run the integrity check.

## 3. Three ideas that explain most of the code

**1. Every protected route is the same chain.** `protect` (who are you) → `authorize(role)` (are you allowed) → validators → `validate` → controller. If you remember one convention, remember this. Role checks live on the server in `routes/`; the frontend guards only hide screens.

**2. Encrypted fields are `{ iv, content, authTag }` objects (AES-256-GCM) plus one wrapped key per application.** `decryptApplicationFields(app, ['incomeDetails', ...])` in `security/encryption/applicationCrypto.js` is the only place that turns ciphertext back into plaintext for application data. To change who can see what, change the list of field names a controller passes in.

**3. Status changes are enforced in controllers, not in the schema.** The `status` enum only lists the legal values; the *transitions* (`Submitted → Verified → Approved`, `Rejected` from any non-approved state) are `if` checks in `verifierController.js` and `adminController.js`.

## 4. Trace one application through the code

Open these in order. Each step is one function.

| Step | What happens | Where |
| --- | --- | --- |
| 1 | Browser fetches the public key | `getPublicKey` in `controllers/authController.js` (`GET /api/auth/public-key`) |
| 2 | Browser encrypts four fields, wraps the AES key, posts multipart form data | Frontend `ApplyScholarship.jsx` |
| 3 | Route chain: login check, student role, file upload, field validation | `routes/applicationRoutes.js` (`POST /`) |
| 4 | Files saved, type and size checked | `middleware/uploadMiddleware.js` |
| 5 | Ciphertext stored as received; `Document` row links the file names | `submitApplication` in `controllers/applicationController.js` |
| 6 | Verifier lists applications: ID number, income, academic details decrypted | `getAllApplications` in `controllers/verifierController.js` |
| 7 | Verifier marks `Verified` | `verifyApplication` (only `Verified` is accepted) |
| 8 | Admin approves: the status must be `Verified`; a record of the encrypted fields is canonicalised, hashed and signed | `approveScholarship` in `controllers/adminController.js`, `security/signature/digitalSignature.js` |
| 9 | Student fetches own applications, decrypted, plus a QR code for approved ones | `getMyApplications` |
| 10 | Anyone logged in re-checks the signature; anyone at all can scan the QR | `verifySignature`, `verifyByQR` |

Login has its own trace: `loginUser` → (`verifyOTP` or `verifyTOTP`) → `generateToken`, all in `authController.js`. Token verification is `middleware/authMiddleware.js`.

## 5. Design decisions and trade-offs

| Decision | Alternative | Why this way | Cost |
| --- | --- | --- | --- |
| **Hybrid encryption** (AES for data, RSA for the key) | Encrypt every field with RSA | RSA can only encrypt a few hundred bytes; AES handles any size and is fast. RSA protects the small key. | Two layers to keep consistent across client and server |
| **Encrypt in the browser** | Encrypt on the server before saving | Plaintext never travels in the request body or reaches the database, so a request log, proxy or backup cannot leak it | The server still holds the private key, so this is **not** end-to-end encryption (see below) |
| **Server decrypts for staff** | Give staff their own keys | Simple review workflow; staff need no key management | A compromised server exposes everything. Real E2E would need per-reviewer key wrapping |
| **One AES key per application** | One global key | A leaked key exposes one application, not all | An `encryptedAesKey` column per record |
| **Per-role field lists** | Return everything to every staff role | Least privilege: a verifier never receives bank details, an admin never receives the ID number | Lists are repeated in three controllers; a new field must be added in each place that needs it |
| **Sign the *ciphertext* record** | Sign decrypted values | Signing and verifying never need decryption or the AES key; any change to stored data breaks the hash | Records must be rebuilt **identically** in `approveScholarship` and `verifySignature` or every check reports "tampered" |
| **Canonical JSON (sorted keys) before signing** | `JSON.stringify` directly | Key order cannot change the bytes being signed, so verification does not depend on how the object was built | One more function (`canonicalize`) that both signing and hashing rely on |
| **Typed JWTs (`access` vs `invite`)** | One token kind | An invite link can never be replayed as a login session | One extra claim to check |
| **HS256 only, secret length enforced at startup** | Library defaults | Prevents algorithm-confusion attacks and weak or default secrets | The server refuses to start with a short secret |
| **OTP stored as a bcrypt hash** | Plain OTP in the DB | A database leak does not reveal live codes | bcrypt cost makes verification slower (acceptable for 6 digits and one check) |
| **TOTP secret encrypted at rest with the same hybrid scheme** | Plain text | Reuses the existing crypto; a database leak does not reveal authenticator secrets | Needs the private key to log staff in |
| **Invite-only staff accounts** | Self-signup with role selection | Privilege cannot be self-assigned; `register` hard-codes `role: "student"` | Needs an admin to bootstrap (hence `seedAdmin.js`) |
| **Account lockout (5 failures, 15 min) plus per-IP rate limits** | Rate limit only | Slows password guessing against one account from many IPs | An attacker can lock out a known email (a denial-of-service trade-off) |
| **MongoDB with Mongoose** | SQL | Application documents embed `{ iv, content, authTag }` objects naturally; a small, flat set of collections | No multi-document transactions are used, so `submitApplication` saves the `Application` and then the `Document` in two steps |

## 6. Quirks and gotchas in the current code

These are verified against the code. Several are good first issues (section 9).

**Behaviour that surprises people**

1. **`verificationStatus` exists only in the student endpoint.** `getMyApplications` computes it, but it is not a schema field. In the verifier list, the admin list and `verify-qr`, `app.verificationStatus` is `undefined`, so the key is absent from the JSON.
2. **`GET /api/admin/applications` returns every application**, despite the controller name `getVerifiedApplications`. The UI filters by status.
3. **The staff QR is shown once.** At a staff member's first login the TOTP secret is saved as soon as the QR code is generated, before they confirm a code. On the next login the server answers `totp_app` and never shows the QR again. If someone closes the page without scanning, an admin has to remove and re-invite them.
4. **Email failures are swallowed** in `register`, `login` and `onboard`: the error is logged and the API still returns success. When a user says "I never got the code", look at the server log first.
5. **Upload errors become HTTP 500.** Multer's "Only PDFs and Images are allowed!" and file-too-large errors reach the global error handler in `app.js`, which answers `500 Internal Server Error`. A 400 with the real message would be friendlier.
6. **`uploads/` is resolved two different ways.** Multer writes to the relative path `uploads/` (depends on the working directory), while `serveDocument` reads from `../uploads` relative to the controller file. Start the server from the repository root.
7. **Registration HTML-escapes the name.** `check("username").escape()` turns `&` or `'` into entities before they are stored.
8. **`removeStaff` is more than staff removal.** It hard-deletes any user except yourself and the super admin, including students, and deletes their `Application` records. Their `Document` records and uploaded files are left behind.
9. **`protect` checks that the user exists, not that the account is active.** Suspended or locked accounts keep a valid token until it expires (30 days). There is also no token revocation list.
10. **`approveScholarship` returns a QR code of the bare application ID.** The QR code students see comes from `getMyApplications` and encodes the `verify-qr` URL. They are different things.
11. **`config/public.pem` is tracked but regenerated on a fresh clone.** See [section 2](#2-run-it-locally). Do not commit a changed `public.pem` unless you are deliberately rotating keys.

**Security-relevant things to keep in mind**

12. **`/verify-otp` and `/verify-totp` have no per-account attempt counter.** They take a `userId` in the body, are not covered by `loginLimiter`, and are limited only by the global 100 requests per 15 minutes per IP.
13. **`GET /api/applications/verify-signature/:id` checks login, not ownership.** Any logged-in user who knows an ID can run it. It reveals only valid/tampered, but keep it in mind before adding fields to that response.
14. **`GET /api/applications/verify-qr/:id` is public** and returns the applicant's name and status. This is by design (that is what the QR is for); do not add anything sensitive to it.
15. **Never commit generated secrets.** `scripts/admin_qr.html` is output from `seedAdmin.js` and contains a TOTP secret. `private.pem` and `.env` are git-ignored; keep it that way.

**Dead or ignored configuration**

16. `mfaEnabled` (set in `registerUser`, `onboardEmployee` and `seedAdmin.js`) and `deviceTrustEnabled` (`seedAdmin.js`) are not in the `User` schema, so Mongoose silently drops them.
17. `trustedDevices` is written but never read. The "trust this device" checkbox has no effect on login.
18. `passwordHistory` and `suspended` / `locked` account statuses exist in the schema, but nothing sets or enforces them yet (except `suspended` blocking password login).

## 7. Testing your change

There is **no automated test suite** and no lint script in this repository yet, so verify by hand. Treat adding tests as a valuable contribution (section 9).

### Before opening a PR

```bash
node -e "require('./app')"      # catches syntax and require errors (needs JWT_SECRET set)
npm run dev                     # server starts, "MongoDB Connected" appears
```

### Behaviour checklist

Run the ones your change could affect. `TOKEN` is a JWT from a completed login.

| Area | Check | Expected |
| --- | --- | --- |
| Auth | `GET /api/applications/my` with no `Authorization` header | 401 |
| Auth | Call `/api/admin/users` with a student token | 403 |
| Auth | Use an invite token as a Bearer token | 401 "invalid token type" |
| Login | 5 wrong passwords for one account | The 5th returns 423 "locked" and further logins are refused until the lockout ends. The per-IP limiter also allows only 5 login requests per 15 minutes (429 after that), so restart the server between experiments |
| Lifecycle | Approve an application that is still `Submitted` | 400 |
| Lifecycle | Reject an `Approved` application | 400 |
| Lifecycle | `PUT /api/verifier/applications/:id` with `status: "Rejected"` | 403 |
| Crypto | Submit as a student, then read it as student, verifier, admin | Each role sees only its fields (README table) |
| Crypto | Change one hex character of a stored field's `content` (or `authTag`) in MongoDB, then load it as the verifier | That application fails to decrypt (an error entry) instead of showing altered data; the rest of the list still loads |
| Crypto | `POST /api/applications` with an encrypted field missing `authTag` | 400 "Invalid encrypted data" |
| Signature | Approve, then `GET /verify-signature/:id` | `valid` |
| Signature | Edit `instituteName` of the approved document in MongoDB, check again | `tampered` |
| Upload | Upload a `.txt` file, and a file over 5 MB | Rejected (currently as 500, see section 6) |
| Documents | Download a file as a different student | 403 |

```bash
curl -i http://localhost:5000/api/applications/my                       # expect 401
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/admin/users   # 403 for a student
```

If you change which fields go into the signed record, also approve a **new** application afterwards: records signed before your change will report `tampered`.

## 8. Questions you should be able to answer

Use these to check your understanding of the codebase. Short answers follow each.

**Why hybrid encryption instead of only RSA, or only AES?**
RSA-4096 with OAEP-SHA256 can encrypt only a small payload, so it wraps a 32-byte AES key; AES-256-GCM encrypts the actual data quickly and adds an auth tag, so modified ciphertext fails to decrypt instead of returning altered data. You get fast bulk encryption and no shared secret to distribute.

**If the server can decrypt everything, why encrypt in the browser at all?**
It protects data at rest (database, backups) and keeps plaintext out of the database and anything between the browser and the app's own decryption code. It is deliberately **not** end-to-end encryption; the README and architecture document say so explicitly. The honest threat model is "database leak", not "server compromise".

**How does a verifier see data without seeing everything?**
Controllers call `decryptApplicationFields` with a per-role list of field names, and respond with plaintext of only those. The AES key never leaves server memory.

**What exactly is signed, and why ciphertext rather than plaintext?**
A canonical JSON record of IDs, the status `Approved`, the encrypted fields, the wrapped key, institute, exam type and the approving admin's ID. Signing the ciphertext means verification needs no decryption and any change to stored data is detected.

**What does the signature prove, and what does it not?**
It proves the stored record is unchanged since an admin approved it, and which admin signed. It does not prove the *content* was true, and the signing key is on the same server as the data, so an attacker who steals the private key can forge approvals.

**How are brute-force attacks handled?**
Per-IP rate limits (5 logins and 100 API calls per 15 minutes), a 15-minute account lockout after 5 failed passwords, bcrypt cost 12, and 6-digit OTPs that expire after 5 minutes. Known gap: OTP and TOTP verification have no per-account counter (section 6, item 12).

**Why are there two token types?**
The staff invite link is a JWT too. A `type` claim (`invite` or `access`) means an invite token cannot be used to call protected routes, and a session token cannot complete an invite.

**Where would you add a new role, such as `auditor`?**
Add it to the `role` enum in `models/User.js`; decide how accounts are created (extend `onboardEmployee` and its `isIn` validator); add routes protected with `authorize('auditor')`; decide which fields it may decrypt; update the frontend's role constants and route guards.

**How would you make approvals safe against two admins clicking at once?**
Today it is a read-check-write (`findById`, check status, `save`). Two simultaneous requests could both pass the check. An atomic `findOneAndUpdate({ _id, status: 'Verified' }, ...)` would close the gap.

**What would you improve first?**
See section 9. A good answer picks something from the quirks list and says how to verify it.

## 9. Ideas for first contributions

Roughly from smallest to largest.

- **Add `verificationStatus` consistently**, either by computing it in the verifier, admin and `verify-qr` responses or by removing the dead references.
- **Return 400 for upload errors** with the real message (a small error-handling middleware for `MulterError` and the file-type error).
- **Remove `mfaEnabled` / `deviceTrustEnabled`** from the places that set them, or add them to the schema if they are meant to exist.
- **Clean up `removeStaff`**: restrict it to staff, or delete the student's `Document` rows and files too.
- **Check `accountStatus` in `protect`** so suspended accounts lose access immediately.
- **Add an `.env.example`** and a `npm test` placeholder.
- **Add a per-account attempt limit** to `verifyOTP` and `verifyTOTP`.
- **Make approval atomic** with a conditional `findOneAndUpdate`.
- **Introduce automated tests**: unit tests for `digitalSignature` (sign, verify, tamper), `applicationCrypto` (round trip) and `canonicalize` need no database; route tests can use `supertest` with an in-memory MongoDB.
- **Extract the signed record** into one shared function used by `approveScholarship` and `verifySignature`, removing the "must stay identical" trap.
- **Encrypt uploaded documents** at rest (a larger design task: key handling for files, streaming).

## 10. Pull request checklist

- [ ] The change is as small as it can be and does one thing.
- [ ] New routes use `protect` and `authorize(...)` in that order, with validators and `validate`.
- [ ] No secrets, `.env`, `private.pem`, `uploads/` content or `scripts/admin_qr.html` are committed, and `config/public.pem` is unchanged (unless you are rotating keys on purpose).
- [ ] If you touched encrypted fields, the signed record or the per-role field lists, you updated **every** place listed in [ARCHITECTURE.md section 13](ARCHITECTURE.md#13-contributing).
- [ ] You ran the relevant rows of the [checklist](#7-testing-your-change) and can say what you ran.
- [ ] Docs are updated if behaviour changed (README, `ARCHITECTURE.md`, this guide).
- [ ] Error responses never include stack traces or sensitive values.
