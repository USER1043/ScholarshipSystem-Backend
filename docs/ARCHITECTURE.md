# SafeApply Backend Architecture

This document explains how the SafeApply backend is put together, for anyone setting it up, using it, or contributing to it. It covers the API, authentication, the encryption model, the application workflow and the data model.

SafeApply is a scholarship application system with three roles:

- **Student:** registers, submits encrypted applications with supporting documents, and tracks their status.
- **Verifier:** staff member who reviews applications and marks them as verified.
- **Admin:** staff member who approves or rejects verified applications, onboards staff and manages users.

The React client has its own architecture document: [Frontend Architecture](https://github.com/USER1043/ScholarshipSystem-Frontend/blob/main/docs/ARCHITECTURE.md).

## Contents

1. [System context](#1-system-context)
2. [Request pipeline](#2-request-pipeline)
3. [Login and MFA](#3-login-and-mfa)
4. [Student registration](#4-student-registration)
5. [Staff invite onboarding](#5-staff-invite-onboarding)
6. [Receiving an application](#6-receiving-an-application)
7. [Reviewing: server-side, least-privilege decryption](#7-reviewing-server-side-least-privilege-decryption)
8. [Application lifecycle](#8-application-lifecycle)
9. [Approval signing, tamper check and QR verification](#9-approval-signing-tamper-check-and-qr-verification)
10. [Data model](#10-data-model)
11. [Keys and secrets](#11-keys-and-secrets)
12. [Security model and known limitations](#12-security-model-and-known-limitations)
13. [Contributing](#13-contributing)

---

## 1. System context

Everything inside the dashed box runs on the backend server. The browser only ever sends sensitive fields to the server as ciphertext.

```mermaid
flowchart LR
    subgraph Client["Browser"]
        SPA["React SPA<br/>(ScholarshipSystem-Frontend)"]
    end

    Auth["Authenticator app<br/>(staff phone)"]
    Scanner["Anyone scanning<br/>a QR code"]

    subgraph Server["Backend server (trust boundary)"]
        API["Express 5 REST API"]
        Keys[("config/private.pem<br/>RSA-4096 private key")]
        Uploads[("uploads/<br/>supporting documents")]
    end

    DB[("MongoDB<br/>users, applications, documents")]
    SMTP["Brevo<br/>transactional email API"]

    SPA -- "HTTPS + JWT<br/>ciphertext on submit" --> API
    Scanner -- "GET /api/applications/verify-qr/:id" --> API
    Auth -. "6-digit TOTP code typed<br/>into the SPA" .-> SPA
    API --> DB
    API --> Keys
    API --> Uploads
    API -- "OTPs, invite links" --> SMTP

    style Server stroke-dasharray: 5 5
```

## 2. Request pipeline

Every request passes through the global middleware in `app.js`, then through the route-specific middleware declared in `routes/`.

```mermaid
flowchart TD
    Req["Incoming request"] --> Helmet["helmet()<br/>security headers"]
    Helmet --> Cors["cors()<br/>only FRONTEND_URL, credentials allowed"]
    Cors --> Json["express.json() + cookieParser()"]
    Json --> ApiLimit["apiLimiter<br/>100 requests / 15 min per IP"]
    ApiLimit --> Router{"Router<br/>/api/auth, /api/applications,<br/>/api/verifier, /api/admin"}

    Router --> LoginLimit["loginLimiter<br/>5 requests / 15 min per IP<br/>(POST /api/auth/login only)"]
    Router --> Protect["protect<br/>verify JWT (HS256 only)<br/>require type = 'access'<br/>load user from DB"]
    Router --> Public["Public routes<br/>register, verify-otp, verify-totp,<br/>resend-otp, otp-status, public-key,<br/>complete-invite, verify-qr"]

    LoginLimit --> Validate
    Public --> Validate
    Protect --> Authorize["authorize(...roles)<br/>403 if role not allowed"]
    Authorize --> Upload["upload.fields()<br/>(application submit only)"]
    Upload --> Validate["express-validator checks + validate<br/>400 with error list on failure"]
    Validate --> Controller["Controller"]
    Controller --> Services["services/ and security/<br/>email, OTP, TOTP, AES, RSA,<br/>bcrypt, signatures, QR"]
    Services --> Mongo[("MongoDB")]

    Router -. "no match" .-> NotFound["404 handler"]
    Controller -. "unhandled error" .-> ErrorHandler["500 handler"]
```

The exact order of `protect`, `authorize`, `upload` and the validators is set per route in `routes/*.js`; the diagram shows the most complete case (submitting an application). Two routes use `protect` without `authorize`, because any logged-in role may call them: `GET /api/applications/verify-signature/:id`, and `GET /api/applications/documents/:filename`, which does its own owner-or-staff check in the controller.

### Where code lives

| Folder | Responsibility | Key files |
| --- | --- | --- |
| `routes/` | URL → middleware chain → controller | `authRoutes.js`, `applicationRoutes.js`, `verifierRoutes.js`, `adminRoutes.js` |
| `controllers/` | Request handling and business rules | `authController.js`, `applicationController.js`, `verifierController.js`, `adminController.js` |
| `middleware/` | Cross-cutting request checks | `authMiddleware.js` (`protect`), `roleMiddleware.js` (`authorize`), `rateLimiter.js`, `uploadMiddleware.js`, `validateInput.js` |
| `security/` | Cryptography | `encryption/aesUtil.js`, `encryption/rsaUtil.js`, `encryption/applicationCrypto.js`, `hashing/hashUtil.js`, `signature/digitalSignature.js`, `encoding/qrUtil.js` |
| `services/` | External integrations and one-time codes | `emailService.js`, `otpService.js`, `totpService.js` |
| `models/` | Mongoose schemas | `User.js`, `Application.js`, `Document.js` |
| `config/` | Database, JWT secret and RSA keys | `db.js`, `jwt.js`, `public.pem`, `private.pem` (git-ignored) |
| `scripts/` | Admin account maintenance | `seedAdmin.js`, `resetAdmin.js` |

## 3. Login and MFA

Every login needs two factors: the password, and then either an email OTP (students) or an authenticator app code (staff). A JWT is issued only after the second factor succeeds.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant SPA as React SPA
    participant API as POST /api/auth/login
    participant DB as MongoDB
    participant Mail as Brevo email API

    U->>SPA: email + password
    SPA->>API: login request (loginLimiter: 5 per 15 min per IP)
    API->>DB: find user by email
    alt account locked (lockoutUntil in the future)
        API-->>SPA: 423 "Account temporarily locked"
    else wrong password
        API->>DB: failedLoginAttempts + 1<br/>(5th failure sets lockoutUntil = now + 15 min)
        API-->>SPA: 401 (or 423 on the 5th failure)
    else password correct (bcrypt compare)
        API->>DB: reset failedLoginAttempts, set lastLoginAt
        alt student (mfaType = email_otp)
            opt no unexpired OTP exists
                API->>API: 6-digit OTP via crypto.randomInt
                API->>DB: store bcrypt hash of OTP, expiry = now + 5 min
                API->>Mail: send OTP email
            end
            API-->>SPA: { mfaType: "email_otp", userId }
            U->>SPA: enter OTP
            SPA->>API: POST /api/auth/verify-otp
            API->>DB: check expiry, bcrypt compare, clear OTP,<br/>pending_verification → active
        else staff, first login (no TOTP secret yet)
            API->>API: generate TOTP secret (Speakeasy) + QR code
            API->>DB: store secret encrypted (AES-256 key wrapped with RSA)
            API-->>SPA: { mfaType: "totp_setup", qrCode, userId }
            U->>SPA: scan QR, enter code from app
            SPA->>API: POST /api/auth/verify-totp
        else staff, later logins
            API-->>SPA: { mfaType: "totp_app", userId }
            U->>SPA: enter code from app
            SPA->>API: POST /api/auth/verify-totp
            Note over API: decrypt secret, verify code<br/>(±1 time step = ±30 s drift)
        end
        API-->>SPA: JWT { id, type: "access" }, valid 30 days
    end
```

`POST /api/auth/resend-otp` refuses to send a new code while the current one is still valid, and `POST /api/auth/otp-status` returns the seconds remaining so the UI can show a countdown.

## 4. Student registration

Only students can self-register; staff accounts are created through [invite onboarding](#5-staff-invite-onboarding).

```mermaid
sequenceDiagram
    autonumber
    actor S as Student
    participant SPA as React SPA
    participant API as POST /api/auth/register
    participant DB as MongoDB
    participant Mail as Brevo email API

    S->>SPA: name, email, password
    SPA->>API: register request (validated: email format, password 6+ chars)
    API->>DB: reject if the email already exists
    API->>API: bcrypt hash password (cost 12)<br/>generate OTP, bcrypt hash it
    API->>DB: create user: role = student,<br/>accountStatus = pending_verification,<br/>mfaType = email_otp
    API->>Mail: send verification OTP email
    API-->>SPA: 201 Created
    SPA->>S: go to OTP screen
    Note over S,DB: The first successful OTP check (section 3)<br/>changes accountStatus to active.
```

## 5. Staff invite onboarding

Verifier and Admin accounts can only be created by an admin. The new staff member chooses their own password; the admin never sees it.

```mermaid
sequenceDiagram
    autonumber
    actor A as Admin
    participant API as Backend API
    participant DB as MongoDB
    participant Mail as Brevo email API
    actor N as New staff member

    A->>API: POST /api/auth/onboard { username, email, role }<br/>(protect + authorize('admin'))
    API->>DB: create user: accountStatus = invited,<br/>mfaType = totp_app, verifiedBy = admin
    API->>API: sign invite JWT { id, type: "invite" }, valid 24 h
    API->>Mail: email link FRONTEND_URL/setup-account?token=...
    Mail-->>N: invitation email
    N->>API: POST /api/auth/complete-invite { token, password }
    Note over API: password must be 8+ chars with<br/>upper, lower, number and symbol
    API->>API: verify JWT (HS256), require type = "invite"
    API->>DB: require accountStatus = invited,<br/>store bcrypt hash, set active
    API-->>N: "Account set up, please login"
    Note over N,API: At first login the staff member sets up TOTP (section 3).<br/>An invite token can never be used as a session token:<br/>protect() only accepts type = "access".
```

## 6. Receiving an application

The browser encrypts the sensitive fields before sending them (see the [frontend document](https://github.com/USER1043/ScholarshipSystem-Frontend/blob/main/docs/ARCHITECTURE.md#5-submitting-an-application-browser-side-encryption)). The server stores the ciphertext as received and never sees the plaintext at this stage.

```mermaid
sequenceDiagram
    autonumber
    participant SPA as React SPA
    participant API as POST /api/applications
    participant M as Multer
    participant FS as uploads/
    participant DB as MongoDB

    SPA->>API: multipart form: 4 encrypted fields,<br/>encryptedAesKey, instituteName, examType,<br/>incomeProof, marksheet, studentCertificate
    API->>API: protect + authorize('student')
    API->>M: upload.fields()
    M->>M: accept only PDF or image, max 5 MB each
    M->>FS: save as fieldname-timestamp-random.ext
    API->>API: validators: encrypted fields and key present,<br/>examType in JEE / NEET / GATE,<br/>authTag present on every encrypted field
    API->>DB: save Application<br/>{ iv, content, authTag } per encrypted field + encryptedAesKey
    API->>DB: save Document (file names), link to Application
    API-->>SPA: 201 { applicationId }
```

## 7. Reviewing: server-side, least-privilege decryption

Decryption happens only on the server, in `decryptApplicationFields()` (`security/encryption/applicationCrypto.js`). AES keys are never sent to any browser, and each endpoint asks only for the fields its role needs.

```mermaid
sequenceDiagram
    autonumber
    participant SPA as React SPA (reviewer)
    participant C as Controller
    participant AC as decryptApplicationFields()
    participant RSA as rsaUtil
    participant AES as aesUtil
    participant DB as MongoDB

    SPA->>C: GET list endpoint (protect + authorize(role))
    C->>DB: load applications
    loop each application
        C->>AC: decryptApplicationFields(app, fieldsForRole)
        AC->>RSA: unwrap encryptedAesKey with private.pem
        RSA-->>AC: 32-byte AES key (stays in server memory)
        AC->>AES: decrypt only the requested fields
        AES-->>AC: plaintext
        AC-->>C: { field: value, ... }
    end
    C-->>SPA: plaintext of permitted fields only<br/>(no ciphertext, no keys)
```

| Endpoint | Role | Decrypted fields returned |
| --- | --- | --- |
| `GET /api/applications/my` | Student (own applications only) | bank details, ID number, income, GPA, exam score |
| `GET /api/verifier/applications` | Verifier | ID number, income, GPA, exam score |
| `GET /api/admin/applications` | Admin | income, GPA, exam score |

Supporting documents are downloaded separately through `GET /api/applications/documents/:filename`, which allows only the student who uploaded the file, a verifier or an admin.

## 8. Application lifecycle

Each transition is enforced in the controllers, not only in the UI.

```mermaid
stateDiagram-v2
    [*] --> Submitted: student submits<br/>(POST /api/applications)
    Submitted --> Verified: verifier marks verified + comments<br/>(PUT /api/verifier/applications/:id)
    Verified --> Approved: admin approves and signs<br/>(POST /api/admin/approve/:id)
    Submitted --> Rejected: admin rejects with reason<br/>(POST /api/admin/reject/:id)
    Verified --> Rejected: admin rejects with reason
    Approved --> [*]
    Rejected --> [*]

    note right of Approved
        Final. Cannot be rejected.
        Signature, hash, signer and
        time are stored.
    end note
    note right of Rejected
        Stores rejectedBy,
        rejectedAt and rejectionReason.
    end note
```

- A verifier can only set the status to `Verified`; any other value returns 403.
- An admin can approve only an application that is already `Verified`.
- An admin can reject at any stage except `Approved`.

## 9. Approval signing, tamper check and QR verification

Approvals are digitally signed so that any later change to an approved record can be detected, and so each approval can be traced to the admin who made it.

```mermaid
sequenceDiagram
    autonumber
    actor A as Admin
    actor S as Student
    actor P as Third party
    participant API as Backend API
    participant DS as digitalSignature
    participant DB as MongoDB

    rect rgba(128, 128, 128, 0.1)
    Note over A,DB: Approve and sign
    A->>API: POST /api/admin/approve/:id
    API->>API: require status = Verified
    API->>DS: record = { applicationId, studentId, status,<br/>encrypted fields, encryptedAesKey,<br/>instituteName, examType, approvedBy }
    DS->>DS: canonical JSON (keys sorted)<br/>RSA-SHA256 sign with private.pem<br/>SHA-256 hash
    API->>DB: save status = Approved, digitalSignature,<br/>dataHash, signedBy, signedAt
    end

    rect rgba(128, 128, 128, 0.1)
    Note over S,DB: Tamper check (any logged-in user)
    S->>API: GET /api/applications/verify-signature/:id
    API->>DB: load current record
    API->>DS: rebuild the same record, recompute hash,<br/>verify signature with public.pem
    API-->>S: "valid", or "tampered" with<br/>{ hashMatch, signatureValid }
    end

    rect rgba(128, 128, 128, 0.1)
    Note over P,DB: Public QR check (no login)
    S->>P: shows QR code from the status page
    P->>API: GET /api/applications/verify-qr/:id<br/>(URL built from BACKEND_URL)
    API-->>P: applicationId, applicant name, status only
    end
```

Because the signed record contains the **encrypted** fields, signing and verification never need to decrypt anything.

## 10. Data model

```mermaid
erDiagram
    USER ||--o{ APPLICATION : "submits (studentId)"
    USER ||--o{ APPLICATION : "signs (signedBy) / rejects (rejectedBy)"
    USER ||--o{ USER : "onboards (verifiedBy)"
    APPLICATION ||--o| DOCUMENT : "has (documents)"
    USER ||--o{ DOCUMENT : "uploads (studentId)"

    USER {
        ObjectId _id PK
        string username UK
        string email UK
        string password "bcrypt hash"
        string role "student | verifier | admin"
        string mfaType "email_otp | totp_app"
        string mfaSecret "OTP bcrypt hash, or encrypted TOTP secret"
        date mfaExpiry "OTP expiry"
        string accountStatus "pending_verification | active | suspended | locked | invited"
        number failedLoginAttempts
        date lockoutUntil
        ObjectId verifiedBy FK "admin who onboarded"
        array trustedDevices "deviceId + expiry"
    }

    APPLICATION {
        ObjectId _id PK
        ObjectId studentId FK
        string fullName "plaintext"
        string instituteName "plaintext"
        string examType "JEE | NEET | GATE"
        object encryptedBankDetails "AES-GCM iv + content + authTag"
        object encryptedIdNumber "AES-GCM iv + content + authTag"
        object encryptedIncomeDetails "AES-GCM iv + content + authTag"
        object encryptedAcademicDetails "AES-GCM iv + content + authTag (GPA, exam score)"
        string encryptedAesKey "RSA-OAEP wrapped AES key"
        string status "Submitted | Verified | Approved | Rejected"
        string verifierComments
        ObjectId rejectedBy FK
        string rejectionReason
        string digitalSignature "RSA-SHA256, base64"
        string dataHash "SHA-256, hex"
        ObjectId signedBy FK
        date signedAt
        ObjectId documents FK
    }

    DOCUMENT {
        ObjectId _id PK
        ObjectId applicationId FK
        ObjectId studentId FK
        string incomeProof "file name in uploads/"
        string marksheet "file name in uploads/"
        string studentCertificate "file name in uploads/"
    }
```

## 11. Keys and secrets

| Secret | Protects | Where it lives | If it is lost or leaked |
| --- | --- | --- | --- |
| `JWT_SECRET` | Session and invite tokens (HS256) | `.env` (min. 32 chars, checked at startup) | **Leaked:** anyone can forge tokens for any user; rotate it (all users are logged out). **Lost:** set a new one; users log in again. |
| `config/private.pem` (RSA-4096) | Unwrapping every AES key; signing approvals | Server disk, git-ignored | **Leaked:** all stored applications and staff TOTP secrets can be decrypted, and approvals can be forged. **Lost:** all stored data becomes permanently undecryptable. Back it up. |
| `config/public.pem` | Wrapping AES keys (browser); verifying signatures | Server disk, served by `GET /api/auth/public-key` | Public by design. It must match `private.pem`. |
| Per-application AES-256 key | One application's sensitive fields | Stored only in wrapped (RSA-encrypted) form in `encryptedAesKey` | Plain form exists only briefly in the student's browser and in server memory during decryption. |
| Staff TOTP secret | Staff second factor | `mfaSecret`, AES-encrypted with an RSA-wrapped key | Re-enroll the staff member. |
| `BREVO_API_KEY` | Sending OTPs and invites | `.env` | **Leaked:** anyone can send email as your verified sender; revoke it in Brevo and create a new key. |

If either `.pem` file is missing, `rsaUtil.ensureKeys()` generates a **new** key pair. On a server with existing data, that makes everything already stored undecryptable.

## 12. Security model and known limitations

**What the design protects against**

- A leaked database or backup: sensitive fields are ciphertext, and the key needed to read them is not in the database.
- Sensitive data showing up in logs or intermediaries before it reaches the server: it is encrypted in the browser.
- Staff seeing more than they need: each role receives only its permitted fields (section 7).
- Undetected changes to approved records: signatures and hashes (section 9).
- Password guessing: account lockout plus per-IP rate limits.
- Forged or misused tokens: required strong secret, HS256 only, typed tokens.

**What it does not protect against, and current gaps**

- **Not end-to-end encryption.** The server holds the RSA private key and can decrypt everything. This is intentional so staff can review applications, but a fully compromised server exposes all data.
- **Decrypted fields travel over the API.** Production deployments must use HTTPS.
- **Uploaded documents are stored unencrypted** in `uploads/`.
- **Student passwords only need 6+ characters.** The strong-password rule applies only to staff invite setup.
- **Trusted devices are not used.** A `deviceId` is issued and stored when requested, but login never checks it, so it does not skip MFA.
- **`registerUser` sets `mfaEnabled`**, which is not in the `User` schema and is silently ignored.

## 13. Contributing

### Adding a protected route

1. Add the handler to the right file in `controllers/`.
2. Register it in `routes/`, in this order: `protect` → `authorize('role', ...)` → validators → `validate` → handler.

```js
router.post(
  "/example/:id",
  protect,
  authorize("admin"),
  [check("reason", "Reason is required").not().isEmpty(), validate],
  exampleHandler,
);
```

3. Don't rely on the frontend's route guards for access control; the server check above is what enforces it.

### Adding a new encrypted field

1. **Frontend:** encrypt the value with `encryptWithAES` in `ApplyScholarship.jsx` and append it to the form data.
2. **Model:** add an `{ iv, content, authTag }` field to `models/Application.js`.
3. **Submit:** map it in `submitApplication` and add a validator in `routes/applicationRoutes.js`.
4. **Decryption:** add it to `ENCRYPTED_FIELDS` in `security/encryption/applicationCrypto.js`.
5. **Access:** add it to the field list of each role that needs it (`applicationController.js`, `verifierController.js`, `adminController.js`).
6. **Signature:** if it must be tamper-evident, add it to the signed record in **both** `approveScholarship` and `verifySignature`. The two records must stay identical, or every check will report "tampered".
