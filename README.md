# SafeApply - Secure Scholarship System - Server

This is the backend server for the SafeApply, built with [Node.js](https://nodejs.org/) and [Express](https://expressjs.com/). It handles authentication, application processing, and secure data management.

The Frontend code is at [Repo](https://github.com/USER1043/ScholarshipSystem-Frontend)

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for diagrams of the request pipeline, login and MFA flows, the encryption model, the application lifecycle, approval signing and the data model.

New here? Start with the [Contributor Guide](docs/CONTRIBUTOR_GUIDE.md): local setup, a code tour, design decisions and trade-offs, known quirks, and a testing checklist.

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB (via Mongoose)
- **Authentication:** JWT, bcryptjs
- **Security:** Helmet, Express Rate Limit, Speakeasy (TOTP), Node `crypto` (AES-256, RSA-4096, SHA-256)
- **File Handling:** Multer
- **Email:** Brevo transactional email API (HTTP, no SMTP)
- **Validation:** Express Validator

## Features

- **Role-Based Access Control (RBAC):** Distinct routes and permissions for Students, Verifiers, and Admins, enforced on the server.
- **Review Workflow:** Submitted → Verified (by a verifier) → Approved (by an admin, only once Verified) or Rejected (by an admin, any time before approval).
- **Multi-Factor Authentication:** Email OTP for students and TOTP authenticator apps (set up via QR code) for staff.
- **Invite-Only Staff Onboarding:** Admins create Verifier/Admin accounts; staff set their password through an emailed link valid for 24 hours.
- **Digital Signatures:** Approvals are signed with RSA-SHA256, and a verification endpoint detects tampered records.
- **QR Code Verification:** Approved scholarships get a QR code linking to a public status-check endpoint.
- **Secure File Uploads:** PDFs and images only, up to 5 MB, downloadable only by the owning student or staff.
- **Email Notifications:** OTPs and staff invites are sent through the [Brevo](https://www.brevo.com/) transactional email API.

## Security Design

### Data encryption

Sensitive application fields (bank details, Aadhaar ID, income, GPA and exam score) are encrypted **in the browser** before submission:

1. The browser generates a random AES-256 key for the application and encrypts the fields with it using AES-256-GCM. Each field carries an authentication tag, so modified ciphertext fails to decrypt instead of returning altered data.
2. The browser encrypts that AES key with the server's RSA-4096 public key (OAEP, SHA-256).
3. MongoDB stores only the ciphertext, IV and auth tag of each field, and the wrapped key.

Decryption happens **only on the server** (`security/encryption/applicationCrypto.js`). AES keys are never sent to the browser, and each role receives only the fields it needs:

| Role | Decrypted fields returned |
| --- | --- |
| Student (own applications) | Bank details, ID number, income, GPA and exam score |
| Verifier | ID number, income, GPA and exam score |
| Admin | Income, GPA and exam score |

This protects data at rest (database, backups, logs). It is **not** end-to-end encryption: the server holds the RSA private key so that staff can review applications.

### Authentication

- Passwords are hashed with bcrypt (cost factor 12).
- Email OTPs are 6 digits, generated with `crypto.randomInt`, stored only as a bcrypt hash, and valid for 5 minutes.
- Staff TOTP secrets are stored encrypted with the same AES + RSA scheme.
- 5 consecutive failed logins lock the account for 15 minutes.
- Rate limits per IP address: 5 login requests and 100 total API requests per 15 minutes.
- JWTs are verified with HS256 only. Each token carries a type (`access` or `invite`), and only `access` tokens can call protected routes, so an invite link cannot be used as a login session.

## Prerequisites

- Node.js 20.19+ (required by Mongoose 9)
- MongoDB (Local or AtlasURI)
- npm or yarn

## Environment Variables

Create a `.env` file in the project root with the following variables:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=random_string_of_at_least_32_characters
BREVO_API_KEY=your_brevo_api_key
BREVO_SENDER_EMAIL=verified_sender@yourdomain.com
BREVO_SENDER_NAME=SafeApply
SUPER_ADMIN_EMAIL=super_admin_email
SUPER_ADMIN_PASSWORD=super_admin_password
FRONTEND_URL=http://localhost:5173
BACKEND_URL=http://localhost:5000
```

- `JWT_SECRET` is **required** and must be at least 32 characters. The server refuses to start without it. Generate one with:
  ```bash
  node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
  ```
- `FRONTEND_URL` is the only origin allowed by CORS and is used in staff invite links.
- `BACKEND_URL` is encoded into the QR codes for approved scholarships.
- `BREVO_API_KEY` and `BREVO_SENDER_EMAIL` are required to send OTP and invite emails. The sender address must be verified in your Brevo account. `BREVO_SENDER_NAME` is optional and defaults to `SafeApply`.

## Getting Started

1.  **Install dependencies:**

    ```bash
    npm install
    ```

2.  **Create the uploads folder** (Multer does not create it):

    ```bash
    mkdir uploads
    ```

3.  **Create the super admin account** using `SUPER_ADMIN_EMAIL` and `SUPER_ADMIN_PASSWORD`:

    ```bash
    node scripts/seedAdmin.js
    ```

4.  **Start the server:**
    - For development (with nodemon):
      ```bash
      npm run dev
      ```
    - For production:
      ```bash
      npm start
      ```
      The server will typically run on `http://localhost:5000` (or your configured PORT).

### RSA keys

If `config/public.pem` or `config/private.pem` is missing, the server generates a new RSA-4096 key pair in `config/` the first time it is needed. `private.pem` is git-ignored. **Back it up:** if it is lost or regenerated, every stored application and staff TOTP secret becomes impossible to decrypt.

## Scripts

- `npm start`: Runs the server using `node`.
- `npm run dev`: Runs the server using `nodemon` for hot-reloading during development.
- `node scripts/seedAdmin.js`: Creates the super admin account.
- `node scripts/resetAdmin.js`: Deletes the super admin account (run `seedAdmin.js` again afterwards to recreate it).

## Project Structure

```
ScholarshipSystem-Backend/
├── config/          # Database connection, JWT secret handling, RSA keys
├── controllers/     # Route logic handling
├── middleware/      # Express middleware (auth, roles, rate limiting, uploads, validation)
├── models/          # Mongoose data models
├── routes/          # API route definitions
├── scripts/         # Admin seeding and reset scripts
├── security/        # Encryption, hashing, digital signature and QR utilities
├── services/        # Email, OTP and TOTP services
├── uploads/         # Storage for uploaded files (create manually, git-ignored)
├── app.js           # Express app and middleware setup
├── server.js        # Entry point
└── package.json     # Dependencies and scripts
```
