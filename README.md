# SafeApply - Secure Scholarship System - Server

This is the backend server for the SafeApply, built with [Node.js](https://nodejs.org/) and [Express](https://expressjs.com/). It handles authentication, application processing, and secure data management.

The Frontend code is at [Repo](https://github.com/USER1043/ScholarshipSystem-Frontend)

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB (via Mongoose)
- **Authentication:** JWT, bcryptjs
- **Security:** Helmet, Express Rate Limit, Speakeasy (2FA)
- **File Handling:** Multer
- **Validation:** Express Validator

## Features

- **Role-Based Access Control (RBAC):** Distinct routes and permissions for Students, Verifiers, and Admins.
- **Two-Factor Authentication (2FA):** Integrated using Speakeasy and QR codes.
- **Secure File Uploads:** For scholarship documents.
- **Data Security:** Input validation, rate limiting, and secure HTTP headers.
- **Email Notifications:** Integrated with Nodemailer.

## Prerequisites

- Node.js (v18+ recommended)
- MongoDB (Local or AtlasURI)
- npm or yarn

## Environment Variables

Create a `.env` file in the `server` directory with the following variables:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
EMAIL_USER=your_email_address
EMAIL_PASS=your_email_password
SUPER_ADMIN_EMAIL=super_admin_email
SUPER_ADMIN_PASSWORD=super_admin_password
```

## Getting Started

1.  **Navigate to the server directory:**

    ```bash
    cd server
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Start the server:**
    - For development (with nodemon):
      ```bash
      npm run dev
      ```
    - For production:
      ```bash
      npm start
      ```
      The server will typically run on `http://localhost:5000` (or your configured PORT).

## Scripts

- `npm start`: Runs the server using `node`.
- `npm run dev`: Runs the server using `nodemon` for hot-reloading during development.

## Project Structure

```
server/
├── config/          # Database and other configurations
├── controllers/     # Route logic handling
├── middleware/      # Express middleware (auth, upload, etc.)
├── models/          # Mongoose data models
├── routes/          # API route definitions
├── security/        # Security-related utilities (crypto, keys)
├── services/        # Business logic services
├── uploads/         # Storage for uploaded files
├── utils/           # Helper functions
├── server.js        # Entry point
└── package.json     # Dependencies and scripts
```
