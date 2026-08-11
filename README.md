# CyberGuard

A web security assessment tool built with React + Vite (frontend) and Node.js + Express (backend).

> **Disclaimer:** This tool is intended for authorised security assessments only. Only scan targets you own or have explicit permission to test.

---

## Project Structure

```
cyberguard/
├── client/          # React + Vite frontend
│   └── src/
│       ├── api/          # Axios API service
│       ├── components/   # React components
│       └── utils/        # Formatting helpers
├── server/          # Node.js + Express backend
│   └── src/
│       ├── controllers/  # Request handlers
│       ├── routes/       # Express route definitions
│       ├── services/     # Core scanner logic
│       └── utils/        # Validation helpers
├── .gitignore
└── README.md
```

---

## Prerequisites

- **Node.js** v18 or higher
- **npm** v9 or higher

---

## Installation

Install dependencies for both the server and client. Run from the project root:

```bash
# Install server dependencies
cd server
npm install

# Install client dependencies
cd ../client
npm install
```

---

## Running the Application

You need **two terminals** — one for each side.

### Terminal 1 — Backend (Express server)

```bash
cd server
npm run dev
```

The API server will start at: `http://localhost:5000`

### Terminal 2 — Frontend (Vite dev server)

```bash
cd client
npm run dev
```

The React app will open at: `http://localhost:5173`

> The Vite dev server proxies all `/api` requests to `http://localhost:5000`, so no CORS configuration is needed during development.

---

## API Reference

### `POST /api/scan`

Scans a target URL and returns basic security information.

**Request**

```http
POST http://localhost:5000/api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Success Response** `200 OK`

```json
{
  "target": "https://example.com",
  "statusCode": 200,
  "statusText": "OK",
  "responseTime": 312,
  "isHttps": true,
  "contentType": "text/html",
  "server": "ECS (nyb/1D1B)"
}
```

**Error Response** `400 Bad Request`

```json
{
  "error": "Invalid URL. Must be a valid HTTP or HTTPS URL."
}
```

**Error Response** `502 Bad Gateway`

```json
{
  "error": "The target did not respond within the allowed time limit."
}
```

### `GET /health`

Returns server health status.

```json
{ "status": "ok", "service": "CyberGuard API" }
```

---

## Environment Variables

No environment variables are required to run locally. If you want to change the default port, you can set `PORT` before starting the server:

```bash
PORT=8080 npm run dev
```
