# DocuVault — Enterprise Confidential Workspaces & Audited Archive
## Official Player Guide & Service Documentation

Welcome to **DocuVault**, an enterprise confidential document management and workspace collaboration platform designed for legal counsel, engineering executives, and compliance auditors. DocuVault provides multi-tenant repository partitioning, cryptographic record sharing, compliance document archival, and strict member identity isolation.

---

### Service Information
- **Service Name:** DocuVault (Enterprise Confidential Workspaces)
- **Default Port:** `8000`
- **Frontend URL:** `http://<target-ip>:8000/`
- **Interactive Swagger Docs:** `http://<target-ip>:8000/docs`
- **Authentication Scheme:** HTTPOnly Cookies (`user_id`, `session_sig`) signed via HMAC-SHA256

---

### Overview of Modules & Features

```
+-----------------------------------------------------------------------------------+
|                           DocuVault Enterprise Platform                           |
+-----------------------------------------------------------------------------------+
| [📁 Workspaces & Vaults] | [📤 Compliance Exporter] | [🔗 Cryptographic Share Viewer] |
+-----------------------------------------------------------------------------------+
```

#### 1. 🔐 Member Identity & Session Management (`Identity & Profile`)
DocuVault manages user authentication through cryptographic session cookies signed by the platform core.
- **Register Account:** Enroll a new member profile (`username`, `password`, `bio`). The `bio` parameter holds confidential role credentials or executive memos (e.g. `Chief Information Security Officer`).
- **Member Login:** Verifies credentials and sets two HTTPOnly session cookies:
  - `user_id`: The database identity key of the authenticated user.
  - `session_sig`: A 64-character SHA-256 HMAC cryptographic signature validating the `user_id`.
- **Identity Profile (`/api/me`):** Retrieves the current authenticated user's record, profile memo, and authorization state.
- **Session Termination (`/api/logout`):** Clears the active session cookies.

#### 2. 📁 Workspaces & Confidential Document Repositories (`Workspaces`)
Workspaces allow members to organize memos, classified briefs, and operational records into isolated repositories.
- **Create Workspace:** Provision a repository partition with a unique `@handle` (e.g. `quantum-rnd`), display name, and privacy classification (`is_private = true/false`).
- **My Workspaces:** Lists all repositories registered or owned by the authenticated member.
- **Workspace Document Explorer:** Query any workspace by its handle (`/api/workspaces/{handle}`).
  - **Ownership Privileges:** Workspace owners can view all documents, including classified memos (`is_confidential = 1`).
  - **Public Visitors:** Non-owners browsing a workspace can only view unclassified records (`is_confidential = 0`).
- **Publish Document Record:** Append a new document record to an owned workspace (`title`, `content`, `is_confidential`).

#### 3. 📤 Compliance Document Exporter (`Document Exporter`)
A regulatory compliance extraction utility designed for audited data retention and legal discovery.
- **Export by Reference:** Accepts a `workspace_id` and a `document_id`.
- **Integrity Validation:** Verifies caller authorization against the specified workspace and returns a structured export manifest:
  - `exported_by`: The username of the authenticated compliance officer.
  - `document`: The complete record object containing `id`, `title`, `content`, and classification.

#### 4. 🔗 Cryptographic Document Sharing (`Public Share Viewer`)
Allows workspace members to delegate external read access for specific documents to third parties without granting general workspace credentials.
- **Generate Cryptographic Share Link:** Authorized members can call `/api/documents/{doc_id}/share-link` to sign a target record. The server issues a tamper-proof SHA-256 HMAC signature (`sig`).
- **Public Shared Viewer (`/share?doc_id={id}&sig={sig}`):** Unauthenticated third parties can view the targeted document by providing the document ID and valid HMAC signature. Signatures are verified against the DocuVault master HMAC key.

---

### Key API Endpoints Reference

| Endpoint | Method | Auth Required | Parameters / Body | Description |
| :--- | :---: | :---: | :--- | :--- |
| `GET /` | `GET` | No | None | Interactive Web Dashboard (Tailwind CSS SPA) |
| `/api/register` | `POST` | No | Form: `username`, `password`, `bio` | Register account and set session cookies |
| `/api/login` | `POST` | No | Form: `username`, `password` | Authenticate and set session cookies |
| `/api/me` | `GET` | Yes | Cookies: `user_id`, `session_sig` | Fetch authenticated user profile and bio |
| `/api/logout` | `POST` | Yes | Cookies: `user_id`, `session_sig` | Terminate session and invalidate cookies |
| `/api/workspaces` | `POST` | Yes | Form: `handle`, `name`, `is_private` | Create a new workspace repository |
| `/api/workspaces` | `GET` | Yes | Cookies | List workspaces owned by current user |
| `/api/workspaces/{handle}` | `GET` | Optional | Path: `handle` | Browse workspace and view visible documents |
| `/api/workspaces/{ws_id}/documents` | `POST` | Yes | Path: `ws_id`, Form: `title`, `content`, `is_confidential` | Publish document to owned workspace |
| `/api/workspaces/{ws_id}/documents/{doc_id}/export` | `GET` | Yes | Path: `ws_id`, `doc_id` | Export document record for compliance archive |
| `/api/documents/{doc_id}/share-link` | `GET` | Yes | Path: `doc_id` | Generate HMAC signature for external document access |
| `/share` | `GET` | No | Query: `doc_id`, `sig` | Access cryptographically verified shared document |

---

### Interacting with DocuVault

#### Via the Web Dashboard
1. Open `http://<target-ip>:8000/` in any modern web browser.
2. Sign in or register an account in the top-right menu.
3. Manage workspaces, compose confidential memos, export archived records, and test cryptographic signatures directly through the UI.

#### Via CLI / Python
DocuVault endpoints rely on cookie-based authentication. In scripts, maintain a persistent session object:
```python
import requests

session = requests.Session()

# Authenticate
session.post("http://<target-ip>:8000/api/login", data={"username": "alice", "password": "securepassword"})

# Query authenticated profile
me = session.get("http://<target-ip>:8000/api/me").json()
print("Logged in as:", me["username"])

# Create a workspace
ws = session.post("http://<target-ip>:8000/api/workspaces", data={
    "handle": "legal-ops",
    "name": "Legal Operations Vault",
    "is_private": "true"
}).json()

# Export a document
export = session.get(f"http://<target-ip>:8000/api/workspaces/{ws['id']}/documents/1/export").json()
print("Exported document:", export)
```
