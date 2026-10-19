import os
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from .database import get_db, init_db
from .auth import hash_password, sign_token, verify_token
from .cache import get_cached_workspace, set_cached_workspace


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="DocuVault API", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

def get_current_user(request: Request):
    user_id = request.cookies.get("user_id")
    sig = request.cookies.get("session_sig")
    if not user_id or not sig:
        return None
    if not verify_token(user_id, sig):
        return None

    conn = get_db()
    user = conn.execute(
        "SELECT id, username, bio FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

@app.get("/", response_class=HTMLResponse)
def index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    return HTMLResponse("<h1>DocuVault API</h1>")

@app.post("/api/register")
def register(username: str = Form(...), password: str = Form(...), bio: str = Form("Confidential Member")):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, bio) VALUES (?, ?, ?)",
            (username, hash_password(password), bio),
        )
        conn.commit()
        user_id = cur.lastrowid
    except Exception:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

    sig = sign_token(user_id)
    resp = JSONResponse({"status": "ok", "user_id": user_id, "username": username})
    resp.set_cookie("user_id", str(user_id), httponly=True)
    resp.set_cookie("session_sig", sig, httponly=True)
    return resp


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute(
        "SELECT id, username FROM users WHERE username = ? AND password_hash = ?",
        (username, hash_password(password)),
    ).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    sig = sign_token(user["id"])
    resp = JSONResponse({"status": "ok", "user_id": user["id"], "username": user["username"]})
    resp.set_cookie("user_id", str(user["id"]), httponly=True)
    resp.set_cookie("session_sig", sig, httponly=True)
    return resp


@app.get("/api/me")
def get_me(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@app.post("/api/logout")
def logout():
    resp = JSONResponse({"status": "logged_out"})
    resp.delete_cookie("user_id")
    resp.delete_cookie("session_sig")
    return resp

@app.post("/api/workspaces")
def create_workspace(handle: str = Form(...), name: str = Form(...), is_private: bool = Form(True), user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO workspaces (owner_id, handle, name, is_private) VALUES (?, ?, ?, ?)",
            (user["id"], handle, name, 1 if is_private else 0),
        )
        conn.commit()
        ws_id = cur.lastrowid
    except Exception:
        raise HTTPException(status_code=400, detail="Workspace handle already exists")
    finally:
        conn.close()

    ws_data = {"id": ws_id, "owner_id": user["id"], "handle": handle, "name": name, "is_private": 1 if is_private else 0}
    set_cached_workspace(handle, ws_data)
    return ws_data


@app.get("/api/workspaces")
def list_my_workspaces(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")
    conn = get_db()
    workspaces = conn.execute("SELECT * FROM workspaces WHERE owner_id = ?", (user["id"],)).fetchall()
    conn.close()
    return [dict(w) for w in workspaces]

@app.get("/api/workspaces/{handle}")
def get_workspace_documents(handle: str, user=Depends(get_current_user)):
    ws = get_cached_workspace(handle)

    if not ws:
        conn = get_db()
        row = conn.execute("SELECT * FROM workspaces WHERE handle = ?", (handle,)).fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        ws = dict(row)
        set_cached_workspace(handle, ws)

    conn = get_db()
    is_owner = (user is not None and user["id"] == ws["owner_id"])
    if is_owner:
        docs = conn.execute(
            "SELECT id, title, content, is_confidential, created_at FROM documents WHERE workspace_id = ?",
            (ws["id"],),
        ).fetchall()
    else:
        docs = conn.execute(
            "SELECT id, title, content, is_confidential, created_at FROM documents WHERE workspace_id = ? AND is_confidential = 0",
            (ws["id"],),
        ).fetchall()
    conn.close()

    return {
        "id": ws["id"],
        "workspace": ws["name"],
        "handle": ws["handle"],
        "owner_id": ws["owner_id"],
        "is_owner": is_owner,
        "documents": [dict(d) for d in docs],
    }


@app.post("/api/workspaces/{workspace_id}/documents")
def create_document(
    workspace_id: int,
    title: str = Form(...),
    content: str = Form(...),
    is_confidential: bool = Form(False),
    user=Depends(get_current_user),
):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    conn = get_db()
    ws = conn.execute("SELECT id FROM workspaces WHERE id = ? AND owner_id = ?", (workspace_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        raise HTTPException(status_code=403, detail="Workspace not found or unauthorized")

    cur = conn.execute(
        "INSERT INTO documents (workspace_id, title, content, is_confidential) VALUES (?, ?, ?, ?)",
        (workspace_id, title, content, 1 if is_confidential else 0),
    )
    conn.commit()
    doc_id = cur.lastrowid
    conn.close()

    return {"status": "ok", "document_id": doc_id, "title": title}

@app.get("/api/workspaces/{workspace_id}/documents/{document_id}/export")
def export_document(workspace_id: int, document_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    conn = get_db()
    ws = conn.execute("SELECT id FROM workspaces WHERE id = ? AND owner_id = ?", (workspace_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        raise HTTPException(status_code=403, detail="You do not own this workspace")

    doc = conn.execute("SELECT id, title, content, is_confidential FROM documents WHERE id = ?", (document_id,)).fetchone()
    conn.close()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    return {"exported_by": user["username"], "document": dict(doc)}

@app.get("/api/documents/{doc_id}/share-link")
def create_share_link(doc_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    sig = sign_token(doc_id)
    return {"share_url": f"/share?doc_id={doc_id}&sig={sig}", "doc_id": doc_id, "sig": sig}


@app.get("/share")
def view_shared_document(doc_id: int = None, sig: str = None):
    if doc_id is None or sig is None:
        return {"message": "Please provide doc_id and sig parameters"}

    if not verify_token(doc_id, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")

    conn = get_db()
    doc = conn.execute("SELECT id, title, content FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    return {"shared_document": dict(doc)}
