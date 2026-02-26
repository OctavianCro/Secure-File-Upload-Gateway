from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.responses import FileResponse
from typing import Optional
import os
import uuid

app = FastAPI()

# In-memory metadata store (will reset if server restarts)
file_store = {}

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf"}
UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

os.makedirs(UPLOAD_DIR, exist_ok=True)


def is_valid_signature(header: bytes, extension: str) -> bool:
    """Basic magic-byte validation for allowed types."""
    if extension == ".png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {".jpg", ".jpeg"}:
        return header.startswith(b"\xff\xd8\xff")
    if extension == ".pdf":
        return header.startswith(b"%PDF-")
    return False


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    x_user_id: Optional[str] = Header(None),
):
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Missing user ID")

    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    extension = os.path.splitext(file.filename)[1].lower()

    # allowlist extension
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")

    # read header and validate signature (magic bytes)
    header = await file.read(16)
    if not is_valid_signature(header, extension):
        raise HTTPException(status_code=400, detail="File content does not match extension")

    # stream-read remaining bytes with size cap (prevents DoS)
    current_size = len(header)
    contents = bytearray(header)

    while True:
        chunk = await file.read(1024 * 1024)  # 1MB chunks
        if not chunk:
            break

        current_size += len(chunk)
        if current_size > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")

        contents.extend(chunk)

    # store safely (UUID filename, user filename never used for paths)
    file_id = str(uuid.uuid4())
    stored_filename = f"{file_id}{extension}"
    file_path = os.path.join(UPLOAD_DIR, stored_filename)

    with open(file_path, "wb") as f:
        f.write(contents)

    # save metadata for authorization (prevents IDOR)
    file_store[file_id] = {
        "owner": x_user_id,
        "path": file_path,
        "original_name": file.filename,
        "size": current_size,
        "extension": extension,
    }

    return {"file_id": file_id, "size": current_size}


@app.get("/files/{file_id}")
def download_file(
    file_id: str,
    x_user_id: Optional[str] = Header(None),
):
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Missing user ID")

    record = file_store.get(file_id)
    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    # IDOR protection
    if record["owner"] != x_user_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    # extra safety: ensure path still exists on disk
    if not os.path.exists(record["path"]):
        raise HTTPException(status_code=404, detail="File missing on disk")

    return FileResponse(record["path"], filename=record["original_name"])