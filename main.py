import os
import re
import hashlib
import base64
import json
import secrets
import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import (
    PractitionerVerifyRequest,
    PractitionerResponse,
    ChatMessageCreate,
    ChatMessageResponse,
    DietPlanRequest,
    DietPlan,
    ConsultationSessionCreate,
    ConsultationSessionResponse,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = FastAPI(title="AyurVeda Secure API", version="0.1.0")

# CORS for local dev and Vite frontend
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Crypto helpers (AES-256-GCM)
AES_KEY_B64 = os.getenv("AES_KEY_B64")  # 32-byte key in base64
if not AES_KEY_B64:
    # Generate deterministic dev key per container if not provided
    key = hashlib.sha256(b"dev-default-key").digest()
    AES_KEY_B64 = base64.b64encode(key).decode()

AES_KEY = base64.b64decode(AES_KEY_B64)
if len(AES_KEY) != 32:
    raise RuntimeError("AES key must be 32 bytes for AES-256-GCM")

aesgcm = AESGCM(AES_KEY)


def sanitize_no_external_contact(text: str) -> str:
    if not text:
        return text
    # Remove URLs and emails
    text = re.sub(r"https?://\S+|www\.\S+|\S+@\S+", "[redacted]", text, flags=re.IGNORECASE)
    # Remove phone numbers (simple patterns)
    text = re.sub(r"(\+\d{1,3}[- ]?)?\d{10,}", "[redacted]", text)
    return text


def encrypt_content(plain: Optional[str]) -> Optional[dict]:
    if plain is None:
        return None
    nonce = os.urandom(12)
    data = plain.encode()
    ct = aesgcm.encrypt(nonce, data, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "alg": "AES-256-GCM",
    }


def decrypt_content(enc: Optional[dict]) -> Optional[str]:
    if not enc:
        return None
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ciphertext"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode()


@app.get("/test")
async def test():
    try:
        # simple ping to DB
        await db().command("ping")
        return {"ok": True, "db": "connected"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/practitioner/verify", response_model=PractitionerResponse)
async def practitioner_verify(payload: PractitionerVerifyRequest):
    if not re.match(r"^[A-Z0-9-]{6,32}$", payload.ayush_id):
        raise HTTPException(status_code=400, detail="Invalid AYUSH Register Number format")

    # Simulate AYUSH registry check and create a credential hash
    cred_material = f"{payload.ayush_id}|{payload.name}|{payload.document_hash}".encode()
    credential_hash = hashlib.sha256(cred_material).hexdigest()

    # Upsert practitioner
    existing = await db()["practitioner"].find_one({"ayush_id": payload.ayush_id})
    if existing:
        practitioner_id = str(existing.get("_id"))
        await db()["practitioner"].update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "name": payload.name,
                "specialization": payload.specialization,
                "verified": True,
                "credential_hash": credential_hash,
                "updated_at": datetime.datetime.utcnow(),
            }},
        )
    else:
        created = await create_document(
            "practitioner",
            {
                "ayush_id": payload.ayush_id,
                "name": payload.name,
                "specialization": payload.specialization,
                "verified": True,
                "credential_hash": credential_hash,
            },
        )
        practitioner_id = created["_id"]

    # Write immutable audit log (anchoring hash)
    tx_hash = hashlib.sha256((credential_hash + "|verify").encode()).hexdigest()
    await create_document(
        "audit",
        {
            "type": "practitioner_verification",
            "ayush_id": payload.ayush_id,
            "credential_hash": credential_hash,
            "tx_hash": tx_hash,
        },
    )

    return PractitionerResponse(
        practitioner_id=practitioner_id,
        verified=True,
        credential_hash=credential_hash,
        tx_hash=tx_hash,
    )


@app.post("/chat/send", response_model=ChatMessageResponse)
async def chat_send(msg: ChatMessageCreate):
    if not msg.content and not msg.attachments:
        raise HTTPException(status_code=400, detail="Message must contain content or attachments")

    clean_text = sanitize_no_external_contact(msg.content) if msg.content else None
    enc = encrypt_content(clean_text) if clean_text is not None else None

    to_store = {
        "patient_id": msg.patient_id,
        "practitioner_id": msg.practitioner_id,
        "role": msg.role,
        "enc": enc,
        "attachments": msg.attachments or [],
        "language": msg.language or "auto",
    }
    created = await create_document("chatmessage", to_store)

    # Produce audit hash over immutable fields
    audit_payload = json.dumps(
        {
            "pid": msg.patient_id,
            "prid": msg.practitioner_id,
            "role": msg.role,
            "attachments": msg.attachments or [],
            "language": msg.language or "auto",
            "enc_present": enc is not None,
            "created_at": created.get("created_at", ""),
        },
        sort_keys=True,
        default=str,
    ).encode()
    chat_hash = hashlib.sha256(audit_payload).hexdigest()
    await create_document(
        "audit",
        {"type": "chat_message", "hash": chat_hash, "ref_id": created["_id"]},
    )

    # Build response with decrypted content
    return ChatMessageResponse(
        _id=created["_id"],
        patient_id=msg.patient_id,
        practitioner_id=msg.practitioner_id,
        role=msg.role,
        content=clean_text,
        attachments=msg.attachments or [],
        language=msg.language or "auto",
        created_at=str(created.get("created_at")),
    )


@app.get("/chat/history", response_model=List[ChatMessageResponse])
async def chat_history(
    patient_id: str = Query(...),
    practitioner_id: str = Query(...),
    limit: int = Query(50, ge=1, le=200),
):
    items = await get_documents(
        "chatmessage",
        {"patient_id": patient_id, "practitioner_id": practitioner_id},
        limit=limit,
        sort=[("created_at", 1)],
    )
    responses: List[ChatMessageResponse] = []
    for it in items:
        content = decrypt_content(it.get("enc")) if it.get("enc") else None
        responses.append(
            ChatMessageResponse(
                _id=it["_id"],
                patient_id=it["patient_id"],
                practitioner_id=it["practitioner_id"],
                role=it["role"],
                content=content,
                attachments=it.get("attachments", []),
                language=it.get("language", "auto"),
                created_at=str(it.get("created_at")),
            )
        )
    return responses


@app.post("/ai/diet-plan", response_model=DietPlan)
async def ai_diet_plan(req: DietPlanRequest):
    # Lightweight rule-based generator as a stand-in for an AI model
    name = req.name or "patient"
    prakriti = (req.prakriti or "").lower()
    location = req.location or "your area"

    base_diet = [
        "Warm water with lemon and ginger on waking",
        "Balanced khichdi with seasonal vegetables",
        "Steamed local greens with ghee and cumin",
        "Golden milk (turmeric + pepper) before bed",
    ]
    base_life = [
        "Wake before sunrise; light stretching",
        "Pranayama and mindful meals",
        "Evening walk; digital detox 1 hour before sleep",
    ]

    if "vata" in prakriti:
        base_diet.append("Add warm, oily foods; avoid raw and cold items")
        base_life.append("Favor grounding routines and regularity")
    if "pitta" in prakriti:
        base_diet.append("Favor cooling foods; reduce spicy, sour, and fried items")
        base_life.append("Incorporate cooling breathwork and avoid midday heat")
    if "kapha" in prakriti:
        base_diet.append("Favor light, warm foods; limit dairy and heavy sweets")
        base_life.append("Increase activity; stimulate with dry brushing")

    summary = f"Personalized Ayurvedic plan for {name} aligned with NRF principles."
    adjustments = f"Optimized for {location} based on local availability."

    return DietPlan(summary=summary, diet=base_diet, lifestyle=base_life, adjustments=adjustments)


@app.post("/consultation/session", response_model=ConsultationSessionResponse)
async def consultation_session(s: ConsultationSessionCreate):
    # Create ephemeral session token for WebRTC signaling (placeholder token)
    session_id = hashlib.sha256(f"{s.patient_id}|{s.practitioner_id}|{secrets.token_hex(8)}".encode()).hexdigest()[:24]
    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    expires_in = 60 * 30  # 30 minutes

    await create_document(
        "consultation",
        {
            "session_id": session_id,
            "patient_id": s.patient_id,
            "practitioner_id": s.practitioner_id,
            "token": token,
            "expires_at": datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
        },
    )

    await create_document(
        "audit",
        {"type": "consultation_session", "session_id": session_id},
    )

    return ConsultationSessionResponse(session_id=session_id, token=token, expires_in=expires_in)
