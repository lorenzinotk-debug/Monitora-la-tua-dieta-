"""
Backend per "Monitora la tua dieta" — modello zero-knowledge.

Il server:
- Autentica gli utenti (email + password) e rilascia un token di sessione.
- Conserva SOLO blob cifrati per i dati applicativi (diario, target, peso...).
- Non deriva né conserva mai la chiave che cifra quei dati (la DEK): quella
  chiave vive solo nel browser dell'utente, avvolta da password o da chiave
  di recupero — esattamente come nel modello già testato lato client.

Per questo il reset password via email può sempre far rientrare l'utente nel
suo ACCOUNT, ma per tornare a leggere i VECCHI dati cifrati serve la chiave
di recupero (o la vecchia password): è un limite della crittografia reale,
non una scelta arbitraria — vedi README.md.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import select
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr, Field

from database import get_db, get_email_sender, engine
from models import Base, User, VaultKey, EncryptedRecord, PasswordResetToken

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)  # no-op se le tabelle esistono già (schema.sql)

app = FastAPI(title="Monitora la tua dieta — API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET", "CAMBIA-QUESTO-SEGRETO-IN-PRODUZIONE")
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 24 * 7


# ---------------------------------------------------------------------------
# Schemi Pydantic (contratto dell'API)
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    display_name: str | None = None
    salt_password: str
    wrapped_password: str
    salt_recovery: str
    wrapped_recovery: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class VaultKeysResponse(BaseModel):
    salt_password: str
    wrapped_password: str
    salt_recovery: str
    wrapped_recovery: str


class VaultKeysUpdateRequest(BaseModel):
    salt_password: str
    wrapped_password: str


class RecoveryKeysUpdateRequest(BaseModel):
    salt_recovery: str
    wrapped_recovery: str


class RecordUpsertRequest(BaseModel):
    ciphertext: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


# ---------------------------------------------------------------------------
# Autenticazione
# ---------------------------------------------------------------------------
def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
        user_id = payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token non valido o scaduto")
    user = db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utente non trovato")
    return user


# ---------------------------------------------------------------------------
# Endpoint: registrazione e login
# ---------------------------------------------------------------------------
@app.post("/auth/register", response_model=TokenResponse, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(400, "Email già registrata")

    user = User(
        email=payload.email,
        password_hash=pwd_context.hash(payload.password),
        display_name=payload.display_name,
    )
    db.add(user)
    db.flush()  # per avere user.id

    vault = VaultKey(
        user_id=user.id,
        salt_password=payload.salt_password,
        wrapped_password=payload.wrapped_password,
        salt_recovery=payload.salt_recovery,
        wrapped_recovery=payload.wrapped_recovery,
    )
    db.add(vault)
    db.commit()

    return TokenResponse(access_token=create_access_token(str(user.id)))


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(401, "Email o password non corretti")
    return TokenResponse(access_token=create_access_token(str(user.id)))


@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"id": str(user.id), "email": user.email, "display_name": user.display_name}


# ---------------------------------------------------------------------------
# Endpoint: cassaforte (salt + DEK avvolta) — il server non la decifra mai
# ---------------------------------------------------------------------------
@app.get("/vault-keys", response_model=VaultKeysResponse)
def get_vault_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vault = db.get(VaultKey, user.id)
    if not vault:
        raise HTTPException(404, "Cassaforte non trovata")
    return VaultKeysResponse(
        salt_password=vault.salt_password,
        wrapped_password=vault.wrapped_password,
        salt_recovery=vault.salt_recovery,
        wrapped_recovery=vault.wrapped_recovery,
    )


@app.put("/vault-keys/password")
def update_password_wrap(
    payload: VaultKeysUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Il client chiama questo DOPO aver ri-avvolto la DEK con una nuova password
    (tipico dopo un recupero via chiave). Il server sostituisce solo il blob."""
    vault = db.get(VaultKey, user.id)
    if not vault:
        raise HTTPException(404, "Cassaforte non trovata")
    vault.salt_password = payload.salt_password
    vault.wrapped_password = payload.wrapped_password
    db.commit()
    return {"ok": True}


@app.put("/vault-keys/recovery")
def update_recovery_wrap(
    payload: RecoveryKeysUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Rigenera la chiave di recupero (invalida quella precedente)."""
    vault = db.get(VaultKey, user.id)
    if not vault:
        raise HTTPException(404, "Cassaforte non trovata")
    vault.salt_recovery = payload.salt_recovery
    vault.wrapped_recovery = payload.wrapped_recovery
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Endpoint: record cifrati (diario, target, peso, allergie...)
# ---------------------------------------------------------------------------
@app.get("/records")
def list_records(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(EncryptedRecord).where(EncryptedRecord.user_id == user.id)).all()
    return {r.record_key: r.ciphertext for r in rows}


@app.get("/records/{record_key}")
def get_record(record_key: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(EncryptedRecord, {"user_id": user.id, "record_key": record_key})
    if not row:
        raise HTTPException(404, "Non trovato")
    return {"record_key": record_key, "ciphertext": row.ciphertext}


@app.put("/records/{record_key}")
def upsert_record(
    record_key: str,
    payload: RecordUpsertRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.get(EncryptedRecord, {"user_id": user.id, "record_key": record_key})
    if row:
        row.ciphertext = payload.ciphertext
    else:
        row = EncryptedRecord(user_id=user.id, record_key=record_key, ciphertext=payload.ciphertext)
        db.add(row)
    db.commit()
    return {"ok": True}


@app.delete("/records/{record_key}")
def delete_record(record_key: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(EncryptedRecord, {"user_id": user.id, "record_key": record_key})
    if row:
        db.delete(row)
        db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Endpoint: reset password via email (ripristina il LOGIN, non i vecchi dati
# senza la chiave di recupero — vedi nota in cima al file e nel README)
# ---------------------------------------------------------------------------
@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    # Risposta identica anche se l'email non esiste, per non rivelare quali email sono registrate
    if user:
        token = uuid.uuid4().hex
        reset = PasswordResetToken(
            token=token,
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add(reset)
        db.commit()
        base_url = os.environ.get("APP_BASE_URL", "https://TUO-DOMINIO.it")
        reset_link = f"{base_url}/reset-password.html?token={token}"
        get_email_sender().send_password_reset(user.email, reset_link)
    return {"ok": True, "message": "Se l'email è registrata, riceverai un link per reimpostare la password."}


@app.post("/auth/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    reset = db.get(PasswordResetToken, payload.token)
    if not reset or reset.used or reset.expires_at < datetime.now(timezone.utc):
        raise HTTPException(400, "Link non valido o scaduto")
    user = db.get(User, reset.user_id)
    user.password_hash = pwd_context.hash(payload.new_password)
    reset.used = True
    db.commit()
    return {
        "ok": True,
        "message": "Password del login aggiornata. Per tornare a leggere i dati salvati, "
                    "apri l'app e usa la tua chiave di recupero per ri-agganciare la nuova password ai dati cifrati."
    }


@app.get("/health")
def health():
    return {"status": "ok"}

# con dedizione da Lorenzo
