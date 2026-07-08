-- ============================================================
-- Schema per "Monitora la tua dieta" — backend con crittografia zero-knowledge
-- Il server non vede MAI i dati in chiaro: riceve e restituisce solo blob
-- cifrati che il client (browser) cifra e decifra con una chiave che il
-- server non possiede mai.
-- ============================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash   TEXT NOT NULL,          -- argon2, per il LOGIN (non per decifrare i dati)
    display_name    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- La "cassaforte": la DEK (chiave che cifra davvero i dati) è avvolta due
-- volte, esattamente come nel modello client-side già testato: una copia
-- avvolta dalla password, una dalla chiave di recupero. Il server conserva
-- solo le versioni cifrate (wrapped), non la DEK in chiaro.
CREATE TABLE vault_keys (
    user_id         UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    salt_password   TEXT NOT NULL,
    wrapped_password TEXT NOT NULL,
    salt_recovery   TEXT NOT NULL,
    wrapped_recovery TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tutti i dati applicativi (diario, target, peso, allergie...) sono blob
-- cifrati lato client. Il server li tratta come opachi: chiave -> valore cifrato.
CREATE TABLE encrypted_records (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_key      TEXT NOT NULL,          -- es. 'diary:2026-07-05', 'profile', 'weightlog'
    ciphertext      TEXT NOT NULL,           -- formato iv:ciphertext in base64, cifrato dal client
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, record_key)
);

-- Token per il reset della password (via email): permette di rientrare nel
-- LOGIN, non di decifrare vecchi dati senza la chiave di recupero — vedi nota
-- nel README sul perché questa distinzione è inevitabile con crittografia reale.
CREATE TABLE password_reset_tokens (
    token           TEXT PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_encrypted_records_user ON encrypted_records(user_id);
CREATE INDEX idx_reset_tokens_user ON password_reset_tokens(user_id);

-- con dedizione da Lorenzo
