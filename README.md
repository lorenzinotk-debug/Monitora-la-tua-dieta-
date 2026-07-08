# Backend — Monitora la tua dieta

Backend Python (FastAPI) + PostgreSQL. Modello zero-knowledge: il server
autentica gli utenti e conserva i dati, ma non possiede mai la chiave che
li decifra. In caso di violazione del database, solo blob cifrati — niente
pasti, niente peso in chiaro.

Testato con 12 test end-to-end (`test_e2e.py`) contro un vero PostgreSQL.
Ultima verifica: 12/12 passati.

## Stato nel progetto

La versione live dell'app usa Supabase, non questo backend — Supabase dà
già autenticazione, database e API pronte. Il codice qui non è collegato al
frontend, ma è completo e testato: stessa cifratura, stessa cassaforte a
doppia chiave (password + chiave di recupero) della versione in produzione.

Serve come via d'uscita da Supabase se un giorno servono indipendenza da un
servizio terzo o logica lato server che Supabase non offre.

## Funzionalità

- Registrazione e login con password (hash Argon2)
- Sessioni con token JWT
- Cassaforte a doppia chiave: la DEK è avvolta sia dalla password sia da
  una chiave di recupero
- Storage di record cifrati (diario, target, peso, allergie) come blob
  opachi, isolati per utente
- Reset password via email (SMTP se configurato, log in sviluppo)

## Limite della crittografia

Il reset password via email rimette a posto il login, non l'accesso ai
vecchi dati cifrati — il server non ha mai avuto la chiave per decifrarli.
Serve la chiave di recupero. Stesso limite di Signal o Bitwarden.

## Sviluppo locale

```bash
pip install -r requirements.txt

# Postgres in locale, es. via Docker:
# docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=devpass postgres:16
psql -h localhost -U postgres -f schema.sql

cp .env.example .env   # compilare con i valori reali
export $(cat .env | xargs)
uvicorn main:app --reload

# in un altro terminale
python3 test_e2e.py
```

## Deploy

1. Database PostgreSQL gratuito su Supabase o Render. Stringa di
   connessione in `DATABASE_URL`.
2. Eseguire `schema.sql` sull'editor SQL della piattaforma, o
   `psql -f schema.sql` sulla connessione remota.
3. Web Service su Render o Railway collegato al repository. Variabili
   d'ambiente da `.env.example`. Avvio: `uvicorn main:app --host 0.0.0.0
   --port $PORT`.
4. Email reali: account SMTP su Brevo o Mailgun, credenziali in `.env`
   con `EMAIL_PROVIDER=smtp`.
5. Dominio: aggiornare `CORS_ORIGINS` e `APP_BASE_URL` una volta acquistato.

## Collegamento al frontend

Per abbandonare Supabase: riscrivere `storeGet` e `storeSet` nel frontend
perché chiamino questi endpoint. La cifratura lato browser resta identica,
cambia solo dove viaggiano i blob.

---
con dedizione da Lorenzo
