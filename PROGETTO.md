# Monitora la tua dieta — documentazione del progetto

Guida a come è fatto il progetto, come si installa da zero e come si usa.
Nessuna chiave reale è scritta in questo file: dove serve una chiave o un
URL c'è un segnaposto tra `< >` da sostituire con i valori reali. Il file
`.html` dell'app contiene invece l'URL e la chiave pubblica del progetto
Supabase incorporati nel codice (chiavi pubbliche per design — se non si
vuole esporre quale progetto Supabase è in uso, vanno sostituite con
segnaposto prima del push).

---

## 1. Cos'è

App web per il monitoraggio alimentare e dell'attività fisica: pasti con
alternative scelte da menu a tendina, diario con stima automatica delle
calorie, pianificazione settimanale, obiettivi di peso, avvisi per allergie
e preferenze alimentari, tracciamento di peso/circonferenza vita, sezione
dedicata all'esercizio fisico. I dati personali sono cifrati nel browser
prima di essere salvati — né il database né chi lo gestisce può leggerli
in chiaro.

## 2. Architettura

```
┌─────────────────────────┐        HTTPS         ┌──────────────────────────┐
│   Browser (il file       │  ────────────────►   │   Supabase                │
│   .html dell'app)        │                       │   - Auth (login/email)   │
│                           │  ◄────────────────   │   - Postgres (dati)      │
│   Cifratura/decifratura   │   solo blob cifrati   │   - Row Level Security   │
│   sempre qui              │                       │     (isolamento utenti) │
└─────────────────────────┘                       └──────────────────────────┘
```

- **Frontend**: file HTML + CSS + JS separati (`style.css`, `app.js`
  condivisi tra le 4 varianti per piattaforma). Nessuna build.
- **Backend**: Supabase. Autenticazione via email/password con reset
  reale, database Postgres, API automatica protetta da Row Level
  Security (RLS).
- **Cifratura**: Web Crypto API del browser (AES-256-GCM). La chiave che
  cifra i dati (DEK) non arriva mai al server: è avvolta da una chiave
  derivata dalla password, e da una seconda derivata da una chiave di
  recupero. Il server conserva solo le due versioni avvolte.
- **Persistenza delle credenziali**: sessione di accesso ed email restano
  salvate nel browser tra una visita e l'altra. La password non viene mai
  salvata, nemmeno cifrata — va sempre reinserita.

## 3. Modello di sicurezza

| Obiettivo | Meccanismo | Limite |
|---|---|---|
| Rientrare nel login se la password è persa | Email di reset (Supabase) | — |
| Tornare a leggere i vecchi dati cifrati | Chiave di recupero (mostrata una sola volta alla creazione dell'account) | Senza la chiave, i vecchi dati restano illeggibili in modo permanente |
| Cambiare la password conoscendo quella attuale | Impostazioni → Password | — |
| Verificare che il server non legga i dati | Tabelle `vault_keys` e `encrypted_records` su Supabase | Solo blob cifrati, mai testo in chiaro |

Stesso modello di Signal o Bitwarden: email che recupera sempre tutto e
server che non può leggere nulla sono in tensione tra loro per come
funziona la crittografia reale — non possono coesistere entrambi al 100%.

## 4. Struttura dei file

```
monitora-la-tua-dieta-<piattaforma>.html   → 4 varianti (iphone / android / mac / windows),
                                              identiche salvo le istruzioni di installazione
style.css                                  → stile condiviso dalle 4 varianti
app.js                                     → logica applicativa condivisa
supabase_schema.sql                        → schema del database, con RLS
test_rls.py                                → test automatico dell'isolamento tra utenti
backend/                                   → server Python opzionale, non richiesto da Supabase
index.html, robots.txt, sitemap.xml        → landing page pubblica
```

## 5. Installazione da zero

### 5.1 Progetto Supabase
1. Su [supabase.com](https://supabase.com): account gratuito → "New project".
2. Password del database Postgres (diversa dalla password dell'app) da
   salvare da parte.
3. Attesa fine provisioning (1-2 minuti).

### 5.2 Schema del database
1. Nel progetto: **SQL Editor**.
2. Incollare il contenuto di `supabase_schema.sql`.
3. **Run**. Crea le tabelle `vault_keys` e `encrypted_records`, entrambe
   con Row Level Security.

### 5.3 Chiavi del progetto
1. **Project Settings → API**.
2. Copiare:
   - **Project URL**: `https://<progetto>.supabase.co`
   - **anon public key** (o **publishable key** nei progetti recenti):
     pubblica per design, sicura da incorporare nel codice del browser.
3. La `service_role` key non va mai in un file client-side: accesso
   completo, bypassa la sicurezza, resta solo lato server.

### 5.4 Configurazione dell'app
Nel file `.html` della piattaforma scelta:

```javascript
const SUPABASE_URL = '<URL-DEL-PROGETTO>';
const SUPABASE_ANON_KEY = '<ANON-O-PUBLISHABLE-KEY>';
```

Da ripetere su ciascuna delle 4 varianti in uso.

### 5.5 Impostazioni di autenticazione
Su Supabase: **Authentication → Providers**, provider "Email" attivo.
**Authentication → Settings** per scegliere se richiedere conferma email
al primo accesso (l'app gestisce entrambi i casi).

### 5.6 Pubblicazione
Da locale (`file://`) l'app funziona per login e uso quotidiano, ma le
email di conferma/reset non hanno un indirizzo web reale a cui
reindirizzare. Serve un hosting statico (Vercel, Netlify, GitHub Pages) —
file statici, nessun server richiesto.

## 6. Struttura dell'app

Navigazione principale: pannello laterale a scomparsa (icona ☰), 5 voci,
alcune con sotto-menu.

### Pasti
Sotto-menu: Oggi · Diario · Piano settimanale.
- *Oggi*: target giornalieri in base a un obiettivo di peso, scelta dei
  pasti da menu a tendina con più alternative per pasto, voce
  personalizzabile liberamente (testo + kcal, anche 0), alternative
  leggere per i giorni difficili, aggiunta rapida al diario con stima
  automatica.
- *Diario*: cronologia dei pasti per qualsiasi data, navigazione
  giorno/settimana, riepilogo settimanale, modulo di aggiunta legato alla
  data selezionata.
- *Piano settimanale*: pianificazione libera per ogni giorno, più una
  traccia di esempio in stile mediterraneo con grammature e calorie.

Le scelte in "Oggi" si sincronizzano con la pianificazione settimanale e,
se confermate, con il diario.

### Alimenti e allergie
Sotto-menu: Alimenti · Allergie e preferenze.
- *Alimenti*: liste da privilegiare/limitare, alternative facili.
- *Allergie e preferenze*: allergie/intolleranze (campo libero), stile
  alimentare, gusti personali — usati per segnalare nel piano i pasti da
  evitare con un'alternativa.

### Progressi
Peso e circonferenza vita, vista giorno per giorno o settimana per
settimana (quest'ultima più affidabile, meno soggetta a oscillazioni per
liquidi).

### Esercizi
10 categorie di attività (camminata, corsa, nuoto, bicicletta, pesi,
palestra/circuito, HIIT, yoga/pilates, sport di squadra, movimento
quotidiano), ognuna con indicazioni su frequenza e avvio. Le attività
scelte si aggiungono a una routine personale.

### Impostazioni
- Nome visualizzato (saluto "Bentornato, nome").
- Email dell'account, modificabile (conferma richiesta al nuovo indirizzo).
- Password, modificabile — il cambiamento aggiorna anche la cifratura dei
  dati, senza bisogno della chiave di recupero.
- Rigenerazione della chiave di recupero.
- Disconnessione del dispositivo (i dati restano cifrati sull'account).

## 7. Accesso e recupero password

### Primo accesso
1. Schermata "Benvenuto": nome (opzionale), email, password (minimo 8
   caratteri).
2. Se il progetto richiede conferma email: link ricevuto via email, poi
   accesso con email + password.
3. Al primo accesso riuscito: chiave di recupero mostrata una sola volta,
   da salvare prima di proseguire (casella di conferma obbligatoria).

### Password dimenticata
1. "Ho dimenticato la password" nella schermata di accesso.
2. Chiave di recupero salvata al primo accesso → nuova password → accesso
   completo ai dati esistenti.
3. In alternativa, l'email di reset rimette a posto il login, ma senza la
   chiave di recupero i vecchi dati restano cifrati e illeggibili — per
   come funziona la crittografia, non per un difetto del sistema.

### Persistenza tra sessioni
- Email: pre-compilata alla visita successiva.
- Nome: mostrato nel saluto prima ancora di inserire la password.
- Sessione: se valida, evita il login completo — la password resta comunque
  necessaria per decifrare i dati, perché la chiave di cifratura non è
  conservata da nessuna parte tra una sessione e l'altra.
- Password: mai ricordata.

## 8. Verifica della cifratura

Su Supabase, **Table Editor**:
- `vault_keys`: `wrapped_password` e `wrapped_recovery` devono essere
  stringhe illeggibili (`iv:ciphertext` in base64).
- `encrypted_records`: `ciphertext` sempre illeggibile, indipendentemente
  da cosa è stato scritto nel diario.

Testo leggibile in una di queste due tabelle indica un problema nella
cifratura, da correggere prima di usare l'app con dati reali.

## 9. Limitazioni note

- Richiede connessione internet: ogni lettura/scrittura passa da Supabase.
- Il servizio email gratuito di Supabase ha un limite di invii orari; per
  uso con più utenti serve un provider SMTP dedicato (Brevo, Mailgun).
- Reset via email ripristina solo il login: i vecchi dati cifrati restano
  accessibili solo con la chiave di recupero. Eliminare questo limite
  richiederebbe che il server possa leggere i dati, il che annullerebbe
  la protezione.
- Recupero via SMS non incluso: richiede un gateway a pagamento (es.
  Twilio); email più chiave di recupero copre lo stesso bisogno senza
  costi.
- Da locale (`file://`) login e uso quotidiano funzionano, ma i link nelle
  email richiedono un indirizzo web reale per il reindirizzamento.
- La cartella `backend/` (Python/FastAPI) non è necessaria con
  l'architettura basata su Supabase. Resta disponibile per logica lato
  server che Supabase non offre.

---

By Lorè
