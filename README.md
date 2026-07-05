# Monitora la tua dieta — documentazione del progetto

Guida a come è fatto il progetto, come si installa da zero e come si usa.
Nessuna chiave reale è scritta in questo file: dove serve una chiave o un
URL trovi un segnaposto tra `< >` da sostituire con i tuoi valori.

---

## 1. Cos'è

Un'app web per il monitoraggio alimentare: diario con stima automatica delle
calorie, piano settimanale, obiettivi di peso, avvisi per allergie e
preferenze alimentari, tracciamento di peso/circonferenza vita. Tutti i dati
personali sono **cifrati nel browser prima di essere salvati** — né il
database né chi lo gestisce possono leggerli in chiaro.

## 2. Architettura

```
┌─────────────────────────┐        HTTPS         ┌──────────────────────────┐
│   Browser (il file       │  ────────────────►   │   Supabase                │
│   .html dell'app)        │                       │   - Auth (login/email)   │
│                           │  ◄────────────────   │   - Postgres (dati)      │
│   Qui avviene TUTTA la    │   solo blob cifrati   │   - Row Level Security   │
│   cifratura/decifratura   │                       │     (isolamento utenti) │
└─────────────────────────┘                       └──────────────────────────┘
```

- **Frontend**: un unico file HTML (contiene HTML, CSS e JavaScript). Nessuna
  build, nessun server da scrivere per la parte applicativa.
- **Backend**: Supabase (progetto gratuito). Fornisce autenticazione via
  email/password, database Postgres, e un'API automatica sul database
  protetta da Row Level Security (RLS) — non serve scrivere un server a mano.
- **Cifratura**: Web Crypto API del browser (AES-256-GCM). La chiave che
  cifra i dati (DEK) non viene mai inviata al server: viene "avvolta"
  (wrapped) da una chiave derivata dalla password, e da una seconda derivata
  da una chiave di recupero. Il server conserva solo le due versioni avvolte.

## 3. Modello di sicurezza, in breve

| Cosa vuoi fare | Cosa serve | Cosa NON succede |
|---|---|---|
| Accedere al login se scordi la password | Email di reset (Supabase) | — |
| Tornare a leggere i vecchi dati cifrati | La chiave di recupero (mostrata una sola volta alla creazione dell'account) | Senza la chiave, i vecchi dati restano illeggibili per sempre — anche per chi gestisce il database |
| Verificare che il server non legga i dati | Guardare la tabella `encrypted_records` | Non troverai mai testo in chiaro, solo blob cifrati |

Questo è lo stesso modello usato da app come Signal o Bitwarden: nessuno può
avere "l'email recupera sempre tutto" *e* "il server non può leggere nulla"
allo stesso tempo — sono in tensione tra loro per come funziona la
crittografia reale.

## 4. Struttura dei file consegnati

```
monitora-la-tua-dieta-cloud.html   → l'app (versione collegata a Supabase)
supabase_schema.sql                → schema del database, con RLS (da eseguire su Supabase)
test_rls.py                        → test automatico dell'isolamento tra utenti
backend/                           → server Python opzionale (non necessario con Supabase,
                                      utile solo se in futuro serve logica custom lato server)
index.html, robots.txt, sitemap.xml → landing page pubblica per quando pubblichi un dominio
```

## 5. Come installare il progetto da zero

### 5.1 Crea il progetto Supabase
1. Vai su [supabase.com](https://supabase.com) → crea un account gratuito → "New project".
2. Scegli una password per il database e salvala da parte (non è la password dell'app, è quella del database Postgres).
3. Attendi che il progetto finisca di provisionare (1-2 minuti).

### 5.2 Applica lo schema del database
1. Nel progetto, apri **SQL Editor** (menu a sinistra).
2. Incolla tutto il contenuto di `supabase_schema.sql`.
3. Premi **Run**. Deve terminare senza errori (crea le tabelle `vault_keys` e
   `encrypted_records`, entrambe protette da Row Level Security).

### 5.3 Recupera le chiavi del progetto
1. Vai su **Project Settings → API**.
2. Copia:
   - **Project URL** → una stringa come `https://<il-tuo-progetto>.supabase.co`
   - **anon public key** (o, nei progetti più recenti, la **publishable key**) → è pensata per essere pubblica, sicura da incorporare nel codice del browser
3. **Non copiare mai la `service_role` key** in un file client-side: quella
   ha accesso completo e bypassa la sicurezza — resta sempre sul server, se
   mai ne avrai bisogno.

### 5.4 Configura l'app
Apri `monitora-la-tua-dieta-cloud.html` con un editor di testo, cerca queste
due righe (vicino all'inizio dello script) e sostituisci i valori:

```javascript
const SUPABASE_URL = '<URL-DEL-TUO-PROGETTO>';
const SUPABASE_ANON_KEY = '<LA-TUA-ANON-O-PUBLISHABLE-KEY>';
```

### 5.5 Verifica le impostazioni di autenticazione
Su Supabase, vai su **Authentication → Providers** e assicurati che "Email"
sia attivo. Su **Authentication → Settings** puoi scegliere se richiedere la
conferma email prima del primo accesso (l'app gestisce entrambi i casi).

### 5.6 Pubblica il file
Per ora puoi aprire il file `.html` direttamente nel browser per testare.
Per renderlo raggiungibile da altri, caricalo su un hosting statico gratuito
(Vercel, Netlify, GitHub Pages) — non serve altro, è un file singolo.

## 6. Come si usa l'app (lato utente finale)

### Primo accesso
1. Si apre l'app → schermata "Benvenuto".
2. Si inserisce nome (opzionale), email, password (minimo 8 caratteri).
3. Se il progetto richiede la conferma email, arriva un'email con un link:
   va aperto, poi si torna nell'app e si accede con email + password.
4. Al primo accesso riuscito, l'app genera una **chiave di recupero** e la
   mostra una sola volta: va salvata (note, password manager, foto) prima
   di poter continuare — c'è una casella di conferma obbligatoria.

### Uso quotidiano
- **Oggi**: calcolo dei target giornalieri in base a un obiettivo di peso,
  esercizio fisico consigliato, pasto del giorno dal piano, diario rapido
  con stima automatica delle calorie, alternative leggere per i giorni
  difficili.
- **Diario**: cronologia dei pasti per data, con riepilogo settimanale.
- **Piano settimanale**: 7 giorni di pasti mediterranei con grammature,
  calorie e avvisi per allergie/preferenze.
- **Alimenti**: liste di alimenti da privilegiare/limitare, e alternative.
- **Allergie**: allergie, stile alimentare (vegetariano/vegano/...), gusti
  personali — usati per segnalare i pasti da evitare nel piano.
- **Progressi**: peso e circonferenza vita, vista giornaliera o settimanale.
- **Impostazioni**: nome visualizzato, rigenerazione della chiave di
  recupero, disconnessione del dispositivo.

### Se si dimentica la password
1. "Ho dimenticato la password" nella schermata di accesso.
2. Si inserisce la chiave di recupero salvata al primo accesso → si
   impone una nuova password → si rientra con accesso completo ai vecchi dati.
3. In alternativa, "Inviami un'email per reimpostare la password" fa
   rientrare nel login, ma senza la chiave di recupero i vecchi dati
   restano cifrati e illeggibili — per progettazione, non per un bug.

## 7. Verificare che la cifratura funzioni davvero

Su Supabase, **Table Editor**:
- Tabella `vault_keys`: le colonne `wrapped_password` e `wrapped_recovery`
  devono contenere stringhe illeggibili (`iv:ciphertext` in base64), mai
  testo in chiaro.
- Tabella `encrypted_records`: la colonna `ciphertext` deve essere sempre
  illeggibile, qualunque cosa l'utente abbia scritto nel diario.

Se in una di queste due tabelle vedi testo leggibile (es. "pizza
margherita"), qualcosa nella cifratura si è rotto: va segnalato e
corretto prima di usare l'app con dati reali.

## 8. Limiti onesti da conoscere

- **Dipende da una connessione internet**: a differenza della prima versione
  (solo locale), ora ogni lettura/scrittura passa da Supabase.
- **Rate limit email**: il servizio email gratuito incluso in Supabase è
  limitato (poche email/ora). Per un uso reale con più utenti, va
  configurato un provider SMTP dedicato (Brevo, Mailgun...), gratuito anch'esso
  fino a soglie generose.
- **Nessuna sincronizzazione retroattiva**: chi ha usato la vecchia versione
  solo-locale (basata su `localStorage`) non ha i vecchi dati trasferiti
  automaticamente in questa versione — sono due archivi separati.
- **Cartella `backend/`**: il server Python/FastAPI scritto in una fase
  precedente del progetto non è più necessario con questa architettura
  basata su Supabase. Resta disponibile solo se in futuro serve logica
  personalizzata lato server che Supabase da solo non offre.
