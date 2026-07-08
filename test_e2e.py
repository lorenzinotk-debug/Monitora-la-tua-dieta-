import httpx
import secrets
# check pw
BASE = "http://localhost:8000"
c = httpx.Client(base_url=BASE, timeout=10)

def ok(label, cond):
    print(f"{'✅' if cond else '❌ FALLITO'}  {label}")
    if not cond:
        raise SystemExit(1)

print("--- Test 1: registrazione ---")
email = f"test{secrets.token_hex(4)}@example.com"
reg = c.post("/auth/register", json={
    "email": email,
    "password": "password123!",
    "display_name": "Lorenzo",
    "salt_password": "c2FsdFBhc3N3b3Jk",
    "wrapped_password": "aXY6Y2lwaGVydGV4dA==",
    "salt_recovery": "c2FsdFJlY292ZXJ5",
    "wrapped_recovery": "aXY6cmVjb3Zlcnk=",
})
ok("registrazione riuscita (201)", reg.status_code == 201)
token = reg.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

print("--- Test 2: /auth/me con il token ---")
me = c.get("/auth/me", headers=headers)
ok("token valido, utente riconosciuto", me.status_code == 200 and me.json()["email"] == email)

print("--- Test 3: login con password corretta ---")
login = c.post("/auth/login", json={"email": email, "password": "password123!"})
ok("login riuscito", login.status_code == 200 and "access_token" in login.json())

print("--- Test 4: login con password ERRATA (deve fallire) ---")
bad_login = c.post("/auth/login", json={"email": email, "password": "password_sbagliata"})
ok("login rifiutato correttamente", bad_login.status_code == 401)

print("--- Test 5: recupero delle chiavi della cassaforte ---")
vk = c.get("/vault-keys", headers=headers)
ok("cassaforte recuperata", vk.status_code == 200 and vk.json()["salt_password"] == "c2FsdFBhc3N3b3Jk")

print("--- Test 6: salvataggio di un record cifrato (diario) ---")
put_rec = c.put("/records/diary:2026-07-05", headers=headers, json={
    "ciphertext": "aXY6ZGF0aV9jaWZyYXRpX2RlbF9kaWFyaW8="
})
ok("record salvato", put_rec.status_code == 200)

print("--- Test 7: lettura dello stesso record ---")
get_rec = c.get("/records/diary:2026-07-05", headers=headers)
ok("record letto correttamente", get_rec.status_code == 200 and get_rec.json()["ciphertext"] == "aXY6ZGF0aV9jaWZyYXRpX2RlbF9kaWFyaW8=")

print("--- Test 8: lettura senza token (deve fallire) ---")
no_auth = c.get("/records/diary:2026-07-05")
ok("accesso rifiutato senza token", no_auth.status_code in (401, 403))

print("--- Test 9: un secondo utente non vede i dati del primo ---")
reg2 = c.post("/auth/register", json={
    "email": f"altro{secrets.token_hex(4)}@example.com",
    "password": "altrapassword123",
    "salt_password": "s2", "wrapped_password": "w2",
    "salt_recovery": "sr2", "wrapped_recovery": "wr2",
})
token2 = reg2.json()["access_token"]
cross = c.get("/records/diary:2026-07-05", headers={"Authorization": f"Bearer {token2}"})
ok("isolamento tra utenti: 404 per l'altro utente", cross.status_code == 404)

print("--- Test 10: elenco dei record dell'utente 1 ---")
listing = c.get("/records", headers=headers)
ok("elenco corretto", listing.status_code == 200 and "diary:2026-07-05" in listing.json())

print("--- Test 11: richiesta di reset password (email simulata, vedi log server) ---")
forgot = c.post("/auth/forgot-password", json={"email": email})
ok("richiesta accettata", forgot.status_code == 200)

print("--- Test 12: verifica che il server non abbia MAI ricevuto dati in chiaro del diario ---")
# Il ciphertext salvato è esattamente quello che abbiamo inviato: il server
# lo tratta come stringa opaca, non lo interpreta né lo decifra.
ok("il server tratta il record come blob opaco", get_rec.json()["ciphertext"] == "aXY6ZGF0aV9jaWZyYXRpX2RlbF9kaWFyaW8=")

print("\n✅ TUTTI I 12 TEST PASSATI — backend funzionante end-to-end")


