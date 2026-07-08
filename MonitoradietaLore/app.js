const todayStr = () => new Date().toISOString().slice(0,10);

// ---------- SUPABASE ----------
const SUPABASE_URL = 'https://ngunrcegzqxhtziqivzc.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_qOvwaD_k5nRTbVu4WN53BQ__yaZkWjB';
const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------- CRYPTO (AES-GCM) ----------
// Modello: una DEK (chiave dati) casuale cifra tutto. La DEK viene "avvolta" due volte:
// una con una chiave derivata dalla password, una con una chiave derivata dalla chiave di recupero.
// Le due wrap vivono nella tabella Supabase "vault_keys" (protetta da Row Level Security:
// ogni utente legge/scrive solo la propria riga). Il server non vede mai la DEK in chiaro.
let cryptoKey = null; // CryptoKey della DEK, in memoria, mai salvata

function b64enc(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64dec(str){ return Uint8Array.from(atob(str), c=>c.charCodeAt(0)); }

async function deriveWrappingKey(secret, saltB64){
  const salt = b64dec(saltB64);
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:150000, hash:'SHA-256' },
    baseKey, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}
async function aesEncryptBytes(key, bytes){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, bytes);
  return b64enc(iv) + ':' + b64enc(ct);
}
async function aesDecryptBytes(key, combined){
  const [ivB64, ctB64] = combined.split(':');
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64dec(ivB64)}, key, b64dec(ctB64));
  return new Uint8Array(pt);
}
function formatRecoveryCode(bytes){
  const hex = Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
  return hex.match(/.{1,4}/g).join('-');
}
function normalizeRecoveryCode(code){
  return (code||'').toUpperCase().replace(/[^0-9A-F]/g,'');
}

async function fetchVaultRow(){
  const { data, error } = await sb.from('vault_keys').select('*').maybeSingle();
  if(error) throw error;
  return data;
}
async function insertVaultRow(row){
  const { data: { user } } = await sb.auth.getUser();
  const { error } = await sb.from('vault_keys').insert({ user_id: user.id, ...row });
  if(error) throw error;
}
async function updateVaultPasswordWrap(saltPwd, wrappedPwd){
  const { data: { user } } = await sb.auth.getUser();
  const { error } = await sb.from('vault_keys')
    .update({ salt_password: saltPwd, wrapped_password: wrappedPwd })
    .eq('user_id', user.id);
  if(error) throw error;
}
async function updateVaultRecoveryWrap(saltRec, wrappedRec){
  const { data: { user } } = await sb.auth.getUser();
  const { error } = await sb.from('vault_keys')
    .update({ salt_recovery: saltRec, wrapped_recovery: wrappedRec })
    .eq('user_id', user.id);
  if(error) throw error;
}

// Crea la cassaforte per un utente NUOVO (nessuna riga vault_keys esistente ancora).
// Richiede una sessione Supabase già autenticata (dopo signUp o dopo il primo login post-conferma email).
async function createVaultForCurrentUser(password){
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const saltPwd = b64enc(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const saltRec = b64enc(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const recoveryBytes = crypto.getRandomValues(new Uint8Array(10));
  const recoveryCode = formatRecoveryCode(recoveryBytes);

  const wrapKeyPwd = await deriveWrappingKey(password, saltPwd);
  const wrapKeyRec = await deriveWrappingKey(normalizeRecoveryCode(recoveryCode), saltRec);
  const wrappedPwd = await aesEncryptBytes(wrapKeyPwd, dek);
  const wrappedRec = await aesEncryptBytes(wrapKeyRec, dek);

  await insertVaultRow({
    salt_password: saltPwd, wrapped_password: wrappedPwd,
    salt_recovery: saltRec, wrapped_recovery: wrappedRec
  });

  cryptoKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', true, ['encrypt','decrypt']);
  return recoveryCode;
}
// Sblocca la cassaforte ESISTENTE con la password (richiede sessione già autenticata).
async function unlockVaultWithPassword(password){
  const vault = await fetchVaultRow();
  if(!vault) throw new Error('Nessuna cassaforte trovata per questo utente');
  const wrapKeyPwd = await deriveWrappingKey(password, vault.salt_password);
  const dek = await aesDecryptBytes(wrapKeyPwd, vault.wrapped_password); // lancia errore se password errata
  cryptoKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', true, ['encrypt','decrypt']);
}
async function unlockVaultWithRecoveryCode(code){
  const vault = await fetchVaultRow();
  if(!vault) throw new Error('Nessuna cassaforte trovata per questo utente');
  const wrapKeyRec = await deriveWrappingKey(normalizeRecoveryCode(code), vault.salt_recovery);
  const dek = await aesDecryptBytes(wrapKeyRec, vault.wrapped_recovery); // lancia errore se codice errato
  cryptoKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', true, ['encrypt','decrypt']);
  return dek;
}
async function rewrapWithNewPassword(dek, newPassword){
  const saltPwd = b64enc(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const wrapKeyPwd = await deriveWrappingKey(newPassword, saltPwd);
  const wrappedPwd = await aesEncryptBytes(wrapKeyPwd, dek);
  await updateVaultPasswordWrap(saltPwd, wrappedPwd);
  // Sincronizza anche la password di login di Supabase, così i futuri accessi usano la stessa.
  await sb.auth.updateUser({ password: newPassword });
}
async function regenerateRecoveryCode(){
  if(!cryptoKey) return null;
  const dek = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));
  const saltRec = b64enc(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const recoveryBytes = crypto.getRandomValues(new Uint8Array(10));
  const recoveryCode = formatRecoveryCode(recoveryBytes);
  const wrapKeyRec = await deriveWrappingKey(normalizeRecoveryCode(recoveryCode), saltRec);
  const wrappedRec = await aesEncryptBytes(wrapKeyRec, dek);
  await updateVaultRecoveryWrap(saltRec, wrappedRec);
  return recoveryCode;
}

async function encryptString(plaintext){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, cryptoKey, new TextEncoder().encode(plaintext));
  return b64enc(iv) + ':' + b64enc(ct);
}
async function decryptString(payload){
  const [ivB64, ctB64] = payload.split(':');
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64dec(ivB64)}, cryptoKey, b64dec(ctB64));
  return new TextDecoder().decode(pt);
}

// storeGet/storeSet leggono e scrivono blob cifrati sulla tabella Supabase "encrypted_records",
// protetta da RLS: ogni utente vede solo le proprie righe. Stessa firma di prima, quindi tutto
// il resto dell'app (diario, target, peso, allergie...) non deve cambiare una riga di codice.
async function storeGet(key){
  try{
    const { data, error } = await sb.from('encrypted_records').select('ciphertext').eq('record_key', key).maybeSingle();
    if(error || !data) return null;
    const plaintext = await decryptString(data.ciphertext);
    return JSON.parse(plaintext);
  }catch(e){ return null; }
}
async function storeSet(key, value){
  try{
    const cipher = await encryptString(JSON.stringify(value));
    const { data: { user } } = await sb.auth.getUser();
    if(!user) return;
    await sb.from('encrypted_records').upsert({ user_id: user.id, record_key: key, ciphertext: cipher });
  }catch(e){ console.error('storage set failed', e); }
}

// ---------- NAVIGAZIONE (pannello laterale a scomparsa) ----------
const hamburgerBtn = document.getElementById('hamburgerBtn');
const sideDrawer = document.getElementById('sideDrawer');
const drawerBackdrop = document.getElementById('drawerBackdrop');
const drawerCloseBtn = document.getElementById('drawerCloseBtn');

function openDrawer(){
  sideDrawer.classList.add('open');
  drawerBackdrop.classList.add('open');
  hamburgerBtn.setAttribute('aria-expanded','true');
}
function closeDrawer(){
  sideDrawer.classList.remove('open');
  drawerBackdrop.classList.remove('open');
  hamburgerBtn.setAttribute('aria-expanded','false');
}
hamburgerBtn.addEventListener('click', ()=>{
  const isOpen = sideDrawer.classList.contains('open');
  if(isOpen) closeDrawer(); else openDrawer();
});
drawerCloseBtn.addEventListener('click', closeDrawer);
drawerBackdrop.addEventListener('click', closeDrawer);
document.addEventListener('keydown', (ev)=>{
  if(ev.key === 'Escape') closeDrawer();
});

document.querySelectorAll('.tab-btn').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-'+btn.dataset.tab).classList.add('active');
    closeDrawer();
  });
});

// ---------- SOTTO-TAB (dentro Pasti e Alimenti/Allergie) ----------
document.querySelectorAll('.subtab-btn').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    const nav = btn.closest('.subnav');
    const panel = nav.closest('.panel');
    nav.querySelectorAll('.subtab-btn').forEach(b=>b.classList.remove('active'));
    panel.querySelectorAll('.subpanel').forEach(p=>p.classList.remove('active'));
    btn.classList.add('active');
    panel.querySelector('#sub-'+btn.dataset.subtab).classList.add('active');
  });
});

// ---------- PROFILE / TARGETS ----------
async function loadProfile(){
  const p = await storeGet('profile');
  if(p){
    document.getElementById('pSex').value = p.sex;
    document.getElementById('pAge').value = p.age;
    document.getElementById('pWeight').value = p.weight;
    document.getElementById('pHeight').value = p.height;
    document.getElementById('pActivity').value = p.activity;
    if(p.goal){
      document.getElementById('goalDirection').value = p.goal.direction;
      document.getElementById('goalAmount').value = p.goal.amount;
      document.getElementById('goalPeriod').value = p.goal.period;
    }
    renderTargets(p.targets);
    renderGoalWarning(p.targets);
  }
}
function computeTargets(sex, age, weight, height, activity, goal){
  let bmr = sex === 'm'
    ? 10*weight + 6.25*height - 5*age + 5
    : 10*weight + 6.25*height - 5*age - 161;
  let tdee = bmr * activity;

  const direction = goal && goal.direction || 'mantenere';
  const amount = goal && parseFloat(goal.amount) || 0;
  const period = goal && goal.period || 'mese';
  const kcalPerKg = 7700; // stima energetica per kg di massa corporea

  let requestedWeeklyKg = 0;
  if(direction !== 'mantenere' && amount > 0){
    requestedWeeklyKg = period === 'settimana' ? amount : amount / 4.345;
  }
  const safeWeeklyCap = 1; // kg/settimana, limite generale considerato prudente
  const exceededSafeRate = requestedWeeklyKg > safeWeeklyCap;
  const appliedWeeklyKg = Math.min(requestedWeeklyKg, safeWeeklyCap);
  let dailyAdjust = (appliedWeeklyKg * kcalPerKg) / 7;
  if(direction === 'perdere') dailyAdjust = -dailyAdjust;
  else if(direction === 'mantenere') dailyAdjust = 0;

  let calorieTarget = Math.round(tdee + dailyAdjust);
  const floor = 1200;
  let wasFloored = false;
  if(calorieTarget < floor){ calorieTarget = floor; wasFloored = true; }

  let protein = Math.round(weight * 1.3);
  let fiber = 30;
  let sugarMax = Math.round(calorieTarget * 0.05 / 4);
  let satFatMax = Math.round(calorieTarget * 0.08 / 9);
  return {
    calorieTarget, protein, fiber, sugarMax, satFatMax,
    goalMeta: { direction, amount, period, requestedWeeklyKg, exceededSafeRate, wasFloored }
  };
}
function renderTargets(t){
  const grid = document.getElementById('targetsGrid');
  grid.innerHTML = `
    <div class="target-box olive"><div class="val mono">${t.calorieTarget}</div><div class="lbl">kcal/giorno</div></div>
    <div class="target-box teal"><div class="val mono">${t.protein}</div><div class="lbl">proteine g</div></div>
    <div class="target-box mustard"><div class="val mono">${t.fiber}</div><div class="lbl">fibra g</div></div>
    <div class="target-box brick"><div class="val mono">≤${t.sugarMax}</div><div class="lbl">zuccheri semplici g</div></div>
    <div class="target-box brick"><div class="val mono">≤${t.satFatMax}</div><div class="lbl">grassi saturi g</div></div>
  `;
}
function renderGoalWarning(t){
  const box = document.getElementById('goalWarning');
  if(!t || !t.goalMeta){ box.innerHTML=''; return; }
  const g = t.goalMeta;
  let msgs = [];
  if(g.exceededSafeRate){
    msgs.push(`Il ritmo richiesto (~${g.requestedWeeklyKg.toFixed(2)} kg/settimana) supera il limite generalmente considerato prudente (max ~1 kg/settimana). Ho calcolato il target su un ritmo più sicuro; un cambiamento così rapido andrebbe seguito da un medico o un nutrizionista.`);
  }
  if(g.wasFloored){
    msgs.push(`Per sicurezza il target non è stato fatto scendere sotto le 1200 kcal/giorno, anche se il calcolo puro indicherebbe meno. Se l'obiettivo ti sembra comunque troppo aggressivo, allunga i tempi o riducilo.`);
  }
  box.innerHTML = msgs.map(m=>`<div class="lock-hint">${m}</div>`).join('');
}

// ---------- ESERCIZIO FISICO (per categoria di attività) ----------
const exerciseCategories = [
  { key:'camminata', label:'🚶 Camminata', detail:'La base più sostenibile per chiunque: 30-45 min, 4-5 volte a settimana, passo spedito. Basso impatto sulle articolazioni, puoi iniziare da qui indipendentemente dalla forma fisica attuale. Aumenta gradualmente durata o velocità man mano che diventa facile.' },
  { key:'corsa', label:'🏃 Corsa', detail:'Se sei già abituato/a a camminare, la corsa leggera (20-30 min, 1-2 volte a settimana) è il passo successivo naturale. Inizia alternando corsa e camminata (es. 2 min corsa, 1 min camminata) per 20-25 min, aumentando la quota di corsa ogni settimana. Scarpe adatte fanno la differenza.' },
  { key:'nuoto', label:'🏊 Nuoto', detail:'Ottimo se hai dolori articolari o sei in sovrappeso: l\'acqua sostiene il peso del corpo. 30 min, 2-3 volte a settimana, alternando stili se possibile per coinvolgere muscoli diversi. Anche solo camminare in acqua o fare aquagym conta.' },
  { key:'bici', label:'🚴 Bicicletta', detail:'Cardio a basso impatto sulle ginocchia. 30-40 min, 2-3 volte a settimana, sia bici vera che cyclette. Ottima anche come mezzo di trasporto quotidiano: gli spostamenti in bici per lavoro/commissioni si somma agli allenamenti dedicati.' },
  { key:'pesi', label:'🏋️ Allenamento con i pesi', detail:'Fondamentale per mantenere massa muscolare a qualunque obiettivo di peso, non solo per chi vuole aumentare. 2-4 volte a settimana, esercizi multiarticolari (squat, affondi, panca o piegamenti, stacco con tecnica corretta, trazioni o lat machine). 3 serie da 8-12 ripetizioni è un buon punto di partenza; aumenta gradualmente carichi o ripetizioni ogni 1-2 settimane, e lascia almeno 48h di recupero allo stesso gruppo muscolare.' },
  { key:'palestra', label:'🏛️ Palestra / circuito', detail:'Se preferisci un ambiente strutturato: un circuito misto di cardio e pesi, 2-3 volte a settimana, spesso con l\'aiuto di un istruttore per la tecnica corretta. Molte palestre offrono corsi guidati (circuit training, functional training) ottimi per chi inizia.' },
  { key:'hiit', label:'⚡ HIIT / circuito breve', detail:'Allenamento intervallato ad alta intensità: 10-15 min, massimo 1-2 volte a settimana. Molto efficace per il dispendio calorico in poco tempo, ma da inserire con moderazione e non tutti i giorni — il corpo ha bisogno di recupero da questo tipo di stimolo intenso.' },
  { key:'yoga', label:'🧘 Yoga / pilates', detail:'30-45 min, 1-2 volte a settimana. Migliora mobilità, postura e gestione dello stress; un ottimo complemento (non sostituto) ad attività più cardio o di forza. Molte app e video gratuiti online per iniziare da casa.' },
  { key:'squadra', label:'⚽ Sport di squadra', detail:'Calcetto, basket, pallavolo, tennis... la costanza conta più dell\'intensità, e uno sport che ti piace davvero è quello che manterrai nel tempo. 1-2 volte a settimana è già un ottimo contributo, con il vantaggio extra della componente sociale.' },
  { key:'scale', label:'🪜 Scale e movimento quotidiano', detail:'Non sottovalutare il movimento "informale": salire le scale invece dell\'ascensore, scendere una fermata prima, parcheggiare più lontano. 10-15 min al giorno, anche spezzettati, si somma in modo significativo nel corso della settimana.' }
];
let currentExerciseCategoryKey = 'camminata';
function renderExerciseCategoryPicker(){
  const picker = document.getElementById('exerciseCategoryPicker');
  picker.innerHTML = exerciseCategories.map(c=>`<option value="${c.key}">${c.label}</option>`).join('');
  updateExerciseCategoryDetail();
}
function updateExerciseCategoryDetail(){
  const key = document.getElementById('exerciseCategoryPicker').value;
  currentExerciseCategoryKey = key;
  const cat = exerciseCategories.find(c=>c.key===key);
  document.getElementById('exerciseCategoryDetail').textContent = cat.detail;
}
document.getElementById('exerciseCategoryPicker').addEventListener('change', updateExerciseCategoryDetail);

async function renderExerciseRoutine(){
  const routine = await storeGet('exerciseRoutine') || [];
  const box = document.getElementById('exerciseRoutineList');
  if(routine.length === 0){
    box.innerHTML = '<div class="empty">Nessuna attività nella tua routine — scegline una sopra.</div>';
    return;
  }
  box.innerHTML = routine.map((r,i)=>`
    <div class="exercise-routine-item">
      <span style="flex:1;"><strong>${r.title}</strong> — ${r.detail}</span>
      <button class="rm" data-i="${i}">rimuovi</button>
    </div>
  `).join('');
}
document.getElementById('addExerciseBtn').addEventListener('click', async ()=>{
  const cat = exerciseCategories.find(c=>c.key===currentExerciseCategoryKey);
  const routine = await storeGet('exerciseRoutine') || [];
  if(routine.some(r=>r.title===cat.label)) return; // evita doppioni
  routine.push({ title: cat.label, detail: cat.detail });
  await storeSet('exerciseRoutine', routine);
  renderExerciseRoutine();
});
document.getElementById('exerciseRoutineList').addEventListener('click', async (ev)=>{
  const btn = ev.target.closest('button.rm');
  if(!btn) return;
  const routine = await storeGet('exerciseRoutine') || [];
  routine.splice(parseInt(btn.dataset.i,10),1);
  await storeSet('exerciseRoutine', routine);
  renderExerciseRoutine();
});

// ---------- ALTERNATIVE LEGGERE (caldo, imprevisti, poco appetito) ----------
const lightAlternatives = [
  { name:'Yogurt greco con frutta fresca', grams:200, kcal:200, tag:'preferire' },
  { name:'Frullato di frutta e verdura', grams:250, kcal:180, tag:'preferire' },
  { name:'Toast leggero con pomodoro e un filo d\'olio', grams:100, kcal:250, tag:'moderare' },
  { name:'Insalata veloce con feta e olive', grams:200, kcal:300, tag:'moderare' },
  { name:'Acqua di cocco e banana', grams:300, kcal:150, tag:'preferire' },
  { name:'Gazpacho o zuppa fredda di pomodoro', grams:250, kcal:120, tag:'preferire' },
  { name:'Uovo sodo con verdure a foglia', grams:200, kcal:220, tag:'preferire' },
  { name:'Hummus con carote e sedano', grams:200, kcal:220, tag:'preferire' },
  { name:'Skyr o yogurt islandese con miele', grams:200, kcal:190, tag:'preferire' },
  { name:'Minestra leggera di verdure', grams:300, kcal:130, tag:'preferire' },
  { name:'Ricotta con miele e noci', grams:150, kcal:280, tag:'moderare' },
  { name:'Panino integrale con tonno e pomodoro', grams:150, kcal:320, tag:'moderare' },
  { name:'Macedonia di frutta fresca', grams:250, kcal:150, tag:'preferire' },
  { name:'Crackers integrali con formaggio spalmabile light', grams:100, kcal:260, tag:'moderare' }
];
function renderLightAlternatives(){
  const box = document.getElementById('lightAltList');
  box.innerHTML = lightAlternatives.map((a,i)=>`
    <div class="meal-line light-alt-row" data-i="${i}" data-qty="1" style="align-items:center; flex-wrap:wrap; gap:8px;">
      <span class="when mono light-alt-info">${a.grams}g · ${a.kcal} kcal</span>
      <span style="flex:1;">${a.name}</span>
      <div style="display:flex; align-items:center; gap:6px;">
        <button type="button" class="btn secondary small qty-minus" style="padding:2px 11px;">−</button>
        <span class="mono qty-display" style="min-width:16px; text-align:center;">1</span>
        <button type="button" class="btn secondary small qty-plus" style="padding:2px 11px;">+</button>
      </div>
      <button type="button" class="btn secondary small add-btn" style="padding:4px 12px;">+ Aggiungi</button>
    </div>
  `).join('');
}
document.getElementById('lightAltList').addEventListener('click', async (ev)=>{
  const row = ev.target.closest('.light-alt-row');
  if(!row) return;
  const i = parseInt(row.dataset.i,10);
  const alt = lightAlternatives[i];
  let qty = parseInt(row.dataset.qty,10) || 1;

  if(ev.target.classList.contains('qty-minus')){
    qty = Math.max(0, qty-1);
    row.dataset.qty = qty;
    row.querySelector('.qty-display').textContent = qty;
    row.querySelector('.light-alt-info').textContent = `${alt.grams*qty}g · ${alt.kcal*qty} kcal`;
    return;
  }
  if(ev.target.classList.contains('qty-plus')){
    qty = Math.min(6, qty+1);
    row.dataset.qty = qty;
    row.querySelector('.qty-display').textContent = qty;
    row.querySelector('.light-alt-info').textContent = `${alt.grams*qty}g · ${alt.kcal*qty} kcal`;
    return;
  }
  if(ev.target.classList.contains('add-btn')){
    if(qty === 0) return; // niente da aggiungere con quantità a zero
    const totalGrams = alt.grams * qty;
    const totalKcal = alt.kcal * qty;
    const label = qty > 1 ? `${qty}x ${alt.name}` : alt.name;
    const confirmed = confirm(`Aggiungere al diario di oggi?\n\n${label}\n~${totalGrams}g · ${totalKcal} kcal`);
    if(!confirmed) return;
    const date = todayStr();
    const entries = await getDiary(date);
    entries.push({ name: label, tag: alt.tag, kcal: totalKcal, ts: Date.now() });
    await saveDiary(date, entries);
    const btn = ev.target;
    btn.textContent = 'Aggiunto ✓';
    setTimeout(()=>{ btn.textContent = '+ Aggiungi'; }, 1500);
    if(document.getElementById('diaryDate').value === date) renderDiary();
    else await updateGauge(date, entries);
  }
});

document.getElementById('calcBtn').addEventListener('click', async ()=>{
  const sex = document.getElementById('pSex').value;
  const age = parseFloat(document.getElementById('pAge').value);
  const weight = parseFloat(document.getElementById('pWeight').value);
  const height = parseFloat(document.getElementById('pHeight').value);
  const activity = parseFloat(document.getElementById('pActivity').value);
  const goal = {
    direction: document.getElementById('goalDirection').value,
    amount: document.getElementById('goalAmount').value,
    period: document.getElementById('goalPeriod').value
  };
  const msg = document.getElementById('calcMsg');
  if(!age || !weight || !height){ msg.textContent = 'Compila età, peso e altezza.'; msg.style.color='var(--brick-deep)'; return; }
  const targets = computeTargets(sex, age, weight, height, activity, goal);
  renderTargets(targets);
  renderGoalWarning(targets);
  await storeSet('profile', { sex, age, weight, height, activity, goal, targets });
  msg.textContent = 'Target salvati ✓';
  msg.style.color='var(--olive-deep)';
  renderMealsTab();
});

// ---------- DIARY ----------
document.getElementById('diaryDate').value = todayStr();
document.getElementById('wDate').value = todayStr();

async function getDiary(date){
  return (await storeGet('diary:'+date)) || [];
}
async function saveDiary(date, entries){
  await storeSet('diary:'+date, entries);
}
async function renderDiary(){
  const date = document.getElementById('diaryDate').value || todayStr();
  const entries = await getDiary(date);
  const list = document.getElementById('diaryList');
  const profile = await storeGet('profile');
  const totalKcal = entries.reduce((s,e)=> s + (e.kcal || 0), 0);
  let summaryHtml = '';
  if(profile && profile.targets){
    const target = profile.targets.calorieTarget;
    const pct = target ? Math.round((totalKcal/target)*100) : 0;
    const status = pct > 115 ? 'brick' : pct < 70 && entries.length>0 ? 'mustard' : 'olive';
    summaryHtml = `
      <div class="target-box ${status}" style="margin-bottom:14px; max-width:260px;">
        <div class="val mono">${totalKcal} / ${target}</div>
        <div class="lbl">kcal loggate oggi (${pct}% del target)</div>
      </div>`;
  } else if(totalKcal > 0){
    summaryHtml = `<div class="target-box olive" style="margin-bottom:14px; max-width:220px;"><div class="val mono">${totalKcal}</div><div class="lbl">kcal loggate</div></div>`;
  }
  if(entries.length === 0){
    list.innerHTML = summaryHtml + '<div class="empty">Nessuna voce per questa data. Aggiungi qualcosa dalla scheda "Oggi".</div>';
  } else {
    list.innerHTML = summaryHtml + entries.map((e,i)=>`
      <div class="diary-entry">
        <span class="name">${escapeHtml(e.name)}${e.kcal ? ' <span class="mono" style="color:var(--ink-soft); font-size:0.82rem;">· '+e.kcal+' kcal</span>' : ''}</span>
        <span style="display:flex; align-items:center; gap:10px;">
          <span class="tag ${e.tag}">${labelTag(e.tag)}</span>
          <button class="rm" data-i="${i}" data-date="${date}">rimuovi</button>
        </span>
      </div>
    `).join('');
  }
  await updateGauge(date, entries);
  await renderWeekOverview(date);
}
function getWeekDates(dateStr){
  const d = new Date(dateStr+'T00:00:00');
  const day = d.getDay(); // 0=Dom..6=Sab
  const diffToMonday = day === 0 ? -6 : 1 - day;
  const monday = new Date(d);
  monday.setDate(d.getDate() + diffToMonday);
  const arr = [];
  for(let i=0;i<7;i++){
    const dt = new Date(monday);
    dt.setDate(monday.getDate()+i);
    arr.push(dt.toISOString().slice(0,10));
  }
  return arr;
}
async function renderWeekOverview(selectedDate){
  const date = selectedDate || document.getElementById('diaryDate').value || todayStr();
  const week = getWeekDates(date);
  const dayLabels = ['Lun','Mar','Mer','Gio','Ven','Sab','Dom'];
  const rows = await Promise.all(week.map(async d=>{
    const entries = await getDiary(d);
    const kcal = entries.reduce((s,e)=>s+(e.kcal||0),0);
    const counts = {preferire:0, moderare:0, evitare:0};
    entries.forEach(e=>{ if(counts[e.tag]!==undefined) counts[e.tag]++; });
    return { date:d, kcal, counts, n:entries.length };
  }));
  const box = document.getElementById('weekOverview');
  box.innerHTML = rows.map((r,i)=>`
    <div class="week-cell ${r.date===todayStr() ? 'today' : ''}" data-date="${r.date}">
      <div class="wd">${dayLabels[i]}</div>
      <div class="dt">${r.date.slice(8,10)}/${r.date.slice(5,7)}</div>
      <div class="kc">${r.n ? r.kcal+' kcal' : '—'}</div>
      <div class="dots">
        ${Array(Math.min(r.counts.preferire,4)).fill('<span class="dot good"></span>').join('')}
        ${Array(Math.min(r.counts.moderare,4)).fill('<span class="dot mod"></span>').join('')}
        ${Array(Math.min(r.counts.evitare,4)).fill('<span class="dot bad"></span>').join('')}
      </div>
    </div>
  `).join('');
  box.querySelectorAll('.week-cell').forEach(cell=>{
    cell.addEventListener('click', ()=>{
      document.getElementById('diaryDate').value = cell.dataset.date;
      renderDiary();
      renderMealPlanGrid();
    });
  });
}
function labelTag(t){ return t==='preferire'?'Da preferire':t==='moderare'?'Da moderare':'Da evitare'; }
function escapeHtml(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

// ---------- PIANIFICAZIONE PASTI DELLA SETTIMANA (editabile, nel Diario) ----------
const mealSlotKeys = ['colazione','pranzo','spuntino','cena'];
const mealSlotLabels = { colazione:'Colazione', pranzo:'Pranzo', spuntino:'Spuntino', cena:'Cena' };

async function renderMealPlanGrid(selectedDate){
  const date = selectedDate || document.getElementById('diaryDate').value || todayStr();
  const week = getWeekDates(date);
  const monday = week[0];
  const saved = await storeGet('mealplan:'+monday) || {};
  const dayLabels = ['Lun','Mar','Mer','Gio','Ven','Sab','Dom'];
  const box = document.getElementById('mealPlanGrid');
  box.innerHTML = week.map((d,i)=>{
    const dayData = saved[d] || {};
    return `
      <div class="plan-day-col" data-date="${d}">
        <h4>${dayLabels[i]} <span class="mono" style="color:var(--ink-soft); font-weight:400;">${d.slice(8,10)}/${d.slice(5,7)}</span></h4>
        ${mealSlotKeys.map(s=>`<input type="text" class="plan-input" data-slot="${s}" placeholder="${mealSlotLabels[s]}" value="${escapeHtml(dayData[s]||'')}">`).join('')}
      </div>
    `;
  }).join('');
}

document.getElementById('saveMealPlanBtn').addEventListener('click', async ()=>{
  const date = document.getElementById('diaryDate').value || todayStr();
  const week = getWeekDates(date);
  const monday = week[0];
  const result = {};
  document.querySelectorAll('#mealPlanGrid .plan-day-col').forEach(col=>{
    const d = col.dataset.date;
    const dayObj = {};
    col.querySelectorAll('.plan-input').forEach(inp=>{
      if(inp.value.trim()) dayObj[inp.dataset.slot] = inp.value.trim();
    });
    result[d] = dayObj;
  });
  await storeSet('mealplan:'+monday, result);
  const msg = document.getElementById('mealPlanMsg');
  msg.textContent = 'Salvato ✓';
  setTimeout(()=>{ msg.textContent=''; }, 2000);
});

document.getElementById('applyDefaultPlanBtn').addEventListener('click', ()=>{
  const date = document.getElementById('diaryDate').value || todayStr();
  const week = getWeekDates(date);
  document.querySelectorAll('#mealPlanGrid .plan-day-col').forEach((col,i)=>{
    const dIdx = dayIndexToPlanIndex(new Date(week[i]+'T00:00:00').getDay());
    const dayPlan = plan[dIdx];
    const labelToSlot = { 'Colazione':'colazione', 'Pranzo':'pranzo', 'Spuntino':'spuntino', 'Cena':'cena' };
    dayPlan.meals.forEach(m=>{
      const slotKey = labelToSlot[m[0]];
      const input = col.querySelector(`.plan-input[data-slot="${slotKey}"]`);
      if(input) input.value = m[1];
    });
  });
});

// ---------- STIMA AUTOMATICA ALIMENTI ----------
// Porzione tipica e kcal per alimenti/piatti comuni. Stime indicative, non da tabelle di laboratorio.
const foodDB = {
  'pizza margherita': {grams:250, kcal:700, tag:'moderare'},
  'pizza': {grams:250, kcal:700, tag:'moderare'},
  'pesca': {grams:150, kcal:60, tag:'preferire'},
  'mela': {grams:150, kcal:80, tag:'preferire'},
  'banana': {grams:120, kcal:105, tag:'preferire'},
  'pera': {grams:150, kcal:85, tag:'preferire'},
  'arancia': {grams:150, kcal:65, tag:'preferire'},
  'mandarino': {grams:100, kcal:50, tag:'preferire'},
  'anguria': {grams:200, kcal:60, tag:'preferire'},
  'uva': {grams:100, kcal:70, tag:'preferire'},
  'fragole': {grams:150, kcal:45, tag:'preferire'},
  'kiwi': {grams:80, kcal:45, tag:'preferire'},
  'pasta al pomodoro': {grams:300, kcal:380, tag:'moderare'},
  'pasta': {grams:300, kcal:380, tag:'moderare'},
  'pasta integrale': {grams:300, kcal:350, tag:'preferire'},
  'riso bianco': {grams:250, kcal:290, tag:'moderare'},
  'riso integrale': {grams:250, kcal:280, tag:'preferire'},
  'pane bianco': {grams:50, kcal:130, tag:'moderare'},
  'pane integrale': {grams:50, kcal:120, tag:'preferire'},
  'pane': {grams:50, kcal:135, tag:'moderare'},
  'bistecca': {grams:200, kcal:450, tag:'moderare'},
  'pollo alla griglia': {grams:150, kcal:250, tag:'preferire'},
  'pollo': {grams:150, kcal:250, tag:'preferire'},
  'insalata mista': {grams:100, kcal:20, tag:'preferire'},
  'insalata': {grams:100, kcal:25, tag:'preferire'},
  'gelato': {grams:100, kcal:200, tag:'evitare'},
  'patatine fritte': {grams:150, kcal:450, tag:'evitare'},
  'patatine': {grams:50, kcal:270, tag:'evitare'},
  'hamburger': {grams:200, kcal:550, tag:'evitare'},
  'cioccolato': {grams:30, kcal:160, tag:'evitare'},
  'cioccolato fondente': {grams:20, kcal:110, tag:'moderare'},
  'vino rosso': {grams:150, kcal:125, tag:'evitare'},
  'vino': {grams:150, kcal:125, tag:'evitare'},
  'birra': {grams:330, kcal:140, tag:'evitare'},
  'cornetto': {grams:60, kcal:250, tag:'evitare'},
  'croissant': {grams:60, kcal:250, tag:'evitare'},
  'cappuccino': {grams:150, kcal:80, tag:'moderare'},
  'caffe': {grams:30, kcal:5, tag:'preferire'},
  'yogurt': {grams:125, kcal:100, tag:'preferire'},
  'yogurt greco': {grams:170, kcal:150, tag:'preferire'},
  'formaggio': {grams:50, kcal:180, tag:'moderare'},
  'mozzarella': {grams:100, kcal:250, tag:'moderare'},
  'ricotta': {grams:100, kcal:145, tag:'preferire'},
  'uovo': {grams:55, kcal:78, tag:'preferire'},
  'lenticchie': {grams:150, kcal:170, tag:'preferire'},
  'ceci': {grams:150, kcal:250, tag:'preferire'},
  'fagioli': {grams:150, kcal:180, tag:'preferire'},
  'salmone': {grams:150, kcal:280, tag:'preferire'},
  'tonno': {grams:80, kcal:100, tag:'preferire'},
  'merluzzo': {grams:150, kcal:150, tag:'preferire'},
  'prosciutto crudo': {grams:50, kcal:130, tag:'moderare'},
  'prosciutto cotto': {grams:50, kcal:110, tag:'moderare'},
  'salame': {grams:50, kcal:200, tag:'evitare'},
  'salsiccia': {grams:100, kcal:280, tag:'evitare'},
  'patate': {grams:200, kcal:160, tag:'moderare'},
  'patate al forno': {grams:200, kcal:180, tag:'moderare'},
  'focaccia': {grams:100, kcal:280, tag:'moderare'},
  'biscotti': {grams:30, kcal:140, tag:'evitare'},
  'noci': {grams:30, kcal:195, tag:'moderare'},
  'mandorle': {grams:30, kcal:175, tag:'moderare'},
  'avocado': {grams:100, kcal:160, tag:'preferire'},
  'zucchine': {grams:150, kcal:30, tag:'preferire'},
  'pomodoro': {grams:100, kcal:20, tag:'preferire'},
  'pomodori': {grams:100, kcal:20, tag:'preferire'},
  'minestrone': {grams:300, kcal:120, tag:'preferire'},
  'zuppa di verdure': {grams:300, kcal:130, tag:'preferire'},
  'kebab': {grams:250, kcal:600, tag:'evitare'},
  'sushi': {grams:200, kcal:350, tag:'moderare'},
  'torta': {grams:100, kcal:350, tag:'evitare'},
  'dolce': {grams:100, kcal:350, tag:'evitare'},
  'succo di frutta': {grams:200, kcal:90, tag:'evitare'},
  'coca cola': {grams:330, kcal:140, tag:'evitare'},
  'bibita': {grams:330, kcal:140, tag:'evitare'},
  'acqua': {grams:0, kcal:0, tag:'preferire'},
  'te': {grams:200, kcal:2, tag:'preferire'},
  'latte intero': {grams:200, kcal:130, tag:'moderare'},
  'latte scremato': {grams:200, kcal:70, tag:'preferire'},
  'latte': {grams:200, kcal:120, tag:'moderare'},
  'olio d\'oliva': {grams:10, kcal:90, tag:'preferire'},
  'burro': {grams:10, kcal:75, tag:'evitare'},
  'farro': {grams:80, kcal:280, tag:'preferire'},
  'quinoa': {grams:70, kcal:250, tag:'preferire'},
  'falafel': {grams:100, kcal:330, tag:'moderare'},
  'popcorn': {grams:30, kcal:110, tag:'moderare'},
  'nutella': {grams:20, kcal:110, tag:'evitare'},
  'marmellata': {grams:20, kcal:50, tag:'moderare'},
  'miele': {grams:10, kcal:30, tag:'moderare'},
  'broccoli': {grams:200, kcal:70, tag:'preferire'},
  'spinaci': {grams:150, kcal:35, tag:'preferire'},
  'carote': {grams:150, kcal:50, tag:'preferire'},
  'frittata': {grams:150, kcal:250, tag:'moderare'},
  'hummus': {grams:40, kcal:120, tag:'preferire'},
  'panzerotto': {grams:200, kcal:450, tag:'evitare'},
  'panzerotti': {grams:200, kcal:450, tag:'evitare'},
  'calzone': {grams:300, kcal:750, tag:'evitare'},
  'arancino': {grams:150, kcal:300, tag:'moderare'},
  'arancini': {grams:150, kcal:300, tag:'moderare'},
  'suppli': {grams:120, kcal:250, tag:'moderare'},
  'mozzarella in carrozza': {grams:150, kcal:400, tag:'evitare'},
  'olive ascolane': {grams:100, kcal:280, tag:'evitare'},
  'crocchette di patate': {grams:150, kcal:300, tag:'evitare'},
  'crocchette': {grams:150, kcal:300, tag:'evitare'},
  'tiramisu': {grams:120, kcal:350, tag:'evitare'},
  'cannolo': {grams:80, kcal:250, tag:'evitare'},
  'cannoli': {grams:80, kcal:250, tag:'evitare'},
  'sfogliatella': {grams:100, kcal:330, tag:'evitare'},
  'lasagna': {grams:300, kcal:450, tag:'moderare'},
  'lasagne': {grams:300, kcal:450, tag:'moderare'},
  'parmigiana di melanzane': {grams:250, kcal:350, tag:'moderare'},
  'parmigiana': {grams:250, kcal:350, tag:'moderare'},
  'cotoletta': {grams:150, kcal:350, tag:'moderare'},
  'cotoletta alla milanese': {grams:150, kcal:400, tag:'moderare'},
  'piadina': {grams:150, kcal:380, tag:'moderare'},
  'bruschetta': {grams:100, kcal:150, tag:'preferire'},
  'polpette': {grams:150, kcal:300, tag:'moderare'},
  'risotto': {grams:300, kcal:400, tag:'moderare'},
  'gnocchi': {grams:300, kcal:350, tag:'moderare'},
  'panino': {grams:150, kcal:350, tag:'moderare'},
  'toast': {grams:100, kcal:280, tag:'moderare'},
  'club sandwich': {grams:250, kcal:500, tag:'moderare'},
  'poke': {grams:350, kcal:450, tag:'preferire'},
  'ramen': {grams:400, kcal:500, tag:'moderare'},
  'couscous': {grams:200, kcal:250, tag:'preferire'},
  'pizza al taglio': {grams:150, kcal:400, tag:'moderare'},
  'pizza fritta': {grams:200, kcal:550, tag:'evitare'},
  'patatine chips': {grams:50, kcal:270, tag:'evitare'},
  'gelato artigianale': {grams:100, kcal:220, tag:'evitare'},
  'brioche': {grams:60, kcal:280, tag:'evitare'},
  'krapfen': {grams:80, kcal:300, tag:'evitare'},
  'strudel': {grams:100, kcal:260, tag:'evitare'},
  'churros': {grams:80, kcal:300, tag:'evitare'},
  'donut': {grams:70, kcal:280, tag:'evitare'},
  'waffel': {grams:100, kcal:290, tag:'evitare'}
};
function estimateFood(text){
  const n = normalize(text);
  if(!n) return null;
  if(foodDB[n]) return foodDB[n];
  let best=null, bestLen=0;
  for(const key in foodDB){
    if(n.includes(key) && key.length>bestLen){ bestLen=key.length; best=foodDB[key]; }
  }
  if(best) return best;
  for(const key in foodDB){
    if(key.includes(n) && n.length>=3 && key.length>bestLen){ bestLen=key.length; best=foodDB[key]; }
  }
  return best;
}
// Configura un modulo "aggiungi al diario" riusabile: ids = prefisso degli elementi,
// getDate = funzione che restituisce la data su cui operare (oggi, oppure quella selezionata nel Diario).
function setupQuickAddWidget(ids, getDate, onAfterAdd){
  let kcalManuallyEdited = false;
  let currentAutoTag = 'moderare';
  const el = id => document.getElementById(id);

  function updateTagBadge(tag){
    currentAutoTag = tag;
    const badge = el(ids.badge);
    badge.textContent = labelTag(tag);
    badge.className = 'tag ' + tag;
    el(ids.tagSelect).value = tag;
  }
  el(ids.kcal).addEventListener('input', ()=>{ kcalManuallyEdited = true; });
  el(ids.food).addEventListener('input', ()=>{
    const text = el(ids.food).value;
    const match = estimateFood(text);
    const hint = el(ids.hint);
    const tagRow = el(ids.tagRow);
    const portionBtns = el(ids.portionBtns);
    if(match){
      if(!kcalManuallyEdited) el(ids.kcal).value = match.kcal;
      updateTagBadge(match.tag);
      hint.textContent = `Stima automatica: porzione tipica ~${match.grams}g · ~${match.kcal} kcal. Puoi correggere il numero se la tua porzione è diversa.`;
      tagRow.style.display = 'flex';
      portionBtns.style.display = 'none';
    } else if(text.trim().length > 1){
      hint.textContent = 'Non lo riconosco: se lo sai scrivi le kcal a mano, oppure scegli una porzione approssimativa qui sotto.';
      tagRow.style.display = 'flex';
      portionBtns.style.display = 'flex';
      if(!kcalManuallyEdited) updateTagBadge('moderare');
    } else {
      hint.textContent = '';
      tagRow.style.display = 'none';
      portionBtns.style.display = 'none';
    }
  });
  el(ids.portionBtns).addEventListener('click', (ev)=>{
    const btn = ev.target.closest('button[data-kcal]');
    if(!btn) return;
    el(ids.kcal).value = btn.dataset.kcal;
    kcalManuallyEdited = true;
    updateTagBadge('moderare');
    el(ids.hint).textContent = 'Porzione impostata: puoi ancora correggere il numero di kcal se vuoi.';
  });
  el(ids.changeTagLink).addEventListener('click', ()=>{
    const sel = el(ids.tagSelect);
    const isHidden = sel.style.display === 'none';
    sel.style.display = isHidden ? 'inline-block' : 'none';
    sel.value = currentAutoTag;
  });
  el(ids.tagSelect).addEventListener('change', (ev)=>{ updateTagBadge(ev.target.value); });

  el(ids.addBtn).addEventListener('click', async ()=>{
    const name = el(ids.food).value.trim();
    const tag = currentAutoTag;
    const kcal = parseFloat(el(ids.kcal).value) || null;
    if(!name) return;
    const date = getDate();
    const entries = await getDiary(date);
    entries.push({ name, tag, kcal, ts: Date.now() });
    await saveDiary(date, entries);
    el(ids.food).value = '';
    el(ids.kcal).value = '';
    el(ids.hint).textContent = '';
    el(ids.tagRow).style.display = 'none';
    el(ids.portionBtns).style.display = 'none';
    el(ids.tagSelect).style.display = 'none';
    kcalManuallyEdited = false;
    currentAutoTag = 'moderare';
    if(onAfterAdd) await onAfterAdd(date, entries);
  });
}

setupQuickAddWidget({
  food:'quickFood', kcal:'quickKcal', hint:'foodEstimateHint', portionBtns:'portionButtons',
  tagRow:'tagRow', badge:'quickTagBadge', changeTagLink:'changeTagLink', tagSelect:'quickTag', addBtn:'quickAddBtn'
}, () => todayStr(), async (date, entries) => {
  if(document.getElementById('diaryDate').value === date) renderDiary();
  else await updateGauge(date, entries);
});

setupQuickAddWidget({
  food:'diaryQuickFood', kcal:'diaryQuickKcal', hint:'diaryFoodEstimateHint', portionBtns:'diaryPortionButtons',
  tagRow:'diaryTagRow', badge:'diaryQuickTagBadge', changeTagLink:'diaryChangeTagLink', tagSelect:'diaryQuickTag', addBtn:'diaryQuickAddBtn'
}, () => document.getElementById('diaryDate').value || todayStr(), async () => {
  renderDiary();
});

// ---------- NAVIGAZIONE GIORNO / SETTIMANA nel Diario ----------
function shiftDiaryDate(days){
  const current = document.getElementById('diaryDate').value || todayStr();
  const d = new Date(current+'T00:00:00');
  d.setDate(d.getDate()+days);
  const newDate = d.toISOString().slice(0,10);
  document.getElementById('diaryDate').value = newDate;
  document.getElementById('mealsDate').value = newDate;
  renderDiary();
  renderMealPlanGrid();
}
document.getElementById('prevDayBtn').addEventListener('click', ()=> shiftDiaryDate(-1));
document.getElementById('nextDayBtn').addEventListener('click', ()=> shiftDiaryDate(1));
document.getElementById('prevWeekBtn').addEventListener('click', ()=> shiftDiaryDate(-7));
document.getElementById('nextWeekBtn').addEventListener('click', ()=> shiftDiaryDate(7));

document.getElementById('diaryDate').addEventListener('change', ()=>{
  document.getElementById('mealsDate').value = document.getElementById('diaryDate').value;
  renderDiary();
  renderMealPlanGrid();
});
document.getElementById('diaryList').addEventListener('click', async (ev)=>{
  if(ev.target.classList.contains('rm')){
    const date = ev.target.dataset.date;
    const i = parseInt(ev.target.dataset.i,10);
    const entries = await getDiary(date);
    entries.splice(i,1);
    await saveDiary(date, entries);
    renderDiary();
  }
});


// ---------- LIVER GAUGE ----------
async function updateGauge(date, entriesForDate){
  const entries = entriesForDate || await getDiary(todayStr());
  const relevant = date === todayStr() ? entries : await getDiary(todayStr());
  let score = 50;
  if(relevant.length){
    let sum = 0;
    relevant.forEach(e=>{
      sum += e.tag==='preferire' ? 15 : e.tag==='moderare' ? 3 : -18;
    });
    score = Math.max(5, Math.min(100, 50 + sum));
  }
  document.getElementById('gaugeCenterNum').textContent = Math.round(score);
  const ring = document.getElementById('gaugeRing');
  const circumference = 515.2;
  const offset = circumference - (score/100)*circumference;
  ring.setAttribute('stroke-dashoffset', offset);
  let color = score < 40 ? 'var(--brick)' : score < 70 ? 'var(--mustard)' : 'url(#gaugeGradGood)';
  ring.style.stroke = color;
}

// ---------- WEEKLY PLAN ----------
// Valori nutrizionali e grammature stimati per porzioni standard — adatta le quantità ai tuoi target personali.
// Ogni pasto: [momento, descrizione con grammi, kcal, allergeni presenti]
const plan = [
  { day:'Lunedì', totals:{kcal:1780, protein:95, fiber:30, sugar:14, satfat:12}, meals:[
    ['Colazione','Fiocchi d\'avena (50g) con latte scremato (200ml), mirtilli (80g) e un cucchiaino di semi di lino (8g)', 360, ['Lattosio'], ['vegetariano']],
    ['Pranzo','Pasta integrale (80g) con zucchine (150g), ceci (100g) e un filo d\'olio d\'oliva (10g)', 620, ['Glutine'], ['vegetariano','vegano']],
    ['Spuntino','Una mela (150g) e una manciata di noci (20g)', 170, ['Frutta a guscio'], ['vegetariano','vegano']],
    ['Cena','Filetto di merluzzo (180g) al forno, spinaci saltati (150g) con aglio, pane integrale (60g)', 630, ['Pesce e crostacei','Glutine'], ['pesce']]
  ]},
  { day:'Martedì', totals:{kcal:1720, protein:100, fiber:27, sugar:16, satfat:11}, meals:[
    ['Colazione','Yogurt greco magro (170g) con frutti di bosco (100g) e granola senza zuccheri aggiunti (30g)', 320, ['Lattosio','Glutine'], ['vegetariano']],
    ['Pranzo','Quinoa (70g secca) con pomodorini (100g), cetrioli (80g), feta leggera (30g) e ceci (80g)', 600, ['Lattosio'], ['vegetariano']],
    ['Spuntino','Carote (150g) e hummus (40g)', 150, [], ['vegetariano','vegano']],
    ['Cena','Petto di pollo alla griglia (150g), broccoli al vapore (200g), patate dolci al forno (150g)', 650, [], ['carne']]
  ]},
  { day:'Mercoledì', totals:{kcal:1750, protein:92, fiber:29, sugar:13, satfat:13}, meals:[
    ['Colazione','Pane integrale tostato (60g) con avocado (50g) e un uovo in camicia (55g)', 340, ['Glutine','Uova'], ['vegetariano']],
    ['Pranzo','Zuppa di lenticchie e verdure (350g) con crostini integrali (40g)', 560, ['Glutine'], ['vegetariano','vegano']],
    ['Spuntino','Yogurt magro naturale (170g)', 160, ['Lattosio'], ['vegetariano']],
    ['Cena','Salmone al vapore (180g), insalata verde mista (100g), riso integrale (70g secco)', 690, ['Pesce e crostacei'], ['pesce']]
  ]},
  { day:'Giovedì', totals:{kcal:1800, protein:98, fiber:31, sugar:15, satfat:12}, meals:[
    ['Colazione','Porridge di avena (50g) con banana (100g) e cannella', 350, [], ['vegetariano','vegano']],
    ['Pranzo','Farro (80g secco) con verdure grigliate (150g) e tonno al naturale (100g)', 630, ['Glutine','Pesce e crostacei'], ['pesce']],
    ['Spuntino','Una pera (150g) e mandorle non salate (20g)', 170, ['Frutta a guscio'], ['vegetariano','vegano']],
    ['Cena','Frittata di verdure (2 uova, 110g) con verdure (100g), insalata di finocchi e arance (150g)', 650, ['Uova'], ['vegetariano']]
  ]},
  { day:'Venerdì', totals:{kcal:1740, protein:90, fiber:28, sugar:12, satfat:10}, meals:[
    ['Colazione','Smoothie di spinaci (50g), banana (100g), latte vegetale non zuccherato (200ml)', 330, [], ['vegetariano','vegano']],
    ['Pranzo','Riso integrale (80g secco) con legumi misti (120g) e verdure saltate (150g)', 610, [], ['vegetariano','vegano']],
    ['Spuntino','Un frutto di stagione (150g)', 150, [], ['vegetariano','vegano']],
    ['Cena','Orata al forno (200g) con patate (150g) e pomodorini (100g), verdure grigliate (100g)', 650, ['Pesce e crostacei'], ['pesce']]
  ]},
  { day:'Sabato', totals:{kcal:1770, protein:96, fiber:29, sugar:14, satfat:11}, meals:[
    ['Colazione','Yogurt magro (170g) con frutta fresca (100g) e noci (15g)', 340, ['Lattosio','Frutta a guscio'], ['vegetariano']],
    ['Pranzo','Insalatona con ceci (100g), tonno (80g), verdure crude (150g) e olio d\'oliva (10g)', 600, ['Pesce e crostacei'], ['pesce']],
    ['Spuntino','Un paio di gallette integrali (20g) con hummus (40g)', 160, ['Glutine'], ['vegetariano','vegano']],
    ['Cena','Zuppa di verdure e legumi (350g), pane integrale (50g)', 670, ['Glutine'], ['vegetariano','vegano']]
  ]},
  { day:'Domenica', totals:{kcal:1810, protein:94, fiber:30, sugar:17, satfat:13}, meals:[
    ['Colazione','Pane integrale (60g) con marmellata senza zuccheri aggiunti (20g) e frutta (100g)', 360, ['Glutine'], ['vegetariano','vegano']],
    ['Pranzo','Pasta integrale (80g) al pomodoro fresco (150g) e basilico, insalata mista (100g)', 620, ['Glutine'], ['vegetariano','vegano']],
    ['Spuntino','Frutta secca non salata (30g, piccola porzione)', 170, ['Frutta a guscio'], ['vegetariano','vegano']],
    ['Cena','Pollo al limone (150g), verdure al forno (200g), farro (70g secco)', 660, ['Glutine'], ['carne']]
  ]},
];
function dayIndexToPlanIndex(jsDay){
  // JS: 0=domenica..6=sabato → il nostro array parte da Lunedì
  return jsDay === 0 ? 6 : jsDay - 1;
}
function statusFor(value, target, kind){
  if(!target) return 'olive';
  if(kind === 'max'){
    return value <= target ? 'olive' : value <= target*1.2 ? 'mustard' : 'brick';
  }
  const pct = value / target;
  if(pct >= 0.85 && pct <= 1.15) return 'olive';
  if(pct >= 0.7 && pct <= 1.3) return 'mustard';
  return 'brick';
}
const allergenSwap = {
  'Glutine': 'sostituisci con riso, quinoa, grano saraceno o prodotti certificati senza glutine',
  'Lattosio': 'usa versioni delattosate o alternative vegetali (yogurt di soia/cocco, latte vegetale)',
  'Uova': 'sostituisci con tofu strapazzato o una "omelette" di farina di ceci e acqua',
  'Pesce e crostacei': 'sostituisci con pollo, tofu o un\'altra fonte proteica come i legumi',
  'Frutta a guscio': 'sostituisci con semi di zucca o di girasole',
  'Soia': 'sostituisci con legumi diversi (ceci, lenticchie, fagioli)'
};
function mealAllergenWarning(mealAllergens, selectedAllergies){
  if(!selectedAllergies || selectedAllergies.length===0 || !mealAllergens || mealAllergens.length===0) return '';
  const hits = mealAllergens.filter(a=>selectedAllergies.includes(a));
  if(hits.length===0) return '';
  const swaps = hits.map(h=>`<strong>${h}:</strong> ${allergenSwap[h]||'valuta un\'alternativa adatta'}`).join(' · ');
  return `<div style="background:var(--tag-bad-bg); color:var(--tag-bad-text); border-radius:8px; padding:6px 10px; font-size:0.78rem; margin:4px 0 8px;">⚠️ Contiene ${hits.join(', ')} — ${swaps}</div>`;
}
function customAllergenWarning(mealDesc, otherTermsStr){
  if(!otherTermsStr) return '';
  const terms = otherTermsStr.split(',').map(t=>t.trim()).filter(Boolean);
  if(terms.length===0) return '';
  const normDesc = normalize(mealDesc);
  const hits = terms.filter(t=> normDesc.includes(normalize(t)));
  if(hits.length===0) return '';
  return `<div style="background:var(--tag-bad-bg); color:var(--tag-bad-text); border-radius:8px; padding:6px 10px; font-size:0.78rem; margin:4px 0 8px;">⚠️ Contiene "${hits.join(', ')}" (indicato da te) — valuta un'alternativa o rimuovi l'ingrediente.</div>`;
}
const dietStyleSwap = {
  vegetariano: 'sostituisci carne o pesce con tofu, tempeh, legumi o formaggi/uova se li mangi',
  vegano: 'sostituisci gli ingredienti animali con alternative vegetali (tofu, legumi, latte/yogurt vegetali)',
  pescetariano: 'sostituisci la carne con pesce, tofu o legumi',
  niente_pesce: 'sostituisci il pesce con pollo, tofu o legumi'
};
function dietStyleWarning(mealDietTags, dietStyle){
  if(!dietStyle || dietStyle === 'nessuna' || !mealDietTags) return '';
  let conflict = false;
  if(dietStyle === 'vegetariano' && !mealDietTags.includes('vegetariano')) conflict = true;
  if(dietStyle === 'vegano' && !mealDietTags.includes('vegano')) conflict = true;
  if(dietStyle === 'pescetariano' && mealDietTags.includes('carne')) conflict = true;
  if(dietStyle === 'niente_pesce' && mealDietTags.includes('pesce')) conflict = true;
  if(!conflict) return '';
  return `<div style="background:var(--tag-mod-bg); color:var(--tag-mod-text); border-radius:8px; padding:6px 10px; font-size:0.78rem; margin:4px 0 8px;">🔁 Non in linea con il tuo stile alimentare — ${dietStyleSwap[dietStyle]}</div>`;
}
function dislikeWarning(mealDesc, dislikesStr){
  if(!dislikesStr) return '';
  const terms = dislikesStr.split(',').map(t=>t.trim()).filter(Boolean);
  if(terms.length===0) return '';
  const normDesc = normalize(mealDesc);
  const hits = terms.filter(t=> normDesc.includes(normalize(t)));
  if(hits.length===0) return '';
  return `<div style="background:var(--surface); color:var(--ink-soft); border:1px dashed var(--line); border-radius:8px; padding:6px 10px; font-size:0.78rem; margin:4px 0 8px;">👎 Contiene "${hits.join(', ')}", che avevi indicato di non gradire — valuta una porzione senza questo ingrediente o scegli un'alternativa dal tab Alimenti.</div>`;
}
function allergyWarningsFor(meal, selectedAllergies, otherTerms, dietStyle, dislikes){
  return mealAllergenWarning(meal[3], selectedAllergies)
    + customAllergenWarning(meal[1], otherTerms)
    + dietStyleWarning(meal[4], dietStyle)
    + dislikeWarning(meal[1], dislikes);
}

// ---------- I TUOI PASTI (menu a tendina con alternative, per qualsiasi giorno) ----------
// Le opzioni per ogni pasto sono ricavate dal piano settimanale stesso: 7 alternative
// per Colazione, 7 per Pranzo, 7 per Spuntino, 7 per Cena — così ogni pasto ha davvero
// più scelte, non una sola proposta fissa.
function getMealOptionsBySlot(){
  const bySlot = { Colazione:[], Pranzo:[], Spuntino:[], Cena:[] };
  plan.forEach(day=>{
    day.meals.forEach(m=>{
      bySlot[m[0]].push({ label:m[1], kcal:m[2], allergens:m[3]||[], dietTags:m[4]||[], fromDay:day.day });
    });
  });
  return bySlot;
}
const mealSlotOrder = [['Colazione','colazione'], ['Pranzo','pranzo'], ['Spuntino','spuntino'], ['Cena','cena']];

async function getPlannedMealsForDate(date){
  const week = getWeekDates(date);
  const data = await storeGet('mealplan:'+week[0]) || {};
  return data[date] || {};
}
async function setPlannedMealsForDate(date, daySlots){
  const week = getWeekDates(date);
  const monday = week[0];
  const data = await storeGet('mealplan:'+monday) || {};
  data[date] = daySlots;
  await storeSet('mealplan:'+monday, data);
}

async function renderMealsTab(){
  const date = document.getElementById('mealsDate').value || document.getElementById('diaryDate').value || todayStr();
  document.getElementById('mealsDate').value = date;
  const bySlot = getMealOptionsBySlot();
  const planned = await getPlannedMealsForDate(date);
  const selectedAllergies = await storeGet('allergies') || [];
  const otherTerms = await storeGet('allergiesOther') || '';
  const dietStyle = await storeGet('dietStyle') || 'nessuna';
  const dislikes = await storeGet('dislikes') || '';

  const box = document.getElementById('mealsSlots');
  box.innerHTML = mealSlotOrder.map(([label, key])=>{
    const options = bySlot[label];
    const plannedText = planned[key] || '';
    const matchIdx = options.findIndex(o => o.label === plannedText);
    const optionsHtml = options.map((o,i)=>`<option value="${i}" ${i===matchIdx?'selected':''}>${o.label} · ${o.kcal} kcal</option>`).join('');
    const isCustom = plannedText && matchIdx === -1;
    return `
      <div class="meal-slot-row" data-slot="${key}" data-label="${label}">
        <div class="meal-slot-label">${label}</div>
        <select class="meal-slot-select" data-slot="${key}">
          ${optionsHtml}
          <option value="custom" ${isCustom?'selected':''}>✏️ Personalizza...</option>
        </select>
        <div class="meal-slot-kcal mono" data-slot-kcal="${key}">${isCustom ? '' : (options[matchIdx>=0?matchIdx:0].kcal+' kcal')}</div>
        <input type="text" class="meal-slot-custom plan-input" data-slot-custom="${key}"
               style="display:${isCustom?'block':'none'};" placeholder="Scrivi il tuo pasto" value="${escapeHtml(isCustom?plannedText:'')}">
        <input type="number" class="meal-slot-custom-kcal mono" data-slot-customkcal="${key}" min="0"
               style="display:${isCustom?'inline-block':'none'}; width:90px;" placeholder="kcal">
      </div>
    `;
  }).join('');

  // avvisi allergie/gusti sotto ogni riga già selezionata
  box.querySelectorAll('.meal-slot-select').forEach(sel=>{
    updateMealSlotWarning(sel, bySlot, selectedAllergies, otherTerms, dietStyle, dislikes);
  });

  await renderMealsTotal(date, bySlot);
}

function currentMealSelections(bySlot){
  const result = {};
  document.querySelectorAll('#mealsSlots .meal-slot-row').forEach(row=>{
    const key = row.dataset.slot;
    const label = row.dataset.label;
    const sel = row.querySelector('.meal-slot-select');
    if(sel.value === 'custom'){
      const text = row.querySelector('.meal-slot-custom').value.trim();
      const kcalInput = row.querySelector('.meal-slot-custom-kcal');
      result[key] = { label, text, kcal: parseFloat(kcalInput.value) || 0, tag:'moderare' };
    } else {
      const opt = bySlot[label][parseInt(sel.value,10)];
      result[key] = { label, text: opt.label, kcal: opt.kcal, tag:'preferire', allergens:opt.allergens, dietTags:opt.dietTags };
    }
  });
  return result;
}

function updateMealSlotWarning(selectEl, bySlot, selectedAllergies, otherTerms, dietStyle, dislikes){
  const row = selectEl.closest('.meal-slot-row');
  let old = row.querySelector('.meal-slot-warning');
  if(old) old.remove();
  if(selectEl.value === 'custom') return;
  const label = row.dataset.label;
  const opt = bySlot[label][parseInt(selectEl.value,10)];
  const fakeMeal = [label, opt.label, opt.kcal, opt.allergens, opt.dietTags];
  const warn = allergyWarningsFor(fakeMeal, selectedAllergies, otherTerms, dietStyle, dislikes);
  if(warn){
    const div = document.createElement('div');
    div.className = 'meal-slot-warning';
    div.style.flex = '1 1 100%';
    div.innerHTML = warn;
    row.appendChild(div);
  }
}

async function renderMealsTotal(date, bySlot){
  const profile = await storeGet('profile');
  const sel = currentMealSelections(bySlot);
  const totalKcal = Object.values(sel).reduce((s,m)=>s+(m.kcal||0),0);
  let html = `<div class="targets-grid">`;
  if(profile && profile.targets){
    html += `<div class="target-box ${statusFor(totalKcal, profile.targets.calorieTarget,'range')}"><div class="val mono">${totalKcal}</div><div class="lbl">kcal (target ${profile.targets.calorieTarget})</div></div>`;
  } else {
    html += `<div class="target-box olive"><div class="val mono">${totalKcal}</div><div class="lbl">kcal totali</div></div>`;
  }
  html += `</div>`;
  if(!profile || !profile.targets){
    html += `<div class="sub" style="margin-top:8px;">Calcola i tuoi target qui sopra per vedere se questo giorno rientra nel tuo range personale.</div>`;
  }
  document.getElementById('mealsTotal').innerHTML = html;
}

document.getElementById('mealsSlots').addEventListener('change', async (ev)=>{
  const bySlot = getMealOptionsBySlot();
  if(ev.target.classList.contains('meal-slot-select')){
    const row = ev.target.closest('.meal-slot-row');
    const customInput = row.querySelector('.meal-slot-custom');
    const customKcalInput = row.querySelector('.meal-slot-custom-kcal');
    const kcalBox = row.querySelector('.meal-slot-kcal');
    if(ev.target.value === 'custom'){
      customInput.style.display = 'block';
      customKcalInput.style.display = 'inline-block';
      kcalBox.textContent = '';
    } else {
      customInput.style.display = 'none';
      customKcalInput.style.display = 'none';
      const opt = bySlot[row.dataset.label][parseInt(ev.target.value,10)];
      kcalBox.textContent = opt.kcal + ' kcal';
    }
    const selectedAllergies = await storeGet('allergies') || [];
    const otherTerms = await storeGet('allergiesOther') || '';
    const dietStyle = await storeGet('dietStyle') || 'nessuna';
    const dislikes = await storeGet('dislikes') || '';
    updateMealSlotWarning(ev.target, bySlot, selectedAllergies, otherTerms, dietStyle, dislikes);
  }
  const date = document.getElementById('mealsDate').value;
  await renderMealsTotal(date, bySlot);
});

document.getElementById('saveMealsPlanBtn').addEventListener('click', async ()=>{
  const date = document.getElementById('mealsDate').value || todayStr();
  const bySlot = getMealOptionsBySlot();
  const sel = currentMealSelections(bySlot);
  const daySlots = {};
  Object.keys(sel).forEach(k=>{ if(sel[k].text) daySlots[k] = sel[k].text; });
  await setPlannedMealsForDate(date, daySlots);
  document.getElementById('mealsMsg').textContent = 'Piano del giorno salvato ✓';
  setTimeout(()=>{ document.getElementById('mealsMsg').textContent=''; }, 2000);
  if(document.getElementById('diaryDate').value === date) renderMealPlanGrid();
});

document.getElementById('logMealsToDiaryBtn').addEventListener('click', async ()=>{
  const date = document.getElementById('mealsDate').value || todayStr();
  const bySlot = getMealOptionsBySlot();
  const sel = currentMealSelections(bySlot);
  const entries = await getDiary(date);
  Object.keys(sel).forEach(k=>{
    const m = sel[k];
    if(m.text) entries.push({ name: m.label+': '+m.text, tag: m.tag, kcal: m.kcal, ts: Date.now() });
  });
  await saveDiary(date, entries);
  document.getElementById('mealsMsg').textContent = 'Segnato nel diario ✓';
  setTimeout(()=>{ document.getElementById('mealsMsg').textContent=''; }, 2000);
  if(document.getElementById('diaryDate').value === date) renderDiary();
  else await updateGauge(date, entries);
});

function shiftMealsDate(days){
  const current = document.getElementById('mealsDate').value || todayStr();
  const d = new Date(current+'T00:00:00');
  d.setDate(d.getDate()+days);
  const newDate = d.toISOString().slice(0,10);
  document.getElementById('mealsDate').value = newDate;
  document.getElementById('diaryDate').value = newDate;
  renderMealsTab();
}
document.getElementById('mealsPrevDayBtn').addEventListener('click', ()=> shiftMealsDate(-1));
document.getElementById('mealsNextDayBtn').addEventListener('click', ()=> shiftMealsDate(1));
document.getElementById('mealsDate').addEventListener('change', ()=>{
  document.getElementById('diaryDate').value = document.getElementById('mealsDate').value;
  renderMealsTab();
});
async function renderPlan(){
  const c = document.getElementById('planContainer');
  const selectedAllergies = await storeGet('allergies') || [];
  const otherTerms = await storeGet('allergiesOther') || '';
  const dietStyle = await storeGet('dietStyle') || 'nessuna';
  const dislikes = await storeGet('dislikes') || '';
  c.innerHTML = plan.map(d=>`
    <div class="day-card">
      <h3>${d.day} <span class="mono" style="color:var(--ink-soft); font-size:0.8rem; font-weight:400;">· totale ${d.totals.kcal} kcal</span></h3>
      ${d.meals.map(m=>`<div class="meal-line"><span class="when">${m[0]}</span><span>${m[1]} <span class="mono" style="color:var(--ink-soft); font-size:0.8rem;">· ${m[2]} kcal</span>
      ${allergyWarningsFor(m, selectedAllergies, otherTerms, dietStyle, dislikes)}</span></div>`).join('')}
    </div>
  `).join('');
}

// ---------- FOOD LISTS ----------
const goodFoods = [
  'Verdura a foglia verde e ortaggi di ogni colore',
  'Legumi (ceci, lenticchie, fagioli) più volte a settimana',
  'Cereali integrali (avena, farro, riso integrale, pane integrale)',
  'Pesce, soprattutto azzurro e ricco di omega-3',
  'Olio d\'oliva extravergine, con moderazione nelle quantità',
  'Frutta fresca intera (non succhi)',
  'Frutta secca non salata, in piccole porzioni',
  'Yogurt e latticini magri, con moderazione',
  'Acqua come bevanda principale, tè non zuccherato'
];
const badFoods = [
  'Alcol, in qualsiasi quantità',
  'Bevande zuccherate e succhi di frutta industriali',
  'Zuccheri semplici e dolci, soprattutto a base di fruttosio aggiunto',
  'Farine e cereali raffinati (pane bianco, pasta bianca in eccesso)',
  'Fritture e cibi ad alto contenuto di grassi saturi',
  'Carni processate e insaccati',
  'Snack industriali e cibi ultra-processati',
  'Sale in eccesso, specie se c\'è ritenzione di liquidi'
];
function renderFoodLists(){
  document.getElementById('goodList').innerHTML = goodFoods.map(f=>`<li>${f}</li>`).join('');
  document.getElementById('badList').innerHTML = badFoods.map(f=>`<li>${f}</li>`).join('');
}

// ---------- ALIMENTI ALTERNATIVI ----------
const foodSwaps = [
  ['Pane bianco', 'Pane integrale o a lievitazione naturale'],
  ['Bevande zuccherate / succhi di frutta', 'Acqua, tè non zuccherato, acqua con limone'],
  ['Burro o margarina', 'Olio d\'oliva extravergine, con moderazione'],
  ['Carne rossa processata / insaccati', 'Legumi, pesce, carni bianche'],
  ['Riso o pasta bianchi', 'Riso integrale, pasta integrale, farro, quinoa'],
  ['Snack industriali', 'Frutta secca non salata, frutta fresca'],
  ['Fritture', 'Cotture al forno, al vapore, alla griglia'],
  ['Formaggi stagionati o molto grassi', 'Yogurt greco magro, formaggi freschi light'],
  ['Alcolici', 'Infusi, acqua aromatizzata, bevande analcoliche senza zucchero']
];
function renderSwapTable(){
  document.getElementById('swapTable').innerHTML = `
    <div style="display:flex; flex-direction:column; gap:8px;">
      ${foodSwaps.map(([a,b])=>`
        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; padding:8px 0; border-bottom:1px solid var(--line);">
          <span style="flex:1; min-width:180px;">${a}</span>
          <span style="color:var(--ink-soft);">→</span>
          <span style="flex:1; min-width:180px; color:var(--olive-deep); font-weight:600;">${b}</span>
        </div>
      `).join('')}
    </div>`;
}

// ---------- ALLERGIE ----------
function normalize(s){
  return (s||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').trim();
}
const allergenList = ['Glutine','Lattosio','Uova','Pesce e crostacei','Frutta a guscio','Soia'];
function renderAllergyChecks(selected){
  const box = document.getElementById('allergyChecks');
  box.innerHTML = allergenList.map(a=>`
    <label style="flex-direction:row; align-items:center; gap:8px; font-size:0.92rem; color:var(--ink);">
      <input type="checkbox" class="allergyCheck" value="${a}" ${selected.includes(a)?'checked':''} style="width:18px; height:18px;">
      ${a}
    </label>
  `).join('');
}
async function loadAllergies(){
  const selected = await storeGet('allergies') || [];
  const other = await storeGet('allergiesOther') || '';
  renderAllergyChecks(selected);
  document.getElementById('allergyOtherInput').value = other;
}
document.getElementById('saveAllergiesBtn').addEventListener('click', async ()=>{
  const checked = Array.from(document.querySelectorAll('.allergyCheck:checked')).map(el=>el.value);
  const other = document.getElementById('allergyOtherInput').value.trim();
  await storeSet('allergies', checked);
  await storeSet('allergiesOther', other);
  document.getElementById('allergyMsg').textContent = 'Salvate ✓';
  setTimeout(()=>{ document.getElementById('allergyMsg').textContent=''; }, 2000);
  renderPlan();
  renderMealsTab();
});

async function loadTastes(){
  const dietStyle = await storeGet('dietStyle') || 'nessuna';
  const dislikes = await storeGet('dislikes') || '';
  document.getElementById('dietStyle').value = dietStyle;
  document.getElementById('dislikesInput').value = dislikes;
}
document.getElementById('saveTastesBtn').addEventListener('click', async ()=>{
  const dietStyle = document.getElementById('dietStyle').value;
  const dislikes = document.getElementById('dislikesInput').value.trim();
  await storeSet('dietStyle', dietStyle);
  await storeSet('dislikes', dislikes);
  document.getElementById('tastesMsg').textContent = 'Salvate ✓';
  setTimeout(()=>{ document.getElementById('tastesMsg').textContent=''; }, 2000);
  renderPlan();
  renderMealsTab();
});

// ---------- WEIGHT / WAIST TRACKING ----------
async function getWeightLog(){ return (await storeGet('weightlog')) || []; }
async function saveWeightLog(log){ await storeSet('weightlog', log); }

let weightViewMode = 'daily';

document.getElementById('wAddBtn').addEventListener('click', async ()=>{
  const date = document.getElementById('wDate').value || todayStr();
  const weight = parseFloat(document.getElementById('wWeight').value);
  const waist = parseFloat(document.getElementById('wWaist').value);
  if(!weight && !waist) return;
  let log = await getWeightLog();
  log = log.filter(r=>r.date !== date);
  log.push({ date, weight: weight||null, waist: waist||null });
  log.sort((a,b)=> a.date.localeCompare(b.date));
  await saveWeightLog(log);
  renderWeightTab();
});

function setWeightViewMode(mode){
  weightViewMode = mode;
  document.getElementById('weightViewSelect').value = mode;
  renderWeightTab();
}
document.getElementById('weightViewSelect').addEventListener('change', (ev)=> setWeightViewMode(ev.target.value));

function aggregateWeekly(log){
  const map = {};
  log.forEach(r=>{
    const monday = getWeekDates(r.date)[0];
    if(!map[monday]) map[monday] = { weights:[], waists:[] };
    if(r.weight) map[monday].weights.push(r.weight);
    if(r.waist) map[monday].waists.push(r.waist);
  });
  return Object.keys(map).sort().map(monday=>{
    const g = map[monday];
    const avg = arr => arr.length ? +(arr.reduce((a,b)=>a+b,0)/arr.length).toFixed(1) : null;
    return { date: monday, weight: avg(g.weights), waist: avg(g.waists), isWeek:true };
  });
}

async function renderWeightTab(){
  const rawLog = await getWeightLog();
  const log = weightViewMode === 'weekly' ? aggregateWeekly(rawLog) : rawLog;
  const rowsDiv = document.getElementById('weightRows');
  if(log.length===0){
    rowsDiv.innerHTML = '<div class="empty">Nessuna misurazione registrata.</div>';
  } else {
    rowsDiv.innerHTML = log.slice().reverse().map(r=>`
      <div class="weight-row">
        <span class="d">${weightViewMode==='weekly' ? 'Settimana del '+r.date : r.date}</span>
        <span>${r.weight ? r.weight+' kg' : '—'}</span>
        <span>${r.waist ? r.waist+' cm vita' : '—'}</span>
      </div>
    `).join('');
  }
  drawChart(log);
}

function drawChart(log){
  const svg = document.getElementById('weightChart');
  const W = 860, H = 220, padL = 46, padR = 20, padT = 16, padB = 30;
  svg.innerHTML = '';
  if(log.length < 2){
    svg.innerHTML = `<text x="20" y="110" fill="var(--ink-soft)" font-size="13" font-family="Inter">Aggiungi almeno due misurazioni per vedere il grafico.</text>`;
    return;
  }
  const weights = log.filter(r=>r.weight).map(r=>r.weight);
  if(weights.length < 2){
    svg.innerHTML = `<text x="20" y="110" fill="var(--ink-soft)" font-size="13" font-family="Inter">Aggiungi almeno due pesi per vedere il grafico.</text>`;
    return;
  }
  const min = Math.min(...weights) - 1, max = Math.max(...weights) + 1;
  const pts = log.filter(r=>r.weight).map((r,i,arr)=>{
    const x = padL + (i/(arr.length-1)) * (W-padL-padR);
    const y = padT + (1 - (r.weight-min)/(max-min)) * (H-padT-padB);
    return {x,y,label:r.date,val:r.weight};
  });
  let path = pts.map((p,i)=> (i===0?'M':'L')+p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');
  let svgHtml = `<path d="${path}" fill="none" stroke="var(--teal)" stroke-width="2.5"/>`;
  pts.forEach(p=>{
    svgHtml += `<circle cx="${p.x}" cy="${p.y}" r="4" fill="var(--olive-deep)"/>`;
  });
  svgHtml += `<line x1="${padL}" y1="${H-padB}" x2="${W-padR}" y2="${H-padB}" stroke="var(--line)"/>`;
  svgHtml += `<text x="6" y="${padT+5}" font-size="11" fill="var(--ink-soft)" font-family="JetBrains Mono">${max.toFixed(1)}</text>`;
  svgHtml += `<text x="6" y="${H-padB}" font-size="11" fill="var(--ink-soft)" font-family="JetBrains Mono">${min.toFixed(1)}</text>`;
  svg.innerHTML = svgHtml;
}

// ---------- INSTALL BANNER (rilevamento automatico della piattaforma) ----------
(function showInstallBannerIfNeeded(){
  const ua = navigator.userAgent;
  const platform = navigator.platform || '';
  const isStandaloneIOS = window.navigator.standalone === true;
  const isStandaloneOther = window.matchMedia && window.matchMedia('(display-mode: standalone)').matches;
  const isStandalone = isStandaloneIOS || isStandaloneOther;
  if(isStandalone) return;

  const isIOS = /iP(hone|ad|od)/.test(platform) || (ua.includes('Mac') && navigator.maxTouchPoints > 1);
  const isAndroid = /Android/.test(ua);
  const isMac = /Mac/.test(platform) && navigator.maxTouchPoints <= 1;
  const isWindows = /Win/.test(platform) || /Windows/.test(ua);

  const banner = document.getElementById('installBanner');
  if(!banner) return;

  if(isIOS){
    banner.innerHTML = '<strong>Installala sulla Home:</strong> tocca l\'icona <span class="mono">Condividi</span> in basso in Safari, poi <span class="mono">"Aggiungi alla schermata Home"</span>. Da quel momento si apre come un\'app, a schermo intero, e i dati restano salvati sul telefono.';
  } else if(isAndroid){
    banner.innerHTML = '<strong>Installala sulla Home:</strong> tocca i tre puntini <span class="mono">⋮</span> in alto a destra su Chrome, poi <span class="mono">"Aggiungi a schermata Home"</span>. Da quel momento si apre come un\'app, a schermo intero, e i dati restano salvati sul telefono.';
  } else if(isMac){
    banner.innerHTML = '<strong>Installala come app:</strong> su Safari (macOS Sonoma o successivo) vai su <span class="mono">File → "Aggiungi al Dock"</span>. Su Chrome o Edge, apri il menu (icona <span class="mono">⋮</span> o <span class="mono">···</span>) e cerca <span class="mono">"Installa questo sito come app"</span> o <span class="mono">"Altri strumenti → Crea scorciatoia"</span> (spunta "Apri come finestra"). Questa opzione compare solo se apri la pagina da un indirizzo web reale, non da un file scaricato sul Mac.';
  } else if(isWindows){
    banner.innerHTML = '<strong>Installala come app:</strong> su Chrome o Edge, apri il menu (icona <span class="mono">⋮</span> o <span class="mono">···</span>) e cerca <span class="mono">"Installa questo sito come app"</span> (Edge, sotto "App") oppure <span class="mono">"Altri strumenti → Crea scorciatoia"</span> (Chrome, spuntando "Apri come finestra"). Questa opzione compare solo se apri la pagina da un indirizzo web reale, non da un file scaricato sul PC.';
  } else {
    return; // piattaforma non riconosciuta: nessun banner, evita istruzioni sbagliate
  }
  banner.style.display = 'block';
})();


// ---------- LOCK / UNLOCK FLOW (Supabase Auth + cassaforte cifrata) ----------
function setLockError(id, msg){ document.getElementById(id).textContent = msg || ''; }

function showLock(which){
  ['lockCardFirstRun','lockCardRecoveryReveal','lockCardUnlock','lockCardRecoveryEnter','lockCardNewPassword','lockCardConfirmEmail'].forEach(id=>{
    document.getElementById(id).style.display = (id===which) ? 'block' : 'none';
  });
  if(which==='lockCardUnlock'){
    const name = localStorage.getItem('__displayNamePlain');
    const email = localStorage.getItem('__accountEmail');
    document.getElementById('unlockGreeting').textContent = name ? `Bentornato, ${name}` : 'Bentornato';
    if(email) document.getElementById('emailUnlock').value = email;
  }
}

// "Ricordami su questo dispositivo": salva la DEK in chiaro in localStorage, legata
// all'email dell'account. Comodo, ma significa che chiunque avesse accesso a QUESTO
// dispositivo potrebbe leggere i dati senza sapere la password — per questo è sempre
// una scelta esplicita dell'utente (casella da spuntare), mai un default silenzioso.
async function rememberDeviceWith(email){
  const dek = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));
  localStorage.setItem('__rememberedDevice', JSON.stringify({ email, dek: b64enc(dek) }));
}
function forgetDevice(){
  localStorage.removeItem('__rememberedDevice');
}
async function tryAutoUnlockFromRememberedDevice(sessionEmail){
  const raw = localStorage.getItem('__rememberedDevice');
  if(!raw) return false;
  try{
    const { email, dek } = JSON.parse(raw);
    if(email !== sessionEmail) return false;
    cryptoKey = await crypto.subtle.importKey('raw', b64dec(dek), 'AES-GCM', true, ['encrypt','decrypt']);
    return true;
  }catch(e){ return false; }
}

// Dopo un login/signup riuscito (sessione Supabase attiva), controlla se esiste già
// una cassaforte per questo utente: se sì la sblocca con la password appena usata,
// se no la crea ora (capita sia per un account nuovo con conferma email disattivata,
// sia per il primo login DOPO aver confermato l'email).
async function postAuthSetup(password){
  const vault = await fetchVaultRow();
  if(vault){
    await unlockVaultWithPassword(password);
  } else {
    const recoveryCode = await createVaultForCurrentUser(password);
    document.getElementById('recoveryCodeDisplay').textContent = recoveryCode;
    document.getElementById('confirmSavedRecovery').checked = false;
    document.getElementById('btnContinueAfterRecovery').disabled = true;
    showLock('lockCardRecoveryReveal');
    return; // l'apertura dell'app avviene dopo la conferma della chiave di recupero
  }
  unlockUI();
}

async function boot(){
  const { data: { session } } = await sb.auth.getSession();
  if(session){
    const autoUnlocked = await tryAutoUnlockFromRememberedDevice(session.user.email);
    if(autoUnlocked){ unlockUI(); return; }
    showLock('lockCardUnlock');
  } else {
    const savedEmail = localStorage.getItem('__accountEmail');
    showLock(savedEmail ? 'lockCardUnlock' : 'lockCardFirstRun');
  }
}

document.getElementById('btnCreatePass').addEventListener('click', async ()=>{
  const p1 = document.getElementById('passSet1').value;
  const p2 = document.getElementById('passSet2').value;
  const name = document.getElementById('nameSet').value.trim();
  const email = document.getElementById('emailSet').value.trim();
  setLockError('lockErrorSet','');
  if(!email){ setLockError('lockErrorSet','Inserisci un\'email.'); return; }
  if(p1.length < 8){ setLockError('lockErrorSet','Usa almeno 8 caratteri.'); return; }
  if(p1 !== p2){ setLockError('lockErrorSet','Le due password non coincidono.'); return; }

  const { data, error } = await sb.auth.signUp({ email, password: p1 });

  // Email già registrata: Supabase la segnala in due modi diversi a seconda della
  // configurazione del progetto — un errore esplicito, oppure (per non rivelare quali
  // email esistono già) un utente "fantasma" con identities vuoto e nessun errore.
  const looksAlreadyRegistered =
    (error && /already registered|already exists|user already/i.test(error.message)) ||
    (!error && data && data.user && Array.isArray(data.user.identities) && data.user.identities.length === 0);

  if(looksAlreadyRegistered){
    localStorage.setItem('__accountEmail', email);
    document.getElementById('emailUnlock').value = email;
    setLockError('lockErrorUnlock','Questa email ha già un account: inserisci la password per accedere.');
    showLock('lockCardUnlock');
    return;
  }
  if(error){ setLockError('lockErrorSet', error.message); return; }

  localStorage.setItem('__accountEmail', email);
  if(name) localStorage.setItem('__displayNamePlain', name);

  if(!data.session){
    // Conferma email richiesta dal progetto Supabase: non abbiamo ancora una sessione
    // autenticata, quindi non possiamo creare la cassaforte adesso. La creeremo al primo
    // login riuscito dopo la conferma (vedi postAuthSetup).
    document.getElementById('confirmEmailAddress').textContent = email;
    showLock('lockCardConfirmEmail');
    return;
  }
  if(name) await storeSet('displayName', name);
  await postAuthSetup(p1);
});

document.getElementById('btnBackToLoginFromConfirm').addEventListener('click', ()=>{
  showLock('lockCardUnlock');
});

document.getElementById('confirmSavedRecovery').addEventListener('change', (ev)=>{
  document.getElementById('btnContinueAfterRecovery').disabled = !ev.target.checked;
});
document.getElementById('copyRecoveryBtn').addEventListener('click', async ()=>{
  const code = document.getElementById('recoveryCodeDisplay').textContent;
  try{ await navigator.clipboard.writeText(code); }catch(e){}
  const btn = document.getElementById('copyRecoveryBtn');
  btn.textContent = 'Copiata ✓';
  setTimeout(()=>{ btn.textContent = 'Copia la chiave'; }, 1500);
});
document.getElementById('btnContinueAfterRecovery').addEventListener('click', ()=>{
  unlockUI();
});

document.getElementById('btnUnlock').addEventListener('click', async ()=>{
  const email = document.getElementById('emailUnlock').value.trim();
  const p = document.getElementById('passUnlock').value;
  const remember = document.getElementById('rememberDeviceCheck').checked;
  setLockError('lockErrorUnlock','');
  if(!email || !p) return;
  const { error } = await sb.auth.signInWithPassword({ email, password: p });
  if(error){ setLockError('lockErrorUnlock', error.message); return; }
  localStorage.setItem('__accountEmail', email);
  try{
    await postAuthSetup(p);
    if(remember && cryptoKey) await rememberDeviceWith(email);
  }catch(e){
    setLockError('lockErrorUnlock','Password corretta per l\'accesso, ma non decifra i tuoi dati. Riprova o usa la chiave di recupero.');
    cryptoKey = null;
  }
});
document.getElementById('passUnlock').addEventListener('keydown', (e)=>{
  if(e.key === 'Enter') document.getElementById('btnUnlock').click();
});

document.getElementById('forgotLink').addEventListener('click', ()=>{
  setLockError('lockErrorRecovery','');
  document.getElementById('recoveryCodeInput').value = '';
  showLock('lockCardRecoveryEnter');
});
document.getElementById('backToPasswordLink').addEventListener('click', ()=>{
  showLock('lockCardUnlock');
});
document.getElementById('sendResetEmailLink').addEventListener('click', async ()=>{
  const email = document.getElementById('emailUnlock').value.trim() || localStorage.getItem('__accountEmail') || '';
  if(!email){ setLockError('lockErrorRecovery','Inserisci prima la tua email nella schermata di accesso.'); return; }
  const { error } = await sb.auth.resetPasswordForEmail(email);
  setLockError('lockErrorRecovery', error ? error.message : `Email inviata a ${email}, se l'account esiste. Ricorda: reimposta il login, ma per i vecchi dati ti servirà comunque la chiave di recupero.`);
});

let pendingRecoveredDek = null;
document.getElementById('btnUseRecovery').addEventListener('click', async ()=>{
  const code = document.getElementById('recoveryCodeInput').value;
  setLockError('lockErrorRecovery','');
  try{
    pendingRecoveredDek = await unlockVaultWithRecoveryCode(code);
    document.getElementById('newPass1').value = '';
    document.getElementById('newPass2').value = '';
    setLockError('lockErrorNewPass','');
    showLock('lockCardNewPassword');
  }catch(e){
    setLockError('lockErrorRecovery','Chiave di recupero non valida.');
  }
});

document.getElementById('btnSetNewPassword').addEventListener('click', async ()=>{
  const p1 = document.getElementById('newPass1').value;
  const p2 = document.getElementById('newPass2').value;
  setLockError('lockErrorNewPass','');
  if(p1.length < 8){ setLockError('lockErrorNewPass','Usa almeno 8 caratteri.'); return; }
  if(p1 !== p2){ setLockError('lockErrorNewPass','Le due password non coincidono.'); return; }
  await rewrapWithNewPassword(pendingRecoveredDek, p1);
  pendingRecoveredDek = null;
  unlockUI();
});

function signOutLocally(){
  sb.auth.signOut();
  localStorage.clear();
  location.reload();
}
document.getElementById('forgotBothLink').addEventListener('click', ()=>{
  const sure = confirm('Senza password né chiave di recupero, i vecchi dati cifrati restano illeggibili per sempre — anche per noi, per progettazione. Puoi comunque disconnettere questo dispositivo e usare "Ho dimenticato la password" per rientrare nel login la prossima volta (creando poi dati nuovi). Vuoi disconnetterti ora?');
  if(sure) signOutLocally();
});
document.getElementById('resetAppBtn').addEventListener('click', ()=>{
  const sure = confirm('Questo disconnette il dispositivo e dimentica localmente nome/email salvati. I tuoi dati NON vengono cancellati: restano cifrati e al sicuro sul tuo account, pronti quando accedi di nuovo. Continuare?');
  if(sure) signOutLocally();
});
document.getElementById('regenerateRecoveryBtn').addEventListener('click', async ()=>{
  const newCode = await regenerateRecoveryCode();
  if(!newCode) return;
  document.getElementById('settingsRecoveryCode').textContent = newCode;
  document.getElementById('settingsRecoveryReveal').style.display = 'block';
});

document.getElementById('forgetDeviceBtn').addEventListener('click', ()=>{
  forgetDevice();
  const msg = document.getElementById('forgetDeviceMsg');
  msg.textContent = 'Fatto ✓';
  setTimeout(()=>{ msg.textContent=''; }, 2000);
});

async function loadDisplayName(){
  const name = await storeGet('displayName');
  document.getElementById('displayNameInput').value = name || '';
  document.getElementById('greetTag').textContent = name ? `Ciao, ${name}` : 'Il tuo piano alimentare';
}
document.getElementById('saveNameBtn').addEventListener('click', async ()=>{
  const name = document.getElementById('displayNameInput').value.trim();
  await storeSet('displayName', name);
  if(name) localStorage.setItem('__displayNamePlain', name);
  else localStorage.removeItem('__displayNamePlain');
  document.getElementById('greetTag').textContent = name ? `Ciao, ${name}` : 'Il tuo piano alimentare';
  const msg = document.getElementById('nameMsg');
  msg.textContent = 'Salvato ✓';
  setTimeout(()=>{ msg.textContent=''; }, 2000);
});

async function loadAccountEmail(){
  const { data: { user } } = await sb.auth.getUser();
  document.getElementById('accountEmailInput').value = user ? user.email : '';
}
document.getElementById('saveEmailBtn').addEventListener('click', async ()=>{
  const newEmail = document.getElementById('accountEmailInput').value.trim();
  const msg = document.getElementById('emailMsg');
  msg.textContent = '';
  if(!newEmail){ msg.textContent = 'Inserisci un\'email.'; return; }
  const { error } = await sb.auth.updateUser({ email: newEmail });
  if(error){ msg.textContent = error.message; msg.style.color = 'var(--brick)'; return; }
  msg.style.color = 'var(--olive-deep)';
  msg.textContent = 'Controlla la tua nuova email per confermare il cambiamento ✓';
});

document.getElementById('savePasswordBtn').addEventListener('click', async ()=>{
  const p1 = document.getElementById('settingsNewPass1').value;
  const p2 = document.getElementById('settingsNewPass2').value;
  const msg = document.getElementById('passwordMsg');
  msg.textContent = '';
  msg.style.color = 'var(--brick)';
  if(p1.length < 8){ msg.textContent = 'Usa almeno 8 caratteri.'; return; }
  if(p1 !== p2){ msg.textContent = 'Le due password non coincidono.'; return; }
  if(!cryptoKey){ msg.textContent = 'Sessione non pronta, riprova.'; return; }
  try{
    const dek = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));
    await rewrapWithNewPassword(dek, p1);
    msg.style.color = 'var(--olive-deep)';
    msg.textContent = 'Password aggiornata ✓';
    document.getElementById('settingsNewPass1').value = '';
    document.getElementById('settingsNewPass2').value = '';
  }catch(e){
    msg.textContent = 'Non sono riuscito ad aggiornare la password: ' + e.message;
  }
});

function unlockUI(){
  document.getElementById('lockScreen').style.display = 'none';
  document.getElementById('appRoot').style.display = 'block';
  startApp();
}

// ---------- THEME TOGGLE ----------
function applyTheme(pref){
  document.documentElement.setAttribute('data-theme', pref);
  document.getElementById('themeToggle').textContent = pref === 'light' ? '☀️' : '🌙';
}
(function initTheme(){
  const pref = localStorage.getItem('__themePref') || 'dark';
  applyTheme(pref);
})();
document.getElementById('themeToggle').addEventListener('click', ()=>{
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  localStorage.setItem('__themePref', next);
  applyTheme(next);
});

// ---------- APP INIT (dopo lo sblocco) ----------
async function startApp(){
  renderPlan();
  renderFoodLists();
  renderSwapTable();
  renderExerciseCategoryPicker();
  renderExerciseRoutine();
  renderLightAlternatives();
  document.getElementById('mealsDate').value = document.getElementById('diaryDate').value || todayStr();
  await loadDisplayName();
  await loadAccountEmail();
  await loadAllergies();
  await loadTastes();
  await loadProfile();
  await renderMealsTab();
  await renderDiary();
  await renderMealPlanGrid();
  setWeightViewMode('weekly');
}

boot();
