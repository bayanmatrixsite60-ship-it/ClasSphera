/* ClasSphera backend · QVMPXT · Cloudflare Pages advanced mode (_worker.js) · v2.8.0
   "One platform. Complete control. Zero compromise."

   BINDINGS   DB (D1) · KV (KV namespace) · ASSETS (automatic on Pages) · R2 (optional: snapshots, backups, audit) · AI (optional: Workers AI)
   SECRETS    TG_TOKEN, TG_CHAT, MASTER_KEY (16+ chars; also signs sessions unless JWT_SECRET is set)
   OPTIONAL   JWT_SECRET · GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET · STRIPE_KEY · STRIPE_WEBHOOK_SECRET
              EMAIL (Cloudflare Send Email binding) + MAIL_FROM · MAIL_KEY (Resend, fallback only) · FOUNDER_EMAIL
              OTP_DAILY_CAP · AI_DAILY_CAP · SLOW_MS · SITE_LASTMOD
   DATABASE   created and upgraded automatically by migrate() (schema_meta, versions 1.0 → 2.2). Old rows are never dropped.
   STORAGE    every institution workspace is stored as named sections ("parts") in D1 with a revision number per section.
              Writes are atomic and revision-checked (optimistic concurrency); sections over 400k chars are chunked.
              Tenant data is always read with the institution id (sub) taken from the signed session, never from the request.
   SESSIONS   HS256 JWT returned in the JSON body AND set as an HttpOnly cookie (cs_s) so background queues authenticate too.
   FILES      /robots.txt /sitemap.xml /manifest.webmanifest /sw.js /favicon.svg /favicon.ico /favicon-48x48.png /icon-192.png
              /icon-512.png /apple-touch-icon.png /.well-known/security.txt are all produced here (uploaded assets win if present).
   PAGES      every public route has real crawlable HTML + canonical + tagline in title/description + JSON-LD.
   ROUTES     see R{} below. Subdomains <name>.<root> serve the app shell and open that institution's secure login. */

const SITE='https://classphera.pages.dev',APEX='classphera.pages.dev',LASTMOD='2026-11-12';
const APP_V='2.8.2',API_SCHEMA='2.8.0',DATA_SCHEMA=3,MIN_CLIENT_MAJOR=2;
const TAG='One platform. Complete control. Zero compromise.',BRAND='ClasSphera by QVMPXT',BN_KW='স্কুল ম্যানেজমেন্ট সফটওয়্যার, কোচিং ম্যানেজম্যান্ট সফটওয়্যার, কলেজ ম্যানেজম্যান্ট সফটওয়্যার, নিরাপদ মাদ্রাসা ম্যানেজম্যান্ট সফটওয়্যার, মাদ্রাসা ফি ম্যানেজমেন্ট, অনলাইন স্কুল ম্যানেজমেন্ট সিস্টেম, মাদ্রাসার হিসাব রাখার সফটওয়্যার, স্কুলের বেতন ম্যানেজমেন্ট সিস্টেম, অনলাইন ফি কালেকশন সফটওয়্যার, ডিজিটাল ফি ও ডোনেশন রিকনসিলিয়েশন, মাদ্রাসা ম্যানেজম্যান্ট সফটওয়্যার, সুরক্ষিত স্কুল সফটওয়্যার, ক্লাউড স্কুল ম্যানেজমেন্ট বাংলাদেশ, মাদ্রাসা অটোমেশন সফটওয়্যার, নিরাপদ চ্যাট ও নোটিফিকেশন সিস্টেম',BN_DESC=' স্কুল, কলেজ, কোচিং ও মাদ্রাসার জন্য নিরাপদ ম্যানেজমেন্ট সফটওয়্যার: অনলাইন ফি কালেকশন, ডিজিটাল ফি ও ডোনেশন রিকনসিলিয়েশন, ক্লাউড স্কুল ম্যানেজমেন্ট বাংলাদেশ।';
const FOUNDER_MAIL='marufchowdhury579@gmail.com',FOUNDER_PHONE='+8801347272307',FOUNDER='M MARUF CHOWDHURY';
const ROOTS=[APEX,'classphera.com','classsphera.com'];
const AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const GATES=['bKash','Nagad','Rocket','Upay','SureCash','SSLCommerz','Visa','Mastercard','Stripe','PayPal','Bitcoin','USDT Vault','Cash','Bank transfer'];
const GATE_KEY=new Map(GATES.map(g=>[g.toLowerCase().replace(/[^a-z]/g,''),g])); /* 'bkash', 'BKASH', 'Sure Cash', 'sure-cash' all resolve to the canonical name */
const gateOf=v=>GATE_KEY.get(String(v==null?'':v).toLowerCase().replace(/[^a-z]/g,''))||null;
const SUBRX=/^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$/,MAILRX=/^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/,PHONERX=/^\+?\d{7,15}$/,FPRX=/^[0-9a-f]{64}$/,KEYRX=/^[A-Za-z0-9_]{1,40}$/;
const RESERVED=['www','app','api','admin','mail','ftp','root','support','status','cdn','static','login','signup','classphera','classsphera','qvmpxt'];
const ROLES=['Admin','Teacher','Accountant','Guardian','Supervisor'];
const INLINE_MAX=400000,CHUNK=400000,PART_MAX=24e6;

/* ───────────── core helpers ───────────── */
class Err extends Error{constructor(s,m,x){super(m);this.status=s;this.extra=x||{}}}
const enc=new TextEncoder(),dec=new TextDecoder();
const u8=s=>enc.encode(s);
const hex=b=>{const a=new Uint8Array(b);let s='';for(let i=0;i<a.length;i++)s+=a[i].toString(16).padStart(2,'0');return s};
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const eq=(a,b)=>{a=String(a);b=String(b);let d=a.length^b.length;const n=Math.max(a.length,b.length);for(let i=0;i<n;i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0};
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',u8(s)));
const b64u=b=>{const a=new Uint8Array(b);let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const unb64u=s=>{s=String(s).replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const r=atob(s),a=new Uint8Array(r.length);for(let i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a};
const nowS=()=>Math.floor(Date.now()/1000),iso=()=>new Date().toISOString();
const isO=v=>!!v&&typeof v==='object'&&!Array.isArray(v);
const str=(v,n)=>String(v==null?'':v).replace(/[\u0000-\u001F\u007F]+/g,' ').trim().slice(0,n);
const nph=v=>String(v==null?'':v).replace(/[^\d+]/g,'').slice(0,20);
const wsn=s=>String(s||'').toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,60);
const X=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const BASEH={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-robots-tag':'noindex, nofollow','x-api-schema-version':API_SCHEMA,'x-app-schema-version':API_SCHEMA};
const J=(o,s=200,h)=>new Response(JSON.stringify(o),{status:s,headers:h?{...BASEH,...h}:BASEH});
const JR=(t,s=200,h)=>new Response(t,{status:s,headers:h?{...BASEH,...h}:BASEH});
const bg=(C,p)=>{const q=Promise.resolve(p).catch(()=>{});if(C.ctx&&C.ctx.waitUntil)C.ctx.waitUntil(q);return q};

/* in-isolate memo and rate limiter (cheap, approximate); KV limiter for sensitive routes */
const MEM=new Map(),RLM=new Map();
const memo=async(k,ms,fn)=>{const n=Date.now(),h=MEM.get(k);if(h&&h.e>n)return h.v;const v=await fn();if(MEM.size>3000)MEM.clear();MEM.set(k,{v,e:n+ms});return v};
const memoDel=k=>MEM.delete(k);
function hitMem(k,max,ms){const n=Date.now();let r=RLM.get(k);if(!r||r.e<n){r={c:0,e:n+ms};RLM.set(k,r);if(RLM.size>6000)for(const[x,v]of RLM)if(v.e<n)RLM.delete(x)}r.c++;return r.c>max}
async function hit(env,key,max,ttl){try{const k=key+':'+Math.floor(Date.now()/(ttl*1000));if(env.KV&&env.KV.incr)return (await env.KV.incr(k,ttl*2))>max;const n=(+(await env.KV.get(k))||0)+1;await env.KV.put(k,String(n),{expirationTtl:Math.max(60,ttl*2)});return n>max}catch{return hitMem('kvf:'+key,max,ttl*1000)}} /* KV quota hit or KV down: fall back to the in-isolate counter instead of failing the request */
async function spend(env,key,n,max,ttl){try{const k=key+':'+Math.floor(Date.now()/(ttl*1000)),c=+(await env.KV.get(k))||0;if(c+n>max)return true;await env.KV.put(k,String(c+n),{expirationTtl:Math.max(60,ttl*2)});return false}catch{return hitMem('kvs:'+key,max,ttl*1000)}}

/* ───────────── secrets, JWT, AES ───────────── */
const secret=env=>{const s=env.JWT_SECRET||env.MASTER_KEY;if(!s||String(s).length<16)throw new Err(503,'Server is not configured: set MASTER_KEY (16+ characters) or JWT_SECRET.');return String(s)};
/* ── key-value store on D1 (replaces Cloudflare KV: OTPs, tokens, rate limits, bans). Same get/put/delete API, TTL via expirationTtl.
   Cloudflare KV's free plan allows only 1,000 writes a day; D1 allows 100,000, and no KV binding is needed any more. ── */
function d1kv(env){
 const db=env.DB,ns=()=>Math.floor(Date.now()/1000);
 return{
  async get(k){await migrate(env);const r=await db.prepare('SELECT v,exp FROM kvx WHERE k=?').bind(String(k)).first();if(!r)return null;if(r.exp&&r.exp<ns())return null;return r.v},
  async put(k,v,o){await migrate(env);const t=o&&+o.expirationTtl>0?ns()+Math.max(60,Math.floor(+o.expirationTtl)):0;
   await db.prepare('INSERT INTO kvx(k,v,exp) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v,exp=excluded.exp').bind(String(k),String(v),t).run();
   if(Math.random()<0.01)await db.prepare('DELETE FROM kvx WHERE exp>0 AND exp<?').bind(ns()).run().catch(()=>{})},
  async delete(k){await migrate(env);await db.prepare('DELETE FROM kvx WHERE k=?').bind(String(k)).run()},
  async incr(k,ttl){await migrate(env);const t=ns()+Math.max(60,ttl),r=await db.prepare("INSERT INTO kvx(k,v,exp) VALUES(?,'1',?) ON CONFLICT(k) DO UPDATE SET v=CAST(v AS INTEGER)+1 RETURNING v").bind(String(k),t).first();return +(r&&r.v)||1}}}
const withKV=env=>env&&env.DB&&!env.__d1kv?{...env,KV:d1kv(env),__d1kv:true}:env;
/* ── diagnostics: readable reasons instead of a bare "server error" ── */
function needBindings(env){const m=[];
 if(!env||!env.DB||typeof env.DB.prepare!=='function')m.push('DB (D1 database)');
 if(m.length){console.error('[ClasSphera] Missing Cloudflare binding(s): '+m.join(', '));throw new Err(503,'Missing Cloudflare binding: '+m.join(' and ')+'. Add it in Cloudflare → Pages/Worker → Settings → Bindings (the variable name must match exactly), then redeploy.',{code:'missing_binding'})}}
function whyOf(e){
 const m=String(e&&e.message||e||'unknown error').replace(/\s+/g,' ').trim().slice(0,300);
 if(/KV .*(limit|quota)|limit exceeded|too many requests/i.test(m)&&/KV|put\(\)|get\(\)/i.test(m))return'Cloudflare KV limit reached: '+m;
 if(/no such table|D1_ERROR|SQLITE|database/i.test(m))return'Database error: '+m;
 if(/Cannot read prop.*(prepare|get|put|batch)|is not a function|undefined/i.test(m)&&/DB|KV|prepare|batch|\.get|\.put/i.test(m))return'A Cloudflare binding (DB or KV) is missing or misnamed: '+m;
 return m}
/* Google credentials: trimmed, surrounding quotes removed, missing names listed */
const envStr=v=>{let x=String(v==null?'':v).trim();if(/^(["']).*\1$/.test(x))x=x.slice(1,-1).trim();return x};
function gcfg(env){const id=envStr(env&&env.GOOGLE_CLIENT_ID),sec=envStr(env&&env.GOOGLE_CLIENT_SECRET),missing=[];
 if(!id)missing.push('GOOGLE_CLIENT_ID');if(!sec)missing.push('GOOGLE_CLIENT_SECRET');
 if(id&&!/^[\w.-]+\.apps\.googleusercontent\.com$/i.test(id))console.warn('[ClasSphera] GOOGLE_CLIENT_ID does not look like a Google Web Client ID (<number>-<hash>.apps.googleusercontent.com).');
 return{id,sec,missing,ok:!missing.length}}
const HK=new Map();
async function hkey(env){const s=secret(env);let k=HK.get(s);if(!k){k=await crypto.subtle.importKey('raw',u8(s),{name:'HMAC',hash:'SHA-256'},false,['sign']);HK.set(s,k)}return k}
const hmac=async(env,m)=>hex(await crypto.subtle.sign('HMAC',await hkey(env),u8(m)));
async function signJWT(env,c){const h=b64u(u8('{"alg":"HS256","typ":"JWT"}')),p=b64u(u8(JSON.stringify(c)));return h+'.'+p+'.'+b64u(await crypto.subtle.sign('HMAC',await hkey(env),u8(h+'.'+p)))}
async function verifyJWT(env,t){try{t=String(t||'');if(t.length>4096)return null;const a=t.split('.');if(a.length!==3)return null;const s=b64u(await crypto.subtle.sign('HMAC',await hkey(env),u8(a[0]+'.'+a[1])));if(!eq(s,a[2]))return null;const c=JSON.parse(dec.decode(unb64u(a[1])));if(!c||!SUBRX.test(String(c.sub||''))||!(c.exp>nowS()))return null;return c}catch{return null}}
let AESK=null,AESS='';
async function aesKey(env){const s=secret(env);if(AESK&&AESS===s)return AESK;AESK=await crypto.subtle.importKey('raw',await crypto.subtle.digest('SHA-256',u8('cs-totp:'+s)),'AES-GCM',false,['encrypt','decrypt']);AESS=s;return AESK}
async function seal(env,t){const iv=crypto.getRandomValues(new Uint8Array(12)),c=await crypto.subtle.encrypt({name:'AES-GCM',iv},await aesKey(env),u8(t));return b64u(iv)+'.'+b64u(c)}
async function unseal(env,t){const a=String(t).split('.');return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64u(a[0])},await aesKey(env),unb64u(a[1])))}

/* ───────────── D1 layer + automatic, non-destructive migrations ───────────── */
const sq=(env,sql,...a)=>env.DB.prepare(sql).bind(...a);
const SCHEMA=[
['1.0',['CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,sub TEXT,gateway TEXT,item TEXT,usd REAL,txid TEXT,status TEXT,at TEXT)','CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,detail TEXT,ip TEXT,at TEXT)']],
['1.1',['CREATE TABLE IF NOT EXISTS devices(sub TEXT NOT NULL,fp TEXT NOT NULL,first_seen TEXT,last_seen TEXT,ip TEXT,trusted INTEGER DEFAULT 1,PRIMARY KEY(sub,fp))','CREATE INDEX IF NOT EXISTS idx_devices_sub ON devices(sub)']],
['1.2',['CREATE TABLE IF NOT EXISTS institutions(sub TEXT PRIMARY KEY,name TEXT,itype TEXT,country TEXT,created_at TEXT)']],
['1.3',['CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at)','CREATE INDEX IF NOT EXISTS idx_payments_sub ON payments(sub)']],
['2.0',['CREATE TABLE IF NOT EXISTS ws_parts(sub TEXT NOT NULL,k TEXT NOT NULL,rev INTEGER NOT NULL DEFAULT 0,big INTEGER NOT NULL DEFAULT 0,deleted INTEGER NOT NULL DEFAULT 0,size INTEGER NOT NULL DEFAULT 0,data TEXT,updated TEXT,PRIMARY KEY(sub,k))',
 'CREATE TABLE IF NOT EXISTS ws_chunks(sub TEXT NOT NULL,k TEXT NOT NULL,rev INTEGER NOT NULL,i INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(sub,k,i))',
 'CREATE TABLE IF NOT EXISTS ws_guard(ok INTEGER NOT NULL CHECK(ok=0))',
 'CREATE TABLE IF NOT EXISTS ws_meta(sub TEXT PRIMARY KEY,dschema INTEGER NOT NULL DEFAULT 0,created TEXT,updated TEXT,snap_at TEXT)',
 'CREATE TABLE IF NOT EXISTS ws_index(sub TEXT NOT NULL,phone TEXT NOT NULL,mail TEXT NOT NULL,role TEXT,PRIMARY KEY(sub,phone))',
 'CREATE INDEX IF NOT EXISTS idx_ws_index_mail ON ws_index(mail)']],
['2.1',["CREATE TABLE IF NOT EXISTS portal(sub TEXT NOT NULL,sid TEXT NOT NULL,ph TEXT NOT NULL DEFAULT '',gh TEXT NOT NULL DEFAULT '',gs TEXT NOT NULL DEFAULT '',sh TEXT NOT NULL DEFAULT '',ss TEXT NOT NULL DEFAULT '',d TEXT NOT NULL,gen INTEGER NOT NULL DEFAULT 0,updated TEXT,PRIMARY KEY(sub,sid))",
 'CREATE TABLE IF NOT EXISTS portal_inbox(id INTEGER PRIMARY KEY AUTOINCREMENT,sub TEXT NOT NULL,sid TEXT NOT NULL,x TEXT NOT NULL,at INTEGER NOT NULL)',
 'CREATE INDEX IF NOT EXISTS idx_portal_inbox_sub ON portal_inbox(sub,id)',
 'CREATE TABLE IF NOT EXISTS directory(sub TEXT PRIMARY KEY,name TEXT,itype TEXT,country TEXT,city TEXT,address TEXT,phone TEXT,email TEXT,wa TEXT,admission TEXT,about TEXT,logo TEXT,listed INTEGER NOT NULL DEFAULT 0,updated TEXT)',
 'CREATE INDEX IF NOT EXISTS idx_directory_listed ON directory(listed,country,itype)',
 "CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,sub TEXT NOT NULL,name TEXT,dob TEXT,cls TEXT,guardian TEXT,phone TEXT,email TEXT,place TEXT,note TEXT,at TEXT,status TEXT DEFAULT 'new')",
 'CREATE INDEX IF NOT EXISTS idx_admissions_sub ON admissions(sub,at)',
 'CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,sub TEXT NOT NULL,kind TEXT NOT NULL,data TEXT,at TEXT)',
 'CREATE INDEX IF NOT EXISTS idx_events_sub ON events(sub,kind,id)',
 'CREATE TABLE IF NOT EXISTS prefs(sub TEXT NOT NULL,uid TEXT NOT NULL,data TEXT NOT NULL,rev INTEGER NOT NULL DEFAULT 0,updated TEXT,PRIMARY KEY(sub,uid))']],
['2.2',['CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,sub TEXT NOT NULL,uid TEXT NOT NULL,pub TEXT NOT NULL,alg INTEGER NOT NULL,counter INTEGER NOT NULL DEFAULT 0,transports TEXT,created TEXT)',
 'CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(sub,uid)',
 'CREATE TABLE IF NOT EXISTS totp(sub TEXT NOT NULL,uid TEXT NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL DEFAULT 0,created TEXT,PRIMARY KEY(sub,uid))',
 'CREATE TABLE IF NOT EXISTS trusted(sub TEXT NOT NULL,uid TEXT NOT NULL,fp TEXT NOT NULL,first_seen TEXT,last_seen TEXT,PRIMARY KEY(sub,uid,fp))',
 'CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,detail TEXT,sub TEXT,at TEXT)',
 'CREATE INDEX IF NOT EXISTS idx_alerts_at ON alerts(at)',
 'CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status,at)']],
['2.3',['CREATE TABLE IF NOT EXISTS kvx(k TEXT PRIMARY KEY,v TEXT NOT NULL,exp INTEGER NOT NULL DEFAULT 0)']],
['2.4',['DROP INDEX IF EXISTS idx_kvx_exp']], /* an index doubles the write cost of every put; the table is small and purged, so a scan is cheaper */
['2.5',['CREATE TABLE IF NOT EXISTS portal_out(id INTEGER PRIMARY KEY AUTOINCREMENT,sub TEXT NOT NULL,sid TEXT NOT NULL,k TEXT NOT NULL DEFAULT \'m\',x TEXT NOT NULL,u INTEGER NOT NULL DEFAULT 0,at INTEGER NOT NULL)','CREATE INDEX IF NOT EXISTS idx_portal_out ON portal_out(sub,sid,id)']] /* teacher replies (k=m) and notices (k=b, sid=*) that guardians read live through /api/g/data */
,['2.6',["CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY,workspace_sub TEXT NOT NULL,recipient_id TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,type TEXT,action_url TEXT,is_read INTEGER DEFAULT 0,created_at DATETIME)",'CREATE INDEX IF NOT EXISTS idx_notifications_rcpt ON notifications(workspace_sub,recipient_id,created_at)']] /* in-house guardian alerts (attendance, reports, receipts): written by /api/notify*, read live by the guardian through /api/g/data */
,['2.7',['ALTER TABLE portal_out ADD COLUMN meta TEXT','ALTER TABLE portal_inbox ADD COLUMN meta TEXT',
  'CREATE TABLE IF NOT EXISTS portal_rx(sub TEXT NOT NULL,sid TEXT NOT NULL,k TEXT NOT NULL,at INTEGER NOT NULL,who TEXT NOT NULL,e TEXT NOT NULL,PRIMARY KEY(sub,sid,k,at,who))',
  'CREATE TABLE IF NOT EXISTS portal_seen(sub TEXT NOT NULL,sid TEXT NOT NULL,who TEXT NOT NULL,dv INTEGER NOT NULL DEFAULT 0,seen INTEGER NOT NULL DEFAULT 0,ty INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(sub,sid,who))',
  'CREATE TABLE IF NOT EXISTS push_subs(id TEXT PRIMARY KEY,sub TEXT NOT NULL,who TEXT NOT NULL,sid TEXT NOT NULL DEFAULT \'\',ep TEXT NOT NULL,created TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_push_subs ON push_subs(sub,who,sid)']] /* chat extras: reply quotes (meta), reactions, delivered/read/typing state, web-push subscriptions */
,['2.8',['ALTER TABLE push_subs ADD COLUMN p256dh TEXT','ALTER TABLE push_subs ADD COLUMN auth TEXT',
  'CREATE TABLE IF NOT EXISTS push_q(id INTEGER PRIMARY KEY AUTOINCREMENT,sub TEXT NOT NULL,who TEXT NOT NULL,sid TEXT NOT NULL,pl TEXT NOT NULL,cur TEXT NOT NULL DEFAULT \'\',at INTEGER NOT NULL)']] /* readable push: subscription keys for encrypted payloads, plus a small queue for broadcasts that are larger than one request can send */
,['2.9',['CREATE INDEX IF NOT EXISTS idx_portal_sid ON portal(sid)','CREATE INDEX IF NOT EXISTS idx_portal_ph ON portal(ph)']] /* guardian / student sign-in finds the row by mobile number or admission ID alone; the Secret PIN decides which institution it belongs to */
,['3.0',['CREATE TABLE IF NOT EXISTS portal_pin(pk TEXT PRIMARY KEY,sub TEXT NOT NULL,sid TEXT NOT NULL)','CREATE INDEX IF NOT EXISTS idx_portal_pin_sub ON portal_pin(sub)','DROP INDEX IF EXISTS idx_portal_sid','DROP INDEX IF EXISTS idx_portal_ph']] /* one row per Secret PIN across ALL institutions: pk is a lookup hash of the PIN and is the PRIMARY KEY, so two students can never hold the same PIN */
,['3.1',['CREATE TABLE IF NOT EXISTS fee_cfg(sub TEXT PRIMARY KEY,data TEXT NOT NULL,updated TEXT)',
  "CREATE TABLE IF NOT EXISTS fee_due(id TEXT PRIMARY KEY,sub TEXT NOT NULL,sid TEXT NOT NULL,cat TEXT NOT NULL,title TEXT NOT NULL DEFAULT '',amt REAL NOT NULL,cur TEXT NOT NULL DEFAULT 'BDT',due_on TEXT NOT NULL DEFAULT '',publish_at INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'due',nt INTEGER NOT NULL DEFAULT 0,paid_at INTEGER,batch TEXT NOT NULL DEFAULT '')",
  'CREATE INDEX IF NOT EXISTS idx_fee_due_stu ON fee_due(sub,sid,status,publish_at)','CREATE INDEX IF NOT EXISTS idx_fee_due_batch ON fee_due(sub,batch)',
  "CREATE TABLE IF NOT EXISTS fee_rule(id TEXT PRIMARY KEY,sub TEXT NOT NULL,cat TEXT NOT NULL,title TEXT NOT NULL DEFAULT '',amt REAL NOT NULL,cur TEXT NOT NULL DEFAULT 'BDT',cls TEXT NOT NULL DEFAULT '',sids TEXT NOT NULL DEFAULT '',day INTEGER NOT NULL DEFAULT 1,next_at INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 1)",
  "CREATE TABLE IF NOT EXISTS fee_pay(id TEXT PRIMARY KEY,sub TEXT NOT NULL,sid TEXT NOT NULL,due_id TEXT NOT NULL,status TEXT NOT NULL,method TEXT NOT NULL DEFAULT '',cur TEXT NOT NULL DEFAULT 'BDT',amt REAL NOT NULL DEFAULT 0,from_no TEXT NOT NULL DEFAULT '',rcv_no TEXT NOT NULL DEFAULT '',trx TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL,updated INTEGER NOT NULL,decided_by TEXT,decided_at INTEGER)",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_fee_pay_open ON fee_pay(due_id) WHERE status IN ('draft','pending')",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_fee_pay_trx ON fee_pay(sub,method,trx) WHERE trx<>'' AND status IN ('pending','approved')",
  'CREATE INDEX IF NOT EXISTS idx_fee_pay_q ON fee_pay(sub,status,created)',
  'CREATE TABLE IF NOT EXISTS fee_receipt(code TEXT PRIMARY KEY,no TEXT NOT NULL,pay_id TEXT NOT NULL UNIQUE,sub TEXT NOT NULL,sid TEXT NOT NULL,inst TEXT,stu TEXT,cls TEXT,cat TEXT,title TEXT,amt REAL NOT NULL,cur TEXT NOT NULL,method TEXT,from_no TEXT,rcv_no TEXT,trx TEXT,pat INTEGER,at INTEGER NOT NULL,sig TEXT NOT NULL,appr TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_fee_rc_stu ON fee_receipt(sub,sid,at)']] /* fee payments: dues, payment attempts (draft/pending/approved/rejected), permanent receipts, merchant numbers */
,['3.2',['CREATE TABLE IF NOT EXISTS pz_receipts(inst TEXT NOT NULL,trx TEXT NOT NULL,ref TEXT NOT NULL DEFAULT \'\',rno TEXT NOT NULL,sig TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,at INTEGER NOT NULL,PRIMARY KEY(inst,trx))','CREATE INDEX IF NOT EXISTS idx_pz_rc_sig ON pz_receipts(sig)',
  'CREATE TABLE IF NOT EXISTS pz_drafts(sub TEXT NOT NULL,sid TEXT NOT NULL,who TEXT NOT NULL,body TEXT NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(sub,sid,who))']] /* signed receipt links (one row per TrxID per institution) + cloud copy of unfinished payment drafts */
,['3.3',['CREATE TABLE IF NOT EXISTS gv_prof(sub TEXT NOT NULL,sid TEXT NOT NULL,who TEXT NOT NULL,body TEXT NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(sub,sid,who))']] /* saved profile (photos, details, homework ticks, study hub) of one guardian or student, so every device shows the same after sign-in */
];
let MIGRATED=null;
function migrate(env){
 if(MIGRATED)return MIGRATED;
 MIGRATED=(async()=>{
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS schema_meta(k TEXT PRIMARY KEY,v TEXT)').run();
  const r=await env.DB.prepare("SELECT v FROM schema_meta WHERE k='version'").first(),cur=r?r.v:null;
  let at=cur?SCHEMA.findIndex(s=>s[0]===cur):-1;if(cur&&at<0)at=SCHEMA.length-1; /* a newer version already ran: never downgrade */
  for(let i=at+1;i<SCHEMA.length;i++){
   await env.DB.batch(SCHEMA[i][1].map(q=>env.DB.prepare(q)));
   await env.DB.prepare("INSERT INTO schema_meta(k,v) VALUES('version',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(SCHEMA[i][0]).run();
  }
 })().catch(e=>{MIGRATED=null;throw e});
 return MIGRATED}
const dbAudit=(env,kind,detail,ip)=>env.DB.prepare('INSERT INTO audit(kind,detail,ip,at) VALUES(?,?,?,?)').bind(kind,String(detail).slice(0,300),ip,iso()).run().catch(()=>{});
const dbInst=(env,sub)=>env.DB.prepare('SELECT sub,name,itype,country FROM institutions WHERE sub = ?').bind(sub).first();

/* ───────────── founder notifications, alerts, audit trail ───────────── */
/* Telegram sender. Fixes the silent failures: secrets are cleaned (stray spaces/newlines, quotes, a pasted "bot" prefix),
   long text is cut on a line boundary (a cut tag made Telegram answer 400), an HTML parse error is retried once as plain text,
   a 429 is retried once, and the real reason Telegram gave is written to the Worker logs (the token is never logged). */
async function tg(env,text){
 const clean=v=>String(v==null?'':v).trim().replace(/^["']+|["']+$/g,'').trim(),tok=clean(env&&env.TG_TOKEN).replace(/^bot/i,''),chat=clean(env&&env.TG_CHAT);
 if(!tok||!chat){console.error('[ClasSphera] Telegram not sent: '+(!tok?'TG_TOKEN':'TG_CHAT')+' is empty or missing in this environment. Set it for the environment that is live (Pages: Production and Preview are separate), then redeploy.');return false}
 let t=String(text==null?'':text);
 if(t.length>4000){const c=t.lastIndexOf('\n',3950);t=t.slice(0,c>500?c:3950)+'\n…'}
 const plain=s=>s.replace(/<[^>]*$/,'').replace(/<[^>]*>/g,'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
 const url=`https://api.telegram.org/bot${tok}/sendMessage`;
 const send=async extra=>{
  const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chat,disable_web_page_preview:true,...extra}),signal:typeof AbortSignal!=='undefined'&&AbortSignal.timeout?AbortSignal.timeout(8000):undefined});
  let j=null;try{j=await r.json()}catch{}
  return{ok:r.ok&&!(j&&j.ok===false),st:r.status,d:String((j&&j.description)||'').slice(0,200),ra:+(j&&j.parameters&&j.parameters.retry_after)||0}};
 try{
  let r=await send({text:t,parse_mode:'HTML'});
  if(!r.ok&&r.st===400&&/parse entities|unsupported start tag|can't find end|unclosed/i.test(r.d))r=await send({text:plain(t)});
  if(!r.ok&&r.st===429&&r.ra>0&&r.ra<=3){await new Promise(z=>setTimeout(z,r.ra*1000+250));r=await send({text:t,parse_mode:'HTML'})}
  if(!r.ok){const hint=r.st===401||r.st===404?' → TG_TOKEN is wrong or revoked (copy it again from @BotFather)':r.st===400&&/chat not found/i.test(r.d)?' → TG_CHAT is wrong, or the bot was never started / added (open the bot and press Start, or add it to the group/channel as admin)':r.st===403?' → the bot was blocked, removed, or cannot post in that chat':'';
   console.error(`[ClasSphera] Telegram rejected the message: HTTP ${r.st} · ${r.d||'no description'}${hint}`)}
  return r.ok
 }catch(e){console.error('[ClasSphera] Telegram request failed: '+String(e&&e.message||e).slice(0,200));return false}}
async function r2log(env,kind,detail,ip){if(!env.R2)return;try{const d=new Date();await env.R2.put(`audit/${d.toISOString().slice(0,10)}/${d.getTime()}-${rnd(4)}.json`,JSON.stringify({kind,detail:String(detail).slice(0,500),ip,at:d.toISOString(),v:APP_V}),{httpMetadata:{contentType:'application/json'}})}catch{}}
/* security alert: audited, mirrored to R2, hourly cap of 60 Telegram messages */
async function alert(env,ip,kind,detail){await dbAudit(env,kind,detail,ip);await r2log(env,kind,detail,ip);try{if(await spend(env,'alg',1,60,3600))return false}catch{}return tg(env,`🚨 <b>${X(kind)}</b>\n${X(detail)}\nIP: ${X(ip)}`)}
/* system / health alert: de-duplicated, stored, mirrored to Telegram (and e-mail fallback) */
async function sysAlert(env,kind,detail,o={}){
 try{const k='fa:'+(await sha(kind+'|'+(o.key||String(detail).slice(0,160)))).slice(0,40);
  if(await env.KV.get(k))return false;await env.KV.put(k,'1',{expirationTtl:o.ttl||1800});
  const d=String(typeof detail==='string'?detail:JSON.stringify(detail)).slice(0,900);
  await env.DB.prepare('INSERT INTO alerts(kind,detail,sub,at) VALUES(?,?,?,?)').bind(kind,d,o.sub||null,iso()).run().catch(()=>{});
  await r2log(env,kind,d,o.ip||'');
  if(await spend(env,'sag',1,80,3600))return false;
  const ok=await tg(env,`🩺 <b>${X(kind)}</b>\nv${APP_V}${o.sub?' · '+X(o.sub):''}\n${X(d)}`);
  if(!ok)await sendMail(env,env.FOUNDER_EMAIL||FOUNDER_MAIL,'ClasSphera system alert: '+kind,`<pre>${X(d)}</pre>`,d);
  return ok}catch{return false}}
async function fail(env,ip,why){if(await hit(env,'ff:'+ip,5,10)){try{await env.KV.put('ban:'+ip,'1',{expirationTtl:900})}catch{}await alert(env,ip,'IP banned (brute force)',why)}}

/* ───────────── mail / SMS / OTP delivery ───────────── */
async function sendMail(env,to,subject,html,text){
 if(!MAILRX.test(String(to||'')))return false;
 const mb=env.EMAIL||env.SEND_EMAIL; /* Cloudflare native Send Email binding */
 if(mb&&typeof mb.send==='function'){try{await mb.send({to,from:env.MAIL_FROM||'no-reply@classphera.com',subject,html,text});return true}catch(e){console.warn('[ClasSphera] Cloudflare Email send failed: '+(e&&e.message))}}
 if(!env.MAIL_KEY||!env.MAIL_FROM)return false;
 try{const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+env.MAIL_KEY,'content-type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM,to:[to],subject,html,text})});return r.ok}catch{return false}}
async function sendOtp(env,mail,phone,code){
 const ok=await sendMail(env,mail,'Your ClasSphera verification code',`<div style="font-family:Inter,Arial,sans-serif;background:#070812;color:#e6e9f5;padding:28px;border-radius:16px;max-width:420px"><h2 style="margin:0 0 8px">ClasSphera 🔐</h2><p style="color:#9aa1b9">Your 6-digit verification code:</p><p style="font-size:34px;font-weight:800;letter-spacing:10px;color:#34d399;margin:14px 0">${code}</p><p style="color:#9aa1b9;font-size:12px">Valid for 5 minutes. If this was not you, ignore this message and tell your Principal.</p></div>`,`ClasSphera code: ${code} (valid 5 minutes)`);
 if(ok)return 'mail';
 return null}

/* ───────────── sessions ───────────── */
function tokenOf(C){const a=C.req.headers.get('authorization')||'';if(/^Bearer /i.test(a))return a.slice(7).trim();if(C.b&&typeof C.b.token==='string'&&C.b.token)return C.b.token;const m=/(?:^|;\s*)cs_s=([^;]+)/.exec(C.req.headers.get('cookie')||'');return m?decodeURIComponent(m[1]):''}
const revokedAt=(env,sub,ph)=>memo('rv:'+sub+':'+ph,8000,async()=>Math.max(+(await env.KV.get('sxr:'+sub))||0,+(await env.KV.get('sxu:'+sub+':'+ph))||0));
async function auth(C){
 if(C.sess!==undefined)return C.sess;
 const t=tokenOf(C),c=t?await verifyJWT(C.env,t):null;let ok=null;
 if(c&&(!C.tenant||c.sub===C.tenant)){const rv=await revokedAt(C.env,c.sub,c.ph||'');if(!(rv&&c.iat<rv))ok={...c,token:t}}
 C.sess=ok;return ok}
async function need(C,roles){const s=await auth(C);if(!s)throw new Err(401,'invalid session');if(roles&&!roles.includes(s.role))throw new Err(403,'Your role cannot do this');return s}
async function issue(C,u,fp){const now=nowS(),exp=now+28800,token=await signJWT(C.env,{sub:u.sub,ph:u.ph,role:u.role,fp:String(fp||'').slice(0,64),iat:now,exp,v:APP_V});return{token,exp,cookie:`cs_s=${token}; Path=/api; Max-Age=28800; HttpOnly; Secure; SameSite=Strict`}}
const sessResp=(t,o)=>J({...o,token:t.token,exp:t.exp},200,{'set-cookie':t.cookie});
async function trustDevice(env,sub,uid,fp,ip){const t=iso();
 await env.DB.batch([sq(env,'INSERT INTO trusted(sub,uid,fp,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(sub,uid,fp) DO UPDATE SET last_seen=excluded.last_seen',sub,uid,fp,t,t),
  sq(env,'INSERT INTO devices(sub,fp,first_seen,last_seen,ip,trusted) VALUES(?,?,?,?,?,1) ON CONFLICT(sub,fp) DO UPDATE SET last_seen=excluded.last_seen,ip=excluded.ip,trusted=1',sub,fp,t,t,ip),
  sq(env,'DELETE FROM trusted WHERE sub=?1 AND uid=?2 AND fp NOT IN (SELECT fp FROM trusted WHERE sub=?1 AND uid=?2 ORDER BY last_seen DESC LIMIT 20)',sub,uid)])}

/* ───────────── workspace store: sections with revisions, atomic optimistic writes ───────────── */
async function partMeta(env,sub,keys){const out=new Map();for(let i=0;i<keys.length;i+=80){const ks=keys.slice(i,i+80),r=await sq(env,`SELECT k,rev,big,deleted FROM ws_parts WHERE sub=? AND k IN (${ks.map(()=>'?').join(',')})`,sub,...ks).all();for(const x of r.results||[])out.set(x.k,x)}return out}
async function readParts(env,sub,keys){
 const out=new Map(),groups=[];if(keys){for(let i=0;i<keys.length;i+=80)groups.push(keys.slice(i,i+80))}else groups.push(null);
 for(const g of groups){
  const w=g?` AND k IN (${g.map(()=>'?').join(',')})`:'',a=g?[sub,...g]:[sub];
  const[r1,r2]=await env.DB.batch([sq(env,`SELECT k,rev,big,deleted,data FROM ws_parts WHERE sub=?${w}`,...a),sq(env,`SELECT k,i,data FROM ws_chunks WHERE sub=?${w} ORDER BY k,i`,...a)]);
  const ch=new Map();for(const c of r2.results||[]){if(!ch.has(c.k))ch.set(c.k,[]);ch.get(c.k).push(c.data)}
  for(const x of r1.results||[])out.set(x.k,{rev:x.rev,deleted:!!x.deleted,raw:x.deleted?null:(x.big?(ch.get(x.k)||[]).join(''):x.data)})}
 return out}
async function getJson(env,sub,k){const m=await readParts(env,sub,[k]),x=m.get(k);if(!x||x.deleted||!x.raw)return null;try{return JSON.parse(x.raw)}catch{return null}}
const UPSERT='INSERT INTO ws_parts(sub,k,rev,big,deleted,size,data,updated) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sub,k) DO UPDATE SET rev=excluded.rev,big=excluded.big,deleted=excluded.deleted,size=excluded.size,data=excluded.data,updated=excluded.updated';
/* parts: {key: json string}; del: [keys]; revs: {key: expected revision}. All-or-nothing. */
async function commitParts(env,sub,o){
 const keys=[...Object.keys(o.parts),...o.del];if(!keys.length)return{ok:true,revs:{}};
 const cur=await partMeta(env,sub,keys),conf=[];
 for(const k of keys){const r=cur.get(k)?cur.get(k).rev:0;if(r!==(+o.revs[k]||0))conf.push(k)}
 if(conf.length)return{conflict:conf};
 const exp={};for(const k of keys)exp[k]=+o.revs[k]||0;
 const st=[sq(env,'INSERT INTO ws_guard(ok) SELECT 1 WHERE EXISTS (SELECT 1 FROM json_each(?1) AS j WHERE COALESCE((SELECT rev FROM ws_parts WHERE sub=?2 AND k=j.key),0)<>j.value)',JSON.stringify(exp),sub)],nr={},at=iso();
 for(const[k,s]of Object.entries(o.parts)){const old=cur.get(k),rev=(old?old.rev:0)+1,big=s.length>INLINE_MAX?1:0;nr[k]=rev;
  if((old&&old.big)||big)st.push(sq(env,'DELETE FROM ws_chunks WHERE sub=? AND k=?',sub,k));
  if(big)for(let i=0,n=0;i<s.length;i+=CHUNK,n++)st.push(sq(env,'INSERT INTO ws_chunks(sub,k,rev,i,data) VALUES(?,?,?,?,?)',sub,k,rev,n,s.slice(i,i+CHUNK)));
  st.push(sq(env,UPSERT,sub,k,rev,big,0,s.length,big?null:s,at))}
 for(const k of o.del){const old=cur.get(k),rev=(old?old.rev:0)+1;nr[k]=rev;if(old&&old.big)st.push(sq(env,'DELETE FROM ws_chunks WHERE sub=? AND k=?',sub,k));st.push(sq(env,UPSERT,sub,k,rev,0,1,0,null,at))}
 st.push(sq(env,'UPDATE ws_meta SET updated=? WHERE sub=?',at,sub));
 try{await env.DB.batch(st)}catch(e){if(/CHECK constraint failed/i.test(String(e&&e.message)))return{conflict:keys};throw e}
 return{ok:true,revs:nr}}
async function mutatePart(env,sub,k,fn){
 for(let i=0;i<4;i++){const m=await readParts(env,sub,[k]),x=m.get(k);let v;if(x&&!x.deleted&&x.raw){try{v=JSON.parse(x.raw)}catch{}}
  const nv=fn(v),r=await commitParts(env,sub,{parts:{[k]:JSON.stringify(nv)},del:[],revs:{[k]:x?x.rev:0}});if(r.ok)return nv}
 throw new Err(409,'Workspace is busy, try again')}
const hiddenFor=(role,k)=>role!=='Admin'&&(k==='nk'||k==='mp'||k==='rk');
function redactUsers(raw,ph){try{return JSON.stringify(JSON.parse(raw).map(u=>u&&u.email===ph?u:{name:u.name,email:u.email,role:u.role,mail:u.mail}))}catch{return'[]'}}
/* ---- chat privacy: a thread is visible and writable only to the people in it ---- */
const THK=/^[A-Za-z0-9+_.|-]{1,100}$/,THPAV=/^data:image\/[a-z0-9.+-]+;base64,[A-Za-z0-9+\/=]{1,80000}$/i;
const thParty=(k,arr,me)=>{if(k.indexOf('|')>=0){const p=k.split('|');return p.length===2&&p.includes(me)}return!Array.isArray(arr)||!arr.length||arr.some(m=>m&&m.f===me)};
function thView(raw,me){try{const t=JSON.parse(raw);if(!t||typeof t!=='object'||Array.isArray(t))return'{}';const o={},keys=[],em=new Set([me]);
 for(const k of Object.keys(t)){if(k.slice(0,2)==='__'||!Array.isArray(t[k]))continue;if(k.indexOf('|')>=0?thParty(k,null,me):t[k].some(m=>m&&m.f===me)){o[k]=t[k];keys.push(k);k.split('|').forEach(e=>em.add(e))}}
 const rd={},cl={},pv={},dl={},ty={};
 for(const k of keys){const r=t.__rd&&t.__rd[k];if(r&&typeof r==='object')rd[k]=r;const c=t.__clr&&t.__clr[k];if(c&&typeof c==='object'&&c[me]!==undefined)cl[k]={[me]:c[me]};const d=t.__dl&&t.__dl[k];if(d&&typeof d==='object')dl[k]=d;const y=t.__ty&&t.__ty[k];if(y&&typeof y==='object'){const z={};for(const e of Object.keys(y))if(Date.now()-(+y[e]||0)<30000)z[e]=y[e];if(Object.keys(z).length)ty[k]=z}}
 em.forEach(e=>{if(t.__pav&&typeof t.__pav[e]==='string')pv[e]=t.__pav[e]});
 o.__rd=rd;o.__clr=cl;o.__pav=pv;o.__dl=dl;o.__ty=ty;return JSON.stringify(o)}catch{return'{}'}}
/* ---- chat extras: emoji reactions are merged per person, so reacting to someone else's message is allowed ---- */
const RXE=/^[\p{Extended_Pictographic}\u200d\ufe0f]{1,12}$/u;
const nrx=m=>{const o={...m};delete o.rx;return JSON.stringify(o)};
function mergeRx(srv,inc,me){const o={};
 if(isO(srv))for(const e of Object.keys(srv)){const a=Array.isArray(srv[e])?srv[e].filter(x=>typeof x==='string'&&x!==me):[];if(a.length)o[e]=a.slice(0,200)}
 if(isO(inc))for(const e of Object.keys(inc)){if(!RXE.test(e)||!Array.isArray(inc[e])||!inc[e].includes(me))continue;(o[e]=o[e]||[]).push(me)}
 const ks=Object.keys(o);if(!ks.length||ks.length>12)return ks.length?Object.fromEntries(ks.slice(0,12).map(k=>[k,o[k]])):undefined;return o}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function thMerge(env,sub,inc,me,role,note){const st=await getJson(env,sub,'th'),S0=st&&typeof st==='object'&&!Array.isArray(st)?st:{};
 if(!inc||typeof inc!=='object'||Array.isArray(inc)||Object.keys(inc).length>3000)return S0;
 const out={...S0},ok=[];out.__rd={...(S0.__rd||{})};out.__clr={...(S0.__clr||{})};out.__pav={...(S0.__pav||{})};out.__dl={...(S0.__dl||{})};out.__ty={...(S0.__ty||{})};
 for(const k of Object.keys(inc)){if(k.slice(0,2)==='__'||!THK.test(k)||!Array.isArray(inc[k]))continue;
  const sa=Array.isArray(S0[k])?S0[k]:[],ia=inc[k];if(!thParty(k,sa,me)||ia.length>20000)continue;
  if(!ia.every(m=>m&&typeof m==='object'&&!Array.isArray(m)&&typeof m.f==='string'))continue;
  if(JSON.stringify(sa.filter(m=>m&&m.f!==me).map(nrx))!==JSON.stringify(ia.filter(m=>m.f!==me).map(nrx)))continue;
  const sx=new Map();for(const m of sa)if(m&&m.rx)sx.set(m.f+'|'+m.at,m.rx);
   out[k]=ia.map(m=>{const x=m.f===me?{...m,r:role}:{...m};if(m.f===me&&m.rq!==undefined){const q=m.rq;if(isO(q)&&str(q.x,200))x.rq={x:str(q.x,200),n:str(q.n,60)};else delete x.rq}const rx=mergeRx(sx.get(m.f+'|'+m.at),m.rx,me);if(rx)x.rx=rx;else delete x.rx;return x});
   if(note&&k.indexOf('|')>=0&&ia.filter(m=>m.f===me).length>sa.filter(m=>m&&m.f===me).length)note.push(k.split('|').find(e=>e!==me)||'');ok.push(k)}
 for(const f of['__rd','__clr','__dl']){const src=inc[f];if(!src||typeof src!=='object')continue;
  for(const k of Object.keys(src)){if(!THK.test(k)||!Array.isArray(out[k])||!thParty(k,out[k],me))continue;const v=src[k]&&src[k][me];if(typeof v!=='number'||!isFinite(v))continue;
   out[f][k]={...(out[f][k]||{}),[me]:Math.max(0,Math.min(out[k].length,Math.floor(v)))}}}
 {const ty=inc.__ty,now=Date.now();if(isO(ty))for(const k of Object.keys(ty)){if(!THK.test(k)||!Array.isArray(out[k])||!thParty(k,out[k],me))continue;const v=ty[k]&&ty[k][me];if(typeof v!=='number'||!isFinite(v))continue;out.__ty[k]={...(out.__ty[k]||{}),[me]:Math.min(now,Math.max(now-30000,Math.floor(v)))}}
  for(const k of Object.keys(out.__ty)){const o=out.__ty[k];if(!isO(o)){delete out.__ty[k];continue}for(const e of Object.keys(o))if(now-(+o[e]||0)>30000)delete o[e];if(!Object.keys(o).length)delete out.__ty[k]}}
  const a=inc.__pav&&inc.__pav[me];if(typeof a==='string'&&THPAV.test(a))out.__pav[me]=a;
 for(const k of ok)for(const f of['__rd','__clr','__dl']){const r=out[f][k];if(r&&typeof r==='object')for(const e of Object.keys(r))if(+r[e]>out[k].length)r[e]=out[k].length}
 return out}
async function conflictResp(env,sub,keys,ph){const rows=await readParts(env,sub,keys),f=[],rv=[];for(const k of keys){const x=rows.get(k);f.push(JSON.stringify(k)+':'+(x&&!x.deleted&&x.raw?(k==='th'?thView(x.raw,ph):x.raw):'null'));rv.push(JSON.stringify(k)+':'+(x?x.rev:0))}return JR('{"error":"conflict","remote":{'+f.join(',')+'},"revs":{'+rv.join(',')+'}}',409)}
function checkUsers(us){
 if(!Array.isArray(us)||!us.length||us.length>500)return'users must be a non-empty list';
 const seen=new Set();let adm=0;
 for(const u of us){if(!isO(u))return'invalid user';const ph=String(u.email||'');if(!PHONERX.test(ph))return'invalid user phone';if(seen.has(ph))return'duplicate phone number';seen.add(ph);
  if(!MAILRX.test(String(u.mail||'')))return'invalid user e-mail';if(!ROLES.includes(u.role))return'invalid user role';
  if(!FPRX.test(String(u.p||''))||typeof u.salt!=='string'||u.salt.length<8)return'invalid user credentials';if(u.role==='Admin')adm++}
 return adm?null:'at least one Admin is required'}
const usersIdx=us=>JSON.stringify(us.map(u=>({e:u.email,m:String(u.mail).toLowerCase(),r:u.role})));
const idxStmts=(env,sub,us)=>[sq(env,'DELETE FROM ws_index WHERE sub=?',sub),sq(env,'INSERT OR REPLACE INTO ws_index(sub,phone,mail,role) SELECT ?1,json_extract(value,\'$.e\'),json_extract(value,\'$.m\'),json_extract(value,\'$.r\') FROM json_each(?2) WHERE 1',sub,usersIdx(us))];
async function findUser(env,sub,phone,mail){const us=await getJson(env,sub,'users');return Array.isArray(us)?us.find(x=>x&&x.email===phone&&String(x.mail||'').toLowerCase()===mail)||null:null}

/* role rules for writing sections (denied sections are dropped, never an error, so one stray key cannot block a whole sync) */
const ADMIN_ONLY=new Set(['users','rk','mp','inst','plan','nk','pub','cctv','cam','xc','board','gin','gth','cur','sn']);
const NO_DELETE=new Set(['users','inst','led','id','created','students','staff','rk','mp','th']);
const ROLE_ALLOW={Accountant:new Set(['led','th','xm']),Guardian:new Set(['th']),Supervisor:new Set(['th','xm','sub'])};
function canWrite(role,k){if(k==='id'||k==='created')return false;if(role==='Admin')return true;if(ROLE_ALLOW[role])return ROLE_ALLOW[role].has(k);if(role==='Teacher')return!ADMIN_ONLY.has(k)&&k!=='led'&&k!=='staff';return false}
async function confirmedPlan(env,sub){
 const r=await sq(env,"SELECT id,item,gateway,at FROM payments WHERE sub=? AND status='paid' AND item LIKE '%plan%' ORDER BY at DESC LIMIT 1",sub).first();if(!r)return null;
 const until=new Date(r.at).getTime()+(/annual/i.test(r.item)?366:31)*864e5;if(until<Date.now())return null;
 return{name:r.item,gateway:r.gateway,status:'paid',ref:r.id,until:new Date(until).toISOString()}}

/* student limit per plan, enforced on the server: Free (also after a plan ends) 100, Starter 500, Institution 1,500, Sovereign unlimited */
const planStuLimit=name=>/^starter/i.test(name||'')?500:/^institution/i.test(name||'')?1500:/^sovereign/i.test(name||'')?Infinity:100;
/* plan renewal reminders: a paid plan ends 31 days (monthly) or 366 days (annual) after its payment; for the last 7 days one e-mail a day goes to the institution administrator */
async function planRemind(env,only){
 const now=Date.now(),day=iso().slice(0,10);let sent=0;
 const rows=(await sq(env,"SELECT sub,item,MAX(at) AS at FROM payments WHERE status='paid' AND item LIKE '%plan%' AND sub IS NOT NULL"+(only?' AND sub=?':'')+' GROUP BY sub',...(only?[only]:[])).all()).results||[];
 for(const r of rows){
  const until=new Date(r.at).getTime()+(/annual/i.test(r.item)?366:31)*864e5,left=Math.ceil((until-now)/864e5);
  if(!(until>now&&left>=1&&left<=7))continue;
  const k='prem:'+r.sub+':'+day;try{if(await env.KV.get(k))continue}catch{}
  const us=await getJson(env,r.sub,'users'),a=Array.isArray(us)?us.find(u=>u&&u.role==='Admin'&&MAILRX.test(String(u.mail||''))):null;if(!a)continue;
  const pn=((/^(starter|institution|sovereign)/i.exec(String(r.item))||[])[0]||'Paid').replace(/^./,c=>c.toUpperCase()),end=new Date(until).toISOString().slice(0,10),url='https://'+r.sub+'.classphera.com';
  const en=`Your ClasSphera ${pn} plan ends in ${left} day${left>1?'s':''} (on ${end}). After that the workspace returns to the Free plan (up to 100 student records). Your data stays safe, but you cannot add students beyond the Free limit until you renew. Renew from Plans and pricing inside your workspace: ${url}`,
   bn=`আপনার ClasSphera ${pn} প্ল্যান আর ${left} দিন পরে (${end}) শেষ হবে। এরপর ওয়ার্কস্পেস ফ্রী প্ল্যানে (সর্বোচ্চ ১০০ শিক্ষার্থী) ফিরে যাবে। আপনার তথ্য নিরাপদ থাকবে, কিন্তু নবায়ন না করা পর্যন্ত ফ্রী সীমার বেশি শিক্ষার্থী যোগ করা যাবে না। ওয়ার্কস্পেসের Plans and pricing থেকে নবায়ন করুন: ${url}`;
  const ok=await sendMail(env,a.mail,`ClasSphera: your ${pn} plan ends in ${left} day${left>1?'s':''}`,`<p>${X(en)}</p><p>${X(bn)}</p>`,en+'\n\n'+bn);
  if(ok){sent++;try{await env.KV.put(k,'1',{expirationTtl:172800})}catch{}}}
 return sent}
/* ───────────── non-destructive data migrations + snapshots ───────────── */
const DM=[
{v:2,keys:['students'],up(P,ch){const a=P.students;if(!Array.isArray(a))return;for(const s of a){if(!isO(s))continue;let c=false;if(!isO(s.marks)){s.marks={};c=true}if(!Array.isArray(s.rem)){s.rem=[];c=true}if(!isO(s.cf)){s.cf={};c=true}if(typeof s.feeCyc!=='string'||!s.feeCyc){s.feeCyc='monthly';c=true}if(c)ch.add('students')}}},
{v:3,keys:['sn','students','staff','notes','chat','routine','hw','fbk','att','tatt','cur'],up(P,ch){
 for(const k of['notes','chat','routine','hw','fbk'])if(!Array.isArray(P[k])){P[k]=[];ch.add(k)}
 for(const k of['att','tatt'])if(!isO(P[k])){P[k]={};ch.add(k)}
 if(typeof P.cur!=='string'||!P.cur){P.cur='BDT';ch.add('cur')}
 let m=+P.sn||0;for(const a of[...(P.students||[]),...(P.staff||[])]){const r=/(\d+)$/.exec(String(a&&a.id||''));if(r&&+r[1]>m)m=+r[1]}
 if(typeof P.sn!=='number'||P.sn<m){P.sn=m;ch.add('sn')}}}];
async function snapshotTenant(env,sub,reason){
 if(!env.R2)return null;const rows=await readParts(env,sub,null),f=[];
 for(const[k,x]of rows)if(!x.deleted&&x.raw)f.push(JSON.stringify(k)+':{"rev":'+x.rev+',"data":'+x.raw+'}');
 const o='{"v":1,"sub":'+JSON.stringify(sub)+',"reason":'+JSON.stringify(reason)+',"at":'+JSON.stringify(iso())+',"parts":{'+f.join(',')+'}}',key=`snapshots/${sub}/${iso().replace(/[:.]/g,'-')}-${String(reason).replace(/[^a-z0-9-]/gi,'_').slice(0,30)}.json`;
 await env.R2.put(key,o,{httpMetadata:{contentType:'application/json'}});
 try{const l=await env.R2.list({prefix:`snapshots/${sub}/`,limit:1000}),ks=l.objects.map(x=>x.key).sort();for(const x of ks.slice(0,Math.max(0,ks.length-20)))await env.R2.delete(x)}catch{}
 return key}
async function ensureData(C,sub){
 const env=C.env;
 if(await memo('dm:'+sub,60000,async()=>{const r=await sq(env,'SELECT dschema FROM ws_meta WHERE sub=?',sub).first();return!r||r.dschema>=DATA_SCHEMA}))return;
 try{
  const r=await sq(env,'SELECT dschema FROM ws_meta WHERE sub=?',sub).first();if(!r)return;
  const steps=DM.filter(m=>m.v>r.dschema),need=[...new Set(steps.flatMap(m=>m.keys))];
  if(steps.length){
   await snapshotTenant(env,sub,'pre-migration-'+r.dschema+'-to-'+DATA_SCHEMA).catch(()=>{});
   const rows=await readParts(env,sub,need),P={},revs={},ch=new Set();
   for(const k of need){const x=rows.get(k);revs[k]=x?x.rev:0;if(x&&!x.deleted&&x.raw){try{P[k]=JSON.parse(x.raw)}catch{}}}
   for(const m of steps)m.up(P,ch);
   const parts={};for(const k of ch)parts[k]=JSON.stringify(P[k]);
   if(Object.keys(parts).length){const o=await commitParts(env,sub,{parts,del:[],revs});if(o.conflict){memoDel('dm:'+sub);return}}}
  await sq(env,'UPDATE ws_meta SET dschema=? WHERE sub=?',DATA_SCHEMA,sub).run();
 }catch(e){await sysAlert(env,'DATA_MIGRATION_FAILED',String(e&&e.message),{sub})}
 memoDel('dm:'+sub)}

/* ───────────── handlers: workspace ───────────── */
async function subCheck(C){
 const{b,env,ip}=C;if(hitMem('sdc:'+ip,60,600000))throw new Err(429,'rate limited');
 const sub=String(b.sub||'');if(sub!==sub.toLowerCase()||!SUBRX.test(sub)||RESERVED.includes(sub))return J({valid:false,available:false});
 if(!(await dbInst(env,sub)))return J({valid:true,available:true});
 const claimed=await sq(env,'SELECT 1 AS x FROM ws_meta WHERE sub=?',sub).first();
 return claimed?J({valid:true,available:false}):J({valid:true,available:true,legacy:true})}
async function idNew(C){
 const{env,ip}=C;if(hitMem('idn:'+ip,30,3600000))throw new Err(429,'rate limited');
 for(let i=0;i<8;i++){const id='M-'+[...crypto.getRandomValues(new Uint8Array(8))].map(x=>AL[x%32]).join('');let used=false;try{used=!!(await env.KV.get('id:'+id));if(!used)await env.KV.put('id:'+id,'1',{expirationTtl:604800})}catch{used=false}if(!used)return J({id})}
 throw new Err(503,'retry')}
/* Cloudflare Turnstile: human check on workspace sign-up. Secret key comes from the TURNSTILE_SECRET environment variable (never from code).
   If the variable is not set the check is skipped, so sign-up keeps working until it is configured. */
async function turnstileOk(env,token,ip){
 if(!env.TURNSTILE_SECRET)return true;
 const t=String(token||'');if(!t||t.length>2048)return false;
 try{const f=new FormData();f.append('secret',String(env.TURNSTILE_SECRET));f.append('response',t);if(ip&&ip!=='unknown')f.append('remoteip',ip);
  const r=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',body:f}),j=await r.json();return !!(j&&j.success)}
 catch{throw new Err(503,'Security check is temporarily unavailable. Please try again in a minute.')}}
async function wsCreate(C){
 const{b,env,ip}=C,sub=String(b.sub||'');
 if(!(await turnstileOk(env,b.ts,ip)))throw new Err(403,'Security check failed. Reload the page and try again.');
 secret(env); /* fail BEFORE anything is written: a missing MASTER_KEY used to leave a half-created, 'taken' workspace */
 if(sub!==sub.toLowerCase()||!SUBRX.test(sub)||RESERVED.includes(sub))throw new Err(400,'Invalid subdomain');
 if(hitMem('wc:'+ip,8,3600000)||await hit(env,'wc:'+ip,6,3600))throw new Err(429,'Too many workspaces created from this network. Try again later.');
 const w=b.ws;if(!isO(w))throw new Err(400,'Workspace data is missing');
 const keys=Object.keys(w);if(keys.length>120||keys.some(k=>!KEYRX.test(k)))throw new Err(400,'Workspace has invalid sections');
 if(!/^M-[A-Z0-9]{8}$/.test(String(w.id||'')))throw new Err(400,'Invalid workspace id');
 if(!isO(w.inst)||str(w.inst.name,120).length<2)throw new Err(400,'Institution name is required');
 const ue=checkUsers(w.users);if(ue)throw new Err(400,ue);
 if(b.migrate!==true&&w.users.length!==1)throw new Err(400,'A new workspace starts with one administrator');
 const adm=w.users.find(x=>x.role==='Admin'),fp=String(b.fp||'');
 if(isO(w.plan))w.plan={name:str(w.plan.name,60),gateway:str(w.plan.gateway,30),status:'pending'};else delete w.plan;
 const ex=await dbInst(env,sub);let made=false;
 if(ex){const claimed=await sq(env,'SELECT 1 AS x FROM ws_meta WHERE sub=?',sub).first();if(claimed||b.migrate!==true)throw new Err(409,'taken')}
 else{try{await sq(env,'INSERT INTO institutions(sub,name,itype,country,created_at) VALUES(?,?,?,?,?)',sub,str(w.inst.name,120),str(w.inst.type,40),str((w.inst.addr||{}).k,80),iso()).run();made=true}catch(e){if(/UNIQUE|PRIMARY KEY|constraint/i.test(String(e&&e.message)))throw new Err(409,'taken');throw e}}
 const parts={};for(const k of keys){const t=JSON.stringify(w[k]===undefined?null:w[k]);if(t.length>PART_MAX){if(made)await sq(env,'DELETE FROM institutions WHERE sub=?',sub).run().catch(()=>{});throw new Err(413,`Section ${k} is too large`)}parts[k]=t}
 await sq(env,'INSERT OR REPLACE INTO ws_meta(sub,dschema,created,updated) VALUES(?,?,?,?)',sub,DATA_SCHEMA,iso(),iso()).run();
 let r;try{r=await commitParts(env,sub,{parts,del:[],revs:{}})}catch(e){if(made)await sq(env,'DELETE FROM institutions WHERE sub=?',sub).run().catch(()=>{});await sq(env,'DELETE FROM ws_meta WHERE sub=?',sub).run().catch(()=>{});throw e}
 if(r.conflict){if(made)await sq(env,'DELETE FROM institutions WHERE sub=?',sub).run().catch(()=>{});throw new Err(409,'taken')}
 try{
  await env.DB.batch(idxStmts(env,sub,w.users));
  if(FPRX.test(fp))await trustDevice(env,sub,adm.email,fp,ip);
  await r2log(env,'WORKSPACE_CREATED',sub+' · '+str(w.inst.name,80),ip);
  const t=await issue(C,{sub,ph:adm.email,role:'Admin'},fp);
  /* founder alert: new institution registered. Runs only after the workspace is fully created, is never awaited, and any failure is swallowed, so it can never block or fail sign-up. Password and keys are never included. */
  try{const a=w.inst.addr||{},v=(x,n)=>X(str(x,n)||'-'),ad=[a.b,a.s,a.a,a.c,a.k].map(x=>str(x,80)).filter(Boolean).join(', ')||'-',pn=isO(w.plan)&&w.plan.name?`
💎 <b>Plan:</b> ${X(w.plan.name)}${w.plan.gateway?' ('+X(w.plan.gateway)+')':''}`:'';
   bg(C,tg(env,`🚀 <b>New Institution Registered${b.migrate===true?' (migrated)':''}</b>
✦━━━━━━━━━━━━━━━━✦
🏛️ <b>Institution:</b> ${v(w.inst.name,120)}
🎓 <b>Type:</b> ${v(w.inst.type,40)}
🧑‍🤝‍🧑 <b>Students &amp; Staff:</b> ${v(w.inst.size,20)}
🔗 <b>Subdomain:</b> ${X(sub)}.classphera.com
🗺️ <b>Address:</b> ${X(ad)}
🧭 <b>Country:</b> ${v(a.k,80)}
✦━━━━━━━━━━━━━━━━✦
🧑‍💼 <b>Admin Name:</b> ${v(adm.name,80)}
📲 <b>Phone:</b> ${v(adm.email,30)}
💌 <b>Email:</b> ${v(adm.mail,120)}${pn}
✦━━━━━━━━━━━━━━━━✦
🔑 <b>Workspace ID:</b> ${X(w.id)}
⏱️ <b>Registered:</b> ${new Date().toISOString().slice(0,16).replace('T',' ')} UTC`))}catch{}
  return sessResp(t,{revs:r.revs})
 }catch(e){await wsRollback(env,sub,made);throw e}}
/* undo a half-created workspace so the person can simply try again (never leaves a 'taken' ghost) */
async function wsRollback(env,sub,made){try{await env.DB.batch(['ws_chunks','ws_parts','ws_index','trusted','devices','ws_meta'].map(t=>sq(env,`DELETE FROM ${t} WHERE sub=?`,sub)).concat(made?[sq(env,'DELETE FROM institutions WHERE sub=?',sub)]:[]))}catch(e){console.error('[ClasSphera] rollback failed for '+sub+': '+(e&&e.message))}}
async function wsFind(C){
 const{b,env,ip}=C;if(hitMem('wf:'+ip,20,600000))throw new Err(429,'rate limited');
 const m=str(b.email,120).toLowerCase();if(!MAILRX.test(m))throw new Err(400,'invalid email');
 const r=await sq(env,"SELECT sub FROM ws_index WHERE mail=? ORDER BY CASE role WHEN 'Admin' THEN 0 ELSE 1 END LIMIT 1",m).first();
 if(!r)throw new Err(404,'not found');return J({sub:r.sub})}
async function wsSalt(C){
 const{b,env,ip}=C,sub=str(b.sub,40).toLowerCase(),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase();
 if(!SUBRX.test(sub))throw new Err(400,'Invalid request');if(hitMem('sl:'+ip,60,600000))throw new Err(429,'rate limited');
 const u=await findUser(env,sub,phone,mail),fake=(await hmac(env,'salt|'+sub+'|'+phone+'|'+mail)).slice(0,16).toUpperCase();
 return J({salt:u&&typeof u.salt==='string'?u.salt:fake})}
async function wsLogin(C){
 const{b,env,ip}=C,sub=str(b.sub,40).toLowerCase(),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase(),proof=String(b.proof||''),fp=String(b.fp||'');
 if(!SUBRX.test(sub)||!PHONERX.test(phone)||!MAILRX.test(mail)||!FPRX.test(proof)||!FPRX.test(fp))throw new Err(400,'Invalid request');
 if(hitMem('lg:'+ip,40,600000)||await hit(env,'lg:'+ip,25,600))throw new Err(429,'Too many attempts. Try again later.');
 const lk='lf:'+sub+':'+phone,fails=+(await env.KV.get(lk))||0;if(fails>=5)throw new Err(429,'Too many wrong attempts. Wait 15 minutes.');
 const u=await findUser(env,sub,phone,mail),ok=!!u&&FPRX.test(String(u.p||''))&&eq(proof,u.p);
 if(!ok){await env.KV.put(lk,String(fails+1),{expirationTtl:900});await fail(env,ip,'login '+sub);await dbAudit(env,'Login failed',sub,ip);throw new Err(401,'Credentials do not match')}
 await env.KV.delete(lk);
 let known=!!(await sq(env,'SELECT 1 AS x FROM trusted WHERE sub=? AND uid=? AND fp=?',sub,phone,fp).first());
 if(!known&&u.role==='Admin'&&await env.KV.get('skipotp:'+sub)){known=true;await env.KV.delete('skipotp:'+sub)}
 if(known){await trustDevice(env,sub,phone,fp,ip);return sessResp(await issue(C,{sub,ph:phone,role:u.role},fp),{})}
 const hasTotp=!!(await sq(env,'SELECT 1 AS x FROM totp WHERE sub=? AND uid=?',sub,phone).first()),hasPk=!!(await sq(env,'SELECT 1 AS x FROM passkeys WHERE sub=? AND uid=? LIMIT 1',sub,phone).first());
 await env.KV.put('pend:'+sub+':'+fp+':'+phone,JSON.stringify({ph:phone,mail,role:u.role}),{expirationTtl:300});
 let via=null,limited=false;
 if(await hit(env,'otps:'+sub+':'+phone,5,900)||await spend(env,'otpg',1,+env.OTP_DAILY_CAP||2000,86400))limited=true;
 else{const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0'),ok2='otp:'+sub+':'+fp+':'+phone;
  await env.KV.put(ok2,JSON.stringify({h:await hmac(env,`otp|${code}|${sub}|${fp}|${phone}`),n:0,mail,role:u.role}),{expirationTtl:300});
  via=await sendOtp(env,mail,phone,code);if(!via)await env.KV.delete(ok2)}
 await dbAudit(env,'Unknown device',`${sub} ${phone} via ${via||'none'}`,ip);
 if(!via&&!hasTotp&&!hasPk)throw new Err(limited?429:503,limited?'Too many codes requested. Wait a few minutes.':'We could not send the verification code. Ask the founder to enable e-mail delivery, or use an authenticator app.');
 return J({otp:true,known:false,via:via||'none',totp:hasTotp,passkey:hasPk})}
async function otpVerify(C){
 const{b,env,ip}=C,sub=wsn(b.sub),fp=String(b.fp||''),code=String(b.code||''),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase();
 if(!SUBRX.test(sub)||!FPRX.test(fp)||!/^\d{6}$/.test(code)||!PHONERX.test(phone))throw new Err(400,'invalid request');
 const k='otp:'+sub+':'+fp+':'+phone,rec=JSON.parse(await env.KV.get(k)||'null');
 if(!rec)throw new Err(410,'Code expired. Sign in again.');
 if(rec.n>=3){await env.KV.delete(k);throw new Err(429,'Too many wrong codes.')}
 if(rec.mail!==mail||!eq(await hmac(env,`otp|${code}|${sub}|${fp}|${phone}`),rec.h)){rec.n++;await env.KV.put(k,JSON.stringify(rec),{expirationTtl:300});await fail(env,ip,'otp '+sub);await dbAudit(env,'OTP mismatch',sub,ip);throw new Err(401,'Incorrect code.')}
 await env.KV.delete(k);await env.KV.delete('pend:'+sub+':'+fp+':'+phone);await trustDevice(env,sub,phone,fp,ip);
 await r2log(env,'OTP verified',`${sub} · device ${fp.slice(0,12)}`,ip);
 return sessResp(await issue(C,{sub,ph:phone,role:rec.role},fp),{ok:true})}
async function wsLoad(C){
 const{b,env}=C,s=await need(C);await ensureData(C,s.sub);
 if(s.role==='Admin'&&!hitMem('prl:'+s.sub,1,3600000))bg(C,planRemind(env,s.sub));
 const cr=isO(b.revs)?b.revs:null;
 const pack=(rows,gone)=>{const f=[],rv={};for(const[k,x]of rows){if(x.deleted||!x.raw||hiddenFor(s.role,k))continue;f.push(JSON.stringify(k)+':'+(k==='users'&&s.role!=='Admin'?redactUsers(x.raw,s.ph):k==='th'?thView(x.raw,s.ph):x.raw));rv[k]=x.rev}return{f,rv,gone}};
 if(!cr){const rows=await readParts(env,s.sub,null);if(!rows.size)throw new Err(404,'workspace not found');const p=pack(rows,[]);return JR('{"ws":{'+p.f.join(',')+'},"revs":'+JSON.stringify(p.rv)+'}')}
 const wt=Math.min(20000,Math.max(0,+b.wait||0)),w0=Date.now();let live=[],gone=[];
 for(;;){const meta=(await sq(env,'SELECT k,rev,deleted FROM ws_parts WHERE sub=?',s.sub).all()).results||[];live=[];gone=[];for(const r of meta){if(hiddenFor(s.role,r.k))continue;const c=cr[r.k];if(r.deleted){if(c!==undefined&&+c!==r.rev)gone.push(r.k)}else if(+c!==r.rev)live.push(r.k)}
  if(live.length||gone.length||!wt||Date.now()-w0>=wt)break;await sleep(2000)}
 if(!live.length&&!gone.length)return JR('{"parts":{},"revs":{},"gone":[]}');
 const p=pack(live.length?await readParts(env,s.sub,live):new Map(),gone);
 return JR('{"parts":{'+p.f.join(',')+'},"revs":'+JSON.stringify(p.rv)+',"gone":'+JSON.stringify(gone)+'}')}
async function wsSave(C){
 const{b,env,ip}=C,s=await need(C);
 if(C.clientMajor&&C.clientMajor<MIN_CLIENT_MAJOR)throw new Err(426,'Please refresh the app to continue.',{code:'client_outdated'});
 if(b.parts!==undefined&&!isO(b.parts))throw new Err(400,'parts must be an object');
 const parts=isO(b.parts)?b.parts:{},del=Array.isArray(b.del)?b.del.map(String):[],revs=isO(b.revs)?b.revs:{};
 const all=[...Object.keys(parts),...del];if(!all.length)return J({ok:true,revs:{}});
 if(all.length>120||del.length>60)throw new Err(400,'too many sections');
 for(const k of all)if(!KEYRX.test(k)||k==='__proto__')throw new Err(400,'invalid section name');
 const P={},D=[],denied=[];
 for(const k of Object.keys(parts)){if(canWrite(s.role,k))P[k]=parts[k];else denied.push(k)}
 for(const k of del){if(canWrite(s.role,k)&&!NO_DELETE.has(k)&&!(k in parts))D.push(k);else denied.push(k)}
 if(!Object.keys(P).length&&!D.length)return J({ok:true,revs:{},denied});
 if(P.users!==undefined){const e=checkUsers(P.users);if(e)throw new Err(400,e)}
 if(P.inst!==undefined&&(!isO(P.inst)||str(P.inst.name,120).length<2))throw new Err(400,'Institution name is required');
 const pn=[];if(P.th!==undefined)P.th=await thMerge(env,s.sub,P.th,s.ph,s.role,pn);
 if(P.plan!==undefined){const cp=await confirmedPlan(env,s.sub);P.plan=cp||(isO(P.plan)?{name:str(P.plan.name,60),gateway:str(P.plan.gateway,30),status:'pending'}:null)}
 if(Array.isArray(P.students)&&P.students.length>100){const cp=await confirmedPlan(env,s.sub),lim=planStuLimit(cp&&cp.name); /* adding students past the plan limit is refused; existing data may still be saved, edited or reduced */
  if(P.students.length>lim){const old=await getJson(env,s.sub,'students');if(P.students.length>(Array.isArray(old)?old.length:0))throw new Err(403,'Plan limit reached ('+lim+' students). Upgrade your plan to add more students.',{code:'plan_limit',limit:lim})}}
 const S2={};for(const[k,v]of Object.entries(P)){const t=JSON.stringify(v===undefined?null:v);if(t.length>PART_MAX)throw new Err(413,`Section ${k} is too large`);S2[k]=t}
 const oldUsers=P.users!==undefined?await getJson(env,s.sub,'users'):null;
 const r=await commitParts(env,s.sub,{parts:S2,del:D,revs});
 if(r.conflict){const cur=await partMeta(env,s.sub,[...Object.keys(S2),...D]),cf=[...Object.keys(S2),...D].filter(k=>(cur.get(k)?cur.get(k).rev:0)!==(+revs[k]||0));return conflictResp(env,s.sub,cf.length?cf:r.conflict,s.ph)}
 if(pn.length)bg(C,Promise.all([...new Set(pn)].filter(Boolean).map(p=>pushTo(env,s.sub,'s',p))));
 if(P.users!==undefined){
  await env.DB.batch(idxStmts(env,s.sub,P.users));
  if(Array.isArray(oldUsers)){const nm=new Map(P.users.map(u=>[u.email,u])),t=String(nowS());
   for(const o of oldUsers){const n=nm.get(o&&o.email);if(!n||n.p!==o.p||n.role!==o.role){await env.KV.put('sxu:'+s.sub+':'+o.email,t,{expirationTtl:90000});memoDel('rv:'+s.sub+':'+o.email)}}}}
 if(P.inst!==undefined)await sq(env,'UPDATE institutions SET name=?,itype=?,country=? WHERE sub=?',str(P.inst.name,120),str(P.inst.type,40),str((P.inst.addr||{}).k,80),s.sub).run().catch(()=>{});
 if(env.R2)bg(C,(async()=>{const day=iso().slice(0,10),x=await sq(env,'UPDATE ws_meta SET snap_at=?1 WHERE sub=?2 AND (snap_at IS NULL OR snap_at<>?1)',day,s.sub).run();if(x.meta&&x.meta.changes)await snapshotTenant(env,s.sub,'daily')})());
 return J(denied.length?{ok:true,revs:r.revs,denied}:{ok:true,revs:r.revs})}
async function sessCheck(C){const s=await need(C);return J({ok:true,sub:s.sub,exp:s.exp})}
async function sessLogout(C){return J({ok:true},200,{'set-cookie':'cs_s=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict'})}
async function devList(C){const s=await need(C,['Admin']);const r=await sq(C.env,'SELECT fp,first_seen,last_seen,ip,trusted FROM devices WHERE sub = ? ORDER BY last_seen DESC LIMIT 50',s.sub).all();return J({devices:(r.results||[]).map(d=>({...d,fp:d.fp.slice(0,16)}))})}
async function devRevoke(C){
 const s=await need(C,['Admin']),pre=String(C.b.fp||'').slice(0,16);if(!/^[0-9a-f]{16}$/.test(pre))throw new Err(400,'invalid device');
 const d=((await sq(C.env,'SELECT fp FROM devices WHERE sub = ?',s.sub).all()).results||[]).find(x=>x.fp.startsWith(pre));if(!d)throw new Err(404,'not found');
 await C.env.DB.batch([sq(C.env,'DELETE FROM devices WHERE sub = ? AND fp = ?',s.sub,d.fp),sq(C.env,'DELETE FROM trusted WHERE sub = ? AND fp = ?',s.sub,d.fp)]);
 await dbAudit(C.env,'Device revoked',`${s.sub} ${pre}`,C.ip);return J({ok:true})}
async function masterOverride(C){
 const{b,env,ip}=C,sub=wsn(b.sub);
 if(await hit(env,'mo:'+ip,3,3600)){await alert(env,ip,'Master key flood',`workspace ${sub}`);throw new Err(429,'locked')}
 if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await fail(env,ip,'master key '+sub);await alert(env,ip,'Master key attempt',`workspace ${sub}`);throw new Err(403,'rejected')}
 if(!SUBRX.test(sub))throw new Err(400,'invalid subdomain');
 const temp=rnd(6),salt=rnd(8).toUpperCase(),p=await sha('cs:'+salt+temp);let done=false,info=null;
 await mutatePart(env,sub,'users',us=>{if(!Array.isArray(us))throw new Err(404,'workspace not found');const a=us.find(u=>u.role==='Admin');if(!a)throw new Err(404,'no administrator found');a.salt=salt;a.p=p;done=true;info={phone:a.phone||a.email,mail:a.mail,name:a.name||''};return us});
 if(!done)throw new Err(404,'workspace not found');
 await env.KV.put('sxr:'+sub,String(nowS()),{expirationTtl:90000});memoDel('rv:'+sub+':');
 await env.KV.put('skipotp:'+sub,'1',{expirationTtl:1800});
 const ins=await dbInst(env,sub).catch(()=>null),inst=(ins&&ins.name)||'',domain=sub+'.classphera.com';
 await alert(env,ip,'Master override used',`workspace ${sub}${inst?' · '+inst:''}`);
 return J({temp,phone:info.phone,mail:info.mail,sub,inst,iname:inst,itype:(ins&&ins.itype)||'',country:(ins&&ins.country)||'',domain,admin:{name:info.name,phone:info.phone,mail:info.mail}})}

/* ───────────── Ledger Unlock Key: reset a lost password with the recovery code ─────────────
   The recovery code itself never reaches the server. The browser derives a 64-hex proof (rc) from it.
   rv (the proof saved inside the admin-only "rk" section) is set once by recEnroll, or at workspace creation. */
const sealOk=w=>isO(w)&&typeof w.iv==='string'&&typeof w.ct==='string'&&w.iv.length<=64&&w.ct.length<=4000;
async function recEnroll(C){
 const{b,env,ip}=C,s=await need(C,['Admin']),rv=String(b.rv||'');
 if(!FPRX.test(rv))throw new Err(400,'Invalid recovery proof');
 if(hitMem('re:'+ip,20,600000))throw new Err(429,'rate limited');
 await mutatePart(env,s.sub,'rk',rk=>{if(!isO(rk)||!isO(rk.wk)||typeof rk.salt!=='string')throw new Err(404,'Recovery key not found');return{...rk,rv}});
 await dbAudit(env,'Recovery reset enabled',s.sub,ip);return J({ok:true})}
async function wsRecover(C){
 const{b,env,ip}=C,sub=str(b.sub,40).toLowerCase(),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase(),rc=String(b.rc||''),p=String(b.p||''),salt=String(b.salt||''),fp=String(b.fp||''),wk=b.wk;
 if(!SUBRX.test(sub)||!PHONERX.test(phone)||!MAILRX.test(mail)||!FPRX.test(rc)||!FPRX.test(p)||!FPRX.test(fp)||!/^[A-Za-z0-9]{8,128}$/.test(salt))throw new Err(400,'Invalid request');
 if(wk!==undefined&&wk!==null&&!sealOk(wk))throw new Err(400,'Invalid request');
 if(hitMem('rc:'+ip,15,900000)||await hit(env,'rc:'+ip,10,3600))throw new Err(429,'Too many attempts. Try again later.');
 const lk='rcf:'+sub+':'+phone,fails=+(await env.KV.get(lk))||0;if(fails>=5)throw new Err(429,'Too many wrong attempts. Wait 15 minutes.');
 const u=await findUser(env,sub,phone,mail),rk=u&&u.role==='Admin'?await getJson(env,sub,'rk'):null,rv=isO(rk)?String(rk.rv||''):'';
 /* one answer for every failure (wrong code, unknown account, or reset not enabled yet) so nothing about the account leaks */
 if(!(FPRX.test(rv)&&eq(rc,rv))){await env.KV.put(lk,String(fails+1),{expirationTtl:900});await fail(env,ip,'recovery '+sub);await dbAudit(env,'Recovery code failed',sub,ip);throw new Err(401,'Ledger Unlock Key does not match, or key reset is not enabled for this account. Ask the founder for a master key reset.')}
 await env.KV.delete(lk);
 let done=false;
 await mutatePart(env,sub,'users',us=>{if(!Array.isArray(us))throw new Err(404,'workspace not found');const a=us.find(x=>x&&x.role==='Admin'&&x.email===phone&&String(x.mail||'').toLowerCase()===mail);if(!a)throw new Err(404,'administrator not found');a.salt=salt;a.p=p;if(wk)a.wk=wk;else delete a.wk;done=true;return us});
 if(!done)throw new Err(404,'workspace not found');
 await env.KV.put('sxu:'+sub+':'+phone,String(nowS()),{expirationTtl:90000});memoDel('rv:'+sub+':'+phone); /* every older session of this administrator ends; the new one below is issued after this second */
 await trustDevice(env,sub,phone,fp,ip);
 await alert(env,ip,'Password reset with recovery code',`workspace ${sub}`);
 return sessResp(await issue(C,{sub,ph:phone,role:'Admin'},fp),{ok:true})}

/* ───────────── passkeys (WebAuthn) and authenticator app (TOTP) ───────────── */
function derToRaw(sig,len){
 if(sig[0]!==0x30)throw new Error('der');let i=2;if(sig[1]&0x80)i=2+(sig[1]&0x7f);
 if(sig[i]!==0x02)throw new Error('der');const rl=sig[i+1],r=sig.slice(i+2,i+2+rl);i=i+2+rl;
 if(sig[i]!==0x02)throw new Error('der');const sl=sig[i+1],s=sig.slice(i+2,i+2+sl);
 const fix=x=>{while(x.length>len&&x[0]===0)x=x.slice(1);if(x.length>len)throw new Error('der');const o=new Uint8Array(len);o.set(x,len-x.length);return o};
 const out=new Uint8Array(len*2);out.set(fix(r),0);out.set(fix(s),len);return out}
async function verifyAssertion(pk,ad,cdj,sig){
 const h=new Uint8Array(await crypto.subtle.digest('SHA-256',cdj)),data=new Uint8Array(ad.length+h.length);data.set(ad,0);data.set(h,ad.length);const spki=unb64u(pk.pub);
 if(pk.alg===-7){const key=await crypto.subtle.importKey('spki',spki,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,derToRaw(sig,32),data)}
 if(pk.alg===-257){const key=await crypto.subtle.importKey('spki',spki,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);return crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,data)}
 return false}
async function pkChallenge(C){
 const{b,env,ip}=C,sub=str(b.sub,40).toLowerCase(),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase(),fp=String(b.fp||'');
 if(!SUBRX.test(sub)||!FPRX.test(fp))throw new Err(400,'Invalid request');if(hitMem('pkc:'+ip,30,600000))throw new Err(429,'rate limited');
 const ch=b64u(crypto.getRandomValues(new Uint8Array(32)));await env.KV.put('pkc:'+sub+':'+fp+':'+phone,ch,{expirationTtl:120});
 let ids=[];if(await findUser(env,sub,phone,mail))ids=((await sq(env,'SELECT id FROM passkeys WHERE sub=? AND uid=? LIMIT 10',sub,phone).all()).results||[]).map(r=>r.id);
 return J({challenge:ch,ids})}
async function pkRegister(C){
 const{b,env}=C,s=await need(C),id=String(b.id||''),pub=String(b.publicKey||''),alg=+b.alg;
 if(!/^[A-Za-z0-9_-]{16,512}$/.test(id)||!/^[A-Za-z0-9_-]{40,2048}$/.test(pub)||![-7,-257].includes(alg))throw new Err(400,'Unsupported passkey');
 const n=await sq(env,'SELECT COUNT(*) AS n FROM passkeys WHERE sub=? AND uid=?',s.sub,s.ph).first();if(n&&n.n>=10)throw new Err(400,'Too many passkeys registered');
 const ex=await sq(env,'SELECT sub,uid FROM passkeys WHERE id=?',id).first();if(ex&&(ex.sub!==s.sub||ex.uid!==s.ph))throw new Err(409,'Passkey already registered');
 await sq(env,'INSERT INTO passkeys(id,sub,uid,pub,alg,counter,transports,created) VALUES(?,?,?,?,?,0,?,?) ON CONFLICT(id) DO UPDATE SET pub=excluded.pub,alg=excluded.alg',id,s.sub,s.ph,pub,alg,JSON.stringify(Array.isArray(b.transports)?b.transports.slice(0,6).map(x=>str(x,20)):[]),iso()).run();
 await dbAudit(env,'Passkey registered',s.sub+' '+s.ph,C.ip);return J({ok:true})}
async function pkVerify(C){
 const{b,env,ip,req}=C,sub=str(b.sub,40).toLowerCase(),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase(),fp=String(b.fp||''),id=String(b.id||'');
 if(!SUBRX.test(sub)||!FPRX.test(fp)||!/^[A-Za-z0-9_-]{16,512}$/.test(id))throw new Err(400,'Invalid request');
 if(hitMem('pkv:'+ip,30,600000))throw new Err(429,'rate limited');
 const ck='pkc:'+sub+':'+fp+':'+phone,ch=await env.KV.get(ck);if(!ch)throw new Err(410,'Challenge expired. Try again.');await env.KV.delete(ck);
 const bad=async()=>{await fail(env,ip,'passkey '+sub);throw new Err(401,'The biometric check was not accepted.')};
 try{
  const u=await findUser(env,sub,phone,mail),pk=await sq(env,'SELECT id,sub,uid,pub,alg,counter FROM passkeys WHERE id=?',id).first();
  if(!u||!pk||pk.sub!==sub||pk.uid!==phone)return await bad();
  const cdj=unb64u(b.clientDataJSON),ad=unb64u(b.authenticatorData),sig=unb64u(b.signature),cd=JSON.parse(dec.decode(cdj)),origin=req.headers.get('origin')||'';
  if(cd.type!=='webauthn.get'||cd.challenge!==ch||cd.origin!==origin)return await bad();
  let rp='';try{rp=new URL(origin).hostname}catch{return await bad()}
  if(rp!==C.host||ad.length<37)return await bad();
  const rph=hex(await crypto.subtle.digest('SHA-256',u8(rp)));if(!eq(hex(ad.slice(0,32)),rph))return await bad();
  if(!(ad[32]&1)||!(ad[32]&4))return await bad();
  const cnt=new DataView(ad.buffer,ad.byteOffset+33,4).getUint32(0);if(pk.counter>0&&cnt<=pk.counter)return await bad();
  if(!(await verifyAssertion(pk,ad,cdj,sig)))return await bad();
  await sq(env,'UPDATE passkeys SET counter=? WHERE id=?',cnt,id).run();await trustDevice(env,sub,phone,fp,ip);
  await r2log(env,'Passkey sign-in',`${sub} ${phone}`,ip);return sessResp(await issue(C,{sub,ph:phone,role:u.role},fp),{ok:true})
 }catch(e){if(e instanceof Err)throw e;return await bad()}}
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function unb32(s){s=String(s).toUpperCase().replace(/[^A-Z2-7]/g,'');let bits=0,v=0;const o=[];for(const c of s){v=(v<<5)|B32.indexOf(c);bits+=5;if(bits>=8){o.push((v>>>(bits-8))&255);bits-=8}v&=(1<<bits)-1}return new Uint8Array(o)}
async function totpStep(secretB32,code,last){
 const key=await crypto.subtle.importKey('raw',unb32(secretB32),{name:'HMAC',hash:'SHA-1'},false,['sign']),t=Math.floor(Date.now()/30000);
 for(const d of[-1,0,1]){const st=t+d;if(st<=last)continue;let c=st;const m=new Uint8Array(8);for(let i=7;i>=0;i--){m[i]=c&255;c=Math.floor(c/256)}
  const h=new Uint8Array(await crypto.subtle.sign('HMAC',key,m)),o=h[19]&15,n=((h[o]&127)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|h[o+3];
  if(eq(String(n%1000000).padStart(6,'0'),code))return st}
 return 0}
async function totpEnable(C){
 const{b,env}=C,s=await need(C),sec=String(b.secret||'').toUpperCase().replace(/\s/g,''),code=String(b.code||'');
 if(!/^[A-Z2-7]{16,64}$/.test(sec)||!/^\d{6}$/.test(code))throw new Err(400,'Invalid code');
 const st=await totpStep(sec,code,0);if(!st)throw new Err(401,'That code does not match. Check the key and your phone’s clock.');
 await sq(env,'INSERT INTO totp(sub,uid,secret,last_step,created) VALUES(?,?,?,?,?) ON CONFLICT(sub,uid) DO UPDATE SET secret=excluded.secret,last_step=excluded.last_step',s.sub,s.ph,await seal(env,sec),st,iso()).run();
 await dbAudit(env,'TOTP enabled',s.sub+' '+s.ph,C.ip);return J({ok:true})}
async function totpVerify(C){
 const{b,env,ip}=C,sub=str(b.sub,40).toLowerCase(),phone=nph(b.phone),mail=str(b.mail,120).toLowerCase(),fp=String(b.fp||''),code=String(b.code||'');
 if(!SUBRX.test(sub)||!FPRX.test(fp)||!/^\d{6}$/.test(code)||!PHONERX.test(phone))throw new Err(400,'invalid request');
 if(hitMem('tv:'+ip,30,600000)||await hit(env,'tvu:'+sub+':'+phone,8,300))throw new Err(429,'Too many wrong codes.');
 const pend=JSON.parse(await env.KV.get('pend:'+sub+':'+fp+':'+phone)||'null');
 if(!pend||pend.mail!==mail)throw new Err(401,'Sign in with your password first.');
 const row=await sq(env,'SELECT secret,last_step FROM totp WHERE sub=? AND uid=?',sub,phone).first();
 if(!row){await fail(env,ip,'totp none '+sub);throw new Err(401,'Authenticator app is not set up for this account.')}
 let st=0;try{st=await totpStep(await unseal(env,row.secret),code,row.last_step)}catch{}
 if(!st){await fail(env,ip,'totp '+sub);await dbAudit(env,'TOTP mismatch',sub,ip);throw new Err(401,'Incorrect code.')}
 await sq(env,'UPDATE totp SET last_step=? WHERE sub=? AND uid=?',st,sub,phone).run();await env.KV.delete('pend:'+sub+':'+fp+':'+phone);await trustDevice(env,sub,phone,fp,ip);
 return sessResp(await issue(C,{sub,ph:phone,role:pend.role},fp),{ok:true})}

/* ───────────── preferences, enterprise state, client queues ───────────── */
const PREF_RX=/^(cs_lang|cs_theme|cs_ch|cs_ent_[a-z0-9_]{1,30}|cs_cf_[a-z0-9-]{3,30})$/,PREF_USER=/^(cs_lang|cs_theme|cs_ch)$/;
async function mergePrefs(env,sub,uid,inc){
 for(let i=0;i<4;i++){
  const r=await sq(env,'SELECT data,rev FROM prefs WHERE sub=? AND uid=?',sub,uid).first();let cur={};if(r){try{cur=JSON.parse(r.data)}catch{}}
  let ch=false;for(const[k,e]of Object.entries(inc)){const o=cur[k];if(!o||e.t>o.t){cur[k]=e;ch=true}}
  if(!ch)return cur;
  const ks=Object.keys(cur);if(ks.length>60)for(const k of ks.sort((a,b)=>cur[a].t-cur[b].t).slice(0,ks.length-60))delete cur[k];
  const txt=JSON.stringify(cur);if(txt.length>600000)throw new Err(413,'preferences too large');
  if(!r){const x=await sq(env,'INSERT OR IGNORE INTO prefs(sub,uid,data,rev,updated) VALUES(?,?,?,1,?)',sub,uid,txt,iso()).run();if(x.meta&&x.meta.changes)return cur;continue}
  const x=await sq(env,'UPDATE prefs SET data=?,rev=rev+1,updated=? WHERE sub=? AND uid=? AND rev=?',txt,iso(),sub,uid,r.rev).run();if(x.meta&&x.meta.changes)return cur}
 return{}}
async function prefs(C){
 const{b,env}=C,s=await need(C),data=isO(b.data)?b.data:{},instOk=['Admin','Supervisor','Teacher'].includes(s.role),inc={user:{},inst:{}},denied=[];
 if(b.action!=='get'){let n=0;for(const[k,e]of Object.entries(data)){if(++n>60)break;
  if(!PREF_RX.test(k)||(/^cs_cf_/.test(k)&&k!=='cs_cf_'+s.sub)||!isO(e)||typeof e.v!=='string'||e.v.length>65536||!(+e.t>=0)){denied.push(k);continue}
  const sc=PREF_USER.test(k)?'user':'inst';if(sc==='inst'&&!instOk){denied.push(k);continue}inc[sc][k]={v:e.v,t:Math.min(+e.t,Date.now()+60000)}}}
 const out={};for(const sc of['user','inst'])out[sc]=await mergePrefs(env,s.sub,sc==='user'?s.ph:'',inc[sc]);
 return J({ok:true,...out,denied})}
const envelope=C=>isO(C.b.data)?C.b.data:C.b;
async function schemaFields(C){
 const s=await auth(C),d=envelope(C),t=+C.b.queuedAt||Date.now();
 if(!s){if(d.tenant==='demo'||C.b.tenant==='demo')return J({ok:true,dropped:true},202);throw new Err(401,'invalid session')}
 if(!['Admin','Supervisor','Teacher'].includes(s.role))throw new Err(403,'Your role cannot change fields');
 const f=Array.isArray(d.fields)?d.fields.slice(0,200).map(x=>({n:str(x&&x.n,40),t:str(x&&x.t,20),m:str(x&&x.m,30),o:str(x&&x.o,120)})).filter(x=>x.n):null;
 if(!f)throw new Err(400,'fields must be a list');
 await mergePrefs(C.env,s.sub,'',{['cs_cf_'+s.sub]:{v:JSON.stringify(f),t:Math.min(t,Date.now()+60000)}});return J({ok:true})}
async function clientEvent(C){
 const s=await auth(C),d=envelope(C);
 if(!s){if(d.tenant==='demo'||C.b.tenant==='demo')return J({ok:true,dropped:true},202);throw new Err(401,'invalid session')}
 if(hitMem('ev:'+s.sub,600,60000))throw new Err(429,'rate limited');
 const kind=C.path==='/api/audit'?'audit':'sync',txt=JSON.stringify(d).slice(0,4000),env=C.env;
 await sq(env,'INSERT INTO events(sub,kind,data,at) VALUES(?,?,?,?)',s.sub,kind,txt,iso()).run();
 if(Math.random()<.02)await sq(env,'DELETE FROM events WHERE sub=?1 AND kind=?2 AND id<=(SELECT id FROM events WHERE sub=?1 AND kind=?2 ORDER BY id DESC LIMIT 1 OFFSET 5000)',s.sub,kind).run().catch(()=>{});
 return J({ok:true})}
/* in-house guardian alerts: no SMS / WhatsApp gateway. Each alert is written straight into the D1 notifications table
   and the guardian sees it live inside the website through /api/g/data. Recipient = sid, or the guardian phone matched to portal.ph. */
async function inApp(env,sub,items,C){
 const rows=items.map(a=>({sid:/^[A-Za-z0-9-]{1,24}$/.test(String(a.sid||''))?String(a.sid).toUpperCase():'',ph:String(a.to||'').replace(/\D/g,'').slice(-10),ev:str(a.ev,60),x:str(a.msg,200)})).filter(a=>a.x&&(a.sid||a.ph.length>=7));
 if(!rows.length)return{sent:0,failed:items.length};
 const phs=[...new Set(rows.filter(a=>!a.sid).map(a=>a.ph))],by=new Map();
 if(phs.length){const r=(await sq(env,'SELECT sid,ph FROM portal WHERE sub=?1 AND ph IN (SELECT value FROM json_each(?2))',sub,JSON.stringify(phs)).all()).results||[];for(const p of r){if(!by.has(p.ph))by.set(p.ph,[]);by.get(p.ph).push(p.sid)}}
 const at=Date.now(),st=[],tg=[];let sent=0;
 for(const a of rows){const sids=a.sid?[a.sid]:(by.get(a.ph)||[]);if(!sids.length)continue;sent++;
  for(const sid of sids){tg.push({sid,ev:a.ev,x:a.x});st.push(sq(env,'INSERT INTO notifications(id,workspace_sub,recipient_id,title,body,type,is_read,created_at) SELECT ?1,?2,?3,?4,?5,?6,0,?7 WHERE NOT EXISTS(SELECT 1 FROM notifications WHERE workspace_sub=?2 AND recipient_id=?3 AND body=?5 AND created_at>?8)',rnd(8),sub,sid,a.ev||'Alert',a.x,'guardian_alert',new Date(at).toISOString(),new Date(at-216e5).toISOString()))}} /* the same alert is not repeated within 6 hours */
 const fresh=[];for(let i=0;i<st.length;i+=40){const res=await env.DB.batch(st.slice(i,i+40));res.forEach((r,k)=>{if(r&&r.meta&&r.meta.changes>0&&tg[i+k])fresh.push(tg[i+k])})}
 if(fresh.length&&C)bg(C,pushAlerts(env,C.u.origin,sub,fresh)); /* every new alert (attendance, fee, result) is also pushed with its full text */
 if(st.length&&Math.random()<.05)await sq(env,'DELETE FROM notifications WHERE workspace_sub=?1 AND id IN (SELECT id FROM notifications WHERE workspace_sub=?1 ORDER BY created_at DESC LIMIT -1 OFFSET 5000)',sub).run().catch(()=>{});
 return{sent,failed:items.length-sent}}
async function notifyCh(C){
 const s=await auth(C),d=envelope(C),env=C.env,ch=C.path.split('/').pop();
 if(!s){if(d.tenant==='demo'||C.b.tenant==='demo')return J({ok:true,dropped:true},202);throw new Err(401,'invalid session')}
 if(!['Admin','Teacher'].includes(s.role))throw new Err(403,'Your role cannot send alerts');
 const ev=str(d.event,60),msg=str(d.msg,160).replace(/https?:\/\/\S+/gi,''),to=nph(d.to),sid=str(d.sid,24).toUpperCase(),hasSid=/^[A-Z0-9-]{1,24}$/.test(sid);
 if(!ev||!msg)throw new Err(400,'event and message are required');
 let status='local';
 if(ch==='sms'||ch==='whatsapp'||PHONERX.test(to)||hasSid){
  if(!hasSid&&!PHONERX.test(to))throw new Err(400,'invalid phone');
  if(hitMem('ntf:'+s.sub,2000,86400000))throw new Err(429,'daily limit');
  const r=await inApp(env,s.sub,[{to,sid:hasSid?sid:'',ev,msg}],C);status=r.sent?'in_app':'no_guardian_portal'}
 await sq(env,'INSERT INTO events(sub,kind,data,at) VALUES(?,?,?,?)',s.sub,'out:'+ch,JSON.stringify({to,event:ev,msg,status}),iso()).run();
 return J({ok:true,status})}
async function notifyLegacy(C){ /* {sub,id,key,messages:[{to,name,status,inst}]} → {sent,failed}; the server writes the alert text itself and saves it in-app */
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');
 await tenantAuth(C,sub,['Admin','Teacher']);
 if(hitMem('sms:'+C.ip,12,3600000))throw new Err(429,'rate limited');
 const nm=v=>String(v||'').replace(/[^\p{L}\p{M}\p{N} ,'’()&-]/gu,'').replace(/\s+/g,' ').trim(),m=[];
 for(const a of(Array.isArray(b.messages)?b.messages:[]).slice(0,100)){const to=nph(a&&a.to),st=String(a&&a.status||'').toLowerCase(),name=nm(a&&a.name).slice(0,60),inst=nm(a&&a.inst).slice(0,80);
  if(PHONERX.test(to)&&(st==='present'||st==='absent'||st==='late')&&name&&inst)m.push({to,ev:'attendance',msg:`${name} was ${st} today at ${inst}.`})}
 if(!m.length)throw new Err(400,'no valid recipients');
 const r=await inApp(env,sub,m,C);
 return J({sent:r.sent,failed:r.failed},r.sent?200:502)}
/* institution-level authority: a valid session of an allowed role, or the workspace key that the admin saved in the workspace itself */
async function tenantAuth(C,sub,roles){
 const s=await auth(C);if(s&&s.sub===sub&&(!roles||roles.includes(s.role)))return{via:'session',s};
 const key=String(C.b.key||'');if(!/^[0-9a-f]{32,128}$/.test(key))throw new Err(401,'unauthorized');
 if(!(await dbInst(C.env,sub)))throw new Err(404,'unknown institution');
 const nk=await getJson(C.env,sub,'nk');
 if(typeof nk!=='string'||!nk)throw new Err(409,'Workspace is still syncing. Try again in a few seconds.');
 if(!eq(nk,key)){await fail(C.env,C.ip,'workspace key '+sub);await alert(C.env,C.ip,'Workspace key mismatch',`workspace ${sub}`);throw new Err(403,'unauthorized')}
 return{via:'key'}}

/* ───────────── payments ───────────── */
/* BDT wallets (bKash, Nagad, Rocket...) are paid in Taka to the merchant number and verified by sender + TrxID + amount; every other gateway is priced in USD.
   Plans switch on only when a payment row is 'paid': founder confirmation, Stripe webhook, or a matching forwarded wallet SMS (/api/pay/sms).
   Optional env: PAY_NO (receiving number), BDT_RATE (Taka per USD, default 122), PAY_HOOK_KEY (16+ chars, secret for the SMS forwarder). */
const MANUAL_GW=new Set(['bKash','Nagad','Rocket','Upay','SureCash','SSLCommerz']);
const PAY_NO=env=>String((env&&env.PAY_NO)||'01812410928');
const bdtRate=env=>{const r=+(env&&env.BDT_RATE);return r>0&&r<1e4?r:122};
const bdp=v=>{let d=String(v||'').replace(/\D/g,'');if(d.startsWith('880'))d=d.slice(2);if(d.length===10&&d[0]==='1')d='0'+d;return /^01[3-9]\d{8}$/.test(d)?d:''};
const PLAN_USD={starter:29,institution:79,sovereign:199};
const planUsd=item=>{const m=/^(starter|institution|sovereign) plan[^a-z]*(monthly|annual)/i.exec(String(item||''));return m?PLAN_USD[m[1].toLowerCase()]*(m[2].toLowerCase()==='annual'?10:1):null};
const PLAN_BDT={starter:799,institution:1999,sovereign:4999}; const planBdt=item=>{const m=/^(starter|institution|sovereign) plan[^a-z]*(monthly|annual)/i.exec(String(item||''));return m?PLAN_BDT[m[1].toLowerCase()]*(m[2].toLowerCase()==='annual'?10:1):null}; const smsMatch=(o,x)=>(!o.sender||!x.sender||o.sender===x.sender)&&+o.amt>=x.taka-0.5;
async function checkout(C){
 const{b,env,ip}=C,gw=gateOf(b.gateway),loc=MANUAL_GW.has(gw),cur=loc?'BDT':'USD',usd=Math.round(+b.usd*100)/100,item=(str(b.item,100)+(cur==='USD'?'':' ['+cur+']')).trim(),taka=planBdt(item)||Math.round(usd*bdtRate(env));
 /* every check that can fail runs BEFORE anything is written, so a rejected payment costs no D1 write; the device keeps its own fallback record in localStorage */
 if(!gw||!(usd>0&&usd<=5000)||!item)throw new Err(400,'invalid payment');
 if(/plan/i.test(item)){const want=planUsd(item);if(want==null||Math.abs(want-usd)>0.001)throw new Err(400,'invalid plan or price')}
 let sender='',trx='';
 if(loc){sender=bdp(b.sender);trx=String(b.txid||'').trim().toUpperCase();
  if(!sender)throw new Err(400,'Enter the mobile number you paid from (01XXXXXXXXX)');
  if(!/^[A-Z0-9]{8,14}$/.test(trx))throw new Err(400,'Enter the TrxID from your payment SMS (8 to 14 letters or numbers)')}
 if(await hit(env,'pay:'+ip,20,3600))throw new Err(429,'rate limited');
 const id='PAY-'+rnd(5).toUpperCase(),s=await auth(C),sub=s?s.sub:(wsn(b.sub)||null),txid=loc?trx+'|'+sender:str(b.txid,80);let url=null;
 if(/plan/i.test(item)&&!sub)throw new Err(401,'Sign in to your workspace to buy a plan');
 if(loc){let dup=null;try{dup=await sq(env,"SELECT id FROM payments WHERE txid LIKE ? AND status IN ('pending','paid') LIMIT 1",trx+'|%').first()}catch{}
  if(dup)throw new Err(409,'This TrxID was already submitted')}
 try{await sq(env,'INSERT INTO payments(id,sub,gateway,item,usd,txid,status,at) VALUES(?,?,?,?,?,?,?,?)',id,sub,gw,item,usd,txid,'pending',iso()).run()}
 catch(e){throw new Err(503,'The server could not record this payment right now. The details were kept on this device.',{fallback:'local'})}
 if(gw==='Stripe'&&env.STRIPE_KEY){try{const r=await fetch('https://api.stripe.com/v1/checkout/sessions',{method:'POST',headers:{authorization:'Bearer '+env.STRIPE_KEY,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({mode:'payment','line_items[0][price_data][currency]':cur.toLowerCase(),'line_items[0][price_data][product_data][name]':item,'line_items[0][price_data][unit_amount]':String(Math.round(usd*100)),'line_items[0][quantity]':'1',success_url:C.u.origin+'/#dash',cancel_url:C.u.origin+'/#dash','metadata[payment_id]':id})});url=(await r.json()).url||null}catch{url=null}}
 /* the wallet SMS may have been forwarded before this form was submitted */
 let paid=false;
 if(loc){try{const m=await env.KV.get('paysms:'+trx);if(m&&smsMatch(JSON.parse(m),{sender,taka})){await markPaid(C,id,'sms');paid=true}}catch{}}
 await tg(env,`💳 <b>Payment ${id}</b>${paid?' ✅ auto-verified':''}\n${X(item)} · ${cur==='BDT'?'৳'+taka+' (≈$'+usd+')':'$'+usd}\n${X(gw)} · TxID ${X(loc?trx:(txid||'-'))}${loc?' · from '+X(sender):''}\nWorkspace: ${X(sub||'visitor')}${b.institutionId?' · '+X(str(b.institutionId,40)):''}`);
 return J({status:paid?'verified':'pending',id,ref:id,gateway:gw,currency:cur,amount:cur==='BDT'?taka:usd,payTo:loc?PAY_NO(env):undefined,url,message:paid?'Payment confirmed':url?'Redirecting to secure checkout':loc?'Payment received for verification. Your plan turns on as soon as the transfer to '+PAY_NO(env)+' is confirmed.':'Payment recorded. Access activates once the founder verifies it.'})}
async function checkoutVerify(C){
 const{b,env,ip}=C;if(await hit(env,'payv:'+ip,240,3600))throw new Err(429,'rate limited');
 const id=str(b.ref,40).toUpperCase();if(!/^PAY-[A-Z0-9]{4,12}$/.test(id))throw new Err(400,'invalid reference');
 const r=await sq(env,'SELECT id,sub,status FROM payments WHERE id=?',id).first();if(!r)throw new Err(404,'payment not found');
 const s=await auth(C),sub=s?s.sub:(wsn(b.sub)||null);if(!sub||sub!==r.sub)throw new Err(403,'unauthorized');
 const st=r.status==='paid'?'verified':r.status==='rejected'?'rejected':'pending';
 return J({status:st,ref:r.id,message:st==='verified'?'Payment confirmed':st==='rejected'?'The payment was rejected. No plan was activated.':'Still waiting for confirmation'})}
/* wallet SMS forwarder: your phone forwards the "money received" SMS (bKash, Nagad, Rocket) here; a payment is confirmed only when TrxID, sender and amount all match */
async function paySms(C){
 const{b,env,ip}=C,key=env.PAY_HOOK_KEY;if(!key||String(key).length<16)throw new Err(503,'SMS verification is not configured');
 if(!eq(String(b.key||C.req.headers.get('x-pay-key')||''),String(key))){await fail(env,ip,'pay sms');throw new Err(403,'rejected')}
 const t=String(b.text||b.message||b.body||'').slice(0,600);
 const trx=String(b.trxid||(/(?:trx\s*id|txn\s*id|transaction\s*id)\s*[:\-]?\s*([A-Za-z0-9]{8,14})/i.exec(t)||[])[1]||'').toUpperCase(),
  amt=+String(b.amount||(/(?:tk|bdt|৳)\.?\s*([\d,]+(?:\.\d{1,2})?)/i.exec(t)||[])[1]||'').replace(/,/g,''),
  sender=bdp(b.sender||(/(?:from|sender)\s*(?:a\/c)?\s*[:\-]?\s*(\+?(?:88)?01\d{9})/i.exec(t)||[])[1]);
 if(!/^[A-Z0-9]{8,14}$/.test(trx)||!(amt>0))throw new Err(400,'TrxID and amount not found');
 const r=await sq(env,"SELECT id,txid,usd,item FROM payments WHERE txid LIKE ? AND status='pending' LIMIT 1",trx+'|%').first();
 if(r){if(smsMatch({sender,amt},{sender:String(r.txid).split('|')[1],taka:planBdt(r.item)||Math.round(r.usd*bdtRate(env))})){await markPaid(C,r.id,'sms');return J({ok:true,matched:r.id})}
  await tg(env,`⚠️ <b>Payment ${X(r.id)}</b>: SMS TrxID ${X(trx)} found but sender or amount differs (Tk ${amt}). Check it by hand.`);return J({ok:true,matched:false,reason:'mismatch'})}
 try{await env.KV.put('paysms:'+trx,JSON.stringify({sender,amt}),{expirationTtl:172800})}catch{}
 return J({ok:true,matched:false,stored:true})}
async function markPaid(C,id,by){
 const env=C.env,r=await sq(env,'SELECT * FROM payments WHERE id=?',id).first();if(!r)return null;
 if(r.status==='paid')return r;
 await sq(env,"UPDATE payments SET status='paid' WHERE id=?",id).run();
 if(r.sub&&/plan/i.test(r.item)){const plan={name:r.item,gateway:r.gateway,status:'paid',ref:r.id,until:new Date(Date.now()+(/annual/i.test(r.item)?366:31)*864e5).toISOString()};try{await mutatePart(env,r.sub,'plan',()=>plan)}catch{}}
 await tg(env,`✅ <b>Payment ${X(id)} confirmed</b> by ${X(by)}\n${X(r.item)} · ${X(r.sub||'-')}`);return r}
async function fRemind(C){
 const{b,env,ip}=C;if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await fail(env,ip,'founder reminders');throw new Err(403,'rejected')}
 return J({ok:true,sent:await planRemind(env)})}
async function fPayment(C){
 const{b,env,ip}=C;if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await fail(env,ip,'founder payment');throw new Err(403,'rejected')}
 const id=str(b.id,40),st=b.status==='paid'?'paid':b.status==='rejected'?'rejected':'';if(!id||!st)throw new Err(400,'id and status are required');
 if(st==='paid'){const r=await markPaid(C,id,'founder');if(!r)throw new Err(404,'payment not found');return J({ok:true})}
 await sq(env,"UPDATE payments SET status='rejected' WHERE id=?",id).run();return J({ok:true})}
async function stripeHook(C){
 const{env,req,raw}=C,sig=req.headers.get('stripe-signature')||'',sec=env.STRIPE_WEBHOOK_SECRET;if(!sec)throw new Err(503,'webhook not configured');
 const t=/t=(\d+)/.exec(sig),v=/v1=([0-9a-f]+)/.exec(sig);if(!t||!v||Math.abs(nowS()-+t[1])>300)throw new Err(400,'bad signature');
 const k=await crypto.subtle.importKey('raw',u8(sec),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 if(!eq(hex(await crypto.subtle.sign('HMAC',k,u8(t[1]+'.'+raw))),v[1]))throw new Err(400,'bad signature');
 let ev={};try{ev=JSON.parse(raw)}catch{}
 if(ev.type==='checkout.session.completed'){const id=ev.data&&ev.data.object&&ev.data.object.metadata&&ev.data.object.metadata.payment_id;if(id)await markPaid(C,String(id).slice(0,40),'stripe')}
 return J({received:true})}

/* ───────────── backups (R2) ───────────── */
async function backup(C){
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');
 await tenantAuth(C,sub,['Admin']);if(!env.R2)throw new Err(503,'Cloud backup storage is not connected');
 const data=typeof b.data==='string'?b.data:'';if(!data||data.length>25e6)throw new Err(400,'invalid backup');
 if(hitMem('bk:'+sub,6,3600000))throw new Err(429,'rate limited');
 const key=`backups/${sub}/${iso().replace(/[:.]/g,'-')}.json`;await env.R2.put(key,data,{httpMetadata:{contentType:'application/json'}});
 try{const l=await env.R2.list({prefix:`backups/${sub}/`,limit:1000}),ks=l.objects.map(x=>x.key).sort();for(const x of ks.slice(0,Math.max(0,ks.length-30)))await env.R2.delete(x)}catch{}
 return J({ok:true,at:iso()})}

/* ───────────── guardian / student portal (one D1 row per student) ───────────── */
/* fees.items comes from the server snapshot: keep it a clean list of {n,a} so the fee page always renders */
function normFees(f){f=isO(f)?f:{};const items=(Array.isArray(f.items)?f.items:[]).slice(0,40).map(i=>({n:str(i&&i.n,60),a:Math.round((+(i&&i.a)||0)*100)/100})).filter(i=>i.n&&i.a>0);
 return{...f,items,cur:/^[A-Z]{3}$/.test(String(f.cur||''))?f.cur:'BDT'}}
function proj(d,who){
 d=JSON.parse(JSON.stringify(d||{}));
 if(who==='student'){const r=d.rec||{},i=d.inst||{},s=d.stu||{};d={v:d.v,at:d.at,inst:{name:i.name,type:i.type,logo:i.logo,cctv:false},stu:{id:s.id,name:s.name,cls:s.cls,house:s.house,photo:s.photo},marks:d.marks||{},rec:{lesson:r.lesson||[],module:r.module||[],task:r.task||[]},quran:d.quran||''}}
 else{if(!(d.inst&&d.inst.cctv))d.cam='';d.fees=normFees(d.fees)}
 return d}
const hx=(v,n)=>typeof v==='string'&&new RegExp('^[0-9a-f]{'+n+'}$').test(v);
async function gSync(C){
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');
 await tenantAuth(C,sub,['Admin']);if(hitMem('gsy:'+sub,60,3600000))throw new Err(429,'rate limited');
 const list=Array.isArray(b.students)?b.students:[],rows=[];
 for(const s of list.slice(0,20000)){const id=String(s&&s.id||'').toUpperCase();if(!/^[A-Z0-9-]{1,24}$/.test(id)||!isO(s.d))continue;if(JSON.stringify(s.d).length>60000)continue;
  rows.push({id,ph:String(s.ph||'').replace(/\D/g,'').slice(-10),gh:hx(s.gh,64)?s.gh:'',gs:hx(s.gs,16)?s.gs:'',sh:hx(s.sh,64)?s.sh:'',ss:hx(s.ss,16)?s.ss:'',gk:hx(s.gk,64)?s.gk:'',sk:hx(s.sk,64)?s.sk:'',d:s.d})}
 if(list.length&&!rows.length)throw new Err(400,'no valid students');
 const pins=new Map(),conf=[];let nopin=0; /* Secret PIN lookup keys: one PIN belongs to exactly one student, in this institution and in every other one */
 for(const r of rows){const ks=[...new Set([r.gk,r.sk].filter(Boolean))];if(!ks.length){nopin++;continue}for(const k of ks){const o=pins.get(k);if(o&&o!==r.id){conf.push(r.id);continue}pins.set(k,r.id)}}
 const gen=Date.now(),at=iso(),st=[];let cur=[],sz=0;
 const flush=()=>{if(cur.length)st.push(sq(env,"INSERT INTO portal(sub,sid,ph,gh,gs,sh,ss,d,gen,updated) SELECT ?1,json_extract(value,'$.id'),json_extract(value,'$.ph'),json_extract(value,'$.gh'),json_extract(value,'$.gs'),json_extract(value,'$.sh'),json_extract(value,'$.ss'),json_extract(value,'$.d'),?3,?4 FROM json_each(?2) WHERE 1 ON CONFLICT(sub,sid) DO UPDATE SET ph=excluded.ph,gh=excluded.gh,gs=excluded.gs,sh=excluded.sh,ss=excluded.ss,d=excluded.d,gen=excluded.gen,updated=excluded.updated",sub,JSON.stringify(cur),gen,at));cur=[];sz=0};
 for(const r of rows){const t=JSON.stringify(r).length;if(sz+t>500000)flush();cur.push(r);sz+=t}flush();
 st.push(sq(env,'DELETE FROM portal_pin WHERE sub=?1',sub));
 {const pl=[...pins].map(([k,id])=>({k,id}));for(let i=0;i<pl.length;i+=1500)st.push(sq(env,"INSERT INTO portal_pin(pk,sub,sid) SELECT json_extract(value,'$.k'),?1,json_extract(value,'$.id') FROM json_each(?2) WHERE 1 ON CONFLICT(pk) DO NOTHING",sub,JSON.stringify(pl.slice(i,i+1500))))} /* a PIN already held by another student is left alone, never overwritten */
 st.push(sq(env,'DELETE FROM portal WHERE sub=?1 AND gen<>?2',sub,gen));
 for(let i=0;i<st.length;i+=40)await env.DB.batch(st.slice(i,i+40));
 const own=new Map(((await sq(env,'SELECT pk,sid FROM portal_pin WHERE sub=?',sub).all()).results||[]).map(r=>[r.pk,r.sid]));
 for(const[k,id]of pins)if(own.get(k)!==id)conf.push(id); /* the PIN is held by someone else: the admin app makes this student a new one */
 return J({ok:true,count:rows.length,nopin,conflicts:[...new Set(conf)].slice(0,200)})}
async function gLogin(C){ /* the Secret PIN is unique to one student across every institution and finds that student on its own; the guardian's registered mobile number (or the student's admission ID) must belong to that same student, otherwise the PIN does nothing. There is no per-ID lockout, so one person can never lock another institution's users out; the PIN is 100 bits, so guessing is not possible, and attempts are still limited per IP. */
 const{b,env,ip}=C,who=b.who==='student'?'student':'guardian',raw=String(b.pin||'').slice(0,40);
 const cn=raw.toUpperCase().replace(/[\s-]/g,'').replace(/O/g,'0').replace(/[IL]/g,'1'),pin=cn.length===20?cn.match(/.{4}/g).join('-'):raw;
 const sid=str(b.sid,24).toUpperCase(),ph=String(b.phone||'').replace(/\D/g,'').slice(-10);
 if(hitMem('gl:'+ip,30,3600000)||await hit(env,'gl:'+ip,20,3600))throw new Err(429,'Too many attempts. Try again later.');
 const pr=/^[0-9A-Z]{20}$/.test(cn)?await sq(env,'SELECT sub,sid FROM portal_pin WHERE pk=?',await sha('pk:'+cn)).first():null;
 const s=pr?await sq(env,'SELECT * FROM portal WHERE sub=? AND sid=?',pr.sub,pr.sid).first():null;
 const salt=s?(who==='student'?s.ss:s.gs):'0'.repeat(16),want=s?(who==='student'?s.sh:s.gh):'0'.repeat(64);
 const okPin=!!s&&FPRX.test(want)&&eq(await sha(pin+':'+salt),want),okWho=!!s&&(who==='student'?s.sid===sid:(s.ph.length>=7&&s.ph===ph));
 if(!(okPin&&okWho)){await fail(env,ip,'portal login '+who);throw new Err(401,who==='student'?'Details did not match. Check the admission ID and Secret PIN.':'Details did not match. Check the registered mobile number and Secret PIN.')}
 const token=rnd(24);await env.KV.put('gt:'+token,JSON.stringify({sub:s.sub,sid:s.sid,who}),{expirationTtl:43200});
 let d={};try{d=JSON.parse(s.d)}catch{}return J({token,who,sub:s.sub,d:proj(d,who)})}
async function gData(C){
 const t=JSON.parse(await C.env.KV.get('gt:'+String(C.b.token||'').slice(0,60))||'null');if(!t)throw new Err(401,'expired');
  bg(C,pushDrain(C.env));
  let sig=await gSig(C.env,t.sub,t.sid);const wt=Math.min(20000,Math.max(0,+C.b.wait||0)),w0=Date.now(); /* long-poll: with wait+since the call returns the moment something changes */
  if(wt&&typeof C.b.since==='string'){while(sig===C.b.since&&Date.now()-w0<wt){await sleep(1500);sig=await gSig(C.env,t.sub,t.sid)}if(sig===C.b.since)return J({same:true,sig,now:Date.now()})}
  if(t.who==='guardian'&&!hitMem('gdv:'+t.sub+':'+t.sid,2,5000))bg(C,gSeenSt(C.env,t.sub,t.sid,'g','dv',Date.now()).run());
  const[a,o,n,rxq,stq]=await C.env.DB.batch([sq(C.env,'SELECT d FROM portal WHERE sub=? AND sid=?',t.sub,t.sid),
  sq(C.env,"SELECT k,x,u,at,meta FROM portal_out WHERE sub=? AND (sid=? OR sid='*') ORDER BY id DESC LIMIT 80",t.sub,t.sid),
  sq(C.env,'SELECT title AS ev,body AS x,is_read AS u,created_at AS at FROM notifications WHERE workspace_sub=? AND recipient_id=? ORDER BY created_at DESC LIMIT 40',t.sub,t.sid),
   sq(C.env,'SELECT k,at,who,e FROM portal_rx WHERE sub=? AND sid=? ORDER BY at DESC LIMIT 400',t.sub,t.sid),sq(C.env,"SELECT dv,seen,ty FROM portal_seen WHERE sub=? AND sid=? AND who='s'",t.sub,t.sid)]);
 const s=a.results&&a.results[0];if(!s)throw new Err(401,'expired');
 let d={};try{d=JSON.parse(s.d)}catch{}d=proj(d,t.who);
 if(t.who==='guardian'){ /* live layer: replies and notices written after the last publish are merged in, de-duplicated by time + text */
  const rows=(o.results||[]).slice().reverse().map(r=>{try{r.rq=r.meta?JSON.parse(r.meta).rq:undefined}catch{}return r}),msgs=Array.isArray(d.msgs)?d.msgs:[],board=Array.isArray(d.board)?d.board:[];
  for(const r of rows){
   if(r.k==='b'){if(!board.some(m=>m&&+m.at===+r.at&&m.t===r.x))board.push({t:r.x,u:!!r.u,at:+r.at});if(!msgs.some(m=>m&&m.nt&&+m.at===+r.at&&m.x===r.x))msgs.push({f:'s',x:r.x,at:+r.at,nt:r.u?2:1})} /* a notice also lands in the chat, flagged nt:1 (notice) or nt:2 (urgent) so the app can label it "নোটিস" */
   else if(r.k==='g'){const f=msgs.find(m=>m&&m.f==='g'&&+m.at===+r.at);if(f){if(r.rq&&!f.rq)f.rq=r.rq}else msgs.push({f:'g',x:r.x,at:+r.at,...(r.rq?{rq:r.rq}:{})})}
   else{const f=msgs.find(m=>m&&m.f==='s'&&+m.at===+r.at&&m.x===r.x);if(f){if(r.rq&&!f.rq)f.rq=r.rq}else msgs.push({f:'s',x:r.x,at:+r.at,...(r.rq?{rq:r.rq}:{})})}}
  const nt=((n&&n.results)||[]).map(r=>({ev:r.ev,x:r.x,u:!!r.u,at:Date.parse(r.at)||0})); /* in-house alerts (attendance, reports, receipts) */
  d.notifs=nt;for(const r of nt){if(!board.some(m=>m&&+m.at===r.at&&m.t===r.x))board.push({t:r.x,u:false,at:r.at,ev:r.ev})}
  d.msgs=msgs.sort((p,q)=>(+p.at||0)-(+q.at||0)).slice(-60);d.board=board.sort((p,q)=>(+q.at||0)-(+p.at||0)).slice(0,40);gAttach(d,rxq.results||[],stq.results&&stq.results[0])}
 return J({d,now:Date.now(),sig})}
async function gReply(C){ /* institution/teacher → one guardian, delivered live through /api/g/data */
 const{b,env}=C,sub=wsn(b.sub),sid=str(b.sid,24).toUpperCase();if(!SUBRX.test(sub)||!/^[A-Z0-9-]{1,24}$/.test(sid))throw new Err(400,'invalid request');
 await tenantAuth(C,sub,['Admin','Teacher']);if(hitMem('grp:'+sub,600,3600000))throw new Err(429,'rate limited');
 const x=String(b.text||'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').trim().slice(0,1000);if(!x)throw new Err(400,'empty');
 if(!(await sq(env,'SELECT 1 AS x FROM portal WHERE sub=? AND sid=?',sub,sid).first()))throw new Err(404,'student not published yet');
 const now=Date.now(),ca=+b.at,at=Number.isFinite(ca)&&Math.abs(ca-now)<6e5?Math.floor(ca):now; /* the sender's own timestamp is kept (±10 min) so the local copy and the live copy never show twice */
 const r=await sq(env,'INSERT INTO portal_out(sub,sid,k,x,u,at,meta) VALUES(?,?,?,?,?,?,?)',sub,sid,'m',x,0,at,gMeta(b)).run();
 if(Math.random()<.05)await sq(env,'DELETE FROM portal_out WHERE sub=?1 AND sid=?2 AND id<=(SELECT id FROM portal_out WHERE sub=?1 AND sid=?2 ORDER BY id DESC LIMIT 1 OFFSET 200)',sub,sid).run().catch(()=>{});
 bg(C,(async()=>pushTo(env,sub,'g',sid,await mkPl(env,C.u.origin,sub,{k:'msg',x,at,sid})))());return J({ok:true,id:r.meta&&r.meta.last_row_id,at})}
async function gNotice(C){ /* notice / urgent broadcast to every guardian: one row for all (shows on the notice board AND in each guardian's chat), pushed with the full text */
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(400,'invalid request');
 await tenantAuth(C,sub,['Admin']);if(hitMem('gnt:'+sub,120,3600000))throw new Err(429,'rate limited');
 const x=String(b.text||b.t||'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').trim().slice(0,300);if(!x)throw new Err(400,'empty');
 const now=Date.now(),ca=+b.at,at=Number.isFinite(ca)&&Math.abs(ca-now)<6e5?Math.floor(ca):now;
 await sq(env,'INSERT INTO portal_out(sub,sid,k,x,u,at) VALUES(?,?,?,?,?,?)',sub,'*','b',x,(b.urgent||b.u)?1:0,at).run();
 if(Math.random()<.05)await sq(env,"DELETE FROM portal_out WHERE sub=?1 AND sid='*' AND id<=(SELECT id FROM portal_out WHERE sub=?1 AND sid='*' ORDER BY id DESC LIMIT 1 OFFSET 40)",sub).run().catch(()=>{});
 let pushed=0,devices=0,more=false;
 if(pushOn(env)){try{
  const cap=pcap(env),pl=await mkPl(env,C.u.origin,sub,{k:(b.urgent||b.u)?'urgent':'notice',x,at,sid:'*'}),rows=await pushRows(env,sub,'g',null,'',cap);
  devices=rows.length;pushed=await pushSend(env,rows,pl);
  if(rows.length>=cap){more=true;await sq(env,'INSERT INTO push_q(sub,who,sid,pl,cur,at) VALUES(?,?,?,?,?,?)',sub,'g','*',JSON.stringify(pl),rows[rows.length-1].id,Date.now()).run()} /* the rest of the guardians are pushed in the background, one batch per request */
 }catch(e){console.error('notice push failed:',e&&e.message)}}
 /* guardians with no working push device: the admin can share the notice with them by WhatsApp or SMS from their own phone (no gateway involved) */
 const np=((await sq(env,"SELECT sid,ph FROM portal WHERE sub=?1 AND ph<>'' AND sid NOT IN (SELECT sid FROM push_subs WHERE sub=?1 AND who='g') LIMIT 300",sub).all().catch(()=>null))||{}).results||[];
 return J({ok:true,at,pushed,devices,more,noPush:np.map(r=>({sid:r.sid,ph:r.ph}))})}
 /* ───────────── chat extras: reply quotes, reactions, delivered/read ticks, typing, web push ───────────── */
 const gMeta=b=>{const q=b&&b.rq;if(!isO(q))return null;const x=str(q.x,200);return x?JSON.stringify({rq:{x,n:str(q.n,60)}}):null};
 const gSeenSt=(env,sub,sid,who,f,v)=>{if(!['dv','seen','ty'].includes(f))throw new Err(400,'invalid field');return sq(env,'INSERT INTO portal_seen(sub,sid,who,'+f+') VALUES(?1,?2,?3,?4) ON CONFLICT(sub,sid,who) DO UPDATE SET '+f+'=MAX('+f+',excluded.'+f+')',sub,sid,who,Math.floor(v))};
 async function gSig(env,sub,sid){const r=await env.DB.batch([
  sq(env,"SELECT COALESCE(MAX(id),0) a FROM portal_out WHERE sub=?1 AND (sid=?2 OR sid='*')",sub,sid),
  sq(env,'SELECT COUNT(*) a,COALESCE(SUM(unicode(e)),0) b FROM portal_rx WHERE sub=?1 AND sid=?2',sub,sid),
  sq(env,"SELECT COALESCE(MAX(ty),0) a,COALESCE(MAX(seen),0) b,COALESCE(MAX(dv),0) c FROM portal_seen WHERE sub=?1 AND sid=?2 AND who='s'",sub,sid),
  sq(env,"SELECT COALESCE(MAX(updated),'') a FROM portal WHERE sub=?1 AND sid=?2",sub,sid),
  sq(env,"SELECT COUNT(*) a,COALESCE(MAX(created_at),'') b FROM notifications WHERE workspace_sub=?1 AND recipient_id=?2",sub,sid)]);
  return r.map(x=>{const o=(x.results||[])[0]||{};return Object.values(o).join(',')}).join('|')}
 async function gStSig(env,sub){const[a,b]=await env.DB.batch([sq(env,"SELECT COALESCE(MAX(ty),0) a,COALESCE(MAX(dv),0) b,COALESCE(MAX(seen),0) c FROM portal_seen WHERE sub=? AND who='g'",sub),sq(env,'SELECT COUNT(*) a,COALESCE(SUM(unicode(e)),0) b FROM portal_rx WHERE sub=?',sub)]);
  return[a,b].map(x=>Object.values((x.results||[])[0]||{}).join(',')).join('|')}
 async function gStState(env,sub){const[a,b]=await env.DB.batch([sq(env,"SELECT sid,dv,seen,ty FROM portal_seen WHERE sub=? AND who='g' ORDER BY MAX(dv,seen,ty) DESC LIMIT 500",sub),sq(env,'SELECT sid,k,at,who,e FROM portal_rx WHERE sub=? ORDER BY at DESC LIMIT 800',sub)]);
  return{seen:a.results||[],rx:b.results||[],now:Date.now()}}
 function gAttach(d,rx,st){const mp=new Map();for(const r of rx){const key=r.k+':'+r.at;let o=mp.get(key);if(!o)mp.set(key,o={});(o[r.e]=o[r.e]||[]).push(r.who)}
  for(const m of d.msgs){const o=mp.get((m.f==='g'?'g':'m')+':'+m.at);if(o)m.rx=o}
  d.st={sdv:+(st&&st.dv)||0,sseen:+(st&&st.seen)||0,sty:+(st&&st.ty)||0}} /* sdv/sseen: when the institution fetched/read the guardian's messages; sty: when it last typed */
 async function gWho(C){const b=C.b;
  if(typeof b.token==='string'&&/^[0-9a-f]{48}$/.test(b.token)){const t=JSON.parse(await C.env.KV.get('gt:'+b.token)||'null');if(!t||t.who!=='guardian')throw new Err(401,'expired');return{sub:t.sub,sid:t.sid,who:'g'}}
  const sub=wsn(b.sub),sid=str(b.sid,24).toUpperCase();if(!SUBRX.test(sub)||!/^[A-Z0-9-]{1,24}$/.test(sid))throw new Err(400,'invalid request');
  await tenantAuth(C,sub,['Admin','Teacher']);return{sub,sid,who:'s'}}
 async function gReact(C){ /* toggle one emoji on one message; one reaction per person per message */
  const w=await gWho(C),b=C.b,e=String(b.e||''),k=b.k==='g'?'g':'m',at=Math.floor(+b.at);
  if(hitMem('grx:'+w.sub+':'+w.sid+':'+w.who,200,3600000))throw new Err(429,'rate limited');
  if(!RXE.test(e)||!Number.isFinite(at)||at<1e12||at>Date.now()+864e5)throw new Err(400,'invalid reaction');
  const cur=await sq(C.env,'SELECT e FROM portal_rx WHERE sub=? AND sid=? AND k=? AND at=? AND who=?',w.sub,w.sid,k,at,w.who).first();
  if(cur&&cur.e===e){await sq(C.env,'DELETE FROM portal_rx WHERE sub=? AND sid=? AND k=? AND at=? AND who=?',w.sub,w.sid,k,at,w.who).run();return J({ok:true,e:null})}
  await sq(C.env,'INSERT INTO portal_rx(sub,sid,k,at,who,e) VALUES(?,?,?,?,?,?) ON CONFLICT(sub,sid,k,at,who) DO UPDATE SET e=excluded.e',w.sub,w.sid,k,at,w.who,e).run();
  if(Math.random()<.05)await sq(C.env,'DELETE FROM portal_rx WHERE sub=?1 AND sid=?2 AND at<?3',w.sub,w.sid,Date.now()-90*864e5).run().catch(()=>{});
  return J({ok:true,e})}
 async function gSeen(C){ /* "I have read everything up to this message time" → blue ticks on the other side */
  const w=await gWho(C),at=Math.min(Date.now()+6e4,Math.floor(+C.b.at||Date.now()));if(hitMem('gsn:'+w.sub+':'+w.sid+':'+w.who,600,3600000))throw new Err(429,'rate limited');
  await C.env.DB.batch([gSeenSt(C.env,w.sub,w.sid,w.who,'seen',at),gSeenSt(C.env,w.sub,w.sid,w.who,'dv',at)]);return J({ok:true})}
 async function gTyping(C){const w=await gWho(C);if(hitMem('gty:'+w.sub+':'+w.sid+':'+w.who,1500,3600000))return J({ok:true,skipped:true});
  await gSeenSt(C.env,w.sub,w.sid,w.who,'ty',Date.now()).run();return J({ok:true})}
 /* web push with the real message: the text, institution name and logo travel inside an encrypted payload (RFC 8291). Subscriptions saved before the keys were stored fall back to a short lookup (/api/push/peek). Needs VAPID_PUBLIC + VAPID_PRIVATE_JWK (or VAPID_PRIVATE) secrets; without them everything below is a quiet no-op.
    VAPID_PRIVATE_JWK may hold a full JWK (JSON) or just the raw private key string from vapidkeys.com (43 characters); the JWK is then built from it and VAPID_PUBLIC. */
 const PUSHHOST=/^https:\/\/([a-z0-9-]+\.)*(googleapis\.com|push\.services\.mozilla\.com|notify\.windows\.com|push\.apple\.com)\//i;
 const vapidPriv=env=>String(env.VAPID_PRIVATE_JWK||env.VAPID_PRIVATE||'').trim(),vapidPub=env=>String(env.VAPID_PUBLIC||'').replace(/\s+/g,'').replace(/^"|"$/g,'');
 let vapidMemo=null;
 async function vapidKey(env){const raw=vapidPriv(env),pub=vapidPub(env),sg=raw+'|'+pub;if(vapidMemo&&vapidMemo.sg===sg)return vapidMemo.key;
  let jwk;if(raw[0]==='{')jwk=JSON.parse(raw);else jwk={kty:'EC',crv:'P-256',d:raw.replace(/\s+/g,'').replace(/^"|"$/g,'')};
  if(!jwk.x||!jwk.y){const p=unb64u(pub);if(p.length!==65||p[0]!==4)throw new Error('VAPID_PUBLIC must be the 65-byte uncompressed public key');jwk.x=b64u(p.slice(1,33));jwk.y=b64u(p.slice(33))}
  jwk={kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y,d:jwk.d};
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);vapidMemo={sg,key};return key}
 async function vapidJwt(env,aud){const key=await vapidKey(env);
  const h=b64u(u8(JSON.stringify({typ:'JWT',alg:'ES256'}))),p=b64u(u8(JSON.stringify({aud,exp:nowS()+43200,sub:env.VAPID_SUBJECT||'mailto:admin@classphera.com'})));
  return h+'.'+p+'.'+b64u(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,u8(h+'.'+p)))}
 const pushOn=env=>!!(vapidPub(env)&&vapidPriv(env)),pcap=env=>Math.max(5,Math.min(+env.PUSH_BATCH||30,900)); /* devices pushed per request (the free plan allows ~50 outgoing calls; raise PUSH_BATCH on a paid plan) */
 const cutB=(t,n)=>{t=String(t==null?'':t);if(u8(t).length<=n)return t;let a=0,z=t.length;while(a<z){const m=(a+z+1)>>1;if(u8(t.slice(0,m)).length<=n-3)a=m;else z=m-1}return t.slice(0,a)+'…'};
 const evKind=e=>{e=String(e||'').toLowerCase();return/attend|present|absent|late/.test(e)?'attendance':/receipt|fee|pay|due|bill/.test(e)?'fee':/report|result|mark|exam|merit/.test(e)?'result':'alert'};
 /* institution name + logo as saved in the institution profile (published with each student row) */
 const instInfo=(env,sub)=>memo('im:'+sub,300000,async()=>{const r=await sq(env,"SELECT json_extract(d,'$.inst.name') n,length(json_extract(d,'$.inst.logo')) l FROM portal WHERE sub=? LIMIT 1",sub).first().catch(()=>null);let n=str(r&&r.n,80);if(!n){const i=await dbInst(env,sub).catch(()=>null);n=str(i&&i.name,80)}return{n:n||'ClasSphera',l:+(r&&r.l)||0}});
 async function mkPl(env,origin,sub,o){const im=await instInfo(env,sub),at=o.at||Date.now();return{t:im.n,b:cutB(o.x,2200),i:origin+'/api/inst/logo?s='+sub+(im.l?'&v='+im.l:''),k:o.k||'msg',at,s:sub,sid:o.sid||'',g:(o.k||'msg')+':'+at}}
 /* RFC 8291 (aes128gcm) payload encryption with WebCrypto */
 async function pushBody(p256dh,auth,text){const ua=unb64u(p256dh),au=unb64u(auth);if(ua.length!==65||ua[0]!==4||au.length<16)return null;
  const cat=(...a)=>{const o=new Uint8Array(a.reduce((n,x)=>n+x.length,0));let k=0;for(const x of a){o.set(x,k);k+=x.length}return o};
  const kp=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),asPub=new Uint8Array(await crypto.subtle.exportKey('raw',kp.publicKey));
  const uaKey=await crypto.subtle.importKey('raw',ua,{name:'ECDH',namedCurve:'P-256'},false,[]),secret=await crypto.subtle.deriveBits({name:'ECDH',public:uaKey},kp.privateKey,256);
  const hk=async(ikm,salt,info,bits)=>crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt,info},await crypto.subtle.importKey('raw',ikm,'HKDF',false,['deriveBits']),bits);
  const ikm=await hk(secret,au,cat(u8('WebPush: info\0'),ua,asPub),256),salt=crypto.getRandomValues(new Uint8Array(16));
  const cek=await hk(ikm,salt,u8('Content-Encoding: aes128gcm\0'),128),nonce=await hk(ikm,salt,u8('Content-Encoding: nonce\0'),96);
  const key=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['encrypt']),ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:new Uint8Array(nonce)},key,cat(u8(text),new Uint8Array([2]))));
  return cat(salt,new Uint8Array([0,0,16,0,65]),asPub,ct)}
 async function pushOne(env,r,pl,jw){
  if(!PUSHHOST.test(r.ep)){await sq(env,'DELETE FROM push_subs WHERE id=?',r.id).run();return 0}
  const aud=new URL(r.ep).origin,jwt=await(jw[aud]||(jw[aud]=vapidJwt(env,aud))),h={TTL:'86400',Urgency:'high',Authorization:'vapid t='+jwt+', k='+vapidPub(env)};let body=null;
  if(pl&&r.p256dh&&r.auth){try{body=await pushBody(r.p256dh,r.auth,JSON.stringify(pl))}catch{body=null}}
  if(body){h['Content-Encoding']='aes128gcm';h['Content-Type']='application/octet-stream'}
  const res=await fetch(r.ep,{method:'POST',headers:h,body:body||undefined});
  if(res.status===404||res.status===410){await sq(env,'DELETE FROM push_subs WHERE id=?',r.id).run();return 0}
  return res.ok?1:0}
 async function pushSend(env,rows,pl){const jw={};const r=await Promise.all(rows.map(x=>pushOne(env,x,pl,jw).catch(e=>{console.error('web push failed:',e&&e.message);return 0})));return r.reduce((a,b)=>a+b,0)}
 const pushRows=async(env,sub,who,sid,cur,n)=>(await sq(env,'SELECT id,sid,ep,p256dh,auth FROM push_subs WHERE sub=?1 AND who=?2 AND (?3 IS NULL OR sid=?3) AND id>?4 ORDER BY id LIMIT ?5',sub,who,sid==null||sid==='*'?null:String(sid),cur||'',n).all()).results||[];
 async function pushTo(env,sub,who,sid,pl){try{if(!pushOn(env))return 0;if(hitMem('pu:'+sub+':'+who+':'+sid,40,60000))return 0;
  const cap=pcap(env),rows=await pushRows(env,sub,who,sid,'',cap),n=await pushSend(env,rows,pl);
  if(rows.length>=cap)await sq(env,'INSERT INTO push_q(sub,who,sid,pl,cur,at) VALUES(?,?,?,?,?,?)',sub,who,sid==null?'*':String(sid),JSON.stringify(pl||null),rows[rows.length-1].id,Date.now()).run();
  return n}catch(e){console.error('web push failed:',e&&e.message);return 0}}
 /* alerts for many guardians at once (attendance, fee, result): the first batch goes out now, the rest waits in push_q */
 async function pushAlerts(env,origin,sub,list){try{if(!pushOn(env))return;
  const sids=[...new Set(list.map(a=>a.sid))].slice(0,400),rows=(await sq(env,"SELECT id,sid,ep,p256dh,auth FROM push_subs WHERE sub=?1 AND who='g' AND sid IN (SELECT value FROM json_each(?2)) LIMIT 800",sub,JSON.stringify(sids)).all()).results||[];if(!rows.length)return;
  const by=new Map();for(const r of rows){if(!by.has(r.sid))by.set(r.sid,[]);by.get(r.sid).push(r)}
  const cap=pcap(env),now=[],later=[];let used=0;
  for(const a of list){const ds=by.get(a.sid);if(!ds)continue;const pl=await mkPl(env,origin,sub,{k:evKind(a.ev),x:a.x,at:Date.now(),sid:a.sid});
   if(used+ds.length<=cap){used+=ds.length;now.push(pushSend(env,ds,pl))}else later.push(sq(env,'INSERT INTO push_q(sub,who,sid,pl,cur,at) VALUES(?,?,?,?,?,?)',sub,'g',a.sid,JSON.stringify(pl),'',Date.now()))}
  await Promise.all(now);for(let i=0;i<later.length&&i<300;i+=40)await env.DB.batch(later.slice(i,i+40))}catch(e){console.error('alert push failed:',e&&e.message)}}
 /* sends the next batch of a queued job; called from the live polls, at most once every 8 s per worker instance */
 async function pushDrain(env){try{if(!pushOn(env)||hitMem('pqd',1,8000))return;
  const j=await sq(env,'SELECT id,sub,who,sid,pl,cur FROM push_q WHERE at>? ORDER BY id LIMIT 1',Date.now()-864e5).first();
  if(!j){if(Math.random()<.05)await sq(env,'DELETE FROM push_q WHERE at<=?',Date.now()-864e5).run();return}
  const rows=await pushRows(env,j.sub,j.who,j.sid,j.cur,pcap(env));
  if(!rows.length){await sq(env,'DELETE FROM push_q WHERE id=?',j.id).run();return}
  const u=await sq(env,'UPDATE push_q SET cur=? WHERE id=? AND cur=?',rows[rows.length-1].id,j.id,j.cur).run();if(!(u.meta&&u.meta.changes))return; /* another instance took this batch */
  let pl=null;try{pl=JSON.parse(j.pl)}catch{}await pushSend(env,rows,pl)}catch(e){console.error('push queue failed:',e&&e.message)}}
 async function pushKey(C){return J({key:vapidPub(C.env),on:!!(vapidPub(C.env)&&vapidPriv(C.env))})}
 async function pushSub(C){const b=C.b,ep=String(b.endpoint||'').slice(0,700);if(!PUSHHOST.test(ep))throw new Err(400,'invalid endpoint');let sub,who,sid;
  if(typeof b.token==='string'&&/^[0-9a-f]{48}$/.test(b.token)){const t=JSON.parse(await C.env.KV.get('gt:'+b.token)||'null');if(!t||t.who!=='guardian')throw new Err(401,'expired');sub=t.sub;who='g';sid=t.sid}
  else{const s=await need(C);sub=s.sub;who='s';sid=String(s.ph||'')}
  if(hitMem('psub:'+sub+':'+sid,30,3600000))throw new Err(429,'rate limited');const id=await sha(ep);
  if(b.off){await sq(C.env,'DELETE FROM push_subs WHERE id=? AND sub=?',id,sub).run();return J({ok:true})}
  const kk=isO(b.keys)?b.keys:{},pk=/^[A-Za-z0-9_-]{86,88}$/.test(String(kk.p256dh||''))?String(kk.p256dh):null,ak=/^[A-Za-z0-9_-]{22,24}$/.test(String(kk.auth||''))?String(kk.auth):null; /* browser keys: they let the server encrypt the real message into the push */
  await sq(C.env,'INSERT INTO push_subs(id,sub,who,sid,ep,created,p256dh,auth) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET sub=excluded.sub,who=excluded.who,sid=excluded.sid,ep=excluded.ep,p256dh=COALESCE(excluded.p256dh,push_subs.p256dh),auth=COALESCE(excluded.auth,push_subs.auth)',id,sub,who,sid,ep,iso(),pk,ak).run();return J({ok:true,keys:!!(pk&&ak)})}
/* old subscriptions (saved without keys) get an empty push: the service worker then asks for the newest message here */
async function pushPeek(C){const{env}=C,ep=String(C.b.endpoint||'').slice(0,700);if(!PUSHHOST.test(ep)||hitMem('pk:'+C.ip,60,60000))return J({});
 const r=await sq(env,'SELECT sub,who,sid FROM push_subs WHERE id=?',await sha(ep)).first();if(!r||r.who!=='g')return J({});
 const[o,n]=await env.DB.batch([sq(env,"SELECT k,x,u,at FROM portal_out WHERE sub=?1 AND (sid=?2 OR sid='*') AND k IN ('m','b') ORDER BY id DESC LIMIT 1",r.sub,r.sid),sq(env,'SELECT title,body,created_at FROM notifications WHERE workspace_sub=?1 AND recipient_id=?2 ORDER BY created_at DESC LIMIT 1',r.sub,r.sid)]);
 const a=o.results&&o.results[0],c=n.results&&n.results[0],ta=a?+a.at:0,tc=c?Date.parse(c.created_at)||0:0;if(Math.max(ta,tc)<Date.now()-18e5)return J({});
 return J(ta>=tc?await mkPl(env,C.u.origin,r.sub,{k:a.k==='b'?(a.u?'urgent':'notice'):'msg',x:a.x,at:ta,sid:r.sid}):await mkPl(env,C.u.origin,r.sub,{k:evKind(c.title),x:c.body,at:tc,sid:r.sid}))}
/* the institution's profile picture as a plain image URL, used as the push notification icon */
async function instLogo(C){const{env,u}=C,sub=wsn(u.searchParams.get('s')),fb=()=>Response.redirect(u.origin+'/icon-192.png',302);if(!SUBRX.test(sub))return fb();
 let l='';try{const r=await sq(env,"SELECT json_extract(d,'$.inst.logo') l FROM portal WHERE sub=? LIMIT 1",sub).first();l=String(r&&r.l||'');if(!l){const d=await sq(env,'SELECT logo l FROM directory WHERE sub=?',sub).first();l=String(d&&d.l||'')}}catch{return fb()}
 if(/^https:\/\//.test(l))return Response.redirect(l,302);
 const m=/^data:image\/(png|jpeg|jpg|webp|gif);base64,([A-Za-z0-9+\/=]+)$/.exec(l);if(!m)return fb();
 let bin;try{bin=atob(m[2])}catch{return fb()}const a=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);
 return new Response(a,{headers:{'content-type':'image/'+(m[1]==='jpg'?'jpeg':m[1]),'cache-control':'public, max-age=86400','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'"}})}
async function gSend(C){
 const{b,env}=C,tk=String(b.token||'').slice(0,60),t=JSON.parse(await env.KV.get('gt:'+tk)||'null');if(!t||t.who!=='guardian')throw new Err(401,'expired');
 const x=String(b.text||'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').trim().slice(0,1000);if(!x)throw new Err(400,'empty');
 if(await hit(env,'gsd:'+tk,30,3600))throw new Err(429,'rate limited');
 const n=await sq(env,'SELECT COUNT(*) AS n FROM portal_inbox WHERE sub=?',t.sub).first();if(n&&n.n>5000)throw new Err(429,'inbox full');
 const at=Date.now(),mt=gMeta(b),r=(await env.DB.batch([sq(env,'INSERT INTO portal_inbox(sub,sid,x,at,meta) VALUES(?,?,?,?,?)',t.sub,t.sid,x,at,mt),sq(env,'INSERT INTO portal_out(sub,sid,k,x,u,at,meta) VALUES(?,?,?,?,?,?,?)',t.sub,t.sid,'g',x,0,at,mt)]))[0]; /* portal_out copy (k=g) is what /api/g/data returns to the guardian; the inbox row is deleted once the institution has read it */
 if(Math.random()<.05)await sq(env,'DELETE FROM portal_out WHERE sub=?1 AND sid=?2 AND id<=(SELECT id FROM portal_out WHERE sub=?1 AND sid=?2 ORDER BY id DESC LIMIT 1 OFFSET 200)',t.sub,t.sid).run().catch(()=>{});
 bg(C,(async()=>{const pl=await mkPl(env,C.u.origin,t.sub,{k:'inbox',x,at,sid:t.sid}),s=await sq(env,"SELECT json_extract(d,'$.stu.name') n FROM portal WHERE sub=? AND sid=?",t.sub,t.sid).first().catch(()=>null);pl.t=(str(s&&s.n,60)||t.sid)+' · অভিভাবক';return pushTo(env,t.sub,'s',null,pl)})());return J({ok:true,id:r&&r.meta&&r.meta.last_row_id,at})}
async function gInbox(C){
  const sub=wsn(C.b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');await tenantAuth(C,sub,['Admin']);bg(C,pushDrain(C.env));
  const env=C.env,rd=async()=>(await sq(env,'SELECT id,sid,x,at,meta FROM portal_inbox WHERE sub=? ORDER BY id LIMIT 500',sub).all()).results||[];
  let r=await rd(),sig=await gStSig(env,sub);const wt=Math.min(20000,Math.max(0,+C.b.wait||0)),w0=Date.now();
  if(wt&&typeof C.b.since==='string')while(!r.length&&sig===C.b.since&&Date.now()-w0<wt){await sleep(1500);r=await rd();sig=await gStSig(env,sub)} /* long-poll */
  if(r.length){await sq(env,'DELETE FROM portal_inbox WHERE sub=? AND id<=?',sub,r[r.length-1].id).run();const now=Date.now();await env.DB.batch([...new Set(r.map(m=>m.sid))].slice(0,100).map(s=>gSeenSt(env,sub,s,'s','dv',now))).catch(()=>{})}
  const st=await gStState(env,sub);
  return J({msgs:r.map(m=>{let q;try{q=m.meta?JSON.parse(m.meta).rq:undefined}catch{}return{id:m.id,sid:m.sid,x:m.x,at:m.at,...(q?{rq:q}:{})}}),st,sig})}
async function gOtp(C){
 const{b,env,ip}=C,sub=wsn(b.sub),sid=str(b.sid,24).toUpperCase();if(!SUBRX.test(sub)||!sid)throw new Err(404,'not found');
 if(hitMem('go:'+ip,6,3600000)||await hit(env,'go:'+sub+':'+sid,3,3600))throw new Err(429,'rate limited');
 if(!(await sq(env,'SELECT 1 AS x FROM portal WHERE sub=? AND sid=?',sub,sid).first()))throw new Err(404,'not found');
 const sts=await getJson(env,sub,'students'),st=Array.isArray(sts)?sts.find(x=>x&&String(x.id).toUpperCase()===sid):null,ph=nph(st&&st.gphone);
 if(!/^\+\d{7,15}$/.test(ph))throw new Err(422,'Guardian phone must include the country code');
 throw new Err(410,'Codes are no longer sent by SMS. Sign in with the Student admission ID and your PIN, or ask the institution to reset it.')}
async function gQuick(C){
 const{b,env,ip}=C,sub=wsn(b.sub),sid=str(b.sid,24).toUpperCase(),pin=String(b.pin||'').slice(0,40);
 if(!SUBRX.test(sub)||!sid||pin.length<4)throw new Err(400,'invalid request');
 if(hitMem('gq:'+ip,30,3600000))throw new Err(429,'rate limited');
 const fk='gqf:'+sub+':'+sid,fails=+(await env.KV.get(fk))||0;if(fails>=5)throw new Err(429,'Too many wrong attempts. Wait 15 minutes.');
 const s=await sq(env,'SELECT gh,gs,d FROM portal WHERE sub=? AND sid=?',sub,sid).first();let ok=false;
 if(s&&FPRX.test(s.gh))ok=eq(await sha(pin+':'+s.gs),s.gh);
 if(!ok&&s&&/^\d{6}$/.test(pin)){const k='gq:'+sub+':'+sid,rec=JSON.parse(await env.KV.get(k)||'null');if(rec&&rec.n<3){if(eq(await hmac(env,`gq|${pin}|${sub}|${sid}`),rec.h)){ok=true;await env.KV.delete(k)}else{rec.n++;await env.KV.put(k,JSON.stringify(rec),{expirationTtl:300})}}}
 if(!ok){await env.KV.put(fk,String(fails+1),{expirationTtl:900});await fail(env,ip,'quick view '+sub);throw new Err(401,'Incorrect PIN or code')}
 await env.KV.delete(fk);let d={};try{d=JSON.parse(s.d)}catch{}
 const att=Object.values(d.att||{}),pr=att.filter(a=>a&&(a.s==='P'||a.s==='L')).length,f=d.fees||{},tot=(f.items||[]).reduce((a,x)=>a+(+x.a||0),0);
 return J({d:{name:str(d.stu&&d.stu.name,80),cls:str(d.stu&&d.stu.cls,40),att:att.length?Math.round(pr*100/att.length):0,fee:tot&&f.paid!=null&&+f.paid>=tot?'Paid':tot?'Due':'—',hifz:str(d.quran,80)||'—'}})}

/* ───────────── Fee payment & digital receipts · Guardian / Student Fee module ─────────────
   fee_due      one row per student per charge (monthly / exam / custom). Published now or on a chosen date; fee_rule repeats a charge monthly.
   fee_pay      the payment attempt: draft → pending → approved | rejected. Always scoped by sub (institution) + sid (student).
                The amount is recomputed on the server from the due row and the institution's rate, never taken from the browser.
   fee_receipt  permanent, HMAC-signed digital receipt, opened from /api/fee/verify?c=<code> (not purged with chat messages).
   fee_cfg      per-institution merchant / agent numbers and gateway links.
   Staff routes read the institution from the signed session (never from the request); guardian / student routes use the portal token (gt:). */
const FEE_MFS=['bKash','Nagad','Rocket'],FEE_LOCAL=[...FEE_MFS,'SSLCommerz'],FEE_GLOBAL=['Visa','Mastercard','Stripe','PayPal'],FEE_ALL=[...FEE_LOCAL,...FEE_GLOBAL];
const BDMOB=/^(?:\+?88)?01[3-9]\d{8}$/,FEE_REF=/^[A-Z0-9][A-Z0-9_-]{4,39}$/,FEE_ID=/^[A-Z0-9-]{1,24}$/;
const fm2=v=>Math.round((+v||0)*100)/100;
const feeTs=(v,d)=>{const t=typeof v==='number'?v:Date.parse(String(v||''));return Number.isFinite(t)&&t>1e12&&t<Date.now()+1.1e11?Math.floor(t):d};
const feeMask=v=>{v=String(v||'');return v.length>6?v.slice(0,3)+'•'.repeat(Math.min(v.length-6,12))+v.slice(-3):v};
function feeCfgClean(x){x=isO(x)?x:{};const src=isO(x.m)?x.m:{},m={};
 for(const g of FEE_ALL){const a=isO(src[g])?src[g]:{},u=String(a.url||'').trim();
  m[g]={no:str(a.no,60),kind:['Personal','Agent','Merchant'].includes(a.kind)?a.kind:'Personal',url:/^https:\/\/\S{4,300}$/.test(u)?u:'',note:str(a.note,200)}}
 return{m,rate:Math.max(0,Math.min(100000,fm2(x.rate)))}}
const feeOn=(c,g)=>FEE_MFS.includes(g)?!!c.m[g].no:!!(c.m[g].no||c.m[g].url||c.m[g].note);
async function feeCfg(env,sub){const r=await sq(env,'SELECT data FROM fee_cfg WHERE sub=?',sub).first();let d={};try{d=JSON.parse(r&&r.data||'{}')}catch{}return feeCfgClean(d)}
const feePub=c=>({rate:c.rate,m:Object.fromEntries(FEE_ALL.filter(g=>feeOn(c,g)).map(g=>[g,c.m[g]]))});
const feeConv=(a,from,to,rate)=>from===to?fm2(a):rate>0?fm2(from==='BDT'?a/rate:a*rate):null; /* rate = BDT per 1 USD, set by the institution */
const feeSig=(env,o)=>hmac(env,'rcpt|'+[o.code,o.no,o.sub,o.sid,o.amt,o.cur,o.method,o.trx,o.at].join('|'));
async function feeWho(C){const tk=String(C.b.token||'').slice(0,60),t=/^[0-9a-f]{48}$/.test(tk)?JSON.parse(await C.env.KV.get('gt:'+tk)||'null'):null;if(!t||!t.sub||!t.sid)throw new Err(401,'expired');return t}
async function feeDue(env,t,id){const r=await sq(env,"SELECT * FROM fee_due WHERE id=? AND sub=? AND sid=? AND status='due' AND publish_at<=?",String(id||'').slice(0,100),t.sub,t.sid,Date.now()).first();if(!r)throw new Err(404,'This fee is no longer due');return r}

/* ---- scheduling: recurring monthly rules and charges published on a date are created / announced lazily, on the first fee request after their time ---- */
const feeNext=(ms,day)=>{const d=new Date(ms);return Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+1,Math.min(28,day||d.getUTCDate()),d.getUTCHours(),d.getUTCMinutes())};
const feeExpand=(env,o)=>sq(env,"INSERT OR IGNORE INTO fee_due(id,sub,sid,cat,title,amt,cur,due_on,publish_at,status,nt,batch) SELECT ?1||':'||sid,?2,sid,?3,?4,?5,?6,?7,?8,'due',0,?1 FROM portal WHERE sub=?2 AND (?9='' OR json_extract(d,'$.stu.cls')=?9) AND (?10='' OR sid IN (SELECT value FROM json_each(?10)))",o.batch,o.sub,o.cat,o.title,o.amt,o.cur,o.due_on||'',o.at,o.cls||'',o.sids||'').run();
async function feeNotifyNew(C,sub){const env=C.env,rows=(await sq(env,"SELECT id,sid,cat,title,amt,cur FROM fee_due WHERE sub=? AND status='due' AND nt=0 AND publish_at<=? LIMIT 300",sub,Date.now()).all()).results||[];if(!rows.length)return;
 await sq(env,'UPDATE fee_due SET nt=1 WHERE sub=?1 AND id IN (SELECT value FROM json_each(?2))',sub,JSON.stringify(rows.map(r=>r.id))).run();
 bg(C,inApp(env,sub,rows.map(r=>({sid:r.sid,ev:'Fee due',msg:'💳 ফি বকেয়া / Fee due: '+(r.title||r.cat)+' — '+r.amt+' '+r.cur+'. পরিশোধ করুন / Pay now.'})),C))}
async function feeRun(C,sub){const env=C.env,now=Date.now();let made=0;
 const rules=(await sq(env,'SELECT * FROM fee_rule WHERE sub=? AND active=1 AND next_at<=? LIMIT 20',sub,now).all()).results||[];
 for(const r of rules){const due=[];let nx=r.next_at;for(;nx<=now&&due.length<60;nx=feeNext(nx,r.day))due.push(nx);
  for(const at of due.slice(-3)){const x=await feeExpand(env,{batch:'r'+r.id+':'+new Date(at).toISOString().slice(0,7),sub,cat:r.cat,title:r.title,amt:r.amt,cur:r.cur,at,cls:r.cls,sids:r.sids});made+=(x.meta&&x.meta.changes)||0}
  await sq(env,'UPDATE fee_rule SET next_at=? WHERE id=? AND sub=?',nx,r.id,sub).run()}
 await feeNotifyNew(C,sub);return made}
const feeTick=(C,sub)=>hitMem('ftk:'+sub,1,15000)?0:feeRun(C,sub).catch(e=>{console.error('fee tick failed:',e&&e.message)});

/* ---- institution (Admin / Accountant) ---- */
async function feeCfgRoute(C){const s=await need(C,['Admin','Accountant']);
 if(isO(C.b.set)){if(s.role!=='Admin')throw new Err(403,'Only the Admin can change merchant numbers'); /* a payment number decides where money goes */
  const c=feeCfgClean(C.b.set);await sq(C.env,'INSERT INTO fee_cfg(sub,data,updated) VALUES(?,?,?) ON CONFLICT(sub) DO UPDATE SET data=excluded.data,updated=excluded.updated',s.sub,JSON.stringify(c),iso()).run();
  bg(C,dbAudit(C.env,'fee_cfg',s.sub+' by '+str(s.ph,40),C.ip));return J({ok:true,cfg:c})}
 return J({ok:true,cfg:await feeCfg(C.env,s.sub)})}
async function feeAnnounce(C){const s=await need(C,['Admin','Accountant']),{env,b}=C,sub=s.sub;
 if(hitMem('fan:'+sub,60,3600000))throw new Err(429,'rate limited');
 const cat=str(b.cat,40)||'Custom',title=str(b.title,80),amt=fm2(b.amt),cur=b.cur==='USD'?'USD':'BDT',now=Date.now(),at=feeTs(b.at,now),
  dueOn=/^\d{4}-\d{2}-\d{2}$/.test(String(b.due_on||''))?String(b.due_on):'',cls=str(b.cls,40),
  sids=[...new Set((Array.isArray(b.sids)?b.sids:String(b.sids||'').split(/[\s,;]+/)).map(x=>String(x).toUpperCase().trim()).filter(x=>FEE_ID.test(x)))].slice(0,2000),sj=sids.length?JSON.stringify(sids):'';
 if(!(amt>0&&amt<=1e8))throw new Err(400,'Enter a valid amount');
 let created=0;
 if(b.repeat==='monthly'){await sq(env,'INSERT INTO fee_rule(id,sub,cat,title,amt,cur,cls,sids,day,next_at,active) VALUES(?,?,?,?,?,?,?,?,?,?,1)','x'+rnd(6),sub,cat,title,amt,cur,cls,sj,Math.min(28,new Date(at).getUTCDate()),at).run();created=await feeRun(C,sub)}
 else{const r=await feeExpand(env,{batch:'a'+rnd(6),sub,cat,title,amt,cur,due_on:dueOn,at,cls,sids:sj});created=(r.meta&&r.meta.changes)||0;await feeNotifyNew(C,sub)}
 return J({ok:true,created,scheduled:at>now})}
async function feeRuleRoute(C){const s=await need(C,['Admin','Accountant']),{env,b}=C,sub=s.sub;
 if(b.rule){await sq(env,'UPDATE fee_rule SET active=0 WHERE id=? AND sub=?',str(b.rule,40),sub).run();return J({ok:true})}
 if(b.batch){const bt=str(b.batch,100); /* withdraw an announcement: unpaid charges are voided, charges with a payment awaiting approval are kept */
  await env.DB.batch([sq(env,"UPDATE fee_due SET status='void' WHERE sub=?1 AND batch=?2 AND status='due' AND id NOT IN (SELECT due_id FROM fee_pay WHERE sub=?1 AND status='pending')",sub,bt),
   sq(env,"DELETE FROM fee_pay WHERE sub=?1 AND status='draft' AND due_id IN (SELECT id FROM fee_due WHERE sub=?1 AND batch=?2 AND status='void')",sub,bt)]);return J({ok:true})}
 throw new Err(400,'nothing to do')}
async function feeQueue(C){const s=await need(C,['Admin','Accountant']),{env}=C,sub=s.sub;await feeTick(C,sub);
 const[q,h,bt,ru]=await env.DB.batch([
  sq(env,"SELECT p.id,p.sid,p.method,p.cur,p.amt,p.from_no,p.rcv_no,p.trx,p.created,f.cat,f.title,f.amt dueAmt,f.cur dueCur,json_extract(o.d,'$.stu.name') stu,json_extract(o.d,'$.stu.cls') cls FROM fee_pay p JOIN fee_due f ON f.id=p.due_id LEFT JOIN portal o ON o.sub=p.sub AND o.sid=p.sid WHERE p.sub=? AND p.status='pending' ORDER BY p.created LIMIT 200",sub),
  sq(env,"SELECT p.id,p.sid,p.status,p.method,p.cur,p.amt,p.trx,p.updated,p.reason,f.cat,f.title,json_extract(o.d,'$.stu.name') stu FROM fee_pay p JOIN fee_due f ON f.id=p.due_id LEFT JOIN portal o ON o.sub=p.sub AND o.sid=p.sid WHERE p.sub=? AND p.status IN ('approved','rejected') ORDER BY p.updated DESC LIMIT 20",sub),
  sq(env,"SELECT batch,cat,title,amt,cur,MIN(publish_at) at,COUNT(*) n,SUM(status='due') open FROM fee_due WHERE sub=? AND status<>'void' GROUP BY batch ORDER BY MAX(publish_at) DESC LIMIT 15",sub),
  sq(env,'SELECT id,cat,title,amt,cur,cls,next_at FROM fee_rule WHERE sub=? AND active=1 ORDER BY next_at LIMIT 20',sub)]);
 return J({ok:true,role:s.role,count:q.results.length,pending:q.results,recent:h.results,batches:bt.results,rules:ru.results,now:Date.now()})}
async function feeDecide(C){const s=await need(C,['Admin','Accountant']),{env,b}=C,sub=s.sub,id=str(b.id,40);
 if(hitMem('fdc:'+sub,600,3600000))throw new Err(429,'rate limited');
 const p=await sq(env,'SELECT p.*,f.cat,f.title,f.id fid FROM fee_pay p JOIN fee_due f ON f.id=p.due_id WHERE p.id=? AND p.sub=?',id,sub).first();
 if(!p)throw new Err(404,'payment not found');if(p.status!=='pending')throw new Err(409,'This payment was already '+p.status);
 const now=Date.now(),st=await sq(env,"SELECT json_extract(d,'$.stu.name') n,json_extract(d,'$.stu.cls') c FROM portal WHERE sub=? AND sid=?",sub,p.sid).first().catch(()=>null),stu=str(st&&st.n,80)||p.sid,ttl=p.title||p.cat,who=str(s.ph,60);
 if(b.act==='reject'){const reason=str(b.reason,160);
  const r=await sq(env,"UPDATE fee_pay SET status='rejected',reason=?,decided_by=?,decided_at=?,updated=? WHERE id=? AND sub=? AND status='pending'",reason,who,now,now,id,sub).run();
  if(!(r.meta&&r.meta.changes))throw new Err(409,'This payment was already decided');
  bg(C,inApp(env,sub,[{sid:p.sid,ev:'Fee payment',msg:'❌ পেমেন্ট যাচাই হয়নি / Payment not verified: '+ttl+' ('+p.trx+')'+(reason?' — '+reason:'')+'. আবার চেষ্টা করুন / Please try again.'}],C));
  return J({ok:true,status:'rejected'})}
 if(b.act!=='approve')throw new Err(400,'invalid action');
 const im=await instInfo(env,sub),code=rnd(12),no='RCT-'+new Date(now).toISOString().slice(0,10).replace(/-/g,'')+'-'+code.slice(0,6).toUpperCase(),sig=await feeSig(env,{code,no,sub,sid:p.sid,amt:p.amt,cur:p.cur,method:p.method,trx:p.trx,at:now});
 /* one atomic batch: the receipt and the Paid mark are written only while the payment is still pending, so a double click or two accountants can never create two receipts */
 const rs=await env.DB.batch([
  sq(env,"INSERT INTO fee_receipt(code,no,pay_id,sub,sid,inst,stu,cls,cat,title,amt,cur,method,from_no,rcv_no,trx,pat,at,sig,appr) SELECT ?1,?2,p.id,p.sub,p.sid,?3,?4,?5,?6,?7,p.amt,p.cur,p.method,p.from_no,p.rcv_no,p.trx,p.created,?8,?9,?10 FROM fee_pay p WHERE p.id=?11 AND p.sub=?12 AND p.status='pending'",code,no,im.n,stu,str(st&&st.c,40),p.cat,p.title||'',now,sig,who,id,sub),
  sq(env,"UPDATE fee_due SET status='paid',paid_at=?1 WHERE id=?2 AND sub=?3 AND EXISTS(SELECT 1 FROM fee_pay WHERE id=?4 AND sub=?3 AND status='pending')",now,p.fid,sub,id),
  sq(env,"UPDATE fee_pay SET status='approved',decided_by=?1,decided_at=?2,updated=?2 WHERE id=?3 AND sub=?4 AND status='pending'",who,now,id,sub)]);
 if(!(rs[2].meta&&rs[2].meta.changes))throw new Err(409,'This payment was already decided');
 const link=C.u.origin+'/api/fee/verify?c='+code,amt=p.amt+' '+p.cur;
 /* internal message (chat) + in-app notification + web push for the guardian; the permanent copy is the fee_receipt row */
 await sq(env,'INSERT INTO portal_out(sub,sid,k,x,u,at) VALUES(?,?,?,?,?,?)',sub,p.sid,'m',('🧾 পেমেন্ট নিশ্চিত হয়েছে / Payment confirmed\n'+im.n+'\n'+stu+' · '+ttl+' · '+amt+'\n'+p.method+' · TrxID '+p.trx+'\nরসিদ / Receipt: '+no+'\nযাচাই / Verify: '+link).slice(0,1000),0,now).run().catch(()=>{});
 bg(C,inApp(env,sub,[{sid:p.sid,ev:'Fee receipt',msg:'✅ '+ttl+' — '+amt+' পরিশোধিত / paid. রসিদ / Receipt '+no}],C));
 return J({ok:true,status:'approved',code,no,link})}

/* ---- guardian / student ---- */
async function feeMine(C){const t=await feeWho(C),{env}=C;
 if(hitMem('fmn:'+t.sub+':'+t.sid,90,60000))throw new Err(429,'rate limited');
 await feeTick(C,t.sub);
 const[a,d,r,c]=await env.DB.batch([
  sq(env,"SELECT json_extract(d,'$.stu.name') n,json_extract(d,'$.stu.cls') c,json_extract(d,'$.inst.name') i FROM portal WHERE sub=? AND sid=?",t.sub,t.sid),
  sq(env,"SELECT f.id,f.cat,f.title,f.amt,f.cur,f.due_on,f.publish_at,p.id pid,p.status ps,p.method,p.cur pcur,p.from_no,p.trx,(SELECT x.reason FROM fee_pay x WHERE x.due_id=f.id AND x.status='rejected' ORDER BY x.updated DESC LIMIT 1) rej FROM fee_due f LEFT JOIN fee_pay p ON p.due_id=f.id AND p.status IN ('draft','pending') WHERE f.sub=? AND f.sid=? AND f.status='due' AND f.publish_at<=? ORDER BY f.publish_at DESC LIMIT 100",t.sub,t.sid,Date.now()),
  sq(env,'SELECT code,no,inst,stu,sid,cls,cat,title,amt,cur,method,from_no,rcv_no,trx,pat,at FROM fee_receipt WHERE sub=? AND sid=? ORDER BY at DESC LIMIT 60',t.sub,t.sid),
  sq(env,'SELECT data FROM fee_cfg WHERE sub=?',t.sub)]);
 const p=(a.results&&a.results[0])||{};let raw={};try{raw=JSON.parse((c.results&&c.results[0]&&c.results[0].data)||'{}')}catch{}
 const cfg=feeCfgClean(raw),origin=C.u.origin;
 return J({ok:true,now:Date.now(),inst:str(p.i,80)||(await instInfo(env,t.sub)).n,stu:{id:t.sid,name:str(p.n,80),cls:str(p.c,40)},cfg:feePub(cfg),
  dues:(d.results||[]).map(x=>({id:x.id,cat:x.cat,title:x.title,amt:x.amt,cur:x.cur,due_on:x.due_on,at:x.publish_at,state:x.ps||'due',rej:x.rej||'',pay:x.pid?{method:x.method,cur:x.pcur,from:x.from_no,trx:x.trx}:null,alt:{BDT:feeConv(x.amt,x.cur,'BDT',cfg.rate),USD:feeConv(x.amt,x.cur,'USD',cfg.rate)}})),
  receipts:(r.results||[]).map(x=>({...x,link:origin+'/api/fee/verify?c='+x.code}))})}
async function feeDraft(C){const t=await feeWho(C),{env,b}=C;
 if(hitMem('fdr:'+t.sub+':'+t.sid,200,3600000))throw new Err(429,'rate limited');
 const due=await feeDue(env,t,b.due);
 if(b.clear){await sq(env,"DELETE FROM fee_pay WHERE due_id=? AND sub=? AND sid=? AND status='draft'",due.id,t.sub,t.sid).run();return J({ok:true,cleared:true})}
 const g=gateOf(b.method),cur=b.cur==='USD'?'USD':'BDT';if(!FEE_ALL.includes(g)||(FEE_GLOBAL.includes(g))!==(cur==='USD'))throw new Err(400,'Choose a payment method');
 const cfg=await feeCfg(env,t.sub);if(!feeOn(cfg,g))throw new Err(422,'This method is not set up');
 const from=str(b.from,60),trx=str(b.trx,40).toUpperCase().replace(/\s+/g,''),amt=feeConv(due.amt,due.cur,cur,cfg.rate)||0,now=Date.now(),rcv=str(cfg.m[g].no||cfg.m[g].url||cfg.m[g].note,120);
 const upd=()=>sq(env,"UPDATE fee_pay SET method=?,cur=?,amt=?,from_no=?,trx=?,rcv_no=?,updated=? WHERE due_id=? AND sub=? AND sid=? AND status='draft'",g,cur,amt,from,trx,rcv,now,due.id,t.sub,t.sid).run();
 const ex=await sq(env,"SELECT status FROM fee_pay WHERE due_id=? AND status IN ('draft','pending')",due.id).first();
 if(ex&&ex.status==='pending')throw new Err(409,'Already submitted. Waiting for approval.');
 if(ex)await upd();
 else{try{await sq(env,"INSERT INTO fee_pay(id,sub,sid,due_id,status,method,cur,amt,from_no,rcv_no,trx,created,updated) VALUES(?,?,?,?,'draft',?,?,?,?,?,?,?,?)",'p'+rnd(9),t.sub,t.sid,due.id,g,cur,amt,from,rcv,trx,now,now).run()}catch(e){if(/UNIQUE/i.test(String(e&&e.message)))await upd();else throw e}}
 return J({ok:true,state:'draft'})}
async function feeSubmit(C){const t=await feeWho(C),{env,b}=C;
 if(hitMem('fsb:'+t.sub+':'+t.sid,12,3600000)||hitMem('fsi:'+C.ip,40,3600000))throw new Err(429,'Too many attempts. Try again later.');
 const due=await feeDue(env,t,b.due),g=gateOf(b.method),cur=b.cur==='USD'?'USD':'BDT';
 if(!FEE_ALL.includes(g)||(FEE_GLOBAL.includes(g))!==(cur==='USD'))throw new Err(400,'Choose a payment method that matches the currency');
 const cfg=await feeCfg(env,t.sub);if(!feeOn(cfg,g))throw new Err(422,'The institution has not set up this method yet');
 const amt=feeConv(due.amt,due.cur,cur,cfg.rate);if(!(amt>0))throw new Err(422,'This currency is not available for this fee');
 let from=str(b.from,60);const trx=str(b.trx,40).toUpperCase().replace(/\s+/g,'');
 if(FEE_MFS.includes(g)){const f=from.replace(/[\s-]/g,'');if(!BDMOB.test(f))throw new Err(400,'Enter the number you paid from (11-digit mobile number)');from=f.replace(/^\+?88/,'')}
 else if(from.length<3)throw new Err(400,'Enter the payer name, e-mail or number');
 if(!FEE_REF.test(trx))throw new Err(400,'Enter a valid Transaction ID (TrxID)');
 if(await sq(env,"SELECT 1 AS x FROM fee_pay WHERE sub=? AND method=? AND trx=? AND status IN ('pending','approved')",t.sub,g,trx).first())throw new Err(409,'This TrxID was already submitted');
 const ex=await sq(env,"SELECT id,status FROM fee_pay WHERE due_id=? AND status IN ('draft','pending')",due.id).first();
 if(ex&&ex.status==='pending')throw new Err(409,'Already submitted. Waiting for approval.');
 const rcv=str(cfg.m[g].no||cfg.m[g].url||cfg.m[g].note,120),now=Date.now();let id;
 try{
  if(ex){id=ex.id;const r=await sq(env,"UPDATE fee_pay SET status='pending',method=?,cur=?,amt=?,from_no=?,trx=?,rcv_no=?,created=?,updated=? WHERE id=? AND sub=? AND sid=? AND status='draft'",g,cur,amt,from,trx,rcv,now,now,id,t.sub,t.sid).run();if(!(r.meta&&r.meta.changes))throw new Err(409,'Already submitted')}
  else{id='p'+rnd(9);await sq(env,"INSERT INTO fee_pay(id,sub,sid,due_id,status,method,cur,amt,from_no,rcv_no,trx,created,updated) VALUES(?,?,?,?,'pending',?,?,?,?,?,?,?,?)",id,t.sub,t.sid,due.id,g,cur,amt,from,rcv,trx,now,now).run()}
 }catch(e){if(e instanceof Err)throw e;if(/UNIQUE/i.test(String(e&&e.message)))throw new Err(409,'This TrxID was already submitted, or this fee is already waiting for approval');throw e}
 /* alert the institution: the payment appears in the Payment Approvals queue (/api/fee/queue) and every signed-in staff device gets a push */
 bg(C,(async()=>{const p=await sq(env,"SELECT json_extract(d,'$.stu.name') n FROM portal WHERE sub=? AND sid=?",t.sub,t.sid).first().catch(()=>null),
  pl=await mkPl(env,C.u.origin,t.sub,{k:'fee',x:(str(p&&p.n,60)||t.sid)+' · '+(due.title||due.cat)+' · '+amt+' '+cur+' · '+g+' · '+trx,at:now,sid:''});pl.t='💳 Payment Approvals';return pushTo(env,t.sub,'s',null,pl)})());
 return J({ok:true,id,state:'pending'})}

/* ---- public verification page of one receipt: the code is a 96-bit random secret, the signature proves the row was not edited ---- */
const feeDt=ms=>new Date(+ms).toLocaleString('en-GB',{timeZone:'Asia/Dhaka',dateStyle:'medium',timeStyle:'short'})+' (GMT+6)';
function feeRcptHtml(r,ok){
 const row=(a,b,v)=>`<tr><th>${E(a)}<small>${E(b)}</small></th><td>${E(v)}</td></tr>`,
  body=!r?`<div class="bad"><h1>Receipt not found</h1><p>রসিদটি পাওয়া যায়নি। Check the link or scan the QR again.</p></div>`:
  `<div class="${ok?'ok':'bad'}"><b>${ok?'✓ Verified receipt · যাচাইকৃত রসিদ':'✗ This receipt could not be verified · যাচাই করা যায়নি'}</b></div>
<h1>${E(r.inst)}</h1><p class="sub">Digital Money Receipt · ডিজিটাল মানি রিসিপ্ট</p>
<div class="amt">${E(new Intl.NumberFormat('en-US',{minimumFractionDigits:2}).format(r.amt))} <span>${E(r.cur)}</span></div>
<table>${row('Receipt No','রসিদ নং',r.no)}${row('Student','শিক্ষার্থী',r.stu)}${row('Student ID','আইডি',r.sid)}${r.cls?row('Class','শ্রেণি',r.cls):''}${row('Fee','ফি',r.title?r.cat+' · '+r.title:r.cat)}${row('Payment method','পেমেন্ট মাধ্যম',r.method)}${row('Sender','প্রেরক',feeMask(r.from_no))}${row('Receiver','প্রাপক',r.rcv_no||'—')}${row('TrxID','ট্রানজেকশন আইডি',r.trx)}${row('Paid','পরিশোধ',feeDt(r.pat))}${row('Approved','অনুমোদন',feeDt(r.at))}</table>
<button onclick="print()">Print · প্রিন্ট</button><p class="fine">Sender number is partly hidden on this public page. Issued by ClasSphera for the institution above.</p>`;
 return`<!doctype html><html lang="bn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${r?E(r.no)+' · ':''}Receipt · ClasSphera</title><style>:root{color-scheme:dark light;--bg:#070812;--fg:#e6e9f5;--mu:#9aa1b9;--cd:rgba(255,255,255,.06);--bd:rgba(255,255,255,.14)}@media(prefers-color-scheme:light){:root{--bg:#f4f6fb;--fg:#10142b;--mu:#5b6380;--cd:#fff;--bd:#d9deee}}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--fg);font:15px/1.5 Inter,system-ui,'Noto Sans Bengali',sans-serif}main{width:100%;max-width:460px;background:var(--cd);border:1px solid var(--bd);border-radius:20px;padding:22px}h1{font-size:20px;margin:12px 0 2px}.sub{color:var(--mu);margin:0 0 10px}.amt{font-size:34px;font-weight:800;margin:8px 0 14px;background:linear-gradient(90deg,#a78bfa,#22d3ee,#34d399);-webkit-background-clip:text;background-clip:text;color:transparent}.amt span{font-size:16px}table{width:100%;border-collapse:collapse}th,td{padding:8px 0;border-top:1px solid var(--bd);text-align:left;vertical-align:top;font-size:14px}th{color:var(--mu);font-weight:500;width:42%}th small{display:block;font-size:11px}td{font-weight:600;word-break:break-word}.ok,.bad{padding:9px 12px;border-radius:12px;font-size:13px}.ok{background:rgba(52,211,153,.16);color:#10b981}.bad{background:rgba(244,63,94,.14);color:#f43f5e}button{margin-top:16px;width:100%;padding:12px;border-radius:12px;border:0;background:#1e3a8a;color:#fff;font-weight:700}.fine{color:var(--mu);font-size:11px}@media print{button{display:none}body{background:#fff;color:#000}}</style></head><body><main>${body}</main></body></html>`}
async function feeVerify(C){const{env,u,ip}=C;await migrate(env);
 const hdr={'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-robots-tag':'noindex, nofollow','x-content-type-options':'nosniff','referrer-policy':'no-referrer','x-frame-options':'DENY','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"};
 if(hitMem('fv:'+ip,40,60000))return new Response('Too many requests',{status:429,headers:hdr});
 const code=String(u.searchParams.get('c')||'').toLowerCase(),r=/^[0-9a-f]{24}$/.test(code)?await sq(env,'SELECT * FROM fee_receipt WHERE code=?',code).first():null,
  ok=!!r&&eq(await feeSig(env,{code:r.code,no:r.no,sub:r.sub,sid:r.sid,amt:r.amt,cur:r.cur,method:r.method,trx:r.trx,at:r.at}),r.sig);
 return new Response(feeRcptHtml(r,ok),{status:r?200:404,headers:hdr})}

/* ───────────── Global Online Admission ───────────── */
const CAL={uk:['uk','united kingdom','britain','england','scotland','wales'],bangladesh:['bangladesh'],malaysia:['malaysia'],france:['france']};
const TYK={madrasah:'%madr%',school:'%school%',college:'%colleg%',university:'%univ%',coaching:'%coach%'};
const lk=s=>'%'+String(s).replace(/[\\%_]/g,'\\$&')+'%';
const okLogo=l=>/^https:\/\//.test(l||'')||(/^data:image\//.test(l||'')&&String(l).length<60000)?String(l):'';
async function instSearch(C){
 const{b,env,ip}=C;if(hitMem('is:'+ip,60,600000))throw new Err(429,'rate limited');
 const q=str(b.q,80),loc=str(b.loc,80),tk=/^coach/i.test(b.type)?'coaching':String(b.type||'').toLowerCase().split(' ')[0],country=str(b.country,60).toLowerCase(),ES=" ESCAPE '\\'";
 /* A = institutions that published a profile (listed=1). B = real registered workspaces that never published one (they are shown by name, type and country only, so search is never empty; an institution that was explicitly unlisted stays hidden). */
 let sa='SELECT sub,name,itype,country,city,address,phone,email,wa,admission,about,logo FROM directory WHERE listed=1',
  sb="SELECT i.sub AS sub,i.name AS name,i.itype AS itype,i.country AS country,'' AS city,'' AS address,'' AS phone,'' AS email,'' AS wa,'open' AS admission,'' AS about,'' AS logo FROM institutions i JOIN ws_meta m ON m.sub=i.sub WHERE NOT EXISTS(SELECT 1 FROM directory d WHERE d.sub=i.sub)";const a=[],c=[];
 if(q){const l=lk(q);sa+=' AND (name LIKE ?'+ES+' OR city LIKE ?'+ES+' OR country LIKE ?'+ES+' OR address LIKE ?'+ES+' OR itype LIKE ?'+ES+')';a.push(l,l,l,l,l);
  sb+=' AND (i.name LIKE ?'+ES+' OR i.country LIKE ?'+ES+' OR i.itype LIKE ?'+ES+')';c.push(l,l,l)}
 if(TYK[tk]){sa+=' AND itype LIKE ?';a.push(TYK[tk]);sb+=' AND i.itype LIKE ?';c.push(TYK[tk])}
 if(country&&country!=='all'&&country!=='global'){const al=CAL[country]||[country];sa+=' AND ('+al.map(()=>'country LIKE ?'+ES).join(' OR ')+')';al.forEach(x=>a.push(lk(x)));
  sb+=' AND ('+al.map(()=>'i.country LIKE ?'+ES).join(' OR ')+')';al.forEach(x=>c.push(lk(x)))}
 if(loc){const l=lk(loc);sa+=' AND (city LIKE ?'+ES+' OR address LIKE ?'+ES+' OR country LIKE ?'+ES+')';a.push(l,l,l);
  sb+=' AND i.country LIKE ?'+ES;c.push(l)}
 const sql='SELECT * FROM ('+sa+' UNION ALL '+sb+') ORDER BY name LIMIT 50';
 const r=(await sq(env,sql,...a,...c).all()).results||[];return J({items:r.map(x=>({sub:x.sub,name:x.name,type:x.itype,country:x.country,city:x.city,address:x.address,phone:x.phone,email:x.email,wa:x.wa,admission:x.admission,about:x.about,logo:x.logo}))})}
async function instPublish(C){
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');await tenantAuth(C,sub,['Admin']);
 const p=isO(b.profile)?b.profile:{};if(!str(p.name,120))throw new Err(400,'name is required');
 const email=str(p.email,80);if(email&&!MAILRX.test(email))throw new Err(400,'invalid email');
 const adm=['open','waitlist','closed'].includes(p.admission)?p.admission:'open';
 await sq(env,"INSERT INTO directory(sub,name,itype,country,city,address,phone,email,wa,admission,about,logo,listed,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(sub) DO UPDATE SET name=excluded.name,itype=excluded.itype,country=excluded.country,city=excluded.city,address=excluded.address,phone=excluded.phone,email=excluded.email,wa=excluded.wa,admission=excluded.admission,about=excluded.about,logo=excluded.logo,listed=excluded.listed,updated=excluded.updated",
  sub,str(p.name,120),str(p.type,40),str(p.country,60),str(p.city,60),str(p.address,160),str(p.phone,30),email,str(p.wa,30),adm,str(p.about,400),okLogo(p.logo),p.listed?1:0,iso()).run();
 return J({ok:true})}
async function admitApply(C){
 const{b,env,ip}=C,sub=wsn(b.sub),a=isO(b.applicant)?b.applicant:{};if(!SUBRX.test(sub))throw new Err(404,'institution not found');
 if(hitMem('ad:'+ip,6,3600000)||await hit(env,'ad:'+ip,5,3600)||await hit(env,'ads:'+sub,100,3600))throw new Err(429,'Too many applications. Try again later.');
 let d=await sq(env,'SELECT name,email,admission FROM directory WHERE sub=? AND listed=1',sub).first();
 if(!d){const w=await sq(env,'SELECT i.name AS name FROM institutions i JOIN ws_meta m ON m.sub=i.sub WHERE i.sub=? AND NOT EXISTS(SELECT 1 FROM directory d WHERE d.sub=i.sub)',sub).first(); /* registered workspace with no published profile: the request goes to its Admin inbox and the admin's e-mail */
  if(w){const ad=await sq(env,"SELECT mail FROM ws_index WHERE sub=? AND role='Admin' AND mail<>'' LIMIT 1",sub).first();d={name:w.name,email:ad&&ad.mail||'',admission:'open'}}}
 if(!d)throw new Err(404,'institution not found');if(d.admission==='closed')throw new Err(403,'Admissions are closed');
 const v={name:str(a.name,80),dob:str(a.dob,12),cls:str(a.cls,80),guardian:str(a.guardian,80),phone:str(a.phone,24),email:str(a.email,80),place:str(a.place,80),note:str(a.note,500)};
 if(!v.name||!v.cls||!v.guardian||!PHONERX.test(v.phone.replace(/[\s-]/g,'')))throw new Err(400,'Fill in name, class, guardian and a valid phone');
 if(v.email&&!MAILRX.test(v.email))throw new Err(400,'Enter a valid email');
 const id='ADM-'+rnd(5).toUpperCase();
 await sq(env,'INSERT INTO admissions(id,sub,name,dob,cls,guardian,phone,email,place,note,at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',id,sub,v.name,v.dob,v.cls,v.guardian,v.phone,v.email,v.place,v.note,iso()).run();
 bg(C,sendMail(env,d.email,'New admission request: '+v.name,`<h3>${E(d.name)}</h3><p><b>${E(v.name)}</b> · ${E(v.cls)}</p><p>Guardian: ${E(v.guardian)}<br>Phone: ${E(v.phone)}<br>Email: ${E(v.email||'-')}<br>From: ${E(v.place||'-')}<br>DOB: ${E(v.dob||'-')}</p><p>${E(v.note||'')}</p>`,`${v.name} · ${v.cls} · ${v.guardian} · ${v.phone}`));
 return J({ok:true,id})}
async function admitInbox(C){
 const sub=wsn(C.b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');await tenantAuth(C,sub,['Admin']);
 const r=(await sq(C.env,'SELECT id,name,dob,cls,guardian,phone,email,place,note,at,status FROM admissions WHERE sub=? ORDER BY at DESC LIMIT 200',sub).all()).results||[];return J({items:r})}

/* ───────────── AI ───────────── */
async function aiRun(C,s,system,prompt,max){
 const{env}=C;if(!env.AI)throw new Err(503,'AI not configured');
 if(hitMem('ai:'+C.ip,30,3600000)||await spend(env,'ai:'+s.sub,1,+env.AI_DAILY_CAP||300,86400))throw new Err(429,'rate limited');  {const cp=await confirmedPlan(env,s.sub).catch(()=>null),pn=cp&&cp.name||'',lim=/^starter/i.test(pn)?150:/^institution/i.test(pn)?600:/^sovereign/i.test(pn)?Infinity:30;if(lim!==Infinity&&await spend(env,'aim:'+s.sub,1,lim,2678400))throw new Err(429,'Monthly AI limit reached for your plan ('+lim+'). Upgrade under Pricing')}
 const r=await env.AI.run('@cf/meta/llama-3.1-8b-instruct',{messages:[{role:'system',content:system},{role:'user',content:prompt}],max_tokens:max}),text=String(r&&r.response||'').trim();
 if(!text)throw new Err(502,'empty response');return J({text})}
async function aiPaper(C){
 const s=await need(C,['Admin','Teacher','Supervisor']),b=C.b,s1=str(b.subject,120).replace(/"/g,''),c=str(b.chapter,160).replace(/"/g,'');if(!s1||!c)throw new Err(400,'subject and chapter required');
 const d=['Easy','Medium','Hard'].includes(b.difficulty)?b.difficulty:'Medium',k=['Exam paper','Syllabus outline','Lesson plan'].includes(b.kind)?b.kind:'Exam paper';
 return aiRun(C,s,'You are an academic assistant for schools, madrasahs and universities. Reply with plain text only.',`Create a ${k} for subject "${s1}", chapter "${c}", difficulty ${d}. Include marks and clear sections.`,1200)}
async function aiReport(C){
 const s=await need(C,['Admin','Teacher','Supervisor']),st=isO(C.b.student)?C.b.student:{},n=v=>v==null||v===''||!isFinite(+v)?'not available':String(Math.round(+v*100)/100),h=Array.isArray(st.hifz)?st.hifz.slice(0,3).map(x=>Math.max(0,Math.round(+x)||0)).join('/'):'none';
 return aiRun(C,s,'You write short, kind, factual student progress reports for guardians. Plain text only, under 180 words.',`Student: ${str(st.name,60).replace(/"/g,'')}. Attendance percent: ${n(st.attendance)}. Exam average percent: ${n(st.average)}. GPA out of 5: ${n(st.gpa)}. Hifz log counts (very good / good / needs improvement): ${h}. Give strengths, focus areas and one next step.`,500)}

/* ───────────── founder telemetry and tools ───────────── */
async function telegram(C){
 const{b,env,ip,req}=C;if(hitMem('tg:'+ip,40,3600000))throw new Err(429,'rate limited');
 let type=str(b.type,60)||'EVENT';
 if(!/^(THREAT|FEEDBACK|NEW_INSTITUTION|UNKNOWN_DEVICE)/.test(type)&&b.name!=null&&b.size!=null){b.itype=type;type='NEW_INSTITUTION'}
 if(type==='NEW_INSTITUTION'){
  const sub=wsn(b.sub);if(b.sub&&(!SUBRX.test(sub)||RESERVED.includes(sub)||sub!==String(b.sub)))throw new Err(400,'invalid subdomain');
  if(b.email&&!MAILRX.test(String(b.email)))throw new Err(400,'invalid email');
  if(sub)await env.DB.prepare('INSERT OR IGNORE INTO institutions(sub,name,itype,country,created_at) VALUES(?,?,?,?,?)').bind(sub,str(b.name,120),str(b.itype,40),str(b.country,80),iso()).run().catch(()=>{});
  await r2log(env,'NEW_INSTITUTION',`${sub} · ${b.name} · ${b.country}`,ip);
  const cf=req.cf||{},v=k=>X(String(b[k]??'-').slice(0,300)||'-');
  const msg=`🏛️ <b>NEW INSTITUTION REGISTERED</b>\n━━━━━━━━━━━━━━━━━━\n🏫 <b>${v('name')}</b> · ${v('itype')} · 👥 ${v('size')}\n🔗 ${v('url')}\n🆔 <code>${v('sub')}</code>\n\n🌍 <b>Country:</b> ${v('country')}\n📍 <b>Address:</b> ${v('address')}\n\n👤 <b>Founder / Principal:</b> ${v('founder')}\n✉️ ${v('email')}\n📱 ${v('phone')}\n\n📅 <b>UTC:</b> ${v('utc')}\n🌐 <b>IP:</b> ${X(ip)}${cf.country?' · '+X(cf.country):''}${cf.asn?' · AS'+X(cf.asn):''}\n🖥️ <b>Device:</b> <code>${v('fp')}</code>\n🧭 ${v('ua')}\n━━━━━━━━━━━━━━━━━━\n✅ ClasSphera v${X(b.v||APP_V)}`;
  return await tg(env,msg)?J({ok:true}):J({error:'telegram unavailable'},502)}
 const f=['institution','institutionId','subdomain','sub','mail','role','name','itype','size','topic','message','detail','note','fp','at','lang','tz','screen','webdriver','online','ua'];
 const icon=type.startsWith('THREAT')?'🚨':type==='FEEDBACK'?'📨':type==='UNKNOWN_DEVICE'?'📵':'🏫';
 const body=f.filter(k=>b[k]!==undefined&&b[k]!==null&&b[k]!=='').map(k=>`<b>${k==='itype'?'type':k}</b>: ${X(String(b[k]).slice(0,500))}`).join('\n');
 if(type.startsWith('THREAT')||type==='UNKNOWN_DEVICE'){await dbAudit(env,type,String(b.detail||b.note||b.sub||'').slice(0,300),ip);await r2log(env,type,String(b.detail||b.note||b.sub||''),ip)}
 return await tg(env,`${icon} <b>${X(type)}</b>\nIP: ${X(ip)}${req.cf&&req.cf.country?' · '+X(req.cf.country):''}\n${body}`)?J({ok:true}):J({error:'telegram unavailable'},502)}
async function fAlert(C){
 const{env,ip}=C;if(hitMem('fa:'+ip,12,3600000))return J({ok:true,limited:true},202);
 const p=envelope(C),kind=str(p.kind,40).replace(/[^A-Z0-9_a-z-]/g,'')||'CLIENT_ALERT',sub=SUBRX.test(String(p.sub||p.tenant||''))?String(p.sub||p.tenant):null;
 const d={version:str(p.version,20),previous:str(p.previous,20),url:str(p.url,200),online:p.online,detail:p.detail&&JSON.stringify(p.detail).slice(0,500),ua:str(p.ua,160)};
 const sent=await sysAlert(env,kind,d,{sub,ip,key:kind+'|'+d.version+'|'+String(d.detail).slice(0,100),ttl:3600});return J({ok:true,sent})}
async function fMail(C){
 const{env,ip}=C;if(hitMem('fm:'+ip,6,3600000))return J({ok:true,limited:true},202);
 const p=envelope(C),kind=str(p.kind,40)||'CLIENT_ALERT',d=JSON.stringify(p).slice(0,1500);
 const ok=await sendMail(env,env.FOUNDER_EMAIL||FOUNDER_MAIL,'ClasSphera alert: '+kind,`<pre>${X(d)}</pre>`,d)||await sysAlert(env,kind,d,{ip,ttl:3600});return J({ok:true,sent:!!ok})}
async function fHealth(C){
 const{b,env,ip}=C;if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await fail(env,ip,'founder health');throw new Err(403,'rejected')}
 const c=async q=>(await env.DB.prepare(q).first())||{},since=new Date(Date.now()-864e5).toISOString();
 const[i,p,po,pay,al,ev]=await Promise.all([c('SELECT COUNT(*) AS n FROM institutions'),c('SELECT COUNT(*) AS n,COALESCE(SUM(size),0) AS bytes FROM ws_parts'),c('SELECT COUNT(*) AS n FROM portal'),c("SELECT COUNT(*) AS n FROM payments WHERE status='pending'"),env.DB.prepare('SELECT COUNT(*) AS n FROM alerts WHERE at>?').bind(since).first(),c('SELECT COUNT(*) AS n FROM events')]);
 return J({ok:true,app:APP_V,schema:SCHEMA[SCHEMA.length-1][0],dataSchema:DATA_SCHEMA,institutions:i.n,sections:p.n,bytes:p.bytes,portalRows:po.n,pendingPayments:pay.n,alerts24h:al&&al.n,events:ev.n,r2:!!env.R2,ai:!!env.AI,mail:!!env.MAIL_KEY,sms:false,inapp:true,email:!!(env.EMAIL||env.SEND_EMAIL)})}
async function fRestore(C){
 const{b,env,ip}=C;if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await fail(env,ip,'founder restore');throw new Err(403,'rejected')}
 if(!env.R2)throw new Err(503,'R2 is not connected');const sub=wsn(b.sub),key=String(b.snapshot||'');if(!SUBRX.test(sub)||!key.startsWith(`snapshots/${sub}/`))throw new Err(400,'invalid snapshot');
 const o=await env.R2.get(key);if(!o)throw new Err(404,'snapshot not found');const snap=JSON.parse(await o.text());if(!snap||snap.sub!==sub||!isO(snap.parts))throw new Err(400,'invalid snapshot');
 await snapshotTenant(env,sub,'pre-restore').catch(()=>{});
 const keys=Object.keys(snap.parts).filter(k=>KEYRX.test(k)),cur=await partMeta(env,sub,keys),revs={},parts={};
 for(const k of keys){revs[k]=cur.get(k)?cur.get(k).rev:0;parts[k]=JSON.stringify(snap.parts[k].data)}
 const r=await commitParts(env,sub,{parts,del:[],revs});if(r.conflict)throw new Err(409,'Workspace changed during restore. Try again.');
 if(Array.isArray(snap.parts.users&&snap.parts.users.data)){const us=snap.parts.users.data;if(!checkUsers(us))await env.DB.batch(idxStmts(env,sub,us));await env.KV.put('sxr:'+sub,String(nowS()),{expirationTtl:90000})}
 await alert(env,ip,'Workspace restored',`${sub} from ${key}`);return J({ok:true,restored:keys.length})}

/* ───────────── OAuth (Google redirect flow) ───────────── */
async function oauthCallback(env,u){
 const bad=c=>{c=String(c||'failed').replace(/[^\w-]/g,'').slice(0,48)||'failed';console.warn('[ClasSphera] Google sign-in failed: '+c);return Response.redirect(u.origin+'/#oauth_error:'+c,302)};
 try{const g=gcfg(env);if(!g.ok){console.warn('[ClasSphera] Google sign-in is not configured. Missing: '+g.missing.join(', '));return bad('not_configured')}
  const st=u.searchParams.get('state')||'',code=u.searchParams.get('code')||'',ge=u.searchParams.get('error');
  const okState=st?!!(await env.KV.get('os:'+st)):false;if(st)await env.KV.delete('os:'+st);
  if(ge)return bad(ge==='access_denied'?'access_denied':'google_'+ge);
  if(!okState)return bad('state_expired');
  if(!code)return bad('no_code');
  const tr=await fetch('https://oauth2.googleapis.com/token',{method:'POST',body:new URLSearchParams({code,client_id:g.id,client_secret:g.sec,redirect_uri:u.origin+(u.pathname==='/auth/callback'?'/auth/callback':'/api/oauth/google/callback'),grant_type:'authorization_code'})}),t=await tr.json().catch(()=>({}));
  if(!t.access_token){console.warn('[ClasSphera] Google token exchange said: '+(t.error||tr.status)+' '+(t.error_description||''));return bad('token_'+(t.error||('http_'+tr.status)))}
  const pr=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{authorization:'Bearer '+t.access_token}}),p=await pr.json().catch(()=>({}));
  if(!p.email)return bad('profile');
  if(p.email_verified!==true)return bad('email_not_verified');
  const c=rnd(16);await env.KV.put('oc:'+c,JSON.stringify({email:p.email,name:p.name||''}),{expirationTtl:300});return Response.redirect(u.origin+'/#oauth:'+c,302)}
 catch(e){console.error('[ClasSphera] Google callback exception: '+(e&&e.message));return bad('failed')}}
async function oauthClaim(C){const k='oc:'+String(C.b.code||'').slice(0,40),v=await C.env.KV.get(k);if(!v)throw new Err(410,'expired');await C.env.KV.delete(k);return JR(v)}
async function health(C){
 const t0=Date.now(),o={ok:true,app:APP_V,schema:API_SCHEMA,dataSchema:DATA_SCHEMA,time:iso()};
 if(C.u.searchParams.get('deep')==='1'){
  if(hitMem('hd:'+C.ip,10,60000))throw new Err(429,'rate limited');
  try{await C.env.DB.prepare('SELECT 1').first();o.db=true}catch{o.db=false;o.ok=false}
  try{await C.env.KV.get('health:probe');o.kv=true}catch{o.kv=false;o.ok=false}
  o.r2=!!C.env.R2;o.ai=!!C.env.AI;o.ms=Date.now()-t0;
  if(!o.ok)bg(C,sysAlert(C.env,'HEALTH_DEGRADED',JSON.stringify(o),{ttl:900}))}
 return J(o,o.ok?200:503)}

/* ───────────── API router ───────────── */
const R={
 '/api/telegram':telegram,'/api/master-override':masterOverride,'/api/oauth/claim':oauthClaim,'/api/id/new':idNew,'/api/subdomain/check':subCheck,
 '/api/ws/create':wsCreate,'/api/ws/find':wsFind,'/api/ws/salt':wsSalt,'/api/ws/login':wsLogin,'/api/ws/load':wsLoad,'/api/ws/save':wsSave,'/api/ws/recover':wsRecover,'/api/ws/recover/enroll':recEnroll,
 '/api/otp/verify':otpVerify,'/api/session/check':sessCheck,'/api/session/logout':sessLogout,'/api/devices/list':devList,'/api/devices/revoke':devRevoke,
 '/api/passkey/challenge':pkChallenge,'/api/passkey/register':pkRegister,'/api/passkey/verify':pkVerify,'/api/mfa/totp/enable':totpEnable,'/api/mfa/totp/verify':totpVerify,
 '/api/preferences':prefs,'/api/schema/fields':schemaFields,'/api/audit':clientEvent,'/api/sync':clientEvent,
 '/api/notify':notifyLegacy,'/api/notify/sms':notifyCh,'/api/notify/whatsapp':notifyCh,'/api/notify/push':notifyCh,
 '/api/checkout':checkout,'/api/checkout/verify':checkoutVerify,'/api/pay/sms':paySms,'/api/backup':backup,'/api/stripe/webhook':stripeHook,
 '/api/g/sync':gSync,'/api/g/login':gLogin,'/api/g/data':gData,'/api/g/send':gSend,'/api/g/reply':gReply,'/api/g/notice':gNotice,'/api/g/inbox':gInbox,'/api/g/otp':gOtp,'/api/g/quick':gQuick,'/api/g/react':gReact,'/api/g/seen':gSeen,'/api/g/typing':gTyping,'/api/push/key':pushKey,'/api/push/sub':pushSub,'/api/push/peek':pushPeek,
 '/api/inst/search':instSearch,'/api/inst/publish':instPublish,'/api/admit/apply':admitApply,'/api/admit/inbox':admitInbox,
 '/api/ai':aiPaper,'/api/ai/report':aiReport,
 '/api/founder/system-alert':fAlert,'/api/founder/webhook':fAlert,'/api/founder/email-fallback':fMail,'/api/founder/health':fHealth,'/api/founder/payment':fPayment,'/api/founder/plan-reminders':fRemind,'/api/founder/restore':fRestore};
/* ───────────── payment fixes: tamper-proof receipt links + cloud-synced drafts (used by the app's Pay Now / Payment Approvals) ───────────── */
const pzMac=async(env,j)=>(await hmac(env,'pzrcpt|'+j)).slice(0,32);
async function pzRcSign(C){const s=await need(C,['Admin','Accountant']),{env,b}=C,j=String(b.j||'');if(!j||j.length>2000)throw new Err(400,'bad receipt');
 let r;try{r=JSON.parse(j)}catch{throw new Err(400,'bad receipt')}
 const rno=str(isO(r)&&r.n,40),trx=str(isO(r)&&r.t,40).toLowerCase(),ref=str(b.ref,20);if(!rno||!trx||!(+r.a>0))throw new Err(400,'bad receipt');
 await migrate(env);const sig=await pzMac(env,j),now=Date.now(),ex=await sq(env,'SELECT ref FROM pz_receipts WHERE inst=? AND trx=?',s.sub,trx).first();
 if(ex&&ex.ref!==ref)throw new Err(409,'duplicate_trxid'); /* the same TrxID can never back two different payments */
 if(ex)await sq(env,'UPDATE pz_receipts SET rno=?,sig=?,at=? WHERE inst=? AND trx=?',rno,sig,now,s.sub,trx).run();
 else await sq(env,'INSERT INTO pz_receipts(inst,trx,ref,rno,sig,revoked,at) VALUES(?,?,?,?,?,0,?)',s.sub,trx,ref,rno,sig,now).run();
 return J({sig})}
async function pzRcVerify(C){const{env,b}=C,j=String(b.j||''),sig=String(b.sig||'');if(!/^[0-9a-f]{32}$/.test(sig)||!j||j.length>2000)return J({ok:false});
 const m=await pzMac(env,j);let d=0;for(let i=0;i<32;i++)d|=m.charCodeAt(i)^sig.charCodeAt(i);if(d)return J({ok:false});
 try{await migrate(env);const r=await sq(env,'SELECT revoked FROM pz_receipts WHERE sig=?',sig).first();if(r&&r.revoked)return J({ok:false,revoked:true})}catch{}
 return J({ok:true})}
async function pzDraftRoute(C){const t=await feeWho(C),{env,b}=C,who=t.who==='student'?'s':'g';await migrate(env);
 if(b.op==='get'){const r=await sq(env,'SELECT body FROM pz_drafts WHERE sub=? AND sid=? AND who=?',t.sub,t.sid,who).first();let d={};try{d=JSON.parse(r&&r.body||'{}')}catch{}return J({draft:isO(d)?d:{}})}
 if(b.op==='put'){if(hitMem('pzd:'+t.sub+':'+t.sid,300,3600000))throw new Err(429,'rate limited');
  const src=isO(b.draft)?b.draft:{},out={};
  for(const id of Object.keys(src).slice(0,20)){const v=src[id];if(!isO(v)||(v.st!=='draft'&&v.st!=='pending'))continue;
   out[str(id,60)]={st:v.st,sc:v.sc==='G'?'G':'L',m:str(v.m,20),n:str(v.n,60),t:str(v.t,40),a:Math.max(0,+v.a||0),cur:/^[A-Z]{3}$/.test(v.cur||'')?v.cur:'BDT',sub:/^P[0-9A-F]{8}$/.test(v.sub||'')?v.sub:undefined,at:+v.at||0}}
  const body=JSON.stringify(out);if(body.length>6000)throw new Err(400,'too large');
  await sq(env,'INSERT INTO pz_drafts(sub,sid,who,body,updated) VALUES(?,?,?,?,?) ON CONFLICT(sub,sid,who) DO UPDATE SET body=excluded.body,updated=excluded.updated',t.sub,t.sid,who,body,Date.now()).run();
  return J({ok:true})}
 throw new Err(400,'bad request')}
Object.assign(R,{'/api/receipt/sign':pzRcSign,'/api/receipt/verify':pzRcVerify,'/api/g/draft':pzDraftRoute});
Object.assign(R,{'/api/fee/mine':feeMine,'/api/fee/draft':feeDraft,'/api/fee/submit':feeSubmit,'/api/fee/queue':feeQueue,'/api/fee/decide':feeDecide,'/api/fee/announce':feeAnnounce,'/api/fee/rule':feeRuleRoute,'/api/fee/cfg':feeCfgRoute});
/* ───────────── saved guardian / student profile: one small row per person, read once at sign-in and written only when something changes ───────────── */
async function gvProfRoute(C){const t=await feeWho(C),{env,b}=C,who=t.who==='student'?'s':'g';await migrate(env);
 if(b.op==='get'){const r=await sq(env,'SELECT body,updated FROM gv_prof WHERE sub=? AND sid=? AND who=?',t.sub,t.sid,who).first();let d={};try{d=JSON.parse(r&&r.body||'{}')}catch{}return J({prof:isO(d)?d:{},updated:r?+r.updated:0})}
 if(b.op==='put'){if(hitMem('gvp:'+t.sub+':'+t.sid,60,3600000))throw new Err(429,'rate limited');
  const src=isO(b.prof)?b.prof:{},sp=isO(src.p)?src.p:{},out={p:{},hub:{},hw:[]};
  for(const k of Object.keys(sp).slice(0,60)){if(!/^[A-Za-z0-9_]{1,24}$/.test(k)||k==='pq'||k==='pay'||k==='__proto__')continue;const v=sp[k];
   if(k==='sp'||k==='gp'){if(typeof v==='string'&&v.length<=200000&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(v))out.p[k]=v;continue} /* photos: small images only */
   const j=JSON.stringify(v===undefined?null:v);if(j.length<=20000)out.p[k]=v}
  if(isO(src.hub)){const j=JSON.stringify(src.hub);if(j.length<=60000)out.hub=src.hub}
  if(Array.isArray(src.hw))out.hw=src.hw.slice(-60).map(x=>str(x,200));
  const body=JSON.stringify(out);if(body.length>380000)throw new Err(400,'too large');
  const now=Date.now();await sq(env,'INSERT INTO gv_prof(sub,sid,who,body,updated) VALUES(?,?,?,?,?) ON CONFLICT(sub,sid,who) DO UPDATE SET body=excluded.body,updated=excluded.updated',t.sub,t.sid,who,body,now).run();
  return J({ok:true,updated:now})}
 throw new Err(400,'bad request')}
Object.assign(R,{'/api/g/profile':gvProfRoute});
const BODY_LIMIT={'/api/g/profile':4e5,'/api/ws/save':30e6,'/api/ws/create':30e6,'/api/g/sync':25e6,'/api/backup':26e6,'/api/founder/restore':1e5};
const MUTATING=new Set(['/api/ws/save','/api/ws/create','/api/g/sync','/api/backup','/api/preferences']);
async function api(req,env,ctx,u,ip,tenant){
 const t0=Date.now(),p=u.pathname,C={req,env,ctx,u,ip,tenant,path:p,host:u.hostname.toLowerCase(),b:{},raw:''};
 try{
  needBindings(env);
  const o=req.headers.get('origin');let foreign=false;if(o){try{foreign=new URL(o).host!==u.host}catch{foreign=true}}
  if(foreign&&p!=='/api/stripe/webhook')return J({error:'forbidden'},403);
  if(await memo('ban:'+ip,15000,()=>env.KV.get('ban:'+ip)))return J({error:'Temporarily blocked. Try again in 15 minutes.'},429);
  if(hitMem('rl:'+ip,300,60000))return J({error:'Too many requests'},429);
  if(req.method==='GET'){
   if(p==='/api/health')return await health(C);
   if(p==='/api/version')return J({app:APP_V,schema:API_SCHEMA,dataSchema:DATA_SCHEMA,db:SCHEMA[SCHEMA.length-1][0]});
   if(p==='/api/oauth/google/start'){
    const g=gcfg(env);
    if(!g.ok){console.warn('[ClasSphera] Google sign-in is not configured. Missing Worker binding(s): '+g.missing.join(', '));return J({error:'Google sign-in is not configured on the server. Missing: '+g.missing.join(', ')+'.',missing:g.missing},503)}
    const st=rnd(16);await env.KV.put('os:'+st,'1',{expirationTtl:600});
    return J({url:'https://accounts.google.com/o/oauth2/v2/auth?'+new URLSearchParams({client_id:g.id,redirect_uri:u.origin+(u.searchParams.get('cb')==='auth'?'/auth/callback':'/api/oauth/google/callback'),response_type:'code',scope:'openid email profile',state:st,prompt:'select_account'})})}
   if(p==='/api/oauth/google/callback')return await oauthCallback(env,u);
   if(p==='/api/inst/logo')return await instLogo(C);
   if(p==='/api/fee/verify')return await feeVerify(C);
   return J({error:'not found'},404)}
  if(req.method!=='POST')return J({error:'not found'},404);
  const h=R[p];if(!h)return J({error:'not found'},404);
  const lim=BODY_LIMIT[p]||262144,cl=+req.headers.get('content-length')||0;if(cl>lim)return J({error:'too large'},413);
  C.raw=await req.text();if(C.raw.length>lim)return J({error:'too large'},413);
  if(C.raw){try{const x=JSON.parse(C.raw);C.b=isO(x)?x:{}}catch{if(p!=='/api/stripe/webhook')return J({error:'invalid json'},400)}}
  const cv=req.headers.get('x-app-schema-version')||'';
  if(cv){const maj=+cv.split('.')[0];C.clientMajor=maj||0;
   if(maj&&maj!==+API_SCHEMA.split('.')[0])bg(C,sysAlert(env,'API_SCHEMA_MISMATCH',`client ${cv} · server ${API_SCHEMA} · ${p}`,{key:cv+'|'+API_SCHEMA,ttl:21600,ip}));
   if(maj&&maj<MIN_CLIENT_MAJOR&&MUTATING.has(p))return J({error:'Please refresh the app to continue.',code:'client_outdated'},426)}
  await migrate(env);
  const res=await h(C),dur=Date.now()-t0;
  if(dur>(+env.SLOW_MS||4000))bg(C,sysAlert(env,'PERF_SLOW',`${p} took ${dur} ms`,{key:p,ttl:1800,ip}));
  return res
 }catch(e){
  if(e instanceof Err)return J({error:e.message,...e.extra},e.status);
  bg(C,sysAlert(env,'WORKER_EXCEPTION',`${p}: ${String(e&&e.message).slice(0,200)}`,{key:p+String(e&&e.message).slice(0,60),ttl:900,ip}));
  console.error('[ClasSphera] '+p+' failed: '+(e&&e.stack||e));
  if(p==='/api/ws/create')return J({error:whyOf(e),code:'internal_error'},500); /* the real reason, so sign-up problems can be fixed from the screen */
  return J({error:'server error'},500)}}

/* ───────────── SEO: pages, sitemap, robots, manifest, service worker, icons ───────────── */
const HERO='One Platform. Complete Control of Your Institution.';
const INTRO='One workspace for enrollment, attendance, marks, fees and guardian communication. Every institution gets its own isolated subdomain and starts completely empty.';
const PAYTXT='Pay with bKash, Nagad, Rocket, SSLCommerz, Visa, Mastercard, Stripe, PayPal, Bitcoin or USDT Vault.';
const PRODS=[['Enrollment','Admissions, student profiles and guardian records.'],['Attendance Support','ID-card scan logs for students and ustads, with guardian alerts.'],['Learning Management','Routines, homework diaries and teacher feedback.'],['Assessment','Digital marksheets and instant merit lists.'],['Connected Intelligence','AI question papers, syllabus outlines and lesson plans.'],['Analytics and Insights','Progress graphs and class averages.'],['Finance Vault','Encrypted ledger, fee collection and receipts.'],['Secure Messaging','Guardian to teacher conversations.'],['Staff Management','Ustad records, salaries and credentials.'],['Security Center','Role-based access, tamper detection and threat alerts.']];
const PLANS=[['Free','Up to 100 students',0,['Student and staff registers','Attendance with automatic guardian updates','Marksheets, fees and receipts','Real-time guardian chat and alerts','Student and guardian portals','Digital ID cards and notices','Homework, timetable, library, MCQ exams and Hifz log','30 AI generations a month','Isolated workspace, passkeys, MFA and four roles','Community support']],['Starter','Up to 500 students',29,['Everything in Free','Exams, transport, hostel and meals','Certificates and reports center','Assessment grading and batch or shift setup','AI report assistant and 150 AI generations a month']],['Institution','Up to 1,500 students',79,['Everything in Starter','Leave and payroll, inventory and assets','Admissions pipeline and alumni','Sadaqah and Zakat vault','Public website builder','Your logo and colours across the workspace','Credit, GPA, transcripts and thesis tracking','600 AI generations a month']],['Sovereign','Unlimited, multi-campus',199,['Everything in Institution','Unlimited students and AI generations','Live CCTV rooms','Multi-campus dashboard','Custom domain','Priority support']]]; const SOLS=[['Schools','Class routines, homework diaries, guardian alerts and report cards.'],['Madrassas','Hostel and meal tracking, Quran progress, Sadaqah ledger and ustad records.'],['Coaching centers','Batch attendance, mock tests and recurring fees.'],['Colleges','Departments, semester results, fee collection and staff payroll.'],['Universities','Faculty, department, program and batch hierarchy at large scale.']];
const ALLSOL=[['Student records','Profiles, guardians, residence and results.'],['Staff management','Credentials, salaries and joining dates.'],['Financial ledgers','Income, expenses, dues, loans and receipts.'],['Institutional hierarchies','Campus, faculty, department, class and batch.']];
const OSL=[['Data layer','One isolated workspace per institution, stored under its own subdomain.'],['Identity layer','Four roles with separate permissions and token sessions that end on inactivity.'],['Intelligence layer','AI papers, lesson plans, merit lists and progress analytics.'],['Communication layer','Guardian alerts under your branded sender name and secure messaging.']];
const HELP=[['Set up your institution','Sign up, choose a subdomain, and save the recovery code shown once at the end.'],['Add team members','Settings and team: add teachers, accountants and guardians with their roles.'],['Add students and staff','Lists start empty. Press Add on Students or Staff.'],['Enter marks','Marksheets: type a subject, enter scores, and the merit list updates.'],['Collect fees','Finance vault lists students with a fee set. Press Collect to log it and print a receipt.'],['Locked out?','Contact the QVMPXT founder. A master key regenerates the administrator password.']];
const TRUST=[['Isolated workspaces','Each institution lives on its own subdomain with its own data, never shared.'],['Role-based access','Admins, teachers, accountants and guardians each see only what they need.'],['Encrypted ledger','Finance records are sealed with AES-256 before they are stored.'],['Founder threat alerts','Suspicious sign-ins and injection attempts are logged and reported at once.']];
const TERMS=['ClasSphera is operated by QVMPXT. Each institution owns the records it enters and must keep its administrator credentials and recovery code safe.','Subscriptions renew on the cycle you choose. A payment counts as received only after the payment gateway confirms it.','Attempts to break into or tamper with any workspace are logged and reported to the founder.'];
const PRIVACY=['Each institution’s data lives in its own isolated workspace and is never mixed with another’s.','Security alerts and feedback sent to the founder include device and browser details to help investigate abuse.','Guardian phone numbers are used only to send the alerts your institution triggers.'];
const ENT=[
['ver','Version History & One-Click Rollback','Immutable pre-update snapshots for students, Hifz, results and fees. Compare versions and restore instantly.'],
['rbac','Access Control & Audit Trail','Six role tiers, a hash-chained activity log, passkey and OTP two-step sign-in and AES-256 tenant isolation.'],
['fields','Dynamic Custom Field Builder','Add Hifz Para, Kitab Khana, credit hours, thesis or any field to any module without waiting for a release.'],
['notify','Multi-Channel Guardian Alerts','Attendance, fee, result and notice alerts reach guardians as push notifications with your institution’s name, logo and the full message, and are also kept in the guardian’s inbox and notice board. iPhone needs the site added to the Home Screen first. If a guardian blocks notifications, share the notice by WhatsApp or SMS.'],
['sync','Offline-First Sync Engine','An encrypted local queue that syncs to the cloud automatically the moment connection returns.'],
['health','Founder Health & Schema Guard','Detects version changes and unreadable data early and alerts the founder before users notice.'],
['campus','Multi-Campus & Branch Analytics','Compare attendance, fees and results across every campus and drill into any branch.'],
['finance','Financial & Sadaqah/Fee Reconciliation','Match receipts to bank and mobile-money records with Sadaqah, Lillah and Zakat kept separate.']];
const grid=(a,c='md:grid-cols-2')=>`<div class="grid ${c} gap-4">${a.map(x=>`<div class="glass p-5"><h3 class="font-bold">${E(x[0])}</h3><p class="text-sm mu mt-1">${E(x[1])}</p></div>`).join('')}</div>`;
const plans=()=>`<div class="grid md:grid-cols-2 lg:grid-cols-4 gap-4">${PLANS.map(p=>`<div class="glass p-5"><h3 class="font-bold text-lg">${E(p[0])}</h3><p class="text-xs mu">${E(p[1])}</p><p class="text-3xl font-bold my-3">${p[2]?`$${p[2]}/month`:'$0'}</p><p class="text-xs">${p[2]?`Yearly billing: $${p[2]*10}/year, saves $${p[2]*2} a year`:'Free forever'}</p><ul class="text-sm mt-2">${p[3].map(x=>`<li>✓ ${E(x)}</li>`).join('')}</ul></div>`).join('')}</div><p class="text-xs mu text-center mt-4">${E(PAYTXT)}</p>`;
const H1=t=>`<h1 class="text-2xl md:text-3xl font-extrabold mb-2">${E(t)}</h1><p class="text-sm mu mb-4">${E(BRAND)} · ${E(TAG)}</p>`,H2=t=>`<h2 class="text-xl md:text-2xl font-extrabold mt-12 mb-4">${E(t)}</h2>`;
const paras=a=>`<div class="glass p-5 text-sm space-y-3 max-w-2xl">${a.map(x=>`<p>${E(x)}</p>`).join('')}</div>`;
const pg=(path,v,hash,name,h1,desc,body,pr,cf)=>({path,v,hash,name,h1,pr:pr||'0.8',cf:cf||'monthly',body,desc:`${TAG} ${desc}`,title:path==='/'?`${BRAND} | ${TAG}`:`${name} | ${BRAND} – ${TAG}`});
const PAGES=[
 pg('/','home','','Home',HERO,'ClasSphera by QVMPXT is one secure platform for schools, madrasahs, coaching centers, colleges and universities: student records, attendance, marksheets, AI question papers, finance vault and guardian messaging.',()=>`<h1 class="text-3xl font-extrabold">${E(HERO)}</h1><p class="mt-3 text-sm mu">${E(BRAND)} · ${E(TAG)}</p><p class="mt-5 mu max-w-xl">${E(INTRO)}</p>${H2('Everything an institution runs on')}${grid(PRODS,'sm:grid-cols-2 lg:grid-cols-3')}${H2('Built for isolation and trust')}${grid(TRUST)}${H2('Pricing')}${plans()}`,'1.0','weekly'),
 pg('/login','home','login','Login','Log in to your institution workspace','ClasSphera by QVMPXT login: sign in to your school, madrasah, college or university workspace with two-step verification, passkeys and authenticator codes.',()=>`${H1('Login')}<p class="max-w-2xl">Sign in to your institution workspace with your institution address, phone number, email and secure password. New devices are verified with a one-time code, an authenticator app or a fingerprint / Face ID passkey.</p>`,'0.9','monthly'),
 pg('/signup','home','signup','Sign Up','Create your institution workspace','Sign up for ClasSphera by QVMPXT in three steps and get an isolated, encrypted workspace with its own subdomain, free for up to 100 student records.',()=>`${H1('Sign Up')}<p class="max-w-2xl">Create your institution in three steps: institution details, address and administrator. Every workspace gets its own subdomain, a unique secure ID and a recovery code, and starts completely empty.</p>${plans()}`,'0.9','monthly'),
 pg('/guardian-signup','guard','guardian-signup','Guardian Sign Up','Guardian sign in and registration','ClasSphera by QVMPXT guardian portal: parents see only their own child’s attendance, marks, fees, notices and secure messages with the school.',()=>`${H1('Guardian Sign Up')}<p class="max-w-2xl">Parents and guardians sign in with the registered mobile number and the secret PIN given by the institution. Students sign in with their admission ID and secret PIN. You see only your own child’s records.</p>`,'0.8','monthly'),
 pg('/student-signup','guard','student-signup','Student Sign Up','Student sign in and registration','ClasSphera by QVMPXT student portal: students open their own routine, homework, marksheet and Quran progress with an admission ID and PIN.',()=>`${H1('Student Sign Up')}<p class="max-w-2xl">Students sign in with the institution name, admission ID or roll number and a secret PIN. The student portal shows only your own routine, homework, marks and progress.</p>`,'0.8','monthly'),
 pg('/connect','connect','','Connect Us','Connect with the ClasSphera founder','Contact ClasSphera by QVMPXT: founder phone, WhatsApp and email, help and support, feedback, security guidelines and terms.',()=>`${H1('Connect Us')}<div class="glass p-5 max-w-xl"><p><b>${E(FOUNDER)}</b> · Sovereign Founder, QVMPXT</p><p class="mt-2"><a href="mailto:${FOUNDER_MAIL}">${FOUNDER_MAIL}</a></p><p><a href="tel:${FOUNDER_PHONE}">${FOUNDER_PHONE}</a></p></div>${H2('Help & support')}${grid(HELP)}`,'0.8','monthly'),
 pg('/download','home','app-download','App Download','Download and install the ClasSphera app','Install ClasSphera by QVMPXT on your phone or computer for fast, offline-ready access to your institution workspace.',()=>`${H1('App Download')}<p class="max-w-2xl">Install ClasSphera as an app: choose “Add to Home screen” on Android and iOS, or “Install app” in desktop Chrome and Edge. It works offline and syncs when you reconnect.</p>`,'0.7','monthly'),
 pg('/admission','admit','','Global Online Admission','Global Online Admission','Find a school, madrasah, college or university anywhere in the world on ClasSphera by QVMPXT and apply online directly to the institution.',()=>`${H1('Global Online Admission')}<p class="max-w-2xl">Search institutions by name, type, country and city, see whether admissions are open, and send your application by email or WhatsApp.</p>`,'0.8','weekly'),
 pg('/enterprise','enterprise','','Enterprise Suite','Enterprise Suite','ClasSphera by QVMPXT Enterprise Suite: version history and rollback, access control and audit trail, custom fields, guardian alerts, offline sync, health guard, campus analytics and reconciliation.',()=>`${H1('Enterprise Suite')}<p class="max-w-2xl">Enterprise-grade tools for madrasahs, schools, colleges and multi-campus universities.</p>${grid(ENT.map(x=>[x[1],x[2]]))}<ul class="mt-4">${ENT.map(x=>`<li><a href="/enterprise/${x[0]}">${E(x[1])}</a></li>`).join('')}</ul>`,'0.9','weekly'),
 ...ENT.map(x=>pg('/enterprise/'+x[0],'enterprise','enterprise:'+x[0],x[1],x[1],`${BRAND} Enterprise Suite: ${x[2]}`,()=>`${H1(x[1])}<p class="max-w-2xl">${E(x[2])}</p><p class="mt-4"><a href="/enterprise">All Enterprise Suite modules</a></p>`,'0.7','monthly')),
 pg('/products','products','','Products','Products','Ten connected ClasSphera modules: enrollment, attendance, learning management, assessment, AI tools, analytics, finance vault, messaging, staff and security.',()=>`${H1('Products')}${grid(PRODS,'sm:grid-cols-2 lg:grid-cols-3')}`,'0.9'),
 pg('/solutions','sol','','Solutions','Solutions for every institution','ClasSphera fits schools, madrasahs, coaching centers, colleges and universities with student records, staff management, financial ledgers and institutional hierarchies.',()=>`${H1('Solutions')}${grid(SOLS,'md:grid-cols-2 lg:grid-cols-3')}${H2('Included in every solution')}${grid(ALLSOL,'sm:grid-cols-2 lg:grid-cols-4')}`,'0.9'),
 pg('/pricing','price','','Pricing','Pricing','ClasSphera Free plan up to 100 student records, then Starter $29, Institution $79 and Sovereign $199 per month. Pay with bKash, Nagad, Rocket, SSLCommerz, cards, PayPal, Bitcoin or USDT.',()=>`${H1('Pricing')}${plans()}`,'0.9'),
 pg('/connected-os','os','','Connected OS','Connected OS','The ClasSphera Connected OS: data, identity, intelligence and communication layers working together for every institution.',()=>`${H1('Connected OS')}${grid(OSL)}`,'0.7'),
 pg('/help','help','','Help Center','Help center','Set up your institution, add team members, students and staff, enter marks, collect fees and recover administrator access in ClasSphera.',()=>`${H1('Help center')}<div class="space-y-3">${HELP.map(x=>`<div class="glass p-4"><h2 class="font-bold">${E(x[0])}</h2><p class="mt-2 text-sm mu">${E(x[1])}</p></div>`).join('')}</div>`,'0.6'),
 pg('/feedback','fb','','Feedback Portal','Feedback portal','Send ideas, problems or praise privately to the ClasSphera founder together with your institution’s details.',()=>`${H1('Feedback portal')}<p class="text-sm mb-4 mu">Sent privately to the founder with your institution’s details.</p>`,'0.3','yearly'),
 pg('/terms','terms','','Terms of Use','Terms of use','Terms of use for ClasSphera, operated by QVMPXT: record ownership, subscriptions, payments and workspace security.',()=>`${H1('Terms of use')}${paras(TERMS)}`,'0.3','yearly'),
 pg('/privacy','privacy','','Privacy','Privacy','How ClasSphera keeps each institution’s data isolated, what security alerts include and how guardian phone numbers are used.',()=>`${H1('Privacy')}${paras(PRIVACY)}`,'0.3','yearly')];
const BYPATH=Object.fromEntries(PAGES.map(p=>[p.path,p]));
const VIEWPATH={home:'/',products:'/products',sol:'/solutions',price:'/pricing',os:'/connected-os',help:'/help',fb:'/feedback',terms:'/terms',privacy:'/privacy',connect:'/connect',admit:'/admission',enterprise:'/enterprise',guard:'/guardian-signup'};
const INITHASH=Object.fromEntries(PAGES.filter(p=>p.hash).map(p=>[p.path,p.hash]));
const DLPATHS={'/login':1,'/signup':1,'/guardian-signup':1,'/student-signup':1,'/download':1};
const ALIAS={'/index.html':'/','/price':'/pricing','/sol':'/solutions','/os':'/connected-os','/fb':'/feedback','/product':'/products','/solution':'/solutions','/terms-of-use':'/terms','/privacy-policy':'/privacy','/help-center':'/help','/log-in':'/login','/sign-in':'/login','/register':'/signup','/sign-up':'/signup','/guardian':'/guardian-signup','/student':'/student-signup','/contact':'/connect','/connect-us':'/connect','/install':'/download','/app':'/download','/admit':'/admission','/enterprise-suite':'/enterprise'};
const NAVP=['/','/login','/signup','/guardian-signup','/student-signup','/connect','/download','/admission','/enterprise','/products','/solutions','/pricing','/connected-os','/help','/feedback','/terms','/privacy'];
const NAV=`<nav id="cs-nav" aria-label="ClasSphera pages" style="max-width:72rem;margin:0 auto;padding:1rem 1rem 2rem;display:flex;flex-wrap:wrap;gap:.5rem 1.25rem;justify-content:center;font-size:.8rem">${[...NAVP,...ENT.map(x=>'/enterprise/'+x[0])].map(p=>{const x=BYPATH[p];return`<a href="${p}" data-h="${E(x.hash||x.v)}" style="color:var(--mu)">${E(x.name)}</a>`}).join('')}</nav>`;
const ROBOTS=lm=>`User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ${SITE}/sitemap.xml\n`;
const SITEMAP=env=>{const lm=(env&&env.SITE_LASTMOD)||LASTMOD;return`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${PAGES.map(p=>`<url><loc>${SITE}${p.path==='/'?'/':p.path}</loc><lastmod>${lm}</lastmod><changefreq>${p.cf}</changefreq><priority>${p.pr}</priority></url>`).join('\n')}\n</urlset>\n`};
const MANIFEST=JSON.stringify({name:'ClasSphera',short_name:'ClasSphera',description:`${BRAND}. ${TAG}`,id:'/',start_url:'/',scope:'/',display:'standalone',background_color:'#070812',theme_color:'#070812',lang:'en',dir:'auto',categories:['education','productivity'],icons:[{src:'/icon-192.png',sizes:'192x192',type:'image/png',purpose:'any'},{src:'/icon-512.png',sizes:'512x512',type:'image/png',purpose:'any'},{src:'/favicon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}],shortcuts:[{name:'Login',url:'/login'},{name:'Guardian sign in',url:'/guardian-signup'},{name:'Student sign in',url:'/student-signup'},{name:'Global Online Admission',url:'/admission'}]});
const FAVICON='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none"><rect width="100" height="100" fill="#070812"/><defs><linearGradient id="a" gradientUnits="userSpaceOnUse" x1="8" y1="8" x2="92" y2="92"><stop stop-color="#a78bfa"/><stop offset=".5" stop-color="#22d3ee"/><stop offset="1" stop-color="#34d399"/></linearGradient><linearGradient id="b" gradientUnits="userSpaceOnUse" x1="56" y1="40" x2="82" y2="60"><stop stop-color="#fef08a"/><stop offset="1" stop-color="#f59e0b"/></linearGradient></defs><path d="M50 5l39 22.5v45L50 95 11 72.500v-45z" fill="#0b1030" stroke="url(#a)" stroke-width="4" stroke-linejoin="round"/><path d="M50 17l28 16.200v33.600L50 83 22 66.800V33.200z" stroke="url(#a)" stroke-opacity=".35" stroke-width="1.5" stroke-linejoin="round"/><path d="M63.500 36.500A21 21 0 1 0 63.500 63.500" stroke="url(#a)" stroke-width="9" stroke-linecap="round"/><path d="M60 50l9.500-10 9.500 10-9.500 10z" fill="url(#b)"/><ellipse cx="50" cy="50" rx="41" ry="12" transform="rotate(-32 50 50)" stroke="url(#a)" stroke-opacity=".55" stroke-width="1.8"/><circle cx="23" cy="73" r="3.200" fill="#f472b6"/></svg>';
const SW=`/* ClasSphera service worker ${APP_V} */
const V='cs-${APP_V}';
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.add(new Request('/',{cache:'reload'}))).catch(()=>{}).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x.startsWith('cs-')&&x!==V).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{const r=e.request;if(r.method!=='GET')return;const u=new URL(r.url);if(u.origin!==location.origin||u.pathname.startsWith('/api/'))return;
 if(r.mode==='navigate'){e.respondWith(fetch(r).then(x=>{if(x.ok){const c=x.clone();caches.open(V).then(h=>h.put('/',c))}return x}).catch(()=>caches.match('/').then(x=>x||new Response('Offline',{status:503,headers:{'content-type':'text/plain'}}))));return}
 if(/\\.(png|svg|ico|webmanifest|woff2?|css|js)$/.test(u.pathname)&&u.pathname!=='/sw.js'){e.respondWith(caches.open(V).then(c=>c.match(r).then(h=>{const f=fetch(r).then(x=>{if(x.ok)c.put(r,x.clone());return x}).catch(()=>h);return h||f})))}});
const CSL={notice:'📢 নোটিস',urgent:'🚨 জরুরি নোটিস',attendance:'✅ হাজিরা',fee:'💳 ফি',result:'🎓 রেজাল্ট'};
function csShow(d){d=d||{};const p=CSL[d.k],b=(p?p+'\\n':'')+(d.b||'You have a new message');return self.registration.showNotification(d.t||'ClasSphera',{body:b,icon:d.i||'/icon-192.png',badge:'/icon-192.png',tag:d.g||'cs-msg',renotify:true,requireInteraction:d.k==='urgent',vibrate:[120,60,120],timestamp:d.at||Date.now(),lang:'bn',data:d})}
self.addEventListener('push',e=>{e.waitUntil((async()=>{let d=null;try{d=e.data?e.data.json():null}catch(_){}
 if(!d||!d.b){try{const s=await self.registration.pushManager.getSubscription();if(s){const r=await fetch('/api/push/peek',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({endpoint:s.endpoint})});if(r.ok){const j=await r.json();if(j&&j.b)d=j}}}catch(_){}}
 await csShow(d)})())});
self.addEventListener('notificationclick',e=>{e.notification.close();const d=e.notification.data||{};e.waitUntil((async()=>{
 try{const c=await caches.open('csnotif');await c.put('/__csn',new Response(JSON.stringify(d),{headers:{'content-type':'application/json'}}))}catch(_){}
 const l=await self.clients.matchAll({type:'window',includeUncontrolled:true});
 for(const c of l){if('focus' in c){try{c.postMessage({cs:'notif',d:d})}catch(_){}return c.focus()}}
 return self.clients.openWindow('/?csn=1')})())});`;
/* PNG icons rendered from the logo geometry (no external files needed) */
const HEXV=[[50,5],[89,27.5],[89,72.5],[50,95],[11,72.5],[11,27.5]];
const HEXE=HEXV.map((a,i)=>{const b=HEXV[(i+1)%6],dx=b[0]-a[0],dy=b[1]-a[1],l=Math.hypot(dx,dy),nx=dy/l,ny=-dx/l;return[nx,ny,nx*a[0]+ny*a[1]]});
const mix=(a,b,t)=>{t=Math.max(0,Math.min(1,t));return[a[0]+(b[0]-a[0])*t,a[1]+(b[1]-a[1])*t,a[2]+(b[2]-a[2])*t]};
function logoPx(x,y){
 const g=Math.max(0,Math.min(1,((x-8)+(y-8))/168)),grad=g<.5?mix([167,139,250],[34,211,238],g*2):mix([34,211,238],[52,211,153],(g-.5)*2),dx=x-50,dy=y-50,r=Math.hypot(dx,dy);
 let d=-1e9;for(const e of HEXE){const v=e[0]*x+e[1]*y-e[2];if(v>d)d=v}
 if(Math.hypot(x-23,y-73)<=3.2)return[244,114,182];
 if(Math.abs(x-69.5)/9.5+Math.abs(y-50)/10<=1)return mix([254,240,138],[245,158,11],(x-60)/19);
 if(Math.abs(r-21)<=4.5&&!(dx>0&&Math.abs(dy)<dx))return grad;
 if(d>=-2&&d<=2)return grad;
 if(d<-2)return[11,16,48];
 return[7,8,18]}
const CRCT=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c>>>0}return t})();
const crc32=b=>{let c=~0;for(let i=0;i<b.length;i++)c=CRCT[(c^b[i])&255]^(c>>>8);return(~c)>>>0};
async function deflate(bytes){const cs=new CompressionStream('deflate'),w=cs.writable.getWriter();w.write(bytes);w.close();return new Uint8Array(await new Response(cs.readable).arrayBuffer())}
function pngChunk(type,data){const out=new Uint8Array(12+data.length),dv=new DataView(out.buffer);dv.setUint32(0,data.length);for(let i=0;i<4;i++)out[4+i]=type.charCodeAt(i);out.set(data,8);dv.setUint32(8+data.length,crc32(out.subarray(4,8+data.length)));return out}
async function iconPng(n){
 const rows=new Uint8Array(n*(n*4+1)),k=100/n;let o=0;
 for(let py=0;py<n;py++){rows[o++]=0;for(let px=0;px<n;px++){let r=0,g=0,b=0;for(let sy=0;sy<2;sy++)for(let sx=0;sx<2;sx++){const c=logoPx((px+.25+sx*.5)*k,(py+.25+sy*.5)*k);r+=c[0];g+=c[1];b+=c[2]}rows[o++]=r>>2;rows[o++]=g>>2;rows[o++]=b>>2;rows[o++]=255}}
 const ih=new Uint8Array(13),dv=new DataView(ih.buffer);dv.setUint32(0,n);dv.setUint32(4,n);ih[8]=8;ih[9]=6;
 const ch=[new Uint8Array([137,80,78,71,13,10,26,10]),pngChunk('IHDR',ih),pngChunk('IDAT',await deflate(rows)),pngChunk('IEND',new Uint8Array(0))],out=new Uint8Array(ch.reduce((a,c)=>a+c.length,0));
 let p=0;for(const c of ch){out.set(c,p);p+=c.length}return out}
const ICONS={'/favicon-48x48.png':48,'/favicon.ico':48,'/icon-192.png':192,'/icon-512.png':512,'/apple-touch-icon.png':180};

/* structured data: brand, tagline, navigation (sitelinks), breadcrumbs */
const LD=(p,host)=>{
 const org={'@type':'Organization','@id':SITE+'/#org',name:'QVMPXT',url:SITE+'/',slogan:TAG,brand:{'@type':'Brand',name:'ClasSphera',slogan:TAG},logo:SITE+'/icon-512.png',email:FOUNDER_MAIL,telephone:FOUNDER_PHONE,founder:{'@type':'Person',name:FOUNDER}};
 const web={'@type':'WebSite','@id':SITE+'/#website',url:SITE+'/',name:'ClasSphera',alternateName:['Classphera','ClassSphera','Class Sphera',BRAND],description:TAG,publisher:{'@id':SITE+'/#org'},inLanguage:'en'};if(p.bn)web.keywords=BN_KW;
 const nav=['/','/login','/signup','/guardian-signup','/student-signup','/connect','/download','/enterprise'];
 const g=[web,org,{'@type':'WebPage','@id':SITE+p.path+'#webpage',url:SITE+p.path,name:p.title,description:p.bn?p.desc+BN_DESC:p.desc,isPartOf:{'@id':SITE+'/#website'},inLanguage:'en'},
  {'@type':'ItemList','@id':SITE+'/#navigation',name:'ClasSphera main navigation',itemListElement:nav.map((x,i)=>({'@type':'ListItem',position:i+1,item:{'@type':'SiteNavigationElement','@id':SITE+x+'#nav',name:BYPATH[x].name,description:BYPATH[x].desc,url:SITE+(x==='/'?'/':x)}}))}];
 if(p.path!=='/'){const c=[{'@type':'ListItem',position:1,name:'Home',item:SITE+'/'}];if(p.path.startsWith('/enterprise/'))c.push({'@type':'ListItem',position:2,name:'Enterprise Suite',item:SITE+'/enterprise'},{'@type':'ListItem',position:3,name:p.name,item:SITE+p.path});else c.push({'@type':'ListItem',position:2,name:p.name,item:SITE+p.path});g.push({'@type':'BreadcrumbList',itemListElement:c})}
 const app={'@type':'SoftwareApplication',name:'ClasSphera',applicationCategory:'EducationalApplication',operatingSystem:'Web',url:SITE+'/',description:TAG,publisher:{'@id':SITE+'/#org'}};if(p.bn)app.keywords=BN_KW;
 if(p.path==='/pricing'||p.path==='/')app.offers=PLANS.map(x=>({'@type':'Offer',name:x[0],description:x[1],price:String(x[2]),priceCurrency:'USD'}));
 g.push(app);return'<script type="application/ld+json">'+JSON.stringify({'@context':'https://schema.org','@graph':g}).replace(/</g,'\\u003c')+'</script>'};

/* inline scripts added to every HTML page */
const BOOT=()=>`<script>(function(){var P=${JSON.stringify(VIEWPATH)},I=${JSON.stringify(INITHASH)},D=${JSON.stringify(DLPATHS)},h=history,ps=h.pushState,rs=h.replaceState;
function f(u){if(typeof u!=='string'||u.charAt(0)!=='#')return u;var a=u.slice(1).split(':'),v=a[0];if(v==='home'&&D[location.pathname])return location.pathname+u;if(v==='enterprise'&&/^[a-z]+$/.test(a[1]||''))return'/enterprise/'+a[1]+u;if(P[v]!==undefined)return P[v]+u;return'/'+u}
h.pushState=function(s,t,u){return ps.call(h,s,t,f(u))};h.replaceState=function(s,t,u){return rs.call(h,s,t,f(u))};
var ih=I[location.pathname];if(ih&&!location.hash){try{rs.call(h,{d:0},'',location.pathname+'#'+ih)}catch(e){}}
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[data-h]');if(a&&e.button===0&&!e.metaKey&&!e.ctrlKey&&!e.shiftKey&&typeof nav==='function'){e.preventDefault();var x=a.getAttribute('data-h');if(/^(login|signup|guardian-signup|student-signup|app-download)$/.test(x))location.hash='#'+x;else nav(x)}})})();</script>`;
const CLIENT_PATCH=`<script>(function(){
/* 1) preferences, UI toggles and enterprise custom fields follow the signed-in account across devices */
if(!window.__csPrefs){window.__csPrefs=1;
var TRACK=/^(cs_lang|cs_theme|cs_ch|cs_ent_(ver|rbac|fields|notify|sync|health|campus|finance)|cs_cf_[a-z0-9-]{3,30})$/,LS=window.localStorage,sp=Storage.prototype,setI=sp.setItem,META='cs_pmeta',applying=false,timer=null,lastTok='',busy=false;
function gm(){try{return JSON.parse(LS.getItem(META)||'{}')}catch(e){return{}}}
function sm(m){try{setI.call(LS,META,JSON.stringify(m))}catch(e){}}
function tok(){try{return S&&S.user&&S.user.token||''}catch(e){return''}}
sp.setItem=function(k){setI.apply(this,arguments);if(!applying&&this===LS&&TRACK.test(k)){var m=gm();m[k]=Date.now();sm(m);sched()}};
function sched(){clearTimeout(timer);timer=setTimeout(sync,1500)}
function post(b,t){return fetch('/api/preferences',{method:'POST',keepalive:true,headers:{'content-type':'application/json',authorization:'Bearer '+t},body:JSON.stringify(b)}).then(function(r){return r.ok?r.json():null})}
function apply(res){var ch=[];['user','inst'].forEach(function(sc){var o=res&&res[sc]||{};for(var k in o){if(!TRACK.test(k))continue;var e=o[k],m=gm();if(e&&typeof e.v==='string'&&(m[k]||0)<e.t){applying=true;try{setI.call(LS,k,e.v)}finally{applying=false}m[k]=e.t;sm(m);ch.push(k)}}});
 if(!ch.length)return;
 try{if(ch.indexOf('cs_lang')>-1){var v=JSON.parse(LS.getItem('cs_lang'));if(typeof LNG!=='undefined'&&typeof TX!=='undefined'&&v&&TX[v])LNG=v}}catch(e){}
 try{var ae=document.activeElement,md=document.getElementById('modal');if(typeof render==='function'&&!(md&&md.classList.contains('open'))&&!(ae&&/^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName)))render()}catch(e){}}
function sync(){var t=tok();if(!t||busy)return;busy=true;var m=gm(),d={};for(var i=0;i<LS.length;i++){var k=LS.key(i);if(TRACK.test(k)){var v=LS.getItem(k);if(v!==null)d[k]={v:v,t:m[k]||0}}}
 post({action:'sync',data:d},t).then(function(r){if(r)apply(r)}).catch(function(){}).then(function(){busy=false})}
setInterval(function(){var t=tok();if(t&&t!==lastTok){lastTok=t;sync()}if(!t)lastTok=''},1500);
setInterval(sync,90000);document.addEventListener('visibilitychange',function(){if(!document.hidden)sync()});
var lo=window.logout;if(typeof lo==='function'){window.logout=function(){try{fetch('/api/session/logout',{method:'POST',keepalive:true,headers:{'content-type':'application/json'},body:'{}'})}catch(e){}lastTok='';return lo.apply(this,arguments)}}}
/* 2) the login two-step button and the guardian quick-view OTP sender share the name csOtp in index.html; restore the login verifier */
var f=window.csOtp;if(typeof f==='function'&&String(f).indexOf('/api/g/otp')>-1){var g=f;
 window.csOtp=function(id){if(typeof id==='string'&&id)return g.apply(this,arguments);return loginOtp()};
 var loginOtp=async function(){var O=S.otp;if(!O)return closeM();var i=document.getElementById('otp'),m=document.getElementById('otpm'),v=(i&&i.value||'').trim();
  var fail=function(t){if(i)i.classList.add('cs-err');if(m)m.innerHTML='<div class="cs-msg">⚠ '+t+'</div>'};
  if(!/^\\d{6}$/.test(v))return fail('Enter all 6 digits');if(Date.now()>O.exp){S.otp=null;return fail('Code expired. Sign in again.')}
  var j=null;try{j=await rq(O.mode==='totp'?'/api/mfa/totp/verify':'/api/otp/verify',{sub:O.sub,fp:O.f,code:v,phone:O.ph,mail:O.em})}
  catch(e){var st=e&&e.status;if(!st||st>=500)return fail('Verification service unavailable. Try again.');if(st===410){S.otp=null;closeM();return toast('Code expired. Sign in again.')}if(st===429){S.otp=null;S.lock=Date.now()+60000;closeM();return toast((e&&e.error)||'Too many wrong codes. Locked for a minute.')}}
  if(!j||!j.token){O.tries=(O.tries||0)+1;try{threat('OTP mismatch',O.sub)}catch(e){}if(O.tries>=3){S.otp=null;S.lock=Date.now()+60000;closeM();return toast('Too many wrong codes. Locked for a minute.')}return fail('Incorrect code. '+(3-O.tries)+' attempt(s) left')}
  S.otp=null;try{await window.csEnter(O.sub,O.ph,O.em,O.pw,j.token);toast('✅ Verified')}catch(e){closeM();toast((e&&e.error)||'Could not open the workspace. Sign in again.')}}}
})();</script>`;
const FEE_PAY_PATCH=String.raw`<script>(function(){
if(window.__csFee)return;window.__csFee=1;
var D=document,LS=window.localStorage,MFS=['bKash','Nagad','Rocket'],LOCAL=['bKash','Nagad','Rocket','SSLCommerz'],GLOB=['Visa','Mastercard','Stripe','PayPal'];
var G={tok:'',who:'',seen:0,data:null,busy:0,pend:0},M=null,A={tok:'',deny:false,q:null,cfg:null,tab:'q',busy:0,open:false};
var T={
bn:{fees:'ফি',due:'বকেয়া',pay:'পরিশোধ করুন',submit:'সাবমিট',resume:'চালিয়ে যান',draft:'পেমেন্ট ড্রাফট',pending:'অনুমোদনের অপেক্ষায়',rej:'যাচাই হয়নি',close:'বন্ধ করুন',stu:'শিক্ষার্থী',id:'আইডি',
 local:'লোকাল (BDT)',glob:'গ্লোবাল (USD)',method:'পেমেন্ট মাধ্যম',none:'এই মুদ্রার জন্য প্রতিষ্ঠান এখনো কোনো মাধ্যম চালু করেনি।',noCur:'এই মুদ্রায় পরিশোধ এখন সম্ভব নয়।',
 how:'আপনার {m} থেকে {no} ({kind}) নম্বরে {amt} পাঠান। তারপর নিচের তথ্য দিয়ে সাবমিট করুন।',howG:'প্রতিষ্ঠানের নির্দেশনা অনুযায়ী {amt} পরিশোধ করুন, তারপর রেফারেন্স আইডি দিন।',
 from:'যে নম্বর থেকে পরিশোধ করেছেন',trx:'ট্রানজেকশন আইডি (TrxID)',payer:'পেমেন্টকারীর নাম / ই-মেইল / নম্বর',ref:'ট্রানজেকশন / রেফারেন্স আইডি',copy:'কপি',copied:'কপি হয়েছে',open:'পেমেন্ট পেজ খুলুন',
 sent:'✅ জমা হয়েছে। প্রতিষ্ঠান যাচাই করলে রসিদ পাবেন।',approved:'✅ আপনার পেমেন্ট অনুমোদিত হয়েছে। রসিদ দেখুন।',docs:'ডিজিটাল রসিদ',noDues:'কোনো বকেয়া নেই 🎉',receipt:'ডিজিটাল মানি রিসিপ্ট',verify:'যাচাই পেজ খুলুন',copyLink:'লিংক কপি',
 inst:'প্রতিষ্ঠান',rno:'রসিদ নং',fee:'ফি',amt:'পরিমাণ',meth:'মাধ্যম',snd:'প্রেরকের নম্বর',rcv:'প্রাপকের নম্বর',paid:'পরিশোধের সময়',appr:'অনুমোদনের সময়',err:'কিছু ভুল হয়েছে। আবার চেষ্টা করুন।',dueOn:'শেষ তারিখ',
 q:'পেমেন্ট অনুমোদন',ann:'ফি ঘোষণা',set:'সেটিংস',empty:'কোনো অপেক্ষমান পেমেন্ট নেই',approve:'অনুমোদন',reject:'বাতিল',why:'বাতিলের কারণ (ঐচ্ছিক)',recent:'সাম্প্রতিক',
 cat:'ফির ধরন',title:'শিরোনাম',amount:'পরিমাণ',cur:'মুদ্রা',pub:'প্রকাশের সময় (খালি = এখনই)',tgt:'কাদের জন্য',all:'সব শিক্ষার্থী',cls:'শ্রেণি',ids:'নির্দিষ্ট আইডি',rep:'প্রতি মাসে পুনরাবৃত্তি',create:'ঘোষণা করুন',made:'শিক্ষার্থীর জন্য তৈরি হয়েছে',sched:'নির্ধারিত সময়ে প্রকাশ হবে',
 stop:'বন্ধ',cancel:'প্রত্যাহার',save:'সংরক্ষণ',saved:'সংরক্ষিত',rate:'১ USD = কত BDT',num:'নম্বর',kind:'ধরন',link:'পেমেন্ট লিংক (https)',note:'নির্দেশনা',onlyAdmin:'শুধু অ্যাডমিন বদলাতে পারবেন',batches:'ঘোষিত ফি',rules:'মাসিক নিয়ম',
 Mo:'মাসিক ফি',Ex:'পরীক্ষার ফি',Ad:'ভর্তি ফি',Cu:'অন্যান্য ফি'},
en:{fees:'Fees',due:'Due',pay:'Pay Now',submit:'Submit',resume:'Resume',draft:'Payment draft',pending:'Waiting for approval',rej:'Not verified',close:'Close',stu:'Student',id:'ID',
 local:'Local (BDT)',glob:'Global (USD)',method:'Payment method',none:'The institution has not enabled a method for this currency yet.',noCur:'Payment in this currency is not available right now.',
 how:'From your {m}, send {amt} to {no} ({kind}). Then fill in the details below and submit.',howG:'Pay {amt} as the institution instructs, then enter the reference ID.',
 from:'Number you paid from',trx:'Transaction ID (TrxID)',payer:'Payer name / e-mail / number',ref:'Transaction / reference ID',copy:'Copy',copied:'Copied',open:'Open payment page',
 sent:'✅ Submitted. You will get a receipt once the institution verifies it.',approved:'✅ Your payment was approved. See your receipt.',docs:'Digital receipts',noDues:'Nothing due 🎉',receipt:'Digital Money Receipt',verify:'Open verification page',copyLink:'Copy link',
 inst:'Institution',rno:'Receipt No',fee:'Fee',amt:'Amount',meth:'Method',snd:'Sender number',rcv:'Receiver number',paid:'Paid at',appr:'Approved at',err:'Something went wrong. Please try again.',dueOn:'Due date',
 q:'Payment Approvals',ann:'Announce fee',set:'Settings',empty:'No payments waiting',approve:'Approve',reject:'Reject',why:'Reason for rejecting (optional)',recent:'Recent',
 cat:'Fee type',title:'Title',amount:'Amount',cur:'Currency',pub:'Publish at (empty = now)',tgt:'For',all:'All students',cls:'A class',ids:'Specific IDs',rep:'Repeat every month',create:'Announce',made:'students charged',sched:'Will publish at the chosen time',
 stop:'Stop',cancel:'Withdraw',save:'Save',saved:'Saved',rate:'1 USD = how many BDT',num:'Number',kind:'Type',link:'Payment link (https)',note:'Instructions',onlyAdmin:'Only the Admin can change these',batches:'Announced fees',rules:'Monthly rules',
 Mo:'Monthly Fee',Ex:'Exam Fee',Ad:'Admission Fee',Cu:'Custom'}};
function L(){try{var v=(typeof LNG!=='undefined'&&LNG)||JSON.parse(LS.getItem('cs_lang')||'null')||'';v=String(v).toLowerCase();return v&&v.indexOf('bn')!==0?'en':'bn'}catch(e){return'bn'}}
function t(k){return(T[L()]||T.en)[k]||T.en[k]||k}
function h(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function money(n,c){var v=Math.round((+n||0)*100)/100;return(v%1?v.toFixed(2):String(v))+' '+c}
function cat(c){var m={'Monthly Fee':'Mo','Exam Fee':'Ex','Admission Fee':'Ad','Custom':'Cu'};return m[c]?t(m[c]):c}
function dt(ms){try{return new Date(+ms).toLocaleString(L()==='bn'?'bn-BD':'en-GB',{dateStyle:'medium',timeStyle:'short'})}catch(e){return''}}
function api(p,b,tok,keep){return fetch(p,{method:'POST',keepalive:!!keep,headers:Object.assign({'content-type':'application/json'},tok?{authorization:'Bearer '+tok}:{}),body:JSON.stringify(b||{})}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){if(!r.ok){var e=new Error(j.error||'error');e.status=r.status;throw e}return j})})}
function $(i){return D.getElementById(i)}
function own(){return typeof window.pzCards==='function'} /* the app already ships its own fee cards / Pay Now / approvals: this layer then stays silent */
function toast(m){var e=D.createElement('div');e.className='csf-toast';e.textContent=m;D.body.appendChild(e);setTimeout(function(){e.style.opacity='0'},3200);setTimeout(function(){e.remove()},3700)}

/* ---------- styles (glass-morphism, same palette as the app) ---------- */
var css=['.csf-fab{position:fixed;right:14px;bottom:14px;z-index:99990;display:none;gap:8px;align-items:center;padding:11px 16px;border-radius:999px;border:1px solid rgba(255,255,255,.2);background:linear-gradient(135deg,#1e3a8a,#0b1e5b);color:#fff;font:600 14px/1 inherit;box-shadow:0 10px 30px rgba(11,30,91,.55);cursor:pointer}',
'.csf-fab.on{display:flex}.csf-b{min-width:20px;height:20px;border-radius:10px;background:#f43f5e;font-size:12px;display:grid;place-items:center;padding:0 6px}',
'.csf-ov{position:fixed;inset:0;z-index:99995;display:none;align-items:flex-end;justify-content:center;background:rgba(5,6,16,.55);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}.csf-ov.on{display:flex}',
'@media(min-width:640px){.csf-ov{align-items:center;padding:20px}}',
'.csf-g,.csf-card{color:#e6e9f5;background:linear-gradient(160deg,rgba(30,36,74,.72),rgba(12,15,38,.8));border:1px solid rgba(255,255,255,.16);box-shadow:0 24px 70px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.12);backdrop-filter:blur(22px) saturate(150%);-webkit-backdrop-filter:blur(22px) saturate(150%);font-family:inherit}',
'.csf-g{width:100%;max-width:480px;max-height:92vh;overflow:auto;border-radius:22px 22px 0 0;padding:18px}@media(min-width:640px){.csf-g{border-radius:22px}}',
'.csf-g *{box-sizing:border-box}.csf-hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.csf-hd b{font-size:17px}',
'.csf-x{border:0;background:rgba(255,255,255,.1);color:#e6e9f5;width:32px;height:32px;border-radius:50%;font-size:16px;cursor:pointer}',
'.csf-card{border-radius:18px;padding:14px;margin:0 0 12px}.csf-due{border-radius:14px;padding:12px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1)}',
'.csf-r{display:flex;justify-content:space-between;gap:8px;align-items:center}.csf-tag{font-size:12px;padding:3px 9px;border-radius:99px;background:linear-gradient(90deg,rgba(167,139,250,.3),rgba(34,211,238,.3))}',
'.csf-amt{font-size:26px;font-weight:800;margin:6px 0 0;background:linear-gradient(90deg,#a78bfa,#22d3ee,#34d399);-webkit-background-clip:text;background-clip:text;color:transparent}.csf-mu{color:#9aa1b9;font-size:12px}',
'.csf-pay{display:block;width:100%;margin-top:10px;padding:13px;border-radius:14px;border:1px solid rgba(147,197,253,.35);background:linear-gradient(180deg,#1e3a8a,#0b1e5b);color:#fff;font:700 15px/1 inherit;cursor:pointer;box-shadow:0 8px 22px rgba(11,30,91,.5)}.csf-pay:disabled{opacity:.55;cursor:default}',
'.csf-st{display:inline-block;margin-top:8px;font-size:12px;padding:3px 10px;border-radius:99px}.csf-st.d{background:rgba(251,191,36,.18);color:#fbbf24}.csf-st.p{background:rgba(34,211,238,.16);color:#22d3ee}.csf-st.j{background:rgba(244,63,94,.16);color:#fb7185}',
'.csf-seg{display:flex;gap:6px;margin:8px 0}.csf-seg button,.csf-chip{flex:1;padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);color:#e6e9f5;font:600 13px/1 inherit;cursor:pointer}.csf-seg button.on,.csf-chip.on{background:linear-gradient(135deg,#1e3a8a,#0b1e5b);border-color:#60a5fa}',
'.csf-chips{display:grid;grid-template-columns:repeat(2,1fr);gap:6px;margin:6px 0}.csf-box{margin:10px 0;padding:11px;border-radius:12px;background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.25);font-size:13px;line-height:1.5}',
'.csf-g label{display:block;margin:10px 0 4px;font-size:12px;color:#9aa1b9}.csf-g input,.csf-g select,.csf-g textarea{width:100%;padding:11px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(7,8,18,.55);color:#e6e9f5;font:15px inherit;outline:0}.csf-g input:focus,.csf-g select:focus{border-color:#22d3ee}',
'.csf-err{margin-top:10px;color:#fb7185;font-size:13px;min-height:18px}.csf-sm{padding:8px 12px;border-radius:10px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.08);color:#e6e9f5;font:600 12px inherit;cursor:pointer}',
'.csf-ok{background:#059669!important;border-color:#34d399!important}.csf-no{background:rgba(244,63,94,.25)!important}.csf-tb{display:flex;gap:6px;margin-bottom:10px}.csf-tb button{flex:1;padding:9px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);color:#e6e9f5;font:600 12px inherit}.csf-tb button.on{background:#1e3a8a}',
'.csf-kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-top:1px solid rgba(255,255,255,.1);font-size:13px}.csf-kv span:first-child{color:#9aa1b9}.csf-kv span:last-child{font-weight:600;text-align:right;word-break:break-all}',
'.csf-toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%);z-index:99999;max-width:90vw;padding:11px 16px;border-radius:14px;background:rgba(15,20,50,.92);color:#fff;border:1px solid rgba(255,255,255,.2);font:600 14px inherit;transition:opacity .4s}'].join('');
var st=D.createElement('style');st.textContent=css;D.head.appendChild(st);
var root=D.createElement('div');root.id='csf-root';root.innerHTML='<button class="csf-fab" id="csf-fab" data-csf="sheet"></button><div class="csf-ov" id="csf-sheet"></div><div class="csf-ov" id="csf-modal"></div>';
function ready(f){D.body?f():D.addEventListener('DOMContentLoaded',f)}ready(function(){D.body.appendChild(root)});

/* ---------- guardian / student: dues, Pay Now, payment modal ---------- */
function setTok(tk,who){if(!/^[0-9a-f]{48}$/.test(tk||''))return;G.seen=Date.now();if(G.tok!==tk){G.tok=tk;G.who=who||G.who;G.data=null;refresh()}ui()}
var of=window.fetch;window.fetch=function(u,o){var p=of.apply(this,arguments);try{var url=typeof u==='string'?u:(u&&u.url)||'';
 if(url.indexOf('/api/g/login')>-1)p.then(function(r){return r.clone().json()}).then(function(j){if(j&&j.token)setTok(j.token,j.who)}).catch(function(){});
 else if(url.indexOf('/api/g/')>-1&&o&&typeof o.body==='string'){var b=JSON.parse(o.body);if(b&&b.token)setTok(b.token,'')}}catch(e){}return p};
window.csFee={token:setTok,logout:function(){G.tok='';G.data=null;ui()},open:function(){act('sheet')},refresh:function(){refresh()}};
function anchor(){return D.querySelector('[data-cs-fee],#cs-fee-due')}
function live(){return G.tok&&Date.now()-G.seen<9e5}
function refresh(){if(own()||!G.tok||G.busy)return;G.busy=1;api('/api/fee/mine',{token:G.tok}).then(function(j){G.busy=0;var pv=G.data;G.data=j;
  if(pv&&j.receipts.length>pv.receipts.length)toast(t('approved'));G.pend=j.dues.some(function(d){return d.state==='pending'});ui()}).catch(function(e){G.busy=0;if(e.status===401){G.tok='';G.data=null;ui()}})}
var n=0;setInterval(function(){n++;if(G.tok&&!D.hidden&&live()&&(G.pend||n%2===0))refresh();stPoll()},12000);
D.addEventListener('visibilitychange',function(){if(!D.hidden){refresh();stPoll()}});
function card(d){var s=d.state,nm=G.data.stu.name||G.data.stu.id,b='';
 if(s==='draft')b='<span class="csf-st d">'+t('draft')+'</span>';else if(s==='pending')b='<span class="csf-st p">⏳ '+t('pending')+'</span>';else if(d.rej)b='<span class="csf-st j">'+t('rej')+': '+h(d.rej)+'</span>';
 return'<div class="csf-card"><div class="csf-due"><div class="csf-r"><b>'+h(nm)+'</b><span class="csf-tag">'+h(cat(d.cat))+'</span></div>'+(d.title?'<div class="csf-mu">'+h(d.title)+'</div>':'')+
  '<div class="csf-mu" style="margin-top:6px">'+t('due')+'</div><div class="csf-amt">'+h(money(d.amt,d.cur))+'</div>'+(d.due_on?'<div class="csf-mu">'+t('dueOn')+': '+h(d.due_on)+'</div>':'')+b+'</div>'+
  (s==='pending'?'<button class="csf-pay" disabled>⏳ '+t('pending')+'</button>':'<button class="csf-pay" data-csf="pay" data-id="'+h(d.id)+'">'+(s==='draft'?t('resume'):t('pay'))+'</button>')+'</div>'}
function dues(){var d=G.data;if(!d)return'';var o=d.dues.map(card).join('')||'<div class="csf-mu" style="padding:10px 0">'+t('noDues')+'</div>';
 if(d.receipts.length)o+='<div class="csf-hd" style="margin-top:14px"><b style="font-size:14px">🧾 '+t('docs')+'</b></div>'+d.receipts.map(function(r){return'<div class="csf-card" style="padding:10px 12px"><div class="csf-r"><div><b>'+h(r.title||cat(r.cat))+'</b><div class="csf-mu">'+h(r.no)+' · '+h(dt(r.at))+'</div></div><button class="csf-sm" data-csf="rc" data-id="'+h(r.code)+'">'+h(money(r.amt,r.cur))+' ›</button></div></div>'}).join('');return o}
function ui(){var fab=$('csf-fab'),a=anchor(),on=live()&&G.data&&!a&&!own(),cnt=G.data?G.data.dues.length:0;
 if(a&&live()&&G.data&&!own())a.innerHTML=dues();
 if(fab){var stf=A.tok&&!A.deny&&A.q&&!own();fab.className='csf-fab'+((on||stf)?' on':'');fab.innerHTML=stf?'💳 '+t('q')+(A.q.count?' <span class="csf-b">'+A.q.count+'</span>':''):'💳 '+t('fees')+(cnt?' <span class="csf-b">'+cnt+'</span>':'')}
 if(!live()&&$('csf-modal').className.indexOf('on')>-1&&M)closePay();
 if($('csf-sheet').className.indexOf('on')>-1&&!A.edit&&A.tab!=='s')sheet()}
function sheet(){var s=$('csf-sheet');s.className='csf-ov on';
 if(A.tok&&!A.deny&&A.q){stSheet(s);return}
 s.innerHTML='<div class="csf-g"><div class="csf-hd"><b>💳 '+t('fees')+'</b><button class="csf-x" data-csf="x">✕</button></div>'+dues()+'</div>'}

function avail(g){return G.data.cfg.m[g]}
function startCur(d){var c=G.data.cfg;return LOCAL.some(avail)?'BDT':GLOB.some(avail)&&d.alt.USD?'USD':'BDT'}
function pay(id){var d=G.data.dues.filter(function(x){return x.id===id})[0];if(!d)return;var sv=null;try{sv=JSON.parse(LS.getItem('cs_fee_d:'+id)||'null')}catch(e){}
 var p=d.pay||sv&&{method:sv.m,cur:sv.c,from:sv.f,trx:sv.x}||{};M={d:d,cur:p.cur||startCur(d),m:p.method||'',from:p.from||'',trx:p.trx||'',err:'',busy:0,tm:0,dirty:0};
 if(!avail(M.m))M.m='';$('csf-modal').className='csf-ov on';modal()}
function modal(){var d=M.d,c=G.data.cfg,cur=M.cur,loc=cur==='BDT',list=(loc?LOCAL:GLOB).filter(avail),amt=d.alt[cur],m=M.m&&avail(M.m),mfs=MFS.indexOf(M.m)>-1,body='';
 if(amt==null)body='<div class="csf-box">'+t('noCur')+'</div>';else if(!list.length)body='<div class="csf-box">'+t('none')+'</div>';
 else{body='<label>'+t('method')+'</label><div class="csf-chips">'+list.map(function(g){return'<button class="csf-chip'+(g===M.m?' on':'')+'" data-csf="m" data-id="'+g+'">'+g+'</button>'}).join('')+'</div>';
  if(m){var how=mfs?t('how').replace('{m}',M.m).replace('{no}',m.no).replace('{kind}',m.kind).replace('{amt}',money(amt,cur)):t('howG').replace('{amt}',money(amt,cur));
   body+='<div class="csf-box">'+h(how)+(m.no&&!mfs?'<div><b>'+h(m.no)+'</b></div>':'')+(m.note?'<div class="csf-mu" style="margin-top:6px">'+h(m.note)+'</div>':'')+
    (mfs?'<div style="margin-top:8px"><button class="csf-sm" data-csf="cp" data-id="'+h(m.no)+'">📋 '+h(m.no)+' · '+t('copy')+'</button></div>':'')+
    (m.url?'<div style="margin-top:8px"><a class="csf-sm" style="display:inline-block;text-decoration:none" target="_blank" rel="noopener" href="'+h(m.url)+'">'+t('open')+' ↗</a></div>':'')+'</div>'+
    '<label>'+(mfs?t('from'):t('payer'))+'</label><input id="csf-from" '+(mfs?'inputmode="tel" ':'')+'autocomplete="off" value="'+h(M.from)+'">'+
    '<label>'+(mfs?t('trx'):t('ref'))+'</label><input id="csf-trx" autocapitalize="characters" autocomplete="off" value="'+h(M.trx)+'">'+
    '<div class="csf-err" id="csf-err">'+h(M.err)+'</div><button class="csf-pay" data-csf="submit"'+(M.busy?' disabled':'')+'>'+t('submit')+'</button>'}}
 $('csf-modal').innerHTML='<div class="csf-g"><div class="csf-hd"><b>'+t('pay')+'</b><button class="csf-x" data-csf="cx">✕</button></div>'+
  '<div class="csf-due"><div class="csf-r"><b>'+h(G.data.stu.name||G.data.stu.id)+'</b><span class="csf-tag">'+h(cat(d.cat))+'</span></div><div class="csf-mu">'+h(G.data.inst)+(d.title?' · '+h(d.title):'')+'</div><div class="csf-amt">'+h(amt==null?money(d.amt,d.cur):money(amt,cur))+'</div></div>'+
  '<div class="csf-seg"><button class="'+(loc?'on':'')+'" data-csf="cur" data-id="BDT">'+t('local')+'</button><button class="'+(loc?'':'on')+'" data-csf="cur" data-id="USD">'+t('glob')+'</button></div>'+body+'</div>'}
function draft(now){if(!M||!M.m||!G.tok)return;clearTimeout(M.tm);var f=$('csf-from'),x=$('csf-trx');if(f)M.from=f.value;if(x)M.trx=x.value;
 try{LS.setItem('cs_fee_d:'+M.d.id,JSON.stringify({m:M.m,c:M.cur,f:M.from,x:M.trx}))}catch(e){}
 api('/api/fee/draft',{token:G.tok,due:M.d.id,method:M.m,cur:M.cur,from:M.from,trx:M.trx},'',true).catch(function(){})}
function sched(){if(!M)return;clearTimeout(M.tm);M.tm=setTimeout(draft,700)}
function closePay(){if(M){draft();M=null}$('csf-modal').className='csf-ov';$('csf-modal').innerHTML='';setTimeout(refresh,400)}
function submit(){var f=$('csf-from'),x=$('csf-trx');M.from=f?f.value:M.from;M.trx=x?x.value:M.trx;M.busy=1;M.err='';var b=document.querySelector('#csf-modal .csf-pay');if(b)b.disabled=true;
 api('/api/fee/submit',{token:G.tok,due:M.d.id,method:M.m,cur:M.cur,from:M.from,trx:M.trx}).then(function(){try{LS.removeItem('cs_fee_d:'+M.d.id)}catch(e){}clearTimeout(M.tm);M=null;$('csf-modal').className='csf-ov';$('csf-modal').innerHTML='';toast(t('sent'));refresh()})
 .catch(function(e){M.busy=0;M.err=e.status?e.message:t('err');var el=$('csf-err');if(el)el.textContent=M.err;if(b)b.disabled=false})}
function receipt(code){var r=G.data.receipts.filter(function(x){return x.code===code})[0];if(!r)return;var kv=function(a,b){return'<div class="csf-kv"><span>'+a+'</span><span>'+h(b)+'</span></div>'};
 var o=$('csf-modal');o.className='csf-ov on';o.innerHTML='<div class="csf-g"><div class="csf-hd"><b>🧾 '+t('receipt')+'</b><button class="csf-x" data-csf="rx">✕</button></div><div class="csf-amt" style="margin:0 0 8px">'+h(money(r.amt,r.cur))+'</div>'+
  kv(t('inst'),r.inst)+kv(t('rno'),r.no)+kv(t('stu'),r.stu)+kv(t('id'),r.sid)+kv(t('fee'),r.title?cat(r.cat)+' · '+r.title:cat(r.cat))+kv(t('meth'),r.method)+kv(t('snd'),r.from_no)+kv(t('rcv'),r.rcv_no||'—')+kv('TrxID',r.trx)+kv(t('paid'),dt(r.pat))+kv(t('appr'),dt(r.at))+
  '<div class="csf-r" style="margin-top:12px"><a class="csf-pay" style="text-align:center;text-decoration:none;margin:0" target="_blank" rel="noopener" href="'+h(r.link)+'">'+t('verify')+' ↗</a></div><button class="csf-sm" style="margin-top:8px;width:100%" data-csf="cl" data-id="'+h(r.link)+'">'+t('copyLink')+'</button></div>'}
function copy(v){try{navigator.clipboard.writeText(v).then(function(){toast(t('copied'))},function(){toast(v)})}catch(e){toast(v)}}

/* ---------- institution staff: Payment Approvals, announce fee, merchant numbers ---------- */
function stTok(){try{return S&&S.user&&S.user.token||''}catch(e){return''}}
function stPoll(){if(own())return;var tk=stTok();if(!tk){if(A.tok){A.tok='';A.q=null;ui()}return}if(A.tok!==tk){A.tok=tk;A.deny=false;A.q=null}if(A.deny||A.busy||D.hidden)return;A.busy=1;
 api('/api/fee/queue',{},tk).then(function(j){A.busy=0;var pv=A.q?A.q.count:0;A.q=j;if(j.count>pv&&pv>=0&&A.seenq)toast('💳 '+t('q')+': '+j.count);A.seenq=1;ui();if(A.open&&A.tab!=='s'&&!A.edit)sheet()}).catch(function(e){A.busy=0;if(e.status===401||e.status===403){A.deny=true;ui()}})}
function stSheet(s){var q=A.q,tb=['q','a','s'].map(function(k){return'<button class="'+(A.tab===k?'on':'')+'" data-csf="tab" data-id="'+k+'">'+t(k==='q'?'q':k==='a'?'ann':'set')+'</button>'}).join(''),b='';
 if(A.tab==='q')b=qView(q);else if(A.tab==='a')b=annView(q);else b=setView();
 s.innerHTML='<div class="csf-g"><div class="csf-hd"><b>💳 '+t('fees')+'</b><button class="csf-x" data-csf="x">✕</button></div><div class="csf-tb">'+tb+'</div>'+b+'</div>';if(A.tab==='s'&&!A.cfg)loadCfg()}
function qView(q){var o=q.pending.map(function(p){return'<div class="csf-card"><div class="csf-r"><b>'+h(p.stu||p.sid)+'</b><span class="csf-tag">'+h(cat(p.cat))+'</span></div><div class="csf-mu">'+h(p.sid)+(p.cls?' · '+h(p.cls):'')+(p.title?' · '+h(p.title):'')+'</div><div class="csf-amt">'+h(money(p.amt,p.cur))+'</div>'+
  '<div class="csf-kv"><span>'+t('meth')+'</span><span>'+h(p.method)+'</span></div><div class="csf-kv"><span>'+t('snd')+'</span><span>'+h(p.from_no)+'</span></div><div class="csf-kv"><span>'+t('rcv')+'</span><span>'+h(p.rcv_no||'—')+'</span></div><div class="csf-kv"><span>TrxID</span><span>'+h(p.trx)+'</span></div><div class="csf-mu">'+h(dt(p.created))+'</div>'+
  '<div class="csf-r" style="margin-top:10px"><button class="csf-sm csf-ok" style="flex:2;padding:12px" data-csf="ap" data-id="'+h(p.id)+'">✓ '+t('approve')+'</button><button class="csf-sm csf-no" style="flex:1;padding:12px" data-csf="rj" data-id="'+h(p.id)+'">✕ '+t('reject')+'</button></div></div>'}).join('')||'<div class="csf-mu" style="padding:10px 0">'+t('empty')+'</div>';
 if(q.recent.length)o+='<div class="csf-mu" style="margin:10px 0 4px">'+t('recent')+'</div>'+q.recent.map(function(p){return'<div class="csf-kv"><span>'+(p.status==='approved'?'✅':'❌')+' '+h(p.stu||p.sid)+' · '+h(p.title||cat(p.cat))+'</span><span>'+h(money(p.amt,p.cur))+'</span></div>'}).join('');return o}
function annView(q){var o='<label>'+t('cat')+'</label><select id="fa-cat"><option value="Monthly Fee">'+t('Mo')+'</option><option value="Exam Fee">'+t('Ex')+'</option><option value="Admission Fee">'+t('Ad')+'</option><option value="Custom">'+t('Cu')+'</option></select>'+
 '<label>'+t('title')+'</label><input id="fa-title" maxlength="80"><div class="csf-r"><div style="flex:2"><label>'+t('amount')+'</label><input id="fa-amt" type="number" min="1" step="0.01" inputmode="decimal"></div><div style="flex:1"><label>'+t('cur')+'</label><select id="fa-cur"><option>BDT</option><option>USD</option></select></div></div>'+
 '<label>'+t('dueOn')+'</label><input id="fa-due" type="date"><label>'+t('pub')+'</label><input id="fa-at" type="datetime-local">'+
 '<label>'+t('tgt')+'</label><select id="fa-t"><option value="all">'+t('all')+'</option><option value="cls">'+t('cls')+'</option><option value="ids">'+t('ids')+'</option></select><input id="fa-tv" placeholder="Class 5 / ID1, ID2" style="margin-top:6px">'+
 '<label style="display:flex;gap:8px;align-items:center"><input id="fa-rep" type="checkbox" style="width:auto"> '+t('rep')+'</label><div class="csf-err" id="fa-err"></div><button class="csf-pay" data-csf="an">'+t('create')+'</button>';
 if(q.batches.length)o+='<div class="csf-mu" style="margin:14px 0 4px">'+t('batches')+'</div>'+q.batches.map(function(b){return'<div class="csf-kv"><span>'+h(b.title||cat(b.cat))+' · '+h(money(b.amt,b.cur))+' · '+b.n+(b.open?' ('+b.open+' '+t('due')+')':'')+'</span><span>'+(b.open?'<button class="csf-sm" data-csf="vb" data-id="'+h(b.batch)+'">'+t('cancel')+'</button>':'')+'</span></div>'}).join('');
 if(q.rules.length)o+='<div class="csf-mu" style="margin:14px 0 4px">'+t('rules')+'</div>'+q.rules.map(function(r){return'<div class="csf-kv"><span>'+h(r.title||cat(r.cat))+' · '+h(money(r.amt,r.cur))+'</span><span><button class="csf-sm" data-csf="vr" data-id="'+h(r.id)+'">'+t('stop')+'</button></span></div>'}).join('');return o}
function loadCfg(){api('/api/fee/cfg',{},A.tok).then(function(j){A.cfg=j.cfg;sheet()}).catch(function(){})}
function setView(){var c=A.cfg;if(!c)return'<div class="csf-mu">…</div>';var o='';
 MFS.forEach(function(g){var m=c.m[g];o+='<label>'+g+' · '+t('num')+'</label><div class="csf-r"><input data-fc="'+g+'.no" value="'+h(m.no)+'" inputmode="tel" style="flex:2"><select data-fc="'+g+'.kind" style="flex:1">'+['Personal','Agent','Merchant'].map(function(k){return'<option'+(m.kind===k?' selected':'')+'>'+k+'</option>'}).join('')+'</select></div>'});
 ['SSLCommerz'].concat(GLOB).forEach(function(g){var m=c.m[g];o+='<label>'+g+'</label><input data-fc="'+g+'.url" placeholder="'+t('link')+'" value="'+h(m.url)+'"><input data-fc="'+g+'.no" placeholder="'+t('num')+'" value="'+h(m.no)+'" style="margin-top:6px"><input data-fc="'+g+'.note" placeholder="'+t('note')+'" value="'+h(m.note)+'" style="margin-top:6px">'});
 return o+'<label>'+t('rate')+'</label><input data-fc="rate" type="number" step="0.01" value="'+(c.rate||'')+'"><div class="csf-err" id="fs-err"></div><button class="csf-pay" data-csf="sv">'+t('save')+'</button>'}
function stCall(p,b,done){api(p,b,A.tok).then(function(j){A.busy=0;stPoll();if(done)done(j)}).catch(function(e){toast(e.message||t('err'))})}

/* ---------- one click handler for everything ---------- */
function act(a,el){var id=el&&el.getAttribute('data-id');
 if(a==='sheet'){A.open=true;sheet()}
 else if(a==='x'){A.open=false;A.edit=0;$('csf-sheet').className='csf-ov'}
 else if(a==='pay')pay(id);
 else if(a==='m'){M.m=id;draft();modal()}
 else if(a==='cur'){M.cur=id;M.m='';modal()}
 else if(a==='submit')submit();
 else if(a==='cx')closePay();
 else if(a==='rc')receipt(id);
 else if(a==='rx'){$('csf-modal').className='csf-ov';$('csf-modal').innerHTML=''}
 else if(a==='cp'||a==='cl')copy(id);
 else if(a==='tab'){A.tab=id;A.edit=0;sheet()}
 else if(a==='ap')stCall('/api/fee/decide',{id:id,act:'approve'},function(){toast('✅')});
 else if(a==='rj'){var r=window.prompt(t('why'),'');if(r===null)return;stCall('/api/fee/decide',{id:id,act:'reject',reason:r},function(){toast('✕')})}
 else if(a==='vb')stCall('/api/fee/rule',{batch:id});
 else if(a==='vr')stCall('/api/fee/rule',{rule:id});
 else if(a==='an'){var v=function(i){return($(i)||{}).value||''},tg=v('fa-t'),at=v('fa-at')?new Date(v('fa-at')).getTime():0,b={cat:v('fa-cat'),title:v('fa-title'),amt:v('fa-amt'),cur:v('fa-cur'),due_on:v('fa-due'),at:at,repeat:$('fa-rep').checked?'monthly':''};
  if(tg==='cls')b.cls=v('fa-tv');if(tg==='ids')b.sids=v('fa-tv');api('/api/fee/announce',b,A.tok).then(function(j){toast(j.scheduled&&!j.created?t('sched'):j.created+' '+t('made'));A.busy=0;stPoll();A.tab='q';sheet()}).catch(function(e){var el=$('fa-err');if(el)el.textContent=e.message||t('err')})}
 else if(a==='sv'){var c=JSON.parse(JSON.stringify(A.cfg));D.querySelectorAll('#csf-sheet [data-fc]').forEach(function(i){var p=i.getAttribute('data-fc').split('.');if(p.length===1)c.rate=+i.value||0;else c.m[p[0]][p[1]]=i.value});
  api('/api/fee/cfg',{set:c},A.tok).then(function(j){A.cfg=j.cfg;toast(t('saved'))}).catch(function(e){var el=$('fs-err');if(el)el.textContent=e.message==='Only the Admin can change merchant numbers'?t('onlyAdmin'):(e.message||t('err'))})}}
D.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('[data-csf]');if(b){e.preventDefault();act(b.getAttribute('data-csf'),b);return}
 var ov=e.target;if(ov&&ov.id==='csf-modal'&&M)closePay();else if(ov&&ov.id==='csf-sheet'){A.open=false;ov.className='csf-ov'}},true);
D.addEventListener('input',function(e){var i=e.target&&e.target.id;if(M&&(i==='csf-from'||i==='csf-trx')){M[i==='csf-from'?'from':'trx']=e.target.value;sched()}if(i&&i.indexOf('fa-')===0)A.edit=1});
window.addEventListener('pagehide',function(){if(M)draft()});
D.addEventListener('visibilitychange',function(){if(D.hidden&&M)draft()});
})();
</script>`; /* guardian / student fee cards, Pay Now modal, draft recovery, receipts; staff Payment Approvals */
const htmlHeaders=(main,more={})=>({'content-type':'text/html; charset=utf-8','cache-control':'public, max-age=0, must-revalidate','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin','strict-transport-security':'max-age=31536000','permissions-policy':'camera=(), microphone=(self), geolocation=()',...(main?{}:{'x-robots-tag':'noindex, nofollow'}),...more});
const file=(body,type,main,ttl=3600,more={})=>new Response(body,{headers:{'content-type':type+'; charset=utf-8','cache-control':ttl?'public, max-age='+ttl:'no-cache','x-content-type-options':'nosniff',...(main?{}:{'x-robots-tag':'noindex, nofollow'}),...more}});
const notFound=()=>new Response('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Page not found | ClasSphera</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070812;color:#e6e9f5;font-family:Inter,system-ui,sans-serif;text-align:center;padding:1rem}a{color:#34d399}</style></head><body><main><h1>Page not found</h1><p><a href="/">Back to ClasSphera</a></p></main></body></html>',{status:404,headers:htmlHeaders(false,{'cache-control':'no-store'})});
function tenantSub(host){for(const r of ROOTS){if(host.endsWith('.'+r)){const s=host.slice(0,-(r.length+1));if(SUBRX.test(s)&&!RESERVED.includes(s))return s}}return null}
async function page(req,env,ctx,u,main,p,o){
 o=o||{};const host=o.host||u.hostname,cache=typeof caches!=='undefined'?caches.default:null,ck=new Request('https://cache.classphera.invalid/'+APP_V+'/'+host+p.path+(o.sub?'?t='+o.sub+'&n='+encodeURIComponent(o.title||''):''));
 if(cache){const h=await cache.match(ck);if(h)return new Response(h.body,{status:200,headers:htmlHeaders(main)})}
 const base=await env.ASSETS.fetch(new Request(u.origin+'/'));if(!base.ok)return base;
 const url=o.sub?`https://${host}/`:SITE+(p.path==='/'?'/':p.path),T=o.sub?{title:o.title,desc:o.desc}:p,SD=o.sub?T.desc:T.desc+BN_DESC,set=(a,v)=>({element(e){e.setAttribute(a,v)}});
 const rw=new HTMLRewriter()
  .on('title',{element(e){e.setInnerContent(T.title)}})
  .on('meta[name="description"]',set('content',SD)).on('meta[property="og:title"]',set('content',T.title)).on('meta[property="og:description"]',set('content',SD))
  .on('meta[name="twitter:title"]',set('content',T.title)).on('meta[name="twitter:description"]',set('content',T.desc))
  .on('link[rel="canonical"]',set('href',url)).on('meta[property="og:url"]',set('content',url))
  .on('script[type="application/ld+json"]',{element(e){e.remove()}});
 const rw2=main?rw:rw.on('meta[name="robots"]',set('content','noindex,nofollow')),
 tenantJs=o.sub?`<script>try{history.replaceState(null,'',location.pathname+'?sub=${o.sub}'+location.hash)}catch(e){}</script>`:'';
 const out=rw2.on('head',{element(e){e.append('<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="manifest" href="/manifest.webmanifest"><meta property="og:image" content="'+SITE+'/icon-512.png"><meta name="twitter:image" content="'+SITE+'/icon-512.png"><meta property="og:locale" content="en"><meta name="cs-app-version" content="'+APP_V+'">'+(o.sub?'':'<meta name="keywords" content="ClasSphera, Classphera, class sphera, QVMPXT, school management software, madrasah management, institution management system, student attendance, marksheet, fee collection, '+BN_KW+'">')+LD(o.sub?{...p,path:'/',title:T.title,desc:T.desc}:{...p,bn:1})+BOOT()+tenantJs+'<style>body:not([data-view="home"]) #cs-nav{display:none!important}</style>',{html:true})}})
  .on('main#app',{element(e){e.setInnerContent(p.body(),{html:true})}})
  .on('footer#foot',{element(e){if(p.path==='/'&&!o.sub)e.after(NAV,{html:true})}})
  .on('body',{element(e){e.append(CLIENT_PATCH+FEE_PAY_PATCH,{html:true})}}).transform(base);
 const buf=await out.arrayBuffer();
 if(cache&&ctx&&ctx.waitUntil)ctx.waitUntil(cache.put(ck,new Response(buf,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'public, max-age=120'}})).catch(()=>{}));
 return new Response(buf,{status:200,headers:htmlHeaders(main)})}
async function site(req,env,ctx,u,host,main,tenant){
 const path=u.pathname;
 if(req.method!=='GET'&&req.method!=='HEAD')return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
 if(tenant){
  if(path==='/robots.txt')return file(`User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: https://${host}/sitemap.xml\n`,'text/plain',true);
  if(path==='/sitemap.xml')return file(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>https://${host}/</loc><lastmod>${env.SITE_LASTMOD||LASTMOD}</lastmod><changefreq>monthly</changefreq><priority>1.0</priority></url>\n</urlset>\n`,'application/xml',true);
  if(path==='/'||path==='/index.html'){
   let name='';try{await migrate(env);const r=await dbInst(env,tenant);if(r&&r.name)name=String(r.name)}catch{}
   const label=name||tenant;
   return page(req,env,ctx,u,true,BYPATH['/'],{sub:tenant,host,title:`${label} | Secure Login · ${BRAND}`,desc:`${TAG} Secure sign-in for ${label}. Student records, attendance, marksheets and fees on ${BRAND}.`})}
  if(BYPATH[path]||ALIAS[path])return Response.redirect(SITE+(ALIAS[path]||path),301)}
 if(path==='/robots.txt')return file(main?ROBOTS():'User-agent: *\nDisallow: /\n','text/plain',main);
 if(path==='/sitemap.xml')return main?file(SITEMAP(env),'application/xml',main):notFound();
 if(path==='/manifest.webmanifest')return file(MANIFEST,'application/manifest+json',main,86400);
 if(path==='/favicon.svg')return file(FAVICON,'image/svg+xml',main,86400);
 if(ICONS[path]){try{const r=await env.ASSETS.fetch(req),ct=r.headers.get('content-type')||'';if(r.ok&&/^image\//.test(ct))return r}catch{}
  const png=await memo('icon'+ICONS[path],3600000,()=>iconPng(ICONS[path]));return new Response(png,{headers:{'content-type':'image/png','cache-control':'public, max-age=604800','x-content-type-options':'nosniff'}})}
 if(path==='/.well-known/security.txt')return file(`Contact: mailto:${FOUNDER_MAIL}\nExpires: ${new Date(Date.now()+364*864e5).toISOString()}\nPreferred-Languages: en, bn\nCanonical: ${SITE}/.well-known/security.txt\n`,'text/plain',main);
 if(path==='/sw.js')return file(SW,'application/javascript',main,0,{'service-worker-allowed':'/'});
 if(ALIAS[path])return Response.redirect(u.origin+ALIAS[path]+u.search,301);
 if(path.length>1&&path.endsWith('/'))return Response.redirect(u.origin+path.replace(/\/+$/,'')+u.search,301);
 const p=BYPATH[path];if(p)return page(req,env,ctx,u,main,p);
 if(/\.[a-z0-9]{2,8}$/i.test(path)){
  const r=await env.ASSETS.fetch(req),ct=r.headers.get('content-type')||'';
  if(r.status===200&&ct.includes('text/html'))return notFound();
  if(main)return r;const h=new Headers(r.headers);h.set('x-robots-tag','noindex, nofollow');return new Response(r.body,{status:r.status,headers:h})}
 return notFound()}

/* housekeeping: runs from a Cron trigger when this file is deployed as a standalone Worker */
async function maintenance(env){
 await migrate(env);const d90=new Date(Date.now()-90*864e5).toISOString(),d180=new Date(Date.now()-180*864e5).toISOString();
 await env.DB.batch([sq(env,"DELETE FROM events WHERE at<? AND kind IN ('audit','sync')",d90),sq(env,'DELETE FROM alerts WHERE at<?',d90),sq(env,'DELETE FROM kvx WHERE exp>0 AND exp<?',Math.floor(Date.now()/1000)),sq(env,'DELETE FROM portal_inbox WHERE at<?',Date.now()-90*864e5),sq(env,'DELETE FROM portal_out WHERE at<?',Date.now()-90*864e5),sq(env,'DELETE FROM trusted WHERE last_seen<?',d180),sq(env,'DELETE FROM audit WHERE at<?',new Date(Date.now()-365*864e5).toISOString())]);
 await planRemind(env).catch(e=>console.error('plan reminders',e&&e.message))}

export default{
 async fetch(req,env,ctx){
  env=withKV(env);
  const u=new URL(req.url),host=u.hostname.toLowerCase(),ip=req.headers.get('cf-connecting-ip')||'unknown',tenant=tenantSub(host),main=host===APEX||!!tenant;
  if(u.protocol==='http:'&&main)return Response.redirect('https://'+u.host+u.pathname+u.search,301);
  if(u.pathname==='/auth/callback'&&(req.method==='GET'||req.method==='HEAD'))return await oauthCallback(env,u);
  if(u.pathname.startsWith('/api/'))return api(req,env,ctx,u,ip,tenant);
  try{return await site(req,env,ctx,u,host,main,tenant)}
  catch(e){if(ctx&&ctx.waitUntil)ctx.waitUntil(sysAlert(env,'PAGE_EXCEPTION',`${u.pathname}: ${String(e&&e.message).slice(0,200)}`,{key:u.pathname,ttl:900,ip}));return new Response('Server error',{status:500,headers:{'cache-control':'no-store','x-robots-tag':'noindex'}})}},
async scheduled(ev,env,ctx){env=withKV(env);ctx.waitUntil(maintenance(env).catch(e=>sysAlert(env,'MAINTENANCE_FAILED',String(e&&e.message))))}
};
