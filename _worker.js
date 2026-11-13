/* ClasSphera backend · QVMPXT · Cloudflare Pages advanced mode (_worker.js) · v2.8.0
   "One platform. Complete control. Zero compromise."

   BINDINGS   DB (D1) · KV (KV namespace) · ASSETS (automatic on Pages) · R2 (optional: snapshots, backups, audit) · AI (optional: Workers AI)
   SECRETS    TG_TOKEN, TG_CHAT, MASTER_KEY (16+ chars; also signs sessions unless JWT_SECRET is set)
   OPTIONAL   JWT_SECRET · GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET · STRIPE_KEY · STRIPE_WEBHOOK_SECRET
              TWILIO_SID/TWILIO_TOKEN/TWILIO_FROM/TWILIO_WA_FROM · MAIL_KEY + MAIL_FROM (Resend) · FOUNDER_EMAIL
              SMS_DAILY_CAP · OTP_DAILY_CAP · AI_DAILY_CAP · SLOW_MS · SITE_LASTMOD
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
const APP_V='2.8.0',API_SCHEMA='2.8.0',DATA_SCHEMA=3,MIN_CLIENT_MAJOR=2;
const TAG='One platform. Complete control. Zero compromise.',BRAND='ClasSphera by QVMPXT';
const FOUNDER_MAIL='marufchowdhury579@gmail.com',FOUNDER_PHONE='+8801347272307',FOUNDER='M MARUF CHOWDHURY';
const ROOTS=[APEX,'classphera.com','classsphera.com'];
const AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const GATES=['bKash','Nagad','Rocket','SSLCommerz','Visa','Mastercard','Stripe','PayPal','Bitcoin','USDT Vault','Cash','Bank transfer'];
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
['2.4',['DROP INDEX IF EXISTS idx_kvx_exp']] /* an index doubles the write cost of every put; the table is small and purged, so a scan is cheaper */
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
async function tg(env,text){if(!env.TG_TOKEN||!env.TG_CHAT)return false;try{const r=await fetch(`https://api.telegram.org/bot${env.TG_TOKEN}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:env.TG_CHAT,text:text.slice(0,4000),parse_mode:'HTML',disable_web_page_preview:true})});return r.ok}catch{return false}}
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
 if(!env.MAIL_KEY||!env.MAIL_FROM||!MAILRX.test(String(to||'')))return false;
 try{const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+env.MAIL_KEY,'content-type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM,to:[to],subject,html,text})});return r.ok}catch{return false}}
async function twilio(env,to,body,wa){
 if(!env.TWILIO_SID||!env.TWILIO_TOKEN)return false;const from=wa?(env.TWILIO_WA_FROM?'whatsapp:'+env.TWILIO_WA_FROM:''):env.TWILIO_FROM;if(!from)return false;
 try{const r=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`,{method:'POST',headers:{authorization:'Basic '+btoa(env.TWILIO_SID+':'+env.TWILIO_TOKEN)},body:new URLSearchParams({To:(wa?'whatsapp:':'')+to,From:from,Body:body})});return r.ok}catch{return false}}
async function sendOtp(env,mail,phone,code){
 const ok=await sendMail(env,mail,'Your ClasSphera verification code',`<div style="font-family:Inter,Arial,sans-serif;background:#070812;color:#e6e9f5;padding:28px;border-radius:16px;max-width:420px"><h2 style="margin:0 0 8px">ClasSphera 🔐</h2><p style="color:#9aa1b9">Your 6-digit verification code:</p><p style="font-size:34px;font-weight:800;letter-spacing:10px;color:#34d399;margin:14px 0">${code}</p><p style="color:#9aa1b9;font-size:12px">Valid for 5 minutes. If this was not you, ignore this message and tell your Principal.</p></div>`,`ClasSphera code: ${code} (valid 5 minutes)`);
 if(ok)return 'mail';
 if(/^\+\d{7,15}$/.test(phone)&&await twilio(env,phone,`ClasSphera code: ${code}. Valid 5 minutes.`))return 'sms';
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
 const rd={},cl={},pv={};
 for(const k of keys){const r=t.__rd&&t.__rd[k];if(r&&typeof r==='object')rd[k]=r;const c=t.__clr&&t.__clr[k];if(c&&typeof c==='object'&&c[me]!==undefined)cl[k]={[me]:c[me]}}
 em.forEach(e=>{if(t.__pav&&typeof t.__pav[e]==='string')pv[e]=t.__pav[e]});
 o.__rd=rd;o.__clr=cl;o.__pav=pv;return JSON.stringify(o)}catch{return'{}'}}
async function thMerge(env,sub,inc,me,role){const st=await getJson(env,sub,'th'),S0=st&&typeof st==='object'&&!Array.isArray(st)?st:{};
 if(!inc||typeof inc!=='object'||Array.isArray(inc)||Object.keys(inc).length>3000)return S0;
 const out={...S0},ok=[];out.__rd={...(S0.__rd||{})};out.__clr={...(S0.__clr||{})};out.__pav={...(S0.__pav||{})};
 for(const k of Object.keys(inc)){if(k.slice(0,2)==='__'||!THK.test(k)||!Array.isArray(inc[k]))continue;
  const sa=Array.isArray(S0[k])?S0[k]:[],ia=inc[k];if(!thParty(k,sa,me)||ia.length>20000)continue;
  if(!ia.every(m=>m&&typeof m==='object'&&!Array.isArray(m)&&typeof m.f==='string'))continue;
  if(JSON.stringify(sa.filter(m=>m&&m.f!==me))!==JSON.stringify(ia.filter(m=>m.f!==me)))continue;
  out[k]=ia.map(m=>m.f===me?{...m,r:role}:m);ok.push(k)}
 for(const f of['__rd','__clr']){const src=inc[f];if(!src||typeof src!=='object')continue;
  for(const k of Object.keys(src)){if(!THK.test(k)||!Array.isArray(out[k])||!thParty(k,out[k],me))continue;const v=src[k]&&src[k][me];if(typeof v!=='number'||!isFinite(v))continue;
   out[f][k]={...(out[f][k]||{}),[me]:Math.max(0,Math.min(out[k].length,Math.floor(v)))}}}
 const a=inc.__pav&&inc.__pav[me];if(typeof a==='string'&&THPAV.test(a))out.__pav[me]=a;
 for(const k of ok)for(const f of['__rd','__clr']){const r=out[f][k];if(r&&typeof r==='object')for(const e of Object.keys(r))if(+r[e]>out[k].length)r[e]=out[k].length}
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
 const r=await sq(env,"SELECT item,gateway,at FROM payments WHERE sub=? AND status='paid' AND item LIKE '%plan%' ORDER BY at DESC LIMIT 1",sub).first();if(!r)return null;
 const until=new Date(r.at).getTime()+(/annual/i.test(r.item)?366:31)*864e5;if(until<Date.now())return null;
 return{name:r.item,gateway:r.gateway,status:'paid',until:new Date(until).toISOString()}}

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
  const t=await issue(C,{sub,ph:adm.email,role:'Admin'},fp);return sessResp(t,{revs:r.revs})
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
 const cr=isO(b.revs)?b.revs:null;
 const pack=(rows,gone)=>{const f=[],rv={};for(const[k,x]of rows){if(x.deleted||!x.raw||hiddenFor(s.role,k))continue;f.push(JSON.stringify(k)+':'+(k==='users'&&s.role!=='Admin'?redactUsers(x.raw,s.ph):k==='th'?thView(x.raw,s.ph):x.raw));rv[k]=x.rev}return{f,rv,gone}};
 if(!cr){const rows=await readParts(env,s.sub,null);if(!rows.size)throw new Err(404,'workspace not found');const p=pack(rows,[]);return JR('{"ws":{'+p.f.join(',')+'},"revs":'+JSON.stringify(p.rv)+'}')}
 const meta=(await sq(env,'SELECT k,rev,deleted FROM ws_parts WHERE sub=?',s.sub).all()).results||[],live=[],gone=[];
 for(const r of meta){if(hiddenFor(s.role,r.k))continue;const c=cr[r.k];if(r.deleted){if(c!==undefined&&+c!==r.rev)gone.push(r.k)}else if(+c!==r.rev)live.push(r.k)}
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
 if(P.th!==undefined)P.th=await thMerge(env,s.sub,P.th,s.ph,s.role);
 if(P.plan!==undefined){const cp=await confirmedPlan(env,s.sub);P.plan=cp||(isO(P.plan)?{name:str(P.plan.name,60),gateway:str(P.plan.gateway,30),status:'pending'}:null)}
 const S2={};for(const[k,v]of Object.entries(P)){const t=JSON.stringify(v===undefined?null:v);if(t.length>PART_MAX)throw new Err(413,`Section ${k} is too large`);S2[k]=t}
 const oldUsers=P.users!==undefined?await getJson(env,s.sub,'users'):null;
 const r=await commitParts(env,s.sub,{parts:S2,del:D,revs});
 if(r.conflict){const cur=await partMeta(env,s.sub,[...Object.keys(S2),...D]),cf=[...Object.keys(S2),...D].filter(k=>(cur.get(k)?cur.get(k).rev:0)!==(+revs[k]||0));return conflictResp(env,s.sub,cf.length?cf:r.conflict,s.ph)}
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
 const temp=rnd(6),salt=rnd(8).toUpperCase(),p=await sha('cs:'+salt+temp);let done=false;
 await mutatePart(env,sub,'users',us=>{if(!Array.isArray(us))throw new Err(404,'workspace not found');const a=us.find(u=>u.role==='Admin');if(!a)throw new Err(404,'no administrator found');a.salt=salt;a.p=p;done=true;return us});
 if(!done)throw new Err(404,'workspace not found');
 await env.KV.put('sxr:'+sub,String(nowS()),{expirationTtl:90000});memoDel('rv:'+sub+':');
 await env.KV.put('skipotp:'+sub,'1',{expirationTtl:1800});
 await alert(env,ip,'Master override used',`workspace ${sub}`);return J({temp})}

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
async function notifyCh(C){
 const s=await auth(C),d=envelope(C),env=C.env,ch=C.path.split('/').pop();
 if(!s){if(d.tenant==='demo'||C.b.tenant==='demo')return J({ok:true,dropped:true},202);throw new Err(401,'invalid session')}
 if(!['Admin','Teacher'].includes(s.role))throw new Err(403,'Your role cannot send alerts');
 const ev=str(d.event,60),msg=str(d.msg,160).replace(/https?:\/\/\S+/gi,''),to=nph(d.to);
 if(!ev||!msg)throw new Err(400,'event and message are required');
 let status='local';
 if(ch==='sms'||ch==='whatsapp'){
  if(!PHONERX.test(to))throw new Err(400,'invalid phone');
  if(await spend(env,'smsw:'+s.sub,1,100,86400)||await spend(env,'smsg',1,+env.SMS_DAILY_CAP||500,86400))throw new Err(429,'daily limit');
  status=await twilio(env,to,msg,ch==='whatsapp')?'sent':'queued_unconfigured'}
 await sq(env,'INSERT INTO events(sub,kind,data,at) VALUES(?,?,?,?)',s.sub,'out:'+ch,JSON.stringify({to,event:ev,msg,status}),iso()).run();
 return J({ok:true,status})}
async function notifyLegacy(C){ /* {sub,id,key,messages:[{to,name,status,inst}]} → {sent,failed}; the server writes the SMS text itself */
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');
 await tenantAuth(C,sub,['Admin','Teacher']);
 if(!env.TWILIO_SID||!env.TWILIO_TOKEN||!env.TWILIO_FROM)throw new Err(503,'SMS provider not configured');
 if(hitMem('sms:'+C.ip,12,3600000))throw new Err(429,'rate limited');
 const nm=v=>String(v||'').replace(/[^\p{L}\p{M}\p{N} ,'’()&-]/gu,'').replace(/\s+/g,' ').trim(),m=[];
 for(const a of(Array.isArray(b.messages)?b.messages:[]).slice(0,100)){const to=nph(a&&a.to),st=String(a&&a.status||'').toLowerCase(),name=nm(a&&a.name).slice(0,60),inst=nm(a&&a.inst).slice(0,80);
  if(PHONERX.test(to)&&(st==='present'||st==='absent'||st==='late')&&name&&inst)m.push({to,text:`${name} was ${st} today at ${inst}.`})}
 if(!m.length)throw new Err(400,'no valid recipients');
 if(await spend(env,'smsw:'+sub,m.length,100,86400)||await spend(env,'smsg',m.length,+env.SMS_DAILY_CAP||500,86400))throw new Err(429,'daily limit');
 const r=await Promise.allSettled(m.map(a=>twilio(env,a.to,a.text,false).then(ok=>{if(!ok)throw 0}))),sent=r.filter(x=>x.status==='fulfilled').length;
 return J({sent,failed:r.length-sent},sent?200:502)}
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
async function checkout(C){
 const{b,env,ip}=C,cur=/^[A-Z]{3}$/.test(String(b.cur||''))?b.cur:'USD',usd=Math.round(+b.usd*100)/100,item=(str(b.item,100)+(cur==='USD'?'':' ['+cur+']')).trim();
 if(!GATES.includes(b.gateway)||!(usd>0&&usd<=(cur==='USD'?5000:5e6))||!item)throw new Err(400,'invalid payment');
 if(await hit(env,'pay:'+ip,20,3600))throw new Err(429,'rate limited');
 const id='PAY-'+rnd(5).toUpperCase(),s=await auth(C),sub=s?s.sub:(wsn(b.sub)||null),txid=str(b.txid,80);let url=null;
 await sq(env,'INSERT INTO payments(id,sub,gateway,item,usd,txid,status,at) VALUES(?,?,?,?,?,?,?,?)',id,sub,b.gateway,item,usd,txid,'pending',iso()).run();
 if(b.gateway==='Stripe'&&env.STRIPE_KEY){try{const r=await fetch('https://api.stripe.com/v1/checkout/sessions',{method:'POST',headers:{authorization:'Bearer '+env.STRIPE_KEY,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({mode:'payment','line_items[0][price_data][currency]':cur.toLowerCase(),'line_items[0][price_data][product_data][name]':item,'line_items[0][price_data][unit_amount]':String(Math.round(usd*100)),'line_items[0][quantity]':'1',success_url:C.u.origin+'/#dash',cancel_url:C.u.origin+'/#dash','metadata[payment_id]':id})});url=(await r.json()).url||null}catch{url=null}}
 await tg(env,`💳 <b>Payment ${id}</b>\n${X(item)} · ${cur==='USD'?'$':cur+' '}${usd}\n${X(b.gateway)} · TxID ${X(txid||'-')}\nWorkspace: ${X(sub||'visitor')}${b.institutionId?' · '+X(str(b.institutionId,40)):''}`);
 return J({status:'pending',url,message:url?'Redirecting to secure checkout':'Payment recorded. Access activates once the founder verifies it.'})}
async function markPaid(C,id,by){
 const env=C.env,r=await sq(env,'SELECT * FROM payments WHERE id=?',id).first();if(!r)return null;
 await sq(env,"UPDATE payments SET status='paid' WHERE id=?",id).run();
 if(r.sub&&/plan/i.test(r.item)){const plan={name:r.item,gateway:r.gateway,status:'paid',until:new Date(Date.now()+(/annual/i.test(r.item)?366:31)*864e5).toISOString()};try{await mutatePart(env,r.sub,'plan',()=>plan)}catch{}}
 await tg(env,`✅ <b>Payment ${X(id)} confirmed</b> by ${X(by)}\n${X(r.item)} · ${X(r.sub||'-')}`);return r}
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
function proj(d,who){
 d=JSON.parse(JSON.stringify(d||{}));
 if(who==='student'){const r=d.rec||{},i=d.inst||{},s=d.stu||{};d={v:d.v,at:d.at,inst:{name:i.name,type:i.type,logo:i.logo,cctv:false},stu:{id:s.id,name:s.name,cls:s.cls,house:s.house,photo:s.photo},marks:d.marks||{},rec:{lesson:r.lesson||[],module:r.module||[],task:r.task||[]},quran:d.quran||''}}
 else if(!(d.inst&&d.inst.cctv))d.cam='';
 return d}
const hx=(v,n)=>typeof v==='string'&&new RegExp('^[0-9a-f]{'+n+'}$').test(v);
async function gSync(C){
 const{b,env}=C,sub=wsn(b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');
 await tenantAuth(C,sub,['Admin']);if(hitMem('gsy:'+sub,60,3600000))throw new Err(429,'rate limited');
 const list=Array.isArray(b.students)?b.students:[],rows=[];
 for(const s of list.slice(0,20000)){const id=String(s&&s.id||'').toUpperCase();if(!/^[A-Z0-9-]{1,24}$/.test(id)||!isO(s.d))continue;if(JSON.stringify(s.d).length>60000)continue;
  rows.push({id,ph:String(s.ph||'').replace(/\D/g,'').slice(-10),gh:hx(s.gh,64)?s.gh:'',gs:hx(s.gs,16)?s.gs:'',sh:hx(s.sh,64)?s.sh:'',ss:hx(s.ss,16)?s.ss:'',d:s.d})}
 if(list.length&&!rows.length)throw new Err(400,'no valid students');
 const gen=Date.now(),at=iso(),st=[];let cur=[],sz=0;
 const flush=()=>{if(cur.length)st.push(sq(env,"INSERT INTO portal(sub,sid,ph,gh,gs,sh,ss,d,gen,updated) SELECT ?1,json_extract(value,'$.id'),json_extract(value,'$.ph'),json_extract(value,'$.gh'),json_extract(value,'$.gs'),json_extract(value,'$.sh'),json_extract(value,'$.ss'),json_extract(value,'$.d'),?3,?4 FROM json_each(?2) WHERE 1 ON CONFLICT(sub,sid) DO UPDATE SET ph=excluded.ph,gh=excluded.gh,gs=excluded.gs,sh=excluded.sh,ss=excluded.ss,d=excluded.d,gen=excluded.gen,updated=excluded.updated",sub,JSON.stringify(cur),gen,at));cur=[];sz=0};
 for(const r of rows){const t=JSON.stringify(r).length;if(sz+t>500000)flush();cur.push(r);sz+=t}flush();
 st.push(sq(env,'DELETE FROM portal WHERE sub=?1 AND gen<>?2',sub,gen));
 for(let i=0;i<st.length;i+=40)await env.DB.batch(st.slice(i,i+40));
 return J({ok:true,count:rows.length})}
async function gLogin(C){
 const{b,env,ip}=C,sub=wsn(String(b.sub||'').toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/\.classs?phera\.[a-z.]+$/,'')),sid=str(b.sid,24).toUpperCase(),who=b.who==='student'?'student':'guardian',pin=String(b.pin||'').slice(0,40);
 if(hitMem('gl:'+ip,30,3600000)||await hit(env,'gl:'+ip,20,3600))throw new Err(429,'Too many attempts. Try again later.');
 const fk='gf:'+sub+':'+sid+':'+who,fails=+(await env.KV.get(fk))||0;
 if(fails>=5)throw new Err(429,'Too many wrong attempts. Wait 15 minutes or ask the institution to reset access.');
 const s=SUBRX.test(sub)&&sid?await sq(env,'SELECT * FROM portal WHERE sub=? AND sid=?',sub,sid).first():null;
 const salt=s?(who==='student'?s.ss:s.gs):'0'.repeat(16),want=s?(who==='student'?s.sh:s.gh):'0'.repeat(64);
 const okPin=!!s&&FPRX.test(want)&&eq(await sha(pin+':'+salt),want),okPh=who==='student'||(!!s&&s.ph.length>=7&&String(b.phone||'').replace(/\D/g,'').slice(-10)===s.ph);
 if(!(okPin&&okPh)){await env.KV.put(fk,String(fails+1),{expirationTtl:900});await fail(env,ip,'guardian login '+sub);throw new Err(401,'Details did not match. Check the ID, mobile number and PIN.')}
 await env.KV.delete(fk);const token=rnd(24);await env.KV.put('gt:'+token,JSON.stringify({sub,sid,who}),{expirationTtl:43200});
 let d={};try{d=JSON.parse(s.d)}catch{}return J({token,who,d:proj(d,who)})}
async function gData(C){
 const t=JSON.parse(await C.env.KV.get('gt:'+String(C.b.token||'').slice(0,60))||'null');if(!t)throw new Err(401,'expired');
 const s=await sq(C.env,'SELECT d FROM portal WHERE sub=? AND sid=?',t.sub,t.sid).first();if(!s)throw new Err(401,'expired');
 let d={};try{d=JSON.parse(s.d)}catch{}return J({d:proj(d,t.who)})}
async function gSend(C){
 const{b,env}=C,tk=String(b.token||'').slice(0,60),t=JSON.parse(await env.KV.get('gt:'+tk)||'null');if(!t||t.who!=='guardian')throw new Err(401,'expired');
 const x=String(b.text||'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').trim().slice(0,1000);if(!x)throw new Err(400,'empty');
 if(await hit(env,'gsd:'+tk,30,3600))throw new Err(429,'rate limited');
 const n=await sq(env,'SELECT COUNT(*) AS n FROM portal_inbox WHERE sub=?',t.sub).first();if(n&&n.n>5000)throw new Err(429,'inbox full');
 const at=Date.now(),r=await sq(env,'INSERT INTO portal_inbox(sub,sid,x,at) VALUES(?,?,?,?)',t.sub,t.sid,x,at).run();return J({ok:true,id:r.meta&&r.meta.last_row_id,at})}
async function gInbox(C){
 const sub=wsn(C.b.sub);if(!SUBRX.test(sub))throw new Err(401,'unauthorized');await tenantAuth(C,sub,['Admin']);
 const r=(await sq(C.env,'SELECT id,sid,x,at FROM portal_inbox WHERE sub=? ORDER BY id LIMIT 500',sub).all()).results||[];
 if(r.length)await sq(C.env,'DELETE FROM portal_inbox WHERE sub=? AND id<=?',sub,r[r.length-1].id).run();return J({msgs:r})}
async function gOtp(C){
 const{b,env,ip}=C,sub=wsn(b.sub),sid=str(b.sid,24).toUpperCase();if(!SUBRX.test(sub)||!sid)throw new Err(404,'not found');
 if(hitMem('go:'+ip,6,3600000)||await hit(env,'go:'+sub+':'+sid,3,3600))throw new Err(429,'rate limited');
 if(!(await sq(env,'SELECT 1 AS x FROM portal WHERE sub=? AND sid=?',sub,sid).first()))throw new Err(404,'not found');
 const sts=await getJson(env,sub,'students'),st=Array.isArray(sts)?sts.find(x=>x&&String(x.id).toUpperCase()===sid):null,ph=nph(st&&st.gphone);
 if(!/^\+\d{7,15}$/.test(ph))throw new Err(422,'Guardian phone must include the country code');
 if(await spend(env,'smsg',1,+env.SMS_DAILY_CAP||500,86400))throw new Err(429,'daily limit');
 const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0');
 await env.KV.put('gq:'+sub+':'+sid,JSON.stringify({h:await hmac(env,`gq|${code}|${sub}|${sid}`),n:0}),{expirationTtl:300});
 if(!(await twilio(env,ph,`ClasSphera code: ${code}. Valid 5 minutes.`,false))){await env.KV.delete('gq:'+sub+':'+sid);throw new Err(503,'SMS provider not configured')}
 return J({ok:true})}
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

/* ───────────── Global Online Admission ───────────── */
const CAL={uk:['uk','united kingdom','britain','england','scotland','wales'],bangladesh:['bangladesh'],malaysia:['malaysia'],france:['france']};
const TYK={madrasah:'%madr%',school:'%school%',college:'%colleg%',university:'%univ%',coaching:'%coach%'};
const lk=s=>'%'+String(s).replace(/[\\%_]/g,'\\$&')+'%';
const okLogo=l=>/^https:\/\//.test(l||'')||(/^data:image\//.test(l||'')&&String(l).length<60000)?String(l):'';
async function instSearch(C){
 const{b,env,ip}=C;if(hitMem('is:'+ip,60,600000))throw new Err(429,'rate limited');
 const q=str(b.q,80),loc=str(b.loc,80),tk=/^coach/i.test(b.type)?'coaching':String(b.type||'').toLowerCase().split(' ')[0],country=str(b.country,60).toLowerCase();
 let sql='SELECT sub,name,itype,country,city,address,phone,email,wa,admission,about,logo FROM directory WHERE listed=1';const a=[];
 if(q){const l=lk(q);sql+=" AND (name LIKE ? ESCAPE '\\' OR city LIKE ? ESCAPE '\\' OR country LIKE ? ESCAPE '\\' OR address LIKE ? ESCAPE '\\' OR itype LIKE ? ESCAPE '\\')";a.push(l,l,l,l,l)}
 if(TYK[tk]){sql+=' AND itype LIKE ?';a.push(TYK[tk])}
 if(country&&country!=='all'&&country!=='global'){const al=CAL[country]||[country];sql+=' AND ('+al.map(()=>"country LIKE ? ESCAPE '\\'").join(' OR ')+')';al.forEach(x=>a.push(lk(x)))}
 if(loc){const l=lk(loc);sql+=" AND (city LIKE ? ESCAPE '\\' OR address LIKE ? ESCAPE '\\' OR country LIKE ? ESCAPE '\\')";a.push(l,l,l)}
 sql+=' ORDER BY name LIMIT 50';
 const r=(await sq(env,sql,...a).all()).results||[];return J({items:r.map(x=>({sub:x.sub,name:x.name,type:x.itype,country:x.country,city:x.city,address:x.address,phone:x.phone,email:x.email,wa:x.wa,admission:x.admission,about:x.about,logo:x.logo}))})}
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
 const d=await sq(env,'SELECT name,email,admission FROM directory WHERE sub=? AND listed=1',sub).first();
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
 if(hitMem('ai:'+C.ip,30,3600000)||await spend(env,'ai:'+s.sub,1,+env.AI_DAILY_CAP||300,86400))throw new Err(429,'rate limited');
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
 return J({ok:true,app:APP_V,schema:SCHEMA[SCHEMA.length-1][0],dataSchema:DATA_SCHEMA,institutions:i.n,sections:p.n,bytes:p.bytes,portalRows:po.n,pendingPayments:pay.n,alerts24h:al&&al.n,events:ev.n,r2:!!env.R2,ai:!!env.AI,mail:!!env.MAIL_KEY,sms:!!env.TWILIO_SID})}
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
 '/api/ws/create':wsCreate,'/api/ws/find':wsFind,'/api/ws/salt':wsSalt,'/api/ws/login':wsLogin,'/api/ws/load':wsLoad,'/api/ws/save':wsSave,
 '/api/otp/verify':otpVerify,'/api/session/check':sessCheck,'/api/session/logout':sessLogout,'/api/devices/list':devList,'/api/devices/revoke':devRevoke,
 '/api/passkey/challenge':pkChallenge,'/api/passkey/register':pkRegister,'/api/passkey/verify':pkVerify,'/api/mfa/totp/enable':totpEnable,'/api/mfa/totp/verify':totpVerify,
 '/api/preferences':prefs,'/api/schema/fields':schemaFields,'/api/audit':clientEvent,'/api/sync':clientEvent,
 '/api/notify':notifyLegacy,'/api/notify/sms':notifyCh,'/api/notify/whatsapp':notifyCh,'/api/notify/push':notifyCh,
 '/api/checkout':checkout,'/api/backup':backup,'/api/stripe/webhook':stripeHook,
 '/api/g/sync':gSync,'/api/g/login':gLogin,'/api/g/data':gData,'/api/g/send':gSend,'/api/g/inbox':gInbox,'/api/g/otp':gOtp,'/api/g/quick':gQuick,
 '/api/inst/search':instSearch,'/api/inst/publish':instPublish,'/api/admit/apply':admitApply,'/api/admit/inbox':admitInbox,
 '/api/ai':aiPaper,'/api/ai/report':aiReport,
 '/api/founder/system-alert':fAlert,'/api/founder/webhook':fAlert,'/api/founder/email-fallback':fMail,'/api/founder/health':fHealth,'/api/founder/payment':fPayment,'/api/founder/restore':fRestore};
const BODY_LIMIT={'/api/ws/save':30e6,'/api/ws/create':30e6,'/api/g/sync':25e6,'/api/backup':26e6,'/api/founder/restore':1e5};
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
const PLANS=[['Free','Up to 200 student records',0,['Student and staff directory','Attendance and marksheets','Isolated workspace and unique ID','Community support']],['Starter','Up to 500 students',29,['Student and staff directory','Attendance','Marksheets']],['Institution','Up to 1,500 students',79,['Everything in Starter','AI paper generator','Encrypted finance vault','Role-based team access']],['Sovereign','Unlimited, multi-campus',199,['Everything in Institution','Custom domain','Priority support']]];
const SOLS=[['Schools','Class routines, homework diaries, guardian alerts and report cards.'],['Madrassas','Hostel and meal tracking, Quran progress, Sadaqah ledger and ustad records.'],['Coaching centers','Batch attendance, mock tests and recurring fees.'],['Colleges','Departments, semester results, fee collection and staff payroll.'],['Universities','Faculty, department, program and batch hierarchy at large scale.']];
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
['notify','Multi-Channel Guardian Alerts','Attendance, report, receipt and emergency alerts by SMS, WhatsApp and Web Push, queued safely offline.'],
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
 pg('/signup','home','signup','Sign Up','Create your institution workspace','Sign up for ClasSphera by QVMPXT in three steps and get an isolated, encrypted workspace with its own subdomain, free for up to 200 student records.',()=>`${H1('Sign Up')}<p class="max-w-2xl">Create your institution in three steps: institution details, address and administrator. Every workspace gets its own subdomain, a unique secure ID and a recovery code, and starts completely empty.</p>${plans()}`,'0.9','monthly'),
 pg('/guardian-signup','guard','guardian-signup','Guardian Sign Up','Guardian sign in and registration','ClasSphera by QVMPXT guardian portal: parents see only their own child’s attendance, marks, fees, notices and secure messages with the school.',()=>`${H1('Guardian Sign Up')}<p class="max-w-2xl">Parents and guardians sign in with the institution name, the student’s admission ID, the registered mobile number and a secret PIN given by the institution. You see only your own child’s records.</p>`,'0.8','monthly'),
 pg('/student-signup','guard','student-signup','Student Sign Up','Student sign in and registration','ClasSphera by QVMPXT student portal: students open their own routine, homework, marksheet and Quran progress with an admission ID and PIN.',()=>`${H1('Student Sign Up')}<p class="max-w-2xl">Students sign in with the institution name, admission ID or roll number and a secret PIN. The student portal shows only your own routine, homework, marks and progress.</p>`,'0.8','monthly'),
 pg('/connect','connect','','Connect Us','Connect with the ClasSphera founder','Contact ClasSphera by QVMPXT: founder phone, WhatsApp and email, help and support, feedback, security guidelines and terms.',()=>`${H1('Connect Us')}<div class="glass p-5 max-w-xl"><p><b>${E(FOUNDER)}</b> · Sovereign Founder, QVMPXT</p><p class="mt-2"><a href="mailto:${FOUNDER_MAIL}">${FOUNDER_MAIL}</a></p><p><a href="tel:${FOUNDER_PHONE}">${FOUNDER_PHONE}</a></p></div>${H2('Help & support')}${grid(HELP)}`,'0.8','monthly'),
 pg('/download','home','app-download','App Download','Download and install the ClasSphera app','Install ClasSphera by QVMPXT on your phone or computer for fast, offline-ready access to your institution workspace.',()=>`${H1('App Download')}<p class="max-w-2xl">Install ClasSphera as an app: choose “Add to Home screen” on Android and iOS, or “Install app” in desktop Chrome and Edge. It works offline and syncs when you reconnect.</p>`,'0.7','monthly'),
 pg('/admission','admit','','Global Online Admission','Global Online Admission','Find a school, madrasah, college or university anywhere in the world on ClasSphera by QVMPXT and apply online directly to the institution.',()=>`${H1('Global Online Admission')}<p class="max-w-2xl">Search institutions by name, type, country and city, see whether admissions are open, and send your application by email or WhatsApp.</p>`,'0.8','weekly'),
 pg('/enterprise','enterprise','','Enterprise Suite','Enterprise Suite','ClasSphera by QVMPXT Enterprise Suite: version history and rollback, access control and audit trail, custom fields, guardian alerts, offline sync, health guard, campus analytics and reconciliation.',()=>`${H1('Enterprise Suite')}<p class="max-w-2xl">Enterprise-grade tools for madrasahs, schools, colleges and multi-campus universities.</p>${grid(ENT.map(x=>[x[1],x[2]]))}<ul class="mt-4">${ENT.map(x=>`<li><a href="/enterprise/${x[0]}">${E(x[1])}</a></li>`).join('')}</ul>`,'0.9','weekly'),
 ...ENT.map(x=>pg('/enterprise/'+x[0],'enterprise','enterprise:'+x[0],x[1],x[1],`${BRAND} Enterprise Suite: ${x[2]}`,()=>`${H1(x[1])}<p class="max-w-2xl">${E(x[2])}</p><p class="mt-4"><a href="/enterprise">All Enterprise Suite modules</a></p>`,'0.7','monthly')),
 pg('/products','products','','Products','Products','Ten connected ClasSphera modules: enrollment, attendance, learning management, assessment, AI tools, analytics, finance vault, messaging, staff and security.',()=>`${H1('Products')}${grid(PRODS,'sm:grid-cols-2 lg:grid-cols-3')}`,'0.9'),
 pg('/solutions','sol','','Solutions','Solutions for every institution','ClasSphera fits schools, madrasahs, coaching centers, colleges and universities with student records, staff management, financial ledgers and institutional hierarchies.',()=>`${H1('Solutions')}${grid(SOLS,'md:grid-cols-2 lg:grid-cols-3')}${H2('Included in every solution')}${grid(ALLSOL,'sm:grid-cols-2 lg:grid-cols-4')}`,'0.9'),
 pg('/pricing','price','','Pricing','Pricing','ClasSphera Free plan up to 200 student records, then Starter $29, Institution $79 and Sovereign $199 per month. Pay with bKash, Nagad, Rocket, SSLCommerz, cards, PayPal, Bitcoin or USDT.',()=>`${H1('Pricing')}${plans()}`,'0.9'),
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
const NAV=`<nav aria-label="ClasSphera pages" style="max-width:72rem;margin:0 auto;padding:1rem 1rem 2rem;display:flex;flex-wrap:wrap;gap:.5rem 1.25rem;justify-content:center;font-size:.8rem">${[...NAVP,...ENT.map(x=>'/enterprise/'+x[0])].map(p=>{const x=BYPATH[p];return`<a href="${p}" data-h="${E(x.hash||x.v)}" style="color:var(--mu)">${E(x.name)}</a>`}).join('')}</nav>`;
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
 if(/\\.(png|svg|ico|webmanifest|woff2?|css|js)$/.test(u.pathname)&&u.pathname!=='/sw.js'){e.respondWith(caches.open(V).then(c=>c.match(r).then(h=>{const f=fetch(r).then(x=>{if(x.ok)c.put(r,x.clone());return x}).catch(()=>h);return h||f})))}});`;
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
 const web={'@type':'WebSite','@id':SITE+'/#website',url:SITE+'/',name:'ClasSphera',alternateName:['Classphera','ClassSphera','Class Sphera',BRAND],description:TAG,publisher:{'@id':SITE+'/#org'},inLanguage:'en'};
 const nav=['/','/login','/signup','/guardian-signup','/student-signup','/connect','/download','/enterprise'];
 const g=[web,org,{'@type':'WebPage','@id':SITE+p.path+'#webpage',url:SITE+p.path,name:p.title,description:p.desc,isPartOf:{'@id':SITE+'/#website'},inLanguage:'en'},
  {'@type':'ItemList','@id':SITE+'/#navigation',name:'ClasSphera main navigation',itemListElement:nav.map((x,i)=>({'@type':'ListItem',position:i+1,item:{'@type':'SiteNavigationElement','@id':SITE+x+'#nav',name:BYPATH[x].name,description:BYPATH[x].desc,url:SITE+(x==='/'?'/':x)}}))}];
 if(p.path!=='/'){const c=[{'@type':'ListItem',position:1,name:'Home',item:SITE+'/'}];if(p.path.startsWith('/enterprise/'))c.push({'@type':'ListItem',position:2,name:'Enterprise Suite',item:SITE+'/enterprise'},{'@type':'ListItem',position:3,name:p.name,item:SITE+p.path});else c.push({'@type':'ListItem',position:2,name:p.name,item:SITE+p.path});g.push({'@type':'BreadcrumbList',itemListElement:c})}
 const app={'@type':'SoftwareApplication',name:'ClasSphera',applicationCategory:'EducationalApplication',operatingSystem:'Web',url:SITE+'/',description:TAG,publisher:{'@id':SITE+'/#org'}};
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
const htmlHeaders=(main,more={})=>({'content-type':'text/html; charset=utf-8','cache-control':'public, max-age=0, must-revalidate','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin','strict-transport-security':'max-age=31536000','permissions-policy':'camera=(), microphone=(self), geolocation=()',...(main?{}:{'x-robots-tag':'noindex, nofollow'}),...more});
const file=(body,type,main,ttl=3600,more={})=>new Response(body,{headers:{'content-type':type+'; charset=utf-8','cache-control':ttl?'public, max-age='+ttl:'no-cache','x-content-type-options':'nosniff',...(main?{}:{'x-robots-tag':'noindex, nofollow'}),...more}});
const notFound=()=>new Response('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Page not found | ClasSphera</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070812;color:#e6e9f5;font-family:Inter,system-ui,sans-serif;text-align:center;padding:1rem}a{color:#34d399}</style></head><body><main><h1>Page not found</h1><p><a href="/">Back to ClasSphera</a></p></main></body></html>',{status:404,headers:htmlHeaders(false,{'cache-control':'no-store'})});
function tenantSub(host){for(const r of ROOTS){if(host.endsWith('.'+r)){const s=host.slice(0,-(r.length+1));if(SUBRX.test(s)&&!RESERVED.includes(s))return s}}return null}
async function page(req,env,ctx,u,main,p,o){
 o=o||{};const host=o.host||u.hostname,cache=typeof caches!=='undefined'?caches.default:null,ck=new Request('https://cache.classphera.invalid/'+APP_V+'/'+host+p.path+(o.sub?'?t='+o.sub+'&n='+encodeURIComponent(o.title||''):''));
 if(cache){const h=await cache.match(ck);if(h)return new Response(h.body,{status:200,headers:htmlHeaders(main)})}
 const base=await env.ASSETS.fetch(new Request(u.origin+'/'));if(!base.ok)return base;
 const url=o.sub?`https://${host}/`:SITE+(p.path==='/'?'/':p.path),T=o.sub?{title:o.title,desc:o.desc}:p,set=(a,v)=>({element(e){e.setAttribute(a,v)}});
 const rw=new HTMLRewriter()
  .on('title',{element(e){e.setInnerContent(T.title)}})
  .on('meta[name="description"]',set('content',T.desc)).on('meta[property="og:title"]',set('content',T.title)).on('meta[property="og:description"]',set('content',T.desc))
  .on('meta[name="twitter:title"]',set('content',T.title)).on('meta[name="twitter:description"]',set('content',T.desc))
  .on('link[rel="canonical"]',set('href',url)).on('meta[property="og:url"]',set('content',url))
  .on('script[type="application/ld+json"]',{element(e){e.remove()}});
 const rw2=main?rw:rw.on('meta[name="robots"]',set('content','noindex,nofollow')),
 tenantJs=o.sub?`<script>try{history.replaceState(null,'',location.pathname+'?sub=${o.sub}'+location.hash)}catch(e){}</script>`:'';
 const out=rw2.on('head',{element(e){e.append('<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="manifest" href="/manifest.webmanifest"><meta property="og:image" content="'+SITE+'/icon-512.png"><meta name="twitter:image" content="'+SITE+'/icon-512.png"><meta property="og:locale" content="en"><meta name="cs-app-version" content="'+APP_V+'">'+LD(o.sub?{...p,path:'/',title:T.title,desc:T.desc}:p)+BOOT()+tenantJs,{html:true})}})
  .on('main#app',{element(e){e.setInnerContent(p.body(),{html:true})}})
  .on('footer#foot',{element(e){e.after(NAV,{html:true})}})
  .on('body',{element(e){e.append(CLIENT_PATCH,{html:true})}}).transform(base);
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
 await env.DB.batch([sq(env,"DELETE FROM events WHERE at<? AND kind IN ('audit','sync')",d90),sq(env,'DELETE FROM alerts WHERE at<?',d90),sq(env,'DELETE FROM kvx WHERE exp>0 AND exp<?',Math.floor(Date.now()/1000)),sq(env,'DELETE FROM portal_inbox WHERE at<?',Date.now()-90*864e5),sq(env,'DELETE FROM trusted WHERE last_seen<?',d180),sq(env,'DELETE FROM audit WHERE at<?',new Date(Date.now()-365*864e5).toISOString())])}

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
