/* ClasSphera backend · QVMPXT · Cloudflare Pages advanced mode (_worker.js)
   Matches index.html 1:1: every /api call the page makes, plus crawlable pages for Googlebot.
   Bindings: DB (D1), KV (KV namespace), AI (Workers AI, optional). ASSETS is automatic on Pages.
   Secrets:  TG_TOKEN, TG_CHAT, MASTER_KEY
   Optional: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET (redirect URI: https://classphera.pages.dev/api/oauth/google/callback),
             STRIPE_KEY, TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM, SMS_DAILY_CAP (max SMS per day for the whole site, default 500)
   D1 schema (run once):
   CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,sub TEXT,gateway TEXT,item TEXT,usd REAL,txid TEXT,status TEXT,at TEXT);
   CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,detail TEXT,ip TEXT,at TEXT);
   Served by this worker, no extra files needed:
   /robots.txt  /sitemap.xml  /manifest.webmanifest  /favicon.svg  /favicon.ico  /.well-known/security.txt
   Real URLs for every public page: /products /solutions /pricing /connected-os /help /feedback /terms /privacy
   Bump LASTMOD below whenever page content changes.
   MOVING TO A .COM LATER: change only SITE and APEX below (and the Google OAuth redirect URI). Canonical, og:url,
   sitemap, robots and all JSON-LD are generated from them. */

const SITE='https://classphera.pages.dev',APEX='classphera.pages.dev',LASTMOD='2026-11-11';
const AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const GATES=['bKash','Nagad','Rocket','SSLCommerz','Visa','Mastercard','Stripe','PayPal','Bitcoin','USDT Vault','Cash','Bank transfer'];

const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-robots-tag':'noindex, nofollow'}});
const X=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const eq=(a,b)=>{a=String(a);b=String(b);let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0};
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));

async function tg(env,text){if(!env.TG_TOKEN||!env.TG_CHAT)return false;try{const r=await fetch(`https://api.telegram.org/bot${env.TG_TOKEN}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:env.TG_CHAT,text:text.slice(0,4000),parse_mode:'HTML',disable_web_page_preview:true})});return r.ok}catch{return false}}
/* fixed-window rate limit: true when the limit is exceeded */
async function hit(env,key,max,ttl){const k=key+':'+Math.floor(Date.now()/(ttl*1000)),n=(+(await env.KV.get(k))||0)+1;await env.KV.put(k,String(n),{expirationTtl:Math.max(60,ttl*2)});return n>max}
/* counts n units against a daily budget: true when it would be exceeded */
async function spend(env,key,n,max,ttl){const k=key+':'+Math.floor(Date.now()/(ttl*1000)),c=+(await env.KV.get(k))||0;if(c+n>max)return true;await env.KV.put(k,String(c+n),{expirationTtl:ttl*2});return false}
async function alert(env,ip,kind,detail){await env.DB.prepare('INSERT INTO audit(kind,detail,ip,at) VALUES(?,?,?,?)').bind(kind,String(detail).slice(0,300),ip,new Date().toISOString()).run().catch(()=>{});return tg(env,`🚨 <b>${X(kind)}</b>\n${X(detail)}\nIP: ${X(ip)}`)}

/* ───────────────────────── API (exactly what index.html calls) ───────────────────────── */
async function oauthCallback(env,u){
 const back=()=>Response.redirect(u.origin+'/#home',302);
 try{
  const st=u.searchParams.get('state')||'',code=u.searchParams.get('code');
  if(!code||!st||!env.GOOGLE_CLIENT_ID||!(await env.KV.get('os:'+st)))return back();
  await env.KV.delete('os:'+st);
  const t=await(await fetch('https://oauth2.googleapis.com/token',{method:'POST',body:new URLSearchParams({code,client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,redirect_uri:u.origin+'/api/oauth/google/callback',grant_type:'authorization_code'})})).json();
  if(!t.access_token)return back();
  const p=await(await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{authorization:'Bearer '+t.access_token}})).json();
  if(!p.email||p.email_verified!==true)return back();
  const c=rnd(16);await env.KV.put('oc:'+c,JSON.stringify({email:p.email,name:p.name||''}),{expirationTtl:300});
  return Response.redirect(u.origin+'/#oauth:'+c,302);
 }catch{return back()}
}

/* guardian/student portal helpers */
async function GOK(env,ip,sub,key,id){
 if(!sub||!/^[0-9a-f]{32,128}$/.test(key))return J({error:'unauthorized'},401);
 const kh=await sha(key),rec=JSON.parse(await env.KV.get('nk:'+sub)||'null');
 if(rec){if(!eq(rec.h,kh)){await alert(env,ip,'Portal key mismatch',`workspace ${sub}`);return J({error:'unauthorized'},403)}}
 else{if(await hit(env,'nkn:'+ip,3,86400))return J({error:'rate limited'},429);await env.KV.put('nk:'+sub,JSON.stringify({h:kh,id:String(id||'').slice(0,40),at:new Date().toISOString()}))}
 return null}
/* what each role may receive. A student never gets fees, messages, CCTV, ratings, behaviour or attendance. */
function proj(d,who){
 d=JSON.parse(JSON.stringify(d||{}));
 if(who==='student'){const r=d.rec||{},i=d.inst||{},s=d.stu||{};d={v:d.v,at:d.at,inst:{name:i.name,type:i.type,logo:i.logo,cctv:false},stu:{id:s.id,name:s.name,cls:s.cls,house:s.house,photo:s.photo},marks:d.marks||{},rec:{lesson:r.lesson||[],module:r.module||[],task:r.task||[]},quran:d.quran||''}}
 else if(!(d.inst&&d.inst.cctv))d.cam='';
 return d}

async function api(req,env,u,ip){
 try{
  const o=req.headers.get('origin');let foreign=false;
  if(o){try{foreign=new URL(o).host!==u.host}catch{foreign=true}}
  if(foreign)return J({error:'forbidden'},403);
  if(await hit(env,'rl:'+ip,120,60))return J({error:'Too many requests'},429);
  const p=u.pathname;
  if(req.method==='GET'&&p==='/api/oauth/google/start'){ /* index.html: fetch('/api/oauth/google/start') → {url} */
   if(!env.GOOGLE_CLIENT_ID||!env.GOOGLE_CLIENT_SECRET)return J({error:'not configured'},503);
   const st=rnd(16);await env.KV.put('os:'+st,'1',{expirationTtl:600});
   return J({url:'https://accounts.google.com/o/oauth2/v2/auth?'+new URLSearchParams({client_id:env.GOOGLE_CLIENT_ID,redirect_uri:u.origin+'/api/oauth/google/callback',response_type:'code',scope:'openid email profile',state:st,prompt:'select_account'})})}
  if(req.method==='GET'&&p==='/api/oauth/google/callback')return oauthCallback(env,u); /* → /#oauth:<code> */
  if(req.method!=='POST')return J({error:'not found'},404);
  const raw=await req.text();if(raw.length>(p==='/api/g/sync'?12e6:262144))return J({error:'too large'},413);
  let b={};try{b=JSON.parse(raw||'{}')}catch{}if(!b||typeof b!=='object'||Array.isArray(b))b={};
  const ws=s=>String(s||'').toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,60);
  switch(p){
   case '/api/telegram':{ /* threat telemetry (THREAT: …), FEEDBACK, NEW_INSTITUTION → founder */
    if(await hit(env,'tg:'+ip,40,3600))return J({error:'rate limited'},429);
    let type=String(b.type||'EVENT').slice(0,60);
    /* index.html sends {type:'NEW_INSTITUTION',…,type:<school|madrasah…>} so the institution type overwrites the event name; restore it */
    if(!/^(THREAT|FEEDBACK|NEW_INSTITUTION)/.test(type)&&b.name!=null&&b.size!=null){b.itype=type;type='NEW_INSTITUTION'}
    const f=['institution','institutionId','subdomain','role','name','itype','size','topic','message','detail','at','lang','tz','screen','webdriver','online','ua'];
    const icon=type.startsWith('THREAT')?'🚨':type==='FEEDBACK'?'📨':'🏫';
    const body=f.filter(k=>b[k]!==undefined&&b[k]!==null&&b[k]!=='').map(k=>`<b>${k==='itype'?'type':k}</b>: ${X(String(b[k]).slice(0,500))}`).join('\n');
    if(type.startsWith('THREAT'))await env.DB.prepare('INSERT INTO audit(kind,detail,ip,at) VALUES(?,?,?,?)').bind(type,String(b.detail||'').slice(0,300),ip,new Date().toISOString()).run().catch(()=>{});
    return await tg(env,`${icon} <b>${X(type)}</b>\nIP: ${X(ip)}\n${body}`)?J({ok:true}):J({error:'telegram unavailable'},502)}
   case '/api/master-override':{ /* {key,sub} → {temp} */
    const sub=ws(b.sub);
    if(await hit(env,'mo:'+ip,3,3600)){await alert(env,ip,'Master key flood',`workspace ${sub}`);return J({error:'locked'},429)}
    if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await alert(env,ip,'Master key attempt',`workspace ${sub}`);return J({error:'rejected'},403)}
    await alert(env,ip,'Master override used',`workspace ${sub}`);return J({temp:rnd(6)})}
   case '/api/oauth/claim':{ /* {code} → {email,name} */
    const k='oc:'+String(b.code||'').slice(0,40),v=await env.KV.get(k);if(!v)return J({error:'expired'},410);
    await env.KV.delete(k);return new Response(v,{headers:{'content-type':'application/json','cache-control':'no-store','x-robots-tag':'noindex, nofollow'}})}
   case '/api/id/new':{ /* → {id}: "M-" + 8 chars of the same 32-letter alphabet index.html uses (^M-[A-Z0-9]{8}$) */
    if(await hit(env,'idn:'+ip,30,3600))return J({error:'rate limited'},429);
    for(let i=0;i<8;i++){
     const id='M-'+[...crypto.getRandomValues(new Uint8Array(8))].map(x=>AL[x%32]).join('');
     if(!(await env.KV.get('id:'+id))){await env.KV.put('id:'+id,'1');return J({id})}}
    return J({error:'retry'},503)}
   case '/api/checkout':{ /* {gateway,item,usd,txid,sub,institutionId} → {status,url,message} */
    const cur=/^[A-Z]{3}$/.test(String(b.cur||''))?b.cur:'USD',usd=Math.round(+b.usd*100)/100,item=(String(b.item||'').slice(0,100)+(cur==='USD'?'':' ['+cur+']')).trim();
    if(!GATES.includes(b.gateway)||!(usd>0&&usd<=(cur==='USD'?5000:5e6))||!item)return J({error:'invalid payment'},400);
    if(await hit(env,'pay:'+ip,20,3600))return J({error:'rate limited'},429);
    const id='PAY-'+rnd(5).toUpperCase(),sub=String(b.sub||'').slice(0,60)||null,txid=String(b.txid||'').slice(0,80);let url=null;
    await env.DB.prepare('INSERT INTO payments VALUES(?,?,?,?,?,?,?,?)').bind(id,sub,b.gateway,item,usd,txid,'pending',new Date().toISOString()).run();
    if(b.gateway==='Stripe'&&env.STRIPE_KEY){try{const r=await fetch('https://api.stripe.com/v1/checkout/sessions',{method:'POST',headers:{authorization:'Bearer '+env.STRIPE_KEY,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({mode:'payment','line_items[0][price_data][currency]':cur.toLowerCase(),'line_items[0][price_data][product_data][name]':item,'line_items[0][price_data][unit_amount]':String(Math.round(usd*100)),'line_items[0][quantity]':'1',success_url:u.origin+'/pricing#price',cancel_url:u.origin+'/pricing#price','metadata[payment_id]':id})});url=(await r.json()).url||null}catch{url=null}}
    await tg(env,`💳 <b>Payment ${id}</b>\n${X(item)} · ${cur==='USD'?'$':cur+' '}${usd}\n${X(b.gateway)} · TxID ${X(txid||'-')}\nWorkspace: ${X(sub||'visitor')}${b.institutionId?' · '+X(String(b.institutionId).slice(0,40)):''}`);
    return J({status:'pending',url,message:url?'Redirecting to secure checkout':'Payment recorded. Access activates once the founder verifies it.'})}
   case '/api/notify':{ /* {sub,id,key,messages:[{to,name,status,inst}]} → {sent,failed}. The server builds the SMS text itself; nobody can send free text. */
    if(!env.TWILIO_SID||!env.TWILIO_TOKEN||!env.TWILIO_FROM)return J({error:'SMS provider not configured'},503);
    const sub=ws(b.sub),key=String(b.key||'');
    if(!sub||!/^[0-9a-f]{32,128}$/.test(key))return J({error:'unauthorized'},401);
    if(await hit(env,'sms:'+ip,10,3600))return J({error:'rate limited'},429);
    /* per-workspace secret: the first call registers its hash, every later call must present the same key */
    const kh=await sha(key),rec=JSON.parse(await env.KV.get('nk:'+sub)||'null');
    if(rec){if(!eq(rec.h,kh)){await alert(env,ip,'SMS key mismatch',`workspace ${sub}`);return J({error:'unauthorized'},403)}}
    else{if(await hit(env,'nkn:'+ip,3,86400))return J({error:'rate limited'},429);await env.KV.put('nk:'+sub,JSON.stringify({h:kh,id:String(b.id||'').slice(0,40),at:new Date().toISOString()}))}
    const nm=v=>String(v||'').replace(/[^\p{L}\p{M}\p{N} ,'’()&-]/gu,'').replace(/\s+/g,' ').trim(); /* no links, no symbols */
    const m=[];
    for(const a of (Array.isArray(b.messages)?b.messages:[]).slice(0,100)){
     const to=String(a&&a.to||'').replace(/[^\d+]/g,''),st=String(a&&a.status||'').toLowerCase(),name=nm(a&&a.name).slice(0,60),inst=nm(a&&a.inst).slice(0,80);
     if(/^\+?\d{7,15}$/.test(to)&&(st==='present'||st==='absent'||st==='late')&&name&&inst)m.push({to,text:`${name} was ${st} today at ${inst}.`})}
    if(!m.length)return J({error:'no valid recipients'},400);
    if(await spend(env,'smsw:'+sub,m.length,100,86400)||await spend(env,'smsg',m.length,+env.SMS_DAILY_CAP||500,86400))return J({error:'daily limit'},429);
    const r=await Promise.allSettled(m.map(a=>fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`,{method:'POST',headers:{authorization:'Basic '+btoa(env.TWILIO_SID+':'+env.TWILIO_TOKEN)},body:new URLSearchParams({To:a.to,From:env.TWILIO_FROM,Body:a.text})}).then(x=>{if(!x.ok)throw 0})));
    const sent=r.filter(x=>x.status==='fulfilled').length;
    return J({sent,failed:r.length-sent},sent?200:502)}
   case '/api/g/sync':{ /* admin browser → {sub,id,key,students:[{id,ph,gh,gs,sh,ss,d}]}. One snapshot per student; PIN hashes only. */
    const sub=ws(b.sub),key=String(b.key||''),deny=await GOK(env,ip,sub,key,b.id);if(deny)return deny;
    if(await hit(env,'gsy:'+sub,60,3600))return J({error:'rate limited'},429);
    const out={},hx=(v,n)=>typeof v==='string'&&new RegExp('^[0-9a-f]{'+n+'}$').test(v);
    for(const s of (Array.isArray(b.students)?b.students:[]).slice(0,500)){
     const id=String(s&&s.id||'').toUpperCase();if(!/^[A-Z0-9-]{1,24}$/.test(id)||!s.d||typeof s.d!=='object')continue;
     const d=JSON.stringify(s.d);if(d.length>60000)continue;
     out[id]={ph:String(s.ph||'').replace(/\D/g,'').slice(-10),gh:hx(s.gh,64)?s.gh:'',gs:hx(s.gs,16)?s.gs:'',sh:hx(s.sh,64)?s.sh:'',ss:hx(s.ss,16)?s.ss:'',d:s.d}}
    const v=JSON.stringify({at:Date.now(),s:out});if(v.length>2e7)return J({error:'too large'},413);
    await env.KV.put('gs:'+sub,v);return J({ok:true,count:Object.keys(out).length})}
   case '/api/g/login':{ /* {sub,sid,who,phone,pin} → {token,who,d}: only that student's own data, trimmed for the role */
    const sub=ws(String(b.sub||'').toLowerCase().replace(/\.classphera\.[a-z.]+$/,'')),sid=String(b.sid||'').trim().toUpperCase().slice(0,24),who=b.who==='student'?'student':'guardian',pin=String(b.pin||'').slice(0,40);
    if(await hit(env,'gl:'+ip,20,3600))return J({error:'Too many attempts. Try again later.'},429);
    const fk='gf:'+sub+':'+sid+':'+who,fails=+(await env.KV.get(fk))||0;
    if(fails>=5)return J({error:'Too many wrong attempts. Wait 15 minutes or ask the institution to reset access.'},429);
    const db=JSON.parse(await env.KV.get('gs:'+sub)||'null'),s=db&&db.s&&db.s[sid];
    const salt=s?(who==='student'?s.ss:s.gs):'0'.repeat(16),want=s?(who==='student'?s.sh:s.gh):'0'.repeat(64);
    const okPin=eq(await sha(pin+':'+salt),want)&&!!s&&/^[0-9a-f]{64}$/.test(want)&&want!=='0'.repeat(64),okPh=who==='student'||(!!s&&s.ph.length>=7&&String(b.phone||'').replace(/\D/g,'').slice(-10)===s.ph);
    if(!(okPin&&okPh)){await env.KV.put(fk,String(fails+1),{expirationTtl:900});return J({error:'Details did not match. Check the ID, mobile number and PIN.'},401)}
    await env.KV.delete(fk);
    const token=rnd(24);await env.KV.put('gt:'+token,JSON.stringify({sub,sid,who}),{expirationTtl:43200});
    return J({token,who,d:proj(s.d,who)})}
   case '/api/g/data':{ /* {token} → {d} */
    const t=JSON.parse(await env.KV.get('gt:'+String(b.token||'').slice(0,60))||'null');if(!t)return J({error:'expired'},401);
    const db=JSON.parse(await env.KV.get('gs:'+t.sub)||'null'),s=db&&db.s&&db.s[t.sid];if(!s)return J({error:'expired'},401);
    return J({d:proj(s.d,t.who)})}
   case '/api/g/send':{ /* guardian → staff message, picked up by the institution's browser */
    const tk=String(b.token||'').slice(0,60),t=JSON.parse(await env.KV.get('gt:'+tk)||'null');if(!t||t.who!=='guardian')return J({error:'expired'},401);
    const x=String(b.text||'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').trim().slice(0,1000);if(!x)return J({error:'empty'},400);
    if(await hit(env,'gsd:'+tk,30,3600))return J({error:'rate limited'},429);
    const k='gi:'+t.sub,a=JSON.parse(await env.KV.get(k)||'[]'),m={id:rnd(6),sid:t.sid,x,at:Date.now()};a.push(m);
    await env.KV.put(k,JSON.stringify(a.slice(-300)));return J({ok:true,id:m.id,at:m.at})}
   case '/api/g/inbox':{ /* institution browser → pending guardian messages (then cleared) */
    const sub=ws(b.sub),deny=await GOK(env,ip,sub,String(b.key||''),b.id);if(deny)return deny;
    const k='gi:'+sub,a=JSON.parse(await env.KV.get(k)||'[]');if(a.length)await env.KV.delete(k);return J({msgs:a})}
   case '/api/ai':{ /* {sub,subject,chapter,difficulty,kind} → {text} */
    if(!env.AI)return J({error:'AI not configured'},503);
    if(await hit(env,'ai:'+ip,30,3600))return J({error:'rate limited'},429);
    const clean=(v,n)=>String(v||'').replace(/["\r\n]+/g,' ').trim().slice(0,n),s=clean(b.subject,120),c=clean(b.chapter,160);
    if(!s||!c)return J({error:'subject and chapter required'},400);
    const d=['Easy','Medium','Hard'].includes(b.difficulty)?b.difficulty:'Medium',k=['Exam paper','Syllabus outline','Lesson plan'].includes(b.kind)?b.kind:'Exam paper';
    const r=await env.AI.run('@cf/meta/llama-3.1-8b-instruct',{messages:[{role:'system',content:'You are an academic assistant for schools, madrasahs and universities. Reply with plain text only.'},{role:'user',content:`Create a ${k} for subject "${s}", chapter "${c}", difficulty ${d}. Include marks and clear sections.`}],max_tokens:1200});
    const text=String(r&&r.response||'').trim();
    return text?J({text}):J({error:'empty response'},502)}
  }
  return J({error:'not found'},404);
 }catch(e){return J({error:'server error'},500)}
}

/* ───────────────────────── SEO / crawler layer ───────────────────────── */
/* Page copy below mirrors the text index.html renders, so Googlebot sees the same content as visitors. */
/*DATA*/
const HERO='One Platform. Complete Control of Your Institution.';
const INTRO='One workspace for enrollment, attendance, marks, fees and guardian communication. Every institution gets its own isolated subdomain and starts completely empty.';
const PAYTXT='Pay with bKash, Nagad, Rocket, SSLCommerz, Visa, Mastercard, Stripe, PayPal, Bitcoin or USDT Vault.';
const PRODS=[['Enrollment','Admissions, student profiles and guardian records.'],['Attendance Support','ID-card scan logs for students and ustads, with guardian alerts.'],['Learning Management','Routines, homework diaries and teacher feedback.'],['Assessment','Digital marksheets and instant merit lists.'],['Connected Intelligence','AI question papers, syllabus outlines and lesson plans.'],['Analytics and Insights','Progress graphs and class averages.'],['Finance Vault','Encrypted ledger, fee collection and receipts.'],['Secure Messaging','Guardian to teacher conversations.'],['Staff Management','Ustad records, salaries and credentials.'],['Security Center','Role-based access, tamper detection and threat alerts.']];
const PLANS=[['Free','Up to 200 student records',0,['Student and staff directory','Attendance and marksheets','Isolated workspace and unique ID','Community support']],['Starter','Up to 500 students',29,['Student and staff directory','Attendance','Marksheets']],['Institution','Up to 1,500 students',79,['Everything in Starter','AI paper generator','Encrypted finance vault','Role-based team access']],['Sovereign','Unlimited, multi-campus',199,['Everything in Institution','Custom domain','Priority support']]];
const SOLS=[['Schools','Class routines, homework diaries, guardian alerts and report cards.'],['Madrassas','Hostel and meal tracking, Quran progress, Sadaqah ledger and ustad records.'],['Coaching centers','Batch attendance, mock tests and recurring fees.'],['Colleges','Departments, semester results, fee collection and staff payroll.'],['Universities','Faculty, department, program and batch hierarchy at large scale.']];
const ALLSOL=[['Student records','Profiles, guardians, residence and results.'],['Staff management','Credentials, salaries and joining dates.'],['Financial ledgers','Income, expenses, dues, loans and receipts.'],['Institutional hierarchies','Campus, faculty, department, class and batch.']];
const OSL=[['Data layer','One isolated workspace per institution, stored under its own subdomain.'],['Identity layer','Four roles with separate permissions and token sessions that end on inactivity.'],['Intelligence layer','AI papers, lesson plans, merit lists and progress analytics.'],['Communication layer','Guardian alerts under your branded sender name and secure messaging.']];
const HELP=[['Set up your institution','Sign up, choose a subdomain, and save the recovery code shown once at the end.'],['Add team members','Settings and team: add teachers, accountants and guardians with their roles.'],['Add students and staff','Lists start empty. Press Add on Students or Staff.'],['Enter marks','Marksheets: type a subject, enter scores, and the merit list updates.'],['Collect fees','Finance vault lists students with a fee set. Press Collect to log it and print a receipt.'],['Locked out?','Contact the QVMPXT founder. A master key regenerates the administrator password.']];
const TRUST=[['Isolated workspaces','Each institution lives on its own subdomain with its own data, never shared.','Every institution gets a private workspace on its own subdomain, for example madrasahname.classphera.com. Records, users and ledgers are stored per workspace, so one institution can never read another’s data.',['Own subdomain and unique secure ID','Separate data store per institution','Starts completely empty']],['Role-based access','Admins, teachers, accountants and guardians each see only what they need.','Four roles decide which tabs and records each person can open, so nobody sees more than their job needs.',['Teachers mark attendance and scores','Accountants manage the ledger','Guardians use messages and the student portal']],['Encrypted ledger','Finance records are sealed with AES-256 before they are stored.','Income, expenses, donations and Sadaqah entries are sealed with AES-256-GCM in the browser before storage. A recovery code unlocks the vault if a password is lost.',['Automatic receipts','Local and global payment gateways','Tamper detection on local data']],['Founder threat alerts','Suspicious sign-ins and injection attempts are logged and reported at once.','Failed sign-ins, injection patterns and tampering are logged at once and reported to the Sovereign Founder.',['Blocked-access popup with founder contact','Lock-out after repeated failures','Alerts queue offline and send later']]];
const TERMS=['ClasSphera is operated by QVMPXT. Each institution owns the records it enters and must keep its administrator credentials and recovery code safe.','Subscriptions renew on the cycle you choose. A payment counts as received only after the payment gateway confirms it.','Attempts to break into or tamper with any workspace are logged and reported to the founder.'];
const PRIVACY=['Each institution’s data lives in its own isolated workspace and is never mixed with another’s.','Security alerts and feedback sent to the founder include device and browser details to help investigate abuse.','Guardian phone numbers are used only to send the alerts your institution triggers.'];
const FBTXT='Sent privately to the founder with your institution’s details.';
/*END DATA*/

const grid=(a,c='md:grid-cols-2')=>`<div class="grid ${c} gap-4">${a.map(x=>`<div class="glass p-5"><h3 class="font-bold">${E(x[0])}</h3><p class="text-sm mu mt-1">${E(x[1])}</p></div>`).join('')}</div>`;
const trust=()=>`<div class="grid md:grid-cols-2 gap-4">${TRUST.map(t=>`<div class="glass p-5"><h3 class="font-bold">${E(t[0])}</h3><p class="text-sm mu mt-1">${E(t[1])}</p><p class="text-sm mt-2">${E(t[2])}</p><ul class="text-sm mt-2">${t[3].map(x=>`<li>✓ ${E(x)}</li>`).join('')}</ul></div>`).join('')}</div>`;
const plans=()=>`<div class="grid md:grid-cols-2 lg:grid-cols-4 gap-4">${PLANS.map(p=>`<div class="glass p-5"><h3 class="font-bold text-lg">${E(p[0])}</h3><p class="text-xs mu">${E(p[1])}</p><p class="text-3xl font-bold my-3">${p[2]?`$${p[2]}/month`:'$0'}</p><p class="text-xs">${p[2]?`Yearly billing: $${p[2]*10}/year, saves $${p[2]*2} a year`:'Free forever'}</p><ul class="text-sm mt-2">${p[3].map(x=>`<li>✓ ${E(x)}</li>`).join('')}</ul></div>`).join('')}</div><p class="text-xs mu text-center mt-4">${E(PAYTXT)}</p>`;
const H1=t=>`<h1 class="text-2xl md:text-3xl font-extrabold mb-4">${E(t)}</h1>`,H2=t=>`<h2 class="text-xl md:text-2xl font-extrabold mt-12 mb-4">${E(t)}</h2>`;
const paras=a=>`<div class="glass p-5 text-sm space-y-3 max-w-2xl">${a.map(x=>`<p>${E(x)}</p>`).join('')}</div>`;

const PAGES=[
 {v:'home',path:'/',crumb:'Home',pr:'1.0',cf:'weekly',title:'ClasSphera | Institution Management Platform by QVMPXT',desc:'ClasSphera (Classphera) by QVMPXT: one secure platform for schools, madrasahs, coaching centers, colleges and universities. Student records, attendance, marksheets, AI question papers, finance vault and guardian messaging.',body:()=>`<h1 class="text-3xl font-extrabold">${E(HERO)}</h1><p class="mt-5 mu max-w-xl">${E(INTRO)}</p>${H2('Everything an institution runs on')}${grid(PRODS,'sm:grid-cols-2 lg:grid-cols-3')}${H2('Built for isolation and trust')}${trust()}${H2('Pricing')}${plans()}`},
 {v:'products',path:'/products',crumb:'Products',pr:'0.9',cf:'monthly',title:'Products | ClasSphera Institution Management Modules',desc:'Ten connected ClasSphera modules: enrollment, attendance, learning management, assessment, AI tools, analytics, finance vault, messaging, staff and security.',body:()=>`${H1('Products')}<p class="text-sm mu mb-5">Ten connected modules, one isolated workspace per institution.</p>${grid(PRODS,'sm:grid-cols-2 lg:grid-cols-3')}`},
 {v:'sol',path:'/solutions',crumb:'Solutions',pr:'0.9',cf:'monthly',title:'Solutions for Schools, Madrasahs and Universities | ClasSphera',desc:'ClasSphera fits schools, madrasahs, coaching centers, colleges and universities with student records, staff management, financial ledgers and institutional hierarchies.',body:()=>`${H1('Solutions')}${grid(SOLS,'md:grid-cols-2 lg:grid-cols-3')}${H2('Included in every solution')}${grid(ALLSOL,'sm:grid-cols-2 lg:grid-cols-4')}`},
 {v:'price',path:'/pricing',crumb:'Pricing',pr:'0.9',cf:'monthly',title:'Pricing | ClasSphera Free Plan and Paid Plans',desc:'ClasSphera Free plan up to 200 student records, then Starter $29, Institution $79 and Sovereign $199 per month. Pay with bKash, Nagad, Rocket, SSLCommerz, Visa, Mastercard, Stripe, PayPal, Bitcoin or USDT.',body:()=>`${H1('Pricing')}${plans()}`},
 {v:'os',path:'/connected-os',crumb:'Connected OS',pr:'0.7',cf:'monthly',title:'Connected OS | ClasSphera by QVMPXT',desc:'The ClasSphera Connected OS: data, identity, intelligence and communication layers working together for every institution.',body:()=>`${H1('Connected OS')}${grid(OSL)}`},
 {v:'help',path:'/help',crumb:'Help center',pr:'0.6',cf:'monthly',title:'Help Center | ClasSphera',desc:'Set up your institution, add team members, students and staff, enter marks, collect fees and recover administrator access in ClasSphera.',body:()=>`${H1('Help center')}<div class="space-y-3">${HELP.map(x=>`<div class="glass p-4"><h2 class="font-bold">${E(x[0])}</h2><p class="mt-2 text-sm mu">${E(x[1])}</p></div>`).join('')}</div>`},
 {v:'fb',path:'/feedback',crumb:'Feedback portal',pr:'0.3',cf:'yearly',title:'Feedback Portal | ClasSphera',desc:'Send ideas, problems or praise privately to the ClasSphera founder together with your institution’s details.',body:()=>`${H1('Feedback portal')}<p class="text-sm mb-4 mu">${E(FBTXT)}</p>`},
 {v:'terms',path:'/terms',crumb:'Terms of use',pr:'0.3',cf:'yearly',title:'Terms of Use | ClasSphera',desc:'Terms of use for ClasSphera, operated by QVMPXT: record ownership, subscriptions, payments and workspace security.',body:()=>`${H1('Terms of use')}${paras(TERMS)}`},
 {v:'privacy',path:'/privacy',crumb:'Privacy',pr:'0.3',cf:'yearly',title:'Privacy | ClasSphera',desc:'How ClasSphera keeps each institution’s data isolated, what security alerts include and how guardian phone numbers are used.',body:()=>`${H1('Privacy')}${paras(PRIVACY)}`}
];
const BYPATH=Object.fromEntries(PAGES.map(p=>[p.path,p]));
const VIEWPATH=Object.fromEntries(PAGES.map(p=>[p.v,p.path]));
const ALIAS={'/index.html':'/','/price':'/pricing','/sol':'/solutions','/os':'/connected-os','/fb':'/feedback','/product':'/products','/solution':'/solutions','/terms-of-use':'/terms','/privacy-policy':'/privacy','/help-center':'/help'};

const ROBOTS=`User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ${SITE}/sitemap.xml\n`;
const SITEMAP=()=>`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${PAGES.map(p=>`<url><loc>${SITE}${p.path}</loc><lastmod>${LASTMOD}</lastmod><changefreq>${p.cf}</changefreq><priority>${p.pr}</priority></url>`).join('\n')}\n</urlset>\n`;
const MANIFEST=JSON.stringify({name:'ClasSphera',short_name:'ClasSphera',description:'One secure platform for schools, madrasahs, coaching centers, colleges and universities.',start_url:'/',scope:'/',display:'standalone',background_color:'#070812',theme_color:'#070812',categories:['education','productivity'],icons:[{src:'/favicon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}]});
const FAVICON='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none"><defs><linearGradient id="a" gradientUnits="userSpaceOnUse" x1="8" y1="8" x2="92" y2="92"><stop stop-color="#a78bfa"/><stop offset=".5" stop-color="#22d3ee"/><stop offset="1" stop-color="#34d399"/></linearGradient><linearGradient id="b" gradientUnits="userSpaceOnUse" x1="56" y1="40" x2="82" y2="60"><stop stop-color="#fef08a"/><stop offset="1" stop-color="#f59e0b"/></linearGradient></defs><path d="M50 5l39 22.5v45L50 95 11 72.500v-45z" fill="#0b1030" stroke="url(#a)" stroke-width="4" stroke-linejoin="round"/><path d="M50 17l28 16.200v33.600L50 83 22 66.800V33.200z" stroke="url(#a)" stroke-opacity=".35" stroke-width="1.5" stroke-linejoin="round"/><path d="M63.500 36.500A21 21 0 1 0 63.500 63.500" stroke="url(#a)" stroke-width="9" stroke-linecap="round"/><path d="M60 50l9.500-10 9.500 10-9.500 10z" fill="url(#b)"/><ellipse cx="50" cy="50" rx="41" ry="12" transform="rotate(-32 50 50)" stroke="url(#a)" stroke-opacity=".55" stroke-width="1.8"/><circle cx="23" cy="73" r="3.200" fill="#f472b6"/></svg>';

const NAV=`<nav aria-label="ClasSphera pages" style="max-width:72rem;margin:0 auto;padding:1rem 1rem 2rem;display:flex;flex-wrap:wrap;gap:.5rem 1.25rem;justify-content:center;font-size:.8rem">${PAGES.map(p=>`<a href="${p.path}" data-v="${p.v}" style="color:var(--mu)">${E(p.crumb)}</a>`).join('')}</nav>`;
const BOOT=v=>`<script>(function(){var P=${JSON.stringify(VIEWPATH)},h=history,ps=h.pushState,rs=h.replaceState;function f(u){if(typeof u==='string'&&u.charAt(0)==='#'){return(P[u.slice(1).split(':')[0]]||'/')+u}return u}h.pushState=function(s,t,u){return ps.call(h,s,t,f(u))};h.replaceState=function(s,t,u){return rs.call(h,s,t,f(u))};var v=${JSON.stringify(v)};if(v!=='home'&&!location.hash){try{rs.call(h,{d:0},'',location.pathname+'#'+v)}catch(e){}}document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[data-v]');if(a&&e.button===0&&!e.metaKey&&!e.ctrlKey&&!e.shiftKey&&typeof go==='function'){e.preventDefault();go(a.getAttribute('data-v'))}})})();</script>`;
/* Structured data is built here for EVERY page from SITE, so the page's own copy can never disagree with the live domain. */
const LD=p=>{
 const org={'@type':'Organization','@id':SITE+'/#org',name:'QVMPXT',url:SITE+'/',brand:{'@type':'Brand',name:'ClasSphera'},email:'marufchowdhury579@gmail.com',telephone:'+8801347272307'};
 const web={'@type':'WebSite','@id':SITE+'/#website',url:SITE+'/',name:'ClasSphera',alternateName:['Classphera','ClassSphera','Class Sphera','classphera'],publisher:{'@id':SITE+'/#org'},inLanguage:'en'};
 const g=[web,org,{'@type':'WebPage','@id':SITE+p.path+'#webpage',url:SITE+p.path,name:p.title,description:p.desc,isPartOf:{'@id':SITE+'/#website'},inLanguage:'en'}];
 if(p.v!=='home')g.push({'@type':'BreadcrumbList',itemListElement:[{'@type':'ListItem',position:1,name:'Home',item:SITE+'/'},{'@type':'ListItem',position:2,name:p.crumb,item:SITE+p.path}]});
 const app={'@type':'SoftwareApplication',name:'ClasSphera',applicationCategory:'EducationalApplication',operatingSystem:'Web',url:SITE+'/',publisher:{'@id':SITE+'/#org'}};
 if(p.v==='price')app.offers=PLANS.map(x=>({'@type':'Offer',name:x[0],description:x[1],price:String(x[2]),priceCurrency:'USD'}));
 if(p.v==='home'||p.v==='price')g.push(app);
 return '<script type="application/ld+json">'+JSON.stringify({'@context':'https://schema.org','@graph':g}).replace(/</g,'\\u003c')+'</script>'};

const htmlHeaders=(main,more={})=>({'content-type':'text/html; charset=utf-8','cache-control':'public, max-age=0, must-revalidate','x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin','strict-transport-security':'max-age=31536000',...(main?{}:{'x-robots-tag':'noindex, nofollow'}),...more});
const file=(body,type,main,ttl=3600)=>new Response(body,{headers:{'content-type':type+'; charset=utf-8','cache-control':'public, max-age='+ttl,'x-content-type-options':'nosniff',...(main?{}:{'x-robots-tag':'noindex, nofollow'})}});
const notFound=()=>new Response('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Page not found | ClasSphera</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070812;color:#e6e9f5;font-family:Inter,system-ui,sans-serif;text-align:center;padding:1rem}a{color:#34d399}</style></head><body><main><h1>Page not found</h1><p><a href="/">Back to ClasSphera</a></p></main></body></html>',{status:404,headers:htmlHeaders(false,{'cache-control':'no-store'})});

async function page(req,env,u,main,p){
 const base=await env.ASSETS.fetch(new Request(u.origin+'/'));
 if(!base.ok)return base;
 const url=SITE+p.path,set=(a,v)=>({element(e){e.setAttribute(a,v)}});
 let rw=new HTMLRewriter();
 if(p.v!=='home'){
  rw=rw.on('title',{element(e){e.setInnerContent(p.title)}})
   .on('meta[name="description"]',set('content',p.desc))
   .on('meta[property="og:title"]',set('content',p.title))
   .on('meta[property="og:description"]',set('content',p.desc))
   .on('meta[name="twitter:title"]',set('content',p.title))
   .on('meta[name="twitter:description"]',set('content',p.desc));
 }
 rw=rw.on('link[rel="canonical"]',set('href',url)).on('meta[property="og:url"]',set('content',url))
  .on('script[type="application/ld+json"]',{element(e){e.remove()}}); /* replaced below by one graph built from SITE */
 if(!main)rw=rw.on('meta[name="robots"]',set('content','noindex,nofollow'));
 rw=rw.on('head',{element(e){e.append('<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="manifest" href="/manifest.webmanifest">'+LD(p)+BOOT(p.v),{html:true})}})
  .on('main#app',{element(e){e.setInnerContent(p.body(),{html:true})}}) /* the app replaces this with its own render() */
  .on('footer#foot',{element(e){e.after(NAV,{html:true})}});
 const out=rw.transform(base);
 return new Response(out.body,{status:200,headers:htmlHeaders(main)});
}

async function site(req,env,u,host,main){
 const path=u.pathname;
 if(req.method!=='GET'&&req.method!=='HEAD')return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
 if(path==='/robots.txt')return file(main?ROBOTS:'User-agent: *\nDisallow: /\n','text/plain',main);
 if(path==='/sitemap.xml')return main?file(SITEMAP(),'application/xml',main):notFound();
 if(path==='/manifest.webmanifest')return file(MANIFEST,'application/manifest+json',main,86400);
 if(path==='/favicon.svg')return file(FAVICON,'image/svg+xml',main,86400);
 if(path==='/favicon.ico')return Response.redirect(u.origin+'/favicon.svg',301);
 if(path==='/.well-known/security.txt')return file(`Contact: mailto:marufchowdhury579@gmail.com\nExpires: ${new Date(Date.now()+364*864e5).toISOString()}\nPreferred-Languages: en, bn\nCanonical: ${SITE}/.well-known/security.txt\n`,'text/plain',main);
 if(path==='/sw.js')return file("self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('fetch',()=>{});",'application/javascript',main,0);
 if(ALIAS[path])return Response.redirect(u.origin+ALIAS[path]+u.search,301);
 if(path.length>1&&path.endsWith('/'))return Response.redirect(u.origin+path.replace(/\/+$/,'')+u.search,301);
 const p=BYPATH[path];
 if(p)return page(req,env,u,main,p);
 /* other files (images, js, css…): pass through, but never serve the app shell as a fake 200 for a missing file */
 if(/\.[a-z0-9]{2,8}$/i.test(path)){
  const r=await env.ASSETS.fetch(req),ct=r.headers.get('content-type')||'';
  if(r.status===200&&ct.includes('text/html'))return notFound();
  if(main)return r;
  const h=new Headers(r.headers);h.set('x-robots-tag','noindex, nofollow');return new Response(r.body,{status:r.status,headers:h});
 }
 return notFound();
}

export default{async fetch(req,env){
 const u=new URL(req.url),host=u.hostname.toLowerCase(),ip=req.headers.get('cf-connecting-ip')||'unknown',main=host===APEX;
 if(u.protocol==='http:'&&main)return Response.redirect('https://'+u.host+u.pathname+u.search,301);
 if(u.pathname.startsWith('/api/'))return api(req,env,u,ip);
 try{return await site(req,env,u,host,main)}catch(e){return new Response('Server error',{status:500,headers:{'cache-control':'no-store','x-robots-tag':'noindex'}})}
}};
