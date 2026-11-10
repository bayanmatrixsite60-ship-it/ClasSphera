/* ClasSphera backend · QVMPXT · Cloudflare Pages advanced mode
   Bindings: DB (D1), KV (KV namespace), AI (Workers AI, optional). ASSETS is automatic on Pages.
   Secrets:  TG_TOKEN, TG_CHAT, MASTER_KEY  (optional: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET (redirect URI: https://YOURDOMAIN/api/oauth/google/callback), STRIPE_KEY, TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM)
   D1 schema (run once):
   CREATE TABLE tenants(sub TEXT PRIMARY KEY,iid TEXT UNIQUE,name TEXT,type TEXT,admin TEXT,phone TEXT,pw TEXT,salt TEXT,created TEXT);
   CREATE TABLE payments(id TEXT PRIMARY KEY,sub TEXT,gateway TEXT,item TEXT,usd REAL,txid TEXT,status TEXT,at TEXT);
   CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,detail TEXT,ip TEXT,at TEXT); */
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});
const X=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const eq=(a,b)=>{a=String(a);b=String(b);let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0};
const kdf=async(pw,salt)=>{const e=new TextEncoder(),k=await crypto.subtle.importKey('raw',e.encode(pw),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:e.encode(salt),iterations:100000,hash:'SHA-256'},k,256))};
const tenantOf=h=>{const m=h.toLowerCase().match(/^([a-z0-9-]+)\.classphera\.com$/);return m&&m[1]!=='www'?m[1]:null};
const GATES=['bKash','Nagad','Rocket','SSLCommerz','Visa','Mastercard','Stripe','PayPal','Bitcoin','USDT Vault','Cash','Bank transfer'];

async function tg(env,text){if(!env.TG_TOKEN||!env.TG_CHAT)return false;try{const r=await fetch(`https://api.telegram.org/bot${env.TG_TOKEN}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:env.TG_CHAT,text:text.slice(0,4000),parse_mode:'HTML',disable_web_page_preview:true})});return r.ok}catch{return false}}
async function hit(env,key,max,ttl){const n=(+(await env.KV.get(key))||0)+1;await env.KV.put(key,String(n),{expirationTtl:Math.max(60,ttl)});return n>max}
async function alert(env,ip,kind,detail){await env.DB.prepare('INSERT INTO audit(kind,detail,ip,at) VALUES(?,?,?,?)').bind(kind,String(detail).slice(0,300),ip,new Date().toISOString()).run().catch(()=>{});return tg(env,`🚨 <b>${X(kind)}</b>\n${X(detail)}\nIP: ${X(ip)}`)}
async function session(req,env,host){const t=(req.headers.get('authorization')||'').replace(/^Bearer /,'');if(!t)return null;const s=JSON.parse(await env.KV.get('s:'+t)||'null');if(!s)return null;const tn=tenantOf(host);if(tn&&tn!==s.sub)return null;await env.KV.put('s:'+t,JSON.stringify(s),{expirationTtl:900});return s}

export default{async fetch(req,env){
 const u=new URL(req.url),ip=req.headers.get('cf-connecting-ip')||'unknown';
 if(!u.pathname.startsWith('/api/'))return env.ASSETS.fetch(req);
 const o=req.headers.get('origin');if(o&&new URL(o).host!==u.host)return J({error:'forbidden'},403);
 try{
  if(await hit(env,'rl:'+ip,120,60))return J({error:'Too many requests'},429);
  const host=u.hostname,tn=tenantOf(host);
  if(u.pathname==='/api/ws'){ /* KV sync, isolated per tenant, session required */
   const s=await session(req,env,host);if(!s)return J({error:'unauthorized'},401);
   if(req.method==='GET')return new Response(await env.KV.get('ws:'+s.sub)||'null',{headers:{'content-type':'application/json','cache-control':'no-store'}});
   if(req.method==='PUT'){const t=await req.text();if(t.length>2e6)return J({error:'too large'},413);JSON.parse(t);await env.KV.put('ws:'+s.sub,t);return J({ok:true})}
  }
  if(req.method==='GET'&&u.pathname==='/api/oauth/google/start'){
   if(!env.GOOGLE_CLIENT_ID||!env.GOOGLE_CLIENT_SECRET)return J({error:'not configured'},503);
   const st=rnd(16);await env.KV.put('os:'+st,'1',{expirationTtl:600});
   return J({url:'https://accounts.google.com/o/oauth2/v2/auth?'+new URLSearchParams({client_id:env.GOOGLE_CLIENT_ID,redirect_uri:u.origin+'/api/oauth/google/callback',response_type:'code',scope:'openid email profile',state:st,prompt:'select_account'})})}
  if(req.method==='GET'&&u.pathname==='/api/oauth/google/callback'){
   const st=u.searchParams.get('state')||'',code=u.searchParams.get('code');
   if(!code||!(await env.KV.get('os:'+st)))return Response.redirect(u.origin+'/#home',302);
   await env.KV.delete('os:'+st);
   const t=await(await fetch('https://oauth2.googleapis.com/token',{method:'POST',body:new URLSearchParams({code,client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,redirect_uri:u.origin+'/api/oauth/google/callback',grant_type:'authorization_code'})})).json();
   const p=await(await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{authorization:'Bearer '+t.access_token}})).json();
   if(!p.email||p.email_verified!==true)return Response.redirect(u.origin+'/#home',302);
   const c=rnd(16);await env.KV.put('oc:'+c,JSON.stringify({email:p.email,name:p.name||''}),{expirationTtl:300});
   return Response.redirect(u.origin+'/#oauth:'+c,302)}
  if(req.method!=='POST')return J({error:'not found'},404);
  if((+req.headers.get('content-length')||0)>262144)return J({error:'too large'},413);
  const b=await req.json().catch(()=>({}));
  switch(u.pathname){
   case '/api/telegram':{ /* threat telemetry + feedback + new-institution events → founder */
    if(await hit(env,'tg:'+ip,40,3600))return J({error:'rate limited'},429);
    const type=String(b.type||'EVENT').slice(0,60),f=['institution','institutionId','subdomain','role','name','size','topic','message','detail','at','lang','tz','screen','webdriver','online','ua'];
    const icon=type.startsWith('THREAT')?'🚨':type==='FEEDBACK'?'📨':'🏫';
    const body=f.filter(k=>b[k]!==undefined&&b[k]!==null&&b[k]!=='').map(k=>`<b>${k}</b>: ${X(String(b[k]).slice(0,500))}`).join('\n');
    if(type.startsWith('THREAT'))await env.DB.prepare('INSERT INTO audit(kind,detail,ip,at) VALUES(?,?,?,?)').bind(type,String(b.detail||'').slice(0,300),ip,new Date().toISOString()).run().catch(()=>{});
    return await tg(env,`${icon} <b>${X(type)}</b>\nIP: ${X(ip)}\n${body}`)?J({ok:true}):J({error:'telegram unavailable'},502)}
   case '/api/master-override':{
    if(await hit(env,'mo:'+ip,3,3600)){await alert(env,ip,'Master key flood',`workspace ${b.sub}`);return J({error:'locked'},429)}
    if(!env.MASTER_KEY||!eq(b.key||'',env.MASTER_KEY)){await alert(env,ip,'Master key attempt',`workspace ${b.sub}`);return J({error:'rejected'},403)}
    await alert(env,ip,'Master override used',`workspace ${b.sub}`);return J({temp:rnd(6)})}
   case '/api/oauth/claim':{
    const k='oc:'+String(b.code||'').slice(0,40),v=await env.KV.get(k);if(!v)return J({error:'expired'},410);
    await env.KV.delete(k);return new Response(v,{headers:{'content-type':'application/json','cache-control':'no-store'}})}
   case '/api/id/new':{ /* sovereign institution ID: M-12345-AB7K, unique across KV and D1 */
    const A='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for(let i=0;i<8;i++){
     const id='M-'+(crypto.getRandomValues(new Uint32Array(1))[0]%90000+10000)+'-'+[...crypto.getRandomValues(new Uint8Array(4))].map(x=>A[x%32]).join('');
     if(!(await env.KV.get('id:'+id))&&!(await env.DB.prepare('SELECT 1 FROM tenants WHERE iid=?').bind(id).first())){await env.KV.put('id:'+id,'1');return J({id})}}
    return J({error:'retry'},503)}
   case '/api/auth/register':{
    const sub=String(b.sub||'').toLowerCase(),ph=String(b.phone||'').replace(/[^\d+]/g,'');
    if(!/^[a-z0-9-]{3,40}$/.test(sub)||!/^M-\d{5}-[A-Z0-9]{4}$/.test(b.iid||'')||!/^\+?\d{7,15}$/.test(ph)||String(b.admin||'').length<2||String(b.password||'').length<8)return J({error:'invalid input'},400);
    const salt=rnd(16);
    try{await env.DB.prepare('INSERT INTO tenants VALUES(?,?,?,?,?,?,?,?,?)').bind(sub,b.iid,String(b.name||'').slice(0,120),String(b.type||'').slice(0,30),String(b.admin).slice(0,80),ph,await kdf(b.password,salt),salt,new Date().toISOString()).run()}catch{return J({error:'subdomain or ID taken'},409)}
    await tg(env,`🏫 <b>New institution</b>\n${X(b.name)} (${X(b.type)})\n${X(b.iid)} · ${X(sub)}.classphera.com`);
    const t=rnd(24);await env.KV.put('s:'+t,JSON.stringify({sub,iid:b.iid}),{expirationTtl:900});return J({token:t,iid:b.iid})}
   case '/api/auth/login':{ /* 4 fields: domain, admin name, phone, password */
    const sub=String(tn||b.domain||'').toLowerCase().replace(/\.classphera\.com.*$/,''),ph=String(b.phone||'').replace(/[^\d+]/g,''),k=`lf:${sub}:${ip}`;
    if((+(await env.KV.get(k))||0)>=5)return J({error:'locked',flagged:true},429);
    const r=await env.DB.prepare('SELECT * FROM tenants WHERE sub=?').bind(sub).first();
    if(r&&r.phone===ph&&eq(r.admin.toLowerCase(),String(b.admin||'').trim().toLowerCase())&&eq(r.pw,await kdf(String(b.password||''),r.salt))){
     await env.KV.delete(k);const t=rnd(24);await env.KV.put('s:'+t,JSON.stringify({sub,iid:r.iid}),{expirationTtl:900});return J({token:t,iid:r.iid,admin:r.admin,sub})}
    const n=(+(await env.KV.get(k))||0)+1;await env.KV.put(k,String(n),{expirationTtl:900});
    await alert(env,ip,'Credential mismatch',`${n} failed attempt(s) on ${sub}`);return J({error:'credentials rejected',flagged:true},401)}
   case '/api/checkout':{
    const usd=+b.usd;if(!GATES.includes(b.gateway)||!(usd>0&&usd<=5000))return J({error:'invalid payment'},400);
    const id='PAY-'+rnd(5).toUpperCase(),item=String(b.item||'').slice(0,100);let url=null;
    await env.DB.prepare('INSERT INTO payments VALUES(?,?,?,?,?,?,?,?)').bind(id,b.sub||null,b.gateway,item,usd,String(b.txid||'').slice(0,80),'pending',new Date().toISOString()).run();
    if(b.gateway==='Stripe'&&env.STRIPE_KEY){const r=await fetch('https://api.stripe.com/v1/checkout/sessions',{method:'POST',headers:{authorization:'Bearer '+env.STRIPE_KEY,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({mode:'payment','line_items[0][price_data][currency]':'usd','line_items[0][price_data][product_data][name]':item,'line_items[0][price_data][unit_amount]':String(Math.round(usd*100)),'line_items[0][quantity]':'1',success_url:u.origin+'/#price',cancel_url:u.origin+'/#price','metadata[payment_id]':id})});url=(await r.json()).url||null}
    await tg(env,`💳 <b>Payment ${id}</b>\n${X(item)} · $${usd}\n${X(b.gateway)} · TxID ${X(b.txid||'-')}\nWorkspace: ${X(b.sub||'visitor')}`);
    return J({status:'pending',url,message:url?'Redirecting to secure checkout':'Payment recorded. Access activates once the founder verifies it.'})}
   case '/api/notify':{
    if(!env.TWILIO_SID||!env.TWILIO_TOKEN||!env.TWILIO_FROM)return J({error:'SMS provider not configured'},503);
    if(await hit(env,'sms:'+String(b.sub),200,86400))return J({error:'daily limit'},429);
    const m=(Array.isArray(b.messages)?b.messages:[]).slice(0,100).filter(a=>/^\+?[0-9]{7,15}$/.test(a.to||''));
    const r=await Promise.allSettled(m.map(a=>fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`,{method:'POST',headers:{authorization:'Basic '+btoa(env.TWILIO_SID+':'+env.TWILIO_TOKEN)},body:new URLSearchParams({To:a.to,From:env.TWILIO_FROM,Body:String(a.text).slice(0,300)})}).then(x=>{if(!x.ok)throw 0})));
    return J({sent:r.filter(x=>x.status==='fulfilled').length,failed:r.filter(x=>x.status==='rejected').length})}
   case '/api/ai':{
    if(!env.AI)return J({error:'AI not configured'},503);
    if(await hit(env,'ai:'+ip,30,3600))return J({error:'rate limited'},429);
    const s=String(b.subject||'').slice(0,120),c=String(b.chapter||'').slice(0,160),d=['Easy','Medium','Hard'].includes(b.difficulty)?b.difficulty:'Medium',k=['Exam paper','Syllabus outline','Lesson plan'].includes(b.kind)?b.kind:'Exam paper';
    const r=await env.AI.run('@cf/meta/llama-3.1-8b-instruct',{messages:[{role:'system',content:'You are an academic assistant for schools, madrasahs and universities. Reply with plain text only.'},{role:'user',content:`Create a ${k} for subject "${s}", chapter "${c}", difficulty ${d}. Include marks and clear sections.`}],max_tokens:1200});
    return J({text:r.response||''})}
  }
  return J({error:'not found'},404);
 }catch(e){return J({error:'server error'},500)}
}};
