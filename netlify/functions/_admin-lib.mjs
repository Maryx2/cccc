
import crypto from 'node:crypto';

export function json(body,status=200,headers={}){
  return new Response(JSON.stringify(body),{
    status,
    headers:{'content-type':'application/json; charset=utf-8',...headers}
  });
}
export function env(name,required=true){
  const v=process.env[name]||'';
  if(required&&!v)throw new Error(`${name} is not configured`);
  return v;
}
export function serviceKey(){
  return process.env.SUPABASE_SERVICE_ROLE_KEY||process.env.SUPABASE_SECRET_KEY||'';
}
export function signingSecret(){
  return process.env.ADMIN_SESSION_SECRET
    || crypto.createHash('sha256').update(
      `starblast|${process.env.ADMIN_PASSWORD||''}|${serviceKey()||'admin'}`
    ).digest('hex');
}
function sign(payload){
  return crypto.createHmac('sha256',signingSecret()).update(payload).digest('hex');
}
export function makeToken(username,role='owner',seconds=28800){
  const payload=`${String(username).trim()}|${String(role).toLowerCase()}|${Date.now()+seconds*1000}`;
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload)}`;
}
export function cookie(token,seconds){
  return `starblast_admin=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}; Secure`;
}
export function session(req){
  const cookies=req.headers.get('cookie')||'';
  const raw=cookies.split(';').map(x=>x.trim()).find(x=>x.startsWith('starblast_admin='))?.split('=').slice(1).join('=');
  if(!raw)return null;
  try{
    const token=decodeURIComponent(raw),[b64,sig]=token.split('.');
    const payload=Buffer.from(b64,'base64url').toString();
    const expected=sign(payload);
    if(!sig||sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;
    const [username,role,exp]=payload.split('|');
    if(Date.now()>=Number(exp))return null;
    return {username,role:String(role||'').toLowerCase(),exp:Number(exp)};
  }catch{return null}
}
export function requireAdmin(req){
  const s=session(req);
  if(!s)throw Object.assign(new Error('Unauthorized'),{status:401});
  return s;
}
export function canEdit(s){return ['owner','admin'].includes(String(s.role).toLowerCase())}
export function sbUrl(){return env('SUPABASE_URL').replace(/\/$/,'')}
export async function rest(path,{method='GET',body,prefer}={}){
  const key=serviceKey();
  if(!key)throw new Error('SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) is not configured');
  const r=await fetch(`${sbUrl()}/rest/v1/${path}`,{
    method,
    headers:{
      apikey:key,Authorization:`Bearer ${key}`,
      ...(body!==undefined?{'content-type':'application/json'}:{}),
      ...(prefer?{Prefer:prefer}:{})
    },
    body:body===undefined?undefined:JSON.stringify(body)
  });
  const text=await r.text();
  let data=null;try{data=text?JSON.parse(text):null}catch{data=text}
  if(!r.ok)throw new Error(data?.message||data?.error||text||`Supabase ${r.status}`);
  return data;
}
export async function authAdmin(path,{method='GET',body}={}){
  const key=serviceKey();
  if(!key)throw new Error('Supabase service key is not configured');
  const r=await fetch(`${sbUrl()}/auth/v1/admin/${path}`,{
    method,
    headers:{apikey:key,Authorization:`Bearer ${key}`,'content-type':'application/json'},
    body:body===undefined?undefined:JSON.stringify(body)
  });
  const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{data=text}
  if(!r.ok)throw new Error(data?.msg||data?.message||text||`Auth ${r.status}`);
  return data;
}
export async function audit(s,action,target=null,details={}){
  try{
    await rest('rpc/write_admin_audit_log',{
      method:'POST',
      body:{p_admin_username:s.username,p_action:action,p_target_user_id:target,p_details:details}
    });
  }catch(e){console.error('audit:',e.message)}
}
export const num=v=>Number(v||0);
export const agoIso=ms=>new Date(Date.now()-ms).toISOString();
