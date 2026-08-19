import crypto from 'node:crypto';
export const COOKIE='starblast_admin';
export const json=(body,status=200,headers={})=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json','cache-control':'no-store',...headers}});
export const secret=()=>process.env.ADMIN_SESSION_SECRET||((process.env.ADMIN_PASSWORD&&process.env.ADMIN_USERNAME)?crypto.createHash('sha256').update('starblast-admin-session|'+process.env.ADMIN_USERNAME+'|'+process.env.ADMIN_PASSWORD).digest('hex'):'');
export const sign=v=>crypto.createHmac('sha256',secret()).update(v).digest('hex');
export const cookie=(value,maxAge,secure=true)=>`${COOKIE}=${value}; Path=/; HttpOnly; ${secure?'Secure; ':''}SameSite=Lax; Max-Age=${maxAge}`;
export function session(req){
  const auth=(req.headers.get('authorization')||'').trim();
  const bearer=/^Bearer\s+(.+)$/i.exec(auth)?.[1];
  const cookieToken=(req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.split('=').slice(1).join('=');
  const raw=bearer||cookieToken;
  if(!raw||!secret())return null;
  try{
    const [b64,sig]=raw.split('.');
    const payload=Buffer.from(b64,'base64url').toString();
    const expected=sign(payload);
    if(!sig||sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;
    const [username,role,exp]=payload.split('|');
    if(Date.now()>=Number(exp))return null;
    return{username,role:String(role||'').trim().toLowerCase(),exp:Number(exp),token:raw};
  }catch{return null}
}
export function requireRole(req,roles){const s=session(req);if(!s)return null;if(roles&&!roles.includes(s.role))return false;return s}
export function env(){const url=(process.env.SUPABASE_URL||'').replace(/\/$/,'');const key=process.env.SUPABASE_SERVICE_ROLE_KEY||process.env.SUPABASE_SECRET_KEY||'';if(!url||!key)throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) are required');return{url,key,headers:{apikey:key,Authorization:`Bearer ${key}`,'content-type':'application/json'}}}
export async function rest(path,method='GET',body,prefer='return=representation'){const {url,headers}=env();const r=await fetch(`${url}/rest/v1/${path}`,{method,headers:{...headers,Prefer:prefer},body:body===undefined?undefined:JSON.stringify(body)});const txt=await r.text();let data=null;try{data=txt?JSON.parse(txt):null}catch{data=txt}if(!r.ok)throw new Error(typeof data==='object'?(data.message||data.error||JSON.stringify(data)):String(data||r.statusText));return data}
export async function rpc(name,body={}){const {url,headers}=env();const r=await fetch(`${url}/rest/v1/rpc/${name}`,{method:'POST',headers,body:JSON.stringify(body)});const txt=await r.text();let data=null;try{data=txt?JSON.parse(txt):null}catch{data=txt}if(!r.ok)throw new Error(typeof data==='object'?(data.message||data.error||JSON.stringify(data)):String(data||r.statusText));return data}
export async function audit(s,action,target=null,details={}){
  // Write audit records through a SECURITY DEFINER RPC. This avoids browser/RLS
  // ambiguity while keeping the audit table closed to anon/authenticated roles.
  await rpc('write_admin_audit_log',{p_admin_username:s.username,p_action:action,p_target_user_id:target,p_details:{...details,role:s.role}});
}
export const permissions={owner:['*'],admin:['players','edit_players','tokens','config','alerts','notes','suspend','refresh','export'],moderator:['players','alerts','notes','suspend','export'],analyst:['view','export']};
export function can(s,perm){if(!s)return false;const role=String(s.role||'').trim().toLowerCase();return !!(permissions[role]?.includes('*')||permissions[role]?.includes(perm)||perm==='view')}
export function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){const hash=crypto.scryptSync(password,salt,64).toString('hex');return{salt,hash}}
export function verifyPassword(password,salt,hash){const got=crypto.scryptSync(password,salt,64);const want=Buffer.from(hash,'hex');return got.length===want.length&&crypto.timingSafeEqual(got,want)}


export function makeToken(username, role='owner', ttlSeconds=8*60*60){
  if(!secret()) throw new Error('ADMIN_SESSION_SECRET is not configured');
  const exp=Date.now()+Number(ttlSeconds||0)*1000;
  const payload=`${String(username||'').trim().toLowerCase()}|${String(role||'owner').trim().toLowerCase()}|${exp}`;
  const b64=Buffer.from(payload).toString('base64url');
  return `${b64}.${sign(payload)}`;
}
