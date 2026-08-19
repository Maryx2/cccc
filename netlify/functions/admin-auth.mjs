
import {json,makeToken,cookie,session} from './_admin-lib.mjs';
export default async(req)=>{
  if(req.method==='GET'){
    const s=session(req);
    return s?json({ok:true,session:{username:s.username,role:s.role}}):json({error:'Unauthorized'},401);
  }
  if(req.method==='DELETE'){
    return json({ok:true},200,{'set-cookie':'starblast_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure'});
  }
  if(req.method!=='POST')return json({error:'Method not allowed'},405);
  let b={};try{b=await req.json()}catch{}
  const u=String(b.username||'').trim(),p=String(b.password||'');
  const eu=String(process.env.ADMIN_USERNAME||'').trim(),ep=String(process.env.ADMIN_PASSWORD||'');
  if(!eu||!ep)return json({error:'ADMIN_USERNAME / ADMIN_PASSWORD are not configured in Netlify'},500);
  if(u!==eu||p!==ep)return json({error:'Invalid admin login'},401);
  const role='owner',token=makeToken(u,role);
  return json({ok:true,session:{username:u,role}},200,{'set-cookie':cookie(token,28800)});
};
