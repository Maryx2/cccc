import {json,cookie,session,makeToken} from './_admin-lib.mjs';

const DEFAULT_ALLOWED = [
  'marymdb1998@gmail.com',
  'amirnajmabadi415@gmail.com'
];

function allowedEmails(){
  const extra=(process.env.ADMIN_ALLOWED_EMAILS||'')
    .split(',')
    .map(x=>x.trim().toLowerCase())
    .filter(Boolean);
  return [...new Set([...DEFAULT_ALLOWED,...extra])];
}

function supabaseConfig(){
  return {
    url:(process.env.SUPABASE_URL||'').replace(/\/$/,''),
    anon:process.env.SUPABASE_ANON_KEY||''
  };
}

function validAdminCredentials(email,password){
  const allowed=allowedEmails();
  const expected=process.env.ADMIN_SHARED_PASSWORD||'highnotes1234';
  return allowed.includes(String(email||'').trim().toLowerCase())
    && String(password||'')===expected;
}

export default async(req)=>{
  if(req.method==='GET'){
    const s=session(req);
    if(s) return json({ok:true,session:{username:s.username,role:s.role,email:s.username},token:s.token});
    const cfg=supabaseConfig();
    return json({
      ok:false,
      session:null,
      auth_mode:'fixed_admin_credentials',
      allowed_emails:allowedEmails(),
      config:{
        supabase_url:!!cfg.url,
        supabase_anon_key:!!cfg.anon,
        admin_session_secret:!!process.env.ADMIN_SESSION_SECRET,
        shared_password_override:!!process.env.ADMIN_SHARED_PASSWORD
      }
    },401);
  }

  if(req.method==='DELETE'){
    return json({ok:true},200,{
      'set-cookie':cookie('',0,new URL(req.url).protocol==='https:')
    });
  }

  if(req.method!=='POST') return json({error:'Method not allowed'},405);

  try{
    const body=await req.json();
    const email=String(body.email||body.username||'').trim().toLowerCase();
    const password=String(body.password||'');

    if(!email||!password) return json({error:'Email and password are required'},400);

    if(!allowedEmails().includes(email)){
      return json({error:'This email is not authorized for Mission Control.'},403);
    }

    if(!validAdminCredentials(email,password)){
      return json({error:'Invalid admin email or password.'},401);
    }

    const actualEmail=email;
    const role='owner';
    const token=makeToken(actualEmail,role,8*60*60);

    return json(
      {ok:true,session:{username:actualEmail,email:actualEmail,role},token},
      200,
      {'set-cookie':cookie(token,8*60*60,new URL(req.url).protocol==='https:')}
    );
  }catch(e){
    return json({error:e.message||'Admin login failed'},401);
  }
};
