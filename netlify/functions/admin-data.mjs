import {json,requireRole,rest,env} from './_admin-lib.mjs';
const num=v=>Number(v||0),ago=ms=>new Date(Date.now()-ms).toISOString();
async function authUsers(){const {url,headers}=env();const r=await fetch(`${url}/auth/v1/admin/users?page=1&per_page=1000`,{headers});if(!r.ok)throw new Error('Could not load Auth users');const d=await r.json();return d.users||[]}
export default async req=>{const s=requireRole(req);if(!s)return json({error:'Unauthorized'},401);try{const u=new URL(req.url),section=u.searchParams.get('section')||'overview';
 if(section==='session')return json({session:{username:s.username,role:s.role}});
 if(section==='overview'){const [profiles,runs,active,config,alerts,ledger]=await Promise.all([rest('profiles?select=*&order=total_score.desc&limit=1000'),rest(`runs?select=*&created_at=gte.${encodeURIComponent(ago(86400000))}&order=created_at.desc&limit=3000`),rest(`active_runs?select=*&started_at=gte.${encodeURIComponent(ago(1800000))}&limit=500`),rest('game_config?select=*&id=eq.1'),rest('anomaly_alerts?select=*&status=eq.open&order=detected_at.desc&limit=50'),rest(`high_notes_token_ledger?select=delta,source,created_at&created_at=gte.${encodeURIComponent(ago(86400000))}&limit=10000`)]);const sum=profiles.reduce((a,p)=>(a.players++,a.launches+=num(p.launches),a.hnt+=num(p.high_notes_tokens),a),{players:0,launches:0,hnt:0});const online=profiles.filter(p=>p.last_seen_at&&Date.now()-new Date(p.last_seen_at)<90000).length;return json({session:s,summary:{...sum,online,active:active.length,runs24h:runs.length,hntSpent24h:-ledger.filter(x=>num(x.delta)<0).reduce((z,x)=>z+num(x.delta),0),hntIssued24h:ledger.filter(x=>num(x.delta)>0).reduce((z,x)=>z+num(x.delta),0),openAlerts:alerts.length,rareRate:runs.length?runs.filter(r=>num(r.multiplier)>3).length/runs.length*100:0},topPlayers:profiles.slice(0,10),alerts:alerts.slice(0,8),config:config?.[0]||null});}
 if(section==='players'){const q=(u.searchParams.get('q')||'').trim().replace(/[*,]/g,''),filter=q?`&username=ilike.*${encodeURIComponent(q)}*`:'';const [profiles,users]=await Promise.all([rest(`profiles?select=*&order=last_seen_at.desc.nullslast&limit=250${filter}`),authUsers().catch(()=>[])]);const m=new Map(users.map(x=>[x.id,x]));return json({players:profiles.map(p=>({...p,email:m.get(p.user_id)?.email||null}))});}
 if(section==='player'){const id=u.searchParams.get('id');const [p,runs,note,ledger,users]=await Promise.all([rest(`profiles?select=*&user_id=eq.${id}&limit=1`),rest(`runs?select=*&user_id=eq.${id}&order=created_at.desc&limit=500`),rest(`admin_player_notes?select=*&user_id=eq.${id}&limit=1`),rest(`high_notes_token_ledger?select=*&user_id=eq.${id}&order=created_at.desc&limit=500`),authUsers().catch(()=>[])]);const player=p?.[0]||null;const au=users.find(x=>x.id===id);return json({player:player?{...player,email:au?.email||null,auth_created_at:au?.created_at||null,last_sign_in_at:au?.last_sign_in_at||null}:null,runs,note:note?.[0]||null,ledger});}
 if(section==='live'){const [profiles,runs]=await Promise.all([rest(`profiles?select=user_id,username,level,total_score,high_notes_tokens,last_seen_at,is_suspended&last_seen_at=gte.${encodeURIComponent(ago(900000))}&order=last_seen_at.desc&limit=500`),rest(`runs?select=*&created_at=gte.${encodeURIComponent(ago(3600000))}&order=created_at.desc&limit=150`)]);let active=[];try{active=await rest(`active_flights?select=*&updated_at=gte.${encodeURIComponent(ago(10000))}&order=multiplier.desc&limit=500`)}catch{active=await rest(`active_runs?select=*&started_at=gte.${encodeURIComponent(ago(1800000))}&order=started_at.desc&limit=500`)}const n=new Map(profiles.map(p=>[p.user_id,p.username]));return json({players,active:active.map(x=>({...x,username:x.username||n.get(x.user_id)||'Unknown'})),events:runs.map(x=>({...x,username:n.get(x.user_id)||'Unknown'}))});}
 if(section==='economy'){const days=Math.min(90,Math.max(1,num(u.searchParams.get('days'))||7)),since=ago(days*86400000);const [ledger,profiles]=await Promise.all([rest(`high_notes_token_ledger?select=*&created_at=gte.${encodeURIComponent(since)}&order=created_at.desc&limit=10000`),rest('profiles?select=user_id,username,high_notes_tokens&limit=5000')]);const n=new Map(profiles.map(p=>[p.user_id,p.username]));const issued=ledger.filter(x=>num(x.delta)>0).reduce((s,x)=>s+num(x.delta),0),spent=-ledger.filter(x=>num(x.delta)<0).reduce((s,x)=>s+num(x.delta),0);return json({summary:{issued,spent,net:issued-spent,totalSupply:profiles.reduce((s,p)=>s+num(p.high_notes_tokens),0),avgBalance:profiles.length?profiles.reduce((s,p)=>s+num(p.high_notes_tokens),0)/profiles.length:0},ledger:ledger.map(x=>({...x,username:n.get(x.user_id)||'Unknown'}))});}
 if(section==='alerts')return json({alerts:await rest('anomaly_alerts?select=*&order=detected_at.desc&limit=500')});
 if(section==='admins'){if(s.role!=='owner')return json({error:'Owner role required'},403);return json({admins:await rest('admin_accounts?select=username,role,active,created_by,created_at,last_login_at&order=created_at.asc')});}
 if(section==='leaderboard')return json({players:await rest('profiles?select=user_id,username,total_score,best_score,level,launches,ejects,failures,best_multiplier,best_streak,high_notes_tokens,last_seen_at,is_suspended&order=total_score.desc&limit=100')});
 if(section==='audit')return json({logs:await rest('admin_audit_logs?select=*&order=created_at.desc&limit=500')});
 if(section==='config')return json({config:(await rest('game_config?select=*&id=eq.1'))?.[0]||null});


 if(section==='crews'){
   const [crews,members]=await Promise.all([rest('crews?select=*&order=season_score.desc&limit=500'),rest('crew_members?select=crew_id,user_id,role,joined_at&limit=5000')]);
   const counts={};for(const m of members)counts[m.crew_id]=(counts[m.crew_id]||0)+1;
   return json({crews:crews.map(c=>({...c,members:counts[c.id]||0}))});
 }

 if(section==='events'){
   const events=await rest('game_events?select=*&order=created_at.desc&limit=200');
   return json({events});
 }
 if(section==='records'){
   const [profiles,runs,milestones]=await Promise.all([
     rest('profiles?select=user_id,username,total_score,season_score,launches,ejects,best_multiplier,best_streak,last_seen_at&order=total_score.desc&limit=5000'),
     rest(`runs?select=user_id,multiplier,outcome,score,created_at&created_at=gte.${encodeURIComponent(ago(30*86400000))}&order=multiplier.desc&limit=5000`),
     rest('community_milestones?select=*&order=created_at.desc&limit=100')
   ]);
   const names=new Map(profiles.map(p=>[p.user_id,p.username]));
   const todayStart=new Date();todayStart.setUTCHours(0,0,0,0);
   const today=runs.filter(r=>new Date(r.created_at)>=todayStart);
   const best=(arr)=>arr.length?{username:names.get(arr[0].user_id)||'Unknown',multiplier:num(arr[0].multiplier),created_at:arr[0].created_at}:null;
   const allSorted=[...runs].sort((a,b)=>num(b.multiplier)-num(a.multiplier));
   const todaySorted=[...today].sort((a,b)=>num(b.multiplier)-num(a.multiplier));
   const streak=[...profiles].sort((a,b)=>num(b.best_streak)-num(a.best_streak))[0]||null;
   const flights=[...profiles].sort((a,b)=>num(b.launches)-num(a.launches))[0]||null;
   const season=[...profiles].sort((a,b)=>num(b.season_score)-num(a.season_score))[0]||null;
   return json({records:{today:best(todaySorted),allTime30d:best(allSorted),streak,flights,season},milestones});
 }

 if(section==='system'){let db=true,auth=true,dbError=null,authError=null;try{await rest('profiles?select=user_id&limit=1')}catch(e){db=false;dbError=e.message}try{await authUsers()}catch(e){auth=false;authError=e.message}return json({session:s,checks:{database:db,auth,serviceRole:!!process.env.SUPABASE_SERVICE_ROLE_KEY,sessionSecret:!!process.env.ADMIN_SESSION_SECRET},errors:{dbError,authError},now:new Date().toISOString()});}
 return json({error:'Unknown section'},400);
}catch(e){return json({error:e.message||'Admin data error'},500)}};
