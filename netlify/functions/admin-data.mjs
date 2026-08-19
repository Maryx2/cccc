
import {json,requireAdmin,rest,authAdmin,num,agoIso} from './_admin-lib.mjs';

const qs=x=>encodeURIComponent(String(x??''));
async function authUsers(){
  try{return (await authAdmin('users?page=1&per_page=1000'))?.users||[]}catch{return []}
}
async function profiles(q=''){
  const filter=q?`&username=ilike.*${qs(q)}*`:'';
  return await rest(`profiles?select=*&order=total_score.desc&limit=1000${filter}`)||[];
}
async function ledger(limit=1000){
  try{return await rest(`high_notes_token_ledger?select=*&order=created_at.desc&limit=${limit}`)||[]}catch{return []}
}
export default async(req)=>{
  try{
    requireAdmin(req);
    const url=new URL(req.url),section=url.searchParams.get('section')||'overview';
    if(section==='players'){
      const ps=await profiles(url.searchParams.get('q')||''),users=await authUsers(),um=new Map(users.map(u=>[u.id,u]));
      return json({players:ps.map(p=>({...p,email:um.get(p.user_id)?.email||null,auth_created_at:um.get(p.user_id)?.created_at||null,last_sign_in_at:um.get(p.user_id)?.last_sign_in_at||null}))});
    }
    if(section==='player'){
      const id=url.searchParams.get('id');
      const [p]=await rest(`profiles?select=*&user_id=eq.${qs(id)}&limit=1`)||[];
      if(!p)return json({error:'Player not found'},404);
      let user=null;try{user=await authAdmin(`users/${id}`)}catch{}
      let runs=[];try{runs=await rest(`runs?select=*&user_id=eq.${qs(id)}&order=created_at.desc&limit=200`)||[]}catch{}
      let led=[];try{led=await rest(`high_notes_token_ledger?select=*&user_id=eq.${qs(id)}&order=created_at.desc&limit=100`)||[]}catch{}
      let note=null;try{[note]=await rest(`admin_player_notes?select=*&user_id=eq.${qs(id)}&limit=1`)||[]}catch{}
      return json({player:{...p,email:user?.email||null,auth_created_at:user?.created_at||null,last_sign_in_at:user?.last_sign_in_at||null},runs,ledger:led,note});
    }
    if(section==='leaderboard'){
      return json({players:(await profiles()).slice(0,100)});
    }
    if(section==='live'){
      const ps=await profiles(),fresh=ps.filter(p=>p.last_seen_at&&new Date(p.last_seen_at)>new Date(Date.now()-15*60*1000));
      let active=[];try{active=await rest(`active_runs?select=*&started_at=gte.${qs(agoIso(30*60*1000))}&order=started_at.desc&limit=100`)||[]}catch{}
      let events=[];try{events=await rest(`runs?select=*&created_at=gte.${qs(agoIso(60*60*1000))}&order=created_at.desc&limit=100`)||[]}catch{}
      const n=new Map(ps.map(p=>[p.user_id,p.username]));
      return json({players:fresh,active:active.map(x=>({...x,username:n.get(x.user_id)||'Unknown'})),events:events.map(x=>({...x,username:n.get(x.user_id)||'Unknown'}))});
    }
    if(section==='economy'){
      const ps=await profiles(),l=await ledger(3000),days=Math.max(1,Number(url.searchParams.get('days')||7)),cut=Date.now()-days*86400000;
      const recent=l.filter(x=>new Date(x.created_at).getTime()>=cut);
      return json({summary:{issued:recent.filter(x=>num(x.delta)>0).reduce((a,x)=>a+num(x.delta),0),spent:Math.abs(recent.filter(x=>num(x.delta)<0).reduce((a,x)=>a+num(x.delta),0)),net:recent.reduce((a,x)=>a+num(x.delta),0),totalSupply:ps.reduce((a,x)=>a+num(x.high_notes_tokens),0),avgBalance:ps.length?ps.reduce((a,x)=>a+num(x.high_notes_tokens),0)/ps.length:0},ledger:recent.map(x=>({...x,username:ps.find(p=>p.user_id===x.user_id)?.username||'Unknown'}))});
    }
    if(section==='overview'){
      const ps=await profiles(),l=await ledger(2000),cut=Date.now()-86400000;
      let runs=[];try{runs=await rest(`runs?select=*&created_at=gte.${qs(new Date(cut).toISOString())}&order=created_at.desc&limit=3000`)||[]}catch{}
      let active=[];try{active=await rest(`active_runs?select=*&started_at=gte.${qs(agoIso(30*60*1000))}&limit=500`)||[]}catch{}
      const recentL=l.filter(x=>new Date(x.created_at).getTime()>=cut),online=ps.filter(p=>p.last_seen_at&&new Date(p.last_seen_at).getTime()>Date.now()-90000).length;
      return json({summary:{online,active:active.length,runs24h:runs.length,hntSpent24h:Math.abs(recentL.filter(x=>num(x.delta)<0).reduce((a,x)=>a+num(x.delta),0)),hntIssued24h:recentL.filter(x=>num(x.delta)>0).reduce((a,x)=>a+num(x.delta),0),hnt:ps.reduce((a,x)=>a+num(x.high_notes_tokens),0),rareRate:runs.length?100*runs.filter(x=>num(x.multiplier)>3).length/runs.length:0,openAlerts:0},topPlayers:ps.slice(0,10),alerts:[]});
    }
    if(section==='config'){
      let config={};try{[config]=await rest('game_config?select=*&id=eq.1&limit=1')||[{}]}catch{}
      return json({config});
    }
    if(section==='audit'){
      let logs=[];try{logs=await rest('admin_audit_logs?select=*&order=created_at.desc&limit=500')||[]}catch{}
      return json({logs});
    }
    if(section==='alerts')return json({alerts:[]});
    if(section==='admins')return json({admins:[]});
    if(section==='system')return json({checks:{supabase:true,service_role:true,admin_auth:true}});
    return json({error:'Unknown section'},400);
  }catch(e){return json({error:e.message},e.status||500)}
};
