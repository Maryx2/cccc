
import {json,requireAdmin,canEdit,rest,authAdmin,audit,num} from './_admin-lib.mjs';

const qs=x=>encodeURIComponent(String(x??''));
const allowedFields=['username','xp','level','total_score','best_score','best_multiplier','launches','ejects','failures','best_streak'];
export default async(req)=>{
  try{
    const s=requireAdmin(req);
    if(req.method!=='POST')return json({error:'Method not allowed'},405);
    const b=await req.json(),a=String(b.action||'');
    if(a==='update_player'){
      if(!canEdit(s))return json({error:'Owner or Admin required'},403);
      const patch={};
      for(const k of allowedFields)if(b[k]!==undefined){
        if(k==='username'){const v=String(b[k]).trim();if(!/^[A-Za-z0-9_-]{3,20}$/.test(v))return json({error:'Username must be 3–20 letters, numbers, _ or -'},400);patch[k]=v}
        else patch[k]=Math.max(k==='best_multiplier'?1:0,Number(b[k])||0);
      }
      if(!Object.keys(patch).length)return json({error:'Nothing to update'},400);
      await rest(`profiles?user_id=eq.${qs(b.userId)}`,{method:'PATCH',body:{...patch,updated_at:new Date().toISOString()},prefer:'return=minimal'});
      await audit(s,'UPDATE_PLAYER',b.userId,patch);return json({ok:true});
    }
    if(a==='update_player_email'){
      if(s.role!=='owner')return json({error:'Owner required'},403);
      const email=String(b.email||'').trim().toLowerCase();
      if(!email.includes('@'))return json({error:'Valid email required'},400);
      await authAdmin(`users/${b.userId}`,{method:'PUT',body:{email,email_confirm:true}});
      await audit(s,'UPDATE_PLAYER_EMAIL',b.userId,{email});return json({ok:true});
    }
    if(a==='adjust_tokens'){
      if(!canEdit(s))return json({error:'Owner or Admin required'},403);
      const delta=Math.trunc(Number(b.delta||0));if(!delta)return json({error:'Token amount cannot be zero'},400);
      const [p]=await rest(`profiles?select=user_id,high_notes_tokens&user_id=eq.${qs(b.userId)}&limit=1`)||[];
      if(!p)return json({error:'Player not found'},404);
      const old=num(p.high_notes_tokens),balance=Math.max(0,old+delta),actual=balance-old;
      if(!actual)return json({balance});
      await rest(`profiles?user_id=eq.${qs(b.userId)}`,{method:'PATCH',body:{high_notes_tokens:balance,updated_at:new Date().toISOString()},prefer:'return=minimal'});
      await rest('high_notes_token_ledger',{method:'POST',body:{user_id:b.userId,delta:actual,balance_after:balance,reason:String(b.reason||'Admin adjustment').slice(0,200),source:'admin',admin_username:s.username},prefer:'return=minimal'});
      await audit(s,actual>0?'GIVE_HNT':'TAKE_HNT',b.userId,{delta:actual,balance});
      return json({ok:true,balance});
    }
    if(a==='suspend_player'){
      if(!['owner','admin','moderator'].includes(s.role))return json({error:'Insufficient role'},403);
      await rest(`profiles?user_id=eq.${qs(b.userId)}`,{method:'PATCH',body:{is_suspended:!!b.suspended,updated_at:new Date().toISOString()},prefer:'return=minimal'});
      await audit(s,b.suspended?'SUSPEND_PLAYER':'UNSUSPEND_PLAYER',b.userId,{});return json({ok:true});
    }
    if(a==='save_note'){
      if(!['owner','admin','moderator'].includes(s.role))return json({error:'Insufficient role'},403);
      await rest('admin_player_notes',{method:'POST',body:{user_id:b.userId,note:String(b.note||'').slice(0,5000),updated_by:s.username,updated_at:new Date().toISOString()},prefer:'resolution=merge-duplicates,return=minimal'});
      await audit(s,'SAVE_NOTE',b.userId,{});return json({ok:true});
    }
    if(a==='refresh_player_stats'){
      if(!canEdit(s))return json({error:'Owner or Admin required'},403);
      const runs=await rest(`runs?select=outcome,multiplier,score,duration_ms,created_at&user_id=eq.${qs(b.userId)}&order=created_at.asc&limit=10000`)||[];
      let launches=runs.length,ejects=0,failures=0,total=0,bestScore=0,bestMult=1,cur=0,bestStreak=0,totalPlay=0;
      for(const r of runs){const score=num(r.score),m=num(r.multiplier);total+=score;bestScore=Math.max(bestScore,score);bestMult=Math.max(bestMult,m);totalPlay+=num(r.duration_ms);if(r.outcome==='EJECT'){ejects++;cur++;bestStreak=Math.max(bestStreak,cur)}else{failures++;cur=0}}
      const patch={launches,ejects,failures,total_score:total,best_score:bestScore,best_multiplier:bestMult,current_streak:cur,best_streak:bestStreak,total_play_ms:totalPlay,updated_at:new Date().toISOString()};
      // Remove optional columns if schema rejects them.
      try{await rest(`profiles?user_id=eq.${qs(b.userId)}`,{method:'PATCH',body:patch,prefer:'return=minimal'})}
      catch{delete patch.current_streak;delete patch.total_play_ms;await rest(`profiles?user_id=eq.${qs(b.userId)}`,{method:'PATCH',body:patch,prefer:'return=minimal'})}
      await audit(s,'REFRESH_PLAYER_STATS',b.userId,patch);return json({ok:true});
    }
    if(a==='update_config'){
      if(!canEdit(s))return json({error:'Owner or Admin required'},403);
      await rest('game_config?id=eq.1',{method:'PATCH',body:{...b.config,updated_at:new Date().toISOString()},prefer:'return=minimal'});await audit(s,'UPDATE_CONFIG',null,b.config);return json({ok:true});
    }
    if(a==='scan_anomalies')return json({ok:true,found:0});
    return json({error:'Unknown action'},400);
  }catch(e){return json({error:e.message},e.status||500)}
};
