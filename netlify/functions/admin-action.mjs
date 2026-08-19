import {json,requireRole,can,rest,rpc,audit,hashPassword,env} from './_admin-lib.mjs';
export default async req=>{
 const s=requireRole(req);if(!s)return json({error:'Unauthorized'},401);if(req.method!=='POST')return json({error:'Method not allowed'},405);
 try{const b=await req.json();const action=b.action;

  if(action==='update_player'){
    if(!can(s,'edit_players'))return json({error:'Owner or Admin role required to edit players'},403);
    if(!b.userId)return json({error:'Missing userId'},400);
    const id=encodeURIComponent(b.userId);
    const current=(await rest(`profiles?select=*&user_id=eq.${id}&limit=1`))?.[0];
    if(!current)return json({error:'Player not found'},404);
    const patch={};
    if('username' in b){const v=String(b.username||'').trim();if(!/^[A-Za-z0-9_-]{3,20}$/.test(v))return json({error:'Username must be 3-20 characters using letters, numbers, _ or -'},400);patch.username=v;}
    const ints=['xp','level','total_score','best_score','launches','ejects','failures','current_streak','best_streak'];
    for(const k of ints){if(k in b){const v=Number(b[k]);if(!Number.isInteger(v)||v<0||v>1000000000)return json({error:`Invalid ${k}`},400);patch[k]=k==='level'?Math.max(1,v):v;}}
    if('best_multiplier' in b){const v=Number(b.best_multiplier);if(!Number.isFinite(v)||v<1||v>1000)return json({error:'Invalid best multiplier'},400);patch.best_multiplier=Number(v.toFixed(2));}
    const launches='launches' in patch?patch.launches:Number(current.launches||0),ejects='ejects' in patch?patch.ejects:Number(current.ejects||0),failures='failures' in patch?patch.failures:Number(current.failures||0);
    if(ejects+failures!==launches)return json({error:'Launches must equal ejects + failures'},400);
    if('best_score' in patch&&'total_score' in patch&&patch.best_score>patch.total_score)return json({error:'Best score cannot exceed total score'},400);
    patch.updated_at=new Date().toISOString();
    try{await rest(`profiles?user_id=eq.${id}`,'PATCH',patch,'return=minimal')}catch(e){if(String(e.message).toLowerCase().includes('duplicate'))return json({error:'That username is already taken'},409);throw e}
    const before={},after={};for(const k of Object.keys(patch)){if(k==='updated_at')continue;before[k]=current[k];after[k]=patch[k]}
    await audit(s,'EDIT_PLAYER',b.userId,{before,after});return json({ok:true,player:{...current,...patch}});
  }
  if(action==='update_player_email'){
    if(s.role!=='owner')return json({error:'Owner role required to change login email'},403);
    if(!b.userId)return json({error:'Missing userId'},400);const email=String(b.email||'').trim().toLowerCase();if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json({error:'Invalid email'},400);
    const {url,headers}=env();const r=await fetch(`${url}/auth/v1/admin/users/${encodeURIComponent(b.userId)}`,{method:'PUT',headers,body:JSON.stringify({email,email_confirm:true})});const txt=await r.text();let d;try{d=txt?JSON.parse(txt):{}}catch{d={message:txt}}if(!r.ok)return json({error:d.msg||d.message||'Could not update email'},r.status);
    await audit(s,'EDIT_PLAYER_EMAIL',b.userId,{email});return json({ok:true,email});
  }
  if(action==='adjust_tokens'){
    if(!can(s,'tokens'))return json({error:'Forbidden'},403);const delta=Number(b.delta);if(!b.userId||!Number.isInteger(delta)||delta===0)return json({error:'Invalid token adjustment'},400);
    const balance=await rpc('admin_adjust_hnt',{p_user_id:b.userId,p_delta:delta,p_admin:s.username,p_reason:String(b.reason||'Admin adjustment').slice(0,200)});await audit(s,'ADJUST_HNT',b.userId,{delta,balance});return json({ok:true,balance});
  }
  if(action==='refresh_player_stats'){
    if(!can(s,'refresh'))return json({error:'Forbidden'},403);if(!b.userId)return json({error:'Missing userId'},400);const id=encodeURIComponent(b.userId);
    const runs=[];for(let o=0;o<100000;o+=1000){const page=await rest(`runs?select=outcome,multiplier,score,duration_ms,created_at&user_id=eq.${id}&order=created_at.asc&limit=1000&offset=${o}`);runs.push(...(page||[]));if(!page||page.length<1000)break}
    let ejects=0,failures=0,total=0,bestScore=0,bestMult=1,play=0,streak=0,bestStreak=0;for(const r of runs){const score=Math.max(0,Number(r.score)||0),m=Math.max(1,Number(r.multiplier)||1);if(r.outcome==='EJECT'){ejects++;streak++;bestStreak=Math.max(bestStreak,streak)}else{failures++;streak=0}total+=score;bestScore=Math.max(bestScore,score);bestMult=Math.max(bestMult,m);play+=Math.max(0,Number(r.duration_ms)||0)}
    const patch={launches:runs.length,ejects,failures,total_score:Math.round(total),best_score:Math.round(bestScore),best_multiplier:Number(bestMult.toFixed(2)),current_streak:streak,best_streak:bestStreak,total_play_ms:Math.round(play),updated_at:new Date().toISOString()};await rest(`profiles?user_id=eq.${id}`,'PATCH',patch,'return=minimal');await audit(s,'REFRESH_PLAYER_STATS',b.userId,{runs:runs.length});return json({ok:true,stats:patch});
  }
  if(action==='suspend_player'){
    if(!can(s,'suspend'))return json({error:'Forbidden'},403);if(!b.userId)return json({error:'Missing userId'},400);const suspended=!!b.suspended;await rest(`profiles?user_id=eq.${encodeURIComponent(b.userId)}`,'PATCH',{is_suspended:suspended,updated_at:new Date().toISOString()},'return=minimal');if(suspended)await rest(`active_runs?user_id=eq.${encodeURIComponent(b.userId)}`,'DELETE',undefined,'return=minimal');await audit(s,suspended?'SUSPEND_PLAYER':'UNSUSPEND_PLAYER',b.userId,{});return json({ok:true});
  }
  if(action==='save_note'){
    if(!can(s,'notes'))return json({error:'Forbidden'},403);const note=String(b.note||'').slice(0,4000);await rest('admin_player_notes?on_conflict=user_id','POST',{user_id:b.userId,note,updated_by:s.username,updated_at:new Date().toISOString()},'resolution=merge-duplicates,return=minimal');await audit(s,'SAVE_NOTE',b.userId,{length:note.length});return json({ok:true});
  }


  if(action==='send_inbox'){
    if(!can(s,'players'))return json({error:'Insufficient role'},403);
    const userId=String(b.userId||''),subject=String(b.subject||'Mission Control').trim().slice(0,120),message=String(b.message||'').trim().slice(0,500);
    const hnt=Math.max(0,Math.trunc(Number(b.hnt_reward||0))),xp=Math.max(0,Math.trunc(Number(b.xp_reward||0)));
    if(!userId||!subject)return json({error:'Player and subject required'},400);
    await rest('player_inbox','POST',{user_id:userId,subject,message,hnt_reward:hnt,xp_reward:xp,created_by:s.username},'return=minimal');
    await audit(s,'SEND_INBOX',userId,{subject,hnt,xp});return json({ok:true});
  }
  if(action==='distribute_season_rewards'){
    if(s.role!=='owner')return json({error:'Owner role required'},403);
    const seasonId=Number(b.seasonId);if(!Number.isInteger(seasonId))return json({error:'Invalid season'},400);
    const count=await rest('rpc/distribute_season_rewards','POST',{p_season_id:seasonId,p_admin:s.username});
    await audit(s,'DISTRIBUTE_SEASON_REWARDS',null,{seasonId,count});return json({ok:true,count});
  }

  if(action==='create_event'){
    if(!can(s,'config'))return json({error:'Owner or Admin role required'},403);
    const type=String(b.event_type||''),title=String(b.title||'').trim().slice(0,80),message=String(b.message||'').trim().slice(0,300);
    const allowed=['announcement','double_xp','free_launch','hnt_bonus','challenge'];
    if(!allowed.includes(type)||!title)return json({error:'Invalid event'},400);
    const starts=b.starts_at?new Date(b.starts_at):new Date(),ends=b.ends_at?new Date(b.ends_at):new Date(Date.now()+3600000);
    if(!Number.isFinite(starts.getTime())||!Number.isFinite(ends.getTime())||ends<=starts)return json({error:'Invalid event time window'},400);
    let value=Number(b.value??1);if(!Number.isFinite(value))value=1;
    if(type==='double_xp'&&(value<1||value>5))return json({error:'XP multiplier must be 1–5'},400);
    if(type==='hnt_bonus'&&(!Number.isInteger(value)||value<1||value>1000))return json({error:'HNT bonus must be 1–1000'},400);
    const row={event_type:type,title,message,value,starts_at:starts.toISOString(),ends_at:ends.toISOString(),active:true,created_by:s.username};
    await rest('game_events','POST',row,'return=minimal');await audit(s,'CREATE_EVENT',null,row);return json({ok:true});
  }
  if(action==='end_event'){
    if(!can(s,'config'))return json({error:'Owner or Admin role required'},403);
    await rest(`game_events?id=eq.${encodeURIComponent(b.id)}`,'PATCH',{active:false,ends_at:new Date().toISOString()},'return=minimal');
    await audit(s,'END_EVENT',null,{eventId:b.id});return json({ok:true});
  }
  if(action==='save_milestone'){
    if(!can(s,'config'))return json({error:'Owner or Admin role required'},403);
    const title=String(b.title||'').trim().slice(0,100),description=String(b.description||'').trim().slice(0,300),metric=String(b.metric||'launches'),target=Number(b.target),reward=String(b.reward_label||'COMMUNITY REWARD').slice(0,100);
    if(!title||!['launches','ejects','score'].includes(metric)||!Number.isInteger(target)||target<1)return json({error:'Invalid milestone'},400);
    await rest('community_milestones?active=eq.true','PATCH',{active:false},'return=minimal');
    const row={title,description,metric,target,reward_label:reward,active:true,created_by:s.username};
    await rest('community_milestones','POST',row,'return=minimal');await audit(s,'SAVE_MILESTONE',null,row);return json({ok:true});
  }

  if(action==='update_config'){
    if(!can(s,'config'))return json({error:`Game settings require Owner or Admin role. You are signed in as ${String(s.role||'unknown').toUpperCase()}.`},403);const allowed=['cooldown_seconds','rocket_speed','acceleration','score_multiplier','xp_multiplier','launch_token_cost','shields_enabled','slowmo_enabled','maintenance_mode','announcement','extended_run_percent','crash_threshold','standard_min_crash','standard_max_crash','extended_min_crash','extended_max_crash'];const patch={};for(const k of allowed)if(k in (b.config||{}))patch[k]=b.config[k];const pct=Number(patch.extended_run_percent);const threshold=Number(patch.crash_threshold);const smin=Number(patch.standard_min_crash),smax=Number(patch.standard_max_crash),emin=Number(patch.extended_min_crash),emax=Number(patch.extended_max_crash);if('extended_run_percent' in patch&&(pct<0||pct>100))return json({error:'Extended run percent must be 0–100.'},400);if('crash_threshold' in patch&&threshold<=1)return json({error:'Crash threshold must be above 1×.'},400);if(('standard_min_crash' in patch||'standard_max_crash' in patch)&&(!(smin>=1.01)||!(smax>=smin)))return json({error:'Standard crash range is invalid.'},400);if(('extended_min_crash' in patch||'extended_max_crash' in patch)&&(!(emin>=1.01)||!(emax>=emin)))return json({error:'Extended crash range is invalid.'},400);if(Number.isFinite(threshold)){if(Number.isFinite(smax)&&smax>threshold)return json({error:'Standard max cannot exceed the threshold.'},400);if(Number.isFinite(emin)&&emin<=threshold)return json({error:'Extended min must be above the threshold.'},400);}const current=(await rest('game_config?select=config_version&id=eq.1'))?.[0];patch.config_version=Number(current?.config_version||1)+1;patch.updated_at=new Date().toISOString();await rest('game_config?id=eq.1','PATCH',patch,'return=minimal');await audit(s,'UPDATE_CONFIG',null,patch);return json({ok:true,config:patch});
  }
  if(action==='resolve_alert'){
    if(!can(s,'alerts'))return json({error:'Forbidden'},403);await rest(`anomaly_alerts?id=eq.${encodeURIComponent(b.id)}`,'PATCH',{status:b.status==='ignored'?'ignored':'resolved',resolved_at:new Date().toISOString(),resolved_by:s.username},'return=minimal');await audit(s,'RESOLVE_ALERT',null,{alertId:b.id,status:b.status||'resolved'});return json({ok:true});
  }
  if(action==='scan_anomalies'){
    if(!can(s,'alerts'))return json({error:'Forbidden'},403);const since=new Date(Date.now()-24*3600e3).toISOString();const runs=await rest(`runs?select=id,user_id,outcome,multiplier,score,profile_type,created_at&created_at=gte.${encodeURIComponent(since)}&order=created_at.asc&limit=10000`);const profiles=await rest('profiles?select=user_id,username&limit=5000');const names=new Map(profiles.map(p=>[p.user_id,p.username]));const alerts=[];
    for(const r of runs){if(r.profile_type==='standard'&&Number(r.multiplier)>3)alerts.push({kind:'impossible_multiplier',severity:'critical',user_id:r.user_id,title:`Standard run exceeded 3×: ${names.get(r.user_id)||r.user_id}`,details:{runId:r.id,multiplier:r.multiplier}});if(Number(r.score)>1000000)alerts.push({kind:'score_spike',severity:'high',user_id:r.user_id,title:`Unusually high score: ${names.get(r.user_id)||r.user_id}`,details:{runId:r.id,score:r.score}})}
    const by=new Map();for(const r of runs){const arr=by.get(r.user_id)||[];arr.push(r);by.set(r.user_id,arr)}for(const [uid,arr] of by){for(let i=1;i<arr.length;i++){const gap=new Date(arr[i].created_at)-new Date(arr[i-1].created_at);if(gap<3000){alerts.push({kind:'rapid_runs',severity:'medium',user_id:uid,title:`Rapid launch pattern: ${names.get(uid)||uid}`,details:{gapMs:gap}});break}}}
    const recent=runs.slice(-Math.min(500,runs.length)),rare=recent.filter(r=>Number(r.multiplier)>3).length,rate=recent.length?rare/recent.length*100:0;if(recent.length>=100&&rate>8)alerts.push({kind:'rare_rate',severity:'high',user_id:null,title:`>3× rate elevated: ${rate.toFixed(1)}%`,details:{sample:recent.length,rate}});
    for(const a of alerts){const dupe=await rest(`anomaly_alerts?select=id&status=eq.open&kind=eq.${encodeURIComponent(a.kind)}${a.user_id?`&user_id=eq.${a.user_id}`:''}&detected_at=gte.${encodeURIComponent(new Date(Date.now()-6*3600e3).toISOString())}&limit=1`);if(!dupe?.length)await rest('anomaly_alerts','POST',a,'return=minimal')};await audit(s,'SCAN_ANOMALIES',null,{found:alerts.length});return json({ok:true,found:alerts.length});
  }
  if(action==='create_admin'){
    if(s.role!=='owner')return json({error:'Owner role required'},403);const username=String(b.username||'').trim(),password=String(b.password||''),role=String(b.role||'analyst');if(!/^[A-Za-z0-9_.-]{3,32}$/.test(username)||password.length<10||!['owner','admin','moderator','analyst'].includes(role))return json({error:'Invalid admin account fields'},400);const {salt,hash}=hashPassword(password);await rest('admin_accounts?on_conflict=username','POST',{username,password_salt:salt,password_hash:hash,role,active:true,created_by:s.username},'resolution=merge-duplicates,return=minimal');await audit(s,'CREATE_ADMIN',null,{username,role});return json({ok:true});
  }
  if(action==='set_admin_status'){
    if(s.role!=='owner')return json({error:'Owner role required'},403);await rest(`admin_accounts?username=eq.${encodeURIComponent(b.username)}`,'PATCH',{active:!!b.active},'return=minimal');await audit(s,'SET_ADMIN_STATUS',null,{username:b.username,active:!!b.active});return json({ok:true});
  }
  return json({error:'Unknown action'},400);
 }catch(e){return json({error:e.message||'Admin action failed'},500)}
};
