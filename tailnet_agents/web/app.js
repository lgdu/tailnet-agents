'use strict';
let me = null, token = '', conversation = 'group', members = [], pending = null, busy = false;
let groups=[], activeGroup=null, creationKey=null;
let policyConfig={can_sign:false}, currentPolicy=null, policyPreview=null, policyPending=null;
let policyRefresh=0, policyDissolving=false;
let deliveryTargets=[], deliveryPreview=null, deliveryPending=null;
let credentialPreview=null, credentialPending=null, issuedCredential=null, credentialGeneration=0, credentialStates=new Map();
let runtimeRequest=0, runtimeLoading=false, runtimePage=null, runtimeReceived=0, runtimeRendered='', runtimeLatestNow=0;
let session = 0, view = 0, loading = false, history = new Map(), moreOlder = false;
const $ = id => document.getElementById(id);

function invalidateRuntime(clearTargets=false){
  runtimeRequest++;runtimePage=null;runtimeLoading=false;runtimeRendered='';runtimeLatestNow=0;
  if(clearTargets)$('runtime-target').replaceChildren();
  $('runtime-entries').replaceChildren();$('runtime-error').textContent='';
  $('runtime-status').textContent='尚未读取。只表示指定目录最近接受的授权 heartbeat，不证明执行器健康或全网可达。';
  runtimeControls();
}
function runtimeControls(){
  const disabled=!currentPolicy||!deliveryTargets.length||!policyConfig.can_sign||!!policyPending||policyDissolving||!!deliveryPending||!!credentialPending||runtimeLoading;
  $('runtime-refresh').disabled=disabled;
  $('runtime-next').disabled=disabled||!runtimePage?.has_more;
}
function renderRuntime(){
  if(!runtimePage)return;
  const now=runtimeLatestNow=Math.max(runtimeLatestNow,Date.now()/1000,runtimePage.checked_at+(performance.now()-runtimeReceived)/1000);
  const policy=runtimePage.policy, expired=policy.state==='fresh'&&now>=policy.expires_at;
  const stamp=JSON.stringify([expired,...runtimePage.entries.map(entry=>(entry.state==='online'||entry.state==='unconfirmed')&&(now>=entry.expires_at||expired)?'expired':entry.state)]);
  if(stamp===runtimeRendered)return;runtimeRendered=stamp;
  $('runtime-status').textContent=`来源 ${runtimePage.target.id} · ${runtimePage.target.url} · 读取于 ${new Date(runtimePage.checked_at*1000).toLocaleString()} · 目录观测于 ${new Date(runtimePage.observed_at*1000).toLocaleString()}。`+
    (policy.matches_local?'与本机策略一致。':'策略与本机不同，在线授权未确认；请核对并明确送达策略。')+
    ` 策略：${expired?'已到期':{fresh:'检查时有效',stale:'已到期',future:'时间在未来',dissolved:'已终止',missing:'尚未配置'}[policy.state]}。此页是单个目录的历史观测，不代表执行器健康或全网可达。`;
  $('runtime-entries').replaceChildren();
  if(!runtimePage.entries.length)$('runtime-entries').append(node('p','此目录暂无签名 runtime 观测；这不改变成员资格。'));
  for(const entry of runtimePage.entries){
    const state=(entry.state==='online'||entry.state==='unconfirmed')&&(now>=entry.expires_at||expired)?'expired':entry.state;
    const card=node('article',undefined,'runtime-entry');
    card.append(node('h4',entry.record.name),node('p',entry.subject,'runtime-subject'));
    card.append(node('p',{online:'目录曾观测在线（租约未到期）',offline:'已签名离线',expired:'租约已到期',unauthorized:'授权无效',unconfirmed:'在线授权未确认'}[state]||'状态未确认','runtime-state '+state));
    card.append(node('p',entry.record.endpoint),node('p',`运行代次 ${entry.generation} · heartbeat ${entry.sequence} · 观测于 ${new Date(entry.observed_at*1000).toLocaleString()} · 租约截止 ${new Date(entry.expires_at*1000).toLocaleString()}`));
    $('runtime-entries').append(card);
  }
}
async function fetchRuntime(after=''){
  if(!currentPolicy||!deliveryTargets.length||runtimeLoading||policyPending||policyDissolving||deliveryPending||credentialPending)return;
  const current=session,selected=activeGroup,target=$('runtime-target').value,refresh=policyRefresh;
  const started=performance.now();
  invalidateRuntime();const request=runtimeRequest;runtimeLoading=true;runtimeControls();
  $('runtime-status').textContent='正在读取所选目录；旧在线观测已清除…';
  try{
    const data=await api('/api/runtime-presence?'+new URLSearchParams({group_id:selected,target_id:target,after,limit:'20'}));
    if(current!==session||selected!==activeGroup||target!==$('runtime-target').value||request!==runtimeRequest||refresh!==policyRefresh||!$('manage-dialog').open)return;
    runtimePage=data;runtimeReceived=started;renderRuntime();
  }catch(error){
    if(current===session&&selected===activeGroup&&request===runtimeRequest){$('runtime-status').textContent='本次读取未确认；没有可显示的当前在线观测。';$('runtime-error').textContent=error.message;}
  }finally{if(request===runtimeRequest){runtimeLoading=false;runtimeControls();}}
}
$('runtime-target').onchange=()=>invalidateRuntime();
$('runtime-refresh').onclick=()=>fetchRuntime();
$('runtime-next').onclick=()=>{if(runtimePage?.has_more)fetchRuntime(runtimePage.next_after);};
setInterval(()=>{if(runtimePage&&$('manage-dialog').open)renderRuntime();},500);
function node(tag, text, className) { const n = document.createElement(tag); if(text !== undefined) n.textContent = text; if(className) n.className = className; return n; }
async function api(path, body) {
  if(path.startsWith('/api/messages?')||path.startsWith('/api/members'))path+=(path.includes('?')?'&':'?')+'group_id='+encodeURIComponent(activeGroup||'');
  if(body&&(path==='/api/messages'||path==='/api/presence'))body={...body,group_id:activeGroup};
  const credential = token, controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(path, {signal:controller.signal, method:body ? 'POST' : 'GET', headers:{'Authorization':'Bearer '+credential,'Content-Type':'application/json'}, ...(body ? {body:JSON.stringify(body)} : {})});
    const data = await response.json(); if(!response.ok){const error=new Error(data.error || '请求失败');error.status=response.status;throw error;} return data;
  } finally { clearTimeout(timeout); }
}
function renderMembers() {
  $('member-count').textContent = `${members.filter(m => m.online).length} / ${members.length} 模拟成员在线`;
  $('member-list').replaceChildren(); $('direct-list').replaceChildren();
  for(const m of (activeGroup?members:[])) {
    const nav = node('button', '@ '+m.name+(m.online?'':' · 离线'), 'nav'+(conversation==='dm:'+m.id?' active':'')); nav.onclick=()=>select('dm:'+m.id); if(me?.role!=='observer') $('direct-list').append(nav);
    const card=node('div',undefined,'member-card'), top=node('div',undefined,'member-top'); top.append(node('span',m.name[0],'avatar'));
    const info=node('div'); info.append(node('strong',m.name),node('small',m.online?'模拟 Echo · 在线':'模拟 Echo · 离线')); top.append(info,node('span',undefined,'presence'+(m.online?'':' offline')));
    const toggle=node('button',m.online?'模拟离线':'恢复在线');
    toggle.onclick=async()=>{const current=session; try {const result=await api('/api/presence',{agent:m.id,online:!m.online}); if(current!==session||!me)return; members=result.members; renderMembers();}catch(e){if(current===session)$('network-error').textContent=e.message;}};
    card.append(top); if(me?.role==='admin'&&!groups.find(g=>g.id===activeGroup)?.dissolved)card.append(toggle); $('member-list').append(card);
  }
}
function renderRecipients() {
  $('recipients').replaceChildren();
  if(conversation!=='group') {$('recipients').textContent='独立对话 · 仅目标模拟 Agent 回应';return;}
  $('recipients').append(node('span','点名回应：'));
  for(const m of members){const label=node('label'),input=node('input');input.type='checkbox';input.value=m.id;input.name='recipient';label.append(input,node('span',m.name));$('recipients').append(label);}
  $('recipients').append(node('span','未选择时由 Moderator 回应'));
}
function renderMessages(mode, forceBottom=false) {
  const container=$('messages'), oldHeight=container.scrollHeight, oldTop=container.scrollTop;
  const nearBottom=oldHeight-container.clientHeight-oldTop<80;
  container.replaceChildren();
  const messages=[...history.values()].sort((a,b)=>a.id-b.id);
  if(!messages.length)container.append(node('div','这里还没有消息。\n开始一段新的讨论。','empty'));
  for(const message of messages){
    const human=message.sender==='human',own=human&&message.author===me?.id;
    const label=human?(own?'你':message.author):(members.find(m=>m.id===message.sender)?.name||message.sender);
    const row=node('div',undefined,'chat-row'+(own?' human':''));row.append(node('span',human?'人':label[0],'avatar'));
    const content=node('div');content.append(node('div',`${label} · ${new Date(message.created*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}`,'message-meta'),node('div',message.text,'bubble'));row.append(content);container.append(row);
  }
  if(mode==='older')container.scrollTop=oldTop+(container.scrollHeight-oldHeight);
  else if(mode==='initial'||nearBottom||forceBottom)container.scrollTop=container.scrollHeight;
  else container.scrollTop=oldTop;
}
async function refreshMessages(mode='new',forceBottom=false) {
  if(loading||!me||!activeGroup)return;
  const current=view,currentSession=session,selected=conversation;
  loading=true;$('older').disabled=true;
  try {
    const ids=[...history.keys()];
    let path='/api/messages?conversation='+encodeURIComponent(selected)+'&limit=100';
    if(mode==='older'&&ids.length)path+='&before='+Math.min(...ids);
    if(mode==='new')path+='&after='+(ids.length?Math.max(...ids):0);
    const data=await api(path);
    if(current!==view||currentSession!==session||!me)return;
    let changed=false;for(const message of data.messages){if(!history.has(message.id))changed=true;history.set(message.id,message);}
    if(mode!=='new')moreOlder=data.has_more;
    $('older').hidden=!moreOlder;
    if(changed||mode==='initial')renderMessages(mode,forceBottom);
    $('sync-status').textContent=groups.find(g=>g.id===activeGroup)?.dissolved?'群组已解散 · 历史只读':(data.has_more&&mode==='new'?'正在追赶新消息…':'已同步 · 每 2 秒检查');
    $('network-error').textContent='';
  }catch(error){if(current===view&&currentSession===session){$('sync-status').textContent='连接中断，自动重试';$('network-error').textContent=error.message;}}
  finally{if(current===view&&currentSession===session){loading=false;$('older').disabled=false;}}
}
async function select(value) {
  if(busy||pending||policyPending||policyDissolving||deliveryPending||credentialPending){$('delivery-status').textContent='请先处理待确认消息或策略操作。';return;}
  if(!activeGroup)return;
  conversation=value;view++;loading=false;history=new Map();moreOlder=false;$('older').hidden=true;$('messages').replaceChildren();
  $('group-button').classList.toggle('active',value==='group');$('conversation-title').textContent=value==='group'?'群组讨论':members.find(m=>m.id===value.slice(3))?.name;
  $('conversation-kind').textContent=value==='group'?'GROUP CONVERSATION':'DIRECT CONVERSATION';$('message').value='';renderMembers();renderRecipients();await refreshMessages('initial');
}
function renderGroups(){
  $('group-select').replaceChildren();
  if(!groups.length){const option=node('option','暂无获准访问的群组');option.value='';$('group-select').append(option);}
  for(const group of groups){const option=node('option',group.name+(group.dissolved?' · 已解散':''));option.value=group.id;option.selected=group.id===activeGroup;$('group-select').append(option);}
  $('space-name').textContent=groups.find(g=>g.id===activeGroup)?.name||'尚未加入群组';
  $('create-group').hidden=me?.role!=='admin';
  const selected=groups.find(g=>g.id===activeGroup);
  $('compose').hidden=!activeGroup||!!selected?.dissolved||me?.role==='observer';
  $('manage-group').hidden=!selected||me?.role!=='admin'||selected.creator!==me.id;
  if(selected?.dissolved)$('sync-status').textContent='群组已解散 · 历史只读';
}
async function chooseGroup(id){
  if(busy||pending||policyPending||policyDissolving||deliveryPending||credentialPending){$('group-select').value=activeGroup||'';$('delivery-status').textContent='请先处理待确认消息或策略操作。';return;}
  invalidateRuntime(true);activeGroup=id;credentialPreview=null;issuedCredential=null;credentialGeneration++;credentialStates.clear();$('credential-result').textContent='';currentPolicy=null;policyPreview=null;deliveryTargets=[];deliveryPreview=null;view++;loading=false;history=new Map();members=[];moreOlder=false;$('older').hidden=true;$('messages').replaceChildren();renderGroups();
  if(!id){renderMembers();$('messages').append(node('div',me?.role==='admin'?'点击「创建群组」开始。Agent 不会自动创建。':'等待管理员将你加入一个群组。','empty'));$('sync-status').textContent='尚未加入群组';return;}
  const current=session,selected=id;
  try{const result=await api('/api/members');if(current!==session||selected!==activeGroup)return;members=result.members;await select('group');}
  catch(error){if(current===session)$('network-error').textContent=error.message;}
}
$('group-select').onchange=()=>chooseGroup($('group-select').value);
$('create-group').onclick=async()=>{
  const current=session;creationKey=crypto.randomUUID();$('signed-policy').checked=false;$('signed-choice').hidden=!policyConfig.can_sign;$('group-error').textContent='';$('human-choices').replaceChildren();
  try{const result=await api('/api/humans');if(current!==session)return;for(const human of result.humans){if(human.id===me.id)continue;const label=node('label'),check=node('input');check.type='checkbox';check.name='group-human';check.value=human.id;label.append(check,node('span',human.id+' · '+human.role));$('human-choices').append(label);}$('group-dialog').showModal();}
  catch(error){if(current===session)$('network-error').textContent=error.message;}
};
$('cancel-group').onclick=()=>$('group-dialog').close();
$('group-form').onsubmit=async e=>{
  e.preventDefault();const current=session,button=$('group-form').querySelector('button[type="submit"]');button.disabled=true;
  try{const created=await api('/api/groups',{name:$('group-name').value,humans:[...document.querySelectorAll('input[name="group-human"]:checked')].map(i=>i.value),request_id:creationKey,signed_policy:$('signed-policy').checked});if(current!==session)return;groups=(await api('/api/groups')).groups;if(current!==session)return;$('group-dialog').close();$('group-name').value='';await chooseGroup(created.id);}
  catch(error){if(current===session)$('group-error').textContent=error.message;}
  finally{button.disabled=false;}
};
$('login-form').onsubmit=async e=>{
  e.preventDefault();const current=++session;view++;token=$('token').value;$('login-error').textContent='';
  try{const identity=await api('/api/me');if(current!==session)return;policyConfig=await api('/api/policy-config');if(current!==session)return;const result=await api('/api/groups');if(current!==session)return;
    me=identity;groups=result.groups;conversation='group';history=new Map();loading=false;
    $('human-name').textContent=me.id;$('human-role').textContent={admin:'管理员',participant:'参与者',observer:'观察者'}[me.role];$('login').hidden=true;$('workspace').hidden=false;$('token').value='';await chooseGroup(groups[0]?.id||null);
  }catch(error){if(current!==session)return;token='';me=null;$('workspace').hidden=true;$('login').hidden=false;$('login-error').textContent=error.message;}
};
$('logout').onclick=()=>{invalidateRuntime(true);session++;view++;policyRefresh++;activeGroup=null;groups=[];$('group-dialog').close();$('manage-dialog').close();token='';me=null;pending=null;currentPolicy=null;policyPreview=null;policyPending=null;policyDissolving=false;deliveryTargets=[];deliveryPreview=null;deliveryPending=null;credentialPending=null;credentialPreview=null;issuedCredential=null;credentialGeneration++;credentialStates.clear();$('credential-public-key').value='';$('credential-result').textContent='';$('credential-consent').textContent='';$('credential-history').replaceChildren();$('policy-grant').value='';busy=false;loading=false;history=new Map();conversation='group';$('workspace').hidden=true;$('login').hidden=false;$('message').value='';$('message').disabled=false;$('send-button').disabled=false;$('send-button').textContent='发送 ↑';$('messages').replaceChildren();$('group-button').classList.add('active');$('conversation-title').textContent='群组讨论';$('conversation-kind').textContent='GROUP CONVERSATION';};
$('group-button').onclick=()=>select('group');$('older').onclick=()=>refreshMessages('older');
$('compose').onsubmit=async e=>{
  e.preventDefault();if(busy||!me||!activeGroup||me.role==='observer')return;if(!pending&&!$('message').value.trim())return;
  if(!pending)pending={conversation,text:$('message').value,targets:[...document.querySelectorAll('input[name="recipient"]:checked')].map(i=>i.value),request_id:crypto.randomUUID()};
  const current=session;busy=true;$('send-button').disabled=true;$('message').disabled=true;$('delivery-status').textContent='发送中…';
  try{const result=await api('/api/messages',pending);if(current!==session)return;pending=null;$('message').value='';$('delivery-status').textContent=result.offline_targets.length?'已保存；离线接收者未回应：'+result.offline_targets.join(', '):'已保存 · 模拟回应已生成';await refreshMessages('new',true);}
  catch(error){if(current===session)$('delivery-status').textContent='结果未确认，点击发送重试同一消息：'+error.message;}
  finally{if(current===session){busy=false;$('send-button').disabled=false;$('message').disabled=!!pending;$('send-button').textContent=pending?'重试 ↑':'发送 ↑';}}
};
$('message').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();$('compose').requestSubmit();}};
let polling=false;
setInterval(async()=>{
  if(!me||document.hidden||polling)return;
  polling=true;const current=session;
  try{
    const discovered=await api('/api/groups');if(current!==session||!me)return;
    if(JSON.stringify(discovered.groups)!==JSON.stringify(groups)){groups=discovered.groups;if(activeGroup&&!groups.some(g=>g.id===activeGroup)){pending=null;busy=false;await chooseGroup(null);$('network-error').textContent='群组访问资格已撤销。';}renderGroups();if(!activeGroup&&groups.length)await chooseGroup(groups[0].id);}
    if(!activeGroup)return;await refreshMessages();if(current!==session||!me)return;
    const selected=activeGroup;const result=await api('/api/members');if(current!==session||!me||selected!==activeGroup)return;
    if(JSON.stringify(result.members)!==JSON.stringify(members)){members=result.members;renderMembers();}
  }catch(error){if(current===session)$('network-error').textContent=error.message;}
  finally{polling=false;}
},2000);

async function refreshManagement(){
  invalidateRuntime(true);
  const current=session,selected=activeGroup,refresh=++policyRefresh;
  currentPolicy=null;policyPreview=null;deliveryPreview=null;credentialPreview=null;credentialGeneration++;credentialStates.clear();$('credential-consent').textContent='';policyControls();
  $('policy-error').classList.remove('success');
  if(!policyPending&&!policyDissolving)$('policy-error').textContent='正在读取最新策略，下载暂不可用…';
  const info=await api('/api/group-info?group_id='+encodeURIComponent(selected));
  const people=await api('/api/humans');if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return false;
  $('human-members').replaceChildren();$('add-human').replaceChildren();
  for(const id of info.humans){const row=node('div');row.append(node('span',id+(id===info.creator?' · 创建者':'')));
    if(id!==info.creator&&!info.dissolved){const remove=node('button','撤销访问');remove.type='button';remove.onclick=async()=>{try{await api('/api/group-members',{group_id:selected,subject:id,operation:'remove'});if(current===session&&selected===activeGroup)await refreshManagement();}catch(error){if(current===session)$('manage-error').textContent=error.message;}};row.append(remove);}$('human-members').append(row);}
  for(const human of people.humans){if(info.humans.includes(human.id))continue;const option=node('option',human.id+' · '+human.role);option.value=human.id;$('add-human').append(option);}
  await refreshPolicy(current,selected,refresh);
  await refreshDelivery(current,selected,refresh);
  await refreshCredentials(current,selected,refresh);
  if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return false;
  $('add-member').disabled=info.dissolved||!$('add-human').options.length;
  if(!policyPending&&!policyDissolving){
    $('policy-error').classList.toggle('success',!!currentPolicy);
    $('policy-error').textContent=currentPolicy?'已读取当前签名策略，可下载并明确应用到目录。':'';
  }
  policyControls();
  if(info.dissolved)$('manage-error').textContent='已解散：历史保留，不能重新开放这个群组。';
  return true;
}
$('manage-group').onclick=async()=>{try{$('manage-error').textContent='';$('dissolve-name').value='';await refreshManagement();if(me)$('manage-dialog').showModal();}catch(error){$('network-error').textContent=error.message;}};
$('close-manage').onclick=()=>$('manage-dialog').close();
$('manage-dialog').onclose=()=>invalidateRuntime();
$('add-member').onclick=async()=>{const current=session;try{await api('/api/group-members',{group_id:activeGroup,subject:$('add-human').value,operation:'add'});if(current===session)await refreshManagement();}catch(error){if(current===session)$('manage-error').textContent=error.message;}};
$('dissolve-group').onclick=async()=>{
  if(policyPending||policyDissolving||deliveryPending||credentialPending)return;
  const current=session,selected=activeGroup;
  policyDissolving=true;currentPolicy=null;policyPreview=null;policyControls();
  $('policy-error').classList.remove('success');$('policy-error').textContent='正在解散并读取最新状态…';
  try{
    await api('/api/group-dissolve',{group_id:selected,confirm_name:$('dissolve-name').value});
    if(current!==session||selected!==activeGroup)return;
    groups=(await api('/api/groups')).groups;if(current!==session||selected!==activeGroup)return;
    renderGroups();renderMembers();
    if(!await refreshManagement())throw new Error('群组状态尚未读取，请重新打开管理页面。');
    $('policy-error').classList.toggle('success',!!currentPolicy);
    $('policy-error').textContent=currentPolicy?'已读取最新终止策略。请下载并明确应用到目录。':'';
  }catch(error){
    if(current===session&&selected===activeGroup){currentPolicy=null;$('manage-error').textContent=error.message;}
  }finally{
    if(current===session&&selected===activeGroup){policyDissolving=false;policyControls();}
  }
};

function policyControls(){
  const disabled=!!policyPending||policyDissolving||!!deliveryPending||!!credentialPending||!currentPolicy||currentPolicy.claims.state==='dissolved';
  document.querySelectorAll('.policy-action').forEach(button=>button.disabled=disabled);
  $('policy-approve').disabled=disabled||!policyPreview;
  $('policy-retry').hidden=!policyPending;
  $('policy-grant').disabled=disabled;
  $('policy-export').disabled=!!policyPending||policyDissolving||!!deliveryPending||!!credentialPending||!currentPolicy;
  $('dissolve-group').disabled=!!policyPending||policyDissolving||!!deliveryPending||!!credentialPending||!!groups.find(g=>g.id===activeGroup)?.dissolved;
  deliveryControls();
  credentialControls();
  if((!currentPolicy||policyPending||policyDissolving||deliveryPending||credentialPending)&&(runtimePage||runtimeLoading))invalidateRuntime();
  runtimeControls();
}
async function refreshPolicy(current,selected,refresh){
  $('policy-panel').hidden=!policyConfig.can_sign;
  if(!policyConfig.can_sign)return;
  try{
    const result=await api('/api/group-policy?group_id='+encodeURIComponent(selected));
    if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return;
    currentPolicy=result;policyPreview=null;$('policy-preview-result').textContent='';
    $('policy-status').textContent=`群组 ${result.group_id} · 第 ${result.claims.revision} 版 · ${result.claims.state==='dissolved'?'已签名终止':'签发于 '+new Date(result.claims.issued_at*1000).toLocaleString()}。下载后须明确应用到目录；此页面不自动推送或续期。`;
    $('policy-owner').textContent='所有者公钥（用于核对目录信任配置）：'+result.owner_public_key;
    $('policy-members').replaceChildren();$('policy-audit').replaceChildren();
    for(const [subject,member] of Object.entries(result.claims.members)){
      const row=node('div');row.append(node('p',subject+' · '+member.permissions.join(', ')));
      const remove=node('button','从签名策略中移除此身份');remove.type='button';remove.className='policy-action';
      remove.onclick=()=>{if(window.confirm('确认移除 '+subject+'？当前凭证不能在本 UI 重新批准。'))runPolicyAction('/api/policy-remove',{subject});};
      row.append(remove);$('policy-members').append(row);
    }
    if(!Object.keys(result.claims.members).length)$('policy-members').append(node('p','没有获准的网络 Agent。聊天中的 Echo 参与者不会自动获得权限。'));
    for(const event of result.audit)$('policy-audit').append(node('li',`第 ${event.revision} 版 · ${event.actor} · ${event.action} · ${event.subject}`));
  }catch(error){
    if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return;
    if(error.status!==400)throw error;
    currentPolicy=null;policyPreview=null;$('policy-status').textContent='此群组仅用于本地聊天，没有签名网络策略。可明确创建一个新的签名群组。';
    $('policy-owner').textContent='';$('policy-members').replaceChildren();$('policy-audit').replaceChildren();
  }
  policyControls();
}
async function runPolicyAction(path,payload={}){
  if(policyPending||policyDissolving||deliveryPending||credentialPending||!currentPolicy)return;
  policyPending={path,body:{group_id:activeGroup,expected_revision:currentPolicy.claims.revision,...payload,request_id:crypto.randomUUID()}};
  await retryPolicyAction();
}
async function retryPolicyAction(){
  if(!policyPending)return;
  const current=session,selected=activeGroup,operation=policyPending;
  currentPolicy=null;policyPreview=null;
  policyControls();$('policy-retry').disabled=true;$('policy-error').classList.remove('success');$('policy-error').textContent='正在提交明确授权的操作…';
  try{
    if(!operation.ack)operation.ack=await api(operation.path,operation.body);
    if(current!==session||selected!==activeGroup)return;
    $('policy-grant').value='';$('policy-error').textContent='签名已保存，正在读取最新策略；下载暂不可用…';
    if(!await refreshManagement()||!currentPolicy||currentPolicy.group_id!==selected||currentPolicy.claims.revision<operation.ack.revision){
      throw new Error('尚未读取到已签名的策略版本。');
    }
    policyPending=null;
    $('policy-error').classList.add('success');$('policy-error').textContent='已读取最新签名策略。请下载并明确应用到目录。';
  }catch(error){
    if(current!==session||selected!==activeGroup)return;
    $('policy-error').classList.remove('success');
    currentPolicy=null;
    if(!operation.ack&&error.status>=400&&error.status<500)policyPending=null;
    $('policy-error').textContent=operation.ack?'签名已保存，但最新策略读取失败；请重试读取，下载保持禁用。'+error.message:policyPending?'结果未确认：请重试同一操作，暂不切换群组。'+error.message:'操作未完成，请刷新管理信息后重新确认：'+error.message;
  }finally{if(current===session&&selected===activeGroup){$('policy-retry').disabled=false;policyControls();}}
}
$('policy-retry').onclick=retryPolicyAction;
$('policy-renew').onclick=()=>runPolicyAction('/api/policy-renew');
$('policy-grant').oninput=()=>{policyPreview=null;$('policy-preview-result').textContent='';policyControls();};
$('policy-preview').onclick=async()=>{
  const current=session,selected=activeGroup,grant=$('policy-grant').value.trim();
  policyPreview=null;$('policy-error').classList.remove('success');policyControls();
  try{
    const result=await api('/api/policy-preview',{group_id:selected,grant});
    if(current!==session||selected!==activeGroup||grant!==$('policy-grant').value.trim())return;
    policyPreview={grant,revision:result.revision};
    $('policy-preview-result').textContent=`将批准 ${result.subject}；本凭证权限：${result.permissions.join(', ')}；凭证到期：${new Date(result.expires_at*1000).toLocaleString()}；合并后该身份权限：${result.proposed_member.permissions.join(', ')}。当前策略第 ${result.revision} 版。`;
    $('policy-error').textContent='请核对身份和完整权限，再点击确认批准。';
  }catch(error){if(current===session&&selected===activeGroup)$('policy-error').textContent=error.message;}
  finally{if(current===session&&selected===activeGroup)policyControls();}
};
$('policy-approve').onclick=()=>{if(policyPreview)runPolicyAction('/api/policy-approve',{grant:policyPreview.grant,expected_revision:policyPreview.revision});};
$('policy-export').onclick=()=>{
  if(policyPending||policyDissolving||deliveryPending||credentialPending||!currentPolicy||currentPolicy.group_id!==activeGroup)return;
  const url=URL.createObjectURL(new Blob([currentPolicy.policy+'\n'],{type:'text/plain'}));
  const link=node('a');link.href=url;link.download=currentPolicy.group_id+'.policy';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};

function deliveryControls(){
  const disabled=!!policyPending||policyDissolving||!!deliveryPending||!!credentialPending||!currentPolicy;
  $('policy-target').disabled=disabled;
  $('delivery-preview').disabled=disabled||!deliveryTargets.some(target=>target.id===$('policy-target').value);
  $('delivery-confirm').disabled=disabled||!deliveryPreview||deliveryPreview.policy_hash!==currentPolicy?.policy_hash;
  $('delivery-retry').hidden=!deliveryPending;
}
function deliveryState(receipt){
  if(receipt.authorization_state==='fresh'&&Date.now()/1000>=receipt.expires_at)return '该次检查有效，当前已到期';
  return {fresh:'该次检查有效',stale:'已过期，不能准入',future:'时间在未来，不能准入',dissolved:'终止策略'}[receipt.authorization_state];
}
async function refreshDelivery(current,selected,refresh){
  if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return;
  deliveryPreview=null;deliveryTargets=[];$('delivery-consent').textContent='';
  $('policy-target').replaceChildren();$('delivery-records').replaceChildren();
  if(!currentPolicy){deliveryControls();return;}
  try{
    const [targets,history]=await Promise.all([api('/api/policy-targets?group_id='+encodeURIComponent(selected)),api('/api/policy-deliveries?group_id='+encodeURIComponent(selected))]);
    if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return;
    deliveryTargets=targets.targets;
    $('runtime-target').replaceChildren();
    for(const target of deliveryTargets){const option=node('option',target.id+' · '+target.url);option.value=target.id;$('runtime-target').append(option);}
    runtimeControls();
    for(const target of deliveryTargets){const option=node('option',target.id+' · '+target.url);option.value=target.id;$('policy-target').append(option);}
    if(!deliveryTargets.length)$('delivery-consent').textContent='此群组尚未配置接收方，请由本机管理员设置。';
    for(const entry of history.deliveries){
      const status={acknowledged:'已确认（历史记录）',pending:'尚未确认',unknown:'结果未知',conflict:'存在冲突'}[entry.outcome]||entry.outcome;
      $('delivery-records').append(node('li',`${entry.target.url} · 第 ${entry.revision} 版 · ${status} · ${new Date(entry.updated*1000).toLocaleString()}`+
        (entry.receipt?' · '+deliveryState(entry.receipt)+' · 期限 '+new Date(entry.receipt.expires_at*1000).toLocaleString():'')));
    }
  }catch(error){if(current===session&&selected===activeGroup&&refresh===policyRefresh)$('delivery-error').textContent=error.message;}
  deliveryControls();
}
$('policy-target').onchange=()=>{deliveryPreview=null;$('delivery-consent').textContent='';deliveryControls();};
$('delivery-preview').onclick=async()=>{
  if(!currentPolicy||deliveryPending||credentialPending||policyPending||policyDissolving)return;
  const current=session,selected=activeGroup,target=$('policy-target').value;
  deliveryPreview=null;deliveryControls();
  try{
    const preview=await api('/api/policy-delivery-preview',{group_id:selected,target_id:target,expected_revision:currentPolicy.claims.revision,policy_hash:currentPolicy.policy_hash});
    if(current!==session||selected!==activeGroup||target!==$('policy-target').value)return;
    if(!currentPolicy||preview.policy_hash!==currentPolicy.policy_hash)throw new Error('本地策略已变化，请重新读取并预览。');
    deliveryPreview=preview;
    $('delivery-consent').textContent=`将送达 ${preview.target.url}；群组 ${preview.group_id}；所有者 ${preview.owner}；第 ${preview.revision} 版（${preview.state}）；快照 ${preview.policy_hash}。请核对后确认。`;
    $('delivery-error').textContent='预览未联系远端。确认后才发送此快照与接收方专用读凭据。';
  }catch(error){if(current===session&&selected===activeGroup)$('delivery-error').textContent=error.message;}
  finally{if(current===session&&selected===activeGroup)deliveryControls();}
};
$('delivery-confirm').onclick=async()=>{
  if(!deliveryPreview||deliveryPending||credentialPending||policyPending||policyDissolving||!currentPolicy||deliveryPreview.policy_hash!==currentPolicy.policy_hash)return;
  deliveryPending={body:{group_id:activeGroup,target_id:deliveryPreview.target.id,target_fingerprint:deliveryPreview.target.fingerprint,
    expected_revision:deliveryPreview.revision,policy_hash:deliveryPreview.policy_hash,request_id:crypto.randomUUID()}};
  await retryDelivery();
};
async function retryDelivery(){
  if(!deliveryPending)return;
  const current=session,selected=activeGroup,operation=deliveryPending;
  policyControls();$('delivery-retry').disabled=true;$('delivery-error').textContent='正在送达并核对签名副本与时效…';
  try{
    if(!operation.ack)operation.ack=await api('/api/policy-deliver',operation.body);
    if(current!==session||selected!==activeGroup)return;
    if(!await refreshManagement())throw new Error('本地页面尚未刷新。');
    deliveryPending=null;
    const receipt=operation.ack;
    $('delivery-error').textContent=`于 ${new Date(receipt.checked_at*1000).toLocaleString()} 确认 ${receipt.target.url} 接收第 ${receipt.revision} 版：${deliveryState(receipt)}；接收方时效上限 ${receipt.max_age} 秒，策略期限 ${new Date(receipt.expires_at*1000).toLocaleString()}。这是历史确认，未注册 Agent。`+
      (currentPolicy?.policy_hash!==receipt.policy_hash?' 本地版本已变化，需重新预览送达。':'');
  }catch(error){
    if(current!==session||selected!==activeGroup)return;
    if(error.status>=400&&error.status<500){deliveryPending=null;currentPolicy=null;}
    $('delivery-error').textContent=operation.ack?'接收已确认，但页面刷新失败；重试只重新读取本页状态。'+error.message:
      deliveryPending?'送达未确认，请重试同一请求；接收方可能已保存。'+error.message:error.message;
  }finally{if(current===session&&selected===activeGroup){$('delivery-retry').disabled=false;policyControls();}}
}
$('delivery-retry').onclick=retryDelivery;

function credentialFields(){
  return {public_key:$('credential-public-key').value.trim(),permissions:[...document.querySelectorAll('#credential-permissions input:checked')].map(input=>input.value).sort(),lifetime:Number($('credential-lifetime').value)};
}
function credentialControls(){
  const busy=!!policyPending||policyDissolving||!!deliveryPending||!!credentialPending;
  const active=!!currentPolicy&&currentPolicy.claims.state==='active';
  $('credential-preview').disabled=busy||!active;
  $('credential-public-key').disabled=busy||!active;$('credential-lifetime').disabled=busy||!active;
  document.querySelectorAll('#credential-permissions input').forEach(input=>input.disabled=busy||!active||input.value==='join');
  $('credential-confirm').disabled=busy||!active||!credentialPreview||Date.now()/1000>=credentialPreview.preview_expires_at||credentialPreview.policy_hash!==currentPolicy?.policy_hash;
  $('credential-retry').hidden=!credentialPending;
  const available=!busy&&active&&issuedCredential?.claims.group_id===activeGroup&&credentialStates.get(issuedCredential.claims.jti)==='valid'&&issuedCredential.claims.nbf<=Date.now()/1000&&Date.now()/1000<issuedCredential.claims.exp;
  $('credential-download').disabled=!available;$('credential-use').disabled=!available;
  document.querySelectorAll('.credential-recover').forEach(button=>button.disabled=busy||!active||button.dataset.state!=='valid');
}
function invalidateCredential(){
  credentialGeneration++;credentialPreview=null;issuedCredential=null;
  $('credential-consent').textContent='';$('credential-result').textContent='';credentialControls();
}
$('credential-public-key').oninput=invalidateCredential;
$('credential-lifetime').oninput=invalidateCredential;
$('credential-permissions').onchange=invalidateCredential;
$('credential-preview').onclick=async()=>{
  if(!currentPolicy||credentialPending||policyPending||deliveryPending||policyDissolving)return;
  const current=session,selected=activeGroup,generation=++credentialGeneration,fields=credentialFields();
  credentialPreview=null;issuedCredential=null;$('credential-result').textContent='';credentialControls();
  try{
    const preview=await api('/api/credential-preview',{group_id:selected,...fields,expected_revision:currentPolicy.claims.revision,policy_hash:currentPolicy.policy_hash});
    if(current!==session||selected!==activeGroup||generation!==credentialGeneration)return;
    if(!currentPolicy||preview.policy_hash!==currentPolicy.policy_hash)throw new Error('策略已变化，请刷新并重新预览。');
    credentialPreview=preview;
    $('credential-consent').textContent=`仅签发给 ${preview.subject}；群组 ${preview.group_id}；所有者 ${preview.owner}；权限 ${preview.permissions.join(', ')}；固定期限 ${new Date(preview.issued_at*1000).toLocaleString()} 至 ${new Date(preview.expires_at*1000).toLocaleString()}；预览有效至 ${new Date(preview.preview_expires_at*1000).toLocaleTimeString()}；策略第 ${preview.expected_revision} 版。`;
    $('credential-error').textContent='预览未签发。请核对 Agent 公钥指纹与完整权限；确认后仍需另行批准成员。';
  }catch(error){if(current===session&&selected===activeGroup&&generation===credentialGeneration)$('credential-error').textContent=error.message;}
  finally{if(current===session&&selected===activeGroup)credentialControls();}
};
$('credential-confirm').onclick=async()=>{
  if(!credentialPreview||credentialPending||policyPending||deliveryPending||policyDissolving||!currentPolicy||credentialPreview.policy_hash!==currentPolicy.policy_hash||Date.now()/1000>=credentialPreview.preview_expires_at)return;
  const preview=credentialPreview;
  credentialPending={body:{group_id:activeGroup,public_key:preview.public_key,permissions:preview.permissions,lifetime:preview.lifetime,
    expected_revision:preview.expected_revision,policy_hash:preview.policy_hash,issued_at:preview.issued_at,consent_hash:preview.consent_hash,request_id:crypto.randomUUID()}};
  await retryCredential();
};
async function retryCredential(){
  if(!credentialPending)return;
  const current=session,selected=activeGroup,operation=credentialPending;
  policyControls();$('credential-retry').disabled=true;$('credential-error').textContent='正在签发或取回此请求的原凭证…';
  try{
    if(!operation.ack)operation.ack=await api('/api/credential-issue',operation.body);
    if(current!==session||selected!==activeGroup)return;
    if(!await refreshManagement())throw new Error('本地页面尚未刷新。');
    credentialPending=null;issuedCredential=operation.ack;
    const claims=issuedCredential.claims;
    $('credential-result').textContent=`已签发 ${claims.sub}；凭证 ${claims.jti}；权限 ${claims.permissions.join(', ')}；到期 ${new Date(claims.exp*1000).toLocaleString()}。`;
    $('credential-error').textContent='成员策略未改变。请下载并校验安装，或另行预览、确认成员审批。重试不会延长期限。';
  }catch(error){
    if(current!==session||selected!==activeGroup)return;
    if(error.status>=400&&error.status<500){credentialPending=null;credentialPreview=null;}
    $('credential-error').textContent=operation.ack?'签发已确认，但页面读取失败；重试只读取本地页面。'+error.message:
      credentialPending?'结果未知，请重试同一签发；不会生成另一份凭证。'+error.message:error.message;
  }finally{if(current===session&&selected===activeGroup){$('credential-retry').disabled=false;policyControls();}}
}
$('credential-retry').onclick=retryCredential;
async function refreshCredentials(current,selected,refresh){
  if(!currentPolicy||current!==session||selected!==activeGroup||refresh!==policyRefresh)return;
  const history=await api('/api/credential-issuances?group_id='+encodeURIComponent(selected));
  if(current!==session||selected!==activeGroup||refresh!==policyRefresh)return;
  $('credential-history').replaceChildren();credentialStates=new Map(history.issuances.map(entry=>[entry.claims.jti,entry.state]));
  for(const entry of history.issuances){
    const state={valid:'签发时效有效（不代表已获准入群）',expired:'已到期',future:'尚未生效',retired:'移除时已停用'}[entry.state];
    const row=node('li',`${entry.claims.sub} · ${entry.claims.jti} · ${entry.claims.permissions.join(', ')} · ${state} · 到期 ${new Date(entry.claims.exp*1000).toLocaleString()}`);
    const recover=node('button','明确取回这份原凭证');recover.type='button';recover.className='credential-recover';recover.dataset.state=entry.state;
    recover.onclick=async()=>{if(credentialPending||policyPending||deliveryPending||policyDissolving||!currentPolicy||currentPolicy.claims.state!=='active'||entry.state!=='valid')return;credentialPending={body:{group_id:selected,...entry.request}};await retryCredential();};
    row.append(recover);$('credential-history').append(row);
    if(issuedCredential?.claims.jti===entry.claims.jti&&entry.state!=='valid')issuedCredential=null;
  }
  credentialControls();
}
$('credential-download').onclick=()=>{
  credentialControls();if($('credential-download').disabled)return;
  const url=URL.createObjectURL(new Blob([issuedCredential.grant+'\n'],{type:'text/plain'}));
  const link=node('a');link.href=url;link.download=issuedCredential.claims.sub.split(':')[1].slice(0,16)+'-'+issuedCredential.claims.jti+'.grant';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};
$('credential-use').onclick=()=>{
  credentialControls();if($('credential-use').disabled)return;
  $('policy-grant').value=issuedCredential.grant;policyPreview=null;$('policy-preview').click();
};
setInterval(credentialControls,1000);
