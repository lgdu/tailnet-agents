'use strict';
let me = null, token = '', conversation = 'group', members = [], pending = null, busy = false;
let groups=[], activeGroup=null, creationKey=null;
let policyConfig={can_sign:false}, currentPolicy=null, policyPreview=null, policyPending=null;
let session = 0, view = 0, loading = false, history = new Map(), moreOlder = false;
const $ = id => document.getElementById(id);
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
  if(busy||pending||policyPending){$('delivery-status').textContent='请先重试待确认消息，或退出连接后重新进入。';return;}
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
  if(busy||pending||policyPending){$('group-select').value=activeGroup||'';$('delivery-status').textContent='请先处理待确认消息。';return;}
  activeGroup=id;currentPolicy=null;policyPreview=null;view++;loading=false;history=new Map();members=[];moreOlder=false;$('older').hidden=true;$('messages').replaceChildren();renderGroups();
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
$('logout').onclick=()=>{session++;view++;activeGroup=null;groups=[];$('group-dialog').close();$('manage-dialog').close();token='';me=null;pending=null;currentPolicy=null;policyPreview=null;policyPending=null;$('policy-grant').value='';busy=false;loading=false;history=new Map();conversation='group';$('workspace').hidden=true;$('login').hidden=false;$('message').value='';$('message').disabled=false;$('send-button').disabled=false;$('send-button').textContent='发送 ↑';$('messages').replaceChildren();$('group-button').classList.add('active');$('conversation-title').textContent='群组讨论';$('conversation-kind').textContent='GROUP CONVERSATION';};
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
  const current=session,selected=activeGroup;
  const info=await api('/api/group-info?group_id='+encodeURIComponent(selected));
  const people=await api('/api/humans');if(current!==session||selected!==activeGroup)return;
  $('human-members').replaceChildren();$('add-human').replaceChildren();
  for(const id of info.humans){const row=node('div');row.append(node('span',id+(id===info.creator?' · 创建者':'')));
    if(id!==info.creator&&!info.dissolved){const remove=node('button','撤销访问');remove.type='button';remove.onclick=async()=>{try{await api('/api/group-members',{group_id:selected,subject:id,operation:'remove'});if(current===session&&selected===activeGroup)await refreshManagement();}catch(error){if(current===session)$('manage-error').textContent=error.message;}};row.append(remove);}$('human-members').append(row);}
  for(const human of people.humans){if(info.humans.includes(human.id))continue;const option=node('option',human.id+' · '+human.role);option.value=human.id;$('add-human').append(option);}
  await refreshPolicy(current,selected);
  $('add-member').disabled=info.dissolved||!$('add-human').options.length;$('dissolve-group').disabled=info.dissolved||!!policyPending;
  if(info.dissolved)$('manage-error').textContent='已解散：历史保留，不能重新开放这个群组。';
}
$('manage-group').onclick=async()=>{try{$('manage-error').textContent='';$('dissolve-name').value='';await refreshManagement();if(me)$('manage-dialog').showModal();}catch(error){$('network-error').textContent=error.message;}};
$('close-manage').onclick=()=>$('manage-dialog').close();
$('add-member').onclick=async()=>{const current=session;try{await api('/api/group-members',{group_id:activeGroup,subject:$('add-human').value,operation:'add'});if(current===session)await refreshManagement();}catch(error){if(current===session)$('manage-error').textContent=error.message;}};
$('dissolve-group').onclick=async()=>{if(policyPending)return;const current=session;try{await api('/api/group-dissolve',{group_id:activeGroup,confirm_name:$('dissolve-name').value});if(current!==session)return;groups=(await api('/api/groups')).groups;if(current!==session)return;renderGroups();renderMembers();await refreshManagement();}catch(error){if(current===session)$('manage-error').textContent=error.message;}};

function policyControls(){
  const disabled=!!policyPending||!currentPolicy||currentPolicy.claims.state==='dissolved';
  document.querySelectorAll('.policy-action').forEach(button=>button.disabled=disabled);
  $('policy-approve').disabled=disabled||!policyPreview;
  $('policy-retry').hidden=!policyPending;
  $('policy-grant').disabled=disabled;
  $('dissolve-group').disabled=!!policyPending||!!groups.find(g=>g.id===activeGroup)?.dissolved;
}
async function refreshPolicy(current,selected){
  $('policy-panel').hidden=!policyConfig.can_sign;
  if(!policyConfig.can_sign)return;
  try{
    const result=await api('/api/group-policy?group_id='+encodeURIComponent(selected));
    if(current!==session||selected!==activeGroup)return;
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
    if(current!==session||selected!==activeGroup)return;
    if(error.status!==400)throw error;
    currentPolicy=null;policyPreview=null;$('policy-status').textContent='此群组仅用于本地聊天，没有签名网络策略。可明确创建一个新的签名群组。';
    $('policy-owner').textContent='';$('policy-members').replaceChildren();$('policy-audit').replaceChildren();
  }
  $('policy-export').disabled=!currentPolicy;policyControls();
}
async function runPolicyAction(path,payload={}){
  if(policyPending||!currentPolicy)return;
  policyPending={path,body:{group_id:activeGroup,expected_revision:currentPolicy.claims.revision,...payload,request_id:crypto.randomUUID()}};
  await retryPolicyAction();
}
async function retryPolicyAction(){
  if(!policyPending)return;
  const current=session,selected=activeGroup,operation=policyPending;
  policyControls();$('policy-retry').disabled=true;$('policy-error').classList.remove('success');$('policy-error').textContent='正在提交明确授权的操作…';
  try{
    await api(operation.path,operation.body);
    if(current!==session||selected!==activeGroup)return;
    policyPending=null;policyPreview=null;$('policy-grant').value='';
    $('policy-error').classList.add('success');$('policy-error').textContent='已保存并签名。请下载当前策略，并明确应用到目录。';
    await refreshManagement();
  }catch(error){
    if(current!==session||selected!==activeGroup)return;
    $('policy-error').classList.remove('success');
    if(error.status>=400&&error.status<500){policyPending=null;policyPreview=null;}
    $('policy-error').textContent=policyPending?'结果未确认：请重试同一操作，暂不切换群组。'+error.message:'操作未完成，请刷新管理信息后重新确认：'+error.message;
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
  if(!currentPolicy)return;
  const url=URL.createObjectURL(new Blob([currentPolicy.policy+'\n'],{type:'text/plain'}));
  const link=node('a');link.href=url;link.download=currentPolicy.group_id+'.policy';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};
