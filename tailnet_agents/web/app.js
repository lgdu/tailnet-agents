'use strict';
let me = null, token = '', conversation = 'group', members = [], pending = null, busy = false;
let groups=[], activeGroup=null;
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
    const data = await response.json(); if(!response.ok) throw new Error(data.error || '请求失败'); return data;
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
    card.append(top); if(me?.role==='admin')card.append(toggle); $('member-list').append(card);
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
    $('sync-status').textContent=data.has_more&&mode==='new'?'正在追赶新消息…':'已同步 · 每 2 秒检查';
    $('network-error').textContent='';
  }catch(error){if(current===view&&currentSession===session){$('sync-status').textContent='连接中断，自动重试';$('network-error').textContent=error.message;}}
  finally{if(current===view&&currentSession===session){loading=false;$('older').disabled=false;}}
}
async function select(value) {
  if(busy||pending){$('delivery-status').textContent='请先重试待确认消息，或退出连接后重新进入。';return;}
  if(!activeGroup)return;
  conversation=value;view++;loading=false;history=new Map();moreOlder=false;$('older').hidden=true;$('messages').replaceChildren();
  $('group-button').classList.toggle('active',value==='group');$('conversation-title').textContent=value==='group'?'群组讨论':members.find(m=>m.id===value.slice(3))?.name;
  $('conversation-kind').textContent=value==='group'?'GROUP CONVERSATION':'DIRECT CONVERSATION';$('message').value='';renderMembers();renderRecipients();await refreshMessages('initial');
}
function renderGroups(){
  $('group-select').replaceChildren();
  if(!groups.length){const option=node('option','暂无获准访问的群组');option.value='';$('group-select').append(option);}
  for(const group of groups){const option=node('option',group.name);option.value=group.id;option.selected=group.id===activeGroup;$('group-select').append(option);}
  $('space-name').textContent=groups.find(g=>g.id===activeGroup)?.name||'尚未加入群组';
  $('create-group').hidden=me?.role!=='admin';
  $('compose').hidden=!activeGroup||me?.role==='observer';
}
async function chooseGroup(id){
  if(busy||pending){$('group-select').value=activeGroup||'';$('delivery-status').textContent='请先处理待确认消息。';return;}
  activeGroup=id;view++;loading=false;history=new Map();members=[];moreOlder=false;$('older').hidden=true;$('messages').replaceChildren();renderGroups();
  if(!id){renderMembers();$('messages').append(node('div',me?.role==='admin'?'点击「创建群组」开始。Agent 不会自动创建。':'等待管理员将你加入一个群组。','empty'));$('sync-status').textContent='尚未加入群组';return;}
  const current=session,selected=id;
  try{const result=await api('/api/members');if(current!==session||selected!==activeGroup)return;members=result.members;await select('group');}
  catch(error){if(current===session)$('network-error').textContent=error.message;}
}
$('group-select').onchange=()=>chooseGroup($('group-select').value);
$('create-group').onclick=async()=>{
  const current=session;$('group-error').textContent='';$('human-choices').replaceChildren();
  try{const result=await api('/api/humans');if(current!==session)return;for(const human of result.humans){if(human.id===me.id)continue;const label=node('label'),check=node('input');check.type='checkbox';check.name='group-human';check.value=human.id;label.append(check,node('span',human.id+' · '+human.role));$('human-choices').append(label);}$('group-dialog').showModal();}
  catch(error){if(current===session)$('network-error').textContent=error.message;}
};
$('cancel-group').onclick=()=>$('group-dialog').close();
$('group-form').onsubmit=async e=>{
  e.preventDefault();const current=session,button=$('group-form').querySelector('button[type="submit"]');button.disabled=true;
  try{const created=await api('/api/groups',{name:$('group-name').value,humans:[...document.querySelectorAll('input[name="group-human"]:checked')].map(i=>i.value)});if(current!==session)return;groups=(await api('/api/groups')).groups;if(current!==session)return;$('group-dialog').close();$('group-name').value='';await chooseGroup(created.id);}
  catch(error){if(current===session)$('group-error').textContent=error.message;}
  finally{button.disabled=false;}
};
$('login-form').onsubmit=async e=>{
  e.preventDefault();const current=++session;view++;token=$('token').value;$('login-error').textContent='';
  try{const identity=await api('/api/me');if(current!==session)return;const result=await api('/api/groups');if(current!==session)return;
    me=identity;groups=result.groups;conversation='group';history=new Map();loading=false;
    $('human-name').textContent=me.id;$('human-role').textContent={admin:'管理员',participant:'参与者',observer:'观察者'}[me.role];$('login').hidden=true;$('workspace').hidden=false;$('token').value='';await chooseGroup(groups[0]?.id||null);
  }catch(error){if(current!==session)return;token='';me=null;$('workspace').hidden=true;$('login').hidden=false;$('login-error').textContent=error.message;}
};
$('logout').onclick=()=>{session++;view++;activeGroup=null;groups=[];$('group-dialog').close();token='';me=null;pending=null;busy=false;loading=false;history=new Map();conversation='group';$('workspace').hidden=true;$('login').hidden=false;$('message').value='';$('message').disabled=false;$('send-button').disabled=false;$('send-button').textContent='发送 ↑';$('messages').replaceChildren();$('group-button').classList.add('active');$('conversation-title').textContent='群组讨论';$('conversation-kind').textContent='GROUP CONVERSATION';};
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
    if(JSON.stringify(discovered.groups)!==JSON.stringify(groups)){groups=discovered.groups;renderGroups();if(!activeGroup&&groups.length)await chooseGroup(groups[0].id);}
    if(!activeGroup)return;await refreshMessages();if(current!==session||!me)return;
    const selected=activeGroup;const result=await api('/api/members');if(current!==session||!me||selected!==activeGroup)return;
    if(JSON.stringify(result.members)!==JSON.stringify(members)){members=result.members;renderMembers();}
  }catch(error){if(current===session)$('network-error').textContent=error.message;}
  finally{polling=false;}
},2000);
