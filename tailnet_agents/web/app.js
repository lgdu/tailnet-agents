'use strict';
let me = null;
let token = '', conversation = 'group', members = [], pending = null, busy = false;
const $ = id => document.getElementById(id);
function node(tag, text, className) { const n = document.createElement(tag); if(text !== undefined) n.textContent = text; if(className) n.className = className; return n; }
async function api(path, body) {
  const response = await fetch(path, {method: body ? 'POST' : 'GET', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, ...(body ? {body: JSON.stringify(body)} : {})});
  const data = await response.json(); if(!response.ok) throw new Error(data.error || '请求失败'); return data;
}
function renderMembers() {
  $('member-count').textContent = `${members.filter(m => m.online).length} / ${members.length} 模拟成员在线`;
  $('member-list').replaceChildren(); $('direct-list').replaceChildren();
  for(const m of members) {
    const nav = node('button', '@ ' + m.name, 'nav' + (conversation === 'dm:' + m.id ? ' active' : '')); nav.onclick = () => select('dm:' + m.id); if(me?.role !== 'observer') $('direct-list').append(nav);
    const card = node('div', undefined, 'member-card'), top = node('div', undefined, 'member-top'); top.append(node('span', m.name[0], 'avatar'));
    const info = node('div'); info.append(node('strong', m.name), node('small', m.online ? '模拟 Echo · 在线' : '模拟 Echo · 离线')); top.append(info, node('span', undefined, 'presence' + (m.online ? '' : ' offline')));
    const toggle = node('button', m.online ? '模拟离线' : '恢复在线'); toggle.onclick = async () => { try { const result = await api('/api/presence', {agent: m.id, online: !m.online}); members = result.members; renderMembers(); } catch(e) {$('network-error').textContent = e.message;} }; card.append(top); if(me?.role === 'admin') card.append(toggle); $('member-list').append(card);
  }
}
function renderRecipients() {
  $('recipients').replaceChildren();
  if(conversation !== 'group') { $('recipients').textContent = '独立对话 · 仅目标模拟 Agent 回应'; return; }
  $('recipients').append(node('span', '点名回应：'));
  for(const m of members) { const label = node('label'), input = node('input'); input.type = 'checkbox'; input.value = m.id; input.name = 'recipient'; label.append(input, node('span', m.name)); $('recipients').append(label); }
  $('recipients').append(node('span', '未选择时由 Moderator 回应'));
}
async function refreshMessages() {
  const selected = conversation;
  const data = await api('/api/messages?conversation=' + encodeURIComponent(selected));
  if(selected !== conversation) return;
  $('messages').replaceChildren();
  if(!data.messages.length) $('messages').append(node('div', '这里还没有消息。\n开始一段新的讨论。', 'empty'));
  for(const message of data.messages) {
    const human = message.sender === 'human', own = human && message.author === me?.id, label = human ? (own ? '你' : message.author) : (members.find(m=>m.id===message.sender)?.name || message.sender);
    const row = node('div', undefined, 'chat-row' + (own ? ' human' : '')); row.append(node('span', human ? '人' : label[0], 'avatar'));
    const content = node('div'); content.append(node('div', `${label} · ${new Date(message.created*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}`, 'message-meta'), node('div', message.text, 'bubble')); row.append(content); $('messages').append(row);
  }
  $('messages').scrollTop = $('messages').scrollHeight;
}
async function select(value) {
  if(busy || pending) { $('delivery-status').textContent = '请先重试待确认消息，或退出连接后重新进入。'; return; }
  conversation = value; $('group-button').classList.toggle('active', value === 'group');
  $('conversation-title').textContent = value === 'group' ? '群组讨论' : members.find(m=>m.id===value.slice(3))?.name;
  $('conversation-kind').textContent = value === 'group' ? 'GROUP CONVERSATION' : 'DIRECT CONVERSATION';
  $('message').value = ''; renderMembers(); renderRecipients();
  try { await refreshMessages(); } catch(e) {$('network-error').textContent=e.message;}
}
$('login-form').onsubmit = async e => {
  e.preventDefault(); token = $('token').value; $('login-error').textContent='';
  try { me = await api('/api/me'); members = (await api('/api/members')).members; $('human-name').textContent=me.id; $('human-role').textContent={admin:'管理员',participant:'参与者',observer:'观察者'}[me.role]; $('compose').hidden=me.role==='observer'; $('login').hidden=true; $('workspace').hidden=false; $('token').value=''; renderMembers(); renderRecipients(); await refreshMessages(); }
  catch(error) {token=''; $('workspace').hidden=true; $('login').hidden=false; $('login-error').textContent=error.message;}
};
$('logout').onclick = () => {token=''; me=null; pending=null; conversation='group'; $('workspace').hidden=true; $('login').hidden=false; $('message').value=''; $('messages').replaceChildren(); $('group-button').classList.add('active'); $('conversation-title').textContent='群组讨论'; $('conversation-kind').textContent='GROUP CONVERSATION';};
$('group-button').onclick = () => select('group');
$('compose').onsubmit = async e => {
  e.preventDefault(); if(busy) return; if(!pending && !$('message').value.trim()) return;
  if(!pending) pending = {conversation, text:$('message').value, targets:[...document.querySelectorAll('input[name="recipient"]:checked')].map(i=>i.value), request_id:crypto.randomUUID()};
  busy=true; $('send-button').disabled=true; $('message').disabled=true; $('delivery-status').textContent='发送中…';
  try {const result = await api('/api/messages', pending); pending=null; $('message').value=''; $('delivery-status').textContent=result.offline_targets.length ? '已保存；离线接收者未回应：' + result.offline_targets.join(', ') : '已保存 · 模拟回应已生成'; await refreshMessages();}
  catch(error) {$('delivery-status').textContent='结果未确认，点击发送重试同一消息：' + error.message;}
  finally {busy=false; $('send-button').disabled=false; $('message').disabled=!!pending; $('send-button').textContent=pending ? '重试 ↑' : '发送 ↑';}
};
$('message').onkeydown = e => {if(e.key==='Enter' && !e.shiftKey && !e.isComposing){e.preventDefault(); $('compose').requestSubmit();}};
