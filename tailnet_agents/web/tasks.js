'use strict';
let taskGeneration=0,taskBindings=[],taskConsent=null,taskPending=null,taskPreviewRequest=null;
let taskBusy=false,taskAfter=0,taskHistoryAfter=0,taskMono=0,taskWall=0;
const newTaskId=()=>crypto.randomUUID().replaceAll('-','');
function invalidateTasks(){
  taskGeneration++;taskConsent=null;taskPending=null;taskPreviewRequest=null;taskBusy=false;taskBindings=[];
  $('task-binding').replaceChildren();$('task-rows').replaceChildren();$('task-consents').replaceChildren();
  $('task-input').value='';$('task-id').value='';$('task-confirm-id').value='';
  $('task-preview-text').textContent='';$('task-result').textContent='';$('task-context').textContent='';$('task-storage').textContent='';
  $('task-status').textContent='尚未读取。';taskAfter=taskHistoryAfter=0;
  $('task-next').disabled=$('task-history-next').disabled=true;taskControls();
}
function taskCurrent(g,s,group,binding){
  return g===taskGeneration&&s===session&&group===activeGroup&&$('task-dialog').open&&
    (binding===undefined||binding===$('task-binding').value);
}
function taskControls(){
  if(taskConsent&&taskConsent.consent_state==='preview'){
    const elapsed=Math.max(performance.now()-taskMono,Date.now()-taskWall,0)/1000;
    if(Date.now()/1000>=taskConsent.expires_at||elapsed>=taskConsent.expires_at-taskConsent.received_at)
      taskConsent.consent_state='expired';
  }
  const bound=taskBindings.some(b=>b.id===$('task-binding').value),locked=taskBusy||!!taskPending;
  for(const id of ['task-operation','task-id','task-input','task-new','task-preview'])$(id).disabled=locked||!bound;
  $('task-input').disabled=locked||!bound||$('task-operation').value!=='queue';
  $('task-binding').disabled=locked;
  $('task-confirm-id').disabled=locked||!taskConsent;
  $('task-confirm').disabled=taskBusy||!!taskPending||!taskConsent||
    !['preview','started','done'].includes(taskConsent.consent_state)||!taskConsent.eligible||
    $('task-confirm-id').value!==taskConsent.task_id;
  $('task-retry').hidden=!taskPending;$('task-retry').disabled=taskBusy;
  for(const id of ['task-list','task-history','task-storage-read'])$(id).disabled=taskBusy||!bound;
}
function clearTaskPreview(){
  if(taskBusy||taskPending)return;
  taskGeneration++;taskConsent=null;taskPreviewRequest=null;$('task-confirm-id').value='';
  $('task-preview-text').textContent='';$('task-result').textContent='';taskControls();
}
function showTaskConsent(value){
  taskConsent={...value,received_at:Date.now()/1000};taskMono=performance.now();taskWall=Date.now();
  $('task-preview-text').textContent=JSON.stringify(value,null,2);$('task-confirm-id').value='';taskControls();
}
$('task-open').onclick=async()=>{
  invalidateTasks();const g=taskGeneration,s=session,group=activeGroup;
  $('task-dialog').showModal();$('task-id').value=newTaskId();$('task-operation').value='queue';
  try{
    const result=await api('/api/task-bindings?'+new URLSearchParams({group_id:group}));
    if(!taskCurrent(g,s,group))return;
    taskBindings=result.bindings;
    for(const binding of taskBindings){const option=node('option',binding.id+' · '+binding.caller+' → '+binding.executor);option.value=binding.id;$('task-binding').append(option);}
    $('task-context').textContent=JSON.stringify(taskBindings,null,2);
    $('task-status').textContent=taskBindings.length?'已读取明确绑定；尚未读取任务、保存意向或联系执行器。':'此人类/群组没有显式任务绑定。';
  }catch(error){if(taskCurrent(g,s,group))$('task-status').textContent=error.message;}
  finally{if(taskCurrent(g,s,group))taskControls();}
};
$('task-close').onclick=()=>$('task-dialog').close();
$('task-dialog').onclose=invalidateTasks;
$('task-form').onsubmit=event=>event.preventDefault();
$('task-binding').onchange=()=>{clearTaskPreview();$('task-storage').textContent='';$('task-rows').replaceChildren();$('task-consents').replaceChildren();taskAfter=taskHistoryAfter=0;$('task-next').disabled=$('task-history-next').disabled=true;};
for(const id of ['task-operation','task-id','task-input'])$(id).addEventListener(id==='task-operation'?'change':'input',clearTaskPreview);
$('task-confirm-id').oninput=taskControls;
$('task-new').onclick=()=>{clearTaskPreview();$('task-id').value=newTaskId();$('task-input').value='';$('task-operation').value='queue';taskControls();};
$('task-preview').onclick=async()=>{
  if(taskBusy||taskPending)return;
  const g=taskGeneration,s=session,group=activeGroup,binding=$('task-binding').value;
  if(taskConsent)taskPreviewRequest=null;
  if(!taskPreviewRequest){taskPreviewRequest={group_id:group,binding_id:binding,operation:$('task-operation').value,task_id:$('task-id').value,request_id:newTaskId()};
    if(taskPreviewRequest.operation==='queue')taskPreviewRequest.input=$('task-input').value;}
  taskBusy=true;taskConsent=null;$('task-preview-text').textContent='';$('task-confirm-id').value='';
  $('task-result').textContent='';taskControls();$('task-status').textContent='正在保存预览；尚未执行。';
  try{const result=await api('/api/task-preview',taskPreviewRequest);
    if(!taskCurrent(g,s,group,binding))return;
    showTaskConsent(result);$('task-status').textContent='请核对完整身份、输入、操作和原任务 ID，再单独确认。预览不是远端授权检查。';
  }catch(error){if(taskCurrent(g,s,group,binding))$('task-status').textContent=error.message;}
  finally{if(taskCurrent(g,s,group,binding)){taskBusy=false;taskControls();}}
};
$('task-confirm').onclick=()=>{
  taskControls();if($('task-confirm').disabled)return;
  taskPending={group_id:activeGroup,binding_id:$('task-binding').value,consent_id:taskConsent.consent_id,confirm_task_id:taskConsent.task_id};
  retryTask();
};
async function retryTask(){
  if(!taskPending||taskBusy)return;
  const g=taskGeneration,s=session,group=activeGroup,binding=$('task-binding').value,request=taskPending;
  taskBusy=true;taskControls();$('task-status').textContent='正在执行这一个已确认操作；超时后请保留原确认。';
  try{
    const result=await api('/api/task-confirm',request);if(!taskCurrent(g,s,group,binding))return;
    $('task-result').textContent=JSON.stringify(result,null,2);taskPending=null;taskConsent=null;taskPreviewRequest=null;
    $('task-status').textContent='原操作已确认。结果是数据，不会触发后续任务。再次执行其他操作须重新预览。';
  }catch(error){if(taskCurrent(g,s,group,binding))$('task-status').textContent='结果未确认：显式重试同一确认，或读取原任务/确认记录。'+error.message;}
  finally{if(taskCurrent(g,s,group,binding)){taskBusy=false;taskControls();}}
}
$('task-retry').onclick=retryTask;
async function readTaskPage(kind,after=0){
  if(taskBusy)return;
  const g=taskGeneration,s=session,group=activeGroup,binding=$('task-binding').value;
  taskBusy=true;taskControls();
  const container=$(kind==='list'?'task-rows':'task-consents');container.replaceChildren();
  $(kind==='list'?'task-next':'task-history-next').disabled=true;
  try{
    const result=await api('/api/task-read',{group_id:group,binding_id:binding,operation:kind,after,limit:20});
    if(!taskCurrent(g,s,group,binding))return;
    for(const entry of result[kind==='list'?'tasks':'consents']){
      const row=node('li'),button=node('button',kind==='list'?entry.task_id+' · '+entry.state+(entry.cancellation_requested?' · 取消请求已保存':''):
        entry.consent_id+' · '+entry.preview.operation+' · '+entry.state);button.type='button';
      button.onclick=async()=>{
        if(taskBusy||taskPending)return;
        clearTaskPreview();$('task-id').value=kind==='list'?entry.task_id:entry.preview.task_id;
        if(kind==='history'){
          $('task-operation').value=entry.preview.operation;$('task-input').value=entry.preview.input||'';
          showTaskConsent({...entry.preview,consent_id:entry.consent_id,consent_state:entry.state,expires_at:entry.expires_at,issued_at:entry.issued_at});
        }else{
          $('task-operation').value='refresh';const cg=taskGeneration;taskBusy=true;taskControls();
          try{const data=await api('/api/task-read',{group_id:group,binding_id:binding,operation:'show',task_id:entry.task_id});
            if(taskCurrent(cg,s,group,binding))$('task-result').textContent=JSON.stringify(data,null,2);
          }catch(error){if(taskCurrent(cg,s,group,binding))$('task-status').textContent=error.message;}
          finally{if(taskCurrent(cg,s,group,binding)){taskBusy=false;taskControls();}}
        }
        taskControls();
      };row.append(button);container.append(row);
    }
    if(kind==='list'){taskAfter=result.next_after;$('task-next').disabled=!result.has_more;}
    else{taskHistoryAfter=result.next_after;$('task-history-next').disabled=!result.has_more;}
    $('task-status').textContent='本地历史页；不代表当前远端授权或执行器在线。';
  }catch(error){if(taskCurrent(g,s,group,binding))$('task-status').textContent=error.message;}
  finally{if(taskCurrent(g,s,group,binding)){taskBusy=false;taskControls();}}
}
$('task-list').onclick=()=>readTaskPage('list');$('task-next').onclick=()=>readTaskPage('list',taskAfter);
$('task-history').onclick=()=>readTaskPage('history');$('task-history-next').onclick=()=>readTaskPage('history',taskHistoryAfter);
setInterval(()=>{if($('task-dialog').open)taskControls();},300);

$('task-storage-read').onclick=async()=>{
  if(taskBusy)return;
  const g=taskGeneration,s=session,group=activeGroup,binding=$('task-binding').value;
  taskBusy=true;taskControls();$('task-storage').textContent='';
  try{
    const data=await api('/api/task-read',{group_id:group,binding_id:binding,operation:'storage'});
    if(taskCurrent(g,s,group,binding))$('task-storage').textContent=JSON.stringify(data,null,2);
  }catch(error){if(taskCurrent(g,s,group,binding))$('task-status').textContent=error.message;}
  finally{if(taskCurrent(g,s,group,binding)){taskBusy=false;taskControls();}}
};
