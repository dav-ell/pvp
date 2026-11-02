import { icon, labeledAction, copied } from './ui.js';
// Durable links identify a meeting, never an ephemeral media connection.
const $=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
export function meetingId(value,origin=location.origin){
  if(/^[0-9a-f]{64}$/.test(value))return value;
  try{const u=new URL(value,origin);if(u.origin!==origin||u.username||u.password)return null;const id=new URLSearchParams(u.hash.slice(1)).get('meeting');return /^[0-9a-f]{64}$/.test(id||'')?id:null;}catch{return null;}
}
export class MeetingLinks {
 constructor(options){this.o=options;this.items=[];this.selected=null;this.generation=0;this.available=false;this.creating=false;
  $('meetings-button').onclick=()=>this.open().then(()=>this.renderCreate()).catch(e=>this.o.toast(e.message,true));$('meeting-links-nav').onclick=()=>this.open().catch(e=>this.o.toast(e.message,true));
  window.addEventListener('hashchange',()=>this.followLink());
 }
 async activate(){this.available=true;await this.refresh();await this.followLink();}
 reset(){this.generation++;this.items=[];this.selected=null;this.available=false;$('meetings-dialog').hidden=true;$('meetings-content').replaceChildren();}
 action(label,fn,cls='button secondary'){const b=node('button',label,cls);b.type='button';b.onclick=async()=>{if(b.disabled)return;b.disabled=true;try{await fn();}catch(e){this.o.toast(e.message,true);}finally{b.disabled=false;}};return b;}
 async refresh(){if(!this.available||!this.o.user())return;const user=this.o.user().id,generation=this.generation;const items=await this.o.api('/meetings');if(this.o.user()?.id!==user||generation!==this.generation)return;this.items=items;if(!$('meetings-dialog').hidden){if(this.selected)await this.detail(this.selected);else if(!this.creating)this.renderList();}}
 async followLink(){if(!this.available||!this.o.user())return;const id=meetingId(location.href);if(id)await this.o.follow(id);}
 async open(id){if(this.o.user()?.scoped_guest)id=this.o.user().meeting_id;if(!this.available){this.o.toast('Recurring meetings require the updated PVP service.',true);return;}this.o.navigate('meetings');if(id)await this.detail(id);else{this.generation++;this.creating=false;this.selected=null;await this.refresh();this.renderList();}}
 arrive(scene){if(this.scene!==scene){this.scene=scene;this.o.arrive?.($('meetings-content'));}}
 heading(title){$('meetings-dialog').classList.remove('empty-library','room-library');$('meetings-title').textContent=title;document.querySelector('#meetings-dialog>.dialog-heading>.button')?.remove();$('meetings-footer').replaceChildren();}
 footer(note,button){$('meetings-footer').replaceChildren(node('span',note,'muted'),button);}
 renderList(){this.creating=false;this.heading('Your rooms.');const root=$('meetings-content');root.replaceChildren();
  const hasRooms=this.items.length>0;
  $('meetings-dialog').classList.add('room-library');$('meetings-dialog').classList.toggle('empty-library',!hasRooms);
  const create=this.action('Create room',()=>this.renderCreate(),'button primary');create.id='meeting-new';
  if(!hasRooms){
    const scene=node('section',undefined,'room-welcome'),copy=node('div',undefined,'room-welcome-copy');
    copy.append(node('span','A PLACE TO RETURN TO','tiny-label'),node('h2','Good company.\nSame place.'),node('p','Make a little space for your people. One link to keep, whenever you want to catch up.','muted'),create);
    const art=node('img');art.src='/room-scene.svg';art.alt='';art.width=600;art.height=510;scene.append(copy,art);root.append(scene);
  }else{
    document.querySelector('#meetings-dialog>.dialog-heading').append(create);
    root.append(node('p','Pick up where you left off.','room-library-intro'));
    const list=node('div',undefined,'meeting-list');
    this.items.forEach((m,index)=>{
      const card=node('article',undefined,'room-card');card.dataset.meetingId=m.meeting_id;
      const number=node('span',String(index+1).padStart(2,'0'),'room-number');card.append(number);
      const b=this.action('',()=>this.detail(m.meeting_id),'meeting-list-item');const info=node('span',undefined,'meeting-list-info');
      const present=m.participants||[];info.append(node('strong',m.name),node('small',present.length?`${present.length} here · ${present.map(p=>p.display_name).join(', ')}`:m.open_invite?'Anyone with the link':'Invited people only'));b.append(info);card.append(b);
      if(present.length)card.classList.add('room-occupied');
      const actions=node('div',undefined,'room-actions');const copy=this.action('',async()=>{const url=m.url||new URL('/#meeting='+m.meeting_id,location.origin).href;try{await navigator.clipboard.writeText(url);copied(copy,()=>labeledAction(copy,'copy','Copy link'));}catch{await this.detail(m.meeting_id);this.o.toast('Open Show link to copy your invitation.');}});labeledAction(copy,'copy','Copy link');copy.classList.add('room-copy');
      const join=this.action(present.length?'Join them':'Join room',()=>{if(this.o.busy())throw Error('Finish your current conversation first.');return this.o.start(m.meeting_id);},'button primary');join.classList.add('room-join');actions.append(copy,join);card.append(actions);list.append(card);
    });root.append(list);
  }
  const join=node('form',undefined,'meeting-link-form'),input=node('input');input.placeholder='Paste a PVP room link';input.id='meeting-paste';input.required=true;
  const label=node('label','Already have an invitation?');label.htmlFor=input.id;const submit=node('button','Open room','button secondary');submit.type='submit';submit.disabled=true;input.oninput=()=>submit.disabled=!input.value.trim();join.append(label,input,submit);
  join.onsubmit=async e=>{e.preventDefault();const id=meetingId(input.value.trim());if(!id){this.o.toast('Use a PVP room link for this service.',true);return;}submit.disabled=true;try{await this.o.start(id);}catch(e){this.o.toast(e.message,true);}finally{submit.disabled=false;}};root.append(join);
  $('meetings-footer').append(node('span',this.o.user()?.guest?'Keep your link. Host controls belong to this browser session.':'Your link stays the same. Come and go as you like.','muted'));this.arrive('library');
 }
 renderCreate(){this.generation++;this.selected=null;this.creating=true;this.heading('Create a room');const root=$('meetings-content');root.replaceChildren(this.action('All rooms',()=>this.open(),'button subtle'),node('p','Keep this link for next time.','muted'));
  const form=node('form',undefined,'meeting-create-form');form.id='meeting-create-form';
  const name=node('input');name.id='meeting-name';name.placeholder='e.g. Friday catch-up';name.maxLength=80;name.required=true;
  const nameLabel=node('label','Room name');nameLabel.htmlFor=name.id;form.append(nameLabel,name);
  const access=node('select');access.id='meeting-access';for(const [value,text] of [['private','Invited people only'],['open','Anyone with the link']]){const option=node('option',text);option.value=value;access.append(option);}
  access.value='open';if(this.o.user()?.guest)access.disabled=true;
  const accessLabel=node('label','Who can join?');accessLabel.htmlFor=access.id;
  const accessPanel=node('section',undefined,'meeting-panel');const accessHelp=node('p',access.value==='open'?'Anyone with the link can join, including guests without accounts.':'Only the people you invite can join.','muted');access.onchange=()=>accessHelp.textContent=access.value==='open'?'Anyone with the link can join, including guests without accounts.':'Only the people you invite can join.';accessPanel.append(accessLabel,access,accessHelp);form.append(accessPanel);
  const invites=node('details',undefined,'meeting-panel'),friends=this.o.friends().filter(f=>f.status==='accepted'),count=node('summary','Invite saved people · 0/15');invites.append(count,node('p','Add people now or invite them later.','muted'));
  if(!friends.length)invites.append(node('p','Share the room link with your people after creating it.','muted'));
  for(const f of friends){const label=node('label',undefined,'group-choice'),box=node('input');box.type='checkbox';box.value=f.id;box.onchange=()=>{const selected=invites.querySelectorAll('input:checked').length;count.textContent=`Invite saved people · ${selected}/15`;for(const b of invites.querySelectorAll('input'))b.disabled=!b.checked&&selected>=15;};label.append(box,node('span',`${f.display_name} · @${f.username}`));invites.append(label);}form.append(invites,node('p','Your microphone and camera stay off.','muted'));root.append(form);
  const create=node('button','Create link','button primary');create.id='meeting-create';create.type='submit';create.setAttribute('form',form.id);create.disabled=true;name.oninput=()=>create.disabled=submitting||!name.value.trim();this.footer('Reusable invitation · Up to 16 people',create);
  let submitting=false;form.onsubmit=async e=>{e.preventDefault();if(submitting||!name.value.trim())return;submitting=true;create.disabled=true;create.textContent='Creating…';const user=this.o.user()?.id,gen=this.generation;try{const peer_ids=[...form.querySelectorAll('input:checked')].map(b=>b.value);const m=await this.o.api('/meetings',{method:'POST',body:{name:name.value.trim(),peer_ids,open_invite:access.value==='open'}});if(this.o.user()?.id===user&&this.generation===gen)await this.detail(m.meeting_id);}catch(e){this.o.toast(e.message,true);}finally{submitting=false;create.disabled=!name.value.trim();create.textContent='Create link';}};
  this.arrive('create');name.focus();
 }
 async moderate(id,member,action){
  const user=this.o.user()?.id;if(!user)return;
  if(action==='kick'&&!confirm(member.id.startsWith('guest-')?`Kick ${member.display_name}? This guest session will be blocked from rejoining.`:`Kick ${member.display_name}? Their account will be blocked from rejoining until the owner invites them again.`))return;
  if(this.o.user()?.id!==user)return;
  const path=`/meetings/${id}/members/${member.id}`;
  if(action==='kick')await this.o.api(path,{method:'DELETE'});
  else if(action==='promote'||action==='demote')await this.o.api(path+'/admin',{method:'POST',body:{admin:action==='promote'}});
  else if(action==='speak'||action==='stop-speaking')await this.o.api(path+'/speak',{method:'POST',body:{allowed:action==='speak'}});
  else await this.o.api(path+'/mute',{method:'POST',body:{muted:action==='mute'}});
  if(this.o.user()?.id===user&&!$('meetings-dialog').hidden&&this.selected===id)await this.detail(id);
 }

 async detail(id){this.creating=false;this.heading('Room settings');const user=this.o.user()?.id,generation=++this.generation;this.selected=id;$('meetings-content').replaceChildren(node('p','Loading room…','muted'));let m;try{m=await this.o.api(`/meetings/${id}`);}catch(e){if(generation===this.generation&&this.o.user()?.id===user){this.selected=null;$('meetings-content').replaceChildren(node('p',e.message,'muted'),this.action('All rooms',()=>this.open()));}throw e;}if(!user||this.o.user()?.id!==user||generation!==this.generation)return;this.selected=id;this.heading(m.name);
  const root=$('meetings-content');root.replaceChildren(...(this.o.user()?.scoped_guest?[]:[this.action('All rooms',()=>{this.selected=null;return this.refresh();})]),node('p',m.open_invite?'Anyone with the link can join. No account needed.':'Private room · Invited people only','muted'),node('p','Direct calls share your network address with participants.','muted'));
  if(m.zoom)root.append(node('p','Zoom-linked room · Zoom passcodes and host roles do not carry over. This room has no admin. Everyone must join in PVP.','muted'));
  else if(this.o.user()?.guest&&!this.o.user()?.scoped_guest&&m.owner_id===user)root.append(node('p','Your host controls stay with this guest session in this browser. Signing out, switching accounts, or clearing site data loses those controls. Save the meeting link to keep joining.','muted'));
  const link=node('input');link.id='meeting-link';link.readOnly=true;link.value=m.url;link.setAttribute('aria-label','Room invitation');const share=node('section',undefined,'meeting-panel meeting-share'),copy=this.action('',async()=>{try{await navigator.clipboard.writeText(m.url);copied(copy,()=>labeledAction(copy,'copy','Copy link'));}catch{details.open=true;link.select();this.o.toast('Select and copy the link.');}});copy.id='meeting-copy';labeledAction(copy,'copy','Copy link');const details=node('details'),summary=node('summary','Show link');details.append(summary,link);share.append(copy,details);
  const mac=node('a','Open in Mac app','button secondary');mac.href=`pvp://meeting/${id}?origin=${encodeURIComponent(location.origin)}`;if(!this.o.user()?.guest)share.append(mac);root.append(share);
  root.append(node('p',m.participants.length?`Already here: ${m.participants.map(p=>p.display_name).join(', ')}`:'Nobody is here yet. You can join first.','muted'));
  const join=this.action('Join room',async()=>{if(this.o.busy())throw Error('Finish your current call first.');join.disabled=true;try{await this.o.api(`/meetings/${id}`);if(this.o.user()?.id!==user||!!$('meetings-dialog').hidden)return;await this.o.start(id);}finally{join.disabled=false;}},'button primary');join.id='meeting-join';this.footer(this.o.busy()?'A call is already in progress':'Up to 16 members · Meet anytime',join);join.disabled=this.o.busy();root.append(node('h3',`Members · ${m.members.length}/16`));
  const admin=m.members.some(p=>p.id===user&&p.is_admin),owner=user===m.owner_id;
  root.append(node('p',owner?'You own this room.':admin?'You’re an admin.':'The host and admins can mute or remove people.','muted'));
  if(owner&&m.open_invite&&Object.hasOwn(m,'network_visible')){
    const panel=node('details',undefined,'meeting-network-setting'),summary=node('summary','Public room map'),label=node('label','Share anonymous room activity','sheet-switch'),toggle=node('input');
    toggle.id='meeting-network-visible';toggle.type='checkbox';toggle.setAttribute('role','switch');toggle.checked=m.network_visible;
    toggle.onchange=async()=>{toggle.disabled=true;try{await this.o.api(`/meetings/${id}/network`,{method:'POST',body:{visible:toggle.checked}});}catch(e){toggle.checked=!toggle.checked;this.o.toast(e.message,true);}finally{toggle.disabled=false;}};
    label.append(toggle);panel.append(summary,label,node('p','Show this room’s size in the homepage network. No names, links, IPs or locations. Off by default.','muted'));root.append(panel);
  }else if(m.network_visible)root.append(node('p','This room shares its anonymous size on the homepage. Names, links and addresses stay private.','muted'));
  if(admin){
    const panel=node('section',undefined,'meeting-panel'),label=node('label','Raise hand to speak','sheet-switch'),toggle=node('input');
    toggle.id='meeting-raise-hand';toggle.type='checkbox';toggle.setAttribute('role','switch');toggle.checked=!!m.raise_hand_enabled;
    toggle.onchange=async()=>{toggle.disabled=true;try{await this.o.api(`/meetings/${id}/speaking`,{method:'POST',body:{enabled:toggle.checked}});}catch(e){toggle.checked=!toggle.checked;this.o.toast(e.message,true);}finally{toggle.disabled=false;}};
    label.append(toggle);panel.append(label,node('p','Participants need admin approval before unmuting. Admins can speak freely.','muted'));root.append(panel);
  }else if(m.raise_hand_enabled)root.append(node('p','Raise your hand during the meeting and wait for an admin to let you speak.','muted'));

  for(const member of m.members){
    const row=node('div',undefined,'meeting-member');row.dataset.memberId=member.id;
    const info=node('span',undefined,'meeting-member-info');info.append(node('strong',`${member.display_name}${member.id===user?' · You':''}`),node('small',`${(member.id.startsWith('guest-')||member.username?.startsWith('~'))?'Guest':'@'+member.username}${member.id===m.owner_id?' · Owner':member.is_admin?' · Admin':''}${member.moderator_muted?' · Muted by admin':''}`));row.append(info);
    if(member.id!==m.owner_id&&member.id!==user){const menu=node('details',undefined,'person-menu'),summary=node('summary');summary.setAttribute('aria-label',`Manage ${member.display_name}`);summary.append(icon('ellipsis'));menu.append(summary);row.append(menu);
      if(owner&&!member.id.startsWith('guest-'))menu.append(this.action(member.is_admin?'Remove admin':'Make admin',()=>this.moderate(id,member,member.is_admin?'demote':'promote'),'button subtle'));
      if(admin||owner){menu.append(this.action(member.moderator_muted?'Allow unmute':'Mute',()=>this.moderate(id,member,member.moderator_muted?'allow':'mute'),'button subtle'),this.action('Kick',()=>this.moderate(id,member,'kick'),'button danger'));}
    }
    root.append(row);
  }
  if(this.o.user().id===m.owner_id){const choices=this.o.friends().filter(f=>f.status==='accepted'&&!m.members.some(p=>p.id===f.id));const select=node('select');select.id='meeting-add-person';for(const f of choices){const op=node('option',f.display_name);op.value=f.id;select.append(op);}const add=this.action('Add member',async()=>{await this.o.api(`/meetings/${id}/members`,{method:'POST',body:{peer_id:select.value}});await this.detail(id);});add.disabled=!choices.length||m.members.length>=16;const invite=node('section',undefined,'meeting-panel meeting-invite');const label=node('label','Invite a friend');label.htmlFor=select.id;invite.append(label,select,add);if(!choices.length)invite.append(node('p','All your friends are already invited.','muted'));if(m.members.length>=16)invite.append(node('p','This meeting is full. Remove a member to invite someone else.','muted'));root.append(invite,this.action('Delete room',async()=>{if(!confirm('Delete this permanent meeting link and end its active call?'))return;await this.o.api(`/meetings/${id}`,{method:'DELETE'});this.selected=null;await this.refresh();},'button danger'));}
  this.arrive(id);
 }
}
