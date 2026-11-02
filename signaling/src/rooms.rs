//! Group membership and pairwise signaling. No media passes through this service.
use super::*;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Serialize)]
pub(super) struct Member {
    #[serde(flatten)]
    user: User,
    joined: bool,
    invited_by: String,
    invited_at: i64,
    client: String,
    is_admin: bool,
    moderator_muted: bool,
    hand_raised: bool,
    speaking_allowed: bool,
}
#[derive(Clone)]
pub(super) struct Room {
    id: String,
    revision: u32,
    voice: bool,
    raise_hand_enabled: bool,
    meeting_id: Option<String>,
    name: Option<String>,
    owner_id: Option<String>,
    members: HashMap<String, Member>,
    pairs: HashMap<(String, String), Pair>,
}
#[derive(Clone, Default)]
struct Pair {
    generation: u8,
    answer: bool,
    candidates: [u16; 2],
    early_candidates: u16,
}

impl Room {
    #[cfg(test)]
    pub(super) fn snapshot_for_test(&self) -> Value {
        self.snapshot()
    }
    fn snapshot(&self) -> Value {
        let mut members: Vec<_> = self.members.values().cloned().collect();
        // Existing moderation receivers also enforce speaking permissions.
        for member in &mut members {
            member.moderator_muted |=
                self.raise_hand_enabled && !member.is_admin && !member.speaking_allowed;
        }
        members.sort_by(|a, b| a.user.id.cmp(&b.user.id));
        json!({"type":"room-state","room_id":self.id,"revision":self.revision,"voice":self.voice,"raise_hand_enabled":self.raise_hand_enabled,"members":members,"meeting_id":self.meeting_id,"name":self.name,"owner_id":self.owner_id})
    }
}
pub(super) fn joined(live: &Live, user: &str) -> bool {
    live.rooms
        .values()
        .any(|r| r.members.get(user).is_some_and(|m| m.joined))
}
fn busy(live: &Live, user: &str) -> bool {
    joined(live, user)
        || live
            .calls
            .values()
            .any(|c| c.caller == user || c.callee == user)
}
fn find_user(app: &App, id: &str) -> ApiResult<User> {
    app.db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id,username,display_name FROM users WHERE id=?1",
            [id],
            |r| {
                Ok(User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                })
            },
        )
        .optional()?
        .ok_or(bad("Friend is unavailable"))
}
pub(super) fn capabilities(
    app: &App,
    user: &User,
    client: String,
    meeting_moderation: bool,
) -> ApiResult<()> {
    if !matches!(client.as_str(), "browser" | "mac") {
        return Err(bad("Unsupported group client"));
    }
    let pending = {
        let mut live = app.live.lock().unwrap();
        if let Some(peer) = live.peers.get_mut(&user.id) {
            peer.group_client = Some(client);
            peer.meeting_moderation = meeting_moderation;
        }
        live.rooms
            .values()
            .filter(|r| r.members.get(&user.id).is_some_and(|m| !m.joined))
            .map(Room::snapshot)
            .collect::<Vec<_>>()
    };
    if !meeting_moderation
        || app
            .live
            .lock()
            .unwrap()
            .peers
            .get(&user.id)
            .is_some_and(|p| !p.raise_hand)
    {
        let meetings = {
            let live = app.live.lock().unwrap();
            live.rooms
                .values()
                .filter(|r| r.raise_hand_enabled || r.members.values().any(|m| m.moderator_muted))
                .filter_map(|r| r.meeting_id.clone())
                .collect::<Vec<_>>()
        };
        for id in meetings {
            remove_legacy_meeting_members(app, &id);
        }
    }
    for value in pending {
        app.send(&user.id, value);
    }
    Ok(())
}
pub(super) fn create(app: &App, user: &User, peers: Vec<String>) -> ApiResult<()> {
    create_room(app, user, peers, false)
}
pub(super) fn open_voice(app: &App, user: &User) -> ApiResult<()> {
    create_room(app, user, vec![], true)
}
fn create_room(app: &App, user: &User, peers: Vec<String>, voice: bool) -> ApiResult<()> {
    if (!voice && peers.is_empty())
        || peers.len() > 15
        || peers.iter().collect::<HashSet<_>>().len() != peers.len()
        || peers.iter().any(|p| p == &user.id || p.len() > 64)
    {
        return Err(bad("Choose between 1 and 15 different friends"));
    }
    if app.limited(format!("room-create:{}", user.id), 10, 60) {
        return Err(bad("Too many group invitations"));
    }
    let mut members = HashMap::new();
    for id in &peers {
        if !app.accepted(&user.id, id)? {
            return Err(forbidden());
        }
        members.insert(
            id.clone(),
            Member {
                user: find_user(app, id)?,
                joined: false,
                invited_by: user.id.clone(),
                invited_at: now(),
                client: String::new(),
                is_admin: false,
                moderator_muted: false,
                hand_raised: false,
                speaking_allowed: false,
            },
        );
    }
    let room = {
        let mut live = app.live.lock().unwrap();
        if busy(&live, &user.id) {
            return Err(bad("Finish your current call first"));
        }
        if live.rooms.len() >= 256 {
            return Err(bad("Group calls are currently busy"));
        }
        let client = live
            .peers
            .get(&user.id)
            .and_then(|p| p.group_client.clone())
            .ok_or(bad("Update PVP to start a group call"))?;
        members.insert(
            user.id.clone(),
            Member {
                user: user.clone(),
                joined: true,
                invited_by: user.id.clone(),
                invited_at: now(),
                client,
                is_admin: false,
                moderator_muted: false,
                hand_raised: false,
                speaking_allowed: false,
            },
        );
        let room = Room {
            id: Uuid::new_v4().to_string(),
            revision: 1,
            voice,
            raise_hand_enabled: false,
            meeting_id: None,
            name: None,
            owner_id: None,
            members,
            pairs: HashMap::new(),
        };
        live.rooms.insert(room.id.clone(), room.clone());
        room
    };
    publish_capable(app, &room);
    if room.voice {
        for member in room.members.values() {
            app.presence(&member.user.id);
        }
    }
    Ok(())
}
fn publish_capable(app: &App, room: &Room) {
    let ids = {
        let live = app.live.lock().unwrap();
        room.members
            .keys()
            .filter(|id| {
                live.peers
                    .get(*id)
                    .is_some_and(|p| p.group_client.is_some())
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    for id in ids {
        app.send(&id, room.snapshot());
    }
}
pub(super) fn invite(app: &App, user: &User, id: String, peer: String) -> ApiResult<()> {
    if !app.accepted(&user.id, &peer)? {
        return Err(forbidden());
    }
    if app.limited(format!("room-invite:{}", user.id), 30, 60) {
        return Err(bad("Too many group invitations"));
    }
    let invited = find_user(app, &peer)?;
    let room = {
        let mut live = app.live.lock().unwrap();
        let room = live.rooms.get_mut(&id).ok_or(bad("Group call ended"))?;
        if !room.members.get(&user.id).is_some_and(|m| m.joined) {
            return Err(forbidden());
        }
        if room.voice {
            return Err(bad("Friends can join voice rooms from their friends list"));
        }
        if room.meeting_id.is_some() {
            return Err(bad("Manage recurring meeting members from Meetings"));
        }
        if room.members.len() >= 16 || room.members.contains_key(&peer) {
            return Err(bad("Room is full or friend is already invited"));
        }
        room.members.insert(
            peer,
            Member {
                user: invited,
                joined: false,
                invited_by: user.id.clone(),
                invited_at: now(),
                client: String::new(),
                is_admin: false,
                moderator_muted: false,
                hand_raised: false,
                speaking_allowed: false,
            },
        );
        room.revision += 1;
        room.clone()
    };
    publish_capable(app, &room);
    if room.voice {
        for member in room.members.values() {
            app.presence(&member.user.id);
        }
    }
    Ok(())
}
pub(super) fn voice_presence(live: &Live, user: &str) -> Option<Value> {
    live.rooms.values().find(|r| r.voice && r.members.get(user).is_some_and(|m| m.joined))
        .map(|r| json!({"room_id":r.id,"participants":r.members.values().filter(|m|m.joined).count()}))
}
pub(super) fn join_voice(app: &App, user: &User, id: String) -> ApiResult<()> {
    let host = {
        let live = app.live.lock().unwrap();
        let room = live
            .rooms
            .get(&id)
            .filter(|r| r.voice)
            .ok_or(bad("Voice room ended"))?;
        room.members
            .values()
            .filter(|m| m.joined)
            .map(|m| m.user.id.clone())
            .collect::<Vec<_>>()
    };
    let mut friend = None;
    for host in host {
        if app.accepted(&user.id, &host)? {
            friend = Some(host);
            break;
        }
    }
    if friend.is_none() {
        return Err(forbidden());
    }
    join_member(app, user, id, friend)
}
pub(super) fn join(app: &App, user: &User, id: String) -> ApiResult<()> {
    join_member(app, user, id, None)
}
fn join_member(app: &App, user: &User, id: String, friend: Option<String>) -> ApiResult<()> {
    let room = {
        let mut live = app.live.lock().unwrap();
        if busy(&live, &user.id) {
            return Err(bad("Finish your current call first"));
        }
        let client = live
            .peers
            .get(&user.id)
            .and_then(|p| p.group_client.clone())
            .ok_or(bad("Update PVP to join"))?;
        let room = live.rooms.get_mut(&id).ok_or(bad("Group call ended"))?;
        if let Some(friend) = friend {
            if !room.members.get(&friend).is_some_and(|m| m.joined) {
                return Err(bad("Your friend left the voice room"));
            }
            if !room.voice || room.members.len() >= 16 {
                return Err(bad("Voice room is full or ended"));
            }
            room.members.insert(
                user.id.clone(),
                Member {
                    user: user.clone(),
                    joined: false,
                    invited_by: user.id.clone(),
                    invited_at: now(),
                    client: String::new(),
                    is_admin: false,
                    moderator_muted: false,
                    hand_raised: false,
                    speaking_allowed: false,
                },
            );
        }
        let member = room.members.get_mut(&user.id).ok_or_else(forbidden)?;
        if now() - member.invited_at >= 120 {
            return Err(bad("Group invitation expired"));
        }
        member.joined = true;
        member.client = client;
        room.revision += 1;
        room.clone()
    };
    publish_capable(app, &room);
    if room.voice {
        for member in room.members.values() {
            app.presence(&member.user.id);
        }
    }
    Ok(())
}
pub(super) fn leave(app: &App, user: &str, id: &str) -> ApiResult<()> {
    let (room, ended) = {
        let mut live = app.live.lock().unwrap();
        let room = live.rooms.get_mut(id).ok_or(bad("Group call ended"))?;
        if room.members.remove(user).is_none() {
            return Err(forbidden());
        }
        room.pairs.retain(|(a, b), _| a != user && b != user);
        room.revision += 1;
        let ended = !room.members.values().any(|m| m.joined);
        let room = room.clone();
        if ended {
            live.rooms.remove(id);
        }
        (room, ended)
    };
    if room.voice {
        app.presence(user);
        for member in room.members.values() {
            app.presence(&member.user.id);
        }
    }
    app.send(user, json!({"type":"room-ended","room_id":id}));
    if ended {
        for member in room.members.keys() {
            app.send(member, json!({"type":"room-ended","room_id":id}));
        }
    } else {
        publish_capable(app, &room);
    }
    guests::left(app, user);
    if room.owner_id.as_deref() == Some(zoom::OWNER) {
        if let Some(meeting) = &room.meeting_id {
            app.db.lock().unwrap().execute(
                "DELETE FROM meeting_members WHERE meeting_id=?1 AND user_id=?2",
                params![meeting, user],
            )?;
            meetings::changed(app, meeting, Some(user));
        }
    }
    Ok(())
}
// Removing a friend revokes invitations from that friend and the remover's
// consent to remain in an already shared room. Other participants can continue.
pub(super) fn friend_removed(app: &App, user: &str, peer: &str) {
    let removals = {
        let live = app.live.lock().unwrap();
        live.rooms
            .values()
            .flat_map(|r| {
                let mut removals = Vec::new();
                if r.members.get(user).is_some_and(|m| m.joined)
                    && r.members.get(peer).is_some_and(|m| m.joined)
                {
                    removals.push((r.id.clone(), user.to_owned()));
                }
                for (id, inviter) in [(user, peer), (peer, user)] {
                    if r.members
                        .get(id)
                        .is_some_and(|m| !m.joined && m.invited_by == inviter)
                    {
                        removals.push((r.id.clone(), id.to_owned()));
                    }
                }
                removals
            })
            .collect::<Vec<_>>()
    };
    for (id, member) in removals {
        let _ = leave(app, &member, &id);
    }
}
// Internal snapshot is bounded by the live-room limit. It is reduced to counts
// before leaving the server; none of these meeting identifiers is public.
pub(super) fn active_room_sizes(app: &App) -> Vec<(String, usize)> {
    let live = app.live.lock().unwrap();
    live.rooms
        .values()
        .filter_map(|room| {
            let id = room.meeting_id.as_ref()?;
            let count = room
                .members
                .values()
                .filter(|m| m.joined && live.peers.contains_key(&m.user.id))
                .count();
            (1..=16).contains(&count).then(|| (id.clone(), count))
        })
        .collect()
}
pub(super) fn meeting_participants(app: &App, id: &str) -> Vec<User> {
    app.live
        .lock()
        .unwrap()
        .rooms
        .values()
        .filter(|r| r.meeting_id.as_deref() == Some(id))
        .flat_map(|r| {
            r.members
                .values()
                .filter(|m| m.joined)
                .map(|m| m.user.clone())
        })
        .collect()
}
pub(super) fn enter_meeting(
    app: &App,
    user: &User,
    meeting_id: String,
    name: String,
    owner: String,
    flags: meetings::MeetingMember,
    requires_moderation: bool,
) -> ApiResult<()> {
    let raise_hand_enabled = meetings::speaking_enabled(app, &meeting_id)?;
    let room = {
        let mut live = app.live.lock().unwrap();
        if busy(&live, &user.id) {
            return Err(bad("Finish your current call first"));
        }
        let peer = live
            .peers
            .get(&user.id)
            .ok_or(bad("Update PVP to join meetings"))?;
        if raise_hand_enabled && !peer.raise_hand {
            return Err(bad("Update PVP to join meetings with raise hand controls"));
        }
        if requires_moderation && !peer.meeting_moderation {
            return Err(bad("Update PVP to join meetings with admin controls"));
        }
        let client = peer
            .group_client
            .clone()
            .ok_or(bad("Update PVP to join meetings"))?;
        let existing = live
            .rooms
            .values()
            .find(|r| r.meeting_id.as_ref() == Some(&meeting_id))
            .map(|r| r.id.clone());
        let id = if let Some(id) = existing {
            id
        } else {
            if live.rooms.len() >= 256 {
                return Err(bad("Group calls are currently busy"));
            }
            let id = Uuid::new_v4().to_string();
            live.rooms.insert(
                id.clone(),
                Room {
                    id: id.clone(),
                    revision: 1,
                    voice: false,
                    raise_hand_enabled,
                    meeting_id: Some(meeting_id),
                    name: Some(name),
                    owner_id: Some(owner),
                    members: HashMap::new(),
                    pairs: HashMap::new(),
                },
            );
            id
        };
        let room = live.rooms.get_mut(&id).unwrap();
        if room.members.len() >= 16 {
            return Err(bad("Meeting is full"));
        }
        room.members.insert(
            user.id.clone(),
            Member {
                user: user.clone(),
                joined: true,
                invited_by: user.id.clone(),
                invited_at: now(),
                client,
                is_admin: flags.is_admin,
                moderator_muted: flags.moderator_muted,
                hand_raised: false,
                speaking_allowed: false,
            },
        );
        room.revision += 1;
        room.clone()
    };
    publish_capable(app, &room);
    if room.voice {
        for member in room.members.values() {
            app.presence(&member.user.id);
        }
    }
    Ok(())
}
// Older apps keep ordinary calls and unmuted recurring calls. When an admin
// imposes an audio block, every remaining receiver must understand that block.
fn remove_legacy_meeting_members(app: &App, id: &str) {
    let removals = {
        let live = app.live.lock().unwrap();
        live.rooms
            .values()
            .filter(|r| r.meeting_id.as_deref() == Some(id))
            .flat_map(|r| {
                r.members
                    .keys()
                    .filter(|user| {
                        live.peers.get(*user).is_some_and(|p| {
                            !p.meeting_moderation || (r.raise_hand_enabled && !p.raise_hand)
                        })
                    })
                    .map(|user| (r.id.clone(), user.clone()))
            })
            .collect::<Vec<_>>()
    };
    for (room, user) in removals {
        app.send(
            &user,
            json!({"type":"error","message":"Update PVP to join meetings with speaking controls"}),
        );
        let _ = leave(app, &user, &room);
    }
}
pub(super) fn sync_meeting_member(app: &App, id: &str, user: &str) -> ApiResult<()> {
    let flags = meetings::member(app, id, user)?;
    if flags.moderator_muted {
        remove_legacy_meeting_members(app, id);
    }
    let room = {
        let mut live = app.live.lock().unwrap();
        let Some(room) = live
            .rooms
            .values_mut()
            .find(|r| r.meeting_id.as_deref() == Some(id))
        else {
            return Ok(());
        };
        if let Some(member) = room.members.get_mut(user) {
            if member.is_admin != flags.is_admin || flags.moderator_muted {
                member.speaking_allowed = false;
                member.hand_raised = false;
            }
            member.is_admin = flags.is_admin;
            member.moderator_muted = flags.moderator_muted;
            room.revision += 1;
            Some(room.clone())
        } else {
            None
        }
    };
    if let Some(room) = room {
        publish_capable(app, &room);
    }
    Ok(())
}
pub(super) fn sync_speaking(app: &App, id: &str, enabled: bool) {
    let room = {
        let mut live = app.live.lock().unwrap();
        let Some(room) = live
            .rooms
            .values_mut()
            .find(|r| r.meeting_id.as_deref() == Some(id))
        else {
            return;
        };
        if room.raise_hand_enabled == enabled {
            return;
        }
        room.raise_hand_enabled = enabled;
        for member in room.members.values_mut() {
            member.hand_raised = false;
            member.speaking_allowed = false;
        }
        room.revision += 1;
        room.clone()
    };
    if enabled {
        remove_legacy_meeting_members(app, id);
    }
    // Removing unsupported clients can change the room revision.
    let room = app.live.lock().unwrap().rooms.get(&room.id).cloned();
    if let Some(room) = room {
        publish_capable(app, &room);
    }
}
pub(super) fn speaking_member(app: &App, id: &str, user: &str) -> ApiResult<(bool, bool)> {
    let live = app.live.lock().unwrap();
    let room = live
        .rooms
        .values()
        .find(|r| r.meeting_id.as_deref() == Some(id) && r.raise_hand_enabled)
        .ok_or(bad("Raise hand to speak is not enabled"))?;
    let member = room
        .members
        .get(user)
        .filter(|m| m.joined && !m.is_admin)
        .ok_or(forbidden())?;
    Ok((member.hand_raised, member.speaking_allowed))
}
pub(super) fn update_speaker(
    app: &App,
    id: &str,
    user: &str,
    raised: bool,
    allowed: bool,
) -> ApiResult<()> {
    speaking_member(app, id, user)?;
    let room = {
        let mut live = app.live.lock().unwrap();
        let room = live
            .rooms
            .values_mut()
            .find(|r| r.meeting_id.as_deref() == Some(id))
            .unwrap();
        let member = room.members.get_mut(user).unwrap();
        member.hand_raised = raised;
        member.speaking_allowed = allowed;
        room.revision += 1;
        room.clone()
    };
    publish_capable(app, &room);
    Ok(())
}
pub(super) fn remove_meeting_member(app: &App, id: &str, user: &str) {
    let ids = app
        .live
        .lock()
        .unwrap()
        .rooms
        .values()
        .filter(|r| r.meeting_id.as_deref() == Some(id) && r.members.contains_key(user))
        .map(|r| r.id.clone())
        .collect::<Vec<_>>();
    for id in ids {
        let _ = leave(app, user, &id);
    }
}
pub(super) fn end_meeting(app: &App, id: &str) {
    let users = meeting_participants(app, id);
    for user in users {
        remove_meeting_member(app, id, &user.id);
    }
}
pub(super) fn disconnect(app: &App, user: &str) {
    let ids = {
        let live = app.live.lock().unwrap();
        live.rooms
            .values()
            .filter(|r| r.members.get(user).is_some_and(|m| m.joined))
            .map(|r| r.id.clone())
            .collect::<Vec<_>>()
    };
    for id in ids {
        let _ = leave(app, user, &id);
    }
}
pub(super) fn expire(app: &App) {
    let expired = {
        let live = app.live.lock().unwrap();
        live.rooms
            .values()
            .flat_map(|r| {
                r.members
                    .values()
                    .filter(|m| !m.joined && now() - m.invited_at >= 120)
                    .map(|m| (r.id.clone(), m.user.id.clone()))
            })
            .collect::<Vec<_>>()
    };
    for (id, user) in expired {
        let _ = leave(app, &user, &id);
    }
}
pub(super) fn signal(
    app: &App,
    user: &User,
    id: String,
    to: String,
    generation: u8,
    payload: Value,
) -> ApiResult<()> {
    if generation == 0 || generation > 8 || !security::valid_signal(&payload) {
        return Err(bad("Invalid encrypted group negotiation"));
    }
    {
        let mut live = app.live.lock().unwrap();
        let room = live.rooms.get_mut(&id).ok_or(bad("Group call ended"))?;
        if to == user.id
            || ![&to, &user.id]
                .iter()
                .all(|p| room.members.get(*p).is_some_and(|m| m.joined))
        {
            return Err(forbidden());
        }
        let (a, b, index) = if user.id < to {
            (user.id.clone(), to.clone(), 0)
        } else {
            (to.clone(), user.id.clone(), 1)
        };
        let pair = room.pairs.entry((a, b)).or_default();
        match payload["type"].as_str().unwrap() {
            "offer" if index == 0 && generation == pair.generation + 1 => {
                pair.generation = generation;
                pair.answer = false;
                pair.candidates = [pair.early_candidates, 0];
                pair.early_candidates = 0;
            }
            "answer" if index == 1 && generation == pair.generation && !pair.answer => {
                pair.answer = true
            }
            "candidate"
                if index == 0
                    && generation == pair.generation + 1
                    && pair.early_candidates < 128 =>
            {
                pair.early_candidates += 1;
            }
            "candidate" if generation == pair.generation && pair.candidates[index] < 128 => {
                pair.candidates[index] += 1
            }
            _ => return Err(bad("Unexpected group signal")),
        }
    }
    app.send(&to,json!({"type":"room-signal","room_id":id,"from":user.id,"generation":generation,"payload":payload}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(n: usize) -> (App, Vec<User>) {
        let app = App::new(":memory:", "http://localhost".into()).unwrap();
        let mut users = Vec::new();
        for i in 0..n {
            let user = User {
                id: format!("p{i:02}"),
                username: format!("person{i}"),
                display_name: format!("Person {i}"),
            };
            app.db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO users VALUES(?1,?2,?3,'unused')",
                    params![user.id, user.username, user.display_name],
                )
                .unwrap();
            if i > 0 {
                app.db
                    .lock()
                    .unwrap()
                    .execute("INSERT INTO friends VALUES('p00',?1,1,0)", [&user.id])
                    .unwrap();
            }
            let (tx, _rx) = mpsc::channel(256);
            app.live.lock().unwrap().peers.insert(
                user.id.clone(),
                Peer {
                    group_client: Some("browser".into()),
                    meeting_moderation: true,
                    raise_hand: true,
                    connection: format!("c{i}"),
                    session: "unused".into(),
                    tx,
                    stop: Arc::new(Notify::new()),
                },
            );
            users.push(user);
        }
        (app, users)
    }
    fn room_id(app: &App) -> String {
        app.live
            .lock()
            .unwrap()
            .rooms
            .keys()
            .next()
            .unwrap()
            .clone()
    }
    #[test]
    fn initiator_trickle_can_precede_offer_without_bypassing_candidate_budget() {
        let (app, u) = fixture(2);
        open_voice(&app, &u[0]).unwrap();
        let id = room_id(&app);
        join_voice(&app, &u[1], id.clone()).unwrap();
        let candidate = json!({"type":"candidate","candidate":{"candidate":"candidate:1 1 udp 2122260223 192.0.2.1 50000 typ host","sdpMid":"0","sdpMLineIndex":0}});
        assert!(signal(
            &app,
            &u[1],
            id.clone(),
            u[0].id.clone(),
            1,
            candidate.clone()
        )
        .is_err());
        for _ in 0..128 {
            signal(
                &app,
                &u[0],
                id.clone(),
                u[1].id.clone(),
                1,
                candidate.clone(),
            )
            .unwrap();
        }
        assert!(signal(
            &app,
            &u[0],
            id.clone(),
            u[1].id.clone(),
            1,
            candidate.clone()
        )
        .is_err());
        let fp = vec!["AA"; 32].join(":");
        let offer = json!({"type":"offer","sdp":format!("v=0\r\na=fingerprint:sha-256 {fp}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n")});
        signal(&app, &u[0], id.clone(), u[1].id.clone(), 1, offer).unwrap();
        assert!(signal(&app, &u[0], id.clone(), u[1].id.clone(), 1, candidate).is_err());
    }
    #[test]
    fn voice_rooms_enforce_capacity_and_use_discovery_instead_of_ringing() {
        let (app, users) = fixture(18);
        open_voice(&app, &users[0]).unwrap();
        let id = room_id(&app);
        assert!(invite(&app, &users[0], id.clone(), users[1].id.clone()).is_err());
        for user in &users[1..16] {
            join_voice(&app, user, id.clone()).unwrap();
        }
        assert!(join_voice(&app, &users[16], id.clone()).is_err());
        leave(&app, &users[1].id, &id).unwrap();
        join_voice(&app, &users[16], id.clone()).unwrap();
        assert_eq!(app.live.lock().unwrap().rooms[&id].members.len(), 16);
    }
    #[test]
    fn voice_rooms_require_online_friend_consent_and_survive_host_departure() {
        let (app, u) = fixture(4);
        app.db
            .lock()
            .unwrap()
            .execute("DELETE FROM friends WHERE recipient='p03'", [])
            .unwrap();
        open_voice(&app, &u[0]).unwrap();
        let id = room_id(&app);
        assert!(voice_presence(&app.live.lock().unwrap(), &u[0].id).is_some());
        assert!(join_voice(&app, &u[3], id.clone()).is_err());
        assert!(join(&app, &u[1], id.clone()).is_err());
        join_voice(&app, &u[1], id.clone()).unwrap();
        join_voice(&app, &u[2], id.clone()).unwrap();
        assert_eq!(app.live.lock().unwrap().rooms[&id].members.len(), 3);
        assert!(join_voice(&app, &u[1], id.clone()).is_err());
        disconnect(&app, &u[0].id);
        assert!(joined(&app.live.lock().unwrap(), &u[1].id));
        assert!(join_voice(&app, &u[3], id.clone()).is_err());
        disconnect(&app, &u[1].id);
        disconnect(&app, &u[2].id);
        assert!(app.live.lock().unwrap().rooms.is_empty());
    }
    #[test]
    fn removing_a_friend_revokes_pending_and_joined_room_consent() {
        let (app, u) = fixture(3);
        create(&app, &u[0], vec![u[1].id.clone(), u[2].id.clone()]).unwrap();
        let id = room_id(&app);
        friend_removed(&app, &u[0].id, &u[1].id);
        assert!(join(&app, &u[1], id.clone()).is_err());
        join(&app, &u[2], id.clone()).unwrap();
        friend_removed(&app, &u[0].id, &u[2].id);
        let live = app.live.lock().unwrap();
        assert!(!joined(&live, &u[0].id));
        assert!(joined(&live, &u[2].id));
    }
    #[test]
    fn admission_requires_invitation_consent_and_mutual_friendship_with_inviter() {
        let (app, u) = fixture(4);
        app.db
            .lock()
            .unwrap()
            .execute("DELETE FROM friends WHERE recipient='p03'", [])
            .unwrap();
        assert!(create(&app, &u[0], vec![u[3].id.clone()]).is_err());
        create(&app, &u[0], vec![u[1].id.clone()]).unwrap();
        let id = room_id(&app);
        assert!(join(&app, &u[2], id.clone()).is_err());
        assert!(signal(
            &app,
            &u[1],
            id.clone(),
            u[0].id.clone(),
            1,
            json!({"type":"offer","sdp":"invalid"})
        )
        .is_err());
        join(&app, &u[1], id.clone()).unwrap();
        assert!(join(&app, &u[1], id.clone()).is_err());
        assert!(invite(&app, &u[2], id.clone(), u[3].id.clone()).is_err());
        leave(&app, &u[1].id, &id).unwrap();
        assert!(!joined(&app.live.lock().unwrap(), &u[1].id));
        leave(&app, &u[0].id, &id).unwrap();
        assert!(app.live.lock().unwrap().rooms.is_empty());
    }
    #[test]
    fn sixteen_member_limit_and_legacy_calls_remain_isolated() {
        let (app, u) = fixture(18);
        assert!(create(&app, &u[0], u[1..17].iter().map(|u| u.id.clone()).collect()).is_err());
        create(&app, &u[0], u[1..16].iter().map(|u| u.id.clone()).collect()).unwrap();
        let id = room_id(&app);
        assert!(invite(&app, &u[0], id.clone(), u[16].id.clone()).is_err());
        for user in &u[1..16] {
            join(&app, user, id.clone()).unwrap();
        }
        assert_eq!(app.live.lock().unwrap().rooms[&id].members.len(), 16);
        assert!(handle_message(
            &app,
            &u[0],
            ClientMessage::Call {
                peer_id: u[16].id.clone()
            }
        )
        .is_err());
        disconnect(&app, &u[0].id);
        assert_eq!(app.live.lock().unwrap().rooms[&id].members.len(), 15);
        assert!(joined(&app.live.lock().unwrap(), &u[1].id));
    }
    #[test]
    fn signals_bind_sender_recipient_room_generation_and_encrypted_transport() {
        let (app, u) = fixture(3);
        create(&app, &u[0], vec![u[1].id.clone()]).unwrap();
        let id = room_id(&app);
        join(&app, &u[1], id.clone()).unwrap();
        let fp = vec!["AA"; 32].join(":");
        let sdp =
            format!("v=0\r\na=fingerprint:sha-256 {fp}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n");
        let offer = json!({"type":"offer","sdp":sdp});
        let answer = json!({"type":"answer","sdp":sdp});
        assert!(signal(&app, &u[2], id.clone(), u[1].id.clone(), 1, offer.clone()).is_err());
        assert!(signal(&app, &u[1], id.clone(), u[0].id.clone(), 1, offer.clone()).is_err());
        signal(&app, &u[0], id.clone(), u[1].id.clone(), 1, offer.clone()).unwrap();
        assert!(signal(&app, &u[0], id.clone(), u[1].id.clone(), 1, offer.clone()).is_err());
        assert!(signal(&app, &u[1], id.clone(), u[0].id.clone(), 2, answer.clone()).is_err());
        signal(&app, &u[1], id.clone(), u[0].id.clone(), 1, answer.clone()).unwrap();
        signal(&app, &u[0], id.clone(), u[1].id.clone(), 2, offer).unwrap();
        assert!(signal(&app, &u[1], id.clone(), u[0].id.clone(), 1, answer).is_err());
        assert!(signal(
            &app,
            &u[0],
            id,
            u[1].id.clone(),
            3,
            json!({"type":"offer","sdp":"v=0\r\nm=audio 9 RTP/AVP 111\r\n"})
        )
        .is_err());
    }
}
