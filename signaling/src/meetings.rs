//! Durable meeting identity and admission; live calls remain ephemeral P2P rooms.
use super::*;
use std::collections::HashSet;

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
#[derive(Clone, Serialize)]
pub(super) struct MeetingMember {
    #[serde(flatten)]
    pub(super) user: User,
    pub(super) is_admin: bool,
    pub(super) moderator_muted: bool,
}
fn members(app: &App, id: &str) -> ApiResult<Vec<MeetingMember>> {
    let db = app.db.lock().unwrap();
    let mut q = db.prepare("SELECT u.id,u.username,u.display_name,(r.owner=u.id OR COALESCE(c.is_admin,0)=1),COALESCE(c.moderator_muted,0) FROM users u JOIN meeting_members m ON m.user_id=u.id JOIN meetings r ON r.id=m.meeting_id LEFT JOIN meeting_controls c ON c.meeting_id=m.meeting_id AND c.user_id=m.user_id WHERE m.meeting_id=?1 ORDER BY u.display_name,u.id")?;
    let users = q
        .query_map([id], |r| {
            Ok(MeetingMember {
                user: User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                },
                is_admin: r.get(3)?,
                moderator_muted: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(q);
    drop(db);
    let mut users = users;
    users.extend(guests::members(app, id));
    Ok(users)
}
pub(super) fn member(app: &App, id: &str, peer: &str) -> ApiResult<MeetingMember> {
    members(app, id)?
        .into_iter()
        .find(|m| m.user.id == peer)
        .ok_or(forbidden())
}
fn administrator(app: &App, user: &User, id: &str) -> ApiResult<String> {
    let (owner, _) = admitted(app, user, id)?;
    if !member(app, id, &user.id)?.is_admin {
        return Err(forbidden());
    }
    Ok(owner)
}
fn admitted(app: &App, user: &User, id: &str) -> ApiResult<(String, String)> {
    if !valid_id(id) {
        return Err(bad("Invalid meeting link"));
    }
    if guests::is_guest(user) {
        guests::scope(app, user, id)?;
    }
    let (owner, name, open, invited, blocked): (String, String, bool, bool, bool) = app.db.lock().unwrap().query_row(
        "SELECT r.owner,r.name,COALESCE(a.open_invite,0),EXISTS(SELECT 1 FROM meeting_members m WHERE m.meeting_id=r.id AND m.user_id=?2),EXISTS(SELECT 1 FROM meeting_blocks b WHERE b.meeting_id=r.id AND b.user_id=?2) FROM meetings r LEFT JOIN meeting_access a ON a.meeting_id=r.id WHERE r.id=?1 AND r.revoked=0",
        params![id,user.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))
        .optional()?.ok_or(forbidden())?;
    if blocked || (!open && (!invited || (owner != user.id && !app.accepted(&owner, &user.id)?))) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "Ask the meeting owner to invite you",
        ));
    }
    let result = (owner, name);
    Ok(result)
}
fn open_invite(app: &App, id: &str) -> ApiResult<bool> {
    Ok(app
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT open_invite FROM meeting_access WHERE meeting_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}
fn describe(app: &App, user: &User, id: &str) -> ApiResult<Value> {
    let (owner, name) = admitted(app, user, id)?;
    Ok(
        json!({"meeting_id":id,"name":name,"open_invite":open_invite(app,id)?,"raise_hand_enabled":speaking_enabled(app,id)?,"network_visible":network_visible(app,id)?,"owner_id":owner,"zoom":owner==zoom::OWNER,"url":format!("{}/#meeting={id}",app.origin.trim_end_matches('/')),"members":members(app,id)?,"participants":rooms::meeting_participants(app,id)}),
    )
}
pub(super) fn public_preview(app: &App, id: &str) -> ApiResult<Value> {
    if !valid_id(id) {
        return Err(bad("Invalid meeting link"));
    }
    let (name, owner): (String, String) = app.db.lock().unwrap().query_row(
        "SELECT r.name,r.owner FROM meetings r JOIN meeting_access a ON a.meeting_id=r.id WHERE r.id=?1 AND r.revoked=0 AND a.open_invite=1",
        [id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(ApiError(StatusCode::FORBIDDEN, "This meeting link is unavailable or requires an invitation"))?;
    Ok(
        json!({"meeting_id":id,"name":name,"open_invite":true,"network_visible":network_visible(app,id)?,"zoom":owner==zoom::OWNER,"url":format!("{}/#meeting={id}",app.origin.trim_end_matches('/'))}),
    )
}
pub(super) async fn preview(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(public_preview(&app, &id)?))
}
pub(super) fn changed(app: &App, id: &str, extra: Option<&str>) {
    if let Ok(users) = members(app, id) {
        for user in users {
            app.send(&user.user.id, json!({"type":"meetings-changed"}));
        }
    }
    if let Some(user) = extra {
        app.send(user, json!({"type":"meetings-changed"}));
    }
}
#[derive(Deserialize)]
pub(super) struct Create {
    name: String,
    #[serde(default)]
    open_invite: bool,
    #[serde(default)]
    peer_ids: Vec<String>,
}
#[derive(Deserialize)]
pub(super) struct Add {
    peer_id: String,
}
pub(super) async fn list(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.participant(&headers)?;
    if guests::is_guest(&user) {
        let id = guests::describe(&app, &user)["meeting_id"]
            .as_str()
            .ok_or_else(forbidden)?
            .to_owned();
        return match describe(&app, &user, &id) {
            Ok(meeting) => Ok(Json(json!([meeting]))),
            Err(error) if error.0 == StatusCode::FORBIDDEN => Ok(Json(json!([]))),
            Err(error) => Err(error),
        };
    }
    let ids = {
        let db = app.db.lock().unwrap();
        let mut q=db.prepare("SELECT r.id FROM meetings r WHERE r.revoked=0 AND (EXISTS(SELECT 1 FROM meeting_members m WHERE m.meeting_id=r.id AND m.user_id=?1) OR EXISTS(SELECT 1 FROM meeting_visits v WHERE v.meeting_id=r.id AND v.user_id=?1)) ORDER BY r.created DESC,r.id LIMIT 100")?;
        let ids = q
            .query_map([&user.id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids
    };
    Ok(Json(Value::Array(
        ids.iter()
            .map(|id| describe(&app, &user, id))
            .collect::<ApiResult<Vec<_>>>()?,
    )))
}
pub(super) async fn get(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.participant(&headers)?;
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(data): Json<Create>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let name = data.name.trim();
    if user.username.starts_with('~') && !data.open_invite {
        return Err(bad("Guest meetings must allow anyone with the link"));
    }
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err(bad("Choose a meeting name of 1–80 characters"));
    }
    let peers = data.peer_ids.into_iter().collect::<HashSet<_>>();
    if peers.len() > 15 || peers.contains(&user.id) {
        return Err(bad("Meetings support up to 16 members"));
    }
    if app.limited(format!("meeting-create:{}", user.id), 10, 60) {
        return Err(bad("Too many meeting links"));
    }
    for peer in &peers {
        if !app.accepted(&user.id, peer)? {
            return Err(forbidden());
        }
    }
    let id = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    {
        let mut db = app.db.lock().unwrap();
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM meetings WHERE owner=?1 AND revoked=0",
            [&user.id],
            |r| r.get(0),
        )?;
        if count >= 100 {
            return Err(bad("You already have 100 meetings"));
        }
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO meetings VALUES(?1,?2,?3,?4,0)",
            params![id, user.id, name, now()],
        )?;
        tx.execute(
            "INSERT INTO meeting_access(meeting_id,open_invite) VALUES(?1,?2)",
            params![id, data.open_invite],
        )?;
        for member in peers.iter().chain(std::iter::once(&user.id)) {
            tx.execute(
                "INSERT INTO meeting_members(meeting_id,user_id) VALUES(?1,?2)",
                params![id, member],
            )?;
        }
        tx.commit()?;
    }
    changed(&app, &id, None);
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) async fn add(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(data): Json<Add>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let (owner, _) = admitted(&app, &user, &id)?;
    if owner != user.id || !app.accepted(&user.id, &data.peer_id)? {
        return Err(forbidden());
    }
    {
        let db = app.db.lock().unwrap();
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM meeting_members WHERE meeting_id=?1",
            [&id],
            |r| r.get(0),
        )?;
        if count + guests::members(&app, &id).len() as i64 >= 16 {
            return Err(bad("Meeting is full"));
        }
        db.execute(
            "INSERT OR IGNORE INTO meeting_members(meeting_id,user_id) VALUES(?1,?2)",
            params![id, data.peer_id],
        )?;
    }
    app.db.lock().unwrap().execute(
        "DELETE FROM meeting_blocks WHERE meeting_id=?1 AND user_id=?2",
        params![id, data.peer_id],
    )?;
    changed(&app, &id, None);
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) async fn remove(
    State(app): State<App>,
    headers: HeaderMap,
    Path((id, peer)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let owner = administrator(&app, &user, &id)?;
    if peer == owner || peer == user.id {
        return Err(forbidden());
    }
    member(&app, &id, &peer)?;
    if peer.starts_with("guest-") {
        guests::moderate(&app, &id, &peer, None)?;
        rooms::remove_meeting_member(&app, &id, &peer);
        changed(&app, &id, Some(&peer));
        return Ok(Json(describe(&app, &user, &id)?));
    }
    app.db.lock().unwrap().execute(
        "INSERT OR IGNORE INTO meeting_blocks(meeting_id,user_id) VALUES(?1,?2)",
        params![id, peer],
    )?;
    app.db.lock().unwrap().execute(
        "DELETE FROM meeting_members WHERE meeting_id=?1 AND user_id=?2",
        params![id, peer],
    )?;
    rooms::remove_meeting_member(&app, &id, &peer);
    changed(&app, &id, Some(&peer));
    Ok(Json(describe(&app, &user, &id)?))
}
#[derive(Deserialize)]
pub(super) struct Admin {
    admin: bool,
}
#[derive(Deserialize)]
pub(super) struct Mute {
    muted: bool,
}
pub(super) async fn set_admin(
    State(app): State<App>,
    headers: HeaderMap,
    Path((id, peer)): Path<(String, String)>,
    Json(data): Json<Admin>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let (owner, _) = admitted(&app, &user, &id)?;
    if owner != user.id || peer == owner {
        return Err(forbidden());
    }
    if peer.starts_with("guest-") {
        return Err(forbidden());
    }
    member(&app, &id, &peer)?;
    if app.limited(format!("meeting-moderate:{}", user.id), 60, 60) {
        return Err(bad("Too many moderation changes"));
    }
    app.db.lock().unwrap().execute(
        "INSERT INTO meeting_controls(meeting_id,user_id,is_admin) VALUES(?1,?2,?3) ON CONFLICT(meeting_id,user_id) DO UPDATE SET is_admin=excluded.is_admin",
        params![id, peer, data.admin],
    )?;
    rooms::sync_meeting_member(&app, &id, &peer)?;
    changed(&app, &id, None);
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) async fn set_mute(
    State(app): State<App>,
    headers: HeaderMap,
    Path((id, peer)): Path<(String, String)>,
    Json(data): Json<Mute>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let owner = administrator(&app, &user, &id)?;
    if peer == owner || peer == user.id {
        return Err(forbidden());
    }
    member(&app, &id, &peer)?;
    if app.limited(format!("meeting-moderate:{}", user.id), 60, 60) {
        return Err(bad("Too many moderation changes"));
    }
    if peer.starts_with("guest-") {
        guests::moderate(&app, &id, &peer, Some(data.muted))?;
        rooms::sync_meeting_member(&app, &id, &peer)?;
        changed(&app, &id, None);
        return Ok(Json(describe(&app, &user, &id)?));
    }
    app.db.lock().unwrap().execute(
        "INSERT INTO meeting_controls(meeting_id,user_id,moderator_muted) VALUES(?1,?2,?3) ON CONFLICT(meeting_id,user_id) DO UPDATE SET moderator_muted=excluded.moderator_muted",
        params![id, peer, data.muted],
    )?;
    rooms::sync_meeting_member(&app, &id, &peer)?;
    changed(&app, &id, None);
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) fn network_visible(app: &App, id: &str) -> ApiResult<bool> {
    Ok(app
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT visible FROM meeting_network WHERE meeting_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}
#[derive(Deserialize)]
pub(super) struct NetworkVisibility {
    pub(super) visible: bool,
}
pub(super) async fn set_network(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(data): Json<NetworkVisibility>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let (owner, _) = admitted(&app, &user, &id)?;
    if owner != user.id {
        return Err(forbidden());
    }
    if data.visible && !open_invite(&app, &id)? {
        return Err(bad(
            "Only link-accessible rooms can share anonymous activity",
        ));
    }
    app.db.lock().unwrap().execute("INSERT INTO meeting_network(meeting_id,visible) VALUES(?1,?2) ON CONFLICT(meeting_id) DO UPDATE SET visible=excluded.visible", params![id,data.visible])?;
    changed(&app, &id, None);
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) fn speaking_enabled(app: &App, id: &str) -> ApiResult<bool> {
    Ok(app
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT enabled FROM meeting_speaking WHERE meeting_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}
#[derive(Deserialize)]
pub(super) struct Speaking {
    enabled: bool,
}
#[derive(Deserialize)]
pub(super) struct Hand {
    raised: bool,
}
#[derive(Deserialize)]
pub(super) struct Speaker {
    allowed: bool,
}
pub(super) async fn set_speaking(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(data): Json<Speaking>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    administrator(&app, &user, &id)?;
    if app.limited(format!("meeting-moderate:{}", user.id), 60, 60) {
        return Err(bad("Too many moderation changes"));
    }
    app.db.lock().unwrap().execute("INSERT INTO meeting_speaking(meeting_id,enabled) VALUES(?1,?2) ON CONFLICT(meeting_id) DO UPDATE SET enabled=excluded.enabled", params![id, data.enabled])?;
    rooms::sync_speaking(&app, &id, data.enabled);
    changed(&app, &id, None);
    Ok(Json(describe(&app, &user, &id)?))
}
pub(super) async fn set_hand(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(data): Json<Hand>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.participant(&headers)?;
    admitted(&app, &user, &id)?;
    let (_, allowed) = rooms::speaking_member(&app, &id, &user.id)?;
    if data.raised && allowed {
        return Err(bad("You already have permission to speak"));
    }
    if app.limited(format!("meeting-hand:{}", user.id), 60, 60) {
        return Err(bad("Too many hand changes"));
    }
    rooms::update_speaker(&app, &id, &user.id, data.raised, false)?;
    Ok(Json(json!({"ok":true})))
}
pub(super) async fn set_speaker(
    State(app): State<App>,
    headers: HeaderMap,
    Path((id, peer)): Path<(String, String)>,
    Json(data): Json<Speaker>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    administrator(&app, &user, &id)?;
    let (raised, allowed) = rooms::speaking_member(&app, &id, &peer)?;
    if data.allowed && !raised && !allowed {
        return Err(bad("Wait for this person to raise their hand"));
    }
    if app.limited(format!("meeting-moderate:{}", user.id), 60, 60) {
        return Err(bad("Too many moderation changes"));
    }
    if data.allowed {
        if peer.starts_with("guest-") {
            guests::moderate(&app, &id, &peer, Some(false))?;
        } else {
            app.db.lock().unwrap().execute(
                "UPDATE meeting_controls SET moderator_muted=0 WHERE meeting_id=?1 AND user_id=?2",
                params![id, peer],
            )?;
        }
        rooms::sync_meeting_member(&app, &id, &peer)?;
    }
    rooms::update_speaker(&app, &id, &peer, false, data.allowed)?;
    Ok(Json(json!({"ok":true})))
}
pub(super) async fn revoke(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let (owner, _) = admitted(&app, &user, &id)?;
    if owner != user.id {
        return Err(forbidden());
    }
    app.db
        .lock()
        .unwrap()
        .execute("UPDATE meetings SET revoked=1 WHERE id=?1", [&id])?;
    rooms::end_meeting(&app, &id);
    changed(&app, &id, None);
    Ok(Json(json!({"ok":true})))
}
pub(super) fn enter(app: &App, user: &User, id: String) -> ApiResult<()> {
    let (owner, name) = admitted(app, user, &id)?;
    if app.limited(format!("meeting-enter:{}", user.id), 30, 60) {
        return Err(bad("Too many meeting joins"));
    }
    let mut enrolled = false;
    if guests::is_guest(user) {
        if members(app, &id)?.len() >= 16 {
            return Err(bad("Meeting is full"));
        }
        guests::enroll(app, user, &id)?;
    } else if open_invite(app, &id)? {
        let db = app.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM meeting_members WHERE meeting_id=?1 AND user_id=?2)",
            params![id, user.id],
            |r| r.get(0),
        )?;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM meeting_members WHERE meeting_id=?1",
            [&id],
            |r| r.get(0),
        )?;
        if !exists && count + guests::members(app, &id).len() as i64 >= 16 {
            return Err(bad("Meeting is full"));
        }
        enrolled = db.execute(
            "INSERT OR IGNORE INTO meeting_members(meeting_id,user_id) VALUES(?1,?2)",
            params![id, user.id],
        )? > 0;
    }
    let flags = member(app, &id, &user.id)?;
    let requires_moderation =
        speaking_enabled(app, &id)? || members(app, &id)?.iter().any(|m| m.moderator_muted);
    let zoom = owner == zoom::OWNER;
    let result = rooms::enter_meeting(
        app,
        user,
        id.clone(),
        name,
        owner,
        flags,
        requires_moderation,
    );
    if guests::is_guest(user) {
        if result.is_err() {
            guests::left(app, &user.id);
        } else {
            changed(app, &id, None);
        }
    }
    if enrolled {
        if result.is_err() {
            app.db.lock().unwrap().execute(
                "DELETE FROM meeting_members WHERE meeting_id=?1 AND user_id=?2",
                params![id, user.id],
            )?;
        } else {
            if zoom {
                app.db.lock().unwrap().execute(
                    "INSERT OR IGNORE INTO meeting_visits VALUES(?1,?2)",
                    params![id, user.id],
                )?;
            }
            changed(app, &id, None);
        }
    }
    result
}
pub(super) fn friend_removed(app: &App, user: &str, peer: &str) -> ApiResult<()> {
    let removals: Vec<(String, String)> = {
        let db = app.db.lock().unwrap();
        let mut q = db.prepare("SELECT r.id,m.user_id FROM meetings r JOIN meeting_members m ON m.meeting_id=r.id WHERE ((r.owner=?1 AND m.user_id=?2) OR (r.owner=?2 AND m.user_id=?1)) AND NOT EXISTS(SELECT 1 FROM meeting_access a WHERE a.meeting_id=r.id AND a.open_invite=1)")?;
        let rows = q
            .query_map(params![user, peer], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (id, member) in removals {
        app.db.lock().unwrap().execute(
            "DELETE FROM meeting_members WHERE meeting_id=?1 AND user_id=?2",
            params![id, member],
        )?;
        rooms::remove_meeting_member(app, &id, &member);
        changed(app, &id, Some(&member));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(path: &str, n: usize) -> (App, Vec<User>, Vec<HeaderMap>) {
        let app = App::new(path, "https://lopixel.space".into()).unwrap();
        let mut users = Vec::new();
        let mut headers = Vec::new();
        for i in 0..n {
            let user = User {
                id: format!("m{i:02}"),
                username: format!("meeting{i}"),
                display_name: format!("Member {i}"),
            };
            let token = format!("{i:064x}");
            {
                let db = app.db.lock().unwrap();
                db.execute(
                    "INSERT INTO users VALUES(?1,?2,?3,'unused')",
                    params![user.id, user.username, user.display_name],
                )
                .unwrap();
                db.execute(
                    "INSERT INTO sessions VALUES(?1,?2,?3)",
                    params![token_hash(&token), user.id, now() + 86400],
                )
                .unwrap();
                if i > 0 {
                    db.execute("INSERT INTO friends VALUES('m00',?1,1,0)", [&user.id])
                        .unwrap();
                }
            }
            let mut h = HeaderMap::new();
            h.insert("cookie", format!("pvp_session={token}").parse().unwrap());
            headers.push(h);
            connect(&app, &user);
            users.push(user);
        }
        (app, users, headers)
    }
    fn connect(app: &App, user: &User) {
        let (tx, _rx) = mpsc::channel(256);
        app.live.lock().unwrap().peers.insert(
            user.id.clone(),
            Peer {
                group_client: Some("browser".into()),
                meeting_moderation: true,
                raise_hand: true,
                connection: Uuid::new_v4().to_string(),
                session: "unused".into(),
                tx,
                stop: Arc::new(Notify::new()),
            },
        );
    }
    async fn make(app: &App, h: &HeaderMap, ids: Vec<String>) -> Value {
        create(
            State(app.clone()),
            h.clone(),
            Json(Create {
                open_invite: false,
                name: "Weekly catch-up".into(),
                peer_ids: ids,
            }),
        )
        .await
        .unwrap()
        .0
    }
    #[tokio::test]
    async fn homepage_network_is_opt_in_owner_only_and_contains_only_size_counts() {
        let (app, u, h) = fixture(":memory:", 3);
        let private = make(&app, &h[0], vec![]).await;
        let private_id = private["meeting_id"].as_str().unwrap().to_owned();
        assert!(!network_visible(&app, &private_id).unwrap());
        assert!(set_network(
            State(app.clone()),
            h[0].clone(),
            Path(private_id),
            Json(NetworkVisibility { visible: true })
        )
        .await
        .is_err());
        let m = create(
            State(app.clone()),
            h[0].clone(),
            Json(Create {
                name: "A secret room name".into(),
                open_invite: true,
                peer_ids: vec![],
            }),
        )
        .await
        .unwrap()
        .0;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        enter(&app, &u[0], id.clone()).unwrap();
        enter(&app, &u[1], id.clone()).unwrap();
        assert_eq!(
            super::super::network::snapshot(State(app.clone()))
                .await
                .unwrap()
                .0["rooms"],
            json!([])
        );
        assert!(set_network(
            State(app.clone()),
            h[1].clone(),
            Path(id.clone()),
            Json(NetworkVisibility { visible: true })
        )
        .await
        .is_err());
        assert!(set_network(
            State(app.clone()),
            HeaderMap::new(),
            Path(id.clone()),
            Json(NetworkVisibility { visible: true })
        )
        .await
        .is_err());
        let _ = set_network(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(NetworkVisibility { visible: true }),
        )
        .await
        .unwrap();
        let snapshot = super::super::network::snapshot(State(app.clone()))
            .await
            .unwrap()
            .0;
        assert_eq!(snapshot["rooms"], json!([{ "peers":2,"count":1 }]));
        let encoded = snapshot.to_string();
        for secret in [
            &id,
            "A secret room name",
            &u[0].id,
            &u[0].username,
            "address",
            "fingerprint",
            "meeting_id",
            "session",
            "candidate",
        ] {
            assert!(!encoded.contains(secret));
        }
        app.live.lock().unwrap().peers.remove(&u[1].id);
        assert_eq!(
            super::super::network::snapshot(State(app.clone()))
                .await
                .unwrap()
                .0["rooms"],
            json!([{ "peers":1,"count":1 }])
        );
        let _ = set_network(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(NetworkVisibility { visible: false }),
        )
        .await
        .unwrap();
        assert_eq!(
            super::super::network::snapshot(State(app.clone()))
                .await
                .unwrap()
                .0["rooms"],
            json!([])
        );
        let _ = set_network(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(NetworkVisibility { visible: true }),
        )
        .await
        .unwrap();
        let _ = revoke(State(app.clone()), h[0].clone(), Path(id))
            .await
            .unwrap();
        assert_eq!(
            super::super::network::snapshot(State(app)).await.unwrap().0["rooms"],
            json!([])
        );
    }
    #[tokio::test]
    async fn open_link_admission_and_kick_are_durable_and_private_stays_private() {
        let (app, users, headers) = fixture(":memory:", 18);
        app.db
            .lock()
            .unwrap()
            .execute("DELETE FROM friends", [])
            .unwrap();
        let private = make(&app, &headers[0], vec![]).await;
        assert!(describe(&app, &users[1], private["meeting_id"].as_str().unwrap()).is_err());
        let open = create(
            State(app.clone()),
            headers[0].clone(),
            Json(Create {
                name: "Open weekly meeting".into(),
                peer_ids: vec![],
                open_invite: true,
            }),
        )
        .await
        .unwrap()
        .0;
        let id = open["meeting_id"].as_str().unwrap();
        assert_eq!(open["open_invite"], true);
        assert!(describe(&app, &users[1], id).is_ok());
        assert!(
            member(&app, id, &users[1].id).is_err(),
            "preview never enrolls a visitor"
        );
        enter(&app, &users[1], id.into()).unwrap();
        assert!(!member(&app, id, &users[1].id).unwrap().is_admin);
        assert!(set_admin(
            State(app.clone()),
            headers[1].clone(),
            Path((id.into(), users[1].id.clone())),
            Json(Admin { admin: true })
        )
        .await
        .is_err());
        friend_removed(&app, &users[0].id, &users[1].id).unwrap();
        assert!(
            member(&app, id, &users[1].id).is_ok(),
            "open membership independent of friendship"
        );
        let _ = remove(
            State(app.clone()),
            headers[0].clone(),
            Path((id.into(), users[1].id.clone())),
        )
        .await
        .unwrap();
        assert!(enter(&app, &users[1], id.into()).is_err());
        assert!(describe(&app, &users[1], id).is_err());
        enter(&app, &users[0], id.into()).unwrap();
        for user in users.iter().take(17).skip(2) {
            enter(&app, user, id.into()).unwrap();
        }
        assert!(
            enter(&app, &users[17], id.into()).is_err(),
            "sixteen member cap includes owner"
        );
        assert_eq!(members(&app, id).unwrap().len(), 16);
        let path = std::env::temp_dir().join(format!("pvp-open-{}.sqlite", Uuid::new_v4()));
        app.db
            .lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
            .unwrap();
        let restored = App::new(path.to_str().unwrap(), app.origin.clone()).unwrap();
        assert!(open_invite(&restored, id).unwrap());
        assert!(
            describe(&restored, &users[1], id).is_err(),
            "kick block survives backup/restore"
        );
        let _ = revoke(State(app.clone()), headers[0].clone(), Path(id.into()))
            .await
            .unwrap();
        assert!(describe(&app, &users[17], id).is_err());
    }
    #[tokio::test]
    async fn durable_identity_survives_empty_call_restart_and_database_migration() {
        let path = std::env::temp_dir().join(format!("pvp-meeting-{}.sqlite", Uuid::new_v4()));
        let moved = path.with_extension("moved.sqlite");
        let (app, u, h) = fixture(path.to_str().unwrap(), 3);
        let m = make(&app, &h[0], vec![u[1].id.clone(), u[2].id.clone()]).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        assert!(valid_id(&id));
        assert_eq!(m["url"], format!("https://lopixel.space/#meeting={id}"));
        let _ = set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Admin { admin: true }),
        )
        .await
        .unwrap();
        let _ = set_mute(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Mute { muted: true }),
        )
        .await
        .unwrap();
        // Owner can be offline. The first invited member creates the live room.
        app.live.lock().unwrap().peers.remove(&u[0].id);
        enter(&app, &u[1], id.clone()).unwrap();
        enter(&app, &u[2], id.clone()).unwrap();
        assert_eq!(app.live.lock().unwrap().rooms.len(), 1);
        let live_id = app
            .live
            .lock()
            .unwrap()
            .rooms
            .keys()
            .next()
            .unwrap()
            .clone();
        rooms::leave(&app, &u[1].id, &live_id).unwrap();
        rooms::leave(&app, &u[2].id, &live_id).unwrap();
        assert!(app.live.lock().unwrap().rooms.is_empty());
        enter(&app, &u[2], id.clone()).unwrap();
        assert_ne!(
            app.live.lock().unwrap().rooms.keys().next().unwrap(),
            &live_id
        );
        drop(app);
        // Reopening the same SQLite store is the service restart path.
        let restarted = App::new(path.to_str().unwrap(), "https://lopixel.space".into()).unwrap();
        assert_eq!(describe(&restarted, &u[1], &id).unwrap()["url"], m["url"]);
        assert_eq!(members(&restarted, &id).unwrap().len(), 3);
        assert!(member(&restarted, &id, &u[1].id).unwrap().is_admin);
        assert!(member(&restarted, &id, &u[2].id).unwrap().moderator_muted);
        assert!(restarted.live.lock().unwrap().rooms.is_empty());
        drop(restarted);
        // A checkpointed closed DB restored at a new instance/path preserves links.
        std::fs::copy(&path, &moved).unwrap();
        let migrated = App::new(moved.to_str().unwrap(), "https://lopixel.space".into()).unwrap();
        connect(&migrated, &u[1]);
        enter(&migrated, &u[1], id.clone()).unwrap();
        assert_eq!(describe(&migrated, &u[1], &id).unwrap()["url"], m["url"]);
        drop(migrated);
        for p in [&path, &moved] {
            let _ = std::fs::remove_file(p);
        }
    }
    #[tokio::test]
    async fn admission_requires_roster_and_accepted_friendship_and_owner_controls() {
        let (app, u, h) = fixture(":memory:", 4);
        let m = make(&app, &h[0], vec![u[1].id.clone()]).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        assert!(enter(&app, &u[2], id.clone()).is_err());
        assert!(get(State(app.clone()), h[2].clone(), Path(id.clone()))
            .await
            .is_err());
        assert!(add(
            State(app.clone()),
            h[1].clone(),
            Path(id.clone()),
            Json(Add {
                peer_id: u[2].id.clone()
            })
        )
        .await
        .is_err());
        let _ = add(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Add {
                peer_id: u[2].id.clone(),
            }),
        )
        .await
        .unwrap();
        enter(&app, &u[1], id.clone()).unwrap();
        enter(&app, &u[2], id.clone()).unwrap();
        let _ = remove(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
        )
        .await
        .unwrap();
        assert!(enter(&app, &u[1], id.clone()).is_err());
        assert_eq!(rooms::meeting_participants(&app, &id).len(), 1);
        assert!(remove(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[0].id.clone()))
        )
        .await
        .is_err());
        // Defense in depth if a database error left a roster row after unfriend.
        app.db
            .lock()
            .unwrap()
            .execute("DELETE FROM friends WHERE recipient=?1", [&u[2].id])
            .unwrap();
        assert!(admitted(&app, &u[2], &id).is_err());
        friend_removed(&app, &u[0].id, &u[2].id).unwrap();
        assert!(rooms::meeting_participants(&app, &id).is_empty());
        assert_eq!(members(&app, &id).unwrap().len(), 1);
        assert!(revoke(State(app.clone()), h[1].clone(), Path(id.clone()))
            .await
            .is_err());
        enter(&app, &u[0], id.clone()).unwrap();
        let _ = revoke(State(app.clone()), h[0].clone(), Path(id.clone()))
            .await
            .unwrap();
        assert!(enter(&app, &u[0], id).is_err());
        assert!(app.live.lock().unwrap().rooms.is_empty());
        assert_eq!(list(State(app), h[0].clone()).await.unwrap().0, json!([]));
    }
    #[tokio::test]
    async fn names_membership_and_sixteen_member_limit_are_validated() {
        let (app, u, h) = fixture(":memory:", 18);
        assert!(create(
            State(app.clone()),
            h[0].clone(),
            Json(Create {
                open_invite: false,
                name: "\n".into(),
                peer_ids: vec![]
            })
        )
        .await
        .is_err());
        assert!(create(
            State(app.clone()),
            h[0].clone(),
            Json(Create {
                open_invite: false,
                name: "Weekly".into(),
                peer_ids: u[1..17].iter().map(|u| u.id.clone()).collect()
            })
        )
        .await
        .is_err());
        let m = make(&app, &h[0], u[1..16].iter().map(|u| u.id.clone()).collect()).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        assert_eq!(m["members"].as_array().unwrap().len(), 16);
        assert!(add(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Add {
                peer_id: u[16].id.clone()
            })
        )
        .await
        .is_err());
        for user in &u[..16] {
            enter(&app, user, id.clone()).unwrap();
        }
        assert_eq!(rooms::meeting_participants(&app, &id).len(), 16);
        assert!(enter(&app, &u[16], id).is_err());
    }
    #[tokio::test]
    async fn creator_controls_persistent_admin_roles_and_admins_mute_and_kick() {
        let (app, u, h) = fixture(":memory:", 4);
        let m = make(&app, &h[0], u[1..].iter().map(|u| u.id.clone()).collect()).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        assert!(member(&app, &id, &u[0].id).unwrap().is_admin);
        assert!(!member(&app, &id, &u[1].id).unwrap().is_admin);
        assert!(set_admin(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Admin { admin: true })
        )
        .await
        .is_err());
        let _ = set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Admin { admin: true }),
        )
        .await
        .unwrap();
        assert!(member(&app, &id, &u[1].id).unwrap().is_admin);
        for user in &u {
            enter(&app, user, id.clone()).unwrap();
        }
        assert!(set_mute(
            State(app.clone()),
            h[2].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Mute { muted: true })
        )
        .await
        .is_err());
        assert!(remove(
            State(app.clone()),
            h[2].clone(),
            Path((id.clone(), u[1].id.clone()))
        )
        .await
        .is_err());
        assert!(set_mute(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[0].id.clone())),
            Json(Mute { muted: true })
        )
        .await
        .is_err());
        assert!(remove(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[0].id.clone()))
        )
        .await
        .is_err());
        assert!(set_admin(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Admin { admin: true })
        )
        .await
        .is_err());
        let _ = set_mute(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Mute { muted: true }),
        )
        .await
        .unwrap();
        assert!(member(&app, &id, &u[2].id).unwrap().moderator_muted);
        let snapshot = app
            .live
            .lock()
            .unwrap()
            .rooms
            .values()
            .next()
            .unwrap()
            .snapshot_for_test();
        assert!(snapshot["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["id"] == u[2].id && m["moderator_muted"] == true));
        let _ = set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[3].id.clone())),
            Json(Admin { admin: true }),
        )
        .await
        .unwrap();
        let _ = set_mute(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[3].id.clone())),
            Json(Mute { muted: true }),
        )
        .await
        .unwrap();
        let _ = remove(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[3].id.clone())),
        )
        .await
        .unwrap();
        assert!(enter(&app, &u[3], id.clone()).is_err());
        assert_eq!(rooms::meeting_participants(&app, &id).len(), 3);
        let controls: i64 = app
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM meeting_controls WHERE meeting_id=?1 AND user_id=?2",
                params![id, u[3].id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(controls, 0, "kicking cascades to role and mute state");
        let _ = add(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Add {
                peer_id: u[3].id.clone(),
            }),
        )
        .await
        .unwrap();
        let readded = member(&app, &id, &u[3].id).unwrap();
        assert!(!readded.is_admin && !readded.moderator_muted);

        let _ = set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Admin { admin: false }),
        )
        .await
        .unwrap();
        // Stale UI/API requests after demotion cannot keep exercising admin powers.
        assert!(set_mute(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Mute { muted: false })
        )
        .await
        .is_err());
        assert!(remove(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone()))
        )
        .await
        .is_err());
        let _ = set_mute(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Mute { muted: false }),
        )
        .await
        .unwrap();
        assert!(!member(&app, &id, &u[2].id).unwrap().moderator_muted);
        assert!(set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id, u[0].id.clone())),
            Json(Admin { admin: false })
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn legacy_calls_continue_but_admin_mutes_require_capable_receivers() {
        let (app, u, h) = fixture(":memory:", 3);
        app.live
            .lock()
            .unwrap()
            .peers
            .get_mut(&u[2].id)
            .unwrap()
            .meeting_moderation = false;
        let m = make(&app, &h[0], u[1..].iter().map(|u| u.id.clone()).collect()).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        enter(&app, &u[0], id.clone()).unwrap();
        enter(&app, &u[1], id.clone()).unwrap();
        enter(&app, &u[2], id.clone()).unwrap();
        let _ = set_mute(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Mute { muted: true }),
        )
        .await
        .unwrap();
        assert_eq!(rooms::meeting_participants(&app, &id).len(), 2);
        assert!(enter(&app, &u[2], id.clone()).is_err());
        // Receiver support can be advertised on reconnect/update.
        rooms::capabilities(&app, &u[2], "browser".into(), true).unwrap();
        enter(&app, &u[2], id.clone()).unwrap();
        rooms::capabilities(&app, &u[2], "browser".into(), false).unwrap();
        assert_eq!(rooms::meeting_participants(&app, &id).len(), 2);
        let _ = set_mute(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Mute { muted: false }),
        )
        .await
        .unwrap();
        enter(&app, &u[2], id).unwrap();
        let old: ClientMessage =
            serde_json::from_value(json!({"type":"room-capabilities","client":"mac"})).unwrap();
        assert!(matches!(
            old,
            ClientMessage::RoomCapabilities {
                meeting_moderation: false,
                ..
            }
        ));
    }
    #[tokio::test]
    async fn raised_hands_require_current_admin_approval_and_reset_on_departure() {
        let (app, u, h) = fixture(":memory:", 4);
        let m = make(&app, &h[0], vec![u[1].id.clone(), u[2].id.clone()]).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        assert_eq!(m["raise_hand_enabled"], false);
        assert!(set_speaking(
            State(app.clone()),
            h[2].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: true })
        )
        .await
        .is_err());
        assert!(set_speaking(
            State(app.clone()),
            h[3].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: true })
        )
        .await
        .is_err());
        let _ = set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Admin { admin: true }),
        )
        .await
        .unwrap();
        let _ = set_speaking(
            State(app.clone()),
            h[1].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: true }),
        )
        .await
        .unwrap();
        assert!(
            set_hand(
                State(app.clone()),
                h[2].clone(),
                Path(id.clone()),
                Json(Hand { raised: true })
            )
            .await
            .is_err(),
            "only live participants can raise a hand"
        );
        for user in &u[..3] {
            enter(&app, user, id.clone()).unwrap();
        }
        let snapshot = || {
            app.live
                .lock()
                .unwrap()
                .rooms
                .values()
                .next()
                .unwrap()
                .snapshot_for_test()
        };
        let participant = |index: usize| {
            snapshot()["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["id"] == u[index].id)
                .unwrap()
                .clone()
        };
        assert_eq!(participant(0)["moderator_muted"], false);
        assert_eq!(participant(1)["moderator_muted"], false);
        assert_eq!(
            participant(2)["moderator_muted"],
            true,
            "receivers must block unapproved audio"
        );
        assert!(
            set_speaker(
                State(app.clone()),
                h[0].clone(),
                Path((id.clone(), u[2].id.clone())),
                Json(Speaker { allowed: true })
            )
            .await
            .is_err(),
            "approval requires a request"
        );
        let _ = set_hand(
            State(app.clone()),
            h[2].clone(),
            Path(id.clone()),
            Json(Hand { raised: true }),
        )
        .await
        .unwrap();
        assert_eq!(participant(2)["hand_raised"], true);
        assert!(
            set_speaker(
                State(app.clone()),
                h[2].clone(),
                Path((id.clone(), u[2].id.clone())),
                Json(Speaker { allowed: true })
            )
            .await
            .is_err(),
            "participants cannot approve themselves"
        );
        let _ = set_speaker(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Speaker { allowed: true }),
        )
        .await
        .unwrap();
        assert_eq!(participant(2)["speaking_allowed"], true);
        assert_eq!(participant(2)["hand_raised"], false);
        assert_eq!(participant(2)["moderator_muted"], false);
        let _ = set_hand(
            State(app.clone()),
            h[2].clone(),
            Path(id.clone()),
            Json(Hand { raised: false }),
        )
        .await
        .unwrap();
        assert_eq!(
            participant(2)["moderator_muted"],
            true,
            "finishing a turn revokes permission"
        );
        let _ = set_hand(
            State(app.clone()),
            h[2].clone(),
            Path(id.clone()),
            Json(Hand { raised: true }),
        )
        .await
        .unwrap();
        let _ = set_speaker(
            State(app.clone()),
            h[1].clone(),
            Path((id.clone(), u[2].id.clone())),
            Json(Speaker { allowed: true }),
        )
        .await
        .unwrap();
        rooms::disconnect(&app, &u[2].id);
        enter(&app, &u[2], id.clone()).unwrap();
        assert_eq!(participant(2)["speaking_allowed"], false);
        assert_eq!(participant(2)["hand_raised"], false);
        let _ = set_admin(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Admin { admin: false }),
        )
        .await
        .unwrap();
        assert_eq!(
            participant(1)["moderator_muted"],
            true,
            "demotion also revokes unrestricted speaking"
        );
        assert!(set_speaking(
            State(app.clone()),
            h[1].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: false })
        )
        .await
        .is_err());
        let _ = set_hand(
            State(app.clone()),
            h[2].clone(),
            Path(id.clone()),
            Json(Hand { raised: true }),
        )
        .await
        .unwrap();
        assert!(
            set_speaker(
                State(app.clone()),
                h[1].clone(),
                Path((id.clone(), u[2].id.clone())),
                Json(Speaker { allowed: true })
            )
            .await
            .is_err(),
            "stale admin menus cannot approve"
        );
        let _ = set_speaking(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: false }),
        )
        .await
        .unwrap();
        assert_eq!(participant(2)["hand_raised"], false);
        assert_eq!(participant(2)["moderator_muted"], false);
        assert!(set_hand(
            State(app.clone()),
            h[2].clone(),
            Path(id.clone()),
            Json(Hand { raised: true })
        )
        .await
        .is_err());
        app.live
            .lock()
            .unwrap()
            .peers
            .get_mut(&u[1].id)
            .unwrap()
            .raise_hand = false;
        let _ = set_speaking(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: true }),
        )
        .await
        .unwrap();
        assert_eq!(
            rooms::meeting_participants(&app, &id).len(),
            2,
            "unsupported clients leave when enabled"
        );
        assert!(enter(&app, &u[1], id.clone()).is_err());
        let _ = set_speaking(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: false }),
        )
        .await
        .unwrap();
        enter(&app, &u[1], id).unwrap();
    }
    #[tokio::test]
    async fn speaking_setting_survives_restart_but_requests_and_grants_do_not() {
        let path = std::env::temp_dir().join(format!("pvp-speaking-{}.sqlite", Uuid::new_v4()));
        let (app, u, h) = fixture(path.to_str().unwrap(), 2);
        let m = make(&app, &h[0], vec![u[1].id.clone()]).await;
        let id = m["meeting_id"].as_str().unwrap().to_owned();
        let _ = set_speaking(
            State(app.clone()),
            h[0].clone(),
            Path(id.clone()),
            Json(Speaking { enabled: true }),
        )
        .await
        .unwrap();
        enter(&app, &u[1], id.clone()).unwrap();
        let _ = set_hand(
            State(app.clone()),
            h[1].clone(),
            Path(id.clone()),
            Json(Hand { raised: true }),
        )
        .await
        .unwrap();
        let _ = set_speaker(
            State(app.clone()),
            h[0].clone(),
            Path((id.clone(), u[1].id.clone())),
            Json(Speaker { allowed: true }),
        )
        .await
        .unwrap();
        drop(app);
        let restarted = App::new(path.to_str().unwrap(), "https://lopixel.space".into()).unwrap();
        assert_eq!(
            describe(&restarted, &u[1], &id).unwrap()["raise_hand_enabled"],
            true
        );
        connect(&restarted, &u[1]);
        enter(&restarted, &u[1], id.clone()).unwrap();
        assert_eq!(
            rooms::speaking_member(&restarted, &id, &u[1].id).unwrap(),
            (false, false)
        );
        drop(restarted);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn additive_migration_preserves_old_links_and_gives_the_creator_admin_rights() {
        let path = std::env::temp_dir().join(format!("pvp-old-meeting-{}.sqlite", Uuid::new_v4()));
        let id = "a".repeat(64);
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,display_name TEXT NOT NULL,password TEXT NOT NULL);CREATE TABLE meetings(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,created INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);CREATE TABLE meeting_members(meeting_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(meeting_id,user_id));INSERT INTO users VALUES('owner','owner','Owner','hash');").unwrap();
            db.execute(
                "INSERT INTO meetings VALUES(?1,'owner','Old weekly',0,0)",
                [&id],
            )
            .unwrap();
            db.execute("INSERT INTO meeting_members VALUES(?1,'owner')", [&id])
                .unwrap();
        }
        let app = App::new(path.to_str().unwrap(), "https://lopixel.space".into()).unwrap();
        let owner = User {
            id: "owner".into(),
            username: "owner".into(),
            display_name: "Owner".into(),
        };
        let m = describe(&app, &owner, &id).unwrap();
        assert_eq!(m["url"], format!("https://lopixel.space/#meeting={id}"));
        assert_eq!(m["members"][0]["is_admin"], true);
        assert_eq!(m["members"][0]["moderator_muted"], false);
        drop(app);
        std::fs::remove_file(path).unwrap();
    }
}
