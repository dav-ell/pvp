//! Scoped invitation guests and persistent accountless meeting creators.
use super::*;

const LIFETIME: i64 = 8 * 3600;
pub(super) struct Session {
    pub user: User,
    pub meeting_id: String,
    pub expires: i64,
    pub enrolled: bool,
    pub blocked: bool,
    pub muted: bool,
}
pub(super) fn is_guest(user: &User) -> bool {
    user.id.starts_with("guest-")
}
fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("pvp_guest="))
}
pub(super) fn user(app: &App, headers: &HeaderMap) -> ApiResult<User> {
    let sessions = app.guests.lock().unwrap();
    token(headers)
        .and_then(|token| sessions.get(&token_hash(token)))
        .filter(|s| s.expires > now())
        .map(|s| s.user.clone())
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "Please sign in or join with a meeting link",
        ))
}
pub(super) fn scope(app: &App, user: &User, id: &str) -> ApiResult<()> {
    let sessions = app.guests.lock().unwrap();
    let session = sessions
        .values()
        .find(|s| s.user.id == user.id && s.meeting_id == id && s.expires > now())
        .ok_or_else(forbidden)?;
    if session.blocked {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "You were removed from this meeting",
        ));
    }
    Ok(())
}
pub(super) fn describe(app: &App, user: &User) -> Value {
    let sessions = app.guests.lock().unwrap();
    let id = sessions
        .values()
        .find(|s| s.user.id == user.id)
        .map(|s| &s.meeting_id);
    json!({"id":user.id,"username":user.username,"display_name":user.display_name,"guest":true,"scoped_guest":true,"meeting_id":id})
}
fn cookie(app: &App, token: &str) -> String {
    let secure = if app.origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    // Session cookie, with an absolute server-side lifetime that cannot slide.
    format!("pvp_guest={token}; Path=/; HttpOnly; SameSite=Strict{secure}")
}
#[derive(Deserialize)]
pub(super) struct Join {
    display_name: String,
}

// A browser-owned identity needs no username, password, or registration. The
// existing persistent, hashed session capability preserves meeting ownership.
pub(super) async fn start(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Join>,
) -> ApiResult<Response> {
    let _operation = app.operations.lock().unwrap();
    if let Ok(user) = app.user(&headers) {
        return Ok(Json(identity(&user)).into_response());
    }
    let name = input.display_name.trim();
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
        return Err(bad("Enter a display name of 1–60 characters"));
    }
    let previous = user(&app, &headers).ok();
    let user = User {
        id: Uuid::new_v4().to_string(),
        // Not a valid registerable/login username; no password can authenticate it.
        username: format!("~{}", Uuid::new_v4().simple()),
        display_name: name.to_owned(),
    };
    {
        let mut db = app.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO users VALUES(?1,?2,?3,'!')",
            params![user.id, user.username, user.display_name],
        )?;
        tx.execute("INSERT INTO discovery_preferences VALUES(?1,0)", [&user.id])?;
        tx.commit()?;
    }
    if let Some(previous) = previous {
        retire(&app, &previous);
    }
    app.session(&user)
}

pub(super) async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Join>,
) -> ApiResult<Response> {
    let _operation = app.operations.lock().unwrap();
    meetings::public_preview(&app, &id)?;
    if app.user(&headers).is_ok() {
        return Err(bad("You are already signed in. Use Join meeting."));
    }
    let name = input.display_name.trim();
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
        return Err(bad("Enter a display name of 1–60 characters"));
    }
    if let Ok(user) = user(&app, &headers) {
        let same = app
            .guests
            .lock()
            .unwrap()
            .values()
            .any(|s| s.user.id == user.id && s.meeting_id == id);
        if same {
            scope(&app, &user, &id)?;
            return Ok(Json(describe(&app, &user)).into_response());
        }
        // Changing links ends the previous guest visit before replacing its cookie.
        retire(&app, &user);
    }
    let user = User {
        id: format!("guest-{}", Uuid::new_v4()),
        username: String::new(),
        display_name: name.to_owned(),
    };
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    {
        let mut sessions = app.guests.lock().unwrap();
        if sessions.len() >= 1024 {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Guest access is busy. Try again later",
            ));
        }
        sessions.insert(
            token_hash(&token),
            Session {
                user: user.clone(),
                meeting_id: id,
                expires: now() + LIFETIME,
                enrolled: false,
                blocked: false,
                muted: false,
            },
        );
    }
    Ok((
        [("set-cookie", cookie(&app, &token))],
        Json(describe(&app, &user)),
    )
        .into_response())
}
pub(super) fn members(app: &App, id: &str) -> Vec<meetings::MeetingMember> {
    app.guests
        .lock()
        .unwrap()
        .values()
        .filter(|s| s.meeting_id == id && s.enrolled && !s.blocked && s.expires > now())
        .map(|s| meetings::MeetingMember {
            user: s.user.clone(),
            is_admin: false,
            moderator_muted: s.muted,
        })
        .collect()
}
pub(super) fn enroll(app: &App, user: &User, id: &str) -> ApiResult<()> {
    scope(app, user, id)?;
    let mut sessions = app.guests.lock().unwrap();
    let session = sessions
        .values_mut()
        .find(|s| s.user.id == user.id)
        .ok_or_else(forbidden)?;
    session.enrolled = true;
    Ok(())
}
pub(super) fn left(app: &App, user: &str) {
    let id = {
        let mut sessions = app.guests.lock().unwrap();
        sessions
            .values_mut()
            .find(|s| s.user.id == user && s.enrolled)
            .map(|s| {
                s.enrolled = false;
                s.meeting_id.clone()
            })
    };
    if let Some(id) = id {
        meetings::changed(app, &id, Some(user));
    }
}
pub(super) fn moderate(app: &App, id: &str, peer: &str, muted: Option<bool>) -> ApiResult<()> {
    let mut sessions = app.guests.lock().unwrap();
    let s = sessions
        .values_mut()
        .find(|s| s.user.id == peer && s.meeting_id == id && s.enrolled)
        .ok_or_else(forbidden)?;
    if let Some(muted) = muted {
        s.muted = muted;
    } else {
        s.blocked = true;
        s.enrolled = false;
    }
    Ok(())
}
fn retire(app: &App, user: &User) {
    rooms::disconnect(app, &user.id);
    left(app, &user.id);
    app.guests
        .lock()
        .unwrap()
        .retain(|_, s| s.user.id != user.id);
    app.send(&user.id, json!({"type":"signed-out"}));
}
pub(super) async fn logout(State(app): State<App>, headers: HeaderMap) -> ApiResult<Response> {
    let _operation = app.operations.lock().unwrap();
    let user = user(&app, &headers)?;
    retire(&app, &user);
    Ok((
        [("set-cookie", format!("{}; Max-Age=0", cookie(&app, "")))],
        Json(json!({"ok":true})),
    )
        .into_response())
}
pub(super) fn expire(app: &App) {
    let _operation = app.operations.lock().unwrap();
    let users: Vec<_> = app
        .guests
        .lock()
        .unwrap()
        .values()
        .filter(|s| s.expires <= now())
        .map(|s| s.user.clone())
        .collect();
    for user in users {
        retire(app, &user);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (App, String, HeaderMap) {
        let app = App::new(":memory:", "https://pvp.example".into()).unwrap();
        let id = "a".repeat(64);
        {
            let db = app.db.lock().unwrap();
            db.execute_batch(
                "INSERT INTO users VALUES('owner','owner','Owner','unused');
                INSERT INTO sessions VALUES('unused','owner',9999999999);",
            )
            .unwrap();
            for (id, open) in [
                (&id, true),
                (&"b".repeat(64), true),
                (&"c".repeat(64), false),
            ] {
                db.execute(
                    "INSERT INTO meetings VALUES(?1,'owner','Test meeting',0,0)",
                    [id],
                )
                .unwrap();
                db.execute("INSERT INTO meeting_members VALUES(?1,'owner')", [id])
                    .unwrap();
                db.execute(
                    "INSERT INTO meeting_access VALUES(?1,?2)",
                    params![id, open],
                )
                .unwrap();
            }
        }
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "pvp_session=owner-token".parse().unwrap());
        app.db
            .lock()
            .unwrap()
            .execute("UPDATE sessions SET token=?1", [token_hash("owner-token")])
            .unwrap();
        (app, id, headers)
    }
    async fn visit(app: &App, id: &str) -> (User, HeaderMap) {
        let response = create(
            State(app.clone()),
            HeaderMap::new(),
            Path(id.to_owned()),
            Json(Join {
                display_name: "Visitor".into(),
            }),
        )
        .await
        .unwrap();
        let cookie = response.headers()["set-cookie"].to_str().unwrap();
        assert!(cookie.contains("HttpOnly; SameSite=Strict; Secure"));
        assert!(!cookie.contains("Max-Age"));
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.split(';').next().unwrap().parse().unwrap());
        let user = app.participant(&headers).unwrap();
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
        (user, headers)
    }
    #[tokio::test]
    async fn guests_are_scoped_cannot_gain_account_privileges_and_expire_without_sliding() {
        let (app, id, owner) = fixture();
        let (visitor, headers) = visit(&app, &id).await;
        assert!(app.user(&headers).is_err());
        for message in [
            ClientMessage::VoiceOpen,
            ClientMessage::VoiceJoin {
                room_id: "anything".into(),
            },
            ClientMessage::Call {
                peer_id: "owner".into(),
            },
            ClientMessage::RoomCreate {
                peer_ids: vec!["owner".into()],
            },
            ClientMessage::RoomInvite {
                room_id: "anything".into(),
                peer_id: "owner".into(),
            },
            ClientMessage::RoomJoin {
                room_id: "anything".into(),
            },
        ] {
            assert_eq!(
                handle_message(&app, &visitor, message).unwrap_err().0,
                StatusCode::FORBIDDEN
            );
        }
        for other in ["b".repeat(64), "c".repeat(64)] {
            assert!(meetings::enter(&app, &visitor, other).is_err());
        }
        let expiry = app.guests.lock().unwrap().values().next().unwrap().expires;
        let _ = me(
            State(app.clone()),
            headers.clone(),
            Query(HashMap::from([("renew".into(), "1".into())])),
        )
        .await
        .unwrap();
        assert_eq!(
            app.guests.lock().unwrap().values().next().unwrap().expires,
            expiry
        );
        meetings::enter(&app, &visitor, id.clone()).unwrap();
        assert_eq!(members(&app, &id).len(), 1);
        assert!(!members(&app, &id)[0].is_admin);
        assert!(meetings::set_admin(
            State(app.clone()),
            owner,
            Path((id.clone(), visitor.id.clone())),
            Json(serde_json::from_value::<meetings::Admin>(json!({"admin":true})).unwrap())
        )
        .await
        .is_err());
        app.guests
            .lock()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .expires = now() - 1;
        assert!(app.participant(&headers).is_err());
        expire(&app);
        assert!(app.guests.lock().unwrap().is_empty());
        assert!(rooms::meeting_participants(&app, &id).is_empty());
        assert_eq!(
            app.db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn temporary_guest_slots_are_capped_released_and_kicked_sessions_stay_blocked() {
        let (app, id, _) = fixture();
        let mut visitors = Vec::new();
        for _ in 0..15 {
            let (visitor, _) = visit(&app, &id).await;
            meetings::enter(&app, &visitor, id.clone()).unwrap();
            visitors.push(visitor);
        }
        let (next, headers) = visit(&app, &id).await;
        assert_eq!(
            meetings::enter(&app, &next, id.clone()).unwrap_err().1,
            "Meeting is full"
        );
        assert_eq!(members(&app, &id).len(), 15);
        let room_id = app
            .live
            .lock()
            .unwrap()
            .rooms
            .keys()
            .next()
            .unwrap()
            .clone();
        rooms::leave(&app, &visitors[0].id, &room_id).unwrap();
        meetings::enter(&app, &next, id.clone()).unwrap();
        moderate(&app, &id, &next.id, Some(true)).unwrap();
        rooms::sync_meeting_member(&app, &id, &next.id).unwrap();
        rooms::leave(&app, &next.id, &room_id).unwrap();
        meetings::enter(&app, &next, id.clone()).unwrap();
        assert!(
            members(&app, &id)
                .iter()
                .find(|m| m.user.id == next.id)
                .unwrap()
                .moderator_muted
        );
        moderate(&app, &id, &next.id, None).unwrap();
        rooms::remove_meeting_member(&app, &id, &next.id);
        assert!(meetings::enter(&app, &next, id.clone()).is_err());
        assert_eq!(
            create(
                State(app.clone()),
                headers,
                Path(id),
                Json(Join {
                    display_name: "Try again".into()
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
    }
}
