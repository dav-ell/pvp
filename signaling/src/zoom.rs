//! Zoom invitations are room identifiers, never proof of host identity.
//! No Zoom URL, passcode, tracking token, or host credential is persisted/fetched.
use super::*;
use regex::Regex;
use std::{collections::HashSet, sync::LazyLock};
use url::Url;

pub(super) const OWNER: &str = "pvp-zoom-service";
const INVALID: &str = "Paste a Zoom invitation with a numeric meeting ID. For a personal /my/ or registration link, use the numbered join link from the invitation.";

#[derive(Debug, PartialEq, Eq, Hash)]
struct Meeting {
    realm: &'static str,
    number: String,
}

fn number(value: &str) -> Option<String> {
    let value: String = value.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    ((9..=11).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_digit())).then_some(value)
}

fn from_url(value: &str, depth: usize) -> Option<Meeting> {
    if depth > 4 {
        return None;
    }
    let value = value
        .trim_end_matches(['.', ',', ';', ')', ']', '}'])
        .replace("&amp;", "&");
    let url = Url::parse(&value)
        .or_else(|_| Url::parse(&format!("https://{value}")))
        .ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    if matches!(url.scheme(), "http" | "https")
        && (host.ends_with(".safelinks.protection.outlook.com")
            || host == "www.google.com"
            || host == "google.com")
    {
        return url.query_pairs().find_map(|(key, value)| {
            matches!(key.as_ref(), "url" | "q")
                .then(|| from_url(&value, depth + 1))
                .flatten()
        });
    }
    if !matches!(url.scheme(), "http" | "https" | "zoommtg" | "zoomus") {
        return None;
    }
    let realm = [
        "zoom.us",
        "zoom.com",
        "zoom.com.cn",
        "zoom.cn",
        "zoomgov.com",
    ]
    .into_iter()
    .find(|domain| host == *domain || host.ends_with(&format!(".{domain}")))?;
    let realm = if realm == "zoomgov.com" {
        "zoomgov.com"
    } else {
        "zoom.us"
    };
    let parts: Vec<_> = url.path().trim_matches('/').split('/').collect();
    let id = match parts.as_slice() {
        ["j" | "s", id] | ["wc", "join", id] | ["wc", id, "join" | "start"] => number(id),
        ["join" | "j"] | ["wc", "join"] => url.query_pairs().find_map(|(key, value)| {
            matches!(key.as_ref(), "confno" | "meetingid" | "meeting_id")
                .then(|| number(&value))
                .flatten()
        }),
        _ => None,
    }?;
    Some(Meeting { realm, number: id })
}

fn parse(input: &str) -> ApiResult<Meeting> {
    if input.len() > 16_384 || input.chars().any(|c| c == '\0') {
        return Err(bad(INVALID));
    }
    let input = input.trim();
    if let Some(number) = number(input) {
        return Ok(Meeting {
            realm: "zoom.us",
            number,
        });
    }
    static LINKS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)(?:^|[\s<("'])([a-z][a-z0-9+.-]*://[^\s<>"']+|(?:[a-z0-9-]+\.)*zoom\.(?:us|com|cn)/[^\s<>"']+|(?:[a-z0-9-]+\.)*zoomgov\.com/[^\s<>"']+)"#).unwrap()
    });
    static IDS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?im)^\s*Meeting ID:\s*([0-9][0-9 -]{7,16}[0-9])\s*$").unwrap()
    });
    let mut meetings: HashSet<_> = LINKS
        .captures_iter(input)
        .filter_map(|m| from_url(&m[1], 0))
        .collect();
    if meetings.is_empty() {
        for capture in IDS.captures_iter(input) {
            if let Some(number) = number(&capture[1]) {
                meetings.insert(Meeting {
                    realm: "zoom.us",
                    number,
                });
            }
        }
    }
    if meetings.len() > 1 {
        return Err(bad(
            "This contains different Zoom meetings. Paste one invitation at a time.",
        ));
    }
    meetings.into_iter().next().ok_or_else(|| bad(INVALID))
}

#[derive(Deserialize)]
pub(super) struct Open {
    link: String,
}

pub(super) async fn open(State(app): State<App>, Json(data): Json<Open>) -> ApiResult<Json<Value>> {
    let meeting = parse(&data.link)?;
    // Versioned, public identity: region, password, tracking parameters and
    // recurring occurrence IDs must never create a second room for one meeting.
    let id = token_hash(&format!("pvp:zoom:v1:{}:{}", meeting.realm, meeting.number));
    let _operation = app.operations.lock().unwrap();
    {
        let mut db = app.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO users VALUES(?1,'~zoom-service','Zoom-linked rooms','!')",
            [OWNER],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO discovery_preferences VALUES(?1,0)",
            [OWNER],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO meetings VALUES(?1,?2,?3,?4,0)",
            params![id, OWNER, format!("P2P Zoom · {}", meeting.number), now()],
        )?;
        tx.execute("INSERT OR IGNORE INTO meeting_access VALUES(?1,1)", [&id])?;
        tx.commit()?;
    }
    let mut preview = meetings::public_preview(&app, &id)?;
    preview["zoom_meeting_id"] = json!(meeting.number);
    Ok(Json(preview))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_variants_share_an_identity() {
        let expected = Meeting {
            realm: "zoom.us",
            number: "12345678901".into(),
        };
        for input in [
            "https://us02web.zoom.us/j/12345678901?pwd=secret&omn=12",
            "https://company.zoom.us/j/12345678901?pwd=changed&from=calendar#success",
            "https://zoom.com/wc/join/12345678901?pwd=secret",
            "https://app.zoom.us/wc/12345678901/join",
            "zoommtg://zoom.us/join?confno=12345678901&pwd=secret",
            "zoomus://zoom.us/join?confno=12345678901",
            "zoom.us/j/12345678901",
            "123 4567 8901",
            "Join Zoom Meeting\nhttps://company.zoom.us/j/12345678901?pwd=secret\nMeeting ID: 123 4567 8901\nPasscode: 123456",
            "<https://zoom.us/j/12345678901?pwd=abc&amp;from=invite>",
            "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fzoom.us%2Fj%2F12345678901%3Fpwd%3Dsecret&data=tracking",
            "https://www.google.com/url?q=https%3A%2F%2Fzoom.us%2Fj%2F12345678901",
            "https://zoom.us/s/12345678901?zak=HOST_SECRET",
            "https://zoom.us/join?confno=12345678901",
        ] { assert_eq!(parse(input).unwrap(), expected, "{input}"); }
    }

    #[test]
    fn malformed_ambiguous_and_unresolvable_links_fail_without_guessing() {
        for input in [
            "https://zoom.us.evil.example/j/12345678901",
            "https://evilzoom.us/j/12345678901",
            "https://zoom.us@evil.example/j/12345678901",
            "https://evil@zoom.us/j/12345678901",
            "https://zoom.us/my/team",
            "https://zoom.us/meeting/register/abc",
            "https://zoom.us/j/123",
            "https://zoom.us/j/123456789012",
            "ftp://zoom.us/j/12345678901",
            "1234567890oops",
            "https://zoom.us/j/12345678901 https://zoom.us/j/98765432109",
            "https://zoom.us:9999/j/12345678901",
            "https://zoom.us/j/12345678901/other",
        ] {
            assert!(parse(input).is_err(), "{input}");
        }
        assert_ne!(
            parse("https://zoomgov.com/j/12345678901").unwrap(),
            parse("https://zoom.us/j/12345678901").unwrap()
        );
    }

    #[tokio::test]
    async fn rooms_are_stable_ownerless_and_store_no_zoom_credentials() {
        let app = App::new(":memory:", "https://pvp.example".into()).unwrap();
        let first = open(
            State(app.clone()),
            Json(Open {
                link: "https://zoom.us/j/12345678901?pwd=PRIVATE&zak=SECRET".into(),
            }),
        )
        .await
        .unwrap()
        .0;
        let second = open(
            State(app.clone()),
            Json(Open {
                link: "https://us02web.zoom.us/wc/join/12345678901?pwd=OTHER".into(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first, second);
        let db = app.db.lock().unwrap();
        let (owner, name): (String, String) = db
            .query_row("SELECT owner,name FROM meetings", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(owner, OWNER);
        assert_eq!(name, "P2P Zoom · 12345678901");
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM meeting_members", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn departed_visitors_never_reserve_zoom_seats() {
        let app = App::new(":memory:", "https://pvp.example".into()).unwrap();
        let meeting = open(
            State(app.clone()),
            Json(Open {
                link: "https://zoom.us/j/12345678901".into(),
            }),
        )
        .await
        .unwrap()
        .0;
        let id = meeting["meeting_id"].as_str().unwrap();
        for i in 0..20 {
            let user = User {
                id: format!("visitor{i}"),
                username: format!("~visitor{i}"),
                display_name: "Visitor".into(),
            };
            app.db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO users VALUES(?1,?2,?3,'!')",
                    params![user.id, user.username, user.display_name],
                )
                .unwrap();
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
            meetings::enter(&app, &user, id.to_owned()).unwrap();
            assert_eq!(rooms::meeting_participants(&app, id).len(), 1);
            rooms::disconnect(&app, &user.id);
            assert!(rooms::meeting_participants(&app, id).is_empty());
        }
        let db = app.db.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM meeting_members", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM meeting_visits", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            20
        );
    }
}
