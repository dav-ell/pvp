//! Recovery browser surface with identities separate from the general PVP app.
use super::*;

pub(super) fn routes() -> Router<App> {
    let api = Router::new()
        .route("/me", get(me))
        .route("/start", post(guests::start))
        .route("/ws", get(websocket))
        .route("/meetings", post(meetings::create))
        .route("/meetings/{id}/preview", get(meetings::preview))
        .route("/meetings/{id}/guest", post(guests::create))
        .route("/meetings/{id}", get(meetings::get))
        .route("/meetings/{id}/speaking", post(meetings::set_speaking))
        .route("/meetings/{id}/hand", post(meetings::set_hand))
        .route("/meetings/{id}/members/{peer}", delete(meetings::remove))
        .route(
            "/meetings/{id}/members/{peer}/speak",
            post(meetings::set_speaker),
        )
        .route(
            "/meetings/{id}/members/{peer}/mute",
            post(meetings::set_mute),
        )
        .layer(middleware::from_fn(sessions));
    Router::new()
        .nest("/recovery/api", api)
        .route("/recovery", get(index))
        .route("/recovery/", get(index))
        .route(
            "/recovery/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../recovery/app.js"),
                )
            }),
        )
        .route(
            "/recovery/call.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../recovery/call.js"),
                )
            }),
        )
        .route(
            "/recovery/styles.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../recovery/styles.css"),
                )
            }),
        )
        .route(
            "/recovery/icon.svg",
            get(|| async {
                (
                    [("content-type", "image/svg+xml")],
                    include_str!("../../recovery/icon.svg"),
                )
            }),
        )
}

pub(super) async fn index() -> Html<&'static str> {
    Html(include_str!("../../recovery/index.html"))
}

// Never inherit a general PVP identity (or real name) in the recovery app.
// Both host and temporary guest sessions retain HttpOnly / SameSite protection.
async fn sessions(mut request: axum::extract::Request, next: Next) -> Response {
    let cookies = request
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("fellowship_session=")
                .map(|v| format!("pvp_session={v}"))
                .or_else(|| {
                    part.strip_prefix("fellowship_guest=")
                        .map(|v| format!("pvp_guest={v}"))
                })
        })
        .collect::<Vec<_>>()
        .join("; ");
    request.headers_mut().remove("cookie");
    if let Ok(value) = cookies.parse() {
        request.headers_mut().insert("cookie", value);
    }
    let mut response = next.run(request).await;
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .cloned()
        .collect();
    response.headers_mut().remove("set-cookie");
    for value in cookies {
        if let Ok(value) = value.to_str() {
            let renamed = value
                .strip_prefix("pvp_session=")
                .map(|v| format!("fellowship_session={v}"))
                .or_else(|| {
                    value
                        .strip_prefix("pvp_guest=")
                        .map(|v| format!("fellowship_guest={v}"))
                })
                .unwrap_or_else(|| value.to_owned());
            if let Ok(value) = renamed.parse() {
                response.headers_mut().append("set-cookie", value);
            }
        }
    }
    response
}
