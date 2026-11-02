//! Opt-in room-size distribution. The public response contains no joinable links,
//! user/session/room identifiers, IPs, locations, media state or observed ICE edges.
use super::*;

pub(super) async fn snapshot(State(app): State<App>) -> ApiResult<Json<Value>> {
    let active = rooms::active_room_sizes(&app);
    let mut sizes = [0usize; 17];
    {
        let db = app.db.lock().unwrap();
        // Query only live rooms, so inactive saved rooms cannot make this public
        // read scan or allocate memory proportional to all registered meetings.
        let mut q = db.prepare("SELECT EXISTS(SELECT 1 FROM meeting_network n JOIN meetings m ON m.id=n.meeting_id JOIN meeting_access a ON a.meeting_id=m.id WHERE n.meeting_id=?1 AND n.visible=1 AND m.revoked=0 AND a.open_invite=1)")?;
        for (id, peers) in active {
            if q.query_row([id], |r| r.get::<_, bool>(0))? {
                sizes[peers] += 1;
            }
        }
    }
    let rooms = (1..=16)
        .filter(|&peers| sizes[peers] > 0)
        .map(|peers| json!({"peers":peers,"count":sizes[peers]}))
        .collect::<Vec<_>>();
    Ok(Json(
        json!({"version":1,"rooms":rooms,"as_of":now(),"connections":"illustrated"}),
    ))
}
