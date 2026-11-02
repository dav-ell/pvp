//! pvp-relay — UDP room-based media forwarder (effective TURN for pvp).
//!
//! Control messages start with magic `PVPR`. All other UDP datagrams from a
//! joined peer are forwarded unchanged to the other peer in the same room
//! (media stays end-to-end encrypted with the clients' AES key).
//!
//! Usage:
//!   PVP_RELAY_TOKEN=secret pvp-relay --bind 127.0.0.1:3478
//!   pvp-relay --bind 127.0.0.1:3478 --token secret \
//!     --public-front 0.0.0.0:19132 --minecraft-backend 127.0.0.1:19133
//!
//! When `--public-front` is set, a demux listens on that address (typically the
//! only cloud-firewall-open UDP port) and reverse-proxies:
//!   • PVPR / known pvp clients → `--bind` (this process's pvp logic via loopback)
//!   • everything else → `--minecraft-backend` (frps Bedrock after remotePort move)

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};
use tokio::time;

/// Shared with the pvp client (`src/network/relay.rs`).
pub const MAGIC: &[u8; 4] = b"PVPR";
pub const MSG_JOIN: u8 = 1;
pub const MSG_JOIN_OK: u8 = 2;
pub const MSG_KEEPALIVE: u8 = 3;
pub const MSG_ERROR: u8 = 4;
pub const MSG_PEER_READY: u8 = 5;
pub const MSG_PEER_GONE: u8 = 6;

/// Status in JOIN_OK: waiting for second peer.
pub const STATUS_WAITING: u8 = 0;
/// Status in JOIN_OK / PEER_READY: both peers present.
pub const STATUS_PEER_PRESENT: u8 = 1;

const DEFAULT_BIND: &str = "0.0.0.0:3478";
const PEER_TIMEOUT: Duration = Duration::from_secs(45);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const FLOW_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ROOM_LEN: usize = 64;
const MAX_TOKEN_LEN: usize = 128;
const MAX_PEERS_PER_ROOM: usize = 2;
const MAX_FLOWS: usize = 256;
const MAX_ROOMS: usize = 256;

#[derive(Debug, Default)]
struct Room {
    peers: Vec<SocketAddr>,
    last_seen: HashMap<SocketAddr, Instant>,
}

impl Room {
    fn touch(&mut self, addr: SocketAddr) {
        let now = Instant::now();
        self.last_seen.insert(addr, now);
        if !self.peers.contains(&addr) {
            self.peers.push(addr);
        }
    }

    fn remove(&mut self, addr: SocketAddr) {
        self.peers.retain(|a| *a != addr);
        self.last_seen.remove(&addr);
    }

    fn other(&self, addr: SocketAddr) -> Option<SocketAddr> {
        self.peers.iter().copied().find(|a| *a != addr)
    }

    fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

type Rooms = Arc<Mutex<HashMap<String, Room>>>;
type PeerIndex = Arc<Mutex<HashMap<SocketAddr, String>>>;
type Flows = Arc<Mutex<HashMap<SocketAddr, (FlowKind, Arc<UdpSocket>, Instant)>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowKind {
    Pvp,
    Minecraft,
}

struct Args {
    bind: String,
    token: String,
    public_front: Option<String>,
    minecraft_backend: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    if args.token.is_empty() {
        eprintln!("error: relay token is required (--token or PVP_RELAY_TOKEN)");
        std::process::exit(1);
    }

    // When using a public front, bind pvp core on loopback so only the demux is public.
    let bind = if args.public_front.is_some() && args.bind == DEFAULT_BIND {
        "127.0.0.1:3478".to_string()
    } else {
        args.bind.clone()
    };

    let socket = Arc::new(UdpSocket::bind(&bind).await?);
    println!("pvp-relay core listening on {} (UDP)", socket.local_addr()?);
    println!("Auth: token required on JOIN ({} chars)", args.token.len());

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));
    let peer_index: PeerIndex = Arc::new(Mutex::new(HashMap::new()));

    {
        let rooms = Arc::clone(&rooms);
        let peer_index = Arc::clone(&peer_index);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut interval = time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                cleanup_stale(&rooms, &peer_index, &socket).await;
            }
        });
    }

    if let Some(public) = args.public_front.clone() {
        let mc = args
            .minecraft_backend
            .clone()
            .ok_or("--public-front requires --minecraft-backend HOST:PORT")?;
        let pvp_backend = socket.local_addr()?;
        let public_addr: SocketAddr = public.parse()?;
        let mc_addr: SocketAddr = mc.parse()?;
        println!(
            "Public UDP front on {} → pvp={} mc={}",
            public_addr, pvp_backend, mc_addr
        );
        tokio::spawn(async move {
            if let Err(e) = run_public_front(public_addr, pvp_backend, mc_addr).await {
                eprintln!("public front fatal: {}", e);
            }
        });
    }

    let mut buf = vec![0u8; 2048];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        };
        let packet = &buf[..n];

        if packet.len() >= 5 && &packet[0..4] == MAGIC {
            handle_control(&socket, &rooms, &peer_index, &args.token, src, packet).await;
        } else {
            forward_data(&socket, &rooms, &peer_index, src, packet).await;
        }
    }
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut bind = env::var("PVP_RELAY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let mut token = env::var("PVP_RELAY_TOKEN").unwrap_or_default();
    let mut public_front = env::var("PVP_RELAY_PUBLIC_FRONT")
        .ok()
        .filter(|s| !s.is_empty());
    let mut minecraft_backend = env::var("PVP_RELAY_MC_BACKEND")
        .ok()
        .filter(|s| !s.is_empty());

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                i += 1;
                bind = args.get(i).ok_or("--bind requires an address")?.clone();
            }
            "--token" | "-t" => {
                i += 1;
                token = args.get(i).ok_or("--token requires a value")?.clone();
            }
            "--public-front" => {
                i += 1;
                public_front = Some(
                    args.get(i)
                        .ok_or("--public-front requires HOST:PORT")?
                        .clone(),
                );
            }
            "--minecraft-backend" => {
                i += 1;
                minecraft_backend = Some(
                    args.get(i)
                        .ok_or("--minecraft-backend requires HOST:PORT")?
                        .clone(),
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: pvp-relay [--bind HOST:PORT] [--token SECRET]\n\
                     \n\
                     Optional cloud-firewall share (use with Bedrock on same public UDP port):\n\
                       --public-front 0.0.0.0:19132\n\
                       --minecraft-backend 127.0.0.1:19133\n\
                     \n\
                     Env: PVP_RELAY_BIND, PVP_RELAY_TOKEN,\n\
                          PVP_RELAY_PUBLIC_FRONT, PVP_RELAY_MC_BACKEND\n\
                     Default bind: {}",
                    DEFAULT_BIND
                );
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {}", other).into());
            }
        }
        i += 1;
    }
    Ok(Args {
        bind,
        token,
        public_front,
        minecraft_backend,
    })
}

/// UDP reverse-proxy demux on the public port.
async fn run_public_front(
    public: SocketAddr,
    pvp_backend: SocketAddr,
    mc_backend: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    run_public_front_with_limits(
        public,
        pvp_backend,
        mc_backend,
        MAX_FLOWS,
        FLOW_TIMEOUT,
        CLEANUP_INTERVAL,
    )
    .await
}
async fn run_public_front_with_limits(
    public: SocketAddr,
    pvp_backend: SocketAddr,
    mc_backend: SocketAddr,
    max_flows: usize,
    idle: Duration,
    poll: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let front = Arc::new(UdpSocket::bind(public).await?);
    println!("public front bound {}", front.local_addr()?);

    // client addr -> (kind, backend socket bound ephemerally)
    let flows: Flows = Arc::new(Mutex::new(HashMap::new()));

    // Permits cover the socket lifetime, including readers awaiting timeout.
    let flow_slots = Arc::new(Semaphore::new(max_flows));

    let mut buf = vec![0u8; 2048];
    loop {
        let (n, src) = front.recv_from(&mut buf).await?;
        let packet = buf[..n].to_vec();

        let is_pvp_magic = packet.len() >= 4 && &packet[0..4] == MAGIC;

        let backend_sock = {
            let mut g = flows.lock().await;
            if let Some(entry) = g.get_mut(&src) {
                entry.2 = Instant::now();
                if is_pvp_magic {
                    entry.0 = FlowKind::Pvp;
                }
                Arc::clone(&entry.1)
            } else {
                let Ok(slot) = flow_slots.clone().try_acquire_owned() else {
                    continue;
                };
                let kind = if is_pvp_magic {
                    FlowKind::Pvp
                } else {
                    FlowKind::Minecraft
                };
                let backend = match kind {
                    FlowKind::Pvp => pvp_backend,
                    FlowKind::Minecraft => mc_backend,
                };
                let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
                // reader task: backend -> client
                {
                    let sock_r = Arc::clone(&sock);
                    let front_r = Arc::clone(&front);
                    let client = src;
                    let flows_r = Arc::clone(&flows);
                    tokio::spawn(async move {
                        let _slot = slot;
                        let mut b = vec![0u8; 2048];
                        loop {
                            if !flows_r.lock().await.get(&client).is_some_and(|e| {
                                Arc::ptr_eq(&e.1, &sock_r) && e.2.elapsed() <= idle
                            }) {
                                break;
                            }
                            let incoming = time::timeout(poll, sock_r.recv_from(&mut b)).await;
                            match incoming {
                                Ok(Ok((n, sender))) => {
                                    if sender != pvp_backend && sender != mc_backend {
                                        continue;
                                    }
                                    if front_r.send_to(&b[..n], client).await.is_err() {
                                        break;
                                    }
                                    if let Some(e) = flows_r.lock().await.get_mut(&client) {
                                        e.2 = Instant::now();
                                    }
                                }
                                Ok(Err(_)) => break,
                                Err(_) => {
                                    let active =
                                        flows_r.lock().await.get(&client).is_some_and(|e| {
                                            Arc::ptr_eq(&e.1, &sock_r) && e.2.elapsed() <= idle
                                        });
                                    if !active {
                                        break;
                                    }
                                }
                            }
                        }
                        let mut flows = flows_r.lock().await;
                        if flows
                            .get(&client)
                            .is_some_and(|e| Arc::ptr_eq(&e.1, &sock_r))
                        {
                            flows.remove(&client);
                        }
                    });
                }
                // first send
                if let Err(e) = sock.send_to(&packet, backend).await {
                    eprintln!("front: first send to {:?} backend {}: {}", kind, backend, e);
                    continue;
                }
                println!("front: new {:?} flow {} → {}", kind, src, backend);
                g.insert(src, (kind, Arc::clone(&sock), Instant::now()));
                continue; // already sent
            }
        };

        // existing flow: pick backend by kind
        let kind = {
            let g = flows.lock().await;
            g.get(&src).map(|e| e.0).unwrap_or(FlowKind::Minecraft)
        };
        let backend = match kind {
            FlowKind::Pvp => pvp_backend,
            FlowKind::Minecraft => mc_backend,
        };
        if let Err(e) = backend_sock.send_to(&packet, backend).await {
            eprintln!("front: send {} → {}: {}", src, backend, e);
        }
    }
}

async fn handle_control(
    socket: &UdpSocket,
    rooms: &Rooms,
    peer_index: &PeerIndex,
    expected_token: &str,
    src: SocketAddr,
    packet: &[u8],
) {
    let msg_type = packet[4];
    match msg_type {
        MSG_JOIN | MSG_KEEPALIVE => {
            let body = &packet[5..];
            let parsed = match parse_join_body(body) {
                Ok(v) => v,
                Err(e) => {
                    let _ = send_error(socket, src, 1, e).await;
                    return;
                }
            };
            let (room_id, token) = parsed;

            if !tokens_equal(token, expected_token) {
                let _ = send_error(socket, src, 2, "invalid token").await;
                return;
            }

            let status = {
                let mut rooms_g = rooms.lock().await;
                let mut index_g = peer_index.lock().await;

                if let Some(old_room) = index_g.get(&src).cloned() {
                    if old_room != room_id {
                        if let Some(room) = rooms_g.get_mut(&old_room) {
                            room.remove(src);
                            if let Some(other) = room.other(src) {
                                let _ = send_simple(socket, other, MSG_PEER_GONE).await;
                            }
                            if room.is_empty() {
                                rooms_g.remove(&old_room);
                            }
                        }
                        index_g.remove(&src);
                    }
                }

                if !rooms_g.contains_key(&room_id) && rooms_g.len() >= MAX_ROOMS {
                    return;
                }
                let room = rooms_g.entry(room_id.clone()).or_default();

                if room.peers.contains(&src) {
                    room.touch(src);
                    if room.peers.len() >= 2 {
                        STATUS_PEER_PRESENT
                    } else {
                        STATUS_WAITING
                    }
                } else if room.peers.len() >= MAX_PEERS_PER_ROOM {
                    drop(rooms_g);
                    drop(index_g);
                    let _ = send_error(socket, src, 3, "room full").await;
                    return;
                } else {
                    let had_peer = !room.peers.is_empty();
                    room.touch(src);
                    index_g.insert(src, room_id.clone());
                    let status = if room.peers.len() >= 2 {
                        STATUS_PEER_PRESENT
                    } else {
                        STATUS_WAITING
                    };
                    if had_peer {
                        if let Some(other) = room.other(src) {
                            let _ = send_status(socket, other, MSG_PEER_READY, STATUS_PEER_PRESENT)
                                .await;
                        }
                    }
                    println!(
                        "JOIN room={} peer={} peers_in_room={}",
                        room_id,
                        src,
                        room.peers.len()
                    );
                    status
                }
            };

            let _ = send_status(socket, src, MSG_JOIN_OK, status).await;
        }
        _ => {}
    }
}

async fn forward_data(
    socket: &UdpSocket,
    rooms: &Rooms,
    peer_index: &PeerIndex,
    src: SocketAddr,
    packet: &[u8],
) {
    if packet.is_empty() {
        return;
    }

    let other = {
        let mut rooms_g = rooms.lock().await;
        let index_g = peer_index.lock().await;
        let room_id = match index_g.get(&src) {
            Some(r) => r.clone(),
            None => return,
        };
        let room = match rooms_g.get_mut(&room_id) {
            Some(r) => r,
            None => return,
        };
        room.touch(src);
        room.other(src)
    };

    if let Some(dst) = other {
        if let Err(e) = socket.send_to(packet, dst).await {
            eprintln!("forward {} -> {}: {}", src, dst, e);
        }
    }
}

async fn cleanup_stale(rooms: &Rooms, peer_index: &PeerIndex, socket: &UdpSocket) {
    let now = Instant::now();
    let mut rooms_g = rooms.lock().await;
    let mut index_g = peer_index.lock().await;
    let mut empty_rooms = Vec::new();

    for (room_id, room) in rooms_g.iter_mut() {
        let stale: Vec<SocketAddr> = room
            .last_seen
            .iter()
            .filter(|(_, t)| now.duration_since(**t) > PEER_TIMEOUT)
            .map(|(a, _)| *a)
            .collect();

        for addr in stale {
            println!("timeout peer {} room={}", addr, room_id);
            room.remove(addr);
            index_g.remove(&addr);
            if let Some(other) = room.other(addr) {
                let _ = send_simple(socket, other, MSG_PEER_GONE).await;
            }
        }
        if room.is_empty() {
            empty_rooms.push(room_id.clone());
        }
    }
    for id in empty_rooms {
        rooms_g.remove(&id);
    }
}

fn parse_join_body(body: &[u8]) -> Result<(String, &str), &'static str> {
    if body.is_empty() {
        return Err("empty join body");
    }
    let room_len = body[0] as usize;
    if room_len == 0 || room_len > MAX_ROOM_LEN {
        return Err("invalid room length");
    }
    if body.len() < 1 + room_len + 1 {
        return Err("truncated join (room)");
    }
    let room_bytes = &body[1..1 + room_len];
    let room = std::str::from_utf8(room_bytes).map_err(|_| "room not utf-8")?;
    let rest = &body[1 + room_len..];
    let token_len = rest[0] as usize;
    if token_len == 0 || token_len > MAX_TOKEN_LEN {
        return Err("invalid token length");
    }
    if rest.len() < 1 + token_len {
        return Err("truncated join (token)");
    }
    let token_bytes = &rest[1..1 + token_len];
    let token = std::str::from_utf8(token_bytes).map_err(|_| "token not utf-8")?;
    Ok((room.to_string(), token))
}

fn tokens_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn send_status(
    socket: &UdpSocket,
    dst: SocketAddr,
    msg_type: u8,
    status: u8,
) -> std::io::Result<()> {
    let mut pkt = Vec::with_capacity(6);
    pkt.extend_from_slice(MAGIC);
    pkt.push(msg_type);
    pkt.push(status);
    socket.send_to(&pkt, dst).await.map(|_| ())
}

async fn send_simple(socket: &UdpSocket, dst: SocketAddr, msg_type: u8) -> std::io::Result<()> {
    let mut pkt = Vec::with_capacity(5);
    pkt.extend_from_slice(MAGIC);
    pkt.push(msg_type);
    socket.send_to(&pkt, dst).await.map(|_| ())
}

async fn send_error(
    socket: &UdpSocket,
    dst: SocketAddr,
    code: u8,
    msg: &str,
) -> std::io::Result<()> {
    let msg_bytes = msg.as_bytes();
    let len = msg_bytes.len().min(200) as u8;
    let mut pkt = Vec::with_capacity(7 + len as usize);
    pkt.extend_from_slice(MAGIC);
    pkt.push(MSG_ERROR);
    pkt.push(code);
    pkt.push(len);
    pkt.extend_from_slice(&msg_bytes[..len as usize]);
    socket.send_to(&pkt, dst).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn public_front_bounds_flows_and_releases_idle_reader_sockets() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let target = backend.local_addr().unwrap();
        let task = tokio::spawn(run_public_front_with_limits(
            address,
            target,
            target,
            2,
            Duration::from_millis(200),
            Duration::from_millis(20),
        ));
        time::sleep(Duration::from_millis(30)).await;
        let mut buffer = [0; 64];
        let mut readers = Vec::new();
        let mut clients = Vec::new();
        for _ in 0..2 {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(b"PVPR", address).await.unwrap();
            let (_, reader) = time::timeout(Duration::from_secs(1), backend.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            readers.push(reader);
            clients.push(client);
        }
        let third = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        third.send_to(b"PVPR", address).await.unwrap();
        assert!(
            time::timeout(Duration::from_millis(50), backend.recv_from(&mut buffer))
                .await
                .is_err()
        );
        time::sleep(Duration::from_millis(250)).await;
        // Bind each former backend port: the reader and its socket really exited.
        for reader in readers {
            assert!(UdpSocket::bind(reader).await.is_ok());
        }
        third.send_to(b"PVPR", address).await.unwrap();
        assert!(
            time::timeout(Duration::from_secs(1), backend.recv_from(&mut buffer))
                .await
                .is_ok()
        );
        task.abort();
    }
    #[test]
    fn parse_join_roundtrip_shape() {
        let room = "call1";
        let token = "secret";
        let mut body = Vec::new();
        body.push(room.len() as u8);
        body.extend_from_slice(room.as_bytes());
        body.push(token.len() as u8);
        body.extend_from_slice(token.as_bytes());
        let (r, t) = parse_join_body(&body).unwrap();
        assert_eq!(r, "call1");
        assert_eq!(t, "secret");
    }

    #[test]
    fn tokens_equal_works() {
        assert!(tokens_equal("abc", "abc"));
        assert!(!tokens_equal("abc", "abd"));
        assert!(!tokens_equal("abc", "ab"));
    }

    #[test]
    fn magic_is_pvpr() {
        assert_eq!(MAGIC, b"PVPR");
    }
}
