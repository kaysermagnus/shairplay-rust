//! DACP (Digital Audio Control Protocol) client for remote-controlling Apple devices.
//!
//! When an iPhone/iPad/Mac streams audio via AirPlay, it advertises a `_dacp._tcp` mDNS
//! service. This module discovers that service and sends HTTP commands back to control
//! playback (play/pause, next, previous, volume, etc.).

#[cfg(not(target_os = "macos"))]
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use crate::error::NetworkError;
use tracing::debug;

/// Default DACP port, used when mDNS discovery of the `_dacp._tcp` service fails.
const DACP_DEFAULT_PORT: u16 = 3689;

const PLAY_PAUSE_PATH: &str = "/ctrl-int/1/playpause";
const NEXT_PATH: &str = "/ctrl-int/1/nextitem";
const PREVIOUS_PATH: &str = "/ctrl-int/1/previtem";
const STOP_PATH: &str = "/ctrl-int/1/stop";

fn volume_path(volume: u8) -> String {
    format!("/ctrl-int/1/setproperty?dmcp.volume={}", volume.min(100))
}

fn shuffle_path(on: bool) -> String {
    let state = if on { 1 } else { 0 };
    format!("/ctrl-int/1/setproperty?dacp.shufflestate={state}")
}

fn repeat_path(state: u8) -> String {
    format!("/ctrl-int/1/setproperty?dacp.repeatstate={state}")
}

/// Browse `_dacp._tcp` via mDNS and return the port for the given DACP-ID.
/// Returns None if not found within 2 seconds.
#[cfg(not(target_os = "macos"))]
fn discover_dacp_port(dacp_id: &str, _remote_ip: std::net::IpAddr) -> Option<u16> {
    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let receiver = daemon.browse("_dacp._tcp.local.").ok()?;
    let target = dacp_id.to_uppercase();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);

    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(deadline.duration_since(std::time::Instant::now())) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                if info.get_fullname().to_uppercase().contains(&target) {
                    let port = info.get_port();
                    let _ = daemon.shutdown();
                    return Some(port);
                }
            }
            Err(_) => break,
            _ => {}
        }
    }
    let _ = daemon.shutdown();
    None
}

/// Browse `_dacp._tcp` via Bonjour and return the port for the given DACP-ID.
/// Returns None if not found within 2 seconds.
#[cfg(target_os = "macos")]
fn discover_dacp_ports(dacp_id: &str, remote_ip: std::net::IpAddr) -> Vec<u16> {
    let Some(browser) = astro_dnssd::ServiceBrowserBuilder::new("_dacp._tcp")
        .browse()
        .ok()
    else {
        return Vec::new();
    };
    let target = dacp_id.to_uppercase();
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut named = Vec::new();
    let mut peer = Vec::new();

    // recv_timeout errors are not all fatal: a service that fails to
    // resolve surfaces as Err too, and breaking then would drop a
    // still-pending matching service.
    while std::time::Instant::now() < deadline {
        match browser.recv_timeout(deadline.duration_since(std::time::Instant::now())) {
            Ok(service) => {
                if service.name.to_uppercase().contains(&target) {
                    named.push(service.port);
                }
                // Some senders never advertise a service named after the
                // session's DACP-ID; then any `_dacp._tcp` service that
                // resolves to the RTSP peer is a phone endpoint to try.
                else if let Ok(addrs) = service.resolve_socket_addrs(Duration::from_millis(500)) {
                    if addrs.iter().any(|a| a.ip() == remote_ip) {
                        peer.push(service.port);
                    }
                }
            }
            Err(_) => {
                if !named.is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    named.extend(peer);
    named
}

/// Client for sending DACP remote control commands to an Apple device.
///
/// Created from the DACP ID and Active-Remote header received by the AirPlay session.
///
/// # Example
/// ```text
/// let mut client = DacpClient::new("7711DA8B47838CB5", "1986535575");
/// client.discover_from_remote("192.168.1.5".parse().unwrap());
/// // Then from a synchronous remote-control callback:
/// // client.play_pause_blocking().ok();
/// ```
/// HTTP client for sending DACP playback commands to the iPhone.
#[derive(Debug)]
pub(crate) struct DacpClient {
    /// DACP-ID from the RTSP session. Identifies the `_dacp._tcp` mDNS service.
    dacp_id: String,
    active_remote: String,
    remote: Option<SocketAddr>,
    addr: std::sync::Mutex<Option<Vec<SocketAddr>>>,
}

impl DacpClient {
    /// Create a new DACP client from the values received in the AirPlay session.
    pub(crate) fn new(dacp_id: &str, active_remote: &str) -> Self {
        Self {
            dacp_id: dacp_id.to_string(),
            active_remote: active_remote.to_string(),
            remote: None,
            addr: std::sync::Mutex::new(None),
        }
    }

    /// Discover the sender's DACP port over mDNS and aim commands at
    /// the RTSP peer's own address — for an IPv6 link-local peer the
    /// accepted socket carries the interface scope, which the bare
    /// `IpAddr` loses and `connect()` then rejects with `EHOSTUNREACH`.
    /// Falls back to port 3689 on the remote IP if discovery fails.
    pub(crate) fn discover_from_remote(&mut self, remote: SocketAddr) {
        self.remote = Some(remote);
        self.rediscover();
    }

    /// The sender may not advertise `_dacp._tcp` yet when SETUP runs, so
    /// discovery is retried from command calls while only the 3689
    /// fallback is known.
    fn rediscover(&self) {
        let Some(remote) = self.remote else { return };
        #[cfg(target_os = "macos")]
        let ports = discover_dacp_ports(&self.dacp_id, remote.ip());
        #[cfg(not(target_os = "macos"))]
        let ports = discover_dacp_port(&self.dacp_id, remote.ip())
            .into_iter()
            .collect::<Vec<u16>>();
        let ports = if ports.is_empty() {
            vec![DACP_DEFAULT_PORT]
        } else {
            ports
        };
        *self.addr.lock().unwrap() = Some(
            ports
                .into_iter()
                .map(|port| match remote {
                    SocketAddr::V6(v6) => {
                        SocketAddr::V6(SocketAddrV6::new(*v6.ip(), port, 0, v6.scope_id()))
                    }
                    SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), port)),
                })
                .collect(),
        );
    }

    /// Send a raw DACP command from synchronous callbacks.
    pub(crate) fn command_blocking(&self, path: &str) -> Result<(), NetworkError> {
        let mut addrs = self.addr.lock().unwrap().clone().unwrap_or_default();
        // Still on the 3689 fallback? Give discovery another shot.
        if addrs.iter().all(|a| a.port() == DACP_DEFAULT_PORT) || addrs.is_empty() {
            self.rediscover();
            addrs = self.addr.lock().unwrap().clone().unwrap_or_default();
        }
        if addrs.is_empty() {
            return Err(NetworkError::Mdns(
                "DACP not discovered yet — call discover() first".into(),
            ));
        }
        // A sender can run several DACP endpoints; only the session's
        // accepts our Active-Remote. Try each, first 2xx wins.
        let mut last_err = None;
        for addr in addrs {
            match self.command_to(addr, path) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap())
    }

    /// macOS blocks outbound LAN TCP when the responsible process is an
    /// unsigned binary (EHOSTUNREACH to any local address), and that
    /// attribution covers spawned children. Routing the command through
    /// osascript makes a signed process the responsible one.
    #[cfg(target_os = "macos")]
    fn command_to(&self, addr: SocketAddr, path: &str) -> Result<(), NetworkError> {
        // curl needs the zone as an interface name, not a numeric scope id.
        let url = match addr {
            SocketAddr::V6(v) => {
                let zone = if_addrs::get_if_addrs()
                    .ok()
                    .and_then(|ifs| {
                        ifs.into_iter()
                            .find(|i| i.index == Some(v.scope_id()))
                            .map(|i| i.name)
                    })
                    .unwrap_or_else(|| v.scope_id().to_string());
                format!("http://[{}%{}]:{}{}", v.ip(), zone, v.port(), path)
            }
            SocketAddr::V4(v) => format!("http://{}:{}{}", v.ip(), v.port(), path),
        };
        // `launchctl asuser` runs the command under launchd, so the
        // responsible process is not the unsigned receiver.
        let uid = std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
            .unwrap_or(0);
        if uid == 0 {
            return Err(NetworkError::Mdns("could not resolve uid".into()));
        }
        let out = std::process::Command::new("/bin/launchctl")
            .arg("asuser")
            .arg(uid.to_string())
            .args([
                "/usr/bin/curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "2",
                "-H",
            ])
            .arg(format!("Active-Remote: {}", self.active_remote))
            .arg("-H")
            .arg(format!("DACP-ID: {}", self.dacp_id))
            .arg(&url)
            .output()
            .map_err(NetworkError::Io)?;
        let code = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || !code.trim_start().starts_with('2') {
            return Err(NetworkError::Mdns(format!(
                "DACP command rejected: HTTP {code} (curl status {}) {url}",
                out.status.code().unwrap_or(-1)
            )));
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn command_to(&self, addr: SocketAddr, path: &str) -> Result<(), NetworkError> {
        let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .map_err(|e| NetworkError::Mdns(format!("{e} ({addr})")))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let request = self.command_request(path, addr);
        stream.write_all(request.as_bytes())?;

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let response = String::from_utf8_lossy(&buf[..n]);
        // Apple senders answer 204 on success; anything else means the
        // command never ran, so staying silent would hide the failure.
        let status = response.split_whitespace().nth(1).unwrap_or_default();
        if !status.starts_with('2') {
            return Err(NetworkError::Mdns(format!(
                "DACP command rejected: {}",
                response.lines().next().unwrap_or("no response")
            )));
        }
        Ok(())
    }

    pub(crate) fn play_pause_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(PLAY_PAUSE_PATH)
    }

    pub(crate) fn next_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(NEXT_PATH)
    }

    pub(crate) fn prev_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(PREVIOUS_PATH)
    }

    pub(crate) fn stop_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(STOP_PATH)
    }

    pub(crate) fn set_volume_blocking(&self, volume: u8) -> Result<(), NetworkError> {
        self.command_blocking(&volume_path(volume))
    }

    pub(crate) fn set_shuffle_blocking(&self, on: bool) -> Result<(), NetworkError> {
        self.command_blocking(&shuffle_path(on))
    }

    pub(crate) fn set_repeat_blocking(&self, state: u8) -> Result<(), NetworkError> {
        self.command_blocking(&repeat_path(state))
    }

    #[cfg(not(target_os = "macos"))]
    fn command_request(&self, path: &str, addr: SocketAddr) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nActive-Remote: {}\r\nDACP-ID: {}\r\nHost: {addr}\r\n\r\n",
            self.active_remote, self.dacp_id
        )
    }
}
