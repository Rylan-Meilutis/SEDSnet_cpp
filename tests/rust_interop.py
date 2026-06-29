#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import textwrap
import tomllib
from pathlib import Path


DEFAULT_RUST_REPO_URL = "https://github.com/Rylan-Meilutis/sedsprintf_rs.git"


RUST_MAIN = r'''
use sedsprintf_rs::config::{DataEndpoint, DataType};
use sedsprintf_rs::packet::Packet;
use sedsprintf_rs::relay::{Relay, RelaySideOptions};
use sedsprintf_rs::router::{Clock, EndpointHandler, NetworkVariablePermissions, Router, RouterConfig, RouterSideOptions};
use sedsprintf_rs::timesync::{TimeSyncConfig, TimeSyncRole};
use sedsprintf_rs::wire_format;
use sedsprintf_rs::TelemetryResult;
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SharedClock {
    now: Arc<AtomicU64>,
}

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> TelemetryResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(sedsprintf_rs::TelemetryError::Unpack("odd hex length"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for idx in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16)
            .map_err(|_| sedsprintf_rs::TelemetryError::Unpack("bad hex"))?;
        out.push(byte);
    }
    Ok(out)
}

fn capture_side() -> (Arc<Mutex<Vec<Vec<u8>>>>, impl Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static) {
    let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let out = captured.clone();
    (captured, move |bytes| {
        out.lock().unwrap().push(bytes.to_vec());
        Ok(())
    })
}

fn is_gps_data_frame(bytes: &[u8]) -> bool {
    wire_format::peek_frame_info(bytes)
        .map(|frame| frame.envelope.ty == DataType::named("GPS_DATA") && !frame.ack_only())
        .unwrap_or(false)
}

fn is_managed_request_frame(bytes: &[u8]) -> bool {
    wire_format::peek_frame_info(bytes)
        .map(|frame| frame.envelope.ty == DataType::ManagedVariableRequest && !frame.ack_only())
        .unwrap_or(false)
}

fn p2p_payload(source_hostname: &str, source_address: u32, source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1);
    out.extend_from_slice(&destination_port.to_le_bytes());
    out.extend_from_slice(&source_port.to_le_bytes());
    out.extend_from_slice(&source_address.to_le_bytes());
    out.extend_from_slice(&(source_hostname.len() as u16).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(source_hostname.as_bytes());
    out.extend_from_slice(body);
    out
}

fn p2p_stream_payload(flags: u8, source_stream_id: u32, destination_stream_id: u32, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SDSP");
    out.push(1);
    out.push(flags);
    out.extend_from_slice(&source_stream_id.to_le_bytes());
    out.extend_from_slice(&destination_stream_id.to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn emit() -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_INTEROP"),
        Box::new(|| 123_u64),
    );
    router.add_side_packed("cpp", tx);
    router.log_ts(DataType::named("GPS_DATA"), 123, &[11.25_f32, -2.5, 99.0])?;
    let frames = captured.lock().unwrap();
    let bytes = frames.last().ok_or(sedsprintf_rs::TelemetryError::Io("rust emitted no frame"))?;
    println!("{}", hex_encode(bytes));
    Ok(())
}

fn consume(hex: &str) -> TelemetryResult<()> {
    let values = Arc::new(Mutex::new(None::<Vec<f32>>));
    let seen = values.clone();
    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
        *seen.lock().unwrap() = Some(pkt.data_as_f32()?);
        Ok(())
    });
    let router = Router::new_with_clock(
        RouterConfig::new([handler]).with_sender("RUST_INTEROP"),
        Box::new(|| 123_u64),
    );
    let bytes = hex_decode(hex)?;
    router.rx_packed(&bytes)?;
    let got = values
        .lock()
        .unwrap()
        .clone()
        .ok_or(sedsprintf_rs::TelemetryError::Io("rust received no packet"))?;
    println!("{} {} {}", got[0], got[1], got[2]);
    Ok(())
}

fn consume_reliable(hex: &str) -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let values = Arc::new(Mutex::new(None::<Vec<f32>>));
    let seen = values.clone();
    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
        *seen.lock().unwrap() = Some(pkt.data_as_f32()?);
        Ok(())
    });
    let router = Router::new_with_clock(
        RouterConfig::new([handler]).with_sender("RUST_RELIABLE"),
        Box::new(|| 123_u64),
    );
    let side = router.add_side_packed_with_options(
        "cpp",
        tx,
        RouterSideOptions {
            reliable_enabled: true,
            ..Default::default()
        },
    );
    router.rx_packed_from_side(&hex_decode(hex)?, side)?;
    router.process_tx_queue()?;
    let frames = captured.lock().unwrap();
    if frames.is_empty() {
        return Err(sedsprintf_rs::TelemetryError::Io("rust emitted no ack"));
    }
    let got = values
        .lock()
        .unwrap()
        .clone()
        .ok_or(sedsprintf_rs::TelemetryError::Io("rust received no reliable packet"))?;
    for frame in frames.iter() {
        println!("{}", hex_encode(frame));
    }
    println!("{} {} {}", got[0], got[1], got[2]);
    Ok(())
}

fn reliable_session() -> TelemetryResult<()> {
    let now = Arc::new(AtomicU64::new(123));
    let clock = SharedClock { now: now.clone() };
    let (captured, tx) = capture_side();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_RELIABLE"),
        Box::new(clock),
    );
    let side = router.add_side_packed_with_options(
        "cpp",
        tx,
        RouterSideOptions {
            reliable_enabled: true,
            ..Default::default()
        },
    );
    router.log_ts(DataType::named("GPS_DATA"), 123, &[61.0_f32, 62.0, 63.0])?;
    {
        let frames = captured.lock().unwrap();
        let data = frames.last().ok_or(sedsprintf_rs::TelemetryError::Io("rust emitted no reliable frame"))?;
        println!("{}", hex_encode(data));
    }

    let mut saw_ack = false;
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|_| sedsprintf_rs::TelemetryError::Io("failed to read ack"))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        router.rx_packed_from_side(&hex_decode(line)?, side)?;
        saw_ack = true;
    }
    if !saw_ack {
        return Err(sedsprintf_rs::TelemetryError::Io("session received no ack"));
    }

    captured.lock().unwrap().clear();
    now.store(500, Ordering::Relaxed);
    router.process_tx_queue()?;
    if captured.lock().unwrap().iter().any(|frame| is_gps_data_frame(frame)) {
        return Err(sedsprintf_rs::TelemetryError::Io("rust retransmitted after ack"));
    }
    println!("ACK_ACCEPTED");
    Ok(())
}

fn print_relay_frames(prefix: &str, frames: &[Vec<u8>]) {
    for frame in frames {
        println!("{prefix} {}", hex_encode(frame));
    }
}

fn relay_session() -> TelemetryResult<()> {
    let now = Arc::new(AtomicU64::new(123));
    let clock = SharedClock { now };
    let relay = Relay::new(Box::new(clock));
    let (to_source, source_tx) = capture_side();
    let (to_dest, dest_tx) = capture_side();
    let opts = RelaySideOptions {
        reliable_enabled: true,
        ..Default::default()
    };
    let source = relay.add_side_packed_with_options("source", source_tx, opts);
    let dest = relay.add_side_packed_with_options("dest", dest_tx, opts);

    let mut stdin = io::stdin().lock();
    let mut data_hex = String::new();
    stdin
        .read_line(&mut data_hex)
        .map_err(|_| sedsprintf_rs::TelemetryError::Io("relay failed to read data"))?;
    relay.rx_packed_from_side(source, &hex_decode(data_hex.trim())?)?;
    relay.process_all_queues()?;
    {
        let src = to_source.lock().unwrap();
        let dst = to_dest.lock().unwrap();
        if src.is_empty() || dst.is_empty() {
            return Err(sedsprintf_rs::TelemetryError::Io("relay did not ack and forward data"));
        }
        print_relay_frames("SRC", &src);
        print_relay_frames("DST", &dst);
    }
    println!("END");
    to_source.lock().unwrap().clear();
    to_dest.lock().unwrap().clear();

    for line in stdin.lines() {
        let line = line.map_err(|_| sedsprintf_rs::TelemetryError::Io("relay failed to read ack"))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        relay.rx_packed_from_side(dest, &hex_decode(line)?)?;
        relay.process_all_queues()?;
    }
    {
        let src = to_source.lock().unwrap();
        let dst = to_dest.lock().unwrap();
        print_relay_frames("SRC", &src);
        print_relay_frames("DST", &dst);
    }
    println!("END");
    Ok(())
}

fn relay_forward(hexes: &[String]) -> TelemetryResult<()> {
    let relay = Relay::new(Box::new(|| 123_u64));
    let (_to_source, source_tx) = capture_side();
    let (to_dest, dest_tx) = capture_side();
    let source = relay.add_side_packed("source", source_tx);
    relay.add_side_packed("dest", dest_tx);
    for hex in hexes {
        let bytes = hex_decode(hex)?;
        if relay.rx_packed_from_side(source, &bytes).is_ok() {
            let _ = relay.process_all_queues();
        }
    }
    let frames = to_dest.lock().unwrap();
    if frames.is_empty() {
        return Err(sedsprintf_rs::TelemetryError::Io("relay forwarded no frames"));
    }
    for frame in frames.iter() {
        println!("{}", hex_encode(frame));
    }
    Ok(())
}

fn emit_discovery() -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), |_pkt| Ok(()));
    let router = Router::new_with_clock(
        RouterConfig::new([handler]).with_sender("RUST_DISC"),
        Box::new(|| 123_u64),
    );
    router.add_side_packed("cpp", tx);
    router.announce_discovery()?;
    router.process_tx_queue()?;
    for frame in captured.lock().unwrap().iter() {
        println!("{}", hex_encode(frame));
    }
    Ok(())
}

fn consume_discovery(hexes: &[String]) -> TelemetryResult<()> {
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_DISC_CONSUMER"),
        Box::new(|| 123_u64),
    );
    let side = router.add_side_packed("cpp", |_bytes| Ok(()));
    for hex in hexes {
        let bytes = hex_decode(hex)?;
        let _ = router.rx_packed_queue_from_side(&bytes, side);
    }
    let _ = router.process_all_queues();
    println!("DISCOVERY_OK");
    Ok(())
}

fn source_timesync_config() -> TimeSyncConfig {
    TimeSyncConfig {
        role: TimeSyncRole::Source,
        priority: 10,
        ..Default::default()
    }
}

fn consumer_timesync_config() -> TimeSyncConfig {
    TimeSyncConfig {
        role: TimeSyncRole::Consumer,
        priority: 100,
        ..Default::default()
    }
}

fn emit_timesync() -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("RUST_TIME")
            .with_timesync(source_timesync_config()),
        Box::new(|| 1000_u64),
    );
    router.add_side_packed("cpp", tx);
    router.set_local_network_datetime(2026, 1, 2, 3, 4, 5);
    router.poll_timesync()?;
    router.process_tx_queue()?;
    for frame in captured.lock().unwrap().iter() {
        println!("{}", hex_encode(frame));
    }
    Ok(())
}

fn consume_timesync(hexes: &[String]) -> TelemetryResult<()> {
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("RUST_TIME_CONSUMER")
            .with_timesync(consumer_timesync_config()),
        Box::new(|| 1000_u64),
    );
    let side = router.add_side_packed("cpp", |_bytes| Ok(()));
    for hex in hexes {
        router.rx_packed_from_side(&hex_decode(hex)?, side)?;
    }
    let network_ms = router
        .network_time_ms()
        .ok_or(sedsprintf_rs::TelemetryError::Io("rust did not learn network time"))?;
    println!("{network_ms}");
    Ok(())
}

fn emit_managed() -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_MANAGED"),
        Box::new(|| 123_u64),
    );
    router.add_side_packed("cpp", tx);
    let ty = DataType::named("GPS_DATA");
    router.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)?;
    let endpoints = [DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(ty, &[71.0_f32, 72.0, 73.0], &endpoints, 123)?;
    router.set_network_variable(pkt)?;
    router.process_tx_queue()?;
    let frames = captured.lock().unwrap();
    let frame = frames
        .iter()
        .find(|frame| is_gps_data_frame(frame))
        .ok_or(sedsprintf_rs::TelemetryError::Io("rust emitted no managed frame"))?;
    println!("{}", hex_encode(frame));
    Ok(())
}

fn consume_managed(hex: &str) -> TelemetryResult<()> {
    let seen = Arc::new(Mutex::new(0_u32));
    let seen_cb = seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_MANAGED_CONSUMER"),
        Box::new(|| 123_u64),
    );
    let ty = DataType::named("GPS_DATA");
    router.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)?;
    router.on_network_variable_update(ty, move |pkt| {
        let values = pkt.data_as_f32()?;
        if values.len() == 3 {
            *seen_cb.lock().unwrap() += 1;
        }
        Ok(())
    })?;
    router.rx_packed(&hex_decode(hex)?)?;
    let cached = router
        .get_network_variable(ty, Some(10_000))?
        .ok_or(sedsprintf_rs::TelemetryError::Io("rust managed cache empty"))?;
    let values = cached.data_as_f32()?;
    println!("{} {} {} {}", values[0], values[1], values[2], *seen.lock().unwrap());
    Ok(())
}

fn request_managed(hex: &str) -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_MANAGED_SOURCE"),
        Box::new(|| 123_u64),
    );
    let side = router.add_side_packed("cpp", tx);
    let ty = DataType::named("GPS_DATA");
    router.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)?;
    let endpoints = [DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(ty, &[91.0_f32, 92.0, 93.0], &endpoints, 123)?;
    router.seed_managed_variable(pkt)?;
    router.rx_packed_from_side(&hex_decode(hex)?, side)?;
    router.process_tx_queue()?;
    for frame in captured.lock().unwrap().iter() {
        if is_gps_data_frame(frame) {
            println!("{}", hex_encode(frame));
        }
    }
    Ok(())
}

fn emit_managed_request() -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("RUST_MANAGED_REQUESTER"),
        Box::new(|| 123_u64),
    );
    router.add_side_packed("cpp", tx);
    let ty = DataType::named("GPS_DATA");
    router.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)?;
    let _ = router.get_network_variable(ty, Some(0))?;
    router.process_tx_queue()?;
    let frames = captured.lock().unwrap();
    let frame = frames
        .iter()
        .find(|frame| is_managed_request_frame(frame))
        .ok_or(sedsprintf_rs::TelemetryError::Io("rust emitted no managed request"))?;
    println!("{}", hex_encode(frame));
    Ok(())
}

fn emit_p2p() -> TelemetryResult<()> {
    let payload = p2p_payload("rust-p2p", 0x7071, 49152, 777, b"rust-p2p");
    let pkt = Packet::new(DataType::P2pMessage, &[DataEndpoint::Discovery], "rust-p2p", 123, payload.into())?;
    println!("{}", hex_encode(&wire_format::pack_packet(&pkt)));
    Ok(())
}

fn consume_p2p(hex: &str) -> TelemetryResult<()> {
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let seen_cb = seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_hostname("rust-p2p-consumer").with_static_address(0x7072),
        Box::new(|| 123_u64),
    );
    router.bind_p2p_port(777, move |msg| {
        *seen_cb.lock().unwrap() = msg.payload.to_vec();
        Ok(())
    })?;
    router.rx_packed(&hex_decode(hex)?)?;
    let payload = seen.lock().unwrap().clone();
    if payload.is_empty() {
        return Err(sedsprintf_rs::TelemetryError::Io("rust received no p2p datagram"));
    }
    println!("{}", String::from_utf8_lossy(&payload));
    Ok(())
}

fn emit_p2p_stream_syn() -> TelemetryResult<()> {
    let stream = p2p_stream_payload(0x01, 1, 0, 0, &[]);
    let payload = p2p_payload("rust-stream", 0x7073, 49200, 8080, &stream);
    let pkt = Packet::new(DataType::P2pMessage, &[DataEndpoint::Discovery], "rust-stream", 123, payload.into())?;
    println!("{}", hex_encode(&wire_format::pack_packet(&pkt)));
    Ok(())
}

fn accept_p2p_stream(hex: &str) -> TelemetryResult<()> {
    let (captured, tx) = capture_side();
    let accepted = Arc::new(Mutex::new(0_u32));
    let accepted_cb = accepted.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_hostname("rust-stream-server").with_static_address(0x7074),
        Box::new(|| 123_u64),
    );
    router.add_side_packed("cpp", tx);
    router.bind_p2p_stream_port(8080, move |event| {
        if event.kind == sedsprintf_rs::router::P2pStreamEventKind::Accepted {
            *accepted_cb.lock().unwrap() += 1;
        }
        Ok(())
    })?;
    router.rx_packed(&hex_decode(hex)?)?;
    router.process_tx_queue()?;
    if *accepted.lock().unwrap() == 0 {
        return Err(sedsprintf_rs::TelemetryError::Io("rust accepted no p2p stream"));
    }
    println!("accepted");
    for frame in captured.lock().unwrap().iter() {
        println!("{}", hex_encode(frame));
    }
    Ok(())
}

fn main() -> TelemetryResult<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("emit") => emit(),
        Some("consume") => consume(&args.next().ok_or(sedsprintf_rs::TelemetryError::BadArg)?),
        Some("consume-reliable") => consume_reliable(&args.next().ok_or(sedsprintf_rs::TelemetryError::BadArg)?),
        Some("reliable-session") => reliable_session(),
        Some("relay-session") => relay_session(),
        Some("relay-forward") => relay_forward(&args.collect::<Vec<_>>()),
        Some("emit-discovery") => emit_discovery(),
        Some("consume-discovery") => consume_discovery(&args.collect::<Vec<_>>()),
        Some("emit-timesync") => emit_timesync(),
        Some("consume-timesync") => consume_timesync(&args.collect::<Vec<_>>()),
        Some("emit-managed") => emit_managed(),
        Some("consume-managed") => consume_managed(&args.next().ok_or(sedsprintf_rs::TelemetryError::BadArg)?),
        Some("emit-managed-request") => emit_managed_request(),
        Some("request-managed") => request_managed(&args.next().ok_or(sedsprintf_rs::TelemetryError::BadArg)?),
        Some("emit-p2p") => emit_p2p(),
        Some("consume-p2p") => consume_p2p(&args.next().ok_or(sedsprintf_rs::TelemetryError::BadArg)?),
        Some("emit-p2p-stream-syn") => emit_p2p_stream_syn(),
        Some("accept-p2p-stream") => accept_p2p_stream(&args.next().ok_or(sedsprintf_rs::TelemetryError::BadArg)?),
        _ => Err(sedsprintf_rs::TelemetryError::BadArg),
    }
}
'''


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, end="")
        raise subprocess.CalledProcessError(
            completed.returncode,
            cmd,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed.stdout.strip()


def resolve_rust_root(requested_root: Path, work_dir: Path, repo_url: str) -> Path:
    requested_root = requested_root.expanduser()
    checkout = work_dir / "sedsprintf_rs"

    work_dir.mkdir(parents=True, exist_ok=True)
    if (requested_root / "Cargo.toml").is_file():
        if checkout.exists():
            shutil.rmtree(checkout)

        def ignore(_dir: str, names: list[str]) -> set[str]:
            ignored = {".git", "target", "__pycache__", ".pytest_cache"}
            return {name for name in names if name in ignored}

        shutil.copytree(requested_root, checkout, ignore=ignore)
    else:
        if not (checkout / "Cargo.toml").is_file():
            run(["git", "clone", "--depth", "1", repo_url, str(checkout)])
    patch_upstream_checkout_for_interop(checkout)
    return checkout.resolve()


def patch_upstream_checkout_for_interop(checkout: Path) -> None:
    router_rs = checkout / "src" / "router.rs"
    if not router_rs.is_file():
        text = ""
    else:
        text = router_rs.read_text(encoding="utf-8")
    constants = (
        "RuntimeMemoryConfig, MAX_QUEUE_BUDGET, MAX_RECENT_RX_IDS, "
        "QUEUE_GROW_STEP, RECENT_RX_QUEUE_BYTES, STARTING_QUEUE_SIZE"
    )
    old = "use crate::config::RuntimeMemoryConfig;"
    new = f"use crate::config::{{{constants}}};"
    if old in text and "MAX_QUEUE_BUDGET" in text and new not in text:
        text = text.replace(old, new, 1)
    moved_guard = """            let mut st = self.state.lock();
            st.make_shared_queue_room(incoming_cost, RouterQueueKind::Discovery)?;
            drop(st);
            let report =
                crate::config::merge_owned_schema_snapshot_with_budget(
                    snapshot,
                    st.memory.max_queue_budget,
                )?;"""
    fixed_guard = """            let mut st = self.state.lock();
            st.make_shared_queue_room(incoming_cost, RouterQueueKind::Discovery)?;
            let max_queue_budget = st.memory.max_queue_budget;
            drop(st);
            let report =
                crate::config::merge_owned_schema_snapshot_with_budget(snapshot, max_queue_budget)?;"""
    if moved_guard in text:
        text = text.replace(moved_guard, fixed_guard, 1)
    if router_rs.is_file():
        router_rs.write_text(text, encoding="utf-8")

    relay_rs = checkout / "src" / "relay.rs"
    if not relay_rs.is_file():
        return
    text = relay_rs.read_text(encoding="utf-8")
    old_config_tail = "RELIABLE_MAX_RETRIES, RELIABLE_MAX_RETURN_ROUTES, RELIABLE_RETRANSMIT_MS, RuntimeMemoryConfig,"
    new_config_tail = (
        "RELIABLE_MAX_RETRIES, RELIABLE_MAX_RETURN_ROUTES, RELIABLE_RETRANSMIT_MS, "
        f"{constants},"
    )
    if old_config_tail in text and new_config_tail not in text:
        text = text.replace(old_config_tail, new_config_tail, 1)
    old_relay_inner = """            state: RouterMutex::new(RelayInner {
                sides: Vec::new(),"""
    new_relay_inner = """            state: RouterMutex::new(RelayInner {
                memory: RuntimeMemoryConfig::default(),
                sides: Vec::new(),"""
    if old_relay_inner in text:
        text = text.replace(old_relay_inner, new_relay_inner, 1)
    relay_moved_guard = """            let mut st = self.state.lock();
            st.make_shared_queue_room(incoming_cost, RelayQueueKind::Discovery)?;
            drop(st);
            let report =
                crate::config::merge_owned_schema_snapshot_with_budget(snapshot, MAX_QUEUE_BUDGET)?;"""
    relay_fixed_guard = """            let mut st = self.state.lock();
            st.make_shared_queue_room(incoming_cost, RelayQueueKind::Discovery)?;
            let max_queue_budget = st.memory.max_queue_budget;
            drop(st);
            let report =
                crate::config::merge_owned_schema_snapshot_with_budget(snapshot, max_queue_budget)?;"""
    if relay_moved_guard in text:
        text = text.replace(relay_moved_guard, relay_fixed_guard, 1)
    relay_rs.write_text(text, encoding="utf-8")


def rust_build_env(schema_path: Path, ipc_schema_path: Path | None) -> dict[str, str]:
    env = os.environ.copy()
    env["SEDSPRINTF_RS_SCHEMA_PATH"] = str(schema_path.resolve())
    env["SEDSNET_STATIC_SCHEMA_PATH"] = str(schema_path.resolve())
    if ipc_schema_path is not None:
        env["SEDSPRINTF_RS_IPC_SCHEMA_PATH"] = str(ipc_schema_path.resolve())
        env["SEDSNET_STATIC_IPC_SCHEMA_PATH"] = str(ipc_schema_path.resolve())
    else:
        env.pop("SEDSPRINTF_RS_IPC_SCHEMA_PATH", None)
        env.pop("SEDSNET_STATIC_IPC_SCHEMA_PATH", None)
    return env


def run_session(cmd: list[str], responder: list[str]) -> None:
    proc = subprocess.Popen(
        cmd,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stdin is not None
    data_hex = proc.stdout.readline().strip()
    if not data_hex:
        stderr = proc.stderr.read() if proc.stderr is not None else ""
        raise AssertionError(f"session emitted no data: {stderr}")
    response = run([*responder, data_hex])
    ack_lines = [
        line.strip()
        for line in response.splitlines()
        if line.strip()
        and len(line.strip()) % 2 == 0
        and all(ch in "0123456789abcdefABCDEF" for ch in line.strip())
    ]
    if not ack_lines:
        raise AssertionError(f"responder emitted no serialized ack frames: {response!r}")
    # The responder may also emit discovery/schema frames. This session only
    # asserts link reliability, so feed back the ACK frame and leave schema
    # discovery coverage to the mixed-router relay paths.
    stdout, stderr = proc.communicate(input=ack_lines[0] + "\n", timeout=10)
    if proc.returncode != 0:
        print(stdout, end="")
        print(stderr, end="")
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=stdout, stderr=stderr)
    if "ACK_ACCEPTED" not in stdout:
        raise AssertionError(f"session did not accept ack: {stdout!r}")


def serialized_lines(output: str) -> list[str]:
    return [
        line.strip()
        for line in output.splitlines()
        if line.strip()
        and len(line.strip()) % 2 == 0
        and all(ch in "0123456789abcdefABCDEF" for ch in line.strip())
    ]


def read_relay_phase(proc: subprocess.Popen[str]) -> dict[str, list[str]]:
    assert proc.stdout is not None
    frames: dict[str, list[str]] = {"SRC": [], "DST": []}
    while True:
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read() if proc.stderr is not None else ""
            raise AssertionError(f"relay ended before phase marker: {stderr}")
        line = line.strip()
        if line == "END":
            return frames
        prefix, _, hex_frame = line.partition(" ")
        if prefix in frames and hex_frame:
            frames[prefix].append(hex_frame)


def run_relay_path(source: list[str], relay: list[str], destination: list[str]) -> None:
    src_proc = subprocess.Popen(
        source,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert src_proc.stdin is not None
    assert src_proc.stdout is not None
    data_hex = src_proc.stdout.readline().strip()
    if not data_hex:
        stderr = src_proc.stderr.read() if src_proc.stderr is not None else ""
        raise AssertionError(f"relay source emitted no data: {stderr}")

    relay_proc = subprocess.Popen(
        relay,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert relay_proc.stdin is not None
    relay_proc.stdin.write(data_hex + "\n")
    relay_proc.stdin.flush()
    first = read_relay_phase(relay_proc)
    if not first["SRC"] or not first["DST"]:
        raise AssertionError(f"relay did not emit source ACK and destination data: {first!r}")

    dest_response = None
    dest_error = None
    for frame in first["DST"]:
        try:
            dest_response = run([*destination, frame])
            break
        except subprocess.CalledProcessError as exc:
            dest_error = exc
    if dest_response is None:
        assert dest_error is not None
        raise dest_error
    dest_acks = serialized_lines(dest_response)
    if not dest_acks:
        raise AssertionError(f"destination emitted no ACK frames: {dest_response!r}")
    relay_proc.stdin.close()
    second = read_relay_phase(relay_proc)
    relay_stderr = relay_proc.stderr.read() if relay_proc.stderr is not None else ""
    if relay_proc.wait(timeout=10) != 0:
        raise subprocess.CalledProcessError(relay_proc.returncode, relay, stderr=relay_stderr)

    source_acks = (first["SRC"] + second["SRC"])[:1]
    stdout, stderr = src_proc.communicate(input="\n".join(source_acks) + "\n", timeout=10)
    if src_proc.returncode != 0:
        print(stdout, end="")
        print(stderr, end="")
        raise subprocess.CalledProcessError(src_proc.returncode, source, output=stdout, stderr=stderr)
    if "ACK_ACCEPTED" not in stdout:
        raise AssertionError(f"source did not accept relay-routed ACKs: {stdout!r}")


def assert_values(label: str, output: str, expected: tuple[float, float, float]) -> None:
    values = tuple(float(part) for part in output.splitlines()[-1].split())
    if len(values) != len(expected):
        raise AssertionError(f"{label}: expected {len(expected)} values, got {output!r}")
    for got, want in zip(values, expected):
        if abs(got - want) > 0.0001:
            raise AssertionError(f"{label}: expected {expected}, got {values}")


def ensure_rust_harness(work_dir: Path, rust_root: Path) -> Path:
    crate_dir = work_dir / "rust_router_interop"
    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    cargo_metadata = tomllib.loads((rust_root / "Cargo.toml").read_text(encoding="utf-8"))
    package_name = cargo_metadata.get("package", {}).get("name", "sedsprintf_rs")
    package_clause = "" if package_name == "sedsprintf_rs" else f', package = "{package_name}"'
    (crate_dir / "Cargo.toml").write_text(
        textwrap.dedent(
            f"""
            [package]
            name = "rust_router_interop"
            version = "0.0.0"
            edition = "2024"

            [dependencies]
            sedsprintf_rs = {{ path = "{rust_root.as_posix()}"{package_clause} }}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (src_dir / "main.rs").write_text(RUST_MAIN, encoding="utf-8")
    return crate_dir


def nonempty_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.strip()]


def assert_nonzero_ms(label: str, output: str) -> None:
    try:
        value = int(output.splitlines()[-1])
    except (IndexError, ValueError) as exc:
        raise AssertionError(f"{label}: invalid network time output {output!r}") from exc
    if value <= 0:
        raise AssertionError(f"{label}: expected nonzero network time, got {value}")


def assert_values_with_update(label: str, output: str, expected: tuple[float, float, float]) -> None:
    parts = output.splitlines()[-1].split()
    if len(parts) != 4:
        raise AssertionError(f"{label}: expected 4 values, got {output!r}")
    values = tuple(float(part) for part in parts[:3])
    updates = int(parts[3])
    for got, want in zip(values, expected):
        if abs(got - want) > 0.0001:
            raise AssertionError(f"{label}: expected {expected}, got {values}")
    if updates < 1:
        raise AssertionError(f"{label}: expected at least one update callback, got {updates}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpp-peer", required=True, type=Path)
    parser.add_argument("--rust-root", required=True, type=Path)
    parser.add_argument("--rust-repo-url", default=DEFAULT_RUST_REPO_URL)
    parser.add_argument("--schema-path", required=True, type=Path)
    parser.add_argument("--ipc-schema-path", type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()

    rust_root = resolve_rust_root(args.rust_root, args.work_dir, args.rust_repo_url)

    env = rust_build_env(args.schema_path, args.ipc_schema_path)
    crate_dir = ensure_rust_harness(args.work_dir, rust_root)
    cargo = ["cargo", "run", "--quiet", "--manifest-path", str(crate_dir / "Cargo.toml"), "--"]
    cpp = [str(args.cpp_peer)]

    rust_hex = run([*cargo, "emit"], env=env)
    assert_values("C++ receiving Rust frame", run([*cpp, "consume", rust_hex]), (11.25, -2.5, 99.0))

    cpp_hex = run([*cpp, "emit"])
    assert_values("Rust receiving C++ frame", run([*cargo, "consume", cpp_hex], env=env), (41.0, 42.5, -7.25))

    for key in ("SEDSPRINTF_RS_SCHEMA_PATH", "SEDSPRINTF_RS_IPC_SCHEMA_PATH",
                "SEDSNET_STATIC_SCHEMA_PATH", "SEDSNET_STATIC_IPC_SCHEMA_PATH"):
        if key in env:
            os.environ[key] = env[key]
        else:
            os.environ.pop(key, None)
    run_session([*cpp, "reliable-session"], [*cargo, "consume-reliable"])
    run_session([*cargo, "reliable-session"], [*cpp, "consume-reliable"])
    run_relay_path([*cpp, "reliable-session"], [*cargo, "relay-session"], [*cpp, "consume-reliable"])
    run_relay_path([*cpp, "reliable-session"], [*cargo, "relay-session"], [*cargo, "consume-reliable"])
    run_relay_path([*cargo, "reliable-session"], [*cpp, "relay-session"], [*cpp, "consume-reliable"])
    run_relay_path([*cargo, "reliable-session"], [*cpp, "relay-session"], [*cargo, "consume-reliable"])
    run_relay_path([*cpp, "reliable-session"], [*cpp, "relay-session"], [*cargo, "consume-reliable"])
    run_relay_path([*cargo, "reliable-session"], [*cargo, "relay-session"], [*cpp, "consume-reliable"])

    rust_discovery = nonempty_lines(run([*cargo, "emit-discovery"], env=env))
    if not rust_discovery:
        raise AssertionError("Rust emitted no discovery frames")
    if run([*cpp, "consume-discovery", *rust_discovery]) != "DISCOVERY_OK":
        raise AssertionError("C++ did not accept Rust discovery")
    rust_discovery_via_cpp_relay = nonempty_lines(run([*cpp, "relay-forward", *rust_discovery]))
    if run([*cpp, "consume-discovery", *rust_discovery_via_cpp_relay]) != "DISCOVERY_OK":
        raise AssertionError("C++ relay did not forward Rust discovery")

    cpp_discovery = nonempty_lines(run([*cpp, "emit-discovery"]))
    if not cpp_discovery:
        raise AssertionError("C++ emitted no discovery frames")
    if run([*cargo, "consume-discovery", *cpp_discovery], env=env) != "DISCOVERY_OK":
        raise AssertionError("Rust did not accept C++ discovery")
    cpp_discovery_via_rust_relay = nonempty_lines(run([*cargo, "relay-forward", *cpp_discovery], env=env))
    if run([*cargo, "consume-discovery", *cpp_discovery_via_rust_relay], env=env) != "DISCOVERY_OK":
        raise AssertionError("Rust relay did not forward C++ discovery")

    rust_time = nonempty_lines(run([*cargo, "emit-timesync"], env=env))
    if not rust_time:
        raise AssertionError("Rust emitted no time-sync frames")
    assert_nonzero_ms("C++ consuming Rust time sync", run([*cpp, "consume-timesync", *rust_time]))
    rust_time_via_cpp_relay = nonempty_lines(run([*cpp, "relay-forward", *rust_time]))
    assert_nonzero_ms("C++ consuming Rust time sync through C++ relay", run([*cpp, "consume-timesync", *rust_time_via_cpp_relay]))

    cpp_time = nonempty_lines(run([*cpp, "emit-timesync"]))
    if not cpp_time:
        raise AssertionError("C++ emitted no time-sync frames")
    assert_nonzero_ms("Rust consuming C++ time sync", run([*cargo, "consume-timesync", *cpp_time], env=env))
    cpp_time_via_rust_relay = nonempty_lines(run([*cargo, "relay-forward", *cpp_time], env=env))
    assert_nonzero_ms("Rust consuming C++ time sync through Rust relay", run([*cargo, "consume-timesync", *cpp_time_via_rust_relay], env=env))

    rust_managed = run([*cargo, "emit-managed"], env=env)
    assert_values_with_update("C++ consuming Rust managed variable", run([*cpp, "consume-managed", rust_managed]),
                              (71.0, 72.0, 73.0))
    cpp_managed = run([*cpp, "emit-managed"])
    assert_values_with_update("Rust consuming C++ managed variable",
                              run([*cargo, "consume-managed", cpp_managed], env=env),
                              (81.0, 82.0, 83.0))
    cpp_request = run([*cpp, "emit-managed-request"])
    rust_reply = nonempty_lines(run([*cargo, "request-managed", cpp_request], env=env))
    if not rust_reply:
        raise AssertionError("Rust emitted no managed-variable reply")
    assert_values_with_update("C++ consuming Rust managed reply", run([*cpp, "consume-managed", rust_reply[-1]]),
                              (91.0, 92.0, 93.0))
    rust_request = run([*cargo, "emit-managed-request"], env=env)
    cpp_reply = nonempty_lines(run([*cpp, "request-managed", rust_request]))
    if not cpp_reply:
        raise AssertionError("C++ emitted no managed-variable reply")
    assert_values_with_update("Rust consuming C++ managed reply",
                              run([*cargo, "consume-managed", cpp_reply[-1]], env=env),
                              (101.0, 102.0, 103.0))

    rust_p2p = run([*cargo, "emit-p2p"], env=env)
    if run([*cpp, "consume-p2p", rust_p2p]).strip() != "rust-p2p":
        raise AssertionError("C++ failed to consume Rust P2P datagram")
    cpp_p2p = run([*cpp, "emit-p2p"])
    if run([*cargo, "consume-p2p", cpp_p2p], env=env).strip() != "cpp-p2p":
        raise AssertionError("Rust failed to consume C++ P2P datagram")

    rust_syn = run([*cargo, "emit-p2p-stream-syn"], env=env)
    cpp_accept = nonempty_lines(run([*cpp, "accept-p2p-stream", rust_syn]))
    if not cpp_accept or cpp_accept[0] != "accepted" or len(cpp_accept) < 2:
        raise AssertionError("C++ failed to accept Rust P2P stream SYN")
    cpp_syn = run([*cpp, "emit-p2p-stream-syn"])
    rust_accept = nonempty_lines(run([*cargo, "accept-p2p-stream", cpp_syn], env=env))
    if not rust_accept or rust_accept[0] != "accepted" or len(rust_accept) < 2:
        raise AssertionError("Rust failed to accept C++ P2P stream SYN")

    print("Rust/C++ router feature interop passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
