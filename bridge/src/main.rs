//! Keychat for Agent: Keychat protocol sidecar for AI agents.
//!
//! Bidirectional JSON-RPC:
//! - Reads requests from stdin (from TS plugin)
//! - Writes responses to stdout
//! - Also pushes unsolicited "inbound" events when messages arrive from relays

mod mls;
mod protocol;
mod rpc;
mod signal;
mod transport;

use anyhow::Result;
use std::io::{self, Write};
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    log::info!("Keychat for Agent starting");

    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<transport::InboundMessage>();
    let mut state = rpc::BridgeState::new(inbound_tx).await?;

    // Spawn stdin reader
    let (request_tx, mut request_rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            if request_tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut stdout = io::stdout();

    loop {
        tokio::select! {
            // Handle RPC requests from stdin
            Some(line) = request_rx.recv() => {
                let response = state.handle_request(&line).await;
                let response_json = serde_json::to_string(&response)?;
                writeln!(stdout, "{}", response_json)?;
                stdout.flush()?;
            }
            // Push inbound messages from relays
            Some(msg) = inbound_rx.recv() => {
                let push = serde_json::json!({
                    "id": 0,
                    "event": "inbound_message",
                    "data": msg,
                });
                let push_json = serde_json::to_string(&push)?;
                writeln!(stdout, "{}", push_json)?;
                stdout.flush()?;
            }
            else => break,
        }
    }

    log::info!("Keychat for Agent shutting down");
    Ok(())
}
