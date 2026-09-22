//! SCRATCH, never committed: does freenet load a MINIMAL block contract (measurement for the owner)?
//! One private isolated-network node. For each contract code given (the measured one and block.wasm as the
//! control): client PUT of a real block, GET it back; a PUT whose state does not hash to its params (must be
//! refused, or validate_state is not running); a re-PUT of the same block and a client UPDATE (update_state).
//! usage: MIN_PORT=<port> live-min-block <code.wasm>...
use anyhow::{bail, Context, Result};
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi};
use freenet_stdlib::prelude::*;
use probe::node::{Mode, Node, TempTree};
use std::time::{Duration, Instant};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

fn container(code: &[u8], params: &[u8]) -> ContractContainer {
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(code.to_vec())),
        Parameters::from(params.to_vec()),
    )))
}

/// The first answer to `r`, by name, and the ms it took.
async fn op(c: &mut WebApi, r: ContractRequest<'static>) -> Result<(String, Option<Vec<u8>>, u128)> {
    let t = Instant::now();
    timeout(STEP, c.send(ClientRequest::ContractOp(r))).await.map_err(|_| anyhow::anyhow!("send blocked"))??;
    let end = tokio::time::Instant::now() + STEP;
    while tokio::time::Instant::now() < end {
        match timeout(Duration::from_millis(500), c.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }))) => {
                return Ok(("GetResponse".into(), Some(state.as_ref().to_vec()), t.elapsed().as_millis()))
            }
            Ok(Ok(h @ HostResponse::ContractResponse(_))) => {
                let s = format!("{h}");
                return Ok((s.chars().take(160).collect(), None, t.elapsed().as_millis()));
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Ok((format!("ERROR {}", e.to_string().chars().take(220).collect::<String>()), None, t.elapsed().as_millis())),
            Err(_) => {}
        }
    }
    Ok(("SILENT".into(), None, t.elapsed().as_millis()))
}

fn block(n: u8, len: usize) -> ([u8; 32], Vec<u8>) {
    let mut st = vec![freenet_prolly::kind::RAW];
    st.extend(std::iter::repeat(n).take(len));
    (freenet_prolly::block_id(st[0], &st[1..]), st)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let v = std::process::Command::new("freenet").arg("--version").output().context("freenet --version")?;
    println!("freenet: {}", String::from_utf8_lossy(&v.stdout).lines().next().unwrap_or_default());
    let port: u16 = std::env::var("MIN_PORT").ok().and_then(|p| p.parse().ok()).context("MIN_PORT=<port> is required")?;
    let codes: Vec<(String, Vec<u8>)> = std::env::args().skip(1).map(|p| Ok((p.clone(), std::fs::read(&p)?))).collect::<Result<_>>()?;
    if codes.is_empty() { bail!("usage: live-min-block <code.wasm>..."); }
    let dir = std::env::temp_dir().join(format!("live-min-block-{}", std::process::id()));
    let _tree = TempTree(dir.clone());
    let node = Node::spawn_in(port, &dir, Mode::IsolatedNetwork { network_port: port + 1 })?;
    let (stream, _) = tokio_tungstenite::connect_async(node.ws()).await.context("connecting")?;
    let mut c = WebApi::start(stream);
    let mut red = Vec::new();
    for (i, (path, code)) in codes.iter().enumerate() {
        let name = std::path::Path::new(path).file_name().unwrap().to_string_lossy().to_string();
        println!("== {name}: {} B", code.len());
        let (id, st) = block(10 + i as u8, 700);
        let key = container(code, &id).key();
        let put = |params: &[u8], state: Vec<u8>| ContractRequest::Put { contract: container(code, params), state: WrappedState::new(state), related_contracts: RelatedContracts::default(), subscribe: false, blocking_subscribe: false };
        let (a, _, ms) = op(&mut c, put(&id, st.clone())).await?;
        println!("  PUT a real block (701 B state): {a}  [{ms} ms]");
        if !a.starts_with("put response") { red.push(format!("{name}: PUT of a real block: {a}")); }
        let (a, got, ms) = op(&mut c, ContractRequest::Get { key: *key.id(), return_contract_code: false, subscribe: false, blocking_subscribe: false }).await?;
        let same = got.as_deref() == Some(&st[..]);
        println!("  GET it: {a}, state {}  [{ms} ms]", if same { "IDENTICAL" } else { "DIFFERENT/none" });
        if !same { red.push(format!("{name}: GET did not return the state")); }
        let (bid, _) = block(200 + i as u8, 700);
        let (_, other) = block(100 + i as u8, 700);
        let (a, _, ms) = op(&mut c, put(&bid, other)).await?;
        println!("  PUT a state that does NOT hash to its params: {a}  [{ms} ms]");
        if a.starts_with("put response") { red.push(format!("{name}: a mismatched state was ACCEPTED: validate_state is not deciding")); }
        let (a, _, ms) = op(&mut c, put(&id, st.clone())).await?;
        println!("  re-PUT the same block: {a}  [{ms} ms]");
        let (a, _, ms) = op(&mut c, ContractRequest::Update { key, data: UpdateData::State(State::from(st.clone())) }).await?;
        println!("  UPDATE it with its own state: {a}  [{ms} ms]");
    }
    drop(c);
    drop(node);
    if red.is_empty() { println!("VERDICT: GREEN"); Ok(()) } else { for r in &red { println!("RED: {r}"); } bail!("{} red", red.len()) }
}
