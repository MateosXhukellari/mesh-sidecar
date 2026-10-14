use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// A request bigger than this is not a real CSR.
const MAX_REQUEST: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenEntry {
    value: String,
    identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFile {
    token: Vec<TokenEntry>,
}

// token -> the one identity it may request. Single use.
struct Tokens {
    map: Mutex<HashMap<String, String>>,
}

impl Tokens {
    fn from_toml(text: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file: TokenFile = toml::from_str(text)?;
        let map = file.token.into_iter().map(|t| (t.value, t.identity)).collect();
        Ok(Tokens { map: Mutex::new(map) })
    }

    fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    // Removing the entry is what makes the token single-use.
    fn redeem(&self, token: &str) -> Option<String> {
        self.map.lock().unwrap().remove(token)
    }
}

async fn handle(mut sock: TcpStream, tokens: Arc<Tokens>) -> std::io::Result<()> {
    // Request format: line 1 = token, the rest = the CSR. The client
    // closes its sending side when done, which is how we know it's complete.
    let mut raw = Vec::new();
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        (&mut sock).take(MAX_REQUEST).read_to_end(&mut raw),
    )
    .await;
    if !matches!(read, Ok(Ok(_))) {
        return Ok(()); // too slow or broken: drop it
    }

    let text = String::from_utf8_lossy(&raw);
    let Some((token, csr)) = text.split_once('\n') else {
        sock.write_all(b"ERR malformed request\n").await?;
        return Ok(());
    };

    let Some(identity) = tokens.redeem(token.trim()) else {
        sock.write_all(b"ERR invalid token\n").await?;
        return Ok(());
    };

    println!("token redeemed for {identity} (csr: {} bytes)", csr.len());
    sock.write_all(b"ERR signing not implemented yet\n").await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Loaded now so a missing CA key stops startup. Step 3 will use it.
    let _ca_key_pem = std::fs::read_to_string("certs/ca.key")?;

    let tokens = Arc::new(Tokens::load("tokens.toml")?);

    let listener = TcpListener::bind("127.0.0.1:9100").await?;
    println!("CA service on 127.0.0.1:9100");

    loop {
        let (sock, peer) = listener.accept().await?;
        let tokens = tokens.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, tokens).await {
                eprintln!("{peer} error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = r#"
        [[token]]
        value = "abc"
        identity = "spiffe://mesh/orders"
    "#;

    #[test]
    fn token_works_exactly_once() {
        let t = Tokens::from_toml(T).unwrap();
        assert_eq!(t.redeem("abc"), Some("spiffe://mesh/orders".to_string()));
        assert_eq!(t.redeem("abc"), None);
    }

    #[test]
    fn unknown_token_is_refused() {
        let t = Tokens::from_toml(T).unwrap();
        assert_eq!(t.redeem("nope"), None);
    }
}