use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    println!("proxy listening on 127.0.0.1:9000 -> 127.0.0.1:9001");

    loop {
        let (mut inbound, peer) = listener.accept().await?;
        println!("connection from {peer}");

        tokio::spawn(async move {
            let mut outbound = match TcpStream::connect("127.0.0.1:9001").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("cannot reach backend: {e}");
                    return;
                }
            };

            match copy_bidirectional(&mut inbound, &mut outbound).await {
                Ok((to_backend, to_client)) => {
                    println!("{peer} closed: {to_backend} bytes up, {to_client} bytes down");
                }
                Err(e) => eprintln!("{peer} error: {e}"),
            }
        });
    }
}

/*
1. orders sends a request to its local sidecar (plain text)
2. Sidecar A opens a TCP connection to sidecar B and starts the TLS handshake
3. Both sides exchange certificates and verify them against the CA
      -> fail: connection closed, no payload ever sent
4. Sidecar B reads the identity from the cert: "this is orders"
5. Sidecar B checks policy: "may orders call payments?"
      -> no: connection closed
      -> yes: it opens a connection to payments and pipes the bytes
*/
