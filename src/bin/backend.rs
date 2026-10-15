use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9001").await?;
    println!("listening on 127.0.0.1:9001");

    loop {
        let (mut socket, peer) = listener.accept().await?;
        println!("connection from {peer}");

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            println!("{peer} disconnected");
        });
    }
}
