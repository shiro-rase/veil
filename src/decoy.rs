use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct DecoyProxy {
    decoy_addr: String,
}

impl DecoyProxy {
    pub fn new(decoy_addr: impl Into<String>) -> Self {
        Self {
            decoy_addr: decoy_addr.into(),
        }
    }

    pub async fn forward(&self, initial_bytes: &[u8], mut client_stream: TcpStream) -> Result<()> {
        let mut upstream = TcpStream::connect(&self.decoy_addr).await?;
        if !initial_bytes.is_empty() {
            upstream.write_all(initial_bytes).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await;
        Ok(())
    }
}
