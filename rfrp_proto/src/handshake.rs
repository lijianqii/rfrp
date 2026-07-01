use log::{debug, info};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{self, Cipher};

const HANDSHAKE_NONCE_LEN: usize = 32;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

pub async fn server_handshake(
    mut socket: TcpStream,
    auth_token: &str,
) -> Result<(TcpStream, Arc<Cipher>), String> {
    let server_nonce: [u8; HANDSHAKE_NONCE_LEN] = rand::random();

    let mut client_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        socket.read_exact(&mut client_nonce),
    )
    .await
    .map_err(|_| "Handshake: timed out waiting for client nonce".to_string())?
    .map_err(|e| format!("Handshake: failed to read client nonce: {}", e))?;

    tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        socket.write_all(&server_nonce),
    )
    .await
    .map_err(|_| "Handshake: timed out sending server nonce".to_string())?
    .map_err(|e| format!("Handshake: failed to send server nonce: {}", e))?;

    let session_key = crypto::derive_session_key(auth_token, &client_nonce, &server_nonce);
    let cipher = Arc::new(Cipher::new(&session_key));

    debug!("Server handshake complete");
    info!("Handshake complete, encryption established");

    Ok((socket, cipher))
}

pub async fn client_handshake(
    mut socket: TcpStream,
    auth_token: &str,
) -> Result<(TcpStream, Arc<Cipher>), String> {
    let client_nonce: [u8; HANDSHAKE_NONCE_LEN] = rand::random();

    tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        socket.write_all(&client_nonce),
    )
    .await
    .map_err(|_| "Handshake: timed out sending client nonce".to_string())?
    .map_err(|e| format!("Handshake: failed to send client nonce: {}", e))?;

    let mut server_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        socket.read_exact(&mut server_nonce),
    )
    .await
    .map_err(|_| "Handshake: timed out waiting for server nonce".to_string())?
    .map_err(|e| format!("Handshake: failed to read server nonce: {}", e))?;

    let session_key = crypto::derive_session_key(auth_token, &client_nonce, &server_nonce);
    let cipher = Arc::new(Cipher::new(&session_key));

    debug!("Client handshake complete");

    Ok((socket, cipher))
}
