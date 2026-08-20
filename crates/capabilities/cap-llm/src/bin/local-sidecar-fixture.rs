//! Test-only OpenAI-compat sidecar. Prints `PORT=<n>` and serves chat/embed/SSE.

use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    println!("PORT={port}");
    let _ = std::io::stdout().flush();
    for incoming in listener.incoming() {
        let Ok(mut sock) = incoming else { continue };
        let mut buf = [0u8; 16384];
        let n = sock.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let is_embed = req.contains("/v1/embeddings");
        let is_stream = req.contains("\"stream\":true") || req.contains("\"stream\": true");
        let body: Vec<u8> = if is_embed {
            br#"{"data":[{"embedding":[0.1,0.2]}],"model":"nomic-embed"}"#.to_vec()
        } else if is_stream {
            b"data: {\"choices\":[{\"delta\":{\"content\":\"pong\"}}]}\n\n\
              data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n\
              data: [DONE]\n\n"
                .to_vec()
        } else {
            br#"{"choices":[{"message":{"content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"llama"}"#.to_vec()
        };
        let ctype = if is_stream {
            "text/event-stream"
        } else {
            "application/json"
        };
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(header.as_bytes());
        let _ = sock.write_all(&body);
    }
}
