// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::http::ReqHead;
use crate::respond;
use std::io;
use std::sync::Arc;
use tokio::net::TcpStream;

pub trait ConnectionsSource: Send + Sync {

    fn connections_json(&self) -> String;

    fn close_all(&self) {}

    fn close_one(&self, _id: &str) -> bool {
        false
    }
}

pub enum Outcome {
    KeepAlive,
    Close,
}

pub async fn handle(
    stream: &mut TcpStream,
    req: &ReqHead,
    path: &str,
    src: &Arc<dyn ConnectionsSource>,
    ka: bool,
) -> io::Result<Outcome> {
    if req.method.eq_ignore_ascii_case("DELETE") {

        let id = path.strip_prefix("/connections/").filter(|s| !s.is_empty());
        let (code, reason) = match id {
            None => {
                src.close_all();
                (204, "No Content")
            }
            Some(id) => {
                if src.close_one(id) {
                    (204, "No Content")
                } else {
                    (404, "Not Found")
                }
            }
        };
        respond::send(stream, code, reason, &[], b"", ka).await?;
        return Ok(if ka {
            Outcome::KeepAlive
        } else {
            Outcome::Close
        });
    }

    let ka = ka && !req.is_upgrade();
    let body = src.connections_json();
    respond::send(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json")],
        body.as_bytes(),
        ka,
    )
    .await?;
    Ok(if ka {
        Outcome::KeepAlive
    } else {
        Outcome::Close
    })
}
