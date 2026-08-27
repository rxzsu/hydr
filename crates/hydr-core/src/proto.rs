//! Опциональный Protobuf-IDL для control-plane (feature `proto`).
//!
//! Data-plane (`Frame`/`Message`) НЕ трогаем — он остаётся рукописным для
//! 0-overhead и отсутствия сигнатур Protobuf в wire (анти-DPI). Этот модуль
//! предназначен только для административного/статусного протокола (gRPC/JSON
//! gateway и т.п.) и собирается только при `cargo build --features proto`.
#![cfg(feature = "proto")]

pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/hydr.rs"));
}

#[cfg(test)]
mod tests {
    use super::generated::*;
    use prost::Message;

    #[test]
    fn status_roundtrip() {
        let req = StatusRequest { nonce: 0xDEAD_BEEF };
        let bytes = req.encode_to_vec();
        let back = StatusRequest::decode(bytes.as_slice()).expect("decode");
        assert_eq!(back.nonce, req.nonce);

        let resp = StatusResponse {
            nonce: 1,
            uptime_secs: 42,
            active_sessions: 3,
            bytes_in: 1000,
            bytes_out: 2000,
        };
        let rbytes = resp.encode_to_vec();
        let rback = StatusResponse::decode(rbytes.as_slice()).expect("decode");
        assert_eq!(rback.uptime_secs, 42);
        assert_eq!(rback.bytes_in, 1000);
    }
}
