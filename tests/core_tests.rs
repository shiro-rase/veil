use std::collections::HashMap;
use std::net::Ipv4Addr;
use veil::crypto::{derive_session_keys, CipherSession, Keypair};
use veil::dns::DnsResolver;
use veil::ingress::IngressRouter;
use veil::proto::{Frame, ObfuscatedCodec};

#[test]
fn test_crypto_handshake_and_encryption() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    let secret_alice = alice.diffie_hellman(&bob.public);
    let secret_bob = bob.diffie_hellman(&alice.public);
    assert_eq!(secret_alice, secret_bob);

    let network_secret = b"my-super-secret-token";
    let (alice_tx, _alice_rx) = derive_session_keys(&secret_alice, network_secret, true);
    let (_bob_tx, bob_rx) = derive_session_keys(&secret_bob, network_secret, false);

    let mut session_alice = CipherSession::new(alice_tx);
    let mut session_bob = CipherSession::new(bob_rx);

    let msg = b"GET / HTTP/1.1\r\nHost: hui.hui.hui\r\n\r\n";
    let encrypted = session_alice.encrypt(msg).unwrap();
    let decrypted = session_bob.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, msg);
}

#[test]
fn test_obfuscated_codec_framing() {
    let network_secret = b"veil-network-secret-key-12345678";
    let codec = ObfuscatedCodec::new(network_secret);

    let frame = Frame::StreamOpen {
        stream_id: 42,
        domain: "hui.hui.hui".to_string(),
        target_port: 80,
    };

    let encoded = codec.encode_frame(&frame).unwrap();
    assert!(encoded.len() > 20);

    let mut buf = bytes::BytesMut::from(&encoded[..]);
    let decoded = codec.try_decode_frame(&mut buf).unwrap().unwrap();

    match decoded {
        Frame::StreamOpen { stream_id, domain, target_port } => {
            assert_eq!(stream_id, 42);
            assert_eq!(domain, "hui.hui.hui");
            assert_eq!(target_port, 80);
        }
        _ => panic!("Unexpected frame variant decoded"),
    }
}

#[tokio::test]
async fn test_ingress_router_host_and_wildcard() {
    let mut map = HashMap::new();
    map.insert("hui.hui.hui".to_string(), "127.0.0.1:3000".to_string());
    map.insert("*.myhost".to_string(), "127.0.0.1:8080".to_string());
    let router = IngressRouter::new(map);

    assert_eq!(
        router.get_target("hui.hui.hui").await,
        Some("127.0.0.1:3000".to_string())
    );
    assert_eq!(
        router.get_target("hui.hui.hui:80").await,
        Some("127.0.0.1:3000".to_string())
    );
    assert_eq!(
        router.get_target("api.myhost").await,
        Some("127.0.0.1:8080".to_string())
    );
    assert_eq!(
        router.get_target("unknown.domain").await,
        None
    );
}

#[test]
fn test_http_host_parser() {
    let raw_http = b"GET /index.html HTTP/1.1\r\nHost: hui.hui.hui:80\r\nUser-Agent: curl/7.68.0\r\n\r\n";
    let parsed = IngressRouter::parse_http_host(raw_http);
    assert_eq!(parsed, Some("hui.hui.hui".to_string()));
}

#[tokio::test]
async fn test_dns_resolver_local_matching() {
    let resolver = DnsResolver::new("1.1.1.1:53".parse().unwrap());
    resolver.set_domain("hui.hui.hui".to_string(), Ipv4Addr::new(10, 42, 0, 5)).await;
    resolver.set_domain("*.vps".to_string(), Ipv4Addr::new(10, 42, 0, 9)).await;

    let query = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, b'h', b'u', b'i', 0x03, b'h', b'u', b'i', 0x03, b'h', b'u', b'i', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];

    let resp = resolver.handle_query(&query).await.unwrap();
    assert_eq!(&resp[resp.len() - 4..], &[10, 42, 0, 5]);
}

#[test]
fn test_ca_generation() {
    let temp_dir = std::env::temp_dir().join(format!("veil-test-certs-{}", rand::random::<u32>()));
    veil::ca::CertificateAuthority::generate_ca(&temp_dir).unwrap();
    assert!(temp_dir.join("veil-ca.crt").exists());
    assert!(temp_dir.join("veil-ca.key").exists());

    veil::ca::CertificateAuthority::generate_domain_cert(
        &["hui.hui.hui".to_string(), "vps1.vps".to_string()],
        &temp_dir,
    )
    .unwrap();
    assert!(temp_dir.join("hui.hui.hui.crt").exists());
    assert!(temp_dir.join("hui.hui.hui.key").exists());
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_acl_engine_permissions() {
    use veil::acl::{AclEngine, AclRule};

    let rules = vec![
        AclRule {
            client: "admin-laptop".to_string(),
            allow: vec!["*".to_string()],
        },
        AclRule {
            client: "guest-user".to_string(),
            allow: vec!["public.vps".to_string(), "*.hui.hui".to_string()],
        },
    ];
    let acl = AclEngine::new(rules);

    assert!(acl.is_allowed("admin-laptop", "secret.internal"));
    assert!(acl.is_allowed("guest-user", "public.vps"));
    assert!(acl.is_allowed("guest-user", "app.hui.hui"));
    assert!(!acl.is_allowed("guest-user", "secret.internal"));
    assert!(!acl.is_allowed("unregistered-device", "public.vps"));
}

#[tokio::test]
async fn test_token_enrollment_and_approval() {
    use veil::token::{DeviceStatus, TokenManager};

    let mgr = TokenManager::new();
    let token = mgr.create_token("node".to_string(), 300, false).await;
    assert!(token.starts_with("veil-tok-"));

    let status = mgr
        .enroll_device(&token, "node-vps1".to_string(), "pubkey123".to_string())
        .await
        .unwrap();
    assert_eq!(status, DeviceStatus::Pending);
    assert!(!mgr.is_approved("node-vps1").await);

    mgr.approve_device("node-vps1").await.unwrap();
    assert!(mgr.is_approved("node-vps1").await);

    mgr.revoke_device("node-vps1").await.unwrap();
    assert!(!mgr.is_approved("node-vps1").await);
}

#[test]
fn test_ip_packet_and_ping_codec() {
    let codec = ObfuscatedCodec::new(b"secret-123456");
    let packet = Frame::IpPacket {
        src_ip: "10.42.0.100".to_string(),
        dst_ip: "10.42.0.4".to_string(),
        payload: vec![1, 2, 3, 4, 5],
    };

    let enc = codec.encode_frame(&packet).unwrap();
    let mut buf = bytes::BytesMut::from(&enc[..]);
    let dec = codec.try_decode_frame(&mut buf).unwrap().unwrap();

    if let Frame::IpPacket { src_ip, dst_ip, payload } = dec {
        assert_eq!(src_ip, "10.42.0.100");
        assert_eq!(dst_ip, "10.42.0.4");
        assert_eq!(payload, vec![1, 2, 3, 4, 5]);
    } else {
        panic!("Wrong frame");
    }

    let ping = Frame::PingRequest {
        target_node: "node12".to_string(),
        seq: 1,
        timestamp_ms: 123456789,
    };
    let enc_ping = codec.encode_frame(&ping).unwrap();
    let mut buf_ping = bytes::BytesMut::from(&enc_ping[..]);
    let dec_ping = codec.try_decode_frame(&mut buf_ping).unwrap().unwrap();
    if let Frame::PingRequest { target_node, seq, timestamp_ms } = dec_ping {
        assert_eq!(target_node, "node12");
        assert_eq!(seq, 1);
        assert_eq!(timestamp_ms, 123456789);
    } else {
        panic!("Wrong frame");
    }
}

#[test]
fn test_file_transfer_and_status_codec() {
    use veil::proto::NodeStatusItem;

    let codec = ObfuscatedCodec::new(b"secret-123456");
    let init = Frame::FileTransferInit {
        transfer_id: "tx-1".to_string(),
        target_node: "node12".to_string(),
        filename: "test.bin".to_string(),
        target_path: "/tmp/test.bin".to_string(),
        total_size: 1024,
    };
    let enc_init = codec.encode_frame(&init).unwrap();
    let mut buf_init = bytes::BytesMut::from(&enc_init[..]);
    let dec_init = codec.try_decode_frame(&mut buf_init).unwrap().unwrap();
    if let Frame::FileTransferInit { transfer_id, total_size, .. } = dec_init {
        assert_eq!(transfer_id, "tx-1");
        assert_eq!(total_size, 1024);
    } else {
        panic!("Wrong frame");
    }

    let status = Frame::NodeStatusReply {
        nodes: vec![NodeStatusItem {
            node_id: "arch".to_string(),
            virtual_ip: "10.42.0.2".to_string(),
            domains: vec!["arch.mesh".to_string()],
            rx_bytes: 100,
            tx_bytes: 200,
            is_direct: true,
            latency_ms: Some(15),
        }],
    };
    let enc_status = codec.encode_frame(&status).unwrap();
    let mut buf_status = bytes::BytesMut::from(&enc_status[..]);
    let dec_status = codec.try_decode_frame(&mut buf_status).unwrap().unwrap();
    if let Frame::NodeStatusReply { nodes } = dec_status {
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "arch");
        assert_eq!(nodes[0].virtual_ip, "10.42.0.2");
    } else {
        panic!("Wrong frame");
    }
}
