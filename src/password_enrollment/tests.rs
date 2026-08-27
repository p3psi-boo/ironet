use std::{sync::Arc, time::Duration};

use iroh::SecretKey;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
};

use super::{
    client::{confirm, enroll},
    create_config, password_matches,
    protocol::{
        EnrollmentRequest, PASSWORD_KEY_BYTES, PASSWORD_SALT_BYTES, PROTOCOL_VERSION,
        decrypt_invite, derive_password_key, encrypt_invite, make_proof, proof_is_valid,
    },
    server::{enrollment_bind_addresses, handle_connection, serve},
};
use crate::{
    config::Config,
    control::{DaemonCommand, ReloadAck, RpcError},
    product::{self, CreateNetworkOptions, decode_invite},
};

#[test]
fn password_config_derives_a_valid_non_cleartext_key() {
    let password = b"correct horse battery staple";
    let config = create_config(password).unwrap();
    config.validate().unwrap();
    assert_ne!(config.password_key, hex::encode(password));
    let salt = hex::decode(&config.salt).unwrap();
    let salt: [u8; PASSWORD_SALT_BYTES] = salt.try_into().unwrap();
    assert_eq!(
        hex::encode(derive_password_key(password, &salt)),
        config.password_key
    );
    assert!(password_matches(password, &config).unwrap());
    assert!(!password_matches(b"wrong password", &config).unwrap());
}

#[test]
fn proof_is_bound_to_action_endpoint_and_bootstrap() {
    let key = [7_u8; PASSWORD_KEY_BYTES];
    let nonce = [9_u8; 32];
    let endpoint = SecretKey::generate().public();
    let request = EnrollmentRequest::Join {
        version: PROTOCOL_VERSION,
        bootstrap: "192.0.2.10:4000".parse().unwrap(),
        member_endpoint_id: endpoint,
    };
    let proof = make_proof(&key, &nonce, &request);
    assert!(proof_is_valid(&key, &nonce, &request, &proof));
    let other = EnrollmentRequest::Confirm {
        version: PROTOCOL_VERSION,
        invite_id: "enroll-1".into(),
        member_endpoint_id: endpoint,
    };
    assert!(!proof_is_valid(&key, &nonce, &other, &proof));
}

#[test]
fn invite_ciphertext_requires_the_password_key() {
    let key = [3_u8; PASSWORD_KEY_BYTES];
    let (nonce, encrypted) = encrypt_invite(&key, "ironet://join/v2/example").unwrap();
    assert_eq!(
        decrypt_invite(&key, &nonce, &encrypted).unwrap(),
        "ironet://join/v2/example"
    );
    assert!(decrypt_invite(&[4_u8; PASSWORD_KEY_BYTES], &nonce, &encrypted).is_err());
}

#[test]
fn unspecified_bind_expands_to_both_ip_families() {
    assert_eq!(
        enrollment_bind_addresses("[::]:4000".parse().unwrap()),
        [
            "0.0.0.0:4000".parse().unwrap(),
            "[::]:4000".parse().unwrap(),
        ]
    );
}

#[tokio::test]
async fn listener_reconciles_password_enrollment_config_changes() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    product::create_network(
        &config_path,
        directory.path(),
        "nix-lab",
        CreateNetworkOptions {
            bind_address: Some(address),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let disabled = Config::load(&config_path).await.unwrap();
    let (config_tx, config_rx) = watch::channel(disabled.clone());
    let (command_tx, _command_rx) = mpsc::channel(1);
    let service = tokio::spawn(serve(config_path, config_rx, command_tx));

    let mut enabled = disabled.clone();
    enabled.password_enrollment = Some(create_config(b"password").unwrap());
    config_tx.send_replace(enabled);
    let mut connected = false;
    for _ in 0..20 {
        if let Ok(stream) = TcpStream::connect(address).await {
            drop(stream);
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(connected, "listener did not start after config activation");

    config_tx.send_replace(disabled);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(TcpStream::connect(address).await.is_err());
    drop(config_tx);
    assert!(service.await.unwrap().is_ok());
}

#[tokio::test]
async fn direct_enrollment_is_confirmed_after_the_client_persists_its_identity() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let password = b"correct horse battery staple".to_vec();
    product::create_network(
        &config_path,
        directory.path(),
        "nix-lab",
        CreateNetworkOptions {
            password: Some(password.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (command_tx, mut command_rx) = mpsc::channel(2);
    let reload = tokio::spawn(async move {
        let Some(DaemonCommand::Reload { reply }) = command_rx.recv().await else {
            panic!("enrollment did not request a daemon reload");
        };
        reply
            .send(Ok(ReloadAck {
                generation: 2,
                endpoint_id: "authority".into(),
            }))
            .unwrap();
    });
    let server_config = config_path.clone();
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(
                stream,
                &server_config,
                command_tx.clone(),
                Arc::new(Mutex::new(())),
            )
            .await
            .unwrap();
        }
    });

    let member = SecretKey::generate().public();
    let ticket = enroll(address, &password, member).await.unwrap();
    let payload = decode_invite(&ticket.invite).unwrap();
    assert_eq!(payload.member_endpoint_id, member);
    assert!(payload.member_secret.is_none());
    confirm(address, &password, member, &ticket.invite_id)
        .await
        .unwrap();
    confirm(address, &password, member, &ticket.invite_id)
        .await
        .unwrap();
    server.await.unwrap();
    reload.await.unwrap();

    let state = product::load_state(directory.path()).unwrap();
    assert_eq!(state.invites.len(), 1);
    assert!(!state.invites[0].pending_password_enrollment);
    let config = Config::load(&config_path).await.unwrap();
    assert!(config.peers.iter().any(|peer| peer.endpoint_id == member));
}

#[tokio::test]
async fn concurrent_enrollments_commit_every_member() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let password = b"correct horse battery staple".to_vec();
    product::create_network(
        &config_path,
        directory.path(),
        "nix-lab",
        CreateNetworkOptions {
            password: Some(password.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (command_tx, mut command_rx) = mpsc::channel(4);
    let reloads = tokio::spawn(async move {
        for generation in 2..=3 {
            let Some(DaemonCommand::Reload { reply }) = command_rx.recv().await else {
                panic!("missing enrollment reload");
            };
            reply
                .send(Ok(ReloadAck {
                    generation,
                    endpoint_id: "authority".into(),
                }))
                .unwrap();
        }
    });
    let server_config = config_path.clone();
    let server = tokio::spawn(async move {
        let committer = Arc::new(Mutex::new(()));
        let mut handlers = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let config_path = server_config.clone();
            let command_tx = command_tx.clone();
            let committer = committer.clone();
            handlers.push(tokio::spawn(async move {
                handle_connection(stream, &config_path, command_tx, committer).await
            }));
        }
        for handler in handlers {
            handler.await.unwrap().unwrap();
        }
    });

    let first = SecretKey::generate().public();
    let second = SecretKey::generate().public();
    let (one, two) = tokio::join!(
        enroll(address, &password, first),
        enroll(address, &password, second)
    );
    one.unwrap();
    two.unwrap();
    server.await.unwrap();
    reloads.await.unwrap();

    let config = Config::load(&config_path).await.unwrap();
    assert!(config.peers.iter().any(|peer| peer.endpoint_id == first));
    assert!(config.peers.iter().any(|peer| peer.endpoint_id == second));
    assert_eq!(
        product::load_state(directory.path()).unwrap().invites.len(),
        2
    );
}

#[tokio::test]
async fn reload_failure_revokes_the_provisional_enrollment() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let password = b"correct horse battery staple".to_vec();
    product::create_network(
        &config_path,
        directory.path(),
        "nix-lab",
        CreateNetworkOptions {
            password: Some(password.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (command_tx, mut command_rx) = mpsc::channel(3);
    let reloads = tokio::spawn(async move {
        let Some(DaemonCommand::Reload { reply }) = command_rx.recv().await else {
            panic!("missing initial reload");
        };
        reply
            .send(Err(RpcError {
                code: "reload_failed".into(),
                message: "fixture".into(),
            }))
            .unwrap();
        let Some(DaemonCommand::Reload { reply }) = command_rx.recv().await else {
            panic!("missing rollback reload");
        };
        reply
            .send(Ok(ReloadAck {
                generation: 2,
                endpoint_id: "authority".into(),
            }))
            .unwrap();
    });
    let server_config = config_path.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_connection(stream, &server_config, command_tx, Arc::new(Mutex::new(()))).await
    });

    let _ = enroll(address, &password, SecretKey::generate().public())
        .await
        .unwrap_err();
    assert!(server.await.unwrap().is_err());
    reloads.await.unwrap();
    let state = product::load_state(directory.path()).unwrap();
    assert_eq!(state.invites.len(), 1);
    assert!(state.invites[0].revoked);
    assert!(state.invites[0].pending_password_enrollment);
    assert!(Config::load(&config_path).await.unwrap().peers.is_empty());
}

#[tokio::test]
async fn expired_provisional_enrollment_is_revoked() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let password = b"correct horse battery staple".to_vec();
    product::create_network(
        &config_path,
        directory.path(),
        "nix-lab",
        CreateNetworkOptions {
            password: Some(password),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let endpoint = SecretKey::generate().public();
    product::create_password_enrollment_invite(
        &config_path,
        directory.path(),
        60,
        vec!["127.0.0.1:4000".parse().unwrap()],
        endpoint,
    )
    .unwrap();
    assert!(
        product::expire_pending_password_enrollments(&config_path, directory.path(), u64::MAX,)
            .unwrap()
    );
    let state = product::load_state(directory.path()).unwrap();
    assert!(state.invites[0].revoked);
    assert!(Config::load(&config_path).await.unwrap().peers.is_empty());
}

#[tokio::test]
async fn wrong_password_is_rejected_without_creating_an_enrollment() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    product::create_network(
        &config_path,
        directory.path(),
        "nix-lab",
        CreateNetworkOptions {
            password: Some(b"correct horse battery staple".to_vec()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (command_tx, mut command_rx) = mpsc::channel(1);
    let server_config = config_path.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_connection(stream, &server_config, command_tx, Arc::new(Mutex::new(())))
            .await
            .unwrap();
    });

    let error = enroll(address, b"wrong password", SecretKey::generate().public())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("access_denied"));
    server.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), command_rx.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        product::load_state(directory.path())
            .unwrap()
            .invites
            .is_empty()
    );
}
