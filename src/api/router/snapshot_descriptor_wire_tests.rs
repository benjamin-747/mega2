use mst2_codec::descriptor::ServingDescriptor;

use super::*;

async fn assert_postgres_descriptor_matches_codec(fixture: &Fixture, scope: &str) {
    // FIX-OX-26: the resolve path documents its 503 `TEMPORARY_UNAVAILABLE` ("qualified source is
    // being updated; retry the operation") as retryable. Under a parallel full-suite run another
    // writer can hold that window, so honour the documented contract with a bounded retry instead of
    // treating it as a terminal result; the descriptor assertions below are unchanged.
    let resolve = |scope: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v2/snapshots/resolve")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"target":{"kind":"latest"},"scope":scope}).to_string(),
            ))
            .unwrap()
    };
    let mut resolved: Option<Value> = None;
    for attempt in 0..40u32 {
        let response = fixture.app.clone().oneshot(resolve(scope)).await.unwrap();
        if response.status().as_u16() == 503 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            assert!(
                attempt + 1 < 40,
                "resolve kept reporting its documented retryable state for 10 s"
            );
            continue;
        }
        resolved = Some(success_json(response).await);
        break;
    }
    let resolved = resolved.expect("resolve must produce a result");
    let snapshot = resolved["descriptor"]["snapshot_id"].as_str().unwrap();
    let lease = resolved["lease_id"].as_str().unwrap();
    assert_eq!(
        fixture
            .state
            .storage
            .snapshot_metadata_family(lease, true)
            .await
            .unwrap(),
        Some(SnapshotMetadataFamily::Rooted)
    );
    let context = fixture
        .state
        .storage
        .snapshot_context(snapshot, lease)
        .await
        .unwrap();
    let descriptor = &context.built.descriptor;
    assert_eq!(descriptor.scope, scope);
    let codec_bytes = descriptor.encode().unwrap();
    let schema = q_schema(fixture).await;
    let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
    let row = fixture
        .state
        .storage
        .mono_storage()
        .get_connection()
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT {q}.mst2_metadata_descriptor(session.prepare_id,session.instance_id,
                    session.commit_oid,session.root_tree_oid) AS descriptor,
                    session.canonical_descriptor,session.metadata_root,session.snapshot_id
                 FROM {q}.mst2_qualified_session_incarnation session
                 JOIN {q}.mst2_qualified_lease_binding lease USING(snapshot_id,session_incarnation)
                 WHERE session.snapshot_id=$1 AND lease.lease_id=$2 AND session.state='READY'
                   AND lease.state='ACTIVE'",
                q = quoted,
            ),
            [snapshot.into(), lease.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let database_bytes: Vec<u8> = row.try_get("", "descriptor").unwrap();
    assert_eq!(database_bytes, codec_bytes, "scope {scope:?}");
    assert_eq!(
        row.try_get::<Vec<u8>>("", "canonical_descriptor").unwrap(),
        codec_bytes
    );
    assert_eq!(
        ServingDescriptor::decode(&database_bytes).unwrap(),
        *descriptor
    );
    assert_eq!(
        &database_bytes[56..58],
        &u16::try_from(scope.len()).unwrap().to_le_bytes()
    );
    assert_eq!(&database_bytes[58..58 + scope.len()], scope.as_bytes());
    assert_eq!(
        row.try_get::<Vec<u8>>("", "metadata_root").unwrap(),
        descriptor.metadata_root.to_vec()
    );
    assert_eq!(
        resolved["descriptor"]["metadata_root"],
        format!("sha256:{}", hex::encode(descriptor.metadata_root))
    );
    let codec_snapshot = format!("sha256:{}", hex::encode(descriptor.snapshot_id().unwrap()));
    assert_eq!(snapshot, codec_snapshot);
    assert_eq!(context.built.snapshot_id, codec_snapshot);
    assert_eq!(
        row.try_get::<String>("", "snapshot_id").unwrap(),
        codec_snapshot
    );
}

#[tokio::test]
async fn rooted_postgres_descriptor_matches_codec_bytes_for_root_ascii_long_and_utf8_scopes() {
    let component = "a".repeat(247);
    let fixture = Fixture::new_with_pg_config_directories_and_objects(
        true,
        0,
        &[(format!("{component}/é/file"), b"descriptor wire".to_vec())],
    )
    .await;
    let long_scope = format!("/project/{component}");
    let utf8_scope = format!("{long_scope}/é");
    assert_eq!(long_scope.len(), 256);
    assert_eq!(utf8_scope.len(), 259);
    assert_ne!(utf8_scope.len(), utf8_scope.chars().count());
    for scope in ["/", "/project", long_scope.as_str(), utf8_scope.as_str()] {
        assert_postgres_descriptor_matches_codec(&fixture, scope).await;
    }
}
