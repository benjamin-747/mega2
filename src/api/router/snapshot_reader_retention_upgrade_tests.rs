use sea_orm::DatabaseConnection;

use super::*;
use crate::jupiter::{
    migration::test_upgrade_reader_retention,
    storage::qualified_metadata_family::{
        RootedLookupStatus, RootedQualifiedMetadataRepository,
        provision_or_verify_rooted_qualified_family, reader_previous_fixture::restore_previous,
    },
};

#[path = "snapshot_native_runtime_upgrade_tests.rs"]
mod native_runtime;

async fn permanent_rows(fixture: &Fixture) -> Value {
    let txn = transaction(fixture).await;
    let rows=txn.query_one_raw(Statement::from_string(DbBackend::Postgres,
        "SELECT jsonb_build_object(
           'sessions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY snapshot_id,session_incarnation) FROM mst2_qualified_session_incarnation x),
           'leases',(SELECT jsonb_agg(to_jsonb(x) ORDER BY lease_id) FROM mst2_qualified_lease_binding x),
           'sources',(SELECT jsonb_agg(to_jsonb(x) ORDER BY attestation_id) FROM mst2_metadata_source_root_attestation x),
           'certificates',(SELECT jsonb_agg(to_jsonb(x) ORDER BY page_id,generation) FROM mst2_metadata_page_certificate x)) AS rows"))
        .await.unwrap().unwrap().try_get("","rows").unwrap();
    txn.commit().await.unwrap();
    rows
}

#[tokio::test]
async fn current_reader_retention_migration_verifies_fresh_family_without_rewriting_history() {
    let fixture = Fixture::new_with_pg_config(true).await;
    let before = permanent_rows(&fixture).await;
    let high_water = q_count(
        &fixture,
        "SELECT high_water FROM {q}.mst2_metadata_reader_issuance",
    )
    .await;
    let mono = fixture.state.storage.mono_storage();
    let core = mono.get_connection();
    test_upgrade_reader_retention(core).await.unwrap();
    assert_eq!(permanent_rows(&fixture).await, before);
    assert_eq!(
        q_count(
            &fixture,
            "SELECT high_water FROM {q}.mst2_metadata_reader_issuance"
        )
        .await,
        high_water
    );
    provision_or_verify_rooted_qualified_family(core)
        .await
        .unwrap();
    fixture.counts.assert(0, 0);
}

#[tokio::test]
async fn captured_previous_q_upgrade_preserves_old_sid_source_proofs_and_active_legacy_reader() {
    let fixture = Fixture::new_with_pg_config(true).await;
    let pinned = fixture
        .state
        .storage
        .snapshot_context(&fixture.snapshot, &fixture.lease)
        .await
        .unwrap();
    let before = permanent_rows(&fixture).await;
    let txn = transaction(&fixture).await;
    let active = admission(&txn, &fixture).await;
    txn.commit().await.unwrap();
    let schema = q_schema(&fixture).await;
    let mono = fixture.state.storage.mono_storage();
    let core = mono.get_connection();
    restore_previous(core, &schema, true).await;
    assert_eq!(permanent_rows(&fixture).await, before);
    test_upgrade_reader_retention(core).await.unwrap();
    assert_eq!(permanent_rows(&fixture).await, before);
    assert_eq!(q_count(&fixture,"SELECT count(*) FROM {q}.mst2_metadata_reader_operation WHERE reader_issuance=0 AND state='ACTIVE'").await,1);
    assert_eq!(q_count(&fixture,"SELECT count(*) FROM {q}.mst2_metadata_root_anchor WHERE reader_issuance=0 AND anchor_kind IN ('REQUEST','READER')").await,2);
    let restarted =
        RootedQualifiedMetadataRepository::open(core, &fixture.state.storage.config().database)
            .await
            .unwrap();
    let fixed = restarted
        .context(&fixture.snapshot, &fixture.lease, &pinned.built.instance_id)
        .await
        .unwrap();
    assert_eq!(fixed.built.descriptor, pinned.built.descriptor);
    assert_eq!(fixed.commit_oid, pinned.commit_oid);
    let lookup = restarted
        .lookup_metadata(&fixed, &["/file".to_owned()])
        .await
        .unwrap();
    assert!(matches!(
        lookup.results.as_slice(),
        [RootedLookupStatus::File { .. }]
    ));
    assert_eq!(permanent_rows(&fixture).await, before);
    assert_eq!(q_count(&fixture,"SELECT count(*) FROM {q}.mst2_metadata_reader_operation WHERE reader_issuance=0 AND state='ACTIVE'").await,1);
    let txn = transaction(&fixture).await;
    finish(&txn, &(active.0.clone(), 0)).await;
    txn.commit().await.unwrap();
    let txn = transaction(&fixture).await;
    assert!(prune(&txn, 64).await >= 1);
    txn.commit().await.unwrap();
    assert_eq!(
        q_count(
            &fixture,
            "SELECT count(*) FROM {q}.mst2_metadata_reader_operation WHERE reader_issuance=0"
        )
        .await,
        0
    );
    provision_or_verify_rooted_qualified_family(core)
        .await
        .unwrap();
    fixture.counts.assert(0, 0);
}

#[tokio::test]
async fn captured_previous_core_without_q_upgrades_before_new_provisioning() {
    let temp = tempfile::tempdir().unwrap();
    let (config, _schema) = test_db_config(temp.path()).await;
    let core = crate::jupiter::storage::init::database_connection(&config)
        .await
        .unwrap();
    let old_schema: String = core
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT metadata_schema FROM mst2_metadata_namespace WHERE graph_domain='qualified-v1'",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();
    restore_previous(&core, &old_schema, false).await;
    test_upgrade_reader_retention(&core).await.unwrap();
    provision_or_verify_rooted_qualified_family(&core)
        .await
        .unwrap();
    let schema: String = core
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT metadata_schema FROM mst2_metadata_namespace WHERE graph_domain='qualified-v1'",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();
    assert_ne!(schema, old_schema);
    let water: i64 = core
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT high_water FROM \"{}\".mst2_metadata_reader_issuance",
                schema.replace('"', "\"\"")
            ),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();
    assert_eq!(water, 0);
    provision_or_verify_rooted_qualified_family(&core)
        .await
        .unwrap();
}

#[tokio::test]
async fn captured_previous_tampered_q_rejects_upgrade_without_partial_issuance_schema() {
    let fixture = Fixture::new_with_pg_config(true).await;
    let before = permanent_rows(&fixture).await;
    let schema = q_schema(&fixture).await;
    let mono = fixture.state.storage.mono_storage();
    let core = mono.get_connection();
    restore_previous(core, &schema, true).await;
    core.execute_unprepared(&format!(
        "ALTER TABLE \"{}\".mst2_metadata_reader_operation ADD COLUMN unexpected integer",
        schema.replace('"', "\"\"")
    ))
    .await
    .unwrap();
    assert!(test_upgrade_reader_retention(core).await.is_err());
    assert_eq!(permanent_rows(&fixture).await, before);
    let exists: bool = core
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT to_regclass($1) IS NULL AS absent",
            [format!("{schema}.mst2_metadata_reader_issuance").into()],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "absent")
        .unwrap();
    assert!(exists);
    let implementation:String=core.query_one_raw(Statement::from_string(DbBackend::Postgres,
        "SELECT encode(implementation_fingerprint,'hex') FROM mst2_qualified_family_policy WHERE singleton=1"))
        .await.unwrap().unwrap().try_get_by_index(0).unwrap();
    assert_eq!(
        implementation,
        "6d7095dc052e60bf6de21a987b72e23fdfbfe819355f0e847d2a7f3c1cbd3f27"
    );
}

async fn qualified_schema(fixture: &Fixture) -> String {
    fixture
        .state
        .storage
        .mono_storage()
        .get_connection()
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT metadata_schema FROM mst2_metadata_namespace WHERE graph_domain='qualified-v1'",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap()
}

/// The durable business rows AC-4 requires to survive a failed forward roll, read on the
/// migration's own connection.
async fn core_rows(core: &DatabaseConnection, q_schema: &str) -> Value {
    core.query_one_raw(Statement::from_string(
        DbBackend::Postgres,
        format!(
            "SELECT jsonb_build_object(
               'sessions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY snapshot_id,session_incarnation) FROM {q_schema}.mst2_qualified_session_incarnation x),
               'leases',(SELECT jsonb_agg(to_jsonb(x) ORDER BY lease_id) FROM {q_schema}.mst2_qualified_lease_binding x),
               'sources',(SELECT jsonb_agg(to_jsonb(x) ORDER BY attestation_id) FROM {q_schema}.mst2_metadata_source_root_attestation x),
               'certificates',(SELECT jsonb_agg(to_jsonb(x) ORDER BY page_id,generation) FROM {q_schema}.mst2_metadata_page_certificate x),
               'anchors',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM {q_schema}.mst2_metadata_root_anchor x),
               'readers',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM {q_schema}.mst2_metadata_reader_operation x),
               'reader_issuance',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM {q_schema}.mst2_metadata_reader_issuance x)) AS rows"
        ),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "rows")
    .unwrap()
}

/// Every qualified fingerprint a forward roll rewrites, read on the migration's own connection:
/// the core policy, the namespace route and the q-visible family identity.
async fn core_fingerprints(
    core: &DatabaseConnection,
    core_schema: &str,
    q_schema: &str,
) -> Vec<(String, String)> {
    let rows = core
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT 'policy' AS src, encode(implementation_fingerprint,'hex') AS fp FROM {core_schema}.mst2_qualified_family_policy WHERE singleton=1
                 UNION ALL SELECT 'namespace', encode(implementation_fingerprint,'hex') AS fp FROM {core_schema}.mst2_metadata_namespace WHERE graph_domain='qualified-v1'
                 UNION ALL SELECT 'identity', encode(implementation_fingerprint,'hex') AS fp FROM {q_schema}.mst2_metadata_family_identity WHERE singleton=1
                 ORDER BY src"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 3, "expected three fingerprint rows");
    rows.iter()
        .map(|r| {
            (
                r.try_get::<String>("", "src").unwrap(),
                r.try_get::<String>("", "fp").unwrap(),
            )
        })
        .collect()
}

/// The core policy fingerprint out of a `core_fingerprints` snapshot.
fn policy_stamp(fingerprints: &[(String, String)]) -> String {
    fingerprints
        .iter()
        .find(|(src, _)| src == "policy")
        .map(|(_, fp)| fp.clone())
        .expect("policy fingerprint row")
}

/// The deparsed body of the publication-handoff serving function in the family schema.
async fn handoff_body(core: &DatabaseConnection, q_schema: &str) -> String {
    core.query_one_raw(Statement::from_string(
        DbBackend::Postgres,
        format!(
            "SELECT pg_get_functiondef(p.oid) AS body FROM pg_proc p
               JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='{q_schema}' AND p.proname='mst2_metadata_handoff'"
        ),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "body")
    .unwrap()
}

/// FIX-OX-22 VER-1: the registered migrator forward-rolls the last landed family (the
/// pre-FIX-OX-20 revision restored by `restore_last_landed_reader_family`) to the current serving
/// revision through `apply_migrations`, preserving business rows, the canonical descriptor and the
/// reader history, and replays idempotently.
#[tokio::test]
async fn publication_handoff_upgrade_from_last_landed_family() {
    use crate::jupiter::{
        migration::apply_migrations,
        storage::qualified_metadata_family::{
            implementation_fingerprint, reader_previous_fixture::restore_last_landed_reader_family,
        },
    };

    const LANDED_STAMP: &str = "896fc7cfe5292762c012e98c91059961b3e7b7425e3ea473133a0d22411c1d46";

    let fixture = Fixture::new_with_pg_config(true).await;
    let schema = qualified_schema(&fixture).await;
    let mono = fixture.state.storage.mono_storage();
    let core = mono.get_connection();
    let core_schema: String = core
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT core_schema FROM mst2_metadata_namespace WHERE graph_domain='qualified-v1'",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();

    restore_last_landed_reader_family(core, &schema, true).await;
    // Reader history on the last landed family, so "reader history preserved" is actually covered.
    let seed = transaction(&fixture).await;
    for _ in 0..2 {
        let ticket = admission(&seed, &fixture).await;
        finish(&seed, &ticket).await;
    }
    seed.commit().await.unwrap();

    let landed = core_fingerprints(core, &core_schema, &schema).await;
    assert_eq!(
        policy_stamp(&landed),
        LANDED_STAMP,
        "the fixture must start at the last landed revision"
    );
    assert_ne!(
        LANDED_STAMP,
        hex::encode(implementation_fingerprint()),
        "the landed revision must not already be the current one"
    );
    let prior_body = handoff_body(core, &schema).await;
    let before_rows = core_rows(core, &schema).await;
    assert!(before_rows["sessions"][0]["canonical_descriptor"].is_string());
    assert!(!before_rows["readers"].is_null());

    // Drive the registered migrator rather than the direct test hook: clear this migration's
    // bookkeeping row so `apply_migrations` runs it for real, then assert the outcome.
    core.execute_unprepared(
        "DELETE FROM seaql_migrations WHERE version='m20261009_000100_upgrade_qualified_publication_handoff'",
    )
    .await
    .unwrap();
    apply_migrations(core, false).await.unwrap();

    let after = core_fingerprints(core, &core_schema, &schema).await;
    assert_eq!(after.len(), 3, "every fingerprint must be readable");
    assert!(
        after
            .iter()
            .all(|row| row.1 == hex::encode(implementation_fingerprint())),
        "every fingerprint must carry the current compiled revision: {after:?}"
    );
    assert_ne!(handoff_body(core, &schema).await, prior_body);
    assert_eq!(
        core_rows(core, &schema).await,
        before_rows,
        "the forward roll must preserve business rows, descriptor and reader history"
    );

    // Replay through the same registered path is a no-op.
    apply_migrations(core, false).await.unwrap();
    assert_eq!(core_fingerprints(core, &core_schema, &schema).await, after);
    assert_eq!(core_rows(core, &schema).await, before_rows);
}

/// FIX-OX-22 VER-2: a fault during the publication-handoff upgrade rolls the whole transaction
/// back — every fingerprint, the rolled family object and every durable row return to the last
/// landed family snapshot — and the upgrade then replays successfully.
#[tokio::test]
async fn publication_handoff_upgrade_failure_and_replay_are_atomic() {
    use crate::jupiter::{
        migration::test_upgrade_publication_handoff,
        storage::qualified_metadata_family::{
            implementation_fingerprint, reader_previous_fixture::restore_last_landed_reader_family,
        },
    };

    const LANDED_STAMP: &str = "896fc7cfe5292762c012e98c91059961b3e7b7425e3ea473133a0d22411c1d46";

    let fixture = Fixture::new_with_pg_config(true).await;
    let schema = qualified_schema(&fixture).await;
    let mono = fixture.state.storage.mono_storage();
    let core = mono.get_connection();
    let core_schema: String = core
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT core_schema FROM mst2_metadata_namespace WHERE graph_domain='qualified-v1'",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();

    restore_last_landed_reader_family(core, &schema, true).await;
    // Seed real reader history on the last landed family, so the rollback assertion covers the
    // reader tables too.
    let seed = transaction(&fixture).await;
    for _ in 0..2 {
        let ticket = admission(&seed, &fixture).await;
        finish(&seed, &ticket).await;
    }
    seed.commit().await.unwrap();

    let before = core_fingerprints(core, &core_schema, &schema).await;
    assert_eq!(
        policy_stamp(&before),
        LANDED_STAMP,
        "the restored family must carry the last landed stamp"
    );
    let prior_body = handoff_body(core, &schema).await;
    let before_rows = core_rows(core, &schema).await;
    assert!(
        before_rows["sessions"][0]["canonical_descriptor"].is_string(),
        "the last landed family must carry its canonical descriptor"
    );
    assert!(
        !before_rows["readers"].is_null(),
        "the last landed family must carry its reader history"
    );

    // Fault injection inside the transaction, immediately after the family install and its shape
    // verification, through an explicit per-call test seam (no process-global state, so parallel
    // test runs cannot inject it elsewhere). A lock-based fault is unusable here: the engine takes
    // `LOCK TABLE ... IN ACCESS EXCLUSIVE MODE` early, so any conflicting lock times out before the
    // install and the rollback assertions would be vacuous.
    let error = format!(
        "{:?}",
        crate::jupiter::migration::test_upgrade_publication_handoff_with_fault(core)
            .await
            .expect_err("the injected post-install fault must fail the upgrade")
    );
    assert!(
        error.contains("injected post-install family fault"),
        "the failure must be the injected post-install fault: {error}"
    );
    assert_eq!(
        core_fingerprints(core, &core_schema, &schema).await,
        before,
        "every fingerprint must roll back to the last landed family"
    );
    assert_eq!(
        core_rows(core, &schema).await,
        before_rows,
        "durable rows must roll back to the last landed family"
    );
    assert_eq!(
        handoff_body(core, &schema).await,
        prior_body,
        "the rolled family object must be back at the last landed revision"
    );

    // Replay: the same upgrade now succeeds and stamps the current revision. The engine's own
    // prior-shape check would reject a partially applied family, so success also proves the failed
    // attempt left no partial state behind.
    test_upgrade_publication_handoff(core).await.unwrap();
    let after = core_fingerprints(core, &core_schema, &schema).await;
    assert!(
        after
            .iter()
            .all(|row| row.1 == hex::encode(implementation_fingerprint()))
    );
    assert_ne!(handoff_body(core, &schema).await, prior_body);
    assert_eq!(
        core_rows(core, &schema).await,
        before_rows,
        "the forward roll must not change durable rows or history"
    );
    test_upgrade_publication_handoff(core).await.unwrap();
    assert_eq!(core_fingerprints(core, &core_schema, &schema).await, after);
}

/// FIX-OX-22 VER-2 (negative): a family stamped with a revision this forward migration does not
/// roll is refused instead of being re-rendered from the wrong prior.
#[tokio::test]
async fn publication_handoff_refuses_a_non_landed_revision() {
    use crate::jupiter::{
        migration::test_upgrade_publication_handoff,
        storage::qualified_metadata_family::reader_previous_fixture::restore_native_runtime,
    };

    let fixture = Fixture::new_with_pg_config(true).await;
    let schema = qualified_schema(&fixture).await;
    let mono = fixture.state.storage.mono_storage();
    let core = mono.get_connection();
    restore_native_runtime(core, &schema, true).await;

    let error = format!(
        "{:?}",
        test_upgrade_publication_handoff(core)
            .await
            .expect_err("a non-landed revision must be refused")
    );
    assert!(
        error.contains("unsupported prior implementation"),
        "unexpected refusal: {error}"
    );
}
