//! Trusted forward repair of the physical v3 Q family, preserving history.

use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
use sea_orm_migration::prelude::*;
use sha2::{Digest, Sha256};

use crate::jupiter::storage::qualified_metadata_family::{
    implementation_fingerprint, render_family,
};

const PUBLICATION_HANDOFF_CAPTURE: &str =
    "4590ef4923169511579689b9e72ae2494f9a9bc3f8e5fe788c6005e415bc0212";

pub(crate) const PREVIOUS_IMPLEMENTATION: &str =
    "6d7095dc052e60bf6de21a987b72e23fdfbfe819355f0e847d2a7f3c1cbd3f27";

pub(crate) const RETENTION_IMPLEMENTATION: &str =
    "900e7a340e7365c9f31995e070edbfe2076b870ec09fe89e4dc43e56f26b91ab";
/// The implementation fingerprint a database carries after the plan's migrations ran on the tree
/// immediately before FIX-OX-20 (`1b4c6b3^`). FIX-OX-20 changed exactly one fingerprinted source,
/// the `mst2_metadata_handoff` body in `qualified_metadata_serving.sql`, so that state is the last
/// landed family this forward migration must roll. Recomputed independently from the pre-FIX-OX-20
/// sources with the same `implementation_fingerprint` algorithm.
pub(crate) const PUBLICATION_HANDOFF_PRIOR_IMPLEMENTATION: &str =
    "896fc7cfe5292762c012e98c91059961b3e7b7425e3ea473133a0d22411c1d46";

pub(crate) const NATIVE_RUNTIME_IMPLEMENTATION: &str =
    "87b104e6b5593b1d6e5904a4e4be94e6ba0814dbb2c25dd8b38a0ea950d42307";
const PREVIOUS_DECODER: &str = include_str!("m20261008_000500_previous_rooted_decoder.sql");
const PREVIOUS_READERS: &str = include_str!("m20261008_000500_previous_reader_family.sql");
const PREVIOUS_DESCRIPTOR: &str = include_str!("m20261008_000600_previous_descriptor.sql");

/// Which trusted family revision an upgrade installs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InstallProfile {
    /// Re-install the historical native-runtime family.
    Native,
    /// Repair canonical descriptor integer encoding.
    Descriptor,
    /// Install the current serving revision changed by the publication-handoff fix.
    PublicationHandoff,
}

/// Every function declaration in a rendered family, in document order, normalised to
/// `CREATE OR REPLACE` so the install converges whether or not the function already exists.
///
/// The family declares some functions more than once (a later `CREATE OR REPLACE` redefinition),
/// so blocks are emitted in document order rather than deduplicated by name.
pub(crate) fn family_function_blocks(rendered: &str) -> Result<String, DbErr> {
    let mut out = String::new();
    let mut index = 0usize;
    let mut count = 0usize;
    while let Some(offset) = rendered[index..].find("CREATE ") {
        let at = index + offset;
        let tail = &rendered[at..];
        let declaration = tail
            .strip_prefix("CREATE OR REPLACE FUNCTION ")
            .map(|rest| ("CREATE OR REPLACE FUNCTION ", rest))
            .or_else(|| {
                tail.strip_prefix("CREATE FUNCTION ")
                    .map(|rest| ("CREATE FUNCTION ", rest))
            });
        let Some((prefix, body)) = declaration else {
            index = at + "CREATE ".len();
            continue;
        };
        let end = body
            .find("$$;")
            .ok_or_else(|| rejected("native runtime family function body is unterminated"))?
            + "$$;".len();
        let block = &tail[..prefix.len() + end];
        if prefix == "CREATE FUNCTION " {
            out.push_str(&block.replacen("CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1));
        } else {
            out.push_str(block);
        }
        out.push('\n');
        count += 1;
        index = at + prefix.len() + end;
    }
    // Completeness: the render is scanned with the same declaration test, so any declaration whose
    // body is not terminated by `$$;` shows up as a mismatch instead of a silently partial install.
    let declared = rendered
        .lines()
        .filter(|line| {
            line.starts_with("CREATE FUNCTION ") || line.starts_with("CREATE OR REPLACE FUNCTION ")
        })
        .count();
    if count == 0 || count != declared {
        return Err(rejected(
            "native runtime rendered family declares an unusable function set",
        ));
    }
    Ok(out)
}

fn rejected(message: &str) -> DbErr {
    DbErr::Custom(message.into())
}

fn identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn trusted_function(source: &str, name: &str) -> Result<String, DbErr> {
    let prefix = format!("CREATE FUNCTION {name}(");
    let start = source
        .find(&prefix)
        .ok_or_else(|| rejected("reader migration trusted function is missing"))?;
    let function = &source[start..];
    let body = function
        .find("AS $")
        .ok_or_else(|| rejected("reader migration function body is missing"))?
        + 3;
    let tag_end = function[body + 1..]
        .find('$')
        .ok_or_else(|| rejected("reader migration function delimiter is missing"))?
        + body
        + 2;
    let tag = &function[body..tag_end];
    let end = function[tag_end..]
        .find(tag)
        .ok_or_else(|| rejected("reader migration function terminator is missing"))?
        + tag_end
        + tag.len();
    if function.as_bytes().get(end) != Some(&b';') {
        return Err(rejected("reader migration function terminator is invalid"));
    }
    Ok(function[..=end].replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
}

async fn digest<C: ConnectionTrait>(
    connection: &C,
    sql: String,
    values: Vec<Value>,
) -> Result<Vec<u8>, DbErr> {
    connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .await?
        .ok_or_else(|| rejected("reader migration physical fingerprint is missing"))?
        .try_get("", "fingerprint")
}

async fn catalog<C: ConnectionTrait>(
    connection: &C,
    core_oid: i64,
    q_oid: i64,
    exempt_oid: i64,
) -> Result<Vec<u8>, DbErr> {
    let source = include_str!("../storage/qualified_family_catalog.sql")
        .replace("$CORE_OID$", "$1::bigint::oid")
        .replace("$Q_OID$", "$2::bigint::oid")
        .replace("$EXEMPT_Q_OID$", "$3::bigint::oid");
    digest(
        connection,
        source,
        vec![core_oid.into(), q_oid.into(), exempt_oid.into()],
    )
    .await
}

async fn shape<C: ConnectionTrait>(
    connection: &C,
    q_oid: i64,
    namespace: &str,
    storage: &str,
) -> Result<Vec<u8>, DbErr> {
    let search_path: String = connection
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_catalog.current_setting('search_path') AS search_path",
        ))
        .await?
        .ok_or_else(|| rejected("reader migration caller search path is missing"))?
        .try_get("", "search_path")?;
    // Catalog deparsing must use the same path as the trusted shape helper.
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_catalog.set_config('search_path',$1,true)",
            ["pg_catalog,pg_temp".into()],
        ))
        .await?;
    let source = include_str!("../storage/qualified_family_shape.sql")
        .replace("q_oid", "$1::bigint::oid")
        .replace("n_uuid", "$2::uuid")
        .replace("s_uuid", "$3::text");
    let fingerprint = digest(
        connection,
        source,
        vec![q_oid.into(), namespace.into(), storage.into()],
    )
    .await;
    let restored = connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_catalog.set_config('search_path',$1,true)",
            [search_path.into()],
        ))
        .await;
    let fingerprint = fingerprint?;
    restored?;
    Ok(fingerprint)
}

fn replace_function(source: &mut String, name: &str, captured: &str) -> Result<(), DbErr> {
    let plain = |sql: &str| -> Result<String, DbErr> {
        Ok(trusted_function(sql, name)?.replacen(
            "CREATE OR REPLACE FUNCTION",
            "CREATE FUNCTION",
            1,
        ))
    };
    let current = plain(source)?;
    let previous = plain(captured)?;
    *source = source.replacen(&current, &previous, 1);
    Ok(())
}

/// Historical source is used only to authenticate forward migration templates.
pub(crate) fn render_prior_family(
    core: &str,
    core_oid: i64,
    q: &str,
    q_oid: i64,
    namespace: &str,
    storage: &str,
    implementation: &str,
) -> Result<String, DbErr> {
    if ![
        PREVIOUS_IMPLEMENTATION,
        RETENTION_IMPLEMENTATION,
        NATIVE_RUNTIME_IMPLEMENTATION,
    ]
    .contains(&implementation)
    {
        return Err(rejected("native runtime template version is unsupported"));
    }
    let decoder = PREVIOUS_DECODER.replace("\r\n", "\n");
    let readers = PREVIOUS_READERS.replace("\r\n", "\n");
    let descriptor = PREVIOUS_DESCRIPTOR.replace("\r\n", "\n");
    if hex::encode(Sha256::digest(decoder.as_bytes()))
        != "f14d024cfb821f9d6b7348ab9b69f48c09862ff7dd3fbb2b360b253f949e35a9"
        || hex::encode(Sha256::digest(readers.as_bytes()))
            != "ec9b422440da111e5e047e1a4c85a28a33053cf0e320a56ea944ebefeaa8ea37"
        || hex::encode(Sha256::digest(descriptor.as_bytes()))
            != "c833666fcb1b3c9fd0bf186e5ad732f5e8b9b9dbf4360ce8d93a0d91d17d5c1a"
    {
        return Err(rejected("native runtime historical source capture changed"));
    }
    let mut source =
        render_family(core, core_oid, q, q_oid, namespace, storage).replace("\r\n", "\n");
    replace_function(&mut source, "mst2_metadata_descriptor", &descriptor)?;
    if implementation != NATIVE_RUNTIME_IMPLEMENTATION {
        replace_function(&mut source, "mst2_metadata_decode_rooted_plan", &decoder)?;
    }
    if implementation == PREVIOUS_IMPLEMENTATION {
        let start = source
            .find("CREATE TABLE mst2_metadata_reader_operation (")
            .ok_or_else(|| rejected("native runtime reader template is missing"))?;
        let end = source[start..]
            .find("CREATE FUNCTION mst2_metadata_session_covers_prepare(")
            .ok_or_else(|| rejected("native runtime reader template boundary is missing"))?
            + start;
        let captured_start = readers
            .find("-- READER DDL BEGIN\n")
            .ok_or_else(|| rejected("native runtime captured reader DDL is missing"))?
            + "-- READER DDL BEGIN\n".len();
        let captured_end = readers
            .find("-- READER DDL END")
            .ok_or_else(|| rejected("native runtime captured reader DDL boundary is missing"))?;
        source.replace_range(start..end, &readers[captured_start..captured_end]);
        for name in [
            "mst2_metadata_dml_barrier",
            "mst2_metadata_gc_enabled",
            "mst2_metadata_root_anchor_guard",
            "mst2_metadata_serving_complete",
            "mst2_metadata_reader_guard",
            "mst2_metadata_begin_reader",
            "mst2_metadata_finish_reader",
            "mst2_metadata_read_source_entries",
            "mst2_metadata_cleanup_expired",
            "mst2_metadata_gc_owner_cleanup",
        ] {
            replace_function(&mut source, name, &readers)?;
        }
        for name in [
            "mst2_metadata_next_reader_issuance",
            "mst2_metadata_reader_issuance_guard",
            "mst2_metadata_prune_readers",
        ] {
            let function = trusted_function(&source, name)?.replacen(
                "CREATE OR REPLACE FUNCTION",
                "CREATE FUNCTION",
                1,
            );
            source = source.replacen(&function, "", 1);
        }
        source = source.replace(
            "CREATE TRIGGER mst2_metadata_reader_issuance_guard BEFORE INSERT OR UPDATE OR DELETE ON mst2_metadata_reader_issuance\n  FOR EACH ROW EXECUTE FUNCTION mst2_metadata_reader_issuance_guard();", "",
        ).replace("'mst2_metadata_reader_issuance',", "");
    }
    Ok(substitute_family_placeholders(
        source,
        core,
        core_oid,
        q,
        q_oid,
        namespace,
        storage,
        implementation,
    ))
}

// Rationale: mirrors the placeholder-substitution arity the renderers share; bundling these into a
// struct would add a type used only at these call sites.
#[allow(clippy::too_many_arguments)]
fn substitute_family_placeholders(
    source: String,
    core: &str,
    core_oid: i64,
    q: &str,
    q_oid: i64,
    namespace: &str,
    storage: &str,
    implementation: &str,
) -> String {
    source
        .replace(&hex::encode(implementation_fingerprint()), implementation)
        .replace("$CORE_SCHEMA$", &identifier(core))
        .replace("$CORE_LITERAL$", &literal(core))
        .replace("$Q_SCHEMA$", &identifier(q))
        .replace("$Q_LITERAL$", &literal(q))
        .replace("$CORE_OID$", &core_oid.to_string())
        .replace("$Q_OID$", &q_oid.to_string())
        .replace("$NAMESPACE_UUID$", namespace)
        .replace("$STORAGE_UUID$", storage)
        .replace("$IMPLEMENTATION_SHA$", implementation)
}

/// The pre-publication-handoff family: the current render with the captured prior handoff
/// function, used to authenticate the forward migration.
// Rationale: same arity as `render_family`/`render_prior_family`; the fixture and the migration
// must call this renderer identically, so it keeps that family's public shape.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_publication_handoff_prior(
    core: &str,
    core_oid: i64,
    q: &str,
    q_oid: i64,
    namespace: &str,
    storage: &str,
    implementation: &str,
) -> Result<String, DbErr> {
    const PREVIOUS_HANDOFF: &str =
        include_str!("m20261009_000100_previous_publication_handoff_family.sql");
    let previous = PREVIOUS_HANDOFF.replace("\r\n", "\n");
    if hex::encode(Sha256::digest(previous.as_bytes())) != PUBLICATION_HANDOFF_CAPTURE {
        return Err(rejected(
            "publication handoff historical source capture changed",
        ));
    }
    let mut source =
        render_family(core, core_oid, q, q_oid, namespace, storage).replace("\r\n", "\n");
    replace_function(&mut source, "mst2_metadata_handoff", &previous)?;
    Ok(substitute_family_placeholders(
        source,
        core,
        core_oid,
        q,
        q_oid,
        namespace,
        storage,
        implementation,
    ))
}

struct TrustedShape {
    canonical: Vec<u8>,
    legacy: Option<Vec<u8>>,
}

async fn template_shapes<C: ConnectionTrait>(
    connection: &C,
    core: &str,
    core_oid: i64,
    implementation: &[u8],
) -> Result<TrustedShape, DbErr> {
    template_shapes_with(connection, core, core_oid, implementation, false).await
}

async fn template_shapes_with<C: ConnectionTrait>(
    connection: &C,
    core: &str,
    core_oid: i64,
    implementation: &[u8],
    publication_handoff_prior: bool,
) -> Result<TrustedShape, DbErr> {
    let namespace = uuid::Uuid::new_v4().to_string();
    let schema = format!("mst2q_{}", namespace.replace('-', ""));
    let storage = uuid::Uuid::new_v4().to_string();
    let q = identifier(&schema);
    let c = identifier(core);
    connection
        .execute_unprepared(&format!("CREATE SCHEMA {q}"))
        .await?;
    let oid: i64 = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT oid::bigint FROM pg_catalog.pg_namespace WHERE nspname=$1",
            [schema.clone().into()],
        ))
        .await?
        .ok_or_else(|| rejected("native runtime trusted template schema is missing"))?
        .try_get("", "oid")?;
    let version = hex::encode(implementation);
    let source =
        if publication_handoff_prior && implementation != implementation_fingerprint().as_slice() {
            render_publication_handoff_prior(
                core, core_oid, &schema, oid, &namespace, &storage, &version,
            )?
        } else if implementation == implementation_fingerprint().as_slice() {
            render_family(core, core_oid, &schema, oid, &namespace, &storage)
        } else {
            render_prior_family(core, core_oid, &schema, oid, &namespace, &storage, &version)?
        };
    connection.execute_unprepared(&source).await?;
    let canonical = shape(connection, oid, &namespace, &storage).await?;
    // Reproduce only the exact historical Q-visible deparsing defect. The
    // exception is admitted below solely for the known 900e policy without Q.
    let legacy = if version == RETENTION_IMPLEMENTATION {
        let source = include_str!("../storage/qualified_family_shape.sql")
            .replace("q_oid", "$1::bigint::oid")
            .replace("n_uuid", "$2::uuid")
            .replace("s_uuid", "$3::text");
        Some(
            digest(
                connection,
                source,
                vec![oid.into(), namespace.into(), storage.into()],
            )
            .await?,
        )
    } else {
        None
    };
    connection
        .execute_unprepared(&format!(
            "SET LOCAL search_path={c},pg_catalog,pg_temp; DROP SCHEMA {q} CASCADE"
        ))
        .await?;
    Ok(TrustedShape { canonical, legacy })
}

struct Family {
    schema: String,
    oid: i64,
    namespace: String,
    storage: String,
    catalog: Vec<u8>,
}

pub(super) async fn upgrade(
    manager: &SchemaManager<'_>,
    allow_previous_readers: bool,
) -> Result<(), DbErr> {
    upgrade_to(
        manager,
        allow_previous_readers,
        InstallProfile::Native,
        false,
    )
    .await
}

pub(super) async fn upgrade_descriptor(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Finish an interrupted reader/runtime upgrade before the independent
    // descriptor repair, without replaying reader DDL on an admitted family.
    upgrade(manager, true).await?;
    upgrade_to(manager, false, InstallProfile::Descriptor, false).await
}

/// Forward-roll an admitted family to the publication-handoff serving revision.
/// Replay is idempotent: an already-current family returns early.
pub(super) async fn upgrade_publication_handoff(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    upgrade_to(manager, false, InstallProfile::PublicationHandoff, false).await
}

/// Test-only entry point that can fail the transaction immediately after the family install and its
/// shape verification, so the rollback test can prove the installed DDL is undone.
#[cfg(test)]
pub(super) async fn upgrade_publication_handoff_with_fault(
    manager: &SchemaManager<'_>,
    fail_after_family_install: bool,
) -> Result<(), DbErr> {
    upgrade_to(
        manager,
        false,
        InstallProfile::PublicationHandoff,
        fail_after_family_install,
    )
    .await
}

async fn upgrade_to(
    manager: &SchemaManager<'_>,
    allow_previous_readers: bool,
    profile: InstallProfile,
    // Test seam for the rollback test; every production caller passes `false`.
    #[cfg_attr(not(test), allow(unused_variables))] fail_after_family_install: bool,
) -> Result<(), DbErr> {
    if manager.get_database_backend() != DbBackend::Postgres {
        return Err(rejected(
            "qualified reader retention requires primary PostgreSQL",
        ));
    }
    let connection = manager.get_connection();
    let captured = connection.query_one_raw(Statement::from_string(DbBackend::Postgres,
        "SELECT n.nspname,n.oid::bigint,registry.mono_lock_key2 FROM pg_catalog.pg_namespace n
         JOIN mst2_metadata_namespace registry ON registry.singleton=1 AND registry.core_schema=n.nspname
           AND registry.core_schema_oid=n.oid WHERE n.nspname=current_schema()"))
        .await?.ok_or_else(|| rejected("reader migration requires its captured core schema"))?;
    let core: String = captured.try_get("", "nspname")?;
    let core_oid: i64 = captured.try_get("", "oid")?;
    let mono: i32 = captured.try_get("", "mono_lock_key2")?;
    let c = identifier(&core);
    connection
        .execute_unprepared("SELECT pg_catalog.set_config('lock_timeout','5000ms',true)")
        .await?;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_catalog.pg_advisory_xact_lock(1297043024,$1)",
            [mono.into()],
        ))
        .await?;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_catalog.pg_advisory_xact_lock(1296718001,pg_catalog.hashtext($1))",
            [core.clone().into()],
        ))
        .await?;
    let namespaces = connection
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT metadata_schema FROM {c}.mst2_metadata_namespace ORDER BY namespace_uuid"
            ),
        ))
        .await?;
    if !(1..=2).contains(&namespaces.len()) {
        return Err(rejected(
            "reader migration namespace registry is not bounded",
        ));
    }
    let namespace_count = namespaces.len();
    for namespace in namespaces {
        let schema: String = namespace.try_get("", "metadata_schema")?;
        connection
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT pg_catalog.pg_advisory_xact_lock(1296717362,pg_catalog.hashtext($1))",
                [schema.into()],
            ))
            .await?;
    }
    connection.execute_unprepared(&format!(
        "LOCK TABLE {c}.mst2_metadata_namespace,{c}.mst2_qualified_family_policy IN ACCESS EXCLUSIVE MODE"
    )).await?;
    let policy=connection.query_one_raw(Statement::from_string(DbBackend::Postgres,
        format!("SELECT implementation_fingerprint,expected_shape,authority_catalog FROM {c}.mst2_qualified_family_policy WHERE singleton=1")))
        .await?.ok_or_else(|| rejected("reader migration trusted policy is missing"))?;
    let implementation: Vec<u8> = policy.try_get("", "implementation_fingerprint")?;
    let compiled = implementation_fingerprint();
    let runtime =
        hex::decode(NATIVE_RUNTIME_IMPLEMENTATION).map_err(|error| rejected(&error.to_string()))?;
    let current = if profile == InstallProfile::Native {
        runtime.clone()
    } else {
        compiled.clone()
    };
    let previous =
        hex::decode(PREVIOUS_IMPLEMENTATION).map_err(|error| rejected(&error.to_string()))?;
    let retention =
        hex::decode(RETENTION_IMPLEMENTATION).map_err(|error| rejected(&error.to_string()))?;
    // Compare the encoded stamp directly: a decode fallback here would silently turn a broken
    // constant into "no prior accepted" instead of failing loudly.
    let publication_handoff_prior =
        hex::encode(&implementation) == PUBLICATION_HANDOFF_PRIOR_IMPLEMENTATION;
    // Accepted stamps per profile:
    //   * `compiled`             — already current; the caller returns early.
    //   * `PublicationHandoff`   — exactly `compiled` (early return) or the one prior revision this
    //     forward migration rolls. Nothing else is authenticated for it, so a family stamped with
    //     any other revision is refused instead of being re-rendered from the wrong prior.
    //   * `Native` (historical)  — `compiled`, `runtime`, and the reader-retention/previous stamps
    //     the m20261008_000500 re-install path handles.
    //   * `Descriptor` (000600)  — `compiled` or `runtime`.
    let supported = if profile == InstallProfile::PublicationHandoff {
        implementation == compiled || publication_handoff_prior
    } else {
        implementation == compiled
            || implementation == runtime
            || (profile != InstallProfile::Descriptor
                && (implementation == retention
                    || allow_previous_readers && implementation == previous))
    };
    if !supported {
        return Err(rejected(
            "reader migration refuses an unsupported prior implementation",
        ));
    }
    let rows=connection.query_all_raw(Statement::from_string(DbBackend::Postgres,format!(
        "SELECT namespace_uuid::text,metadata_schema,metadata_schema_oid::bigint,metadata_storage_uuid,
           implementation_fingerprint,catalog_fingerprint FROM {c}.mst2_metadata_namespace WHERE graph_domain='qualified-v1'"))).await?;
    let family = match rows.as_slice() {
        [] => None,
        [row] => Some(Family {
            schema: row.try_get("", "metadata_schema")?,
            oid: row.try_get("", "metadata_schema_oid")?,
            namespace: row.try_get("", "namespace_uuid")?,
            storage: row.try_get("", "metadata_storage_uuid")?,
            catalog: row.try_get("", "catalog_fingerprint")?,
        }),
        _ => return Err(rejected("reader migration requires at most one Q family")),
    };
    let q_oid = family.as_ref().map_or(0, |family| family.oid);
    if namespace_count != if family.is_some() { 2 } else { 1 } {
        return Err(rejected(
            "native runtime namespace registry identity is not exact",
        ));
    }
    if policy.try_get::<Vec<u8>>("", "authority_catalog")?
        != catalog(connection, core_oid, 0, q_oid).await?
    {
        return Err(rejected(
            "reader migration prior core authority catalog changed",
        ));
    }
    let scope = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("SELECT {c}.mst2_route_scope_valid($1) AS valid"),
            [core.clone().into()],
        ))
        .await?
        .ok_or_else(|| rejected("reader migration core scope is missing"))?;
    if !scope.try_get::<bool>("", "valid")? {
        return Err(rejected("reader migration prior core scope changed"));
    }
    if let Some(family) = &family {
        for identity in [&family.namespace, &family.storage] {
            let parsed = uuid::Uuid::parse_str(identity)
                .map_err(|_| rejected("native runtime prior Q UUID is invalid"))?;
            if parsed.get_version_num() != 4
                || parsed.get_variant() != uuid::Variant::RFC4122
                || parsed.to_string() != *identity
            {
                return Err(rejected("native runtime prior Q UUID is not canonical v4"));
            }
        }
        let q = identifier(&family.schema);
        let identity=connection.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,format!(
            "SELECT EXISTS(SELECT 1 FROM {c}.mst2_metadata_namespace n
               JOIN {c}.mst2_metadata_namespace g ON g.singleton=1
               JOIN {q}.mst2_metadata_family_identity i ON i.singleton=1
               JOIN {q}.mst2_metadata_storage_scope s ON s.singleton=1
               JOIN pg_catalog.pg_namespace physical ON physical.oid=n.metadata_schema_oid AND physical.nspname=n.metadata_schema
               WHERE n.namespace_uuid=$1::uuid AND n.metadata_schema='mst2q_'||replace(n.namespace_uuid::text,'-','')
                 AND n.singleton IS NULL AND n.family_identity='v3-rooted-qualified-1' AND n.graph_domain='qualified-v1'
                 AND n.admission_state='ROOTED_Q_ADMITTED' AND n.collector_state='ENABLED'
                 AND ROW(n.core_schema,n.core_schema_oid,n.database_name,n.database_oid,n.storage_uuid,n.server_address,n.server_port,n.mono_lock_key2)
                   IS NOT DISTINCT FROM ROW(g.core_schema,g.core_schema_oid,g.database_name,g.database_oid,g.storage_uuid,g.server_address,g.server_port,g.mono_lock_key2)
                 AND n.metadata_storage_uuid<>g.storage_uuid AND n.implementation_fingerprint=$2
                 AND ROW(i.namespace_uuid,i.storage_uuid,i.core_schema_oid,i.metadata_schema_oid,i.family_identity,i.implementation_fingerprint)
                   IS NOT DISTINCT FROM ROW(n.namespace_uuid,n.metadata_storage_uuid,n.core_schema_oid,n.metadata_schema_oid,n.family_identity,n.implementation_fingerprint)
                 AND s.storage_uuid=i.storage_uuid) AS valid"),[family.namespace.clone().into(),implementation.clone().into()])).await?
            .ok_or_else(|| rejected("reader migration prior Q identity is missing"))?;
        if !identity.try_get::<bool>("", "valid")?
            || catalog(connection, core_oid, family.oid, 0).await? != family.catalog
            || shape(connection, family.oid, &family.namespace, &family.storage).await?
                != policy.try_get::<Vec<u8>>("", "expected_shape")?
        {
            return Err(rejected(
                "reader migration prior Q physical stamp or shape changed",
            ));
        }
    }
    let prior = template_shapes_with(
        connection,
        &core,
        core_oid,
        &implementation,
        publication_handoff_prior,
    )
    .await?;
    let recorded_shape: Vec<u8> = policy.try_get("", "expected_shape")?;
    if recorded_shape != prior.canonical
        && !(implementation == retention
            && family.is_none()
            && prior.legacy.as_ref() == Some(&recorded_shape))
    {
        return Err(rejected(
            "native runtime migration prior policy shape is not trusted",
        ));
    }
    if implementation == compiled || implementation == current {
        return Ok(());
    }

    let registration = include_str!("m20261008_000200_rooted_qualified_family.sql")
        .replace("$CORE_SCHEMA$", &c)
        .replace("$CORE_LITERAL$", &literal(&core))
        .replace("$IMPLEMENTATION_SHA$", &hex::encode(&current));
    connection
        .execute_unprepared(&trusted_function(
            &registration,
            "mst2_route_family_registration_guard",
        )?)
        .await?;

    let expected_shape = template_shapes(connection, &core, core_oid, &current)
        .await?
        .canonical;

    if let Some(family) = &family {
        let q = identifier(&family.schema);
        connection.execute_unprepared(&format!("LOCK TABLE {q}.mst2_metadata_reader_operation,{q}.mst2_metadata_root_anchor IN ACCESS EXCLUSIVE MODE")).await?;
        let rendered = if profile == InstallProfile::Native {
            render_prior_family(
                &core,
                core_oid,
                &family.schema,
                family.oid,
                &family.namespace,
                &family.storage,
                NATIVE_RUNTIME_IMPLEMENTATION,
            )?
        } else {
            render_family(
                &core,
                core_oid,
                &family.schema,
                family.oid,
                &family.namespace,
                &family.storage,
            )
        };
        let mut functions = String::new();
        let replacements: Vec<&str> = if profile == InstallProfile::PublicationHandoff {
            // Filled by the whole-family install below.
            Vec::new()
        } else if profile == InstallProfile::Descriptor {
            vec![
                "mst2_metadata_descriptor",
                "mst2_metadata_dml_barrier",
                "mst2_metadata_gc_enabled",
            ]
        } else if implementation == previous {
            vec![
                "mst2_metadata_decode_rooted_plan",
                "mst2_metadata_dml_barrier",
                "mst2_metadata_gc_enabled",
                "mst2_metadata_root_anchor_guard",
                "mst2_metadata_serving_complete",
                "mst2_metadata_next_reader_issuance",
                "mst2_metadata_reader_issuance_guard",
                "mst2_metadata_reader_guard",
                "mst2_metadata_prune_readers",
                "mst2_metadata_begin_reader",
                "mst2_metadata_finish_reader",
                "mst2_metadata_read_source_entries",
                "mst2_metadata_cleanup_expired",
                "mst2_metadata_gc_owner_cleanup",
            ]
        } else {
            vec![
                "mst2_metadata_decode_rooted_plan",
                "mst2_metadata_dml_barrier",
                "mst2_metadata_gc_enabled",
            ]
        };
        if profile == InstallProfile::PublicationHandoff {
            // The released family carries the prior implementation stamp inside every function
            // body, so only a whole-family install converges on the current compiled shape.
            functions = family_function_blocks(&rendered)?;
        } else {
            for name in replacements {
                functions.push_str(&trusted_function(&rendered, name)?);
                functions.push('\n');
            }
        }
        if implementation == previous {
            let upgrade = include_str!("m20261008_000400_reader_retention_upgrade.sql")
                .replace("$Q_SCHEMA$", &q)
                .replace("$READER_FUNCTIONS_SQL$", &functions);
            connection.execute_unprepared(&upgrade).await?;
        } else {
            connection
                .execute_unprepared(&format!("SET LOCAL search_path={q},pg_catalog,pg_temp"))
                .await?;
            connection.execute_unprepared(&functions).await?;
        }
        if shape(connection, family.oid, &family.namespace, &family.storage).await?
            != expected_shape
        {
            return Err(rejected(
                "reader migration upgraded Q differs from the trusted complete shape",
            ));
        }
        // Fail *after* the whole family was installed and verified, so the rollback test proves the
        // installed DDL is undone. The flag is a per-call argument, not process state, so parallel
        // test runs cannot inject it into an unrelated upgrade.
        #[cfg(test)]
        if fail_after_family_install {
            return Err(rejected("injected post-install family fault"));
        }
    }

    // Fingerprints include trigger identities/enabled state, but not table
    // values. Preserve trigger OIDs while writing only these controlled stamps.
    let authority = catalog(connection, core_oid, 0, q_oid).await?;
    let full = if q_oid == 0 {
        None
    } else {
        Some(catalog(connection, core_oid, q_oid, 0).await?)
    };
    connection.execute_unprepared(&format!("ALTER TABLE {c}.mst2_qualified_family_policy DISABLE TRIGGER mst2_route_family_policy_immutable")).await?;
    connection.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,format!(
        "UPDATE {c}.mst2_qualified_family_policy SET implementation_fingerprint=$1,expected_shape=$2,authority_catalog=$3 WHERE singleton=1"),
        [current.clone().into(),expected_shape.clone().into(),authority.clone().into()])).await?;
    connection.execute_unprepared(&format!("ALTER TABLE {c}.mst2_qualified_family_policy ENABLE TRIGGER mst2_route_family_policy_immutable")).await?;
    if let (Some(family), Some(full)) = (&family, &full) {
        let q = identifier(&family.schema);
        connection.execute_unprepared(&format!(
            "ALTER TABLE {q}.mst2_metadata_family_identity DISABLE TRIGGER mst2_00_family_barrier;
             ALTER TABLE {q}.mst2_metadata_family_identity DISABLE TRIGGER mst2_metadata_identity_immutable;
             ALTER TABLE {c}.mst2_metadata_namespace DISABLE TRIGGER mst2_00_route_statement_barrier;
             ALTER TABLE {c}.mst2_metadata_namespace DISABLE TRIGGER mst2_route_immutable")).await?;
        connection.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            format!("UPDATE {q}.mst2_metadata_family_identity SET implementation_fingerprint=$1 WHERE singleton=1"),[current.clone().into()])).await?;
        connection.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,format!(
            "UPDATE {c}.mst2_metadata_namespace SET implementation_fingerprint=$1,catalog_fingerprint=$2 WHERE namespace_uuid=$3::uuid"),
            [current.clone().into(),full.clone().into(),family.namespace.clone().into()])).await?;
        connection.execute_unprepared(&format!(
            "ALTER TABLE {q}.mst2_metadata_family_identity ENABLE TRIGGER mst2_00_family_barrier;
             ALTER TABLE {q}.mst2_metadata_family_identity ENABLE TRIGGER mst2_metadata_identity_immutable;
             ALTER TABLE {c}.mst2_metadata_namespace ENABLE TRIGGER mst2_00_route_statement_barrier;
             ALTER TABLE {c}.mst2_metadata_namespace ENABLE TRIGGER mst2_route_immutable")).await?;
    }
    connection
        .execute_unprepared(&format!("SET LOCAL search_path={c},pg_catalog,pg_temp"))
        .await?;
    if catalog(connection, core_oid, 0, q_oid).await? != authority {
        return Err(rejected(
            "reader migration final core authority catalog changed",
        ));
    }
    if let (Some(family), Some(full)) = (&family, &full)
        && (catalog(connection, core_oid, q_oid, 0).await? != *full
            || shape(connection, family.oid, &family.namespace, &family.storage).await?
                != expected_shape)
    {
        return Err(rejected("reader migration final Q fingerprint changed"));
    }
    Ok(())
}

#[cfg(test)]
mod publication_handoff_anchor {
    use super::*;
    use crate::jupiter::storage::qualified_metadata_family::{
        fingerprint_with_captured_prior_handoff, implementation_fingerprint,
    };

    /// The anchored landing stamp must be reproducible from the captured pre-FIX-OX-20 serving body
    /// and must differ from the current revision, so the migration cannot silently anchor itself.
    #[test]
    fn prior_landing_stamp_is_reproducible_from_the_capture() {
        let capture = include_str!("m20261009_000100_previous_publication_handoff_family.sql");
        assert_eq!(
            hex::encode(Sha256::digest(capture.as_bytes())),
            PUBLICATION_HANDOFF_CAPTURE,
            "the captured prior body changed"
        );
        let prior = fingerprint_with_captured_prior_handoff(capture)
            .expect("the serving revision must declare mst2_metadata_handoff");
        assert_eq!(
            hex::encode(prior),
            PUBLICATION_HANDOFF_PRIOR_IMPLEMENTATION,
            "the anchored prior stamp must match the recomputed pre-FIX-OX-20 fingerprint"
        );
        assert_ne!(
            prior.to_vec(),
            implementation_fingerprint(),
            "the prior stamp must differ from the current revision"
        );
    }
}
