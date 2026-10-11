CREATE FUNCTION mst2_metadata_handoff(request jsonb) RETURNS TABLE(lease_id text,expires_at_unix bigint)
LANGUAGE plpgsql VOLATILE SET search_path=$Q_SCHEMA$,pg_catalog,pg_temp AS $$
DECLARE sid text:=request->>'snapshot_id'; descriptor bytea:=decode(request->>'canonical_descriptor','hex');
  instance text:=request->>'instance_id'; commit_id text:=request->>'commit_oid'; tree_id text:=request->>'root_tree_oid';
  lid text:=request->>'lease_id'; inc uuid:=(request->>'session_incarnation')::uuid; pid text:=request->>'prepare_id';
  p record; s mst2_qualified_session_incarnation%ROWTYPE;
  a record; profile jsonb; now_unix bigint; deadline bigint;
BEGIN
  PERFORM $CORE_SCHEMA$.mst2_route_enter($CORE_LITERAL$);
  PERFORM mst2_metadata_cleanup_expired(64);
  now_unix:=floor(extract(epoch FROM clock_timestamp()))::bigint;
  deadline:=now_unix+least(3600,greatest(1,(request->>'lease_seconds')::bigint));
  IF request->>'authorization_epoch' IS DISTINCT FROM '1' OR lid IS NULL OR inc IS NULL OR descriptor IS NULL
    OR NOT mst2_metadata_publication_valid(instance,commit_id,tree_id,(request->>'publication_sequence')::bigint,
      (request->>'writer_epoch')::bigint,(request->>'certificate_receipt_id')::bigint,true) THEN
    RAISE EXCEPTION 'qualified handoff differs from the independently observed current publication'; END IF;
  SELECT * INTO s FROM mst2_qualified_session_incarnation WHERE snapshot_id=sid AND state='READY';
  IF FOUND THEN
    IF s.state<>'READY' OR s.canonical_descriptor IS DISTINCT FROM descriptor OR s.instance_id IS DISTINCT FROM instance
      OR s.commit_oid IS DISTINCT FROM commit_id OR s.root_tree_oid IS DISTINCT FROM tree_id
      OR ROW(s.publication_sequence,s.writer_epoch,s.certificate_receipt_id) IS DISTINCT FROM
        ROW((request->>'publication_sequence')::bigint,(request->>'writer_epoch')::bigint,(request->>'certificate_receipt_id')::bigint)
      OR NOT mst2_metadata_incarnation_proof(sid,s.session_incarnation,true) THEN
      RAISE EXCEPTION 'qualified handoff cannot revive or replace a historical incarnation'; END IF;
  ELSE
    SELECT metadata_root,storage_seal,source_domain,tagged_root_tree_oid,scope,schema_version,metadata_codec,
      materialization_policy,fs_semantics,access_projection,verification_revision,projection_revision
      INTO p FROM mst2_metadata_prepare WHERE prepare_id=pid AND state='COMMITTED' AND plan_kind='ROOTED'
      AND storage_seal=decode(request->>'storage_seal','hex') AND coverage_retired_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'qualified handoff has no exact definitive rooted receipt'; END IF;
    SELECT attestation_id,attestation_digest,root_generation,root_certificate_digest
      INTO a FROM mst2_metadata_source_root_attestation WHERE attestation_id=(request->>'attestation_id')::uuid
      AND attestation_digest=decode(request->>'attestation_digest','hex') AND root_page=p.metadata_root
      AND root_generation=(request->>'root_generation')::bigint AND root_certificate_digest=decode(request->>'certificate_digest','hex');
    IF NOT FOUND OR descriptor IS DISTINCT FROM mst2_metadata_descriptor(pid,instance,commit_id,tree_id)
      OR NOT mst2_metadata_serving_source(pid,a.attestation_id,p.metadata_root,a.root_generation,a.root_certificate_digest)
      OR NOT mst2_metadata_root_live(p.metadata_root,a.root_generation,a.root_certificate_digest)
      OR NOT EXISTS(SELECT 1 FROM mst2_metadata_root_anchor anchor WHERE anchor.anchor_kind='PREPARE'
        AND anchor.prepare_id=pid AND anchor.owner_key=pid AND anchor.root_page=p.metadata_root
        AND anchor.root_generation=a.root_generation AND anchor.root_certificate_digest=a.root_certificate_digest) THEN
      RAISE EXCEPTION 'qualified handoff lacks its continuously owned exact canonical source root'; END IF;
    profile:=$CORE_SCHEMA$.mst2_route_profile(p.source_domain,p.tagged_root_tree_oid,p.scope,p.schema_version,
      p.metadata_codec,p.materialization_policy,p.fs_semantics,p.access_projection,p.verification_revision,p.projection_revision);
    INSERT INTO $CORE_SCHEMA$.mst2_snapshot_storage_route(snapshot_id,namespace_uuid,canonical_descriptor,instance_id,
      commit_oid,root_tree_oid,metadata_root,source_profile)
      VALUES(sid,'$NAMESPACE_UUID$'::uuid,descriptor,instance,commit_id,tree_id,p.metadata_root,profile)
      ON CONFLICT(snapshot_id) DO NOTHING;
    INSERT INTO mst2_qualified_session_incarnation(snapshot_id,session_incarnation,namespace_uuid,prepare_id,storage_seal,
      metadata_root,root_generation,source_profile,instance_id,commit_oid,root_tree_oid,authorization_epoch,
      publication_sequence,writer_epoch,certificate_receipt_id,canonical_descriptor,attestation_id,attestation_digest,state)
      VALUES(sid,inc,'$NAMESPACE_UUID$'::uuid,pid,p.storage_seal,p.metadata_root,a.root_generation,convert_to(profile::text,'UTF8'),
        instance,commit_id,tree_id,1,(request->>'publication_sequence')::bigint,(request->>'writer_epoch')::bigint,
        (request->>'certificate_receipt_id')::bigint,descriptor,a.attestation_id,a.attestation_digest,'READY') RETURNING * INTO s;
    INSERT INTO mst2_metadata_root_anchor(anchor_id,anchor_kind,owner_key,root_page,root_generation,root_certificate_digest,
      snapshot_id,session_incarnation) VALUES(gen_random_uuid(),'SESSION',sid||':'||inc::text,
        s.metadata_root,s.root_generation,a.root_certificate_digest,sid,inc);
  END IF;
  SELECT root_certificate_digest INTO STRICT a FROM mst2_metadata_source_root_attestation WHERE attestation_id=s.attestation_id;
  INSERT INTO mst2_qualified_lease_binding(lease_id,snapshot_id,session_incarnation,prepare_id,storage_seal,metadata_root,
    root_generation,namespace_uuid,authorization_epoch,publication_sequence,writer_epoch,certificate_receipt_id,
    expires_at_unix,state,lease_epoch) VALUES(lid,sid,s.session_incarnation,s.prepare_id,s.storage_seal,s.metadata_root,
      s.root_generation,s.namespace_uuid,s.authorization_epoch,s.publication_sequence,s.writer_epoch,s.certificate_receipt_id,
      deadline,'ACTIVE',1);
  INSERT INTO $CORE_SCHEMA$.mst2_lease_storage_route(lease_id,snapshot_id,namespace_uuid,session_incarnation,prepare_id,
    metadata_root,authorization_epoch,publication_sequence,writer_epoch,certificate_receipt_id)
    VALUES(lid,sid,s.namespace_uuid,s.session_incarnation,s.prepare_id,s.metadata_root,s.authorization_epoch,
      s.publication_sequence,s.writer_epoch,s.certificate_receipt_id);
  INSERT INTO mst2_metadata_root_anchor(anchor_id,anchor_kind,owner_key,root_page,root_generation,root_certificate_digest,
    snapshot_id,session_incarnation,lease_id) VALUES(gen_random_uuid(),'LEASE',lid,s.metadata_root,s.root_generation,
      a.root_certificate_digest,sid,s.session_incarnation,lid);
  IF pid IS NOT NULL THEN
    SELECT coverage_retired_at INTO p FROM mst2_metadata_prepare WHERE prepare_id=pid AND state='COMMITTED' AND plan_kind='ROOTED'
      AND storage_seal=decode(request->>'storage_seal','hex') AND metadata_root=s.metadata_root;
    IF NOT FOUND OR s.root_generation IS DISTINCT FROM (request->>'root_generation')::bigint
      OR a.root_certificate_digest IS DISTINCT FROM decode(request->>'certificate_digest','hex')
      OR descriptor IS DISTINCT FROM mst2_metadata_descriptor(pid,instance,commit_id,tree_id)
      OR NOT mst2_metadata_session_covers_prepare(pid)
      OR NOT EXISTS(SELECT 1 FROM mst2_metadata_source_root_attestation receipt
        WHERE receipt.attestation_id=(request->>'attestation_id')::uuid
          AND receipt.attestation_digest=decode(request->>'attestation_digest','hex')
          AND receipt.root_page=s.metadata_root AND receipt.root_generation=s.root_generation
          AND receipt.root_certificate_digest=a.root_certificate_digest
          AND mst2_metadata_serving_source(pid,receipt.attestation_id,s.metadata_root,s.root_generation,a.root_certificate_digest)) THEN
      RAISE EXCEPTION 'qualified losing preparation cannot retire a different serving identity'; END IF;
    IF p.coverage_retired_at IS NULL THEN
      UPDATE mst2_metadata_prepare SET coverage_retired_at=clock_timestamp() WHERE prepare_id=pid;
      DELETE FROM mst2_metadata_root_anchor WHERE prepare_id=pid AND anchor_kind IN ('PREPARE','REUSE');
    END IF;
  END IF;
  RETURN QUERY SELECT lid,deadline;
END $$;