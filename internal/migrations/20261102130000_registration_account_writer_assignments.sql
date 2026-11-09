-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1031: persistent identity of explicit installation assignments.
-- No FK to access_bindings: deleting a binding must not erase revocation history.
-- Приёмка: docs/engineering/acceptance/account-scoped-registration-writer.md
-- §4/§5.5: стабильная identity назначения, сохранённый отзыв и безопасный upgrade/rollback.
-- +goose Up
CREATE TABLE kaname.registration_account_writer_assignment (
 assignment_id text PRIMARY KEY CHECK (assignment_id <> ''),
 account_id text NOT NULL,
 module text NOT NULL,
 binding_id text NOT NULL UNIQUE,
 applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 removed_at timestamptz,
 UNIQUE (assignment_id, account_id, module)
);
CREATE TABLE kaname.registration_account_writer_switch (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 switched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 disabled_modules jsonb NOT NULL DEFAULT '[]'::jsonb,
 cluster_writer_retired_at timestamptz
);
-- Canonical authority is separate from optional request claims. Retention
-- permits authorized idempotent cleanup without restoring any tuple or grant.
CREATE TABLE kaname.resource_registration_scope (
 object_type text NOT NULL,
 object_id text NOT NULL,
 project_id text NOT NULL,
 account_id text NOT NULL,
 PRIMARY KEY(object_type,object_id,project_id,account_id)
);
-- Canonical upgrade reader follows only admitted pointer names and subject
-- types from the catalog, and only through registered containers. A saved
-- container project wins over its pointer facts, exactly as in #982. Cycles
-- stop without choosing an account; unresolved rows remain unresolved.
-- +goose StatementBegin
CREATE FUNCTION kaname.registration_legacy_scopes(p_type text,p_id text)
RETURNS TABLE(project_id text,account_id text)
LANGUAGE sql STABLE SET search_path=pg_catalog,kaname AS $$
 WITH RECURSIVE walk(typ,id,visited) AS (
  SELECT p_type,p_id,ARRAY[p_type || ':' || p_id]
  UNION ALL
  SELECT n.typ,n.id,w.visited || (n.typ || ':' || n.id)
  FROM walk w
  JOIN LATERAL (SELECT c.* FROM kaname.catalog_resource c WHERE c.object_type=w.typ ORDER BY c.live DESC LIMIT 1) c ON true
  JOIN kaname.resource_mirror m ON m.object_type=c.dotted AND m.object_id=w.id
  CROSS JOIN LATERAL (
   SELECT coalesce(nullif(m.parent_project_id,''),
    (SELECT e.parent_id FROM kaname.resource_parent_edge e WHERE e.object_type=w.typ AND e.object_id=w.id AND e.parent_type='project' ORDER BY e.depth LIMIT 1),
    (SELECT b.project_id FROM kaname.object_project_binding b WHERE b.object_type=w.typ AND b.object_id=w.id)) AS project
  ) saved
  CROSS JOIN LATERAL (
   SELECT 'project'::text AS typ,saved.project AS id WHERE saved.project IS NOT NULL
   UNION
   SELECT 'project',s.project_id FROM kaname.resource_registration_scope s
    WHERE saved.project IS NULL AND s.object_type=w.typ AND s.object_id=w.id
   UNION
   SELECT split_part(f.subject,':',1),substr(f.subject,strpos(f.subject,':')+1)
    FROM kaname.relation_fact f
    JOIN unnest(c.parent_names,c.parent_types) AS ptr(name,typ) ON ptr.name=f.relation AND ptr.typ=split_part(f.subject,':',1)
    WHERE saved.project IS NULL AND NOT EXISTS(SELECT 1 FROM kaname.resource_registration_scope s WHERE s.object_type=w.typ AND s.object_id=w.id)
      AND f.object_type=w.typ AND f.object_id=w.id
  ) n
  WHERE n.id IS NOT NULL AND n.id<>'' AND NOT (n.typ || ':' || n.id)=ANY(w.visited)
 )
 SELECT DISTINCT p.id,p.account_id FROM walk w JOIN kaname.projects p ON w.typ='project' AND p.id=w.id
$$;
-- +goose StatementEnd

-- Preserve canonical authority for legal pre-1031 omitted claims. No client
-- field/edge is fabricated and no account writer grant is inferred from it.
INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
 SELECT c.object_type,m.object_id,s.project_id,s.account_id
 FROM kaname.resource_mirror m JOIN kaname.catalog_resource c ON c.dotted=m.object_type
 CROSS JOIN LATERAL kaname.registration_legacy_scopes(c.object_type,m.object_id) s
 ON CONFLICT DO NOTHING;

-- Immutable installation lineage, not a lookup by mutable/non-global name.
-- Provenance: 0001_initial.sql:3489 owns this group in this account;
-- :3196/:3176/:3162 bind acb9e920fb038c7e4f74 and its emitted writer tuple
-- to that group. 20260906214500 migrates its cluster coordinate through the
-- canonical cluster_anchor(). Names may change before or after this migration.
-- No FK: deletion must not erase the lineage that fences a future legacy seed.
CREATE TABLE kaname.registration_legacy_cluster_writer_identity (
 singleton boolean PRIMARY KEY CHECK(singleton),
 account_id text NOT NULL,
 group_id text NOT NULL,
 cluster_id text NOT NULL,
 original_binding_id text NOT NULL,
 original_seed_name text NOT NULL,
 granted_relation text NOT NULL
);
INSERT INTO kaname.registration_legacy_cluster_writer_identity
 (singleton,account_id,group_id,cluster_id,original_binding_id,original_seed_name,granted_relation)
 VALUES(true,'acc1a18042d81fb438d6','grp258e6bbe9bbe45568',kaname.cluster_anchor(),'acb9e920fb038c7e4f74','module-relation-writers','fga_writer');

-- One predicate for initial selection, locked recheck and INSERT/UPDATE fence.
-- original_binding_id records the proven assignment lineage; later row IDs of
-- the SAME immutable assignment must also be fenced against resurrection.
-- +goose StatementBegin
CREATE FUNCTION kaname.registration_owns_legacy_cluster_writer(b kaname.access_bindings)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,kaname AS $$
 SELECT coalesce((b).is_system AND (b).subject_type='group'
   AND (b).resource_type='cluster' AND (b).role_id IS NULL
   AND EXISTS(
    SELECT 1 FROM kaname.registration_legacy_cluster_writer_identity i
    JOIN kaname.groups g ON g.id=i.group_id AND g.account_id=i.account_id
    WHERE i.singleton AND (b).subject_id=i.group_id
      AND (b).resource_id=i.cluster_id AND (b).granted_relation=i.granted_relation),false)
$$;
-- +goose StatementEnd

-- A binary rollback must not let its old seed writer resurrect the retired
-- blanket. This narrow schema guard covers that old writer too; account
-- assignments and unrelated cluster system grants are unaffected.
-- +goose StatementBegin
CREATE FUNCTION kaname.registration_cluster_writer_retirement_holds() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kaname AS $$
BEGIN
 IF NEW.status='ACTIVE' AND kaname.registration_owns_legacy_cluster_writer(NEW) THEN
  -- Coordinate even before retirement: a concurrent old grant must commit
  -- before the retirement census, or wait and observe the committed fence.
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('kaname.registration_legacy_writer_seed',0));
  IF EXISTS(SELECT 1 FROM kaname.registration_account_writer_switch WHERE cluster_writer_retired_at IS NOT NULL) THEN
   RAISE EXCEPTION 'legacy registration cluster writer is retired'
    USING ERRCODE='integrity_constraint_violation',CONSTRAINT='registration_cluster_writer_retired';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER registration_cluster_writer_retirement_holds
 BEFORE INSERT OR UPDATE OF status,revoked_at,is_system,subject_type,subject_id,resource_type,resource_id,granted_relation,role_id ON kaname.access_bindings
 FOR EACH ROW EXECUTE FUNCTION kaname.registration_cluster_writer_retirement_holds();

-- The old own-manifest lifecycle first UPSERTs its group by (account,name),
-- minting a new random ID after rename/deletion, then grants its blanket in
-- that same transaction. Fence that exact installation seed namespace too.
-- It is NOT retirement ownership: no foreign group is adopted or revoked.
-- Tenant groups with the same name and other installation group names remain
-- unaffected. An old binary may fail startup; rollback ingress stays CLOSED.
-- +goose StatementBegin
CREATE FUNCTION kaname.registration_retired_legacy_seed_namespace_holds() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kaname AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM kaname.registration_legacy_cluster_writer_identity i
           WHERE i.singleton AND NEW.account_id=i.account_id AND NEW.name=i.original_seed_name) THEN
  -- Held across the entire old seed transaction (UpsertGroup AND GrantRelation).
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('kaname.registration_legacy_writer_seed',0));
  IF EXISTS(SELECT 1 FROM kaname.registration_account_writer_switch WHERE cluster_writer_retired_at IS NOT NULL) THEN
   RAISE EXCEPTION 'legacy registration writer seed namespace is retired'
    USING ERRCODE='integrity_constraint_violation',CONSTRAINT='registration_legacy_seed_namespace_retired';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER registration_retired_legacy_seed_namespace_holds
 BEFORE INSERT OR UPDATE OF account_id,name ON kaname.groups
 FOR EACH ROW EXECUTE FUNCTION kaname.registration_retired_legacy_seed_namespace_holds();

-- The historical blanket remains until the explicit operator confirms that
-- ingress serves only account-enforcing replicas; its emitted-set retirement
-- runs through the guarded binding lifecycle in the installation writer.

-- +goose Down
-- Failing the down keeps both data and migration bookkeeping unchanged.
-- Supported rollback is binary-only with registration ingress CLOSED.
-- +goose StatementBegin
DO $$ BEGIN
 RAISE EXCEPTION 'registration account writer history is irreversible; use binary-only rollback with registration ingress closed';
END $$;
-- +goose StatementEnd
