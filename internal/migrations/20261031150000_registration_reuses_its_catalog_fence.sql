-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- САНКЦИЯ: docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md
-- kaname#983: full xid8 witness, never a historical heap xmin or a client permit.
-- Every mint physically fences its exact catalog PK under the original invoker.
-- +goose Up

CREATE TABLE kaname.registration_catalog_fence (
    catalog_module text NOT NULL,
    catalog_resource text NOT NULL,
    fence_xid xid8 NOT NULL,
    PRIMARY KEY (catalog_module, catalog_resource)
);
REVOKE ALL ON kaname.registration_catalog_fence FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION kaname.registration_catalog_fence_mint() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, kaname AS $$
DECLARE
    v_count bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.catalog_module IS DISTINCT FROM OLD.catalog_module OR
           NEW.catalog_resource IS DISTINCT FROM OLD.catalog_resource THEN
            RAISE EXCEPTION 'catalog fence identity cannot be moved'
                USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_catalog_fence_identity';
        END IF;
    END IF;
    -- Unconditional even for direct DML/COPY, a supplied current xid, or a nested
    -- trigger. Ordinary invoker UPDATE privileges and RR conflicts apply here.
    UPDATE kaname.catalog_resource cr
       SET project_bindings_held = cr.project_bindings_held
     WHERE cr.module = NEW.catalog_module AND cr.resource = NEW.catalog_resource;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count <> 1 THEN
        RAISE EXCEPTION 'catalog fence identity does not exist'
            USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'registration_catalog_fence_catalog_identity';
    END IF;
    NEW.fence_xid := pg_current_xact_id();
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.registration_catalog_fence_ensure(p_module text, p_resource text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, kaname AS $$
BEGIN
    -- Recheck authority after SET ROLE/revocation. A marker is not a grant.
    IF has_column_privilege(current_user, 'kaname.catalog_resource', 'project_bindings_held', 'UPDATE')
       AND EXISTS (SELECT 1 FROM kaname.registration_catalog_fence w
                    WHERE w.catalog_module = p_module AND w.catalog_resource = p_resource
                      AND w.fence_xid = pg_current_xact_id()) THEN
        RETURN;
    END IF;
    -- The unchanged global statement fence serializes miss paths. Avoid UPSERT's
    -- double BEFORE firing: one UPDATE miss followed by one INSERT mints once.
    UPDATE kaname.registration_catalog_fence w SET fence_xid = pg_current_xact_id()
     WHERE w.catalog_module = p_module AND w.catalog_resource = p_resource;
    IF NOT FOUND THEN
        INSERT INTO kaname.registration_catalog_fence(catalog_module, catalog_resource, fence_xid)
        VALUES (p_module, p_resource, pg_current_xact_id());
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.registration_catalog_fence_forget() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, kaname AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        DELETE FROM kaname.registration_catalog_fence;
    ELSIF TG_OP = 'INSERT' THEN
        DELETE FROM kaname.registration_catalog_fence
         WHERE catalog_module = NEW.module AND catalog_resource = NEW.resource;
    ELSIF TG_OP = 'DELETE' THEN
        DELETE FROM kaname.registration_catalog_fence
         WHERE catalog_module = OLD.module AND catalog_resource = OLD.resource;
    ELSE
        DELETE FROM kaname.registration_catalog_fence
         WHERE (catalog_module = OLD.module AND catalog_resource = OLD.resource)
            OR (catalog_module = NEW.module AND catalog_resource = NEW.resource);
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.registration_catalog_fence_refuses_truncate() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, kaname AS $$
BEGIN
    RAISE EXCEPTION 'catalog fence metadata cannot be truncated directly'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_catalog_fence_no_truncate';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER resource_registration_locks_writers
    BEFORE INSERT OR UPDATE OR DELETE ON kaname.registration_catalog_fence
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.resource_registration_locks_writers();
CREATE TRIGGER registration_catalog_fence_mint
    BEFORE INSERT OR UPDATE ON kaname.registration_catalog_fence
    FOR EACH ROW EXECUTE FUNCTION kaname.registration_catalog_fence_mint();
CREATE TRIGGER registration_catalog_fence_no_truncate
    BEFORE TRUNCATE ON kaname.registration_catalog_fence
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.registration_catalog_fence_refuses_truncate();
CREATE TRIGGER registration_catalog_fence_forget_row
    AFTER INSERT OR DELETE ON kaname.catalog_resource
    FOR EACH ROW EXECUTE FUNCTION kaname.registration_catalog_fence_forget();
CREATE TRIGGER registration_catalog_fence_forget_identity
    AFTER UPDATE ON kaname.catalog_resource
    FOR EACH ROW WHEN (OLD.module IS DISTINCT FROM NEW.module OR OLD.resource IS DISTINCT FROM NEW.resource)
    EXECUTE FUNCTION kaname.registration_catalog_fence_forget();
CREATE TRIGGER registration_catalog_fence_forget_all
    AFTER TRUNCATE ON kaname.catalog_resource
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.registration_catalog_fence_forget();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_registration_command_apply() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, kaname AS $$
DECLARE
    v_declared boolean;
    v_held boolean;
    v_bound text;
    v_chain text[] := ARRAY[]::text[];
    v_link text;
    v_type text;
    v_id text;
    v_count bigint;
    v_locked boolean;
    v_catalog record;
BEGIN
    IF pg_trigger_depth() <> 1 THEN
        RAISE EXCEPTION 'registration command requires a direct entry'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'resource_registration_command_direct_entry';
    END IF;
    -- Outputs are exclusively DB decisions, never input authority.
    NEW.type_live := false;
    NEW.model_type := NULL;
    NEW.applied := false;
    NEW.projection_unchanged := false;
    NEW.labels := coalesce(NEW.labels, '{}'::jsonb);
    NEW.parent_chain := coalesce(NEW.parent_chain, ARRAY[]::text[]);

    -- kaname#874: the comparison below is a DIFFERENT SPI statement/snapshot after
    -- this lock has waited. VOLATILE is required; do not combine into one CTE.
    PERFORM 1 FROM kaname.resource_mirror m
     WHERE m.object_type = NEW.dotted_type AND m.object_id = NEW.object_id
       FOR NO KEY UPDATE;
    v_locked := FOUND;
    -- A real tuple write is the RR conflict gate: a stale transaction must
    -- serialize/retry, not validate an invisible binding or edge as absent.
    -- The non-key assignment preserves every logical catalog column. The held
    -- flag callback preserves its value; UPDATE OF permanent_project backfill
    -- does not run. No additional binding lookup or stored witness is needed.
    FOR v_catalog IN SELECT cr.module, cr.resource FROM kaname.catalog_resource cr
        WHERE cr.dotted = NEW.dotted_type AND cr.live ORDER BY cr.module, cr.resource
    LOOP
        PERFORM kaname.registration_catalog_fence_ensure(v_catalog.module, v_catalog.resource);
    END LOOP;
    SELECT cr.object_type, cr.permanent_project,
           cr.permanent_project OR cr.project_bindings_held
      INTO NEW.model_type, v_declared, v_held
      FROM kaname.catalog_resource cr
     WHERE cr.dotted = NEW.dotted_type AND cr.live;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    NEW.type_live := true;

    FOREACH v_link IN ARRAY NEW.parent_chain LOOP
        IF v_link IS NULL OR strpos(v_link, ':') <= 1
           OR strpos(v_link, ':') = length(v_link) THEN
            RAISE EXCEPTION 'invalid registration parent reference'
                USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_parent_reference_form';
        END IF;
        v_type := split_part(v_link, ':', 1);
        v_id := substr(v_link, strpos(v_link, ':') + 1);
        IF strpos(v_type, '.') > 0 THEN
            SELECT cr.object_type INTO v_type FROM kaname.catalog_resource cr
             WHERE cr.dotted = split_part(v_link, ':', 1);
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown registration parent type'
                    USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_parent_type_known';
            END IF;
        END IF;
        v_chain := array_append(v_chain, v_type || ':' || v_id);
    END LOOP;

    -- Mirror first, binding second for EVERY writer, including raw UPSERT.
    -- These writes are provisional: the complete validation below is mandatory
    -- even for stale/no-op, and any refusal rolls back this entire statement.
    UPDATE kaname.resource_mirror m
       SET source_version = NEW.source_version, updated_at = now()
     WHERE v_locked AND m.object_type = NEW.dotted_type AND m.object_id = NEW.object_id
       AND m.parent_project_id = NEW.parent_project_id
       AND m.parent_account_id = NEW.parent_account_id
       AND m.labels = NEW.labels AND m.source_version < NEW.source_version
       AND v_chain = ARRAY(SELECT pe.parent_type || ':' || pe.parent_id
                            FROM kaname.resource_parent_edge pe
                           WHERE pe.object_type = NEW.model_type AND pe.object_id = NEW.object_id
                           ORDER BY pe.depth);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    NEW.applied := v_count > 0;
    NEW.projection_unchanged := NEW.applied;
    IF NOT NEW.applied THEN
        INSERT INTO kaname.resource_mirror
            (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
        VALUES (NEW.dotted_type, NEW.object_id, NEW.parent_project_id, NEW.parent_account_id,
                NEW.labels, NEW.source_version, now())
        ON CONFLICT (object_type, object_id) DO UPDATE
            SET parent_project_id = EXCLUDED.parent_project_id,
                parent_account_id = EXCLUDED.parent_account_id,
                labels = EXCLUDED.labels, source_version = EXCLUDED.source_version, updated_at = now()
          WHERE resource_mirror.source_version < EXCLUDED.source_version;
        GET DIAGNOSTICS v_count = ROW_COUNT;
        NEW.applied := v_count > 0;
    END IF;

    IF v_held THEN
        -- A stale request must never establish the first binding. A concurrent
        -- insert won the mirror lock first; this effective write now serializes
        -- on that same row before touching the binding unique index.
        IF NEW.applied AND v_declared AND NEW.parent_project_id <> '' THEN
            INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
            VALUES (NEW.model_type, NEW.object_id, NEW.parent_project_id)
            ON CONFLICT (object_type, object_id) DO NOTHING;
        END IF;
        -- The ONLY binding lookup on the complete command path, fresh after
        -- conflict wait. Every project link is compared with this local value.
        SELECT b.project_id INTO v_bound FROM kaname.object_project_binding b
         WHERE b.object_type = NEW.model_type AND b.object_id = NEW.object_id;
        IF v_bound IS NULL AND v_declared AND NEW.parent_project_id <> '' THEN
            v_bound := NEW.parent_project_id;
        END IF;
        IF v_bound IS NOT NULL AND
           (NEW.parent_project_id IS DISTINCT FROM v_bound OR EXISTS (
               SELECT 1 FROM unnest(v_chain) AS l(link)
                WHERE split_part(l.link, ':', 1) = 'project'
                  AND substr(l.link, strpos(l.link, ':') + 1) <> v_bound)) THEN
            RAISE EXCEPTION 'object %:% is bound to another project', NEW.model_type, NEW.object_id
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'object_project_binding_holds',
                      TABLE = 'resource_mirror', SCHEMA = 'kaname';
        END IF;
    END IF;
    IF NEW.applied AND NOT NEW.projection_unchanged THEN
        DELETE FROM kaname.resource_parent_edge pe
         WHERE pe.object_type = NEW.model_type AND pe.object_id = NEW.object_id;
        INSERT INTO kaname.resource_parent_edge
            (object_type, object_id, parent_type, parent_id, depth, source_version, updated_at)
        SELECT NEW.model_type, NEW.object_id, split_part(l.link, ':', 1),
               substr(l.link, strpos(l.link, ':') + 1), l.n, NEW.source_version, now()
          FROM unnest(v_chain) WITH ORDINALITY AS l(link, n);
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_mirror_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, kaname
    AS $$
DECLARE
    v_model_type text;
    v_declared   boolean;
    v_held       boolean;
    v_new_binding boolean := false;
    v_raw_chain text[] := ARRAY[]::text[];
    v_catalog record;
BEGIN
    -- Only the direct complete-command trigger writes these tables at depth 2.
    -- This relies on the closed installed trigger/callback graph, not depth
    -- alone. Binding permanence guards NEVER take this branch.
    IF pg_trigger_depth() = 2 THEN
        RETURN NEW;
    END IF;
    IF TG_WHEN = 'BEFORE' THEN
        -- Same RR conflict gate as the complete command, before raw mutation.
        -- SQLSTATE 40001 propagates unchanged; it is not an integrity verdict.
        FOR v_catalog IN SELECT cr.module, cr.resource FROM kaname.catalog_resource cr
            WHERE cr.dotted = NEW.object_type ORDER BY cr.module, cr.resource
        LOOP
            PERFORM kaname.registration_catalog_fence_ensure(v_catalog.module, v_catalog.resource);
        END LOOP;
        SELECT cr.object_type, cr.permanent_project AND cr.live,
               cr.permanent_project OR cr.project_bindings_held
          INTO v_model_type, v_declared, v_held
          FROM kaname.catalog_resource cr WHERE cr.dotted = NEW.object_type;
    ELSE
        -- AFTER uses the catalog tuple already written by this raw statement.
        SELECT cr.object_type, cr.permanent_project AND cr.live, cr.permanent_project OR cr.project_bindings_held
          INTO v_model_type, v_declared, v_held
          FROM kaname.catalog_resource cr
         WHERE cr.dotted = NEW.object_type;
    END IF;
    IF NOT FOUND OR NOT v_held THEN
        RETURN NEW;
    END IF;
    IF TG_WHEN = 'AFTER' AND v_declared AND NEW.parent_project_id <> '' THEN
        INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
        VALUES (v_model_type, NEW.object_id, NEW.parent_project_id)
        ON CONFLICT (object_type, object_id) DO NOTHING;
        v_new_binding := FOUND;
    END IF;
    IF v_new_binding THEN
        SELECT coalesce(array_agg(pe.parent_type || ':' || pe.parent_id), ARRAY[]::text[])
          INTO v_raw_chain FROM kaname.resource_parent_edge pe
         WHERE pe.object_type = v_model_type AND pe.object_id = NEW.object_id;
    END IF;
    IF kaname.object_project_binding_refuses(v_model_type, NEW.object_id, NEW.parent_project_id, v_raw_chain) THEN
        RAISE EXCEPTION 'object %:% is bound to another project', v_model_type, NEW.object_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'object_project_binding_holds',
                  TABLE = 'resource_mirror',
                  SCHEMA = 'kaname';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_parent_edge_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, kaname
    AS $$
DECLARE
    v_catalog record;
BEGIN
    IF pg_trigger_depth() = 2 THEN
        RETURN NEW;
    END IF;
    -- Raw project edges participate in the same real write-conflict gate.
    -- This also protects the reverse RR schedule: an edge committed after the
    -- first-binding writer's snapshot makes that writer serialize/retry.
    FOR v_catalog IN SELECT cr.module, cr.resource FROM kaname.catalog_resource cr
        WHERE cr.object_type = NEW.object_type ORDER BY cr.module, cr.resource
    LOOP
        PERFORM kaname.registration_catalog_fence_ensure(v_catalog.module, v_catalog.resource);
    END LOOP;
    IF kaname.object_project_binding_refuses(NEW.object_type, NEW.object_id, NULL,
                                             ARRAY[NEW.parent_type || ':' || NEW.parent_id]) THEN
        RAISE EXCEPTION 'object %:% is bound to another project', NEW.object_type, NEW.object_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'object_project_binding_holds',
                  TABLE = 'resource_parent_edge',
                  SCHEMA = 'kaname';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose Down

-- Restore safe physical fences before removing optimization metadata.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_registration_command_apply() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, kaname AS $$
DECLARE
    v_declared boolean;
    v_held boolean;
    v_bound text;
    v_chain text[] := ARRAY[]::text[];
    v_link text;
    v_type text;
    v_id text;
    v_count bigint;
    v_locked boolean;
BEGIN
    IF pg_trigger_depth() <> 1 THEN
        RAISE EXCEPTION 'registration command requires a direct entry'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'resource_registration_command_direct_entry';
    END IF;
    -- Outputs are exclusively DB decisions, never input authority.
    NEW.type_live := false;
    NEW.model_type := NULL;
    NEW.applied := false;
    NEW.projection_unchanged := false;
    NEW.labels := coalesce(NEW.labels, '{}'::jsonb);
    NEW.parent_chain := coalesce(NEW.parent_chain, ARRAY[]::text[]);

    -- kaname#874: the comparison below is a DIFFERENT SPI statement/snapshot after
    -- this lock has waited. VOLATILE is required; do not combine into one CTE.
    PERFORM 1 FROM kaname.resource_mirror m
     WHERE m.object_type = NEW.dotted_type AND m.object_id = NEW.object_id
       FOR NO KEY UPDATE;
    v_locked := FOUND;
    -- A real tuple write is the RR conflict gate: a stale transaction must
    -- serialize/retry, not validate an invisible binding or edge as absent.
    -- The non-key assignment preserves every logical catalog column. The held
    -- flag callback preserves its value; UPDATE OF permanent_project backfill
    -- does not run. No additional binding lookup or stored witness is needed.
    UPDATE kaname.catalog_resource cr
       SET project_bindings_held = cr.project_bindings_held
     WHERE cr.dotted = NEW.dotted_type AND cr.live
     RETURNING cr.object_type, cr.permanent_project,
               cr.permanent_project OR cr.project_bindings_held
          INTO NEW.model_type, v_declared, v_held;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    NEW.type_live := true;

    FOREACH v_link IN ARRAY NEW.parent_chain LOOP
        IF v_link IS NULL OR strpos(v_link, ':') <= 1
           OR strpos(v_link, ':') = length(v_link) THEN
            RAISE EXCEPTION 'invalid registration parent reference'
                USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_parent_reference_form';
        END IF;
        v_type := split_part(v_link, ':', 1);
        v_id := substr(v_link, strpos(v_link, ':') + 1);
        IF strpos(v_type, '.') > 0 THEN
            SELECT cr.object_type INTO v_type FROM kaname.catalog_resource cr
             WHERE cr.dotted = split_part(v_link, ':', 1);
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown registration parent type'
                    USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_parent_type_known';
            END IF;
        END IF;
        v_chain := array_append(v_chain, v_type || ':' || v_id);
    END LOOP;

    -- Mirror first, binding second for EVERY writer, including raw UPSERT.
    -- These writes are provisional: the complete validation below is mandatory
    -- even for stale/no-op, and any refusal rolls back this entire statement.
    UPDATE kaname.resource_mirror m
       SET source_version = NEW.source_version, updated_at = now()
     WHERE v_locked AND m.object_type = NEW.dotted_type AND m.object_id = NEW.object_id
       AND m.parent_project_id = NEW.parent_project_id
       AND m.parent_account_id = NEW.parent_account_id
       AND m.labels = NEW.labels AND m.source_version < NEW.source_version
       AND v_chain = ARRAY(SELECT pe.parent_type || ':' || pe.parent_id
                            FROM kaname.resource_parent_edge pe
                           WHERE pe.object_type = NEW.model_type AND pe.object_id = NEW.object_id
                           ORDER BY pe.depth);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    NEW.applied := v_count > 0;
    NEW.projection_unchanged := NEW.applied;
    IF NOT NEW.applied THEN
        INSERT INTO kaname.resource_mirror
            (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
        VALUES (NEW.dotted_type, NEW.object_id, NEW.parent_project_id, NEW.parent_account_id,
                NEW.labels, NEW.source_version, now())
        ON CONFLICT (object_type, object_id) DO UPDATE
            SET parent_project_id = EXCLUDED.parent_project_id,
                parent_account_id = EXCLUDED.parent_account_id,
                labels = EXCLUDED.labels, source_version = EXCLUDED.source_version, updated_at = now()
          WHERE resource_mirror.source_version < EXCLUDED.source_version;
        GET DIAGNOSTICS v_count = ROW_COUNT;
        NEW.applied := v_count > 0;
    END IF;

    IF v_held THEN
        -- A stale request must never establish the first binding. A concurrent
        -- insert won the mirror lock first; this effective write now serializes
        -- on that same row before touching the binding unique index.
        IF NEW.applied AND v_declared AND NEW.parent_project_id <> '' THEN
            INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
            VALUES (NEW.model_type, NEW.object_id, NEW.parent_project_id)
            ON CONFLICT (object_type, object_id) DO NOTHING;
        END IF;
        -- The ONLY binding lookup on the complete command path, fresh after
        -- conflict wait. Every project link is compared with this local value.
        SELECT b.project_id INTO v_bound FROM kaname.object_project_binding b
         WHERE b.object_type = NEW.model_type AND b.object_id = NEW.object_id;
        IF v_bound IS NULL AND v_declared AND NEW.parent_project_id <> '' THEN
            v_bound := NEW.parent_project_id;
        END IF;
        IF v_bound IS NOT NULL AND
           (NEW.parent_project_id IS DISTINCT FROM v_bound OR EXISTS (
               SELECT 1 FROM unnest(v_chain) AS l(link)
                WHERE split_part(l.link, ':', 1) = 'project'
                  AND substr(l.link, strpos(l.link, ':') + 1) <> v_bound)) THEN
            RAISE EXCEPTION 'object %:% is bound to another project', NEW.model_type, NEW.object_id
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'object_project_binding_holds',
                      TABLE = 'resource_mirror', SCHEMA = 'kaname';
        END IF;
    END IF;
    IF NEW.applied AND NOT NEW.projection_unchanged THEN
        DELETE FROM kaname.resource_parent_edge pe
         WHERE pe.object_type = NEW.model_type AND pe.object_id = NEW.object_id;
        INSERT INTO kaname.resource_parent_edge
            (object_type, object_id, parent_type, parent_id, depth, source_version, updated_at)
        SELECT NEW.model_type, NEW.object_id, split_part(l.link, ':', 1),
               substr(l.link, strpos(l.link, ':') + 1), l.n, NEW.source_version, now()
          FROM unnest(v_chain) WITH ORDINALITY AS l(link, n);
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_mirror_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, kaname
    AS $$
DECLARE
    v_model_type text;
    v_declared   boolean;
    v_held       boolean;
    v_new_binding boolean := false;
    v_raw_chain text[] := ARRAY[]::text[];
BEGIN
    -- Only the direct complete-command trigger writes these tables at depth 2.
    -- This relies on the closed installed trigger/callback graph, not depth
    -- alone. Binding permanence guards NEVER take this branch.
    IF pg_trigger_depth() = 2 THEN
        RETURN NEW;
    END IF;
    IF TG_WHEN = 'BEFORE' THEN
        -- Same RR conflict gate as the complete command, before raw mutation.
        -- SQLSTATE 40001 propagates unchanged; it is not an integrity verdict.
        UPDATE kaname.catalog_resource cr
           SET project_bindings_held = cr.project_bindings_held
         WHERE cr.dotted = NEW.object_type
         RETURNING cr.object_type, cr.permanent_project AND cr.live,
                   cr.permanent_project OR cr.project_bindings_held
              INTO v_model_type, v_declared, v_held;
    ELSE
        -- AFTER uses the catalog tuple already written by this raw statement.
        SELECT cr.object_type, cr.permanent_project AND cr.live, cr.permanent_project OR cr.project_bindings_held
          INTO v_model_type, v_declared, v_held
          FROM kaname.catalog_resource cr
         WHERE cr.dotted = NEW.object_type;
    END IF;
    IF NOT FOUND OR NOT v_held THEN
        RETURN NEW;
    END IF;
    IF TG_WHEN = 'AFTER' AND v_declared AND NEW.parent_project_id <> '' THEN
        INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
        VALUES (v_model_type, NEW.object_id, NEW.parent_project_id)
        ON CONFLICT (object_type, object_id) DO NOTHING;
        v_new_binding := FOUND;
    END IF;
    IF v_new_binding THEN
        SELECT coalesce(array_agg(pe.parent_type || ':' || pe.parent_id), ARRAY[]::text[])
          INTO v_raw_chain FROM kaname.resource_parent_edge pe
         WHERE pe.object_type = v_model_type AND pe.object_id = NEW.object_id;
    END IF;
    IF kaname.object_project_binding_refuses(v_model_type, NEW.object_id, NEW.parent_project_id, v_raw_chain) THEN
        RAISE EXCEPTION 'object %:% is bound to another project', v_model_type, NEW.object_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'object_project_binding_holds',
                  TABLE = 'resource_mirror',
                  SCHEMA = 'kaname';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_parent_edge_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, kaname
    AS $$
BEGIN
    IF pg_trigger_depth() = 2 THEN
        RETURN NEW;
    END IF;
    -- Raw project edges participate in the same real write-conflict gate.
    -- This also protects the reverse RR schedule: an edge committed after the
    -- first-binding writer's snapshot makes that writer serialize/retry.
    UPDATE kaname.catalog_resource cr
       SET project_bindings_held = cr.project_bindings_held
     WHERE cr.object_type = NEW.object_type;
    IF kaname.object_project_binding_refuses(NEW.object_type, NEW.object_id, NULL,
                                             ARRAY[NEW.parent_type || ':' || NEW.parent_id]) THEN
        RAISE EXCEPTION 'object %:% is bound to another project', NEW.object_type, NEW.object_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'object_project_binding_holds',
                  TABLE = 'resource_parent_edge',
                  SCHEMA = 'kaname';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

DROP TRIGGER registration_catalog_fence_forget_row ON kaname.catalog_resource;
DROP TRIGGER registration_catalog_fence_forget_identity ON kaname.catalog_resource;
DROP TRIGGER registration_catalog_fence_forget_all ON kaname.catalog_resource;
DROP FUNCTION kaname.registration_catalog_fence_ensure(text, text);
DROP TABLE kaname.registration_catalog_fence;
DROP FUNCTION kaname.registration_catalog_fence_mint();
DROP FUNCTION kaname.registration_catalog_fence_refuses_truncate();
DROP FUNCTION kaname.registration_catalog_fence_forget();
