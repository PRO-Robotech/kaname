-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Retire the six module service-account roles whose declarations grant nothing.
--
-- SUBJECT. `module.api_gateway_sa`, `module.compute_sa`, `module.nlb_sa`,
-- `module.registry_sa`, `module.storage_sa`, `module.vpc_sa` (seeded 0009 /
-- 0044+0045 / 0057, rules authored 0031 §4.7). Their rules name resources the
-- closed (module,resource) → object_type table does not carry — `iam.projects`
-- (the table carries `iam.project`), `vpc.subnets` (`vpc.subnet`),
-- `vpc.security_groups` (`vpc.securityGroup`), `vpc.addresses` (`vpc.address`),
-- `compute.zones` (placement topology left compute for geo entirely). The
-- RESOLVABLE SET OF EACH OF THE SIX IS EMPTY: materialization asks the table,
-- gets nothing back and emits NO tuple at all ("a typo'd type never grants" —
-- reconcile/tuples.go says so at the point of emission). The refusal is correct
-- and deliberately silent, and the silence is the problem: a name the table does
-- not carry looks exactly like one it does — in the seed, in a review diff, and
-- when the role is read back through the API.
--
-- This is the SAME class migration 0076 retired for the network operator. That
-- one was found on one role; an adversarial re-measure over the whole seed found
-- six more with the same property, so the class is closed here rather than the
-- instance.
--
-- HOW THESE SERVICE ACCOUNTS ACTUALLY WORK — three paths, none through the role,
-- each measured separately:
--   1. WRITES to the relation store ride the `fga_writer@iam_fgaproxy:system`
--      tuple seeded DIRECTLY into fga_outbox (0009 for vpc/compute/nlb, 0044 for
--      registry, 0057 for storage). Migration 0044's own header states it: "owner
--      -tuple writes are authorized by the fga_writer ReBAC tuple, not by a role
--      permission".
--   2. READS on the cluster-internal listener ride
--      `system_viewer@cluster:cluster_kacho_root` (0014 — api-gateway/vpc/compute),
--      which authzguard.SystemViewerFloor gates on. Also a direct fga_outbox seed.
--   3. CROSS-SERVICE calls are authorized as the REQUESTING TENANT, not as the
--      module: all six wrap the outgoing context in `auth.PropagateOutgoing`. The
--      vpc client comment states the consequence of not doing so — "peer увидит
--      анонимный/системный вызов, вернёт NOT_FOUND". So `iam.projects.*.get` is
--      presented by the tenant; the role declaration takes no part.
-- On top of that, these bindings were INSERTED BY SEED SQL, bypassing
-- buildBindingTuples — so across their whole life they emitted no tuple at all,
-- not even the hierarchy pointer.
--
-- WHY THE WHOLE ROLE AND NOT ONLY ITS RULES — a trap, measured by probe
-- (access_binding/tuples_module_sa_branch_test.go). buildBindingTuples branches
-- on `len(role.Rules) > 0`: a role WITH rules emits only the hierarchy pointer; a
-- role WITHOUT rules falls into the legacy branch and lands a relation on the
-- binding's scope anchor. The anchor here is the CLUSTER, and on cluster
-- `mapClusterRelations` collapses BOTH `admin` and `editor` into the direct
-- `system_admin`. Clearing `module.compute_sa`'s rules while leaving its
-- permission strings (which carry create/update/delete) would therefore mint
-- `system_admin@cluster:cluster_kacho_root` — the cloud-administrator tier,
-- cascading over everything — and would give the other five
-- `system_viewer@cluster`, which nlb, registry and storage do not hold today. So
-- the rules, the permissions, the bindings and the roles go together.
--
-- WHAT IS DELIBERATELY LEFT ALONE.
--   * The six `service_accounts` rows — identity on the internal perimeter, not a
--     grant.
--   * Both cluster tuples above. Held by
--     TestModuleSACapabilitiesSurviveRetirement, which also asserts the MIRROR
--     cells (api-gateway still has no fga_writer; nlb/registry/storage still have
--     no system_viewer) so a later cleanup cannot hand out what this one removed
--     the declaration of.
--
-- IDEMPOTENT. Every statement is keyed on the deterministic retired ids, so a
-- re-run — or a re-apply against an already-retired database — changes nothing.
-- Additive to the migration history; no applied migration is edited (ban #5).

-- (1) Selectors projected from the retired roles' rules. They cascade from
--     roles(id), but the delete is stated explicitly so the retired state does not
--     depend on a cascade staying configured the way it is today.
DELETE FROM kacho_iam.role_rule_selectors
 WHERE role_id IN (
   'rol' || substr(md5('module.api_gateway_sa'), 1, 17),
   'rol' || substr(md5('module.compute_sa'),     1, 17),
   'rol' || substr(md5('module.nlb_sa'),         1, 17),
   'rol' || substr(md5('module.registry_sa'),    1, 17),
   'rol' || substr(md5('module.storage_sa'),     1, 17),
   'rol' || substr(md5('module.vpc_sa'),         1, 17));

-- (2) The bindings that granted the retired roles. access_bindings_role_fk is
--     ON DELETE RESTRICT, so these go before the roles; subjects / targets /
--     target_members / emitted_tuples / conditions all cascade from the binding.
--     Keyed on role_id (not only on the seeded binding id) so a binding created
--     on one of these roles by any other path goes with it — leaving one behind
--     would block step (3) with a bare RESTRICT and no attributable cause.
DELETE FROM kacho_iam.access_bindings
 WHERE role_id IN (
   'rol' || substr(md5('module.api_gateway_sa'), 1, 17),
   'rol' || substr(md5('module.compute_sa'),     1, 17),
   'rol' || substr(md5('module.nlb_sa'),         1, 17),
   'rol' || substr(md5('module.registry_sa'),    1, 17),
   'rol' || substr(md5('module.storage_sa'),     1, 17),
   'rol' || substr(md5('module.vpc_sa'),         1, 17));

-- (3) The roles themselves. Scoped to the deterministic seeded ids, so an
--     account-scoped custom role that happens to carry the same name is left to
--     its owner.
DELETE FROM kacho_iam.roles
 WHERE id IN (
   'rol' || substr(md5('module.api_gateway_sa'), 1, 17),
   'rol' || substr(md5('module.compute_sa'),     1, 17),
   'rol' || substr(md5('module.nlb_sa'),         1, 17),
   'rol' || substr(md5('module.registry_sa'),    1, 17),
   'rol' || substr(md5('module.storage_sa'),     1, 17),
   'rol' || substr(md5('module.vpc_sa'),         1, 17));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- There is no down path, for the same reason 0076 has none. Re-seeding these
-- roles would re-advertise declarations that grant nothing: the names they author
-- are still absent from the closed object-type table, and the three paths these
-- service accounts actually work by are untouched by this migration and by its
-- reversal. A rollback that genuinely needs a module-SA grant needs names the
-- table carries — which is a NEW grant of cluster size and belongs in a migration
-- of its own, with its own acceptance, not in the reversal of this one.
SELECT 1;

-- +goose StatementEnd
