-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Retire the network-operator's dead authorization fan-out.
--
-- The role `module.vpc_operator_sa` (seeded 0009, rules re-authored 0031 §4.7)
-- authored four rules — `vpc.subnetses`, `vpc.networks`, `vpc.network_interfaces`
-- and `iam.projectses`. None of the four names is in the closed (module,resource)
-- → object_type table, so materialization asks the table, gets nothing back and
-- emits NO tuple at all ("a typo'd type never grants" — the emitter says so at
-- the point of emission). The refusal is correct and deliberately silent, and the
-- silence is the whole problem: a name the table does not carry looks exactly
-- like a name it does — same shape in the seed, same shape in review, same shape
-- when the role is read back through the API. A rule that grants nothing while
-- reading as a grant is a promise nobody owns.
--
-- The fan-out was dead on four independent grounds, each measured separately:
--   1. the four names do not resolve (closed table, with a control in both
--      directions — the predicate accepts `vpc.subnet` and rejects
--      `vpc.subnetses`);
--   2. the cascade this fan-out was built on — `viewer … or system_viewer from
--      cluster` — is REMOVED from the model; fga_model.fga says so on `account`
--      and on `project`;
--   3. the account/project visibility page carries no cluster-wide reader floor
--      at all: visibility is per-object `viewer ∨ v_list`;
--   4. the binding emitter branches on whether the role has rules: a role WITH
--      rules emits only the hierarchy parent-pointer and no access tuple.
--
-- WHY THE WHOLE ROLE, AND NOT JUST ITS RULES. Ground 4 is also a trap. Clearing
-- `rules` while leaving `permissions` in place would move the role into the
-- legacy permissions-only branch, which emits TIER relations on the binding's
-- scope anchor — minting a `viewer@cluster` grant that did not exist before,
-- under the heading of removing a dead one. So the rules, the permissions, the
-- binding and the role go together.
--
-- WHAT IS DELIBERATELY LEFT ALONE.
--   * The ServiceAccount row. It is the operator's identity on the internal
--     perimeter, not a grant.
--   * The `system_viewer@cluster:cluster_kacho_root` tuple seeded by 0010. It was
--     seeded for the cascade of ground 2, but it has since acquired a SECOND,
--     CURRENT reader and is now load-bearing: migration 0014 deliberately does
--     not seed the operator its own tuple, recording that it "already holds
--     system_viewer@cluster from SEC-L migration 0010"; authzguard.SystemViewerFloor
--     gates the internal-listener READ-RPCs on that relation; and vpc gates
--     InternalNetworkService/GetNetwork on it, naming the network operator as the
--     consumer. Removing it would remove a LIVE grant. Held by
--     TestOperatorClusterTupleSurvivesRetirement.
--
-- IDEMPOTENT. Every statement is keyed on the retired ids, so a re-run — or a
-- re-apply against a database already retired — changes nothing. Additive to the
-- migration history; no applied migration is edited (ban #5).

-- (1) Selectors projected from the retired role's rules. They cascade from
--     roles(id), but the delete is stated explicitly so the retired state does not
--     depend on a cascade staying configured the way it is today.
DELETE FROM kacho_iam.role_rule_selectors
 WHERE role_id = 'rol' || substr(md5('module.vpc_operator_sa'), 1, 17);

-- (2) The binding that granted the retired role. access_bindings_role_fk is
--     ON DELETE RESTRICT, so this goes before the role;
--     access_binding_target_members cascades from the binding.
DELETE FROM kacho_iam.access_bindings
 WHERE id = 'acb' || substr(md5('module.vpc_operator_sa'), 1, 17)
    OR role_id = 'rol' || substr(md5('module.vpc_operator_sa'), 1, 17);

-- (3) The role itself. Scoped to the deterministic seeded id, so an account-scoped
--     custom role that happens to carry the same name is left to its owner.
DELETE FROM kacho_iam.roles
 WHERE id = 'rol' || substr(md5('module.vpc_operator_sa'), 1, 17);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- There is no down path. Re-seeding the role would re-advertise a fan-out that
-- grants nothing: the four names it authors are still absent from the closed
-- object-type table, and the cascade it depended on is still out of the model. A
-- rollback that genuinely needs an operator fan-out needs names the table
-- carries, which is a NEW grant of cluster size and belongs in a migration of its
-- own, with its own acceptance — not in the reversal of this one.
SELECT 1;

-- +goose StatementEnd
