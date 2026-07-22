-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- =============================================================================
-- NLB CONTRACT fallout: the loadbalancer :start / :stop power-verbs were removed
-- (administrative enable/disable now lives in NetworkLoadBalancer.admin_state).
-- The `loadbalancer.networkLoadBalancers.{start,stop}` permission strings no
-- longer exist in the permission catalog, so the built-in `loadbalancer.operator`
-- system role must stop granting them (otherwise it carries two dangling verbs
-- that map to no RPC — vestigial grant).
-- =============================================================================
-- A system role carries BOTH the flat 4-segment `permissions[]` (materialized,
-- read back by RoleRepo.Get → domain.Role.Permissions) AND the grouped `rules[]`
-- (scalar `module` since 0033). Both must drop start/stop to stay consistent; the
-- rest of the verbs are preserved VERBATIM (tier-parity via domain.ResolveVerbsAndTier).
--
-- SHAPE:
--   permissions — 4-segment `module.resource.*.verb` (wildcard resourceName, promoted
--                 by 0005); drop `...networkLoadBalancers.*.start` / `.stop`.
--   rules       — SCALAR `{"module":"loadbalancer",...}` since 0033 (array `modules`
--                 form is rejected by the roles_rules_valid CHECK, SQLSTATE 23514).
--
-- The boot-time SyncAllSystemRoleSelectors re-materializes role_rule_selectors from
-- the updated rules (delete-stale), so the removed verbs leave no selector behind.
-- target_manager never granted start/stop — left untouched.

UPDATE kacho_iam.roles SET
    permissions = '[
        "loadbalancer.listeners.*.get",
        "loadbalancer.listeners.*.list",
        "loadbalancer.listeners.*.listOperations",
        "loadbalancer.networkLoadBalancers.*.get",
        "loadbalancer.networkLoadBalancers.*.getTargetStates",
        "loadbalancer.networkLoadBalancers.*.list",
        "loadbalancer.networkLoadBalancers.*.listOperations",
        "loadbalancer.operations.*.get",
        "loadbalancer.targetGroups.*.get",
        "loadbalancer.targetGroups.*.list",
        "loadbalancer.targetGroups.*.listOperations"
    ]'::jsonb,
    rules = '[
        {"module":"loadbalancer","resources":["networkLoadBalancers"],"verbs":["getTargetStates","listOperations","get","list"]},
        {"module":"loadbalancer","resources":["listeners"],"verbs":["get","list","listOperations"]},
        {"module":"loadbalancer","resources":["targetGroups"],"verbs":["get","list","listOperations"]},
        {"module":"loadbalancer","resources":["operations"],"verbs":["get"]}
    ]'::jsonb
  WHERE id = 'rol' || substr(md5('loadbalancer.operator'), 1, 17);

-- +goose Down

-- Restore start/stop on the operator role (both projections).
UPDATE kacho_iam.roles SET
    permissions = '[
        "loadbalancer.listeners.*.get",
        "loadbalancer.listeners.*.list",
        "loadbalancer.listeners.*.listOperations",
        "loadbalancer.networkLoadBalancers.*.get",
        "loadbalancer.networkLoadBalancers.*.getTargetStates",
        "loadbalancer.networkLoadBalancers.*.list",
        "loadbalancer.networkLoadBalancers.*.listOperations",
        "loadbalancer.networkLoadBalancers.*.start",
        "loadbalancer.networkLoadBalancers.*.stop",
        "loadbalancer.operations.*.get",
        "loadbalancer.targetGroups.*.get",
        "loadbalancer.targetGroups.*.list",
        "loadbalancer.targetGroups.*.listOperations"
    ]'::jsonb,
    rules = '[
        {"module":"loadbalancer","resources":["networkLoadBalancers"],"verbs":["start","stop","getTargetStates","listOperations","get","list"]},
        {"module":"loadbalancer","resources":["listeners"],"verbs":["get","list","listOperations"]},
        {"module":"loadbalancer","resources":["targetGroups"],"verbs":["get","list","listOperations"]},
        {"module":"loadbalancer","resources":["operations"],"verbs":["get"]}
    ]'::jsonb
  WHERE id = 'rol' || substr(md5('loadbalancer.operator'), 1, 17);
