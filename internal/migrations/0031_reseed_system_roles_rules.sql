-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC rules-model 2026 clean-cut. Re-seed the 58 system
-- roles with their authored rules[] — the rules model is now the public source of
-- truth for a role's policy (mig 0001 seeded only permissions[]). The rows ALREADY
-- exist (mig 0001 INSERTed them; mig 0005 promoted their permissions to the
-- canonical 4-segment grammar in-place), so this migration ONLY fills the rules
-- column via UPDATE keyed by the deterministic role id — it NEVER touches
-- permissions[] (which still backs FGA emission) and NEVER deletes a row.
--
-- WHY UPDATE (not INSERT … ON CONFLICT): an INSERT validates the supplied
-- permissions[] against the 4-segment roles_permissions_valid CHECK (mig 0005/0025)
-- even on conflict; re-supplying the original 3-segment seed strings would violate
-- it. A pure UPDATE of rules[] sidesteps that — the stored 4-segment permissions
-- are left untouched.
--
-- TIER-PARITY (the load-bearing invariant): each role's rules express the
-- SAME authority its permissions do. The rules-derived per-(module,resource) tier
-- (domain.ResolveVerbsAndTier over the rule's verbs) EQUALS the legacy
-- permissions-derived tier (authzmap.verbClass) for every role — proven by
-- tier_parity_integration_test.go over the actual seeded rows.
--
-- IDEMPOTENT (access not severed): the UPDATE is keyed by the unchanged id
-- (catalog roles: 'rol'||substr(md5(name),1,17); the two kacho-system roles: literal
-- rol000000000sysadmin / rol000000000sysviewer), so the FK-child rows attached by
-- mig 0004 (cluster-admin on 'admin'), 0009 (module-SA), 0010 (operator-SA on
-- 'view'/'kacho-system.viewer'), 0014 (reader-SA) survive intact — the UPDATE only
-- rewrites the rules column, never the row identity. Re-running is a no-op (same
-- rules in, same rules out).

-- 4.1 Wildcards (3).
UPDATE kacho_iam.roles SET rules = '[{"modules":["*"],"resources":["*"],"verbs":["*"]}]'::jsonb                       WHERE id = 'rol' || substr(md5('admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["*"],"resources":["*"],"verbs":["update"]}]'::jsonb                  WHERE id = 'rol' || substr(md5('edit'),  1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["*"],"resources":["*"],"verbs":["read","list","get"]}]'::jsonb      WHERE id = 'rol' || substr(md5('view'),  1, 17);

-- 4.2 IAM narrow — 7 resources × 3 verbs = 21.
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["account"],"verbs":["*"]}]'::jsonb                          WHERE id = 'rol' || substr(md5('iam.account.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["account"],"verbs":["update"]}]'::jsonb                     WHERE id = 'rol' || substr(md5('iam.account.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["account"],"verbs":["read","list","get"]}]'::jsonb         WHERE id = 'rol' || substr(md5('iam.account.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["project"],"verbs":["*"]}]'::jsonb                          WHERE id = 'rol' || substr(md5('iam.project.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["project"],"verbs":["update"]}]'::jsonb                     WHERE id = 'rol' || substr(md5('iam.project.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["project"],"verbs":["read","list","get"]}]'::jsonb         WHERE id = 'rol' || substr(md5('iam.project.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["user"],"verbs":["*"]}]'::jsonb                             WHERE id = 'rol' || substr(md5('iam.user.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["user"],"verbs":["update"]}]'::jsonb                        WHERE id = 'rol' || substr(md5('iam.user.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["user"],"verbs":["read","list","get"]}]'::jsonb            WHERE id = 'rol' || substr(md5('iam.user.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["service_account"],"verbs":["*"]}]'::jsonb                  WHERE id = 'rol' || substr(md5('iam.service_account.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["service_account"],"verbs":["update"]}]'::jsonb             WHERE id = 'rol' || substr(md5('iam.service_account.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["service_account"],"verbs":["read","list","get"]}]'::jsonb WHERE id = 'rol' || substr(md5('iam.service_account.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["group"],"verbs":["*"]}]'::jsonb                            WHERE id = 'rol' || substr(md5('iam.group.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["group"],"verbs":["update"]}]'::jsonb                       WHERE id = 'rol' || substr(md5('iam.group.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["group"],"verbs":["read","list","get"]}]'::jsonb           WHERE id = 'rol' || substr(md5('iam.group.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["role"],"verbs":["*"]}]'::jsonb                             WHERE id = 'rol' || substr(md5('iam.role.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["role"],"verbs":["update"]}]'::jsonb                        WHERE id = 'rol' || substr(md5('iam.role.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["role"],"verbs":["read","list","get"]}]'::jsonb            WHERE id = 'rol' || substr(md5('iam.role.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["access_binding"],"verbs":["*"]}]'::jsonb                   WHERE id = 'rol' || substr(md5('iam.access_binding.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["access_binding"],"verbs":["update"]}]'::jsonb              WHERE id = 'rol' || substr(md5('iam.access_binding.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["iam"],"resources":["access_binding"],"verbs":["read","list","get"]}]'::jsonb  WHERE id = 'rol' || substr(md5('iam.access_binding.view'), 1, 17);

-- 4.3 VPC narrow — 6 resources × 3 verbs = 18.
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["network"],"verbs":["*"]}]'::jsonb                         WHERE id = 'rol' || substr(md5('vpc.network.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["network"],"verbs":["update"]}]'::jsonb                    WHERE id = 'rol' || substr(md5('vpc.network.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["network"],"verbs":["read","list","get"]}]'::jsonb        WHERE id = 'rol' || substr(md5('vpc.network.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["subnet"],"verbs":["*"]}]'::jsonb                          WHERE id = 'rol' || substr(md5('vpc.subnet.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["subnet"],"verbs":["update"]}]'::jsonb                     WHERE id = 'rol' || substr(md5('vpc.subnet.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["subnet"],"verbs":["read","list","get"]}]'::jsonb         WHERE id = 'rol' || substr(md5('vpc.subnet.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["security_group"],"verbs":["*"]}]'::jsonb                  WHERE id = 'rol' || substr(md5('vpc.security_group.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["security_group"],"verbs":["update"]}]'::jsonb             WHERE id = 'rol' || substr(md5('vpc.security_group.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["security_group"],"verbs":["read","list","get"]}]'::jsonb WHERE id = 'rol' || substr(md5('vpc.security_group.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["address"],"verbs":["*"]}]'::jsonb                         WHERE id = 'rol' || substr(md5('vpc.address.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["address"],"verbs":["update"]}]'::jsonb                    WHERE id = 'rol' || substr(md5('vpc.address.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["address"],"verbs":["read","list","get"]}]'::jsonb        WHERE id = 'rol' || substr(md5('vpc.address.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["route_table"],"verbs":["*"]}]'::jsonb                     WHERE id = 'rol' || substr(md5('vpc.route_table.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["route_table"],"verbs":["update"]}]'::jsonb                WHERE id = 'rol' || substr(md5('vpc.route_table.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["route_table"],"verbs":["read","list","get"]}]'::jsonb    WHERE id = 'rol' || substr(md5('vpc.route_table.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["gateway"],"verbs":["*"]}]'::jsonb                         WHERE id = 'rol' || substr(md5('vpc.gateway.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["gateway"],"verbs":["update"]}]'::jsonb                    WHERE id = 'rol' || substr(md5('vpc.gateway.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["vpc"],"resources":["gateway"],"verbs":["read","list","get"]}]'::jsonb        WHERE id = 'rol' || substr(md5('vpc.gateway.view'), 1, 17);

-- 4.4 Compute narrow — 4 resources × 3 verbs = 12.
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["instance"],"verbs":["*"]}]'::jsonb                     WHERE id = 'rol' || substr(md5('compute.instance.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["instance"],"verbs":["update"]}]'::jsonb                WHERE id = 'rol' || substr(md5('compute.instance.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["instance"],"verbs":["read","list","get"]}]'::jsonb    WHERE id = 'rol' || substr(md5('compute.instance.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["disk"],"verbs":["*"]}]'::jsonb                         WHERE id = 'rol' || substr(md5('compute.disk.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["disk"],"verbs":["update"]}]'::jsonb                    WHERE id = 'rol' || substr(md5('compute.disk.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["disk"],"verbs":["read","list","get"]}]'::jsonb        WHERE id = 'rol' || substr(md5('compute.disk.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["image"],"verbs":["*"]}]'::jsonb                        WHERE id = 'rol' || substr(md5('compute.image.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["image"],"verbs":["update"]}]'::jsonb                   WHERE id = 'rol' || substr(md5('compute.image.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["image"],"verbs":["read","list","get"]}]'::jsonb       WHERE id = 'rol' || substr(md5('compute.image.view'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["snapshot"],"verbs":["*"]}]'::jsonb                     WHERE id = 'rol' || substr(md5('compute.snapshot.admin'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["snapshot"],"verbs":["update"]}]'::jsonb                WHERE id = 'rol' || substr(md5('compute.snapshot.edit'), 1, 17);
UPDATE kacho_iam.roles SET rules = '[{"modules":["compute"],"resources":["snapshot"],"verbs":["read","list","get"]}]'::jsonb    WHERE id = 'rol' || substr(md5('compute.snapshot.view'), 1, 17);

-- 4.5 kacho-system built-in (2, hand-rolled deterministic ids).
UPDATE kacho_iam.roles SET rules = '[{"modules":["*"],"resources":["*"],"verbs":["*"]}]'::jsonb                  WHERE id = 'rol000000000sysadmin';
UPDATE kacho_iam.roles SET rules = '[{"modules":["*"],"resources":["*"],"verbs":["read","list","get"]}]'::jsonb WHERE id = 'rol000000000sysviewer';

-- 4.6 NLB operator + target_manager. The rules group the role's permission strings
-- by (loadbalancer, <resource>) and collect the camelCase verbs per resource
-- VERBATIM (so domain.ResolveVerbsAndTier classifies them identically to
-- authzmap.verbClass — tier-parity).
UPDATE kacho_iam.roles SET rules = '[
    {"modules":["loadbalancer"],"resources":["networkLoadBalancers"],"verbs":["start","stop","getTargetStates","listOperations","get","list"]},
    {"modules":["loadbalancer"],"resources":["listeners"],"verbs":["get","list","listOperations"]},
    {"modules":["loadbalancer"],"resources":["targetGroups"],"verbs":["get","list","listOperations"]},
    {"modules":["loadbalancer"],"resources":["operations"],"verbs":["get"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('loadbalancer.operator'), 1, 17);

UPDATE kacho_iam.roles SET rules = '[
    {"modules":["loadbalancer"],"resources":["targetGroups"],"verbs":["addTargets","removeTargets","get","list","listOperations"]},
    {"modules":["loadbalancer"],"resources":["networkLoadBalancers"],"verbs":["getTargetStates","get","list"]},
    {"modules":["loadbalancer"],"resources":["listeners"],"verbs":["get","list"]},
    {"modules":["loadbalancer"],"resources":["operations"],"verbs":["get"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('loadbalancer.target_manager'), 1, 17);

-- 4.7 SEC-C module-SA backing roles (mig 0009) — also system roles, so they MUST
-- carry rules[] under the rules model (every system role materializes
-- through rules). Their permissions are 4-segment `module.resource.*.verb`; group
-- by (module, resource) and collect the verbs VERBATIM (incl. the quirky
-- pluralized resource names subnetses/projectses, mirrored exactly so the
-- tier-parity grouping matches both sides). Tiers: get/list → viewer;
-- create/update/delete → editor (compute_sa's addresses rule is editor).
UPDATE kacho_iam.roles SET rules = '[
    {"modules":["vpc"],"resources":["subnets"],"verbs":["get"]},
    {"modules":["vpc"],"resources":["security_groups"],"verbs":["get"]},
    {"modules":["vpc"],"resources":["addresses"],"verbs":["get","create","delete","update"]},
    {"modules":["iam"],"resources":["projects"],"verbs":["get"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('module.compute_sa'), 1, 17);

UPDATE kacho_iam.roles SET rules = '[
    {"modules":["compute"],"resources":["zones"],"verbs":["get"]},
    {"modules":["iam"],"resources":["projects"],"verbs":["get"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('module.vpc_sa'), 1, 17);

UPDATE kacho_iam.roles SET rules = '[
    {"modules":["vpc"],"resources":["subnets"],"verbs":["get"]},
    {"modules":["iam"],"resources":["projects"],"verbs":["get"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('module.nlb_sa'), 1, 17);

UPDATE kacho_iam.roles SET rules = '[
    {"modules":["vpc"],"resources":["subnetses"],"verbs":["list"]},
    {"modules":["vpc"],"resources":["networks"],"verbs":["get"]},
    {"modules":["vpc"],"resources":["network_interfaces"],"verbs":["get"]},
    {"modules":["iam"],"resources":["projectses"],"verbs":["list"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('module.vpc_operator_sa'), 1, 17);

UPDATE kacho_iam.roles SET rules = '[
    {"modules":["iam"],"resources":["projects"],"verbs":["get"]}
  ]'::jsonb
  WHERE id = 'rol' || substr(md5('module.api_gateway_sa'), 1, 17);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Rollback: clear the rules[] of the 58 system roles (back to the pre-0031
-- permissions-only state). Forward-only data migration — the Down only resets the
-- rules column; permissions are untouched (they were never changed by Up).
UPDATE kacho_iam.roles SET rules = '[]'::jsonb WHERE is_system;

-- +goose StatementEnd
