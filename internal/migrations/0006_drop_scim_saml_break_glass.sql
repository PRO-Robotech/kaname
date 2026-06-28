-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0006_drop_scim_saml_break_glass.sql — physical removal of SCIM, SAML
-- and Break-Glass tables.
--
-- SCIM v2 and SAML organization federation are removed in favour of
-- the exclusive Ory stack (Kratos/Hydra OIDC). Break-Glass (cluster_break_glass_grants +
-- post-incident reviews) is removed as part of the RBAC v2 simplification.
--
-- Tables dropped (CASCADE pulls FKs / indexes / sequences):
--   * scim_user_mappings, scim_groups, scim_group_members  — SCIM v2
--   * saml_sessions                                         — SAML SP
--   * cluster_break_glass_grants, break_glass_post_incident_reviews — BG

-- +goose Up
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.scim_group_members        CASCADE;
DROP TABLE IF EXISTS kacho_iam.scim_groups               CASCADE;
DROP TABLE IF EXISTS kacho_iam.scim_user_mappings        CASCADE;

DROP TABLE IF EXISTS kacho_iam.saml_sessions             CASCADE;

DROP TABLE IF EXISTS kacho_iam.break_glass_post_incident_reviews CASCADE;
DROP TABLE IF EXISTS kacho_iam.cluster_break_glass_grants        CASCADE;
-- +goose StatementEnd
