-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0007_drop_caep_pipeline.sql — retire the dead CAEP push pipeline.
--
-- The CAEP (RFC 8417 Security Event Token) push pipeline was disabled
-- (NoopCAEPEmitter swap-in), then the last stub callers + NoopCAEPEmitter
-- itself were removed. These tables have no remaining callers anywhere in
-- the codebase. Drop them now to retire dead schema.
--
-- (Migration 0002's dedup helper UPDATEs these tables — that migration
-- runs BEFORE this one, so historical re-application order stays valid.)

-- +goose Up
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.caep_event_delivery CASCADE;
DROP TABLE IF EXISTS kacho_iam.caep_outbox CASCADE;
DROP TABLE IF EXISTS kacho_iam.caep_subscribers CASCADE;
-- +goose StatementEnd
