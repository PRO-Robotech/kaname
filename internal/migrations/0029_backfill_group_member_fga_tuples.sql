-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- Backfill the FGA `group:<gid>#member` userset member-tuples for all EXISTING
-- group_members rows (RBAC rules-model 2026, group-membership FGA mirror fix —
-- ExpandAccess + ALL group-based authz).
--
-- THE BUG this closes for historical data:
--   AddMember used to persist ONLY the kacho_iam.group_members row and emitted NO
--   FGA member-tuple, so a GROUP-subject AccessBinding's `<obj>#<rel>@group:<gid>#member`
--   userset resolved to EMPTY in OpenFGA — every pre-fix group member got NO real
--   access via group bindings, and ExpandAccess found no members. The use-case fix
--   (add_member.go EmitFGARelationWrite) covers only NEW memberships; this data
--   migration emits the member-tuple INTENT for the rows that already exist so the
--   live fga_outbox drainer (cmd/kacho-iam/serve.go) materializes them into OpenFGA.
--
-- TUPLE SHAPE (mirrors group/helpers.go memberFGATuple + access_binding subjectRef):
--   payload = {"user":"<member_type>:<member_id>", "relation":"member",
--              "object":"group:<group_id>"}
--   event_type = 'fga.tuple.write'  (existing fga_outbox CHECK literal, no new literal)
--
-- TYPE CONSISTENCY: the object type is `group` — the FGA userset
-- type a group-subject binding points at (fga_model.fga `type group { define
-- member }`), NOT `iam_group` (the group-RESOURCE object-scope hierarchy type
-- group Create emits). member_type already IS the canonical FGA user prefix
-- ('user' / 'service_account', enforced by group_members_type_check), so it maps
-- verbatim into the FGA user namespace.
--
-- IDEMPOTENT (ban #5 / #10): re-running emits nothing for a (group, member)
-- whose write-tuple intent is ALREADY queued or applied — the NOT EXISTS guard
-- de-dupes against any prior fga.tuple.write row carrying the same payload. The
-- drainer is itself at-least-once + idempotent (409 → success) at the OpenFGA
-- side, so a backfilled intent that races a freshly-emitted one converges. This
-- is a NEW migration file — no applied migration is edited.

INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.write',
  jsonb_build_object(
    'user',     gm.member_type || ':' || gm.member_id,
    'relation', 'member',
    'object',   'group:' || gm.group_id
  ),
  now()
FROM kacho_iam.group_members gm
WHERE NOT EXISTS (
  SELECT 1
    FROM kacho_iam.fga_outbox o
   WHERE o.event_type = 'fga.tuple.write'
     AND o.payload->>'user'     = gm.member_type || ':' || gm.member_id
     AND o.payload->>'relation' = 'member'
     AND o.payload->>'object'   = 'group:' || gm.group_id
);

-- +goose Down
-- Best-effort removal of the PENDING (not-yet-applied) backfilled member-tuple
-- intents. Applied rows (sent_at IS NOT NULL) are left to the drainer / a tuple
-- revoke — undoing a tuple ALREADY written to OpenFGA is not this migration's
-- job (symmetric revoke is RemoveMember's). Only un-drained intents are dropped.
DELETE FROM kacho_iam.fga_outbox o
 WHERE o.event_type = 'fga.tuple.write'
   AND o.sent_at IS NULL
   AND o.payload->>'relation' = 'member'
   AND o.payload->>'object' LIKE 'group:%'
   AND EXISTS (
     SELECT 1
       FROM kacho_iam.group_members gm
      WHERE o.payload->>'user'   = gm.member_type || ':' || gm.member_id
        AND o.payload->>'object' = 'group:' || gm.group_id
   );
