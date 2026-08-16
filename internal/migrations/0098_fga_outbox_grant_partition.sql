-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Widen the fga_outbox drainer's ORDERING PARTITION from the tuple
-- (user, relation, object) to the GRANT (user, object) — the narrowest key that
-- still covers the unit a row now carries.
--
-- WHY THE UNIT CHANGED
--
-- A row used to be ONE tuple. The drainer applies one row per call, so a subject's
-- relation set on an object reached OpenFGA one relation at a time, and between the
-- first arrival and the last the set was HALF PRESENT: the subject could read the
-- object it had just created and could not change or delete it. Measured on a stand:
-- read allowed, the same subject's update on the same object refused 50 ms later, the
-- refusal naming exactly one relation standing on the object. The synchronous writer
-- had always applied a whole object in one transactional Write; the queue — which is
-- the at-least-once path, and therefore the one that runs whenever the synchronous
-- attempt is skipped, cancelled or lost — had no such property at all.
--
-- Ordering alone cannot fix that, and this is the point worth keeping: a partition
-- decides WHICH ROWS WAIT FOR WHICH, never how many tuples land together. Atomicity
-- has to come from the row carrying the whole set (services/iam/internal/repo/kacho/
-- pg/fga_outbox/emitter.go). This migration is the other half of that change: once a
-- row is a set, the partition has to cover every row the set can be ordered against,
-- or a revoke of the set could be applied ahead of the grant it supersedes and the
-- tuple would survive its own removal — the over-grant migration 0061 closed.
--
-- WHY (user, object) AND NOT SOMETHING NARROWER
--
-- The rule migration 0067 stated still holds: the key must be the NARROWEST one over
-- which the target's events fail to commute. What changed is the event. Two rows now
-- fail to commute when their SETS INTERSECT, and every set this table carries is one
-- subject's relations on one object — so (user, object) is exactly that narrowest key,
-- not a retreat to the object key 0067 removed.
--
-- The distinction is the whole of 0067's measurement. Its cost was rows of DIFFERENT
-- SUBJECTS on one object serialising against each other: a revoke waiting on up to 632
-- same-object predecessors while its own tuple had at most 3. Different subjects stay
-- in different partitions here, so that cost does not come back. What does merge is one
-- subject's own relations on one object — and those are precisely the rows that must
-- not overtake each other. They are also no longer separate rows: the emitter groups
-- them, so the queue holds roughly one row per grant where it used to hold one per verb.
--
-- ROLLING DEPLOY is safe in both directions.
--   - A pod still on the previous release reads the same column by the same name and
--     partitions on a value that is now STRICTLY WIDER (same tuple ⇒ same grant). A
--     wider key only ever ADDS ordering constraints, so it cannot let a delete overtake
--     its write. It serialises a little more than that pod's own rules require, for the
--     length of the rollout, and nothing else.
--   - The same holds for the rows already queued when this lands: the backfill below
--     merges partitions, never splits them, so no pair that was ordered before becomes
--     unordered.
--
-- The COLUMN NAME stays `tuple_key`. Renaming it would make the claim query of every
-- pod on the previous release address a column that no longer exists, which turns a
-- rollout into a stalled drainer; the name is therefore historical and is documented as
-- such at both ends (fga_outbox/emitter.go PartitionColumn, cmd/kacho-iam/
-- fga_outbox_drainer.go).

CREATE OR REPLACE FUNCTION kacho_iam.fga_outbox_tuple_key() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.tuple_key := (NEW.payload->>'user') || ' ' || (NEW.payload->>'object');
    RETURN NEW;
END;
$$;

-- +goose StatementEnd

-- +goose StatementBegin

-- Re-key the rows the claim can still see. PENDING only, for the reason 0067 gave:
-- the claim and the partial index both filter on `sent_at IS NULL`, so a drained row's
-- key is never read again and rewriting 1.4M of them would touch the heap for data
-- nothing consults.
UPDATE kacho_iam.fga_outbox
   SET tuple_key = (payload->>'user') || ' ' || (payload->>'object')
 WHERE sent_at IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- A row must NAME A RELATION, in one form or the other.
--
-- Until now the partition key carried that guarantee for free: it was built from
-- `relation`, so a payload without one produced a NULL key and the 0067 check refused the
-- INSERT. The key no longer reads `relation`, so that guarantee is gone — and a row naming
-- no relation is not a small mistake: it decodes to nothing the applier can write, poisons,
-- and (being poison) never applies, which for a revoke means access that outlives its own
-- removal. Loud at INSERT beats silent in the queue.
--
-- NOT VALID for the same reason as its sibling: enforced for every row from here on, never
-- validated against the historic rows the claim can no longer see.
ALTER TABLE kacho_iam.fga_outbox
    ADD CONSTRAINT fga_outbox_relation_present_check
    CHECK (
        (payload->>'relation' IS NOT NULL AND payload->>'relation' <> '')
        OR jsonb_array_length(coalesce(payload->'relations', '[]'::jsonb)) > 0
    ) NOT VALID;

-- The index (tuple_key, id) WHERE sent_at IS NULL — migration 0067's
-- fga_outbox_tuple_head_idx — is on the same column and needs no change; the claim's
-- correlated NOT EXISTS keeps using it. ANALYZE because the column's cardinality just
-- dropped by roughly the number of relations per grant, and the claim's plan is chosen
-- from it.
ANALYZE kacho_iam.fga_outbox;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE kacho_iam.fga_outbox DROP CONSTRAINT IF EXISTS fga_outbox_relation_present_check;

-- Back to the triple. NOTE the asymmetry, and it is deliberate: going down NARROWS the
-- partition, which REMOVES ordering constraints. That is only sound once no row carries
-- a relation set — otherwise a set-row's revoke and its grant land in different
-- partitions. Roll the emitter back first.
CREATE OR REPLACE FUNCTION kacho_iam.fga_outbox_tuple_key() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.tuple_key :=
        (NEW.payload->>'user')     || ' ' ||
        (NEW.payload->>'relation') || ' ' ||
        (NEW.payload->>'object');
    RETURN NEW;
END;
$$;

UPDATE kacho_iam.fga_outbox
   SET tuple_key = (payload->>'user') || ' ' || (payload->>'relation') || ' ' || (payload->>'object')
 WHERE sent_at IS NULL
   AND payload->>'relation' IS NOT NULL;

-- +goose StatementEnd
