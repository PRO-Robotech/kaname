-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Retire the network operator's ServiceAccount and everything granted to it.
--
-- Migration 0076 retired the operator's ROLE, its binding and the selectors
-- projected from it, and deliberately left two things standing: the
-- ServiceAccount row ("its identity on the internal perimeter, not a grant") and
-- the cluster tuple `system_viewer@cluster:cluster_kacho_root` seeded by 0010.
-- Both go here, and the second one needs an argument, because 0076 wrote down a
-- reason to keep it.
--
-- WHY THE IDENTITY GOES TOO. An identity is only "not a grant" while something
-- can present it. Nothing can: there is no `services/vpc-operator/` in the tree,
-- no repository behind the name, and no chart that issues a certificate with
-- that SPIFFE SAN — the caller-side circles were pinned to the actually-issued
-- certificates in ebedae53, and the public caller policy stopped naming it in
-- this same change. A principal row with no issuer is not an identity; it is a
-- reservation, and a reservation in the principal table is where a future grant
-- lands without anyone deciding to grant it.
--
-- WHY THE CLUSTER TUPLE GOES, AGAINST 0076's NOTE. 0076 called the tuple
-- load-bearing on the strength of a "second, current reader", naming
-- authzguard.SystemViewerFloor, vpc's InternalNetworkService/GetNetwork, and
-- migration 0014's remark that it does not seed the operator because 0010
-- already did. Every one of those observations is true, and none of them is
-- about THIS tuple: they are readers of the RELATION `system_viewer`, whereas a
-- tuple is keyed to ONE subject. `cluster.system_viewer` is `[user,
-- service_account]` in fga_model.fga — a direct assignment with no userset and
-- no `from`, so it expands to nobody but its own subject. The live readers each
-- hold their OWN tuple, seeded by 0014 for api-gateway / vpc / compute and
-- asserted there per subject; removing the operator's changes nothing for them.
-- The confusion is worth naming because it survived review: "who reads the
-- relation" and "who holds the tuple" are different questions, and the first one
-- always has an answer.
--
-- WHAT THIS DOES NOT TOUCH. The `kacho-system` anchor user and account (they
-- anchor the remaining module SAs), every other module SA and its grants, and
-- the `system_viewer` tuples of api-gateway / vpc / compute. The retirement is
-- keyed to one deterministic subject id throughout, so an account-scoped row
-- that merely resembles it is left to its owner.
--
-- IF THE OPERATOR EVER RETURNS, it returns with a chart that issues its
-- certificate, a caller allowance reviewed against the runtime edge, and a grant
-- of the size it then needs — not by inheriting rights that outlived the
-- component. Hence no down path.
--
-- IDEMPOTENT. Every statement is keyed on the retired subject, so a re-run — or
-- an application against a database where the account is already gone — changes
-- nothing: the deletes match no rows and the revocation intent is inserted only
-- when one is not already queued.

-- (1) The operator as a CO-GRANTEE of anybody's binding (subjects[1..N] live
--     only in the child table). This removes the operator's share of such a
--     binding, never the binding: the other grantees are not our subject. It
--     also has to precede (5) — service_accounts carries a BEFORE DELETE guard
--     (0050) that refuses to drop a principal still referenced as a subject.
DELETE FROM kacho_iam.access_binding_subjects
 WHERE subject_type = 'service_account'
   AND subject_id   = 'sva' || substr(md5('kacho-vpc-operator'), 1, 17);

-- (2) Bindings whose subjects[0] projection IS the operator. Keyed by SUBJECT,
--     not by the seeded binding id: 0076 removed the one it had seeded, and this
--     predicate also covers anything granted to the operator since.
--     access_binding_subjects cascades from the binding.
DELETE FROM kacho_iam.access_bindings
 WHERE subject_type = 'service_account'
   AND subject_id   = 'sva' || substr(md5('kacho-vpc-operator'), 1, 17);

-- (3) Grant intents for the operator that have NOT been delivered yet. Dropping
--     them is what keeps a queued write from applying after the revocation
--     below: the drainer orders per tuple key, and a write enqueued earlier than
--     the delete would otherwise be applied first and then revoked — the same
--     end state, but two round-trips and a window in between.
DELETE FROM kacho_iam.fga_outbox
 WHERE sent_at IS NULL
   AND event_type = 'fga.tuple.write'
   AND payload->>'user' = 'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17));

-- (4) Revoke the cluster tuple that HAS been delivered. Deleting the seed row of
--     0010 would only erase the record of the intent; the tuple itself lives in
--     the relation store and comes out only by a delete intent. Applying it to a
--     store that never received the write is a no-op the applier already treats
--     as success (`cannot_delete` / absent → already applied).
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.delete',
       jsonb_build_object(
         'user',     'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17)),
         'relation', 'system_viewer',
         'object',   'cluster:cluster_kacho_root'),
       now()
 WHERE NOT EXISTS (
   SELECT 1 FROM kacho_iam.fga_outbox
    WHERE event_type = 'fga.tuple.delete'
      AND payload->>'relation' = 'system_viewer'
      AND payload->>'object'   = 'cluster:cluster_kacho_root'
      AND payload->>'user'     = 'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17)));

-- (5) The identity itself. `service_account_oauth_clients.sva_id` is ON DELETE
--     RESTRICT, so this fails loudly if a machine credential was ever issued to
--     the operator. That is the wanted behaviour and not a case to code around:
--     a live credential belonging to a component that does not exist is
--     something a human has to look at, not something a migration should quietly
--     delete or quietly skip.
DELETE FROM kacho_iam.service_accounts
 WHERE id = 'sva' || substr(md5('kacho-vpc-operator'), 1, 17);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- No down path — see "IF THE OPERATOR EVER RETURNS" above. Re-seeding the
-- identity and its cluster read relation would restore a grant whose holder does
-- not exist, which is the state this migration removes.
SELECT 1;

-- +goose StatementEnd
