#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# assert-suites-green.sh — shared newman suite-green gate for EVERY kacho repo's
# .github/workflows/newman-e2e.yml. Run with cwd = kacho-iam/tests/newman
# (collections/ + out/ live there; all repos checkout kacho-iam@main and run the
# shared gen.py + run.sh, so the per-suite reports are identical).
#
# WHY this is shared (KAC — newman gate consolidation): the known-RED whitelist
# used to be duplicated inline in each repo's newman-e2e.yml. They drifted —
# get-malformed (api-gateway#73), delete-binding (iam#108), the user-per-account
# invite fix (iam#113, migration 0011) only ever reached kacho-iam's copy, so vpc/compute/nlb/api-gateway/deploy stayed RED on
# the very same shared suites that kacho-iam reported GREEN. One script = one
# source of truth; un-skip / whitelist edits land everywhere at once.
#
# FOUR OUTCOMES, FOUR NAMES. A request ends one of four ways, and this gate
# reports each separately because folding any of them into another is how a suite
# goes quiet:
#   answered + assertion passed  — the check ran and said yes;
#   answered + assertion failed  — the check ran and said no      (`failed`);
#   answered + SCRIPT CRASHED    — the check never got to run     (`SCRIPT FAILED`);
#   NOT ANSWERED                 — nothing came back              (`UNANSWERED`).
# Plus the degenerate case of a report containing no assertions at all, which is
# printed as NOTHING RAN rather than being allowed to read as "nothing failed".
# None of the three non-passing outcomes is ever subtracted, whitelisted or
# explained away.
#
# The third one was missing until 2026-07-29, and it was invisible by construction:
# newman books a test-script exception under `scripts`/`testScripts`, NOT under
# `assertions.failed` (an assertion that never ran cannot fail) and NOT under
# `requests.failed` (a response did arrive). A case whose script threw on its first
# line therefore reached this gate reading exactly like a clean one — `0 failed,
# 0 UNANSWERED` — with none of its checks performed. Measured on newman 6.2.2: a body
# the script cannot parse yields `assertions.failed=0, requests.failed=0,
# testScripts.failed=1`.
set -e
shopt -s nullglob

collections=(collections/*.postman_collection.json)
if [ "${#collections[@]}" -eq 0 ]; then
  echo "FAIL: no collections generated under collections/"
  exit 1
fi

failed_suites=()

# Totals across the suite. Printed as ONE line at the end so a reader gets the
# whole verdict in numbers without adding up per-collection lines: how many
# collections produced a report OUT OF how many exist, plus requests, assertions,
# failed assertions and UNANSWERED requests. "Collections reported out of
# generated" is the number that makes a silently truncated run visible — every
# other counter looks healthy when a collection simply never ran.
tot_reported=0
tot_requests=0
tot_asserts=0
tot_fails=0
tot_scripts=0
tot_unanswered=0
tot_empty=0

# ─── Execution-coverage gate ─────────────────────────────────────────────────
# The assertion-based verdict below can only see requests that RAN. A request
# that never executed produces no assertions and therefore no failures — so a
# collection that stopped after 6 of its 46 requests reads exactly like one that
# ran all 46 cleanly, and this gate called both GREEN.
#
# That was not hypothetical: a poll pre-request guard used
# `setNextRequest(null)` meaning "skip this poll when the create was rejected and
# no operation id exists". `setNextRequest(null)` does not skip a request, it ENDS
# THE RUN — and the guard fires deterministically on negative cases. The iam suite
# executed 1177 of 1502 requests (78.4%) while every collection was gated GREEN;
# what went unexecuted was the authz-deny data-leak matrix, the ROLE/INV/USR/ESC
# deny matrices and the fail-closed OpenFGA-outage case.
#
# exec-coverage.py closes that: per collection it requires every leaf request to
# have executed or to be STATICALLY EXPLAINED (an explicit `skipRequest()` guard,
# or a literal forward `setNextRequest('<name>')` that jumps over it), and it bans
# `setNextRequest(null)` outright. It runs BEFORE the assertion loop because a
# truncated run makes the assertion counts meaningless.
_gate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_gate_dir}/exec-coverage.py" ] && command -v python3 >/dev/null 2>&1; then
  if ! python3 "${_gate_dir}/exec-coverage.py" \
        --collections-glob 'collections/*.postman_collection.json' \
        --out-dir out; then
    failed_suites+=("execution-coverage")
  fi
  echo
else
  echo "FAIL: exec-coverage.py missing next to the gate — execution coverage unverified" >&2
  exit 1
fi

for col in "${collections[@]}"; do
  name=$(basename "$col" .postman_collection.json)
  report="out/${name}.json"
  if [ ! -f "$report" ]; then
    echo "WARN: no report for $name (newman didn't run for this suite)"
    failed_suites+=("$name(no-report)")
    continue
  fi
  fails=$(jq -r '.run.stats.assertions.failed // 0' "$report")
  # UNANSWERED — requests newman attempted that never produced a response (DNS,
  # refused connection, TLS, timeout). NEVER subtracted, for any reason.
  #
  # A request has three possible ends, and this gate used to have names for only
  # two: a response arrived (whatever its status), an assertion said no, or
  # NOTHING CAME BACK. The third had no home, so it was filed under the first.
  #
  # What stood here was a filter that removed EAI_AGAIN/ENOTFOUND/getaddrinfo
  # from this count, on the stated grounds that an unreachable endpoint IS the
  # internal-only invariant being asserted. It is not. "I could not reach it"
  # and "it refused me" are different findings, and only one of them is evidence.
  # The filter, together with a case assertion phrased "if the status code is
  # undefined, return" (a pass) and an execution-coverage check that read a
  # cursor position as proof of execution, meant all three layers reported
  # success for eight ban-#6 negatives — the checks that Internal* RPCs are not
  # reachable on the advertised external endpoint — while none of them ran. The
  # verdict printed "0 failed requests".
  #
  # The harness now reaches the external listener (deploy/scripts/newman-*.sh
  # forward the api-gateway TLS port and inject externalBaseUrl), so an
  # unanswered request here means the harness is broken or the endpoint is down.
  # Either is worth stopping for; neither is a green check.
  unanswered=$(jq -r '.run.stats.requests.failed // 0' "$report")
  # ANSWERED/ASSERTED — printed so that "nothing ran" is visibly different from
  # "nothing failed". Zero of both is the shape every silent failure took.
  asserts=$(jq -r '.run.stats.assertions.total // 0' "$report")
  reqs=$(jq -r '.run.stats.requests.total // 0' "$report")
  # SCRIPT FAILED — the response arrived and the case's own script threw BEFORE
  # reaching its assertions. A fourth end for a request, and it had no home here: it
  # is not `assertions.failed` (nothing was asserted) and not `requests.failed`
  # (something was answered), so a case that checked NOTHING was indistinguishable
  # from a case that checked everything and agreed.
  #
  # Pre-request scripts count too, for a sharper reason than symmetry: in these suites
  # the pre-request script is what upserts the Authorization header naming the SUBJECT
  # the case is about (gen.py::_auth_pre_script). A crash there does not skip the
  # request — it sends it with whatever header was already on it, i.e. as a DIFFERENT
  # principal, and the expected 401/403 then still holds for the wrong reason.
  #
  # NEVER subtracted and never whitelisted: an exception is not a known-RED product
  # gap, it is a case that did not run.
  scripts_failed=$(jq -r '((.run.stats.testScripts.failed // 0) + (.run.stats.prerequestScripts.failed // 0))' "$report")

  # Known-RED whitelist (RED-by-design, each tracked). Subtraction clamps to 0,
  # so when a case is genuinely fixed the gate still passes; a NEW failure
  # widens the diff and fires the gate. Extend the alternation consciously.
  #
  #   EVERY entry below carries the date it was last CHECKED AGAINST BEHAVIOUR and
  #   the command that checked it. An entry without one is not a known red, it is an
  #   unverified claim about the product — and an unverified claim puts work in the
  #   queue that may not be needed, or keeps a real regression invisible. Re-checking
  #   costs one suite run; leaving it costs somebody a day.
  #
  #   REMOVED 2026-07-29 — any-authz-gated-rpc-during-openfga-outage. The entry
  #   said the case "needs external `kubectl scale openfga --replicas=0`
  #   orchestration" and would stay "permanent until somebody writes it", pointing
  #   at a `scripts/run-failclosed.sh` that existed nowhere in the tree. So for as
  #   long as the entry lived, the invariant it names — no answer about permissions
  #   must never be counted as "allowed" — was not checked at all, and the suite
  #   read green. A case that needs an unavailable dependency does not get a
  #   waiver, it gets a wave that CREATES the condition (testing.md).
  #   That wave now exists: the case moved to its own collection
  #   (cases/authz-failclosed.py), the wrapper it always named was written
  #   (scripts/run-failclosed.sh — scales the store to zero, waits out the
  #   gateway's decision cache, runs the one collection, restores and waits for
  #   ready), and deploy/scripts/newman-parallel.sh drives it as WAVE 3 after every
  #   other suite has reported. No exclusion replaces it: if the wave does not run,
  #   there is no report and this gate says `authz-failclosed(no-report)`.
  #   - inv-get-account-allow-warm-cache — FGA grant→Check warm-cache window.
  #     CHECKED 2026-07-28 (same run): PASSED, converging on the third poll. Kept
  #     because a timing mask is not refuted by one unloaded run — this one exists
  #     for the loaded umbrella. Narrow or drop it from a CI run, not from this one.
  #
  #   PRUNED 2026-07-28 — THE WHOLE `PRO-Robotech/kacho#9` FAMILY, sixteen tokens,
  #   ALL VERIFIED BY RUNNING THE SUITES. Every one of them rested on a single
  #   stated mechanism: that the verbs on a binding, on a service account and on
  #   their neighbours were directly-assignable only, with nothing inherited from
  #   the account or the cluster, so the identity that administers everything could
  #   not act on an object somebody else had created. That mechanism was removed on
  #   2026-07-27 (d907a74e, e3acea6d, a96dbe1a — the three super-admin tiers now
  #   cascade in proto/kacho/cloud/iam/v1/fga_model.fga, and nothing below them
  #   does). The masks were written 2026-07-26, before that change, and nobody came
  #   back to them — so for two days this gate asserted something about the product
  #   that had stopped being true, which is the whole failure mode this list exists
  #   to prevent.
  #   Measured 2026-07-28 on kind-kacho:
  #     rbac-subject-channel-equivalence — teardown-user-revoke and
  #       teardown-usr-iso-revoke return HTTP 200 (the entry claimed a permanent
  #       403); all seven `*-gone` convergence probes pass; the whole
  #       IAM-CH-GRP-MEMBERSHIP-FLIP-OK case passes end to end, including
  #       read-after-add and flip-gone.
  #     iam-authz-grant-check-propagation — 35 of 36 assertions pass;
  #       issue-sakey returns HTTP 200, and probe-check-after-revoke,
  #       poll-op-plaintext and re-get-op-redacted all pass with it, exactly as
  #       their own notes predicted they would once issue-sakey cleared.
  #     iam-invite-grant-fga — 49/49, zero failures; poll-bind-project-anchor and
  #       te4-post-bind-project-viewer both pass, including "bind NOT
  #       FailedPrecondition (assignable)". Neither the product gap of the first
  #       justification nor the stale case of the second is there any more.
  #   Tokens removed: probe-check-after-revoke, poll-op-plaintext,
  #   re-get-op-redacted, poll-bind-project-anchor, te4-post-bind-project-viewer,
  #   teardown-user-gone, teardown-grp-gone, teardown-nonmem-gone,
  #   revoke-binding-gone, teardown-sa-gone, teardown-sa-iso-gone,
  #   teardown-usr-iso-gone, teardown-user-revoke, teardown-usr-iso-revoke,
  #   issue-sakey, ^IAM-CH-GRP-MEMBERSHIP-FLIP-OK.
  #   PRO-Robotech/kacho#9, kacho-iam#212 and kacho-iam#217 should be closed as
  #   fixed. The one remaining red in iam-authz-grant-check-propagation was NOT
  #   masked and must not be: AUTHZGCP-BIND-LIST-BY-SUBJECT-FOREIGN-DENY ::
  #   inv-lists-aaa-subject denied correctly (403) but the response carried no
  #   ErrorInfo detail, so the case could not tell a scoped deny from a catalog
  #   miss. The contract fix landed in the service (iam now attaches the reason,
  #   domain and action on a refusal it decides itself, for every method on the
  #   scope-filtered band). Expected green on the next stand run; unit coverage
  #   is services/iam/internal/authzguard/deny_details_test.go, which enumerates
  #   the band FROM the catalog. Left recorded rather than deleted until a stand
  #   run observes it — the fix is proven in-process, not end to end.
  #
  #   PRUNED 2026-07-26 (the list shrinks, never grows). Every name below matched
  #   NO request in ANY generated collection — the cases were deleted earlier and
  #   the mask outlived them, so it protected nothing while standing ready to
  #   silently absorb any future step that reused the name:
  #     health-check, inv-list-pending, inv-list-reports, inv-get-foreign-pending,
  #     aaa-creates-eligibility, aab-approves-some-pending, list-perms-on-internal.
  #   bootstrap-approveB was pruned with its case: AUTHZGCP-BG-APPROVEB-CLUSTERADMIN-GRANT
  #   called `/iam/v1/breakGlassRequests/{id}:approveB`, an RPC removed from the
  #   product by migration 0006, so the step could only ever receive the gateway's
  #   catalog-miss 403 and its `code < 500` assertion was a tautology. See the
  #   removal note in cases/iam-authz-grant-check-propagation.py.
  #
  #   PRUNED 2026-07-26 (second sweep — SAME class, this time on parent.name). The
  #   whole alternation was re-matched against every folder + request of every
  #   collection under services/*/tests/newman/collections (8211 leaf requests) and
  #   against the case sources they are generated from. TWELVE tokens matched
  #   NOTHING anywhere, because the suites they guarded were rewritten, not fixed:
  #     compute (6) — ^INST-AD-, ^INST-DD-, ^INST-DISK-DEL-WHILE-ATTACHED,
  #       ^INST-DEL-STATE-, ^INST-NIC-, ^INST-CR-CRUD-BOOT-DISK-ID-OK. The instance
  #       suite is now instance-redesign.postman_collection.json and every case is
  #       named INST-RD-* (COMP-1-nn), which the ^INST-<verb> anchors cannot match.
  #       The storage-dependent attach/detach/boot-mirror cases no longer exist at
  #       all — grep of services/compute/tests/newman/cases is empty for all six.
  #     nlb (6) — ^NLB-START-CRUD-OK, ^NLB-STOP-CRUD-OK,
  #       ^NLB-STOP-STATE-ALREADY-STOPPED, ^NLB-DEL-STATE-HAS-ATTACHED,
  #       ^NLB-ATT-STATE-REGION-MISMATCH, ^NLB-ATT-NEG-TG-UNKNOWN. Start/Stop were
  #       removed from the product (iam migration 0059_nlb_operator_drop_start_stop)
  #       and the LB suite has no NLB-ATT-* / -HAS-ATTACHED folder; the surviving
  #       delete-state cases are -HAS-LISTENER and -PROTECTION.
  #   Removing a token that matches nothing cannot change any verdict — it only
  #   takes away the trap where a future step reusing one of those names would be
  #   silently absorbed.
  #   - (#193 FIXED — removed from whitelist) get-confirms / get-confirms-update /
  #     list-with-account were RED because Role.Get/List filtered by the `v_list`
  #     verb relation, which has NO tier→v_* bridge in the FGA model, so a role's
  #     creator / account-admin did not resolve it on their own role → 404 / absent.
  #     Fixed by switching Role.Get/List per-object enforcement to the `viewer` TIER
  #     relation (cascades from account-tier, consistent with account/project List);
  #     the owner now sees their own role, foreign accounts still 404 (no-leak).
  #     IAM-ROL-CR-CRUD-OK get-confirms and IAM-ROL-UP-CRUD-OK get-confirms-update
  #     (single-Get) went GREEN with #193. IAM-ROL-LS-SYSTEM-PLUS-CUSTOM-WITH-ACCOUNT
  #     list-with-account additionally needed a CASE-side page-boundary fix: the
  #     catalog floor is 56 system roles (created_at = migration time → sort first)
  #     and the run-created crudRoleId (created_at = NOW()) landed past the default-50
  #     page; the case now lists with pageSize=1000 so the visible role is returned on
  #     one page (read==enforce already held). All three cases are GREEN in this build
  #     and none is in the known-RED whitelist. (#184 ls-ps1001 was fixed earlier.)
  #   PRUNED 2026-07-28 (third sweep — prose describing a mask that was not there).
  #   neg-v_delete-denied / neg-v_update-denied carried a full paragraph of
  #   justification here, but neither token was in the alternation and neither
  #   matches any request in any collection or case file. A reader budgeting effort
  #   from this list would have counted two open per-verb enforcement reds that do
  #   not exist. (kacho-iam#188 should be re-checked on its own evidence.)
  #   - T31-LBLREVOKE-NLB-* — UN-WHITELISTED 2026-07-28, VERIFIED BY RUNNING IT.
  #     The entry claimed a live product gap ("create-emit works, update-label-remove
  #     does not revoke"). That claim was written 2026-07-26 09:32 and the gap was
  #     closed the SAME DAY at 16:19 (f9574de6, services/nlb — the registration path
  #     was corrected on create, update and delete, with seven Go regressions in
  #     services/nlb/internal/apps/kacho/api/listener/update_label_revoke_test.go
  #     covering label-clear, label-set, re-grant, EMPTY-MASK full PATCH, a drainable
  #     create intent, the delete retraction, and the non-labels no-op). Nobody came
  #     back to the mask, so for two days the gate carried a false statement about
  #     the product — the class this list exists to prevent.
  #     Evidence for removal (2026-07-28, kind-kacho, nlb image built 2026-07-26
  #     17:02 i.e. after the fix): collections/label-revoke-nlb.postman_collection.json
  #     ran 47/47 requests, 23/23 assertions, ZERO failures — including the very
  #     assertion the entry called permanently red, `lsn-post-revoke-deny: Check
  #     denies (allowed !== true)`, alongside `lsn-post-grant-allow` and
  #     `lsn-pre-grant-deny`. Live corroboration: this service's registration queue,
  #     described at the time as never having delivered a single row, is 758/758
  #     delivered with nothing pending.
  #     kacho-iam#217 should be closed as fixed rather than retitled again.
  #   - IAM-ACB-DP-* (rbac-2026 P6 deletion_protection): UN-WHITELISTED (rbac-2026
  #     P7). Both the iam handler (iam#222) and the gateway public-mux
  #     AccessBindingService.Update route (gateway#97) are now in main, so the
  #     update-clear / teardown-clear PATCH /iam/access-bindings/{id}:update steps
  #     resolve and the case runs green end-to-end without whitelisting.
  #     (The seven rbac-subject-channel-equivalence `*-gone` convergence probes and
  #     ^IAM-CH-GRP-MEMBERSHIP-FLIP-OK were removed here in the same 2026-07-28
  #     sweep — see the kacho#9 block near the top of this comment. The FLIP entry
  #     had already been carried "WITHOUT a mechanism, pending a healthy run": that
  #     run happened, and the case passes, so it is gone rather than re-justified.)
  # VPC AUTHZ-*-LS-{OWN,CROSS}-NOB (kacho-iam#276): cross-suite fixture collision, NOT
  # an over-grant. The iam-suite IAM-ACB-CR-CRUD-OK grants `userNOB` the global `*.*` view
  # role on account-A/-B (iam LS-NOB cases assert NOB DOES see), so the iam reconciler
  # legitimately materializes per-object viewer/v_list on every network in scope (#224
  # owner-materialization parity). The vpc LS-NOB cases assume NOB = no-access. NOB is in
  # fact authorized → these stay RED until the owner-decided semantics/test-hygiene fix
  # (kacho-iam#276 A vs B). Assertions still RUN and report; the canary in newman-e2e.yml
  # encodes the live no-leak gate for a genuinely grant-less subject.
  # VPC AUTHZ-*-LS-OWN-AAB (kacho-iam#276 extend): the SAME cross-suite collision as
  # LS-*-NOB. The iam-suite RBACSUBJ-GROUP-GRANTS-MEMBER-OK adds `userAAB` to a group and
  # binds ROLE_VIEW (`*.*` read/list) to that group @ ACCOUNT:{{accountAId}} (=authz-test-a,
  # the shared umbrella env account) → AAB gains account-A viewer/v_list via the group-userset;
  # keystone (e195632) legitimately materializes per-object v_list on every account-A object →
  # AAB sees all of project-A1. The vpc LS-OWN-AAB cases assume AAB = account-B-only. AAB is in
  # fact authorized (proven by the LS-CROSS-AAA GREEN asymmetry: vpc List DOES scope-filter, a
  # blanket bug would leak symmetrically). Only LS-OWN-AAB is whitelisted — LS-CROSS-AAB is a
  # legit ALLOW (AAB owns account-B) and stays enforced. Real fix = de-share the umbrella
  # account across suites (kacho-iam#276); until then RED-by-fixture-collision, same as NOB.
  # IAM-USR-LS-AUTHZ-MEMBER-NO-OVERSHOW (kacho-iam#276 family, SAME-SUITE variant): NOT a leak.
  # The case asserts jwtInvitee — modelled as a "plain member of accountB, no user-viewer
  # grant" — lists accountB users and MUST see 0. But the SHARED tests/authz-fixtures/setup.sh
  # seeds `ensure_binding "$USER_INV" "$ROLE_ADMIN" "account" "$ACCOUNT_B" "$JWT_AAB"` (~L434,
  # comment "INV — owner-of-B (his home) — admin in account-B") → jwtInvitee holds an ACTIVE
  # ROLE_ADMIN AccessBinding on accountB, so the account-tier cascade LEGITIMATELY resolves
  # viewer/v_list on accountB's users → user.List?accountId=accountBId returns ≥1. The
  # "no-grant member" premise is contradicted by the fixture; jwtInvitee IS authorized —
  # independently proven GREEN by IAM-ACC-LS-AUTHZ-SCOPE-INVITED-ADMIN-SEES (asserts the
  # invitee's admin binding on accountB is visible). Legit ALLOW, not membership-over-show.
  # CHECKED 2026-07-28 — the three kacho-iam#276 fixture-collision entries above
  # (LS-*-NOB, LS-OWN-AAB, MEMBER-NO-OVERSHOW) are STILL TRUE, on two counts. The
  # seed line they name is still there (tests/authz-fixtures/setup.sh:706 binds the
  # invitee as an admin of account-B), and the collision is directly observable:
  # `GET /iam/v1/accounts/<account-A>` as the "no bindings" subject returns 200 on
  # the live stand. These subjects ARE authorized; the cases assume they are not.
  # The fix is fixture separation, not a mask edit — do not re-justify, de-share.
  # Real fix = de-share the umbrella accountB across iam suites (kacho-iam#276); until then
  # RED-by-fixture-collision. The assertion still RUNS and reports; a genuinely grant-less
  # subject's no-leak stays gated by IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY, which is NOT
  # whitelisted (a real over-show still fails honestly).
  # COMPUTE instance-suite — the whole block that stood here (INST-AD-* / INST-DD-* /
  # INST-DISK-DEL-WHILE-ATTACHED / INST-DEL-STATE-* / INST-NIC-*, justified as
  # storage.enabled=false + Noop'd vpc-internal :9091 CI-infra gaps) DESCRIBED CASES
  # THAT NO LONGER EXIST, and so did its own "NOT whitelisted, stay RED" counter-list
  # (INST-CR-VAL-CORES-ODD-INVALID / INST-CR-VAL-MISSING-BOOT-DISK-SPEC /
  # INST-UPD-RESOURCES-REQUIRES-STOPPED / INST-CR-CRUD-OK / INST-DEL-CONF-RESPONSE-EMPTY
  # — grep of services/compute/tests/newman/{cases,collections} is empty for every one).
  # The instance suite was rewritten as instance-redesign / INST-RD-* (COMP-1-nn) and
  # the attach-detach coverage went with the compute→storage split. Six masks and a
  # counter-list survived their subject; all are pruned above. Whatever the redesigned
  # suite needs — if anything — must be argued from ITS names on ITS evidence, not
  # inherited from the retired one.
  # NLB owner-tuple materialization lag (kacho#11) — NLB-{CR,UPD,DEL,MV,LIFECYCLE}
  #   + LST-{GET,UPD}-* (parent.name). The START / STOP / ATT / DEL-STATE-HAS-ATTACHED
  #   arms of this enumeration were pruned 2026-07-26 (see the second sweep above): Start
  #   and Stop are no longer product RPCs and no NLB-ATT-* folder exists, so those four
  #   masks had nothing left to cover. NOT a correctness/authz bug and NOT an over-grant: the
  #   owner/creator FGA tuple for a just-created LB/listener materializes eventually-consistent
  #   (at-least-once fga_register_drainer + reconciler), and nlb races LAST in the umbrella
  #   (iam→vpc→compute→nlb) so the drainer backlog peaks and the first post-create Get/Update/
  #   Delete/Start/Stop/Move/Attach of the caller's OWN fresh LB (and Get/Update of its OWN fresh
  #   listener) can 403 (lacks v_update/v_delete/v_get) / 404 (hide-existence read) at the authz
  #   gate before the tuple is visible. The CLIENT already retries (retry_until_authorized, budget
  #   raised 40→60 ×500ms = ~30s in gen.py, round 4); ci-rep4 measured async op-latency ~1.5s
  #   (poll-op p90=3) but materialization p50~10s with a heavy tail — 31/83 wrapped steps exceeded
  #   the old 16s window. This whitelist covers ONLY the residual saturation tail past ~30s under
  #   peak nlb-last backlog — assertions still RUN and report (signal preserved), just not gate-
  #   blocking. Eventual-consistency LATENCY, not a correctness defect (same class + rationale as
  #   the revoke-deny-latency whitelist kacho-iam#257). Subtraction clamps to 0, so a case that
  #   materialises within 30s and passes contributes nothing; a NEW/real failure widens the diff.
  #   NOT whitelisted (stay RED / fully gated, never masked):
  #     - NLB-GTS-* — genuine finding: GetTargetStates → 400 "target_group_id: required" (a
  #       contract/case mismatch, NOT owner-tuple lag).
  #     - NLB-GET-STATE-LEAN-PROJECTION — carries no-leak assertions (does-NOT-leak
  #       v4Source/networkId/subnetId/announce); whitelisting by case would risk masking a real
  #       leak, so it stays gated (its GET-lag relies on the budget=60 fix, not the whitelist).
  #     - cross-resource XRES-* and listener LST-CR-* — create-fail class: cross-service peer
  #       visibility ("subnet <id> not found") + parent-LB `editor`-lag on UNWRAPPED child-create
  #       steps (loadbalancer.listeners.create). Task-excluded (NOT owner-tuple update/del/get);
  #       fixing them needs create-step wrapping / drainer throughput, tracked in kacho#11.
  #   Retire this alternation once drainer throughput closes the tail (kacho#11).
  #   NOT RE-CHECKED 2026-07-28, and deliberately so — stated here rather than left
  #   as a silent gap. This mask is about a saturation tail that only appears when
  #   nlb runs LAST behind the other suites, so an unloaded single-suite run cannot
  #   confirm or refute it: green would prove nothing and red would prove nothing.
  #   It has to be re-checked from a full parallel umbrella run's reports.
  #   Two of these seventeen are already known to be removable on evidence that is
  #   in the tree: services/nlb/tests/newman/docs/RESULTS.md line 35 records that
  #   ^LST-UPD-CRUD-OK and ^LST-UPD-STATE-DEFAULT-TG-REGION-MISMATCH "pass
  #   genuinely" and recommends pruning them, and its third recommendation
  #   (^NLB-ATT-STATE-REGION-MISMATCH) was already carried out. Do those two at the
  #   next umbrella run rather than re-reading this paragraph.
  # ---------------------------------------------------------------------------
  # ROUND-4 CONSOLIDATION — confirmed-product-bug-floor (each tracked by a GitHub
  # issue; NONE masks a leak or a fixable fixture; every assertion still RUNS +
  # reports, only the gate is un-blocked; each self-heals — the subtraction clamps
  # to 0 once the product fix lands, so a genuine regression re-widens the diff and
  # re-fires the gate).
  #   (teardown-user-revoke / teardown-usr-iso-revoke / issue-sakey stood here as the
  #   "confirmed product-bug floor" of this round. All three were REMOVED 2026-07-28:
  #   the inherited-access change of 2026-07-27 closed what they described, and the
  #   suites now return 200 on each of them. See the kacho#9 block above for the
  #   measurements. Two of the three were also unanchored substrings that quietly
  #   absorbed neighbouring `*-await` steps and `issue-sakey-rya15`, so they covered
  #   more than they declared — one more reason not to leave them standing.)
  #   - (^INST-CR-CRUD-BOOT-DISK-ID-OK — PRUNED 2026-07-26 with the rest of the retired
  #     compute instance suite; the case, and the INST-CR-CRUD-OK / INST-DEL-CONF-
  #     RESPONSE-EMPTY it was contrasted against, no longer exist anywhere in the tree.
  #     PRO-Robotech/kacho#10 tracked a storage-mirror read-back that this suite no
  #     longer performs.)
  #   - ^SUBNET-LF-D-VISIBLE / ^SUBNET-LF-D-NOLEAK / ^SUBNET-LF-D-NONE — UN-WHITELISTED
  #     2026-07-28, and the reason is worth reading rather than skimming, because the
  #     entry was wrong in an unusual direction: these three cases are not red. They
  #     are GREEN, and they are green for a bad reason.
  #     Measured 2026-07-28 (`newman run collections/list-filter-d…json`, vpc): 6/6
  #     assertions pass, zero failures, so the masks subtract nothing and never have
  #     while the case read this way. But the three list assertions are phrased
  #     "List reachable (200) or method-gated (403, fixture absent)" — and 403 is
  #     EXACTLY the condition the entry below describes as the defect. Every one of
  #     the ~27 polls in each case came back 403 and the case still declared itself
  #     satisfied. So the restriction the mask was written for is still live, the
  #     probe for it cannot fail, and the mask on top made the pair look accounted
  #     for. Removing the mask changes no verdict; making the assertion discriminate
  #     would, and that is the actual outstanding work (kacho-iam#276).
  #     The two per-object canaries in the same suite DO discriminate and DO pass
  #     honestly: SUBNET-LF-D-GET-404 (hidden subnet → 404, no existence oracle) and
  #     SUBNET-LF-D-GET-OK (visible subnet → 200). Per-object Get resolves the seeded
  #     grant; it is List that does not. Neither canary was ever whitelisted — leave
  #     it that way.
  # NOT whitelisted (honest canaries — stay RED, never masked):
  #   IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY (iam-user) — jwtNoBindings lists
  #   ?accountId=accountA → sees 1 user. Root: #276 cross-suite fixture pollution makes NOB
  #   legit-authorized, compounded by the listBySubject non-self 403 that blocks the
  #   pre-clean (kacho-iam#276). This is THE must-DENY user-list over-show canary; keeping
  #   it un-whitelisted preserves the honest gate (also documented as an env-flake that
  #   clears on re-run). SUBNET-LF-D-GET-404 (vpc) — the per-object existence-no-leak canary.
  #   SG-DEL-NEG-NIC-ATTACHED (vpc security-group, kacho-vpc#27) — deliberately NOT
  #   whitelisted: SEC-hardening r2 converted it from a masked pm.test.skip to a gate-
  #   blocking persistent-RED so the missing within-service SG-in-use refcheck stays
  #   visible pressure. It fires the gate honestly (declared rule #13 known-failing in
  #   the vpc RESULTS.md); leave RED until the product DB refcheck lands.
  # HARNESS-CONFIG failures are NEVER subtracted. A `harness config: <var> is set`
  # assertion fires only when the runner failed to inject a variable the case needs
  # (see gen.py::require_env_url). That is a broken harness, not a known-RED product
  # gap, and 15 of the 89 guarded requests happen to sit under case names this
  # whitelist already matches — so without the explicit exclusion below, losing a
  # variable could be absorbed by an unrelated alternation entry and the suite would
  # go quiet again in exactly the way this whole mechanism exists to prevent.
  if [ "$fails" -gt 0 ]; then
    known_red=$(jq -r '[.run.failures[]? | select((.error.name? // "") == "AssertionError") | select((((.error.test? // "") | startswith("harness config:")) | not)) | select((.source.name? // "" | test("inv-get-account-allow-warm-cache")) or (.parent.name? // "" | test("^AUTHZ-[A-Z-]+-LS-(OWN|CROSS)-NOB|^AUTHZ-[A-Z-]+-LS-OWN-AAB|^IAM-USR-LS-AUTHZ-MEMBER-NO-OVERSHOW|^NLB-LIFECYCLE-CONF |^NLB-CR-CRUD-OK |^NLB-CR-CRUD-WITH-DESCRIPTION |^NLB-CR-CRUD-DELETION-PROTECTION-TRUE |^NLB-UPD-STATE-IMMUTABLE-VIP-SOURCE |^NLB-UPD-STATE-IMMUTABLE-PROJECT |^NLB-UPD-STATE-IMMUTABLE-PLACEMENT |^NLB-UPD-STATE-NO-CHANGE |^NLB-UPD-STATE-MASK-EMPTY |^NLB-UPD-CRUD-DRAIN-TOGGLE |^NLB-MV-IDM-SAME-PROJECT |^NLB-MV-CRUD-OK |^NLB-DEL-CRUD-OK |^NLB-DEL-STATE-HAS-LISTENER |^LST-GET-CRUD-OK |^LST-UPD-CRUD-OK |^LST-UPD-STATE-DEFAULT-TG-REGION-MISMATCH ")))] | length' "$report")
    fails=$((fails - known_red))
    if [ "$fails" -lt 0 ]; then fails=0; fi
  fi

  tot_reported=$((tot_reported + 1))
  tot_requests=$((tot_requests + reqs))
  tot_asserts=$((tot_asserts + asserts))
  tot_fails=$((tot_fails + fails))
  tot_scripts=$((tot_scripts + scripts_failed))
  tot_unanswered=$((tot_unanswered + unanswered))

  echo "$name: ran $reqs request(s) / $asserts assertion(s) — $fails failed (after known-RED skip), $scripts_failed SCRIPT FAILED, $unanswered UNANSWERED"

  # Name what did not answer. A count alone cannot be acted on, and the whole
  # point of separating this category is that somebody reads it.
  # Request-level errors are the ones carrying a transport errno (`error.code`:
  # ECONNREFUSED, ENOTFOUND, ETIMEDOUT…); a script exception carries none, which is
  # what keeps these two listings from describing each other's entries.
  if [ "$unanswered" -gt 0 ]; then
    jq -r '[.run.failures[]? | select((.error.name? // "") != "AssertionError")
            | select((.error.code? // "") != "")
            | "    NOT EXECUTED: \(.source.name? // "?") <- \(.error.message? // "no response")"]
           | unique | .[]' "$report" 2>/dev/null || true
  fi

  # Name what crashed. The message is the whole diagnosis here — "Unexpected token
  # '<'" says the body was not JSON, "X is not defined" says the script was edited
  # without being run — so it is printed rather than counted.
  if [ "$scripts_failed" -gt 0 ]; then
    jq -r '[.run.failures[]? | select((.error.name? // "") != "AssertionError")
            | select((.error.code? // "") == "")
            | "    SCRIPT FAILED (its assertions never ran): \(.source.name? // "?") <- \(.error.name? // "?"): \(.error.message? // "")"]
           | unique | .[]' "$report" 2>/dev/null || true
  fi

  # NOTHING RAN. A report with no assertions is not a clean suite, it is a suite
  # that did not happen — and it reaches this loop reading exactly like a perfect
  # one (0 failed, 0 unanswered). Distinguishing the two is the reason this line
  # exists; without it "zero executed" and "zero failed" are the same verdict.
  empty=0
  if [ "$asserts" -eq 0 ]; then
    echo "    NOTHING RAN: $name produced 0 assertions — a suite that asserts nothing cannot pass"
    empty=1
    tot_empty=$((tot_empty + 1))
  fi

  if [ "$fails" -gt 0 ] || [ "$scripts_failed" -gt 0 ] || [ "$unanswered" -gt 0 ] || [ "$empty" -gt 0 ]; then
    failed_suites+=("$name")
  fi
done

# The verdict in numbers, on one line. Read the FIRST pair first: a run that
# stopped early leaves every other counter looking healthy.
echo "TOTAL: ${tot_reported}/${#collections[@]} collection(s) reported, ${tot_requests} request(s), ${tot_asserts} assertion(s), ${tot_fails} failed, ${tot_scripts} SCRIPT FAILED, ${tot_unanswered} UNANSWERED, ${tot_empty} report(s) with no assertions"

# The same numbers into the job summary when running in CI. Each gate step is
# short, so these blocks land in the interface one after another AS THE STEPS
# FINISH — which is what makes the summary readable during a run, unlike a single
# write at the very end. Each block is self-contained (no shared table header
# somebody else has to have written first).
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  _label="${SUITE_LABEL:-$PWD}"
  # `if`, not `a && b`: under `set -e` a false test at statement level aborts the
  # script — and the abort would happen right where the numbers are printed.
  if [ "${#failed_suites[@]}" -gt 0 ]; then
    _verdict="RED — ${failed_suites[*]}"
  else
    _verdict="GREEN"
  fi
  {
    printf '### гейт `%s` — %s\n\n' "$_label" "$_verdict"
    printf 'коллекций с отчётом **%s из %s** · запросов %s · утверждений %s · **упало %s** · скрипт упал %s · без ответа %s · пустых отчётов %s\n\n' \
      "$tot_reported" "${#collections[@]}" "$tot_requests" "$tot_asserts" \
      "$tot_fails" "$tot_scripts" "$tot_unanswered" "$tot_empty"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "${#failed_suites[@]}" -gt 0 ]; then
  echo "FAIL: suites with failures: ${failed_suites[*]}"
  exit 1
fi
echo "All ${#collections[@]} suites GREEN."
