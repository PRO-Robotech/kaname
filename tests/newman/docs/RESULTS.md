# Newman regression — results & known-failing disposition

The suite is gated by `scripts/assert-suites-green.sh`. **The gate subtracts nothing.**
It reports the counts newman reported — assertions failed, script crashes, unanswered
requests, reports with no assertions — and any of them above zero fires it. Outstanding
red is carried here, as a number and a case list, never as a deduction in the gate.

## Самочтение записи пользователя: ALLOW-полоса перенесена к своему производителю (2026-08-18)

Последние **4** упавших утверждения релиза `gates-verdict` — **2** шага набора
`authz-deny`, `AUTHZ-USR-GT-A-NOB` и `AUTHZ-USR-GT-B-INV`, оба с
`expected 404 to equal 200` на `User <id> not found`.

**Продуктового дефекта здесь не было: 404 — правильный ответ на запрос, который эти
шаги делают.** Клетка ALLOW не имела производителя, и основание структурное, а не
«не доехала выдача»:

| факт | предикат |
|---|---|
| читать свою запись разрешает отношение, принимающее ТОЛЬКО тип `user` | `awk '/^type iam_user/,/^type [^i]/' proto/kacho/cloud/iam/v1/fga_model.fga \| grep 'define subject'` → `[user]` |
| каждый предъявитель матрицы — служебная учётка | `tests/authz-fixtures/principal_pairings.py`, раздел про то, что `userNOBId` / `userINVId` / `userPureNoBindingsId` — ТОЛЬКО цели привязки |
| человеческий предъявитель не проходит порог повышения | `tests/authz-fixtures/mint_rs256.py`, раздел `user_platform_token`: `acr` не несётся, а от порога освобождена только машина. Прежняя редакция называла второй причиной жёсткий kacho-внутренний `aud` — этой причины больше нет: выпуск персонального токена не объявляет адресата у внешнего поставщика (#1121) |

Значит служебная учётка не удовлетворяет это отношение НИ ПРИ КАКОЙ выдаче. Клетка
стояла ALLOW с 2026-07-26 (`c4960673`, раздел ниже): тогда цель переставили вслед за
субъектом, но принципал остался служебной учёткой — переставили ЦЕЛЬ, а не
ПРЕДЪЯВИТЕЛЯ, поэтому самочтением строка не стала ни разу.

**Сделано — не вычет и не маска:**

- обе клетки → `DENY`; строка утверждается СТРОГО (`read_deny_asserts`: 404 **и**
  grpc 5 **и** отсутствие утечки причин отказа) и сохраняет свой предмет — анти-BOLA:
  ни администратор соседнего аккаунта, ни администратор проекта, ни приглашённый не
  читают чужую запись пользователя;
- ALLOW-полоса **не потеряна, а перенесена туда, где у неё есть производитель** —
  `AUTHZ-USR-GT-SELF-CEREMONY`, человеческим предъявителем волны церемонии
  (`jwtHumanCeremonyNoBindings` + `ceremonyNoBindingsUserId`). Коллекция `authz-deny`
  в эту волну входит уже, проверяется машинно:
  `python3 tests/authz-fixtures/ceremony_credentials.py --stems --suite services/iam/tests/newman`.

Без этого переноса строки `USR-GT-*` стали бы сплошным отрицанием, и полностью
отказавший `UserService.Get` оставил бы матрицу зелёной.

**Остаточный долг, названный явно, чтобы клетку не «восстановили» обратно:**
самочтение проверяемо **только** в волне церемонии — машинный посев принципала типа
`user` не производит и не может (см. предикаты выше). В машинной волне у этой полосы
производителя нет; относиться к её отсутствию там как к пробелу фикстуры — ошибка,
это свойство модели аутентификации, а не пропуск.

## Known-RED subtraction removed (2026-07-30)

The gate used to deduct a "known-RED" set from each suite's failure count before
deciding. It was narrowed twice and then removed, and what settled it was the shape of
the three revisions rather than the size of any one:

| revision | selected by | absorbed |
|---|---|---|
| v1 | folder name | 259 assertions in 17 folders — including a P1 leak canary that merely sat in a matched folder |
| v2 | step name inside those folders | fewer, same kind |
| v3 | step-name **suffix** (`-rya<N>`, `get-abs<N>`) | 27 assertions — including a placement-coherence **negative**, `LST-UPD-STATE-DEFAULT-TG-REGION-MISMATCH` |

Each narrowing was a correct local fix, and none of them touched the defect. The
predicate keys on a **name**, while the thing it claimed to select — "this failure is the
known materialization lag, not a real refusal" — is a statement about the **reason** a
step failed, and the reason is not in the name. So it cannot tell its subject from a
stranger at any width; narrowing only reduced how many strangers it caught per run. A
fourth narrowing would have been the same move a third time.

Injection check on a real report (JSON-отчёт коллекции authz-deny в каталоге `out/`
суиты — он под `.gitignore`, отчёт производит прогон; run 2026-07-26): newman
reported `assertions.failed=3`; the gate printed **2**. The one it removed was
`AUTHZ-REVOKE-ENFORCED-A-INV :: inv-get-account-allow-warm-cache`.

**The mechanism that keys on the reason stays.** `retry_until_authorized` and the
operation-poll loops retry while the *response* says the
specific transient thing, and when the budget is spent the real assertion runs on the
terminal response — so a genuine deny still fails. That is a check about behaviour. A
name-match is not, and is not a substitute for one.

### The 19 name-patterns the deduction absorbed — disposition 2026-07-30, ЗАКРЫТО

Nineteen patterns is what the predicate carried; they named **26** subjects (one step, eight
folders, seventeen folders). All nineteen were gone through one by one, against the code and
the file history rather than against their own wording. **Not one survives as a live
declaration**, and none of them is masked either: nothing is subtracted any more, so a red on
any of them is reported by name and becomes a finding with its own evidence.

The numbers: **17 obsolete** (tracker closed as completed, product fixed), **1 justified by a
window that never existed**, **1 misfiled and mis-diagnosed** (a leak canary read as a timing
quirk), and **8 names that the suites do not generate at all** (six in the nlb list, two more
in nlb's round-2 record).

**iam (`authz-deny`) — one step: `inv-get-account-allow-warm-cache`**

Justification was: "residue past a `POLL_CAP`-bounded budget of ~15 s". **That window does not
exist.** `scripts/gen.py` sets `POLL_CAP = 50`, and every loop using it busy-waits a real
500 ms, so the budget is ≈ **25 s** — and the constant has been 50 for the entire history of
that file. The "~15 s" came from a stale comment inside `cases/authz-deny.py` («cap 30 x
500ms»), naming a number nothing sets; the step's own assertion message said "~6 s"; and
`gen.py`'s paragraph about the constant still claimed "~6-10 s" from before the delay was
added. Four numbers, three of them wrong, and the record inherited one of them. A declaration
resting on a window that is not the one being executed **cannot be refuted by measuring** —
the measurement would be of the wrong thing. All three comments are now corrected to the
constant.

There is no live declaration for this step: no tracker issue was ever opened for it, and there
is no evidence that it is red **now**. The last evidence is dated — тот же отчёт коллекции
authz-deny, прогон 2026-07-26, где newman отчитался о трёх упавших утверждениях, а вычет снял
одно из них.
Re-verification needs a live run; nothing here asserts an outcome for it. If it is still red,
the runner says so by name (there is nothing left to subtract) and it becomes a finding with a
fresh tracker.

**vpc (7) + compute (1) — `AUTHZ-*-LS-OWN-AAB` / `get-abs<N>`: LEAK CANARIES, never lag**

Correcting the attribution the removed entry carried: these folders are **not** in the iam
suite. They are generated by `services/vpc/tests/newman/cases/authz-deny.py` (NETWORK, SUBNET,
ADDRESS, ROUTE-TABLE, SECURITY-GROUP, GATEWAY, NIC) and
`services/compute/tests/newman/cases/authz-deny.py` (INSTANCE). The entry sat in this file
because the gate is shared, and the misfiling is why the family read as an iam timing quirk
for as long as it did.

What they assert, verbatim: `LIST no-access: 403 OR 200+empty (no leak)` — account-admin-B
lists project-A1 (an account it has nothing in) and must either be refused or receive an
empty, scope-filtered page. `200` with any row is a **cross-account data leak**. These are P1
negatives, and a name-keyed deduction was removing them. **They must never be weakened, under
any explanation**: the two outcomes they accept are a refusal and an empty page, which are the
two lawful shapes of "you see nothing" — not tolerance of a disagreement.

They are **not declared**, and that is the strict reading rather than the lenient one: a canary
is expected GREEN. Their earlier red had a deterministic fixture root cause — the iam
`rbac-subjects` suite creates a group in the **shared** account-A, adds `userAABId` to it and
binds `ROLE_VIEW` on the account, so while that grant is live, account→project containment
makes project-A1's children legitimately `v_list`-visible to AAB. Teardown for both granting
cases exists in-tree, so a residual red means teardown failed or a run overlapped the live
window: a finding, not a lag. The model-side reason such a grant reaches child resources at all
is tracked open in [`kacho-iam#276`](https://github.com/PRO-Robotech/kacho-iam/issues/276).

Note also that the reason-keyed mechanism was **already** applied here — the `-abs<N>` suffix
comes from the absence-wait wrapper (25 × 500 ms ≈ 12.5 s, then the real assertion runs once on
the terminal response). That wrapper is no longer declared in this suite: it had no caller here
and was removed with #1478; the mechanism it describes lives on in compute and vpc. The deduction was a second, name-keyed layer on top of it, and it was the one that
could hide a persistent leak.

**nlb — 17 folders, matched on their `-rya<N>` (already retry-wrapped) steps**

All seventeen are **no longer declared**. Their tracking issue
([`kacho#11`](https://github.com/PRO-Robotech/kacho/issues/11)) was closed as completed on
**2026-07-19** — eleven days before the entry was last edited — with a product fix and a green
nlb run recorded on it. Two of the seventeen had additionally been re-diagnosed as case bugs by
nlb's own round 5 (both fixed in-tree), and six of the names that list carried are not
generated by that suite at all. Per-name detail:
`services/nlb/tests/newman/docs/RESULTS.md` §«Closed — was «known failing»: owner-tuple
materialization lag».

Budgets are deliberately **not** inflated to bury such reds: raising a retry budget to outlast
a slow path converts a visible red into a slow green and, past the runner's own timeout, into a
cancelled run. If a wrapped step does not converge inside its present budget, the finding is
about the materialization path, not about the budget.

**Что держит эти записи от возврата.** Репо-широкий гейт `tools/knownfailingsubject`
(вызывается из `ci.yaml` и из `e2e-newman.yml`): объявление обязано называть существующий кейс
и ОТКРЫТЫЙ тикет вместе с репозиторием, а на отчёте прогона — падать, если названный кейс
исполнился и прошёл. «Ноль находок» там отличимо от «ноль прочитанного»: гейт печатает
перепись осмотренного.

## Test-side fixes (round — 2026-07-26; base `adf1cb2`) — the suite starts checking itself

Context: `adf1cb2`/`647b5f8` repaired the execution guards, so ~325 previously-dropped
requests began to RUN. Nothing regressed — the 87 post-gate failures that appeared were
requests that had never executed, now reporting honestly. This round closes the test-side
debt they exposed. **No entry was added to the known-RED whitelist** and no assertion was
weakened; two assertions were re-pointed at the refusal that is actually reachable, and
several were strengthened.

### Harness (scripts/gen.py) — two classes that made green cases meaningless

- **The Operation poll ran as the wrong principal.** `poll_operation_until_done` /
  `assert_op_success` / `assert_op_error` hard-coded `jwtAccountAdminA`.
  `OperationService.Get` is principal-scoped and hides a foreign operation as 404, so any
  case whose mutation runs as somebody else polled an operation it may not see, for its
  whole retry budget — `IAM-USR-DL-CRUD-OK` alone was 52 of the 87 failures, one root.
  The default is now `AUTH_INHERIT_OP`: at collection-build time the poll takes the auth of
  the step that captured its operation-id variable (explicit `auth=` still wins; no local
  producer → the historical default; an `anonymous` producer is never inherited). Exactly
  two steps in the whole suite changed principal, which is the point — it is a
  root-cause fix, not 52 patches. Unit-locked in `scripts/gen_test.py`.

- **The Operation id survived between cases.** `opId` is one shared variable and a
  REJECTED mutation writes nothing to it, so the poll confirmed the PREVIOUS case's
  operation and the case passed having tested nothing. `save_from_response` now CLEARS any
  operation-id variable before the capture attempt, and the six hand-written
  `pm.environment.set('…OpId', …)` branches that had the same shape were given the same
  reset. Two live victims: `IAM-USR-INV-IDEM-REINVITE` (400 on a missing field → polled the
  prior invite → "idempotency" never once exercised) and `IAM-ROL-DL-NEG-SYSTEM` (403 →
  the stale id DEFEATED its own `if (!opId) skipRequest()` guard → asserted
  FAILED_PRECONDITION against the previous case's SUCCESSFUL delete). An empty id is now
  reported once, by name, at a `skipRequest()` guard (`required=False` on the 21
  best-effort `cleanup-*` polls, where a refused teardown genuinely has nothing to poll).
  Audit of other shared variables: resource-id captures (`crudRoleId`, `crudGroupId`, …)
  are deliberately NOT reset — they are read many steps later by design; the stale-poll
  class is specific to ids consumed by the next request.

### Fixture / subject defects

- **The "sees nothing" probes were run by a subject that genuinely sees things.**
  `jwtNoBindings` (userNOBId) is the standard grant TARGET of the AccessBinding suites:
  `iam-flat-authz-vbc` grants it `view` on account-A, the `authz-deny` AB-CR ALLOW rows
  grant it `view` on account-B, and both stay ACTIVE in Postgres across runs. Every
  DENY/EMPTY expectation for it was being asserted against an authorised principal.
  Switched to the DEDICATED never-granted `jwtPureNoBindings` (seeded by
  `tests/authz-fixtures/setup.sh`, never a grant target anywhere): the `authz-deny` NOB
  matrix row, `AUTHZ-ULG04`, and the foreign-Get / scope-filter probes in
  `iam-project` / `iam-group` / `iam-service-account`. The two self-referential rows
  (`USR-GT-A` self-get, `ESC-SELF-ADMIN-*` self-grant) were re-targeted to
  `userPureNoBindingsId` so "self" still means self. Stale titles naming `jwtNoBindings`
  on steps that already used the pure subject were corrected.

  > **Позднее уточнение (2026-08-18, раздел «Самочтение записи пользователя» выше):**
  > для `USR-GT-*` этого было НЕ достаточно, и запись оставлена как свидетельство о
  > сделанном тогда, а не как действующее указание. Переставили ЦЕЛЬ вслед за
  > субъектом, но ПРЕДЪЯВИТЕЛЬ остался служебной учёткой, тогда как отношение
  > самочтения принимает только тип `user`, — поэтому клетка ALLOW производителя не
  > получила и красной оставалась до 2026-08-18. Клетки переведены в `DENY`,
  > ALLOW-полоса перенесена в `AUTHZ-USR-GT-SELF-CEREMONY`.

- **`IAM-USR-DL-CRUD-OK` deleted a user that cannot be deleted** (surfaced *by* the poll
  fix — the 404 had been hiding it). `userINVId` holds active AccessBindings by
  construction (own personal-account owner grant + default-project admin + the
  account-B admin grant from the seed), and `User.Delete` is guarded by the access-binding
  RESTRICT. The case asserted only `done`, never SUCCESS, and its get-after-delete ran as
  a principal that gets 404 on that record either way — "gone" was satisfied by
  hide-existence. **Case defect, not a product one**: the RESTRICT is deliberate and
  unit-locked (`pgmaperr_test.go`). The case now self-seeds a genuinely deletable user
  (invite without `roleId` → PENDING row, no binding), deletes it as the account owner and
  asserts the operation SUCCEEDED. The refusal it had been hitting is now covered on
  purpose by the new `IAM-USR-DL-NEG-ACTIVE-BINDINGS`, pinned to its verbatim text.

- **`IAM-USR-INV-IDEM-REINVITE` had never sent a valid request.** `project_id` is required
  whenever `role_id` is set, and the body omitted it → 400 on every run. Rebuilt
  self-contained: re-inviting the same email returns the SAME user row (asserted on
  `response.id`, not the pre-allocated `metadata.userId`), and re-issuing an
  already-active project grant returns Operation `ALREADY_EXISTS` — `AccessBinding.Insert`
  is a strict create by design (the `ON CONFLICT DO UPDATE` upsert was removed because it
  hid duplicate grants, `access_binding_repo.go:18`).

### Stale fixtures in `iam-role` (12 assertions)

| Case | Was | Now |
|---|---|---|
| `IAM-ROL-UP-T33-LABELS-OK` | used `crudRoleId`, deleted by `IAM-ROL-DL-CRUD-OK` earlier in the same collection → 404 on every step | self-seeds its own role (run-unique name) + cleanup |
| `IAM-ROL-LSOP-NEG-PAGE-TOKEN-GARBAGE` | listed the operations of a CLUSTER-scope system role → 403 AUTHZ_DENIED, never reached page-token validation | self-seeded own role; also pins the message to `page_token` |
| `IAM-ROL-DL-NEG-SYSTEM` | ran as an account subject, denied by `cluster-role-mutate` before the system-role guard; the 403 branch left `opId` stale | runs as `jwtBootstrap` (passes the gate, reaches the guard), clears `opId` |
| `IAM-ROL-CR-RULES-CAP-OVER-DENY` | 16 synthetic resource tokens per module, rejected by the closed-catalog check that was added after the payload | asserts the catalog rejection verbatim (see note below) |
| `IAM-ROL-CR-NEG-NO-SCOPE` | hard-expected 400 where the gateway fail-closes 403 on the unscoped `account:*` anchor first | `assert_unscoped_rejected('iam.roles.create', 'account:*')` — tolerant of both, but PINNED to the action + anchor so it cannot pass on an unrelated refusal |

**Note on the compiled-permission cap.** `>1024` is UNREACHABLE through the public API by
construction: the published catalog is 28 resource types × 5 closed verbs = 140 compiled
permissions, and a custom role may not use a module/resource wildcard
(`moduleResourceWildcardSystemOnly: true`). The numeric cap stays locked where it is
reachable — `domain.TestPermissions_Validate_CapRaise1024` (1024 accepted / 1025 rejected).
Re-pointing the black-box case at the closed-catalog gate loses no coverage and replaces an
assertion that could never pass with one that can.

**Product observation (not fixed here — test-only round).** `invite.go:277` still comments
the project bind as "idempotent через ON CONFLICT DO UPDATE"; that upsert was deliberately
removed and the insert is now strict create-or-conflict. The comment contradicts the code
(`architecture.md` doc-truthfulness) — worth a follow-up in the owning repo.

## Test-side fixes (round — 2026-07-21, qa; base `redesign/integration`@99f33d2)

Triaged the clean-seed umbrella CI artifact (`na4/iam/.../out/*.json`). Findings by class:

- **`iam-account-redesign` — 52 raw failures → 0 (ONE case, gate-blocking, FIXED).**
  All 52 collapse to `IAM-PRJ-RD-CR-DUP-NAME-PER-ACCOUNT :: poll-op #4`. Root: the case's
  `cleanup-dup-B` DELETE of account-B's **own freshly-created** project 403'd at the authz
  gate — the creator's `v_delete` FGA owner-tuple was still materialising (opgate removed →
  `op.done` ≠ tuple-visible; the prior create-op polls confirmed the *Operation*, not the
  project resource). The un-retried DELETE never saved a fresh `opId`, so the following
  poll polled the **stale** prior-delete op (minted by a DIFFERENT principal) → 404 from the
  principal-scoped `OperationService.Get` hide-existence (51 retries + 1 done-assert). Fix
  (test-only): wrap both own-fresh-resource cleanup deletes in `retry_until_authorized`
  (bounded read-your-writes, fail-closed at budget). Not a product bug — canonical EC lag.

- **`iam-authz-grant-check-propagation` — 3 (whitelisted, net-positive improvements).**
  (a) `poll_check_denied_step` asserted `j.allowed === false`, but a real
  `InternalIAMService.Check` deny returns `{"reason":…}` with the `false` bool OMITTED
  (proto3-JSON default omission) → the poll could never converge on a correct deny. Fixed
  to `code===200 && j.allowed !== true` (a genuine still-allowed `{"allowed":true}` still
  fails — nothing masked). (b) `AUTHZGCP-AB-CREATE-CHECK-VISIBLE::probe-check` hit the
  unregistered public check-путь, которого нет в каталоге разрешений (always `403 catalog: no
  entry for method`; адрес не воспроизводится — процитированный, он читается как живой
  маршрут) → migrated to the
  working `poll_check_allowed_step` internal `/iam/v1/internal/iam:check` probe. (c)
  `AUTHZGCP-SAKEY-SECRET-NOT-LEAKED::re-get-op-redacted` read non-existent snake_case
  `client_id/client_secret` (real fields are camelCase `clientId`/`privateKeyPem`/
  `clientSecret`) — the "redacted" assert passed vacuously, "client_id present" failed on
  `undefined`. Reframed to lock the black-box observable (one-shot delivery + identifier);
  the 120 s-grace redaction timing is unit-covered (`sa_keys/usecase_redaction_grace_test.go`).

- **`rbac-visibility-set` (12) + `iam-rbac-subjects` (11) — grant-materialisation timing
  under umbrella-parallel load; NOT confidently test-fixable, NOT force-masked.** These are
  dominated by FGA tuple-materialisation lag that exceeded even the ~25 s bounded
  `poll_request_until_status` window (`get-subjects-len-2`/`get-legacy-fills-subjects` → 404
  own-AB hide-existence for the full 51-poll cap; `check-member-allowed`/`expand-access-members`
  → 181 non-converging retries on group#member→viewer). **Wandering-flake signature**:
  `RBACSUBJ-CR-NEW-AUTHOR::get-new-fills-legacy` uses the identical pattern and CONVERGED,
  while its siblings did not — timing, not a functional/test hole (the hint's "0/138 green on
  a healthy seed" confirms). The documented replica-lag remedy (`iam replicaCount=1`) is
  **already** applied in `values.dev.yaml`; the residual is grant-materialisation THROUGHPUT
  under the full parallel run (see MEMORY "grant-materialization O(mirror) root"). Two
  `rbac-visibility-set` sub-classes were read as **over-shows** and deliberately left RED,
  not whitelisted. **Оба объяснения оказались неверны — разобрано 2026-08-04, разделением,
  а не рассуждением:**
  - `*-LABEL-EXACT-OK` (serviceAccount / role / group) краснели не из-за пропускной
    способности материализации и не из-за остатка чужих данных в общем аккаунте, а из-за
    СУБЪЕКТА выдачи: она называла ряд пользователя, которым ни один выдаваемый предъявитель
    не аутентифицируется, тогда как читал набор предъявитель служебной учётки. Три клетки,
    в каждой изменён ровно один признак (см. докстроку `grant_bylabel_generic`): аккаунт
    постоянен + субъект изменён → сходится за 0.0 с; субъект постоянен + аккаунт изменён →
    не сходится за 40 с. Причина в субъекте; исправлено в фикстуре.
  - `*-VLIST-ONLY-DETAIL-404` краснели не из-за over-show, а потому что требовали **снятого**
    инварианта: предикат страницы приведён к отношению чтения
    (`docs/architecture/list-page-membership-equals-read-relation.md`), поэтому выдача
    `{list}` без `get` больше не показывает объект — это принятое следствие, а не дефект.
    Кейсы перенацелены на действующий контракт и проверяют его в обе стороны
    (`IAM-SET-*-LIST-READ-PARITY`).

  Урок обеих строк один: «краснеет — значит продукт течёт» было ДОГАДКОЙ, а не замером, и
  обе догадки оказались ложными. Прежде чем чинить, признаки разделяют по одному.

- **Out of the artifact but NOT in scope**: `iam-internal-only-check` (8) fail with
  `getaddrinfo ENOTFOUND api.kacho.local` — the external endpoint is unresolvable in the
  port-forward-only newman CI (env limitation, not a leak); `iam-rbac-scope-grant` (7) not
  triaged this round.

## Resolved 2026-07-28 — the round-4 "product-bug floor" was no longer there

Everything this section described has been fixed, and the entries that named it are
gone from `assert-suites-green.sh`. It is kept, shortened, as a record of what was
believed and what turned out to be true — the previous text is in git history.

The claim was that a cluster administrator could not delete an access binding
somebody else had created (`652 x 403 vs 32 x 200` across an umbrella run), and that
an account administrator could not issue a key for a service account they had just
created; both were attributed to inherited access simply not existing for those
types. The inherited-access change of **2026-07-27** removed that cause.

Re-measured **2026-07-28** on the kind stand, by running the suites:

| Suite | Step | Was declared | Observed 2026-07-28 |
|---|---|---|---|
| `rbac-subject-channel-equivalence` | `teardown-user-revoke`, `teardown-usr-iso-revoke` | permanent 403 | **HTTP 200** |
| `rbac-subject-channel-equivalence` | the seven `*-gone` convergence probes | red, downstream of the refused revoke | **all pass** |
| `rbac-subject-channel-equivalence` | `IAM-CH-GRP-MEMBERSHIP-FLIP-OK` | red, drain tail | **case passes end to end** |
| `iam-authz-grant-check-propagation` | `issue-sakey` | permanent 403 | **HTTP 200** |
| `iam-authz-grant-check-propagation` | `probe-check-after-revoke`, `poll-op-plaintext`, `re-get-op-redacted` | red, downstream of `issue-sakey` | **all pass** |
| `iam-invite-grant-fga` | `poll-bind-project-anchor`, `te4-post-bind-project-viewer` | red (product gap, later restated as a stale case) | **49/49, zero failures** |

`PRO-Robotech/kacho#9`, `kacho-iam#212` and `kacho-iam#217` should be closed as fixed.

One red in `iam-authz-grant-check-propagation` was not covered by any of this and is
**not** masked: `AUTHZGCP-BIND-LIST-BY-SUBJECT-FOREIGN-DENY :: inv-lists-aaa-subject`
denied correctly, but the response carried no error detail, so the case could not tell a
scoped denial from a missing catalog entry.

**Fixed in the service.** iam now attaches the machine-readable reason (`AUTHZ_DENIED`),
domain and `metadata.action` to a refusal it decides itself — for every method on the
scope-filtered band, where the edge runs no per-RPC check and therefore names no action.
A method with no catalog row still gets nothing, so a catalog miss stays distinguishable,
which is the discriminator the case asserts. Unit coverage enumerates the band from the
catalog itself: `services/iam/internal/authzguard/deny_details_test.go`. The case is
expected green on the next stand run; this row stays until a run observes it, because the
fix is proven in-process and not yet end to end.

## СНЯТО 2026-08-01 — was: known failing, user-list over-show canary (`kacho-iam#276`)

The row declared `IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY::list-nonmember` expected-red
because a shared no-bindings subject carried a residual account-A viewer that the case's
own pre-clean could not strip. **Every mechanism it named is gone from this tree**, and
each half was checked separately rather than inferred from the others:

1. **The subject changed.** The row is about `jwtNoBindings`; the case reads
   `jwtPureNoBindings` — a dedicated principal — and the generated collection agrees, so
   this is what actually runs, not just what the source says. The case's own comment
   names `kacho-iam#276` as the root-cause fix it implements.
2. **The pre-clean it blames does not exist.** `nob_preclean_account_a` — the step the row
   says is a no-op — resolves nowhere in the repository.
3. **The polluter it blames does not exist.** `IAM-ACB-CR-CRUD-OK`, named as the case that
   grants the shared subject a global viewer, is not a case id anywhere in the tree.
4. **The new subject is never granted**, measured with a control in both directions so the
   negative means something: searching binding bodies for `userPureNoBindingsId` finds
   **0** in `cases/`, while the same search for the old `userNOBId` finds **12** in
   `cases/` and **46** in the generated collections — the predicate demonstrably finds
   grants when they exist. The 4 occurrences of `userPureNoBindingsId` in collections are
   the `AUTHZ-ESC-SELF-ADMIN-*` must-DENY canaries, which assert 401/anon and 403/no-bind:
   they assert the subject **stays** ungranted. `tests/authz-fixtures/setup.sh` seeds it
   with that contract written down.

The canary itself stays exactly as it is — un-whitelisted, single-shot, no retry — so a
genuine over-show still fails it honestly. What is removed is the sentence excusing it.

## Resolved — label-remove on storage revokes (was: known failing, NOT whitelisted)

`label-revoke-storage` was added as the OWNER-side analogue of `label-revoke-compute`
before the block-storage duplicate in kacho-compute was deleted, and it was declared
RED on its revoke half when it was written.

**It is green, and has been since the same day it was written.** The gap it found was
real: storage told the authority holding the label selector what a resource's labels
were when it was created and again when it was deleted, and nothing in between, so a
removal never reached the selector and the grant outlived the label it came from. That
is fixed — an update that touches labels now re-tells the authority the labels as they
are now, on all three resources. The declaration above it in this file and in the case
docstring simply outlived the fix by a day.

**Re-verified end to end (live umbrella, 2026-07-28)** against the whole collection,
not a re-reading of the code: `label-revoke-storage` runs **87/87 assertions, 0
failed**, all three `*-post-revoke-deny` steps included. Independently confirmed at
two more layers — the storage register queue carries a second intent per updated
resource stamped with the labels *after* the update (and drains clean: 320 rows, 320
sent, 0 pending), and a direct probe flips Check from `allowed:true` to denied on every
way a label can come off: cleared to nothing, one key dropped, the whole set replaced,
and under a full-object PATCH (empty `update_mask`) as well as an explicit one.

**A stale RED declaration is not a harmless leftover.** It states, in the file that
decides what the gate tolerates, that a live over-grant exists; anyone reading it
either goes hunting for a defect that is already closed or learns that a red revoke
check is something this suite lives with. Both are worse than saying nothing.

## Resolved 2026-07-28 — the "bounded-poll tail" entries

Both rows that stood here (`IAM-CH-GRP-MEMBERSHIP-FLIP-OK`, and the seven `*-gone`
revoke-to-deny probes) explained themselves as an eventual-consistency tail on a loaded
cluster. Neither explanation survived: the tail was measured at sub-second on 2026-07-26,
and on 2026-07-28 every one of these steps passes. They are removed from the gate rather
than re-justified — see the section above.

### Superseded 2026-08-03 — `rbac-subject-channel-equivalence` has a counted debt

The three `rbac-subject-channel-equivalence` rows in the 2026-07-28 table above, and the
paragraph immediately preceding this one, say these steps pass. **They do not, and the
reason is not a tail.** A stale GREEN declaration is the mirror of the stale RED this file
warns about two sections up, and it is the more expensive of the two: it removes the
reader's reason to look.

Re-measured 2026-08-03 across three stored reports (0 failed / 12 / 12). The two red runs
fail on the **byte-identical twelve assertions in the same six steps**, two days apart on
two different seeds — deterministic, not wandering. Mechanism, established by decoding the
fixtures rather than by inference: every failing step reads as `jwtInvitee`, whose token
authenticates as a **service account**, while the binding under test names
`user:{{userINVId}}` — an unrelated user row. The relation names one principal and every
request carries another, so it cannot resolve at any budget; all six exhaust the 300-poll
cap and end on the same 404. No `jwtSAA` step fails — that channel's id↔token pairing
holds, which is the control in the other direction inside a single report.

**Disposition — open debt with a number, not a mask and not a green:** 6 cases,
12 assertions, ~1806 requests per run. Under production posture a machine harness obtains
only `client_credentials`, i.e. a service account, so the user-principal channel is not
drivable here at all; driving it needs its own wave that creates the condition (an
interactive login). Nothing has been skipped, whitelisted or weakened.

Landed alongside, so the shape cannot return silently: the seed no longer discards the
invitee principal (it publishes `svaInviteeId`) and now **asserts its declared id↔token
pairings at seed time** (`tests/authz-fixtures/principal_pairings.py`, injection-proved in
both directions from `prodseed_all.py --self-test`). The case file's `POLL_CAP` comment,
which pre-explained these failures as a drain tail and is why nobody examined them for
three runs, has been replaced with the measured mechanism.

## Product findings (cases omitted, not RED)

| Finding | Disposition |
|---|---|
| ~~`GroupService.List` does not apply the per-object listauthz filter~~ — **WITHDRAWN 2026-08-02: the claim was stale, i.e. false about the product.** | The use-case now applies the per-object visibility filter through the same helper as its sibling resources; verified in the tree, not relayed. The entry outlived its own fix and went on declaring a live defect — the class `testing.md` names when it requires that **every exclusion mechanism expire on its own**: an entry with nothing left to exclude is a finding, and the gate must fail on it. **Debt left behind by the withdrawal:** the omitted case (group by-label exact-set, INV-2) was dropped *because of* this defect. The defect is gone; the case has not been restored. That is an open debt with a subject — not a green row. INV-1 remains emitted and green. |

## Pre-existing environmental flakes (clear on CI re-run)

`iam-access-binding` and `iam-user` occasionally flake whole-suite core-CRUD when the
cluster-admin / OpenFGA bootstrap has not materialized by the time the suite runs (e.g.
`AccessBinding.Create` → `operation.id ... expected undefined`, or the non-member scope-filter
seeing 1 user). These are environmental, not introduced by the suite code. Established remedy:
re-run the `newman-e2e` job.

## Account-scoped List authz uniformity

All five account-scoped IAM List RPCs (`User/ServiceAccount/Role/Project/Group`) carry
`permission = "<exempt>"` — the List CALL itself is not authz-gated; the result set is filtered
in-handler per object. A non-member therefore gets **200 + empty**, not 403; an
anonymous caller (no token) still gets **401 UNAUTHENTICATED** (`<exempt>` removes authz-Check,
not authN). This is exercised black-box by `AUTHZ-ULG04-NONMEMBER-PRJGRP-LIST-EMPTY`
(`jwtNoBindings` → Project & Group List → 200 + empty), the `*-LS-*` scope-filter rows in
`authz-deny.py`, and the `IAM-SET-PRJ/GRP-LABEL-EXACT-OK` exact-set cases in `rbac-visibility-set.py`.

The page predicate is the type's READ relation, not the union `viewer ∪ v_list`:
`services/iam/internal/authzfilter/visibility.go` → `pageRelations` gives `v_get` for
account / project / iam_user / iam_group / iam_service_account / iam_access_binding, and
`{viewer, v_list}` for iam_role alone (role reads have no catalog relation). A row is on the
page **iff** its holder may read it by id — decision
`docs/architecture/list-page-membership-equals-read-relation.md`, gate
`internal/repohygiene/listreadrelationparity_test.go`.

Следствие, принятое вместе с решением: выдача `{list}` БЕЗ `get` не показывает объект и не
открывает его. Это проверяется чёрным ящиком в обе стороны — `IAM-SET-*-LIST-READ-PARITY`
(отрицательное плечо + парный положительный контроль в том же прогоне и на том же субъекте).

> [!warning] Здесь было записано ОБРАТНОЕ, и оно пережило своё решение
> Прежняя редакция утверждала: «`v_list ≠ v_get`, поэтому субъект с одним лишь `v_list`
> ВИДИТ строку в List, а её detail Get отвечает 404». После сужения предиката страницы
> это стало ложным — такой субъект не видит строку вовсе. Утверждение ссылалось на
> кейсы `IAM-SET-*-VLIST-ONLY-DETAIL-404`, которые ровно это и требовали и потому
> краснели на исправном продукте; кейсы перенацелены, ссылки заменены.
When OpenFGA is unavailable the List RPCs fail closed (Unavailable), verified by
`project/list_*_test.go` / `group/list_*_test.go` (incl.
`TestListProjects_NilRelationPort_Unavailable` / `TestListGroups_NilRelationPort_Unavailable`).
Genuine `system/bootstrap` callers run on the internal listener (bypassing the gateway
annotation); on the public path `project`/`group` List treat `system/bootstrap` as anonymous →
empty (verified by `TestListGroups_SystemBootstrapFallback_FailClosed`).

## Test-side fixes (round 2 — `qa/iam-acb-fixture-green`)

Two RED classes in the umbrella CI report were **test-infra** defects (not product) and
are fixed here (verified locally via `py_compile` + `gen.py`; runtime GREEN is pending an
umbrella run):

- **`iam-invite-grant-fga` — `POST /iam/v1/internal/iam:check` → `404 page not found`
  (8 steps: `te{1,2,3}-*`, `te4-*`).** The `check_step` helper hit the **public** cmux
  (`{{baseUrl}}` :18080), which 404s `/iam/v1/internal/*` by design (ban #6) → JSONError on
  the first `pm.response.json()`. Fix: `check_step` now carries the same
  `_internal_url_override` pre-request URL rewrite to `{{internalBaseUrl}}` (:18081) that
  `label-revoke-vpc.py` uses (proven to reach 200 in the very same CI run). The 2 TE4
  `poll-bind-project-anchor` / `te4-post-bind-project-viewer` failures are GREEN as of
  2026-07-28 (whole suite 49/49) and are no longer whitelisted; **#212** is closed.

- **`label-revoke-{vpc,compute}` — cross-service create against a PHANTOM project
  (round-3 root).** Round-2 fixed the create-`403` by granting AAA an explicit
  `ROLE_EDIT @ project:A1` in `tests/authz-fixtures/setup.sh` (so the gateway authz gate
  passes). Round-3 CI then exposed the deeper root: the create Operation now returns `200`
  but completes `done:true` **with an error** — `create-net` → `{code:5,"Project
  prj3m3q…8ftb not found"}` (vpc), `create-disk` → `{code:5,"Folder with id prj3m3q…8ftb
  not found"}` (compute) — for the shared `{{projectA1Id}}`. Root: the fixture's
  `ensure_project` extracts `metadata.projectId` from the completed Create Operation
  **without checking `op.error`**; a Create that finishes with an error still carries the
  pre-allocated id in metadata, so `projectA1Id` was patched to a **phantom** — an id
  whose IAM project ROW never committed. The round-2 `ROLE_EDIT @ project:A1` binding then
  wrote FGA tuples **against that phantom id** (AccessBinding does not require the row to
  exist), so the gateway authz gate passes (tuple present → `200` op), but the
  cross-service peer-check (`vpc/compute → iam ProjectService.Get`) returns `NOT_FOUND` →
  the create op fails → the whole flow cascades RED on an unset resource var. Confirmed:
  `"prj3m3q… not found"` appears in **only** the two cross-service suites (36× vpc, 20×
  compute) and in no same-service suite — two independent services agreeing on `NOT_FOUND`
  ⇒ the row genuinely does not exist (not a per-edge bug). Fix (test-only, no product
  change): `label-revoke-{vpc,compute}.py` now **self-seed a fresh project per case**
  (`create_suite_project` → `{{_t31Proj}}` / `{{_t31cProj}}`, op-poll asserts `done` +
  **no error**) under `accountAId` and route all resource creates through it, replacing
  the shared `{{projectA1Id}}` dependency entirely — mirrors the existing runtime
  zone-discovery pattern в кейсе снятия меток соседнего домена (файл под доменом compute из
  набора iam с тех пор удалён — сегодня там домены iam / nlb / storage / vpc; имя не
  воспроизводится). accountAId stays the shared-tenant
  anchor (the ARM_LABELS role is account-scoped and containment matches
  `parent_account_id == accountAId`, which a project under account-A satisfies). A
  freshly-created, poll-confirmed project is guaranteed to exist for the peer-check, so
  these suites are now **GREEN by construction** (verified locally via `py_compile` +
  `gen.py`; runtime GREEN pending an umbrella run). Belt-and-suspenders: `setup.sh` gained
  a **non-fatal** post-create diagnostic that GETs `project:A1` and logs a loud `WARN` if
  it does not resolve, so a future phantom is diagnosable instead of hiding behind green
  FGA tuples. `label-revoke-nlb` is GREEN as of 2026-07-28 (47/47 requests, 23/23 assertions,
  including the revoke-side deny) and is no longer whitelisted.

---

## IAM-1 redesign (tenancy-tree + authz-core, F1–F11) — newman coverage

Black-box coverage of the **IAM-1** owner-side redesign
(`docs/specs/sub-phase-IAM-1-tenancy-authz-core-acceptance.md`), grounded in the
**landed** `services/iam` code (proto + use-cases + seed migrations), authored test-only
(ban #13 — no product code touched). Local newman env is blocked (no HTTPS ingress on the
kind stand); the cases are `gen.py`-generated + `coverage.py`-validated here and executed
by the `newman-e2e` CI job. IAM Operation id-prefix is **`iop`** (not `epd`).

### New case files (34 cases, `# verifies IAM-1-NN` in each title)

| File | F | Cases (IAM-1-NN) |
|---|---|---|
| `cases/iam-account-redesign.py` (9) | F1/F2/F3 | ownerUserId derive-from-caller + reject-in-body (attacker/self) + Update-immutable (01/02/03); Create-saga two-id metadata + default `"default"` Project + owner-binding `deletionProtection` (04); Delete RESTRICT-non-empty (06); Project.Create under account + no-parent (07); accountId immutable (08); dup-name per-account vs cross-account OK (09) |
| `cases/iam-role-redesign.py` (9) | F4/F5/F6 | definitionTier dotted + isSystem° derived + no scope-field (10); definitionTier empty-tierType + legacy both-scope XOR (11); public Get no compiled `permissions` (13); permissions-input reject + empty-rules reject (14); canonical catalog `view→edit→admin→owner` first-in-order + `edit.effectiveVerbs=[get,list,update,delete*]` + verbNotes verbatim (15); system-role Update (sync FP) + Delete (op.error FP) immutable (16) |
| `cases/iam-access-binding-redesign.py` (16) | F7/F8/F9/F10/F11 | scopeType dotted + target.allInScope + no resourceType/resourceId (18/21); per-object target.resources ResourceRef closed-table no-name (21/23); no-target reject (22); unknown target-type reject (23); scopeType-required + bare-not-dotted reject (18); scope/subjects immutable Update (19); RoleCoversType FP (24); IsRoleAssignable FP (25); malformed scopeId + missing-anchor (26); Delete-hard→gone (27); :revoke soft→REVOKED+revokedAt (28); re-grant-after-revoke new-ACTIVE + dup-ACTIVE ALREADY_EXISTS (29); List garbage-token / pageSize>1000 / unknown-filter-key before authz + whitelist-filter (32) |

Exact error texts/codes/fields are pinned from the landed code (e.g. `"Illegal argument
ownerUserId (derived from caller)"`, `"target is required; use target.allInScope{} to
grant all objects under the anchor"`, `"role %s does not grant verbs on compute.instance;
target type must be covered by role.rules"`, `verbNotes["delete*"] == "co-materialized on
in-scope leaf objects, NOT on the account/project anchor itself"`, seed catalog names
`view/edit/admin/owner`, `edit` rules `verbs=[get,list,update]` ⇒ editor-tier delete*).
`AccessBindingService.Revoke` (the new `:revoke` RPC) is now covered by newman.

### Existing cases updated to the IAM-1 contract (registry-agent style)

- **F1 ownerUserId derived-from-caller** (`Account.Create` body no longer carries
  `ownerUserId`; supplying any value → sync `INVALID_ARGUMENT`):
  - `iam-account.py` — 11 create/BVA/SEC bodies had `ownerUserId` removed (owner° derives
    from the caller = `userAAAId`, so the existing `Get.ownerUserId==userAAAId` assertions
    still hold); the two legacy owner-negatives **repurposed**:
    `IAM-ACC-CR-NEG-OWNER-MISSING` (was "unknown owner → error") and
    `IAM-ACC-CR-AUTHZ-OWNER-MISMATCH-DENY` (was anti-hijack 403) now both assert the
    reject-in-body `400 INVALID_ARGUMENT` — the AS-IS required-branch and anti-hijack-branch
    are gone.
  - `authz-deny.py` — `EXPECT["esc-account-hijack"]` flipped `AAA:ALLOW→DENY` (the
    ownerUserId-hijack vector is now closed for **every** subject, incl. self; `reject_asserts`
    already accepts code 3/400).
  - `rbac-visibility-set.py` — fixture-seed `create-suite-account` dropped `ownerUserId`.
- **F7/F8 AccessBinding scope-anchor + target** — the landed `CreateAccessBindingRequest`
  requires `scopeType` (dotted `iam.account|iam.cluster|iam.project`) + `scopeId` + a
  REQUIRED `target`; the resource message exposes **only** `scopeType`/`scopeId` (no legacy
  `resourceType`/`resourceId`). All **41** legacy create bodies across **15** files
  (`iam-access-binding-redesign.py` ×19 — файл с тех пор переименован, здесь стоит нынешнее
  имя, `authz-deny.py`, `authz-sa-apitoken.py`,
  `iam-authz-grant-check-propagation.py`, `iam-rbac-scope-grant.py`, `iam-rbac-subjects.py`,
  `iam-role.py`, `iam-invite-grant-fga.py`, кейсы снятия меток по доменам, …) were
  migrated: `resourceType:"account"→scopeType:"iam.account"` (+cluster/project),
  `resourceId→scopeId`, and a `target:{allInScope:{}}` injected (these are all whole-scope
  grants, so `allInScope` is the semantically-correct target). The ~40 response-reader
  assertions (`b.resourceType==='account'` → `b.scopeType==='iam.account'`,
  `.resourceId`→`.scopeId`) were migrated with the value change. The legacy
  `:listByScope?resourceType=…&resourceId=…` **query params stay** (the ListByScope/BySubject/
  ByRole/ByAccount RPCs still exist and their request messages keep `resource_type`/
  `resource_id`).
- **F8 target reintroduced** — `IAM-ACB-F51-TARGET-IGNORED` repurposed: the OLD premise
  ("`target` is a removed/ignored key") is inverted — `target` is now REQUIRED and HONORED;
  the case asserts `target.allInScope` IS honored while the still-removed `selector`/
  `targetRef` keys are unknown-ignored.

### `[PHASE-0-GATED]` scenarios — asserted UNGATED-only, gated part documented

The acceptance marks several scenarios `[PHASE-0-GATED]` (land only after the B1/B3/B6
governance change-set). The landed code is **pre-Phase-0**, so these newman cases assert
the **ungated** behavior and do NOT assert the gated part:

- **B3 prefix-derivation** — IAM-1-12 (`tierType` from `tierId` prefix) and IAM-1-18
  (`scopeType` from `scopeId` prefix) are gated. Landed code REQUIRES `tierType`/`scopeType`
  explicitly (`"scopeType is required"`, `role/handler.go` requires `tierType`). The cases
  send explicit dotted `tierType`/`scopeType` and additionally lock the pre-Phase-0
  requirement (empty → `INVALID_ARGUMENT`). Prefix-derivation is a follow-up.
- **B3 hyphen ids** — IAM-1-17 (system roles `rol-viewer`…). Seed ids are the current
  non-hyphen `rol1bda80f2be4d3658e`/`rolde95b43bceeb4b998`/`rol21232f297a57a5a74`/
  `rol72122ce96bfec66e2`. The catalog case keys on role **name** (`view/edit/admin/owner`)
  + verb preview, not the id form.
- **reason-token in `google.rpc.Status.details`** — IAM-1-24/25 gate `reason` tokens
  (`ROLE_DOES_NOT_COVER_TYPE`, `ROLE_NOT_ASSIGNABLE_ON_TIER`) are gated; the cases assert
  the **code + message text** (ungated), not the token.

### Non-black-box scenarios — integration-covered (NOT newman), declared honestly

- **IAM-1-13 (internal `GetRoleCompiled` positive)** — the compiled `permissions[]`
  projection lives on the internal listener (`InternalIAMService.GetRoleCompiled`, :9091),
  which is not reachable from this public-gateway newman env. Newman covers the **public**
  side (two-projection field-ABSENCE on public `Role.Get`/`List`); the internal-positive is
  covered by `services/iam/internal/apps/kacho/api/role/f5_compiled_projection_test.go`.
- **IAM-1-33 (INTERNAL never echoes pgx/SQL)** — requires injecting an uncategorized DB
  error on the write path (not reproducible black-box). Integration-covered
  (INTERNAL-opaque mapping tests). Documented here, not a newman case.
- **IAM-1-31 (Operation.done durability ≠ tuple-visibility materialization timing)** — not a
  standalone black-box assertion; it is the **read-your-writes discipline** applied across
  every positive case via `retry_until_authorized` / `poll_request_until_status`. The saga
  atomicity / re-grant-after-revoke CAS races are integration-covered
  (`create_saga_iam1_test.go`, `revoke_test.go`, `*_integration_test.go`).

### Validation

`gen.py` regenerates all 24 collections cleanly (Python-parse OK on all case files);
`coverage.py` reports **57%** RPC→case coverage (≥ the CI `--min 30` gate, exit 0); no
duplicate case-ids; **no product code touched** (diff is `tests/newman/**` + this doc).
Runtime GREEN is validated by the `newman-e2e` CI job (local env blocked).

---

## IBT conformance — iam as the SINGLE FACADE to the signing provider (#59, Phase C)

`cases/iam-token-facade-conformance.py` → `collections/iam-token-facade-conformance.postman_collection.json`,
run by `scripts/run.sh` (registered next to `iam-permission-catalog`). Eight cases:
IBT-04/05/06/10 (the acceptance's e2e-conformance scenarios) and IBT-12/13/14/15 (the
mirror / hook / docker-handle / provider-surface lanes the acceptance has no scenario for).

### The run this section is about

Production-posture kind stand (`kind-kacho`, `https://127.0.0.1`), api-gateway
`authn.mode=production-strict`, RS256 Bearer minted through the facade
(`InternalBootstrapTokenService.MintBootstrapToken` over mTLS gRPC → OAuth2
client-assertion exchange). Verdict as `scripts/run.sh` prints it:

| collection | assert | failed | requests | unanswered | rc |
|---|---:|---:|---:|---:|---:|
| iam-token-facade-conformance | 169 | **0** | 45 | **0** | 0 |

`TOTAL: 1/1 коллекций отчиталось — 45 запрос(ов), 0 без ответа, 169 утверждени(й), 0 упавших, 0 немых отчёт(ов)`

`scripts/exec-coverage.py` on the same report: **executed 45/45 (100%)**, `SKIPS: 0` —
no step was skipped, silently or otherwise. That number is the one that matters here:
a conformance suite whose steps quietly do not run would report the same zero failures.

### Why the green is believable — injection, in both directions

A suite that is green on its first run has not yet shown it can be red. Five injections
were run against the SAME collection (copies of the environment / collection; the
committed artefacts were not modified), each expected to break exactly one lane:

| injection | expected | measured |
|---|---|---|
| A · facade Bearer replaced by an HS256 alg-confusion forgery of its own payload | verification + enrichment + issuance lanes red | **25 failed** — IBT-04 (`edge did NOT reject authN`), IBT-13, IBT-05 (`Operation envelope returned`, step-up assertion) |
| B · `iamJwksBaseUrl` lost from the harness | RED naming the variable, never a silent skip | **10 failed** — five `harness config: iamJwksBaseUrl is set …` failures across IBT-04/10/12/15 plus the mirror comparisons |
| C · `registryDataPlaneBaseUrl` pointed at the provider | docker lane red | **5 failed** — `anonymous /v2/ is challenged with 401`, `the realm PATH is the facade docker-token handle`, … |
| D · `iamJwksBaseUrl` pointed at the provider (the mis-set that would make the mirror comparison compare the provider with itself) | mirror lane red | **2 failed** — both narrow-proxy steps of IBT-12 |
| E · the IBT-06 / IBT-15 probes re-pointed at a **routed** endpoint (`/iam/v1/me`) | the "no door here" family red | **6 failed** — `NEVER 2xx`, `SAME SHAPE as a nonsense path`, `EMPTY action`, on both cases |
| — · unmodified collection and environment (the legal twin) | silent | **0 failed** |

Injection E is the one that matters for IBT-06/IBT-15: it shows the probes distinguish a
**routed** address from an unrouted one, rather than merely observing that this platform
fail-closes on everything.

### Что из записанного выше УСТАРЕЛО, и почему запись не переписана (2026-08-24, #1169)

Раздел описывает прогон, который БЫЛ, и остаётся верным о нём. Но полоса выдачи с
тех пор сменилась: бутстрап-предъявитель чеканит собственный подписант платформы —
ES256, свой издатель, состав утверждений ПЛОСКО, принципал в `sub`. Поэтому читать
шапку «RS256 Bearer minted through the facade … client-assertion exchange» как
описание сегодняшнего стенда нельзя: это описание того дня.

Что это стоило, измерено: суита, написанная под одну полосу, дала **14 упавших
утверждений из 126** на исправной платформе (прогон 32671767388, шард `iam`,
исполнено 31/41 запроса, 10 записанных пропусков) — пять кейсов, из них два чистым
каскадом. Литералы полосы (один алгоритм, одна запись публикатора, вложенная форма
утверждений, `sub` не равен принципалу) заменены свойствами, общими для ОБЕИХ полос.

Инъекции A–E выше проверяли прежнюю редакцию и повторно не прогонялись. Способность
новой редакции упасть держит `scripts/selftest_token_facade_forms.py`: 20 осей, по
каждой пара «законный вход обеих полос молчит / внесённый дефект падает и называет
себя», стенд не нужен. Замер на день правки — до неё **17** находок, после **0**.

### Divergences from the acceptance text, recorded rather than papered over

1. **IBT-06 predicts 404; the stand answers 403.** MintBootstrapToken carries no
   `google.api.http` binding, so there is no route to miss and the fail-closed authz gate
   answers before the mux — identically for the mint, for the path the acceptance spells,
   and for a typo. 404 can never arrive, so the case asserts what is witnessable (NEVER
   2xx · same refusal shape as a typo · empty `action`) with a positive control proving
   the same listeners do serve routes.
2. **The advertised external TLS listener (:8443) is not probed.** Measured: it requests a
   client certificate, completes the handshake, opens the HTTP/2 stream and answers
   nothing — with no client cert and with the gateway's own; nothing reaches the gateway
   access log. A probe that cannot be answered must not be written as a passing check, so
   the isolation statements are made on the two listeners that answer.
3. **IBT-05 does not exchange the issued user credential for a Bearer.** A user
   client-credentials token carries no `acr` and its client is provisioned without the api
   audience, so that exchange cannot authenticate the edge. That limit is #59's remaining
   open item (the interactive principal), not something a black-box case can assert around.

### Harness requirement

Four base URLs beyond the gateway ones, injected by
`deploy/scripts/newman-{e2e,parallel}.sh` as `--env-var` and port-forwarded there:
`iamJwksBaseUrl` (iam :9097), `providerPublicBaseUrl` (provider :4444),
`iamRegistryTokenBaseUrl` (iam :9096), `registryDataPlaneBaseUrl` (registry :8080).
A missing one turns the case RED naming the variable (`require_env_url`) — injection B
above is the proof, not the promise.
