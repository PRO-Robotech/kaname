# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RBAC explicit model — exact-set visibility invariants black-box suite.

The "create several items per resource, compare visible-set vs created-set" invariants:
verb-bearing v_get/v_list; ProjectService.List = FGA-viewer∪v_list scope-filter; a
label-selector materializes v_list/v_get only on matching objects.

RESOURCE COVERAGE — under the unified label-scope model every iam content type is
label-selectable. A custom role rule with `matchLabels` on an iam content type materializes
per-object v_list/v_get on matching objects; the type's scope-filtered List then returns the
matched set. Coverage here is PER-TYPE-SELECTED because the per-type PAGE PREDICATE differs
(role's page predicate is `{viewer, v_list}`, everyone else's is the read relation `v_get`);
the List CALL authz is UNIFORM — all five account-scoped IAM List RPCs are `<exempt>`:

  - **project** / **serviceAccount** / **group**: предикат страницы `v_get` — тот же,
    чем гейтится одиночный Get. Осмысленны ОБА кейса: точный набор по метке и равенство
    «в странице ⟺ читается по id».
  - **role**: ЕДИНСТВЕННОЕ исключение — предикат страницы `{viewer, v_list}`, потому что
    у чтения роли нет отношения в каталоге, а `RoleService.Get` пускает любого члена
    аккаунта по ярусу viewer (чужой аккаунт по-прежнему 404). Равенство «страница ⟺
    чтение» для роли неверно BY CONSTRUCTION, поэтому выпускается только точный набор.

Remaining (a later chunk): **user** (global scope; a labelled user is produced via invite +
Update) and **accessBinding** (bespoke listByScope, no flat List).

LIST-CALL AUTHZ (unified): ALL five account-scoped IAM List RPCs (Project / Group /
ServiceAccount / Role / User) are `<exempt>` — the gateway performs NO FGA pre-Check on the
List call. Единственный гейт — пообъектный фильтр страницы в хендлере, поэтому выдача по
метке даёт 200+отфильтровано (никогда 403). Прежнее якорное правило `{iam.account list}`
(эмитировало `account#v_list`, чтобы авторизовать САМ ВЫЗОВ Project/Group List) больше не
нужно и снято. ПРЕДИКАТ ЭТОГО ФИЛЬТРА — НЕ союз `viewer ∪ v_list`, а отношение чтения типа
(`services/iam/internal/authzfilter/visibility.go` → `pageRelations`): `v_get` для
account/project/iam_user/iam_group/iam_service_account/iam_access_binding и `{viewer,
v_list}` для iam_role. Союз был убран решением
`docs/architecture/list-page-membership-equals-read-relation.md`.

WHAT THIS PROVES (black-box through api-gateway → IAM → OpenFGA, camelCase REST):

  Non-matching label hidden — IAM-SET-PRJ-LABEL-EXACT-OK.
    In account A: create 3 projects {foo=<runId>} (M+), 3 with NO labels (M−), 2 with
    {baz=<runId>} (other-label). A custom role rule `{iam.project get,list matchLabels:{foo:<runId>}}`
    is bound to a subject on ACCOUNT:accountAId. The subject's project List then contains
    EXACTLY the M+ set: all three M+ visible, NONE of M− visible, NONE of the other-label
    set visible. Per-run unique label value (`foo=<runId>`) makes the matched set exactly
    THIS run's M+ (immune to projects accumulated by prior runs / other suites).

  Членство в странице равно чтению — IAM-SET-PRJ-LIST-READ-PARITY.
    Выдача `verbs:[list]` БЕЗ `get` материализует `v_list` и ярусный кортеж, но НЕ
    `v_get`. Предикат страницы `project`/`group`/`serviceAccount` — именно `v_get`
    (`services/iam/internal/authzfilter/visibility.go` → `pageRelations`), тот же, чем
    гейтится одиночный Get. Значит такая выдача НЕ показывает объект в списке И не
    открывает его по id: строка попадает в страницу тогда и только тогда, когда
    вызывающий вправе прочитать её одиночным Get. Решение и его принятые следствия —
    `docs/architecture/list-page-membership-equals-read-relation.md` (статус: принято,
    гейт `internal/repohygiene/listreadrelationparity_test.go`).

    ЗДЕСЬ БЫЛ ОБРАТНЫЙ ИНВАРИАНТ, И ОН СНЯТ. Прежняя редакция требовала «объект ВИДЕН
    в списке, но Get 404». Он опирался на союз `viewer ∪ v_list` в предикате страницы;
    союз убран, потому что `List` возвращает ТО ЖЕ сообщение ресурса, что и `Get`, —
    «видеть в списке без содержимого» на такой выдаче нереализуемо, членство в
    странице и есть содержимое. Кейс перенацелен на действующий контракт и проверяет
    ОБЕ стороны равенства (отрицательное плечо + парный положительный контроль),
    поэтому он по-прежнему способен упасть — и упадёт, если предикат страницы снова
    разойдётся с отношением чтения в любую из двух сторон.

CLEAN-SLATE PRE-CLEAN — both cases read as jwtInvitee. jwtInvitee can carry a residual
account-A binding (a prior suite's best-effort, async-revoked teardown). A residual
account-VIEWER grant would cascade onto EVERY account-A project and defeat the by-label
filtering (M− would become visible). Each case therefore first deletes (with await) every
active account-A binding for userINVId via a bounded list→delete→await loop, asserting the
slate is clean (zero residual account-A bindings) before granting the by-label role. Discovery
uses the ADMIN-AUTHORIZED :listByScope on account/accountAId (owner sees all subjects, filter
by subjectId) — NOT :listBySubject, which at the time 403'd for the admin caller and yielded a
FALSE clean slate (the residual binding survived and leaked M− into the visible set). Since
#1352 :listBySubject admits the account administrator too (narrowed to that account), so the
403 above is HISTORY, not the contract; the choice stands on its own merit — the pre-clean
wants every subject in the account scope, which is what :listByScope answers. This makes the exact-set assertion self-contained and deterministic — it does NOT depend
on any other case/suite having torn down.

PAGINATION — the reads use `pageSize=1000` so the run-created projects are returned on a
single page even as account A accumulates projects across runs (the page-boundary lesson
from assert-suites-green.sh's role list-with-account note); the M± projects are also
best-effort deleted at teardown to bound growth.

TIMING DISCIPLINE: the by-label materialization is reconciler-driven (≤2s + sweep). The
List-appears assertion POLLS until the M+ set converges (grant→reconcile window); the
detail-404 and the non-matching-hidden checks run on the CONVERGED terminal
response — a genuine never-converging materialization or a real over-grant fails honestly,
never masked.

Fixture deps (crud-fixture/setup.sh): jwtAccountAdminA (grant-authority on accountAId),
accountAId, svaInviteeId/jwtInvitee (non-owner reader).

СУБЪЕКТ ВЫДАЧИ — `svaInviteeId`, А НЕ `userINVId`. Читает набор `jwtInvitee`, и это
предъявитель СЛУЖЕБНОЙ УЧЁТКИ; объявленная пара «id ↔ токен» живёт в
tests/authz-fixtures/principal_pairings.py, где прямо сказано, что `userINVId` — только
ЦЕЛЬ привязки, и ни один выдаваемый токен ею не аутентифицируется. Выдача на такой
субъект не резолвится ни при каком бюджете и выглядит изнутри кейса как незаехавшая
материализация — то есть отказ сообщает не о том месте.

ПРЕДЪЯВИТЕЛЬ, СОЗДАЮЩИЙ АККАУНТ, — ЧЕЛОВЕК. Аккаунт принадлежит пользователю by
construction, поэтому приватный аккаунт суиты заводит человек церемонии (см.
create_suite_account), и он же владеет всем, что суита в нём создаёт.

Test-design techniques: ECP (label equivalence classes — matching foo / no-label / other-label
baz), exact-set comparison (visible ≡ M+), decision-table (verb {get,list} vs {list} × read
path {List, single-Get}), state-transition (grant → materialize → visible), error-guessing
(other-label vs no-label both excluded; v_list-only must not leak content).
"""

CASES = []

POLL_CAP = 50

# Предъявитель, ПРИНАДЛЕЖАЩИЙ ЧЕЛОВЕКУ, — его производит волна церемонии
# (`scripts/run-ceremony.sh` → `tests/authz-fixtures/prodseed_ceremony.py`).
# Имя вынесено в константу, потому что оно называется здесь в тринадцати местах
# одного кейса, и разъехавшаяся половина означала бы отказ в правах посреди
# фикстуры — симптом, неотличимый на вид от продуктового дефекта видимости.
# ЧЕЛОВЕК У КЕЙСА СВОЙ, А НЕ ОБЩИЙ ЧЕЛОВЕК ЦЕРЕМОНИИ. Кейс ЗАВОДИТ аккаунт, а
# заведение списывается с темпа личности (#618, умолчание — три в час на внешний
# идентификатор входа). Восемь заведений волны под одним человеком давали десять
# списаний при потолке три: отказ был верен, а падало не то место, которое полку
# исчерпало. Личность слота заводит РОВНО ОДИН аккаунт — свой; её выдаёт волна
# церемонии по объявлению `ceremony_credentials.ADMISSION_SLOTS`.
_HUMAN = "jwtHumanRbacVisSet"

# ПОДНЯТЫЙ УРОВЕНЬ ВХОДА — ТОТ ЖЕ ЧЕЛОВЕК, ДРУГОЙ УРОВЕНЬ АУТЕНТИФИКАЦИИ.
# Часть ручек объявлена чувствительной (`required_acr_min = "2"`): необратимое
# удаление и выдача прав. Служебная учётка от этого порога ОСВОБОЖДЕНА, поэтому,
# пока эти шаги шли машинным предъявителем, порог не проверялся ни разу — он
# впервые начал действовать вместе с человеческим вызывающим.
# Уровень берётся у КАТАЛОГА, а не по догадке: сверка шагов с
# `gateway/internal/middleware/embed/permission_catalog.json` — часть приёмки этой правки.
_HUMAN_STEPUP = "jwtHumanRbacVisSetStepUp"


# ---------------------------------------------------------------------------
# Helpers (local — mirror iam-rbac-scope-grant.py / iam-read-authz-vget.py idioms).
# ---------------------------------------------------------------------------

def poll_op(op_var, out_id_var=None, auth="jwtAccountAdminA", also_clear_on_error=()):
    """GET /operations/{op_var} until done; assert done && no error; optionally capture id.

    `also_clear_on_error` — прочие ПРОВИЗОРНЫЕ переменные того же шага создания
    (сопутствующий потомок саги). Они сняты той же логикой фантома, что и
    `out_id_var`: их идентификаторы тоже предвыделены и присутствуют у операции,
    завершившейся ошибкой, поэтому на ошибке они обязаны исчезнуть вместе с ней.
    """
    capture = ""
    clear_extra = "".join(
        f"if (j.error) {{ pm.environment.unset('{v}'); }} " for v in also_clear_on_error)
    if out_id_var:
        # ФАНТОМНЫЙ ИДЕНТИФИКАТОР: снимается ЗДЕСЬ, потому что здесь впервые известен исход.
        #
        # Create-шаг сохраняет `metadata.<res>Id` СРАЗУ, до завершения операции — и это
        # неизбежно: до `done` другого источника id нет. Но идентификатор в метаданных
        # ПРЕДВЫДЕЛЕН и присутствует даже у операции, которая завершится ОШИБКОЙ. Значит
        # после `done` с ошибкой в переменной лежит id ресурса, которого в базе нет.
        #
        # Замер 2026-07-30 на боевой посадке: `POST /iam/v1/accounts` → 200 + Operation →
        # `done:true` С ошибкой `code 9 "referenced resource not found or still in use"`,
        # `metadata.accountId = accs403jtr4t654xgg8m`, а `SELECT … FROM kacho_iam.accounts`
        # по этому id — ПУСТО. Кейс продолжил работать с фантомом: каждый последующий
        # `POST /iam/v1/projects` в несуществующий аккаунт честно отвечал 403 «no
        # authorization path» (модель права — выдавать не на что), мутации отвергались,
        # `opId` оставался пустым, поллер звал `GET /operations/` без идентификатора и
        # получал 400. Одна неудача создания дала **550 упавших утверждений** в этой
        # коллекции и увела разбор в ложную сторону («у служебных субъектов нет прав»).
        #
        # Поэтому: на ошибке операции переменная СНИМАЕТСЯ. Дальше шаги упадут на пустом
        # id — там, где предусловие действительно отсутствует, — а не размножат сотни
        # производных отказов вокруг правдоподобного, но несуществующего объекта.
        # Правило дерева: опросить до `done` → утвердить отсутствие ошибки → и только
        # потом извлекать id (testing.md, «Fixture-seed обязан проверять op.error»).
        capture = (f"if (j.error) {{ pm.environment.unset('{out_id_var}'); }} "
                   f"else if (j.response && j.response.id && !pm.environment.get('{out_id_var}')) "
                   f"{{ pm.environment.set('{out_id_var}', j.response.id); }}")
    return Step(
        name=f"poll-{op_var}",
        method="GET",
        path="/operations/{{" + op_var + "}}",
        auth=auth,
        test_script=[
            "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
            "const j = pm.response.json();",
            "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
            "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
            f"if (!j.done && pc < {POLL_CAP}) {{",
            "  pm.environment.set('_pollCount', String(pc + 1));",
            "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 50 x 500ms ~= 25s budget (testing.md) */",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount');",
            "pm.environment.unset('_pollStarted');",
            capture,
            clear_extra,
            "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
        ],
    )


# A small cap on list↔delete iterations — a non-owner subject carries at most a
# handful of account-A bindings; this bounds the clean-slate loop independently of
# the (larger) Operation-await POLL_CAP.
PRECLEAN_LIST_CAP = 12


def preclean_account_loop(tag, next_step):
    """Bounded list→delete→await loop removing EVERY active account-A binding for svaInviteeId
    (any role) so the by-label visibility starts from a clean slate, then jumps to `next_step`.

    CRITICAL flow discipline (the loop must TERMINATE FORWARD, never fall through into the
    delete machinery): the list step's terminal "clean slate" branch does
    `setNextRequest(next_step)` to jump PAST del/await to the first post-preclean step. The
    earlier version simply fell through with no setNextRequest, so Newman advanced to the
    NEXT sequential request — `del_step` — which (on a non-200 delete) jumped back to
    `list_step`, whose pre-request then RESET the iteration counter (the terminal branch had
    unset the request-name-scoped flag) → an unbounded list↔del ping-pong that never honoured
    the cap (observed: 17k+ list invocations, 35-min hang, CI timeout). Jumping forward on the
    terminal branch keeps the flag set across loop-backs, so the counter increments
    monotonically and the cap holds."""
    # Значение вызывающего становится ЧАСТЬЮ ИМЕНИ переменной прогона, а имя не
    # экранируется: оно либо годно, либо порождаемый скрипт не разбирается — и
    # newman запишет это в testScripts, отчитавшись НУЛЁМ упавших утверждений.
    # То же имя уезжает и в АДРЕС (`{{…}}`), который JavaScript'ом не является
    # вовсе, — экранировать одну сторону значит развести писателя и читателя
    # молча. Поэтому исход — проверка годности при генерации (#1220).
    tag = js_name(tag,
                  where="iam/rbac-visibility-set/preclean_account_loop/tag")
    dup = f"{tag}Dup"
    delop = f"{tag}DelOp"
    list_step = f"{tag}-preclean-list"
    del_step = f"{tag}-preclean-del"
    await_step = f"{tag}-preclean-await"
    return [
        Step(
            name=list_step,
            method="GET",
            # Discovery MUST use an AUTHORIZED read: :listByScope on account/accountAId
            # (the account owner sees EVERY binding in the account scope, ALL subjects).
            # The prior :listBySubject?subjectId=userINVId 403'd for the jwtAccountAdminA
            # caller (at the time the read admitted the subject only); the test then
            # treated the empty result as a clean slate, so a residual account-scoped
            # view binding for userINVId leaked into the by-label visibility assertion
            # (M− projects became visible → exact-set mismatch). listByScope returns all
            # subjects → the filter narrows to subjectId=userINVId (pattern: IAM-ACB-CR-CRUD-OK
            # pre-clean-dup). pageSize=1000: the account scope accumulates >50 bindings
            # across re-runs, so the default page (50) could page-out the stale binding.
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{tag}Started') !== pm.info.requestName) {{ pm.environment.set('_{tag}Count', '0'); pm.environment.set('_{tag}Started', pm.info.requestName); }}",
            ],
            test_script=[
                # ЭТО ЧТЕНИЕ УЖЕ АВТОРИЗОВАННОЕ, И ИСХОД У НЕГО ОДИН — 200: владелец
                # аккаунта перечисляет выдачи В ОБЛАСТИ СВОЕГО аккаунта. Текст ниже
                # остался копией от прежнего `:listBySubject` (чужой субъект, отказ
                # by design) и врал дважды: он допускал отказ там, где отказ означал бы
                # потерю владельцем прав на свой аккаунт, и объявлял «известным
                # продуктовым пределом» со ссылкой на посторонний тикет то, что этот
                # набор уже обошёл сменой метода.
                #
                # Цена лжи была не косметической: `arr` на отказе оставался пустым, и
                # утверждение «остаточных выдач нет» — то самое, ради которого шаг
                # существует, — проходило ВАКУУМНО, объявляя чистый слот там, где о
                # слоте не узнали ничего. Ровно этот механизм однажды уже пропустил
                # остаточную выдачу в проверку набора видимости.
                *assert_status(200),
                f"const c = parseInt(pm.environment.get('_{tag}Count') || '0', 10);",
                "const arr = ((pm.response.json() || {}).accessBindings || []).filter(b => b.subjectId === pm.environment.get('svaInviteeId') && b.scopeType === 'iam.account' && b.scopeId === pm.environment.get('accountAId'));",
                f"if (arr.length > 0 && c < {PRECLEAN_LIST_CAP}) {{",
                f"  pm.environment.set('{dup}', arr[0].id);",
                f"  pm.environment.set('_{tag}Count', String(c + 1));",
                f"  pm.execution.setNextRequest('{del_step}');",
                "  return;",
                "}",
                # Terminal (clean slate OR cap hit): jump FORWARD past del/await to next_step.
                f"pm.environment.unset('_{tag}Count'); pm.environment.unset('_{tag}Started'); pm.environment.unset('{dup}');",
                "pm.test('jwtInvitee has zero residual account-A bindings (clean slate for by-label visibility)', () => pm.expect(arr.length, JSON.stringify(arr.map(b => b.id))).to.eql(0));",
                f"pm.execution.setNextRequest('{next_step}');",
            ],
        ),
        poll_request_until_status(
            retry_on=(403,),
            
            name=del_step,
            method="DELETE",
            path="/iam/v1/accessBindings/{{" + dup + "}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean: слот освобождён (200) или его и не было (404) — устойчивый 403 значит, что прежняя выдача ОСТАЛАСЬ активной и strict-create упрётся в UNIQUE', () => pm.expect(pm.response.code, JSON.stringify(pm.response.json() || {})).to.be.oneOf([200, 404]));",
                f"pm.environment.unset('{delop}');",
                "if (pm.response.code === 200) { const dj = pm.response.json() || {}; if (dj.id) pm.environment.set('" + delop + "', dj.id); }",
                # 200 → fall through to await_step; non-200 (already gone / undeletable) → re-list
                # (bounded by the list-step counter, which does NOT reset on this loop-back).
                f"if (!pm.environment.get('{delop}')) {{ pm.execution.setNextRequest('{list_step}'); }}",
            ],
        ),
        Step(
            name=await_step,
            method="GET",
            path="/operations/{{" + delop + "}}",
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{tag}AwaitStarted') !== pm.info.requestName) {{ pm.environment.set('_{tag}AwaitCount', '0'); pm.environment.set('_{tag}AwaitStarted', pm.info.requestName); }}",
            ],
            test_script=[
                "const j = pm.response.json();",
                f"const c = parseInt(pm.environment.get('_{tag}AwaitCount') || '0', 10);",
                f"if (!j.done && c < {POLL_CAP}) {{ pm.environment.set('_{tag}AwaitCount', String(c + 1)); const _ipd2 = Date.now(); while (Date.now() - _ipd2 < 500) void 0; /* real inter-poll delay: cap 50 x 500ms ~= 25s budget (testing.md) */ pm.execution.setNextRequest(pm.info.requestName); return; }}",
                f"pm.environment.unset('_{tag}AwaitCount'); pm.environment.unset('_{tag}AwaitStarted');",
                f"pm.execution.setNextRequest('{list_step}');",
            ],
        ),
    ]


def create_suite_account(acc_var, op_var, auth=_HUMAN, def_prj_var=None):
    """Create a FRESH, suite-private account per run so the by-label PROJECT exact-set reads
    an account in which the reading subject (svaInviteeId) is NOT a member.

    АККАУНТ РОЖДАЕТСЯ НЕ ПУСТЫМ, И ЭТО ЗАБОТА УБОРКИ. Сага создания co-commit'ит в
    той же транзакции проект `default` (redesign-2026 F2), а `Account.Delete`
    отказывается сносить аккаунт, пока в нём есть хоть один проект. Этого потомка
    кейс не заводил и в своих шагах не видит — единственный его след здесь
    `metadata.defaultProjectId`, доступный ещё до `done`. Не захватив id, уборка
    получает ЗАКОННЫЙ отказ `FAILED_PRECONDITION "Account <id> contains projects"`
    на последнем шаге, аккаунт переживает прогон, и красным становится кейс, а не
    продукт. Поэтому `def_prj_var` — не удобство, а условие того, чтобы уборка
    вообще могла завершиться; свойство держит гейт
    `deploy/scripts/assert-cocreated-child-is-torn-down.py`.

    ВЛАДЕЛЕЦ — ЧЕЛОВЕК, И ИНАЧЕ БЫТЬ НЕ МОЖЕТ. `owner_user_id` ссылается на `users(id)`, а
    владелец выводится из принципала. Все предъявители матричного посева — служебные учётки,
    поэтому создание аккаунта ими отвергается синхронно, первым стейтментом. Условие
    «предъявитель принадлежит человеку» создаёт волна церемонии (`scripts/run-ceremony.sh`).
    Следствие, важное для ВСЕГО кейса: раз аккаунт принадлежит человеку церемонии, то и
    проекты/роль/выдачу внутри него заводит он же — служебная учётка матрицы прав в этом
    аккаунте не имеет и получила бы отказ.

    ROOT CAUSE of the persistent red this fixes (diagnosed, NOT a product over-emit): userINVId
    is seeded by authz-fixtures/setup.sh (KAC-125 invite-flow → editor@projectA1) as a MEMBER of
    the SHARED accountA, and ProjectService.List carries an account-member visibility floor that
    returns EVERY project in the account to any member. A member's project List therefore can
    NEVER be narrowed by a matchLabels grant — the account's M−/baz projects AND every other
    suite's projects (authz-test-*, t31-prj-*, …) leak into the visible set. The IDENTICAL
    account-scoped by-label grant is correctly filtered for serviceAccount/group/role (their List
    RPCs have no member floor — those exact-set cases PASS), which pins the leak to project-list
    MEMBERSHIP, not a by-label v_list over-emit. In a fresh account userINVId's ONLY relation is
    the by-label AccessBinding → per-object v_list on the foo-matched projects only → the exact
    set holds. Self-contained: no concurrent suite touches this per-run account (unique
    rbacvis-<runId> name), so it cannot be contaminated. (VLIST-ONLY / SVA / GRP / ROL cases stay
    on accountAId — they already pass; the member floor only breaks the exact-set's M−/baz-hidden
    assertion.)"""
    def_prj_capture = ([] if def_prj_var is None else
                       save_from_response("j.metadata && j.metadata.defaultProjectId",
                                          def_prj_var))
    return [
        Step(name="create-suite-account", method="POST", path="/iam/v1/accounts",
             # IAM-1 F1: ownerUserId° derived-from-caller — not sent in the body.
             body={"name": "rbacvis-{{runId}}",
                   "description": "rbac-visibility-set per-run private account"},
             auth=auth,
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.accountId", acc_var),
                          *def_prj_capture,
                          *save_from_response("j.id", op_var)]),
        poll_op(op_var, out_id_var=acc_var, auth=auth,
                also_clear_on_error=() if def_prj_var is None else (def_prj_var,)),
    ]


def mk_project(short, label_key, id_var, op_var, acct_var="accountAId", auth="jwtAccountAdminA"):
    """ProjectService.Create (+ op-poll) capturing the new project id. label_key None → no
    labels (M−); 'foo'/'baz' → labels={key: <runId>} (per-run unique value). acct_var selects the
    parent account (default shared accountAId; the exact-set case passes a fresh suite-private
    account — see create_suite_account).

    `auth` ОБЯЗАН СООТВЕТСТВОВАТЬ `acct_var`: права выдаются в конкретном аккаунте, поэтому
    предъявитель, законный для общего accountAId, в приватном аккаунте суиты не имеет ничего.
    Пара «чужой аккаунт + прежний предъявитель» дала бы отказ в правах, неотличимый на вид от
    продуктового дефекта видимости — ровно того, что этот набор и проверяет."""
    body = {"accountId": "{{" + acct_var + "}}", "name": short + "-{{runId}}", "description": "newman exact-set project"}
    if label_key:
        body["labels"] = {label_key: "{{runId}}"}
    return [
        Step(
            name="create-" + short,
            method="POST",
            path="/iam/v1/projects",
            body=body,
            auth=auth,
            test_script=[
                *assert_status(200),
                *save_from_response("j.metadata && j.metadata.projectId", id_var),
                *save_from_response("j.id", op_var),
            ],
        ),
        poll_op(op_var, out_id_var=id_var, auth=auth),
    ]


def grant_bylabel_role(role_var, acb_var, role_op, bind_op, verbs, role_name, acct_var="accountAId",
                       auth="jwtAccountAdminA", auth_stepup=None, match_key="foo"):
    """RoleService.Create(rule {iam.project verbs matchLabels:{<match_key>:runId}}) + AccessBinding
    bound to service_account:svaInviteeId @ ACCOUNT:<acct_var>. Fresh role id per run → unique active 5-tuple
    → no strict-create dup → no pre-clean of THIS binding needed. acct_var selects the account
    the role lives in AND the binding scope (default shared accountAId; the exact-set case passes
    a fresh suite-private account — see create_suite_account).

    ДВА ПРЕДЪЯВИТЕЛЯ, А НЕ ОДИН: создание роли — обычная ручка, а ВЫДАЧА ПРАВ объявлена
    чувствительной (`AccessBindingService/Create`, `required_acr_min = "2"`). Один
    предъявитель на оба шага пришлось бы брать по самому высокому порогу — и тогда
    обычный шаг перестал бы проверять, что поднятого уровня ему НЕ требуется."""
    auth_stepup = auth_stepup or auth
    return [
        Step(
            name="create-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                # Role.Create name enforces ^[a-z][a-z0-9_]{0,40}$ (underscores, NOT hyphens
                # — stricter than the proto annotation), so the run-suffix is `_`-joined.
                "accountId": "{{" + acct_var + "}}",
                "name": role_name + "_{{runId}}",
                "description": "newman exact-set by-label role",
                "rules": [
                    # ProjectService.List = <exempt>: шлюз больше не делает pre-Check
                    # `account:<id>#v_list` — единственный гейт это пообъектный фильтр
                    # страницы в хендлере. Отдельное якорное правило не нужно.
                    # Предикат страницы `project` — `v_get`
                    # (`services/iam/internal/authzfilter/visibility.go` → `pageRelations`),
                    # то есть то же отношение, которым гейтится одиночный Get; решение —
                    # `docs/architecture/list-page-membership-equals-read-relation.md`.
                    {"module": "iam", "resources": ["project"], "verbs": verbs,
                     "matchLabels": {match_key: "{{runId}}"}},
                ],
            },
            auth=auth,
            test_script=[
                *assert_status(200),
                *save_from_response("j.metadata && j.metadata.roleId", role_var),
                *save_from_response("j.id", role_op),
            ],
        ),
        poll_op(role_op, out_id_var=role_var, auth=auth),
        Step(
            name="grant-bylabel",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                # СУБЪЕКТ ВЫДАЧИ ОБЯЗАН БЫТЬ ТЕМ, ЧЕМ АУТЕНТИФИЦИРУЕТСЯ ЧИТАТЕЛЬ.
                # Читает этот набор `jwtInvitee`, а это предъявитель СЛУЖЕБНОЙ УЧЁТКИ
                # (`svaInviteeId` — объявленная пара, tests/authz-fixtures/principal_pairings.py).
                # Прежняя выдача называла субъектом `userINVId` — ряд пользователя, которым
                # НИ ОДИН запрос не аутентифицируется, поэтому отношение не резолвилось ни при
                # каком бюджете. Изнутри кейса это неотличимо от «материализация не доехала»:
                # предъявлялось как истечение ожидания на шаге чтения, а не как ошибка выдачи.
                # Замер на стенде (2026-08-04): выдача на служебную учётку → чтение видит
                # объект за 2 с; та же выдача на `userINVId` → 404 и через 26 с (50 попыток).
                "subjects": [{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{svaInviteeId}}"}],
                "roleId": "{{" + role_var + "}}",
                "scopeType": "iam.account",
                "scopeId": "{{" + acct_var + "}}",
                "target": {"allInScope": {}},
            },
            # Выдача прав — чувствительная ручка (acr≥2): нужен поднятый вход.
            auth=auth_stepup,
            test_script=[
                "const j = pm.response.json();",
                "pm.test('grant accepted (200 Operation)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                "pm.test('IAM Operation envelope (iop)', () => pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
                *save_from_response("j.id", bind_op),
                *save_from_response("j.metadata && j.metadata.accessBindingId", acb_var),
            ],
        ),
        poll_op(bind_op, auth=auth),
    ]


def teardown(name, path, auth="jwtAccountAdminA"):
    """RELIABLE teardown — общий помощник gen.py (403 не терминален).

    Ресурс здесь не выдача, а роль/проект, но класс тот же: принятый отказ в правах
    оставляет ресурс в ОБЩЕМ аккаунте, и следующий прогон стартует с чужим мусором.

    `auth` — тот же, что создавал ресурс: снести его вправе тот, кто им владеет.
    """
    return reliable_delete(name, path, auth=auth)


def robust_revoke_binding(name, acb_var, auth="jwtAccountAdminA"):
    """Revoke the by-label binding, polling the DELETE PAST the creator-tuple 403 window so the
    grant is GUARANTEED gone before the SAME-TYPE v_list-only case runs.

    Why it must actually commit (not best-effort): the exact-set case grants {get,list} and the
    v_list-only case (same type, same run → same foo=runId label) grants {list}. If the exact-set
    binding leaks (its DELETE 403s on the admin's not-yet-materialized v_delete on the fresh
    binding object), the v_list-only object inherits v_get from the leaked {get,list} grant
    → its detail Get returns 200 instead of 404 (the invariant violated). The cross-subject preclean
    could not clean it (at the time the admin got 403 on listBySubject for another user; since
    #1352 that read admits the account administrator, narrowed to the account), so the revoke
    itself must commit. Retry the DELETE while 403, then require it to have committed.

    ИСХОД ОДИН — 200 С OPERATION, и «already-gone 404» из утверждения убран. Он описывал
    состояние, которого эта полоса достичь не может: роль и выдача создаются в ЭТОМ кейсе
    под уникальным `runId`, создание проверено строгим `200 + iop…`, операция создания
    дожата `poll_op` БЕЗ терпимости к ALREADY_EXISTS, и удаляет её только этот шаг. Значит
    404 здесь означает ровно одно из двух: выдачи не было (сорванная фикстура — отказ, а
    не «уже нет») либо её снёс кто-то посторонний (дефект). Принимать 404 значит зеленеть
    на том, что док этой же функции объявляет обязательным: «revoke itself must commit».
    Устойчивый 403 остаётся отказом по-прежнему — он и означает «выдача осталась
    активной».

    ИМЯ БЫЛО ШИРЕ ТЕЛА, И ЭТО НЕ ОФОРМЛЕНИЕ. Здесь стояла собственная реализация,
    утверждавшая `200 + Operation` под именем «revoke COMMITTED» — то есть ПРИЁМ запроса
    под именем ИСПОЛНЕНИЯ мутации. Мутации Kachō асинхронны (`api-conventions.md`), и
    следующий шаг цепочки сносит роль, на которую эта выдача ссылается: пока отзыв в
    полёте, владелец честно отвечает `FAILED_PRECONDITION "role is in use by …"`, и
    падает утверждение об исходе УДАЛЕНИЯ РОЛИ — то есть дефект показывается не там, где
    он живёт, и читается как дефект продукта, каковым не является. Ловится редко (один
    упавший ассерт из 3951 на прогоне 2026-08-10), потому что отзыв обычно успевает.

    Теперь это ОБЩИЙ `reliable_delete`: он тем же кодом ретраит 403 и ДОЖИДАЕТСЯ операции,
    а проход генератора, видя пару DELETE→опрос, дописывает ей утверждение об ИСХОДЕ —
    поэтому отзыв, завершившийся ошибкой, больше не читается как отзыв. Строгость к 404
    (обоснование выше) сохранена `terminal_codes=(200,)`, требование самой операции —
    `require_operation=True`; без него `200` без тела дал бы ожиданию ранний выход
    «ждать нечего», и отсутствие отзыва снова стало бы зелёным."""
    return reliable_delete(
        name, "/iam/v1/accessBindings/{{" + acb_var + "}}", auth=auth,
        op_key=acb_var, terminal_codes=(200,), require_operation=True)


# ===========================================================================
# exact-set: by-label grant → subject sees EXACTLY the matching (foo=<runId>) set.
# ===========================================================================
CASES.append(Case(
    id="IAM-SET-PRJ-LABEL-EXACT-OK",
    title="exact-set: 3 projects {foo=runId} (M+), 3 no-label (M−), 2 {baz=runId}; by-label grant {iam.project get,list matchLabels foo} → subject's project List == exactly the M+ set",
    classes=["RBAC", "AUTHZ", "VISIBILITY", "INV2", "LABELS", "EXACT-SET"],
    priority="P0",
    steps=[
        # verifies (non-matching label hidden)
        # FRESH suite-private account per run (see create_suite_account): the shared accountA
        # makes userINVId an account MEMBER (authz-fixtures KAC-125 invite), and
        # ProjectService.List's member floor returns EVERY account project to a member —
        # structurally defeating the by-label narrowing (M−/baz + other suites' projects leak
        # in). In this fresh account userINVId is NOT a member (only the by-label binding below),
        # so the List is narrowed to exactly the foo-matched set.
        # ПРЕДЪЯВИТЕЛЬ ЭТОГО КЕЙСА — ЧЕЛОВЕК ЦЕРЕМОНИИ, И ЭТО ОДНО РЕШЕНИЕ, А НЕ ДВА.
        # Аккаунт может принадлежать только пользователю, значит приватный аккаунт суиты
        # заводит человек; а раз владелец он, то и всё, что внутри (проекты, роль, выдача,
        # уборка), делает он же. Разделить эти два выбора нельзя: служебная учётка матрицы
        # в чужом приватном аккаунте прав не имеет.
        *create_suite_account("visSetAcct", "visSetAcctOp", auth=_HUMAN,
                              def_prj_var="visSetDefPrj"),
        # M+ (foo=runId) — 3 projects.
        *mk_project("setpp1", "foo", "visPP1", "visPP1Op", acct_var="visSetAcct", auth=_HUMAN),
        *mk_project("setpp2", "foo", "visPP2", "visPP2Op", acct_var="visSetAcct", auth=_HUMAN),
        *mk_project("setpp3", "foo", "visPP3", "visPP3Op", acct_var="visSetAcct", auth=_HUMAN),
        # M− (no labels) — 3 projects.
        *mk_project("setpm1", None, "visPM1", "visPM1Op", acct_var="visSetAcct", auth=_HUMAN),
        *mk_project("setpm2", None, "visPM2", "visPM2Op", acct_var="visSetAcct", auth=_HUMAN),
        *mk_project("setpm3", None, "visPM3", "visPM3Op", acct_var="visSetAcct", auth=_HUMAN),
        # other-label (baz=runId) — 2 projects.
        *mk_project("setbq1", "baz", "visBQ1", "visBQ1Op", acct_var="visSetAcct", auth=_HUMAN),
        *mk_project("setbq2", "baz", "visBQ2", "visBQ2Op", acct_var="visSetAcct", auth=_HUMAN),
        # No preclean loop: a fresh per-run account has ZERO residual bindings for userINVId by
        # construction (no other suite touches it), so the clean-slate the preclean used to
        # enforce on shared accountA is guaranteed here.
        # Grant the by-label role (get+list) to svaInviteeId on ACCOUNT:visSetAcct.
        *grant_bylabel_role("visSetRole", "visSetAcb", "visSetRoleOp", "visSetBindOp",
                            ["get", "list"], "setlblrole", acct_var="visSetAcct", auth=_HUMAN,
                            auth_stepup=_HUMAN_STEPUP),
        # The subject lists projects: poll until the exact set is FULLY CONVERGED (all M+ present
        # AND no M− AND no baz), then assert it. Waiting for the whole set (not just M+ present)
        # rides out any transient half-materialized over-visibility during by-label reconcile; a
        # PERMANENT leak never converges → the negatives below still fail at budget (never masked).
        poll_request_until_status(
            name="read-exact-set",
            method="GET",
            path="/iam/v1/projects?accountId={{visSetAcct}}&pageSize=1000",
            auth="jwtInvitee",
            expect_code=200,
            retry_on=(403, 404),
            retry_predicate="(() => { try { const ids = (pm.response.json().projects || []).map(p => p.id); const want = ['visPP1','visPP2','visPP3'].map(v => pm.environment.get(v)); const mneg = ['visPM1','visPM2','visPM3'].map(v => pm.environment.get(v)); const bz = ['visBQ1','visBQ2'].map(v => pm.environment.get(v)); return !want.every(w => ids.indexOf(w) !== -1) || mneg.some(w => ids.indexOf(w) !== -1) || bz.some(w => ids.indexOf(w) !== -1); } catch (e) { return true; } })()",
            test_script=[
                "const j = pm.response.json();",
                "const ids = (j.projects || []).map(p => p.id);",
                "pm.test('all three M+ (foo=runId) projects are visible', () => {",
                "  const want = ['visPP1','visPP2','visPP3'].map(v => pm.environment.get(v));",
                "  pm.expect(want.every(w => ids.indexOf(w) !== -1), 'visible ids: ' + JSON.stringify(ids)).to.be.true;",
                "});",
                "pm.test('no M− (no-label) project is visible (non-matching hidden)', () => {",
                "  const mneg = ['visPM1','visPM2','visPM3'].map(v => pm.environment.get(v));",
                "  pm.expect(mneg.some(w => ids.indexOf(w) !== -1), 'visible ids: ' + JSON.stringify(ids)).to.be.false;",
                "});",
                "pm.test('no other-label (baz=runId) project is visible (label-scoped, not blanket)', () => {",
                "  const bq = ['visBQ1','visBQ2'].map(v => pm.environment.get(v));",
                "  pm.expect(bq.some(w => ids.indexOf(w) !== -1), 'visible ids: ' + JSON.stringify(ids)).to.be.false;",
                "});",
            ],
        ),
        # Teardown — revoke the grant (committed, not best-effort) + role; delete the run's
        # projects AND the project `default`, заведённый сагой создания аккаунта, и только
        # затем сам аккаунт: он не удаляется, пока в нём есть хоть один проект.
        *robust_revoke_binding("teardown-binding", "visSetAcb", auth=_HUMAN_STEPUP),
        *teardown("teardown-role", "/iam/v1/roles/{{visSetRole}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-pp1", "/iam/v1/projects/{{visPP1}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-pp2", "/iam/v1/projects/{{visPP2}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-pp3", "/iam/v1/projects/{{visPP3}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-pm1", "/iam/v1/projects/{{visPM1}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-pm2", "/iam/v1/projects/{{visPM2}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-pm3", "/iam/v1/projects/{{visPM3}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-bq1", "/iam/v1/projects/{{visBQ1}}", auth=_HUMAN_STEPUP),
        *teardown("teardown-bq2", "/iam/v1/projects/{{visBQ2}}", auth=_HUMAN_STEPUP),
        # ПОТОМОК, КОТОРОГО КЕЙС НЕ ЗАВОДИЛ. Проект `default` co-commit'ится сагой
        # `Account.Create` в её же транзакции (redesign-2026 F2) — восьми шагов выше
        # для пустого аккаунта НЕ ДОСТАТОЧНО. Единственный след этого потомка в кейсе —
        # `metadata.defaultProjectId` шага создания аккаунта, снятый в `visSetDefPrj`.
        *teardown("teardown-suite-default-project", "/iam/v1/projects/{{visSetDefPrj}}",
                  auth=_HUMAN_STEPUP),
        # Снос аккаунта суиты: 403 НЕ принимается — он значит, что аккаунт остаётся, а
        # вместе с ним всё, что суита в нём насоздавала. Отказ retry'ится через окно
        # материализации; терминальны снятие (200) и «его уже нет» (404).
        #
        # ПРЕЖДЕ ЗДЕСЬ ТЕРПЕЛИСЬ ЕЩЁ 400 И 409 «на случай, если аккаунт ещё не пуст», и
        # у этой полосы НЕТ ПРОИЗВОДИТЕЛЯ: `Account.Delete` асинхронен и на корректный
        # авторизованный запрос отвечает 200 + `Operation`, а непустоту сообщает уже
        # ИСХОД операции — `error.code 9` «contains projects». То есть терпимость
        # перечисляла коды, которых этот шаг не отдаёт, а комментарий рядом обещал, что
        # недоехавший потомок «виден ИМЕННО здесь», — виден он на `-await`, утверждением
        # об исходе. Полоса без производителя ничего не смягчает и вводит в заблуждение
        # следующего читателя, поэтому снята.
        *reliable_delete("teardown-suite-account", "/iam/v1/accounts/{{visSetAcct}}",
                         auth=_HUMAN_STEPUP),
    ],
))


# ===========================================================================
# v_list-only grant: project appears in the List but the detail Get is closed (404).
# ===========================================================================
CASES.append(Case(
    id="IAM-SET-PRJ-LIST-READ-PARITY",
    title="членство в странице равно чтению (project): грант {iam.project list БЕЗ get} → проекта НЕТ в списке И его Get 404; парный контроль {get,list} на другом ключе метки → в списке И Get 200",
    classes=["RBAC", "AUTHZ", "VISIBILITY", "INV1", "LABELS", "NEG"],
    priority="P0",
    steps=[
        # verifies (docs/architecture/list-page-membership-equals-read-relation.md)
        #
        # Кейс ПЕРЕНАЦЕЛЕН, а не ослаблен. Он требовал снятого инварианта — «объект с
        # выдачей на один лишь `list` виден в списке, но его Get 404». Предикат страницы
        # `project` — `v_get` (`services/iam/internal/authzfilter/visibility.go`,
        # `pageRelations`), то есть ровно то отношение, которым гейтится одиночный Get;
        # принятое следствие «роль с одним лишь `list` больше не показывает объект»
        # записано в решении. Разбор — в докстроке `list_read_parity_case_steps`.
        *mk_project("setvl", "foo", "visVlProj", "visVlProjOp"),
        *mk_project("setvc", "ctl", "visVcProj", "visVcProjOp"),
        *preclean_account_loop("visVl", "create-role"),
        # отрицательное плечо — только `list`
        *grant_bylabel_role("visVlRole", "visVlAcb", "visVlRoleOp", "visVlBindOp",
                            ["list"], "setvllistonly"),
        # положительный контроль — `get`+`list` на ДРУГОМ ключе метки (`ctl`), поэтому
        # селекторы плеч не пересекаются. Без него «нет в списке» неотличимо от
        # «фикстура не поднялась / выдача уехала не тому субъекту».
        *grant_bylabel_role("visVcRole", "visVcAcb", "visVcRoleOp", "visVcBindOp",
                            ["get", "list"], "setvcctl", match_key="ctl"),
        poll_request_until_status(
            name="read-list-parity",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=1000",
            auth="jwtInvitee",
            expect_code=200,
            retry_on=(403, 404),
            # Ждём схождения КОНТРОЛЯ: пока он не виден, про отрицательное плечо
            # утверждать нечего.
            retry_predicate="(() => { try { const ids = (pm.response.json().projects || []).map(p => p.id); return ids.indexOf(pm.environment.get('visVcProj')) === -1; } catch (e) { return true; } })()",
            test_script=[
                "const j = pm.response.json();",
                "const ids = (j.projects || []).map(p => p.id);",
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — проект с грантом {get,list} ВИДЕН в списке "
                "(страница не уже чтения; без этого отрицание ниже ничего не доказывает)', () => "
                "pm.expect(ids.indexOf(pm.environment.get('visVcProj')) !== -1, 'ids: ' + JSON.stringify(ids)).to.be.true);",
                "pm.test('проект с грантом {list} БЕЗ {get} НЕ виден в списке "
                "(членство в странице равно отношению чтения — docs/architecture/"
                "list-page-membership-equals-read-relation.md)', () => "
                "pm.expect(ids.indexOf(pm.environment.get('visVlProj')) !== -1, 'ids: ' + JSON.stringify(ids)).to.be.false);",
            ],
        ),
        # Одиночный кадр (установившееся состояние): `v_get` не выдавался никогда, а
        # поллинг обязательного отказа маскировал бы настоящую утечку.
        Step(
            name="detail-get-listonly-closed",
            method="GET",
            path="/iam/v1/projects/{{visVlProj}}",
            auth="jwtInvitee",
            test_script=[
                "pm.test('Get проекта с грантом {list} без {get} → 404 (содержимое закрыто, hide-existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('grpc code 5 (NOT_FOUND)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
            ],
        ),
        Step(
            name="detail-get-control-open",
            method="GET",
            path="/iam/v1/projects/{{visVcProj}}",
            auth="jwtInvitee",
            test_script=[
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — Get проекта с грантом {get,list} → 200 "
                "(404 здесь означал бы, что 404 выше про сломанную фикстуру, а не про предикат)', "
                "() => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(200));",
            ],
        ),
        *robust_revoke_binding("teardown-binding", "visVlAcb"),
        *robust_revoke_binding("teardown-binding-ctl", "visVcAcb"),
        *teardown("teardown-role", "/iam/v1/roles/{{visVlRole}}"),
        *teardown("teardown-role-ctl", "/iam/v1/roles/{{visVcRole}}"),
        *teardown("teardown-proj", "/iam/v1/projects/{{visVlProj}}"),
        *teardown("teardown-proj-ctl", "/iam/v1/projects/{{visVcProj}}"),
    ],
))


# ===========================================================================
# Generic exact-set engine for the account-scoped iam content types
# (serviceAccount / group / role). Under the unified label-scope model every iam
# content type materializes label-scope IAM-DIRECT from its own-table labels (no
# resource_mirror feed required — the feed-gate is reversed for iam content types;
# domain.feed_registry_materializable + iam-rbac-rules-labels RBACLBL-IAMTYPE-
# ACCEPTED), so the by-label exact-set read-path is black-box-reachable through the
# public api-gateway exactly like iam.project above. The FGA model carries the
# verb-bearing v_get/v_list relations for iam_user/iam_service_account/iam_group/
# iam_role/iam_access_binding (authzmap fga_model_drift_test).
#
# (kind → create/list REST path, List response array key, Operation-metadata id
#  field, role-rule resource token (camelCase: iam.serviceAccount / iam.group /
#  iam.role), short name stem, optional create-body extra.)
# ===========================================================================

# `sep` — the run-suffix joiner for this type's name: serviceAccount/group names match
# ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ (hyphens OK, NO underscore); role names match
# ^[a-z][a-z0-9_]{0,40}$ (underscores OK, NO hyphen) — so they differ.
TYPE_SPECS = {
    "serviceAccount": {"path": "/iam/v1/serviceAccounts", "key": "serviceAccounts",
                       "idmeta": "serviceAccountId", "rule_res": "serviceAccount",
                       "stem": "stsa", "sep": "-", "extra": None},
    "group": {"path": "/iam/v1/groups", "key": "groups",
              "idmeta": "groupId", "rule_res": "group", "stem": "stgr", "sep": "-", "extra": None},
    # Role.Create requires >=1 rule; a benign rule on the OBJECT role does not affect
    # whether the SELECTOR by-label rule materializes it (selection is by the object's
    # labels, not by its own rules).
    "role": {"path": "/iam/v1/roles", "key": "roles",
             "idmeta": "roleId", "rule_res": "role", "stem": "strl", "sep": "_",
             "extra": {"rules": [{"module": "iam", "resources": ["user"], "verbs": ["get"]}]}},
}


def mk_obj(spec, short, label_key, id_var, op_var):
    """Create one account-scoped object of the given type (+ op-poll capturing its id).
    label_key None → no labels (M−); any key → labels={key:<runId>} (per-run unique
    value). Distinct KEYS keep a negative arm and its positive control disjoint: a
    selector on `foo` cannot match an object labelled only `ctl`, and vice versa."""
    body = {"accountId": "{{accountAId}}", "name": short + spec["sep"] + "{{runId}}",
            "description": "newman exact-set obj"}
    if spec["extra"]:
        body.update(spec["extra"])
    if label_key:
        body["labels"] = {label_key: "{{runId}}"}
    return [
        Step(name="create-" + short, method="POST", path=spec["path"], body=body,
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response(f"j.metadata && j.metadata.{spec['idmeta']}", id_var),
                          *save_from_response("j.id", op_var)]),
        poll_op(op_var, out_id_var=id_var),
    ]


def grant_bylabel_generic(spec, role_var, acb_var, role_op, bind_op, verbs, role_name,
                          match_key="foo"):
    """RoleService.Create(rule {iam.<type> verbs matchLabels:{<match_key>:runId}}) +
    AccessBinding bound to service_account:svaInviteeId @ ACCOUNT:accountAId. Fresh role
    id per run → unique active 5-tuple → no strict-create dup → no pre-clean of THIS
    binding needed.

    СУБЪЕКТ ВЫДАЧИ ОБЯЗАН БЫТЬ ТЕМ, ЧЕМ АУТЕНТИФИЦИРУЕТСЯ ЧИТАТЕЛЬ — ровно то же
    требование, что несёт `grant_bylabel_role` выше, и здесь оно было НЕ выполнено.
    Набор читает `jwtInvitee`, а это предъявитель СЛУЖЕБНОЙ УЧЁТКИ (`svaInviteeId`);
    выдача же называла субъектом `userINVId` — ряд пользователя, объявленный в
    `tests/authz-fixtures/principal_pairings.py` как ТОЛЬКО цель привязки: ни один
    выдаваемый предъявитель им не аутентифицируется и не может. Отношение называло
    одного принципала, каждый запрос нёс другого — не резолвится ни при каком бюджете,
    а изнутри кейса это неотличимо от незаехавшей материализации, то есть отказ
    сообщал не о том месте.

    РАЗДЕЛЕНО ЗАМЕРОМ, а не рассуждением (стенд, 2026-08-04): три клетки, в каждой
    изменён ровно один признак; тип — group, читатель — `jwtInvitee`:
      общий аккаунт  + user:userINVId             → не виден за 40 с (контроль);
      общий аккаунт  + service_account:svaInvitee → виден за 0.0 с;
      приватный аккаунт + user:userINVId          → не виден за 40 с.
    В первой паре аккаунт держался постоянным, во второй — субъект. Значит причина в
    СУБЪЕКТЕ выдачи, а не в остатке чужих данных общего аккаунта и не в типе ресурса
    (те же клетки на serviceAccount и role сходятся за 0.0-0.1 с)."""
    return [
        Step(name="create-role", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": role_name + "_{{runId}}",
                   "description": "newman exact-set by-label selector role",
                   # serviceAccount/role List have always been <exempt>; group/project List are
                   # now <exempt> too — no account#v_list anchor needed. The per-object by-label
                   # rule is the only grant; each type's in-handler page filter narrows the List
                   # to the matched set. Предикат страницы — ОТНОШЕНИЕ ЧТЕНИЯ типа
                   # (`services/iam/internal/authzfilter/visibility.go` → `pageRelations`),
                   # а не союз `viewer ∪ v_list`: см. решение
                   # `docs/architecture/list-page-membership-equals-read-relation.md`.
                   "rules": [{"module": "iam", "resources": [spec["rule_res"]],
                              "verbs": verbs,
                              "matchLabels": {match_key: "{{runId}}"}}]},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var),
                          *save_from_response("j.id", role_op)]),
        poll_op(role_op, out_id_var=role_var),
        Step(name="grant-bylabel", method="POST", path="/iam/v1/accessBindings",
             body={"subjects": [{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT",
                                 "id": "{{svaInviteeId}}"}],
                   "roleId": "{{" + role_var + "}}",
                   "scopeType": "iam.account",
                   "scopeId": "{{accountAId}}",
                   "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=["const j = pm.response.json();",
                          "pm.test('grant accepted (200 Operation)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                          "pm.test('IAM Operation envelope (iop)', () => pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
                          *save_from_response("j.id", bind_op),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", acb_var)]),
        poll_op(bind_op),
    ]


def _id_list_js(env_vars):
    return "['" + "','".join(env_vars) + "']"


def exact_set_case_steps(kind, pfx, role_name):
    """Exact-set steps: 3 M+ (foo) / 3 M− (no-label) / 2 baz (other-label) objects;
    by-label grant (get+list) → subject's List == exactly the M+ set."""
    spec = TYPE_SPECS[kind]
    pp = [f"{pfx}PP{i}" for i in (1, 2, 3)]
    mm = [f"{pfx}PM{i}" for i in (1, 2, 3)]
    bq = [f"{pfx}BQ{i}" for i in (1, 2)]
    objs = []
    for i, v in enumerate(pp, 1):
        objs += mk_obj(spec, f"{spec['stem']}p{i}", "foo", v, v + "Op")
    for i, v in enumerate(mm, 1):
        objs += mk_obj(spec, f"{spec['stem']}m{i}", None, v, v + "Op")
    for i, v in enumerate(bq, 1):
        objs += mk_obj(spec, f"{spec['stem']}b{i}", "baz", v, v + "Op")
    want, mneg, bz = _id_list_js(pp), _id_list_js(mm), _id_list_js(bq)
    read = poll_request_until_status(
        name="read-exact-set", method="GET",
        path=spec["path"] + "?accountId={{accountAId}}&pageSize=1000",
        auth="jwtInvitee", expect_code=200, retry_on=(403, 404),
        # Retry until the exact-set is FULLY CONVERGED, not merely until the M+ set is
        # present. The by-label reconciler materializes userINV's per-object v_list on the
        # foo-matched objects eventually-consistently; while it is still landing tuples, a
        # non-matching (M− / baz) object can be TRANSIENTLY visible before the negative
        # filter settles. Waiting only for "all M+ present" can therefore snapshot a
        # half-materialized set and see a baz object that a beat later is correctly hidden.
        # Converged = all M+ present AND no M− AND no baz. Bounded — a PERMANENT other-label
        # leak (a genuine per-object v_list over-emit) never converges, so the negative
        # asserts below still fail it at budget exhaustion (never masked).
        retry_predicate=("(() => { try { const ids = (pm.response.json()." + spec["key"]
                         + " || []).map(o => o.id); "
                         + "const want = " + want + ".map(v => pm.environment.get(v)); "
                         + "const mneg = " + mneg + ".map(v => pm.environment.get(v)); "
                         + "const bz = " + bz + ".map(v => pm.environment.get(v)); "
                         + "return !want.every(w => ids.indexOf(w) !== -1) "
                         + "|| mneg.some(w => ids.indexOf(w) !== -1) "
                         + "|| bz.some(w => ids.indexOf(w) !== -1); } catch (e) { return true; } })()"),
        test_script=[
            "const j = pm.response.json();",
            "const ids = (j." + spec["key"] + " || []).map(o => o.id);",
            "pm.test('" + kind + ": all three M+ (foo=runId) visible', () => { const want = "
            + want + ".map(v => pm.environment.get(v)); pm.expect(want.every(w => ids.indexOf(w) !== -1), 'ids: ' + JSON.stringify(ids)).to.be.true; });",
            "pm.test('" + kind + ": no M− (no-label) visible (non-matching hidden)', () => { const mneg = "
            + mneg + ".map(v => pm.environment.get(v)); pm.expect(mneg.some(w => ids.indexOf(w) !== -1), 'ids: ' + JSON.stringify(ids)).to.be.false; });",
            "pm.test('" + kind + ": no other-label (baz=runId) visible (label-scoped, not blanket)', () => { const bz = "
            + bz + ".map(v => pm.environment.get(v)); pm.expect(bz.some(w => ids.indexOf(w) !== -1), 'ids: ' + JSON.stringify(ids)).to.be.false; });",
        ],
    )
    teardowns = [*robust_revoke_binding("teardown-binding", pfx + "Acb"),
                 *teardown("teardown-role", "/iam/v1/roles/{{" + pfx + "Role}}")]
    for v in pp + mm + bq:
        teardowns.extend(teardown("teardown-" + v, spec["path"] + "/{{" + v + "}}"))
    return [
        *objs,
        *preclean_account_loop(pfx + "Set", "create-role"),
        *grant_bylabel_generic(spec, pfx + "Role", pfx + "Acb", pfx + "RoleOp", pfx + "BindOp",
                               ["get", "list"], role_name),
        read,
        *teardowns,
    ]


def list_read_parity_case_steps(kind, pfx, role_name):
    """ЧЛЕНСТВО В СТРАНИЦЕ РАВНО ОТНОШЕНИЮ ЧТЕНИЯ — обе стороны, на одном субъекте.

    ЧТО ЭТОТ КЕЙС УТВЕРЖДАЛ РАНЬШЕ И ПОЧЕМУ БОЛЬШЕ НЕ УТВЕРЖДАЕТ. Прежняя редакция
    требовала «выдача с одним лишь глаголом `list` → объект ВИДЕН в списке, но его
    одиночный Get отвечает 404». Этот инвариант СНЯТ осознанным решением
    `docs/architecture/list-page-membership-equals-read-relation.md` (статус: принято):
    `List` возвращает то же самое сообщение ресурса, что и `Get`, поэтому «видеть в
    списке без содержимого» на такой выдаче нереализуемо — членство в странице и есть
    содержимое. Предикат страницы приведён к ОТНОШЕНИЮ ЧТЕНИЯ типа
    (`services/iam/internal/authzfilter/visibility.go` → `pageRelations`; для
    group/serviceAccount/project это `v_get`), и принятое следствие записано там же
    дословно: «роль с одним лишь глаголом `list` больше не показывает объект».
    Кейс, продолжающий требовать снятое, закрепляет прошлое поведение и краснеет на
    исправном продукте — поэтому он ПЕРЕНАЦЕЛЕН на действующий контракт, а не ослаблен.

    ЧТО УТВЕРЖДАЕТСЯ ТЕПЕРЬ — равенство двух множеств, наблюдаемое с обеих сторон:
      отрицательное плечо: выдача {verbs:[list]} по метке `foo` → объект НЕ в списке И
                           его Get отвечает 404 (страница не шире чтения);
      положительный контроль: выдача {verbs:[get,list]} по метке `ctl` тому же субъекту
                           в том же аккаунте → второй объект В списке И его Get 200
                           (страница не уже чтения).
    Плечи расцеплены по КЛЮЧУ метки (`foo` против `ctl`), поэтому ни один селектор не
    может выбрать объект чужого плеча.

    ЗАЧЕМ ОБЯЗАТЕЛЕН ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Одинокое «не виден» зеленеет сильнее всего
    именно тогда, когда сломано ВСЁ: неверный субъект выдачи, неподнявшаяся фикстура,
    непоехавшая материализация — любая из этих поломок даёт «не виден» и выдаёт себя за
    исполненный инвариант. Контроль сходится в том же прогоне, тем же субъектом и в том
    же аккаунте, поэтому отрицание доказывает СВОЙ предмет, а не общую неработоспособность.
    (Ровно этот класс и стоил шести утверждений: выдача уезжала на ряд, которым ни один
    предъявитель не аутентифицируется — см. `grant_bylabel_generic`.)"""
    spec = TYPE_SPECS[kind]
    neg = pfx + "Vl"          # плечо list-only: не должен быть виден и не должен читаться
    ctl = pfx + "VlCtl"       # положительный контроль: get+list → виден и читается
    return [
        *mk_obj(spec, f"{spec['stem']}vl", "foo", neg, neg + "Op"),
        *mk_obj(spec, f"{spec['stem']}vc", "ctl", ctl, ctl + "Op"),
        *preclean_account_loop(pfx + "Vl", "create-role"),
        # отрицательное плечо — только `list`
        *grant_bylabel_generic(spec, pfx + "VlRole", pfx + "VlAcb", pfx + "VlRoleOp",
                               pfx + "VlBindOp", ["list"], role_name, match_key="foo"),
        # положительный контроль — `get` + `list` на ДРУГОМ ключе метки
        *grant_bylabel_generic(spec, pfx + "VcRole", pfx + "VcAcb", pfx + "VcRoleOp",
                               pfx + "VcBindOp", ["get", "list"], role_name + "c",
                               match_key="ctl"),
        # Ждём СХОЖДЕНИЯ контроля: пока он не виден, про отрицательное плечо ничего
        # утверждать нельзя — «не виден» было бы неотличимо от «ещё не материализовано».
        poll_request_until_status(
            name="read-list-parity", method="GET",
            path=spec["path"] + "?accountId={{accountAId}}&pageSize=1000",
            auth="jwtInvitee", expect_code=200, retry_on=(403, 404),
            retry_predicate=("(() => { try { const ids = (pm.response.json()." + spec["key"]
                             + " || []).map(o => o.id); return ids.indexOf(pm.environment.get('"
                             + ctl + "')) === -1; } catch (e) { return true; } })()"),
            test_script=[
                "const j = pm.response.json();",
                "const ids = (j." + spec["key"] + " || []).map(o => o.id);",
                "pm.test('" + kind + ": ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — объект с грантом {get,list} ВИДЕН в списке "
                "(страница не уже чтения; без этого отрицание ниже ничего не доказывает)', () => "
                "pm.expect(ids.indexOf(pm.environment.get('" + ctl + "')) !== -1, 'ids: ' + JSON.stringify(ids)).to.be.true);",
                "pm.test('" + kind + ": объект с грантом {list} БЕЗ {get} НЕ виден в списке "
                "(членство в странице равно отношению чтения — docs/architecture/"
                "list-page-membership-equals-read-relation.md)', () => "
                "pm.expect(ids.indexOf(pm.environment.get('" + neg + "')) !== -1, 'ids: ' + JSON.stringify(ids)).to.be.false);",
            ],
        ),
        Step(name="detail-get-listonly-closed", method="GET",
             path=spec["path"] + "/{{" + neg + "}}", auth="jwtInvitee",
             test_script=[
                 "pm.test('" + kind + ": Get объекта с грантом {list} без {get} → 404 (содержимое закрыто, hide-existence)', "
                 "() => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
                 "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                 "pm.test('grpc code 5 (NOT_FOUND)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
             ]),
        Step(name="detail-get-control-open", method="GET",
             path=spec["path"] + "/{{" + ctl + "}}", auth="jwtInvitee",
             test_script=[
                 "pm.test('" + kind + ": ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — Get объекта с грантом {get,list} → 200 "
                 "(404 здесь означал бы, что 404 выше про сломанную фикстуру, а не про предикат)', "
                 "() => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(200));",
             ]),
        *robust_revoke_binding("teardown-binding", pfx + "VlAcb"),
        *robust_revoke_binding("teardown-binding-ctl", pfx + "VcAcb"),
        *teardown("teardown-role", "/iam/v1/roles/{{" + pfx + "VlRole}}"),
        *teardown("teardown-role-ctl", "/iam/v1/roles/{{" + pfx + "VcRole}}"),
        *teardown("teardown-obj", spec["path"] + "/{{" + neg + "}}"),
        *teardown("teardown-obj-ctl", spec["path"] + "/{{" + ctl + "}}"),
    ]


# Per-type case selection is NOT uniform, и решает это ПРЕДИКАТ СТРАНИЦЫ ТИПА —
# `services/iam/internal/authzfilter/visibility.go` → `pageRelations` (сверено с деревом
# и с гейтом `internal/repohygiene/listreadrelationparity_test.go`, который читает
# отношение чтения из сгенерированного каталога прав):
#   - serviceAccount / group / project — предикат страницы `v_get`, то есть ТОТ ЖЕ, чем
#     гейтится одиночный Get. Значит осмысленны оба кейса: точный набор по метке и
#     равенство «в списке ⟺ читается по id» (list-only не показывает и не читается).
#   - role — ЕДИНСТВЕННОЕ исключение: предикат страницы `{viewer, v_list}`, потому что у
#     чтения роли нет отношения в каталоге, а `RoleService.Get` пускает любого члена
#     аккаунта по ярусу viewer. Поэтому для роли равенство «страница ⟺ чтение» неверно
#     BY CONSTRUCTION и кейс паритета для неё НЕ выпускается — выпускается только точный
#     набор. Это не пробел, а другой контракт: он объявлен в `pageRelations` рядом с
#     остальными и там же объяснён.
EXACT_SET_TYPES = [("serviceAccount", "setSva", "SVA"), ("role", "setRol", "ROL"),
                   ("group", "setGrp", "GRP")]
# Типы, чей предикат страницы РАВЕН отношению чтения (`v_get`) → паритет наблюдаем.
LIST_READ_PARITY_TYPES = [("serviceAccount", "setSva", "SVA"), ("group", "setGrp", "GRP")]

for _kind, _pfx, _abbr in EXACT_SET_TYPES:
    CASES.append(Case(
        id=f"IAM-SET-{_abbr}-LABEL-EXACT-OK",
        title=f"exact-set ({_kind}): 3 {{foo=runId}} (M+), 3 no-label (M−), 2 {{baz=runId}}; by-label grant {{iam.{_kind} get,list matchLabels foo}} → subject's List contains exactly the M+ set",
        classes=["RBAC", "AUTHZ", "VISIBILITY", "INV2", "LABELS", "EXACT-SET"],
        priority="P0",
        # verifies (non-matching label hidden)
        steps=exact_set_case_steps(_kind, _pfx, f"stlbl{_abbr.lower()}"),
    ))

for _kind, _pfx, _abbr in LIST_READ_PARITY_TYPES:
    CASES.append(Case(
        id=f"IAM-SET-{_abbr}-LIST-READ-PARITY",
        title=f"членство в странице равно чтению ({_kind}): грант {{iam.{_kind} list БЕЗ get}} → объекта НЕТ в списке И его Get 404; парный контроль {{get,list}} на другом ключе метки → в списке И Get 200",
        classes=["RBAC", "AUTHZ", "VISIBILITY", "INV1", "LABELS", "NEG"],
        priority="P0",
        # verifies (docs/architecture/list-page-membership-equals-read-relation.md)
        steps=list_read_parity_case_steps(_kind, _pfx, f"stvl{_abbr.lower()}"),
    ))
