// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package role — CQRS port-iface'ы для kacho_iam.roles.
package role

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/visibility"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.RoleID) (domain.Role, error)

	// GetWithVersion returns the role plus its optimistic-concurrency token.
	// roles has NO version column (like access_bindings), so the token is the
	// row's `xmin::text` snapshot (the read-modify-write OCC pattern without a
	// version column). The token is opaque to the caller: Role.Update reads it in
	// the sync request-path, echoes it into UpdateCAS in the worker-tx, and a
	// mismatch (a concurrent Role.Update bumped xmin) is rejected by UpdateCAS
	// with ErrFailedPrecondition. Not-found → ErrNotFound (verbatim Get text).
	GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error)
	// List — может фильтровать по is_system и/или account_id.
	List(ctx context.Context, filter ListFilter) ([]domain.Role, string, error)
	// ListAssignable — roles valid for binding on (resourceType, resourceID)
	// per the assignability matrix: system roles always; account-scoped
	// custom only on its own account; project-scoped custom only on its own
	// project; cluster ⇒ system only. The predicate is encoded in the SQL WHERE
	// (mirror of domain.IsRoleAssignable) so keyset pagination is correct
	// across the filtered set. resourceType is one of account|project|cluster
	// (caller validates the whitelist + id format first).
	ListAssignable(ctx context.Context, resourceType, resourceID string, filter ListFilter) ([]domain.Role, string, error)

	// UnresolvedSegments отвечает, КАКИЕ из ОБЪЯВЛЕННЫХ сегментов каждой роли не
	// дают ни одной строки проекции `role_verb` — той единственной таблицы,
	// которую читает цепь вердикта (#1035).
	//
	// Вопрос задаётся ОДИН на страницу: объявленная сторона приходит массивами
	// от вызывающего, который её уже прочитал, а не вычитывается здесь второй
	// раз. Стоимость поэтому следует СТРАНИЦЕ (её величина ограничена
	// контрактом), а не популяции ролей, которая не ограничена ничем.
	//
	// Роль, у которой ни один сегмент не остался без проекции, в ответе
	// ОТСУТСТВУЕТ — ноль выражается отсутствием ключа. Пустой вход законен и
	// означает «спрашивать не о чем»; вызывающий вправе не звать вовсе.
	//
	// # Почему СРЕЗ, а не счётчик — и почему второго метода рядом не заводится
	//
	// Счётчик отвечает на вопрос роли («сколько потеряно») и не отвечает на
	// вопрос правила («какое именно», #1962). Метод-сосед, отдающий срез, был бы
	// вторым запросом и вторым местом, где решается, ЧТО считается
	// неразрешённым, — и разошлись бы они молча, потому что оба возвращают
	// правдоподобные числа на любом входе.
	//
	// Величина счётчика от замены не меняется: вход дедуплицирован
	// (`domain.RuleRefsOf`), поэтому прежний `count(*)` тождественно равен длине
	// среза. Вызывающий берёт её длиной.
	UnresolvedSegments(ctx context.Context, declared []domain.RoleSegment) (map[domain.RoleID][]domain.RoleSegment, error)

	// WithdrawnGrants отвечает, ЧТО у каждой роли отобрано и почему (#1992):
	// строки ведомости переселения, в которые уехали проекции, потерявшие
	// референт при снятии строки каталога платформы.
	//
	// Ведомость до этого читателя НЕ ЧИТАЛ НИКТО: она наполнялась применителем и
	// была невидима отовсюду, поэтому «право отобрали» со стороны арендатора не
	// отличалось от «права не было» — тот же класс, что «значение, которое пишут
	// и не читают».
	//
	// Вопрос задаётся ОДИН на страницу, как и у соседа выше: стоимость обязана
	// следовать СТРАНИЦЕ, величина которой ограничена контрактом, а не популяции
	// ролей, которая не ограничена ничем.
	//
	// Роль без единой строки ведомости в ответе ОТСУТСТВУЕТ — пусто выражается
	// отсутствием ключа, а не пустым срезом. Пустой вход законен и означает
	// «спрашивать не о чем».
	//
	// Порядок внутри роли — НАБОР, а не последовательность: сверять его надо по
	// составу. Отдаётся он упорядоченным лишь затем, чтобы ответ был
	// воспроизводим от прогона к прогону.
	WithdrawnGrants(ctx context.Context, roleIDs []domain.RoleID) (map[domain.RoleID][]domain.WithdrawnGrant, error)

	// PrunedSelectorTypes отвечает, какие точечные типы ВЫРЕЗАНЫ из отбора
	// правил каждой роли и почему (#1988): строки ведомости вырезания, в которую
	// применитель кладёт элементы, потерявшие живую строку каталога.
	//
	// Ведомость до этого читателя НЕ ЧИТАЛ НИКТО — тот же класс и та же цена,
	// что были у соседа выше: «значение, которое пишут и не читают». Заведена
	// она затем, чтобы необратимое вырезание перестало быть безмолвным, и не
	// давала этого, потому что цепочка обрывалась на пути чтения.
	//
	// Вопрос задаётся ОДИН на страницу, как у обоих соседей: стоимость обязана
	// следовать СТРАНИЦЕ, величина которой ограничена контрактом, а не популяции
	// ролей, которая не ограничена ничем.
	//
	// Роль без единой строки ведомости в ответе ОТСУТСТВУЕТ — пусто выражается
	// отсутствием ключа, а не пустым срезом. Пустой вход законен и означает
	// «спрашивать не о чем».
	//
	// ОТПЕЧАТОК ПРАВИЛА НАРУЖУ НЕ ЕДЕТ: он ключ хранения, не координата (см.
	// [domain.PrunedSelectorType]). Поэтому строки, различавшиеся ТОЛЬКО им,
	// отдаются ОДНОЙ записью — иначе вызывающий получил бы пару неотличимых.
	//
	// Порядок внутри роли — НАБОР, а не последовательность: сверять его надо по
	// составу. Отдаётся он упорядоченным лишь затем, чтобы ответ был
	// воспроизводим от прогона к прогону.
	PrunedSelectorTypes(ctx context.Context, roleIDs []domain.RoleID) (map[domain.RoleID][]domain.PrunedSelectorType, error)

	// Lifecycles отвечает, ОБЪЯВЛЕНА ли каждая названная роль манифестом модуля
	// сегодня либо СНЯТА, и при каких обстоятельствах (#1913).
	//
	// Отдельный вопрос от трёх соседей выше, и различие несущее: те отвечают
	// «даёт ли роль то, что объявляет», а этот — «стоит ли за ней объявление
	// вообще». `ROLE_HEALTH_EMPTY` даёт и снятая роль, и объявленная, чьи строки
	// каталога сняты, — а следующий шаг у арендатора разный.
	//
	// Вопрос задаётся ОДИН на страницу, как у соседей: стоимость обязана
	// следовать СТРАНИЦЕ, величина которой ограничена контрактом.
	//
	// Роль, чьей строки нет, в ответе ОТСУТСТВУЕТ, и вызывающий оставляет
	// нулевое состояние — «этим ответом не вычислено». Пустого состояния у
	// существующей строки не бывает: `roles_live_matches_retired` не оставляет
	// третьего.
	Lifecycles(ctx context.Context, roleIDs []domain.RoleID) (map[domain.RoleID]domain.RoleLifecycle, error)
}

type WriterIface interface {
	// Insert — только custom-role. System-роли
	// создаются миграцией; попытка Insert с is_system=true в use-case'е →
	// InvalidArgument до repo (см. role-RPC handler).
	Insert(ctx context.Context, r domain.Role) (domain.Role, error)
	Update(ctx context.Context, r domain.Role, updateMask []string) (domain.Role, error)

	// UpdateCAS is Update guarded by an xmin OCC token. It runs a
	// single-statement `UPDATE roles SET … WHERE id=$id AND xmin::text=$expected
	// RETURNING …`: the row-lock serializes concurrent Role.Updates, so the loser
	// reads the SAME expected version, finds xmin bumped, matches 0 rows →
	// ErrFailedPrecondition (the caller's whole writer-tx — UPDATE + the FGA
	// reconcile fan-out — rolls back together, ban #10). expectedVersion=="" skips
	// the predicate (unconditional last-writer Update — back-compat for callers
	// that do not read a token). 0 rows with a non-empty token ⇒ either the row
	// moved concurrently or it no longer exists → ErrFailedPrecondition.
	UpdateCAS(ctx context.Context, r domain.Role, updateMask []string, expectedVersion string) (domain.Role, error)
	// Delete — system-role нельзя удалять → use-case
	// возвращает FailedPrecondition до похода в БД. Custom с активными bindings —
	// FK RESTRICT (`access_bindings_role_fk`) → SQLSTATE 23503 → FailedPrecondition.
	Delete(ctx context.Context, id domain.RoleID) error

	// UpsertSystemRole заводит либо приводит к объявленному состоянию строку
	// СИСТЕМНОЙ роли — той, чей ярус кластерный (`cluster_id` непуст, отчего
	// вычисляемый `is_system` истинен). Единственный писатель системной строки,
	// не являющийся миграцией (приёмка
	// `services/iam/docs/engineering/acceptance/roles-come-as-data-not-migrations.md`
	// §3.1); `Insert` выше её произвести НЕ МОЖЕТ by construction — `cluster_id`
	// в его перечне колонок отсутствует.
	//
	// # Приведение по `id`, и НИКОГДА не «снять и положить»
	//
	// Роль с выдачами удалить нельзя — `access_bindings_role_fk … ON DELETE
	// RESTRICT` отвергнет операцию; а если бы не отверг, каскад унёс бы селекторы,
	// проекцию глаголов и проекцию сегментов молча. Поэтому оператор ОДИН:
	// вставка с приведением при конфликте по первичному ключу.
	//
	// # `changed` есть свойство ОПЕРАТОРА, а не сравнение в коде
	//
	// Приведение исполняется только при отличии объявленных полей — предикат
	// стоит в `WHERE` ветви `DO UPDATE`, поэтому «ноль отличий» даёт ноль
	// затронутых строк, и вызывающий узнаёт об этом по `changed=false`. Сравнение
	// в коде было бы software check-then-act (запрет #10): между чтением и
	// записью помещается чужая правка.
	//
	// `labels` и `created_at` пишутся ТОЛЬКО при вставке: манифест их не
	// объявляет, и приведение, стиравшее бы метки арендатора, объявляло бы
	// владение тем, чего манифест не несёт.
	UpsertSystemRole(ctx context.Context, r domain.Role) (out domain.Role, changed bool, err error)

	// ReplaceRuleSelectors syncs kacho_iam.role_rule_selectors with the role's
	// UNIFIED materializing rules: ARM_ANCHOR
	// (all) + ARM_NAMES + ARM_LABELS. It DELETEs the role's current selector rows and
	// INSERTs one per materializing rule (keyed by rule_fp), inside the caller's
	// writer-tx (atomic with the role INSERT/UPDATE, ban #10) — so a removed/edited
	// rule drops/replaces its selector together with the rules change. The
	// reconciler's fast-path + sweep JOIN this table to find which bindings a
	// mirror-change event affects (forward-materialization). A legacy
	// permissions-only role clears its selectors (DELETE then no INSERT). Idempotent
	// re-sync (same rules → same set).
	ReplaceRuleSelectors(ctx context.Context, roleID domain.RoleID, selectors []domain.RuleSelector) error

	// ReplaceRoleVerbs syncs kacho_iam.role_verb — проекцию «роль → тип объекта ×
	// глагол», которой отвечает форма E.
	//
	// Отдельно от ReplaceRuleSelectors, потому что это ДРУГАЯ сторона того же
	// правила: та отвечает «подходит ли объект» (типы и метки), эта — «разрешено
	// ли действие» (глаголы). Спутать их дорого: запрос вердикта присоединяет обе,
	// и подмена одной другой даёт ответ, верный по форме и неверный по существу.
	ReplaceRoleVerbs(ctx context.Context, roleID domain.RoleID, pairs []domain.RoleVerb) error

	// ReplaceRuleRefs syncs kacho_iam.role_rule_ref — проекцию ОБЪЯВЛЕННЫХ
	// сегментов правила, на которой возможен внешний ключ в каталог.
	//
	// Ключ на `roles.rules jsonb` невыразим by construction: проверка значения не
	// умеет спрашивать другую таблицу (подзапрос в CHECK отвергается DDL). Поэтому
	// объявление проецируется строками, и пишет их ТОТ ЖЕ оператор и та же
	// транзакция, что и само правило, — иначе между ними помещается снятие строки
	// каталога, и правило переживёт свой референт.
	//
	// Отличие от ReplaceRoleVerbs — в том, ЧТО кладётся: та проекция несёт только
	// резолвящееся, эта — КАЖДЫЙ объявленный сегмент. Пропуск нерезолвящегося и
	// есть дефект, который ключ закрывает.
	ReplaceRuleRefs(ctx context.Context, roleID domain.RoleID, refs []domain.RoleRuleRef) error

	// LiveSystemRoles — живые системные роли, какими их видит ЭТА транзакция
	// (#1913).
	//
	// Отдаётся ВСЯ популяция, а не роли одного модуля: классификацию по
	// владельцу делает сверка, и её перепись обязана называть чужие модули и
	// роли без владельца отдельными числами. Сузив чтение здесь, мы отдали бы
	// сверке множество, на котором эти числа тождественно нулевые.
	LiveSystemRoles(ctx context.Context) ([]domain.Role, error)

	// RetireRole снимает роль модуля: переселяет её проекции в ведомость,
	// снимает их и помечает строку — ОДНОЙ транзакцией вызывающего (#1913).
	//
	// Порядок «проекции → пометка» держат КЛЮЧИ ЖИВОСТИ, а не порядок вызовов:
	// пометка роли с живой проекцией отвергается `23503`. Сужение по
	// `ownerModule` стоит в предикате оператора, а не проверкой перед ним:
	// проверка была бы check-then-act (ban #10).
	//
	// `Marked=false` — ШТАТНЫЙ исход, а не отказ: роль уже снята либо владелец
	// не тот. Повторное применение того же манифеста законно.
	RetireRole(ctx context.Context, id domain.RoleID, ownerModule, reason, actor string) (
		domain.RoleRetirement, error)

	// ReviveRole оживляет снятую роль и снимает из ведомости строки СВОЕЙ
	// причины — одним оператором (#1913).
	//
	// Оба действия неделимы: `withdrawn_grants` говорит настоящим временем «что
	// у роли ОТОБРАНО», поэтому здоровая оживлённая роль с непустым списком
	// утверждала бы о себе неправду. Строки причины «снят каталог» не трогаются.
	//
	// `false` означает «оживлять нечего» — строка и так жива, — а не отказ.
	ReviveRole(ctx context.Context, id domain.RoleID) (bool, error)
}

type ListFilter struct {
	PageSize int32
	// PageToken — токен, КАК ЕГО ПРИСЛАЛ КЛИЕНТ. Его разбирает use-case (форма
	// токена принадлежит контракту RPC, а не таблице), поэтому на пути к
	// репозиторию он пуст, а курсор приезжает разобранным в After.
	PageToken string
	Filter    string
	// AccountID — scope the catalog to a single Account: the result is system
	// roles (always — catalog floor) PLUS the custom roles of THIS Account; a
	// foreign Account's custom roles are excluded at the SQL layer. Empty → no
	// Account scope.
	AccountID domain.AccountID
	IsSystem  *bool // nil = both

	// After — курсор keyset В РАЗОБРАННОМ ВИДЕ: страница начинается со строки,
	// строго следующей за (CreatedAt, ID). nil — с начала.
	After *Cursor

	// Candidates — сужение НАБОРА КАНДИДАТОВ до надмножества видимого
	// вызывающему (задача #645).
	//
	// # Это НЕ то push-down, который здесь раньше запрещался
	//
	// На этом месте стояло «visible-id push-down здесь намеренно НЕТ», и запрет
	// был верен для того, что он описывал: набор ВИДИМЫХ id, добытый у модели
	// перечислением (`ListObjects`), режется server-side пределом без
	// continuation-token, поэтому сужение запроса по нему молча прятало
	// собственные роли тенанта. Тот запрет остаётся в силе — перечисления у
	// модели здесь по-прежнему нет.
	//
	// Этот набор — другой по ИСТОЧНИКУ и по СМЫСЛУ: он приходит из собственных
	// таблиц iam (`internal/repo/kacho/visibility`), предела не имеет и является
	// НАДМНОЖЕСТВОМ видимого — вердикт по каждому кандидату по-прежнему выносит
	// модель (`security.md` §«Авторизация живёт в МОДЕЛИ»). Без него страница
	// берётся окном по всей таблице и всякая роль, перед которой лежит больше
	// `page_size` невидимых предшественников, до сужения не доезжает вовсе.
	//
	// Каталог системных ролей — ПОЛ этой поверхности, и он входит в набор
	// условием (`is_system`), а не постфильтром: пол, применённый к уже взятой
	// странице, повторяет исходный дефект — строка становится полом, только если
	// она в страницу попала.
	//
	// nil ЗНАЧИТ «не сужать», и это НЕ то же, что пустой набор.
	Candidates *visibility.PageScope
}

// Cursor — граница keyset-обхода `(created_at, id) ASC`.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}
