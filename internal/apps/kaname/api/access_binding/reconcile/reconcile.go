// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reconcile — selector/containment reconciler.
//
// Selector membership is DYNAMIC: labels change in the owning service and arrive
// over the compute→iam RegisterResource edge into kaname.resource_mirror.
// The reconciler MATERIALIZES the desired per-object set for a binding from the
// mirror (same-DB, no iam→owner peer call — keeps the graph acyclic), DIFFS
// it against the stored access_binding_target_members, and EMITS/EAGER-REVOKEs
// the per-object FGA tuples through fga_outbox — all in ONE writer-tx (ban #10).
//
// Clean Architecture: this use-case depends ONLY on the domain + the
// ReconcileStore / BindingSource ports (defined here). The pgx implementation is
// the adapter in repo/kaname/pg. No pgx/grpc here.
//
// Triggers:
//
//	(a) Create / Role.Update (rules change) — ReconcileBinding(bindingID).
//	(b) resource_mirror change (RegisterResource) — ReconcileObject(type,id) via
//	    the resource_reconcile_outbox event.
//	(c) periodic sweep — ReconcileBinding over every label-selector binding,
//	    defense-in-depth against a lost event / worker restart.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// BindingScope — the minimal binding facts the reconciler needs to materialize
// membership: the scope-anchor and the FGA emission inputs (subject + the role's
// ARM_LABELS selectors). Loaded by BindingSource from a binding id. The
// rules-based RBAC model has no per-binding target arm — the
// binding is thin; the only dynamic membership source is the role's ARM_LABELS
// rules (LabelSelectors).
type BindingScope struct {
	BindingID domain.AccessBindingID
	Scope     domain.ScopeAnchor
	// Subjects — ВЕСЬ перечень субъектов выдачи (`access_binding_subjects`), в
	// порядке запроса. Разворачивание судит каждого (subjects.go, kaname#880):
	// одиночной пары «вид, идентификатор» здесь нет намеренно — она была
	// проекцией первого субъекта, и выдача разворачивалась ему одному.
	Subjects []domain.Subject
	RoleID   string
	// Policy — политика роли выдачи ([domain.PolicyOfRole] её строки). От неё
	// зависит набор глаголов правила: правка влечёт удаление у ролей платформы и
	// арендатора и не влечёт у роли модуля (kaname#1006). Нулевая — самая строгая
	// ветвь: удаление не приписывается.
	Policy domain.RulePolicy
	// Selectors — the role's UNIFIED materializing selectors (flat explicit
	// RBAC model): ARM_ANCHOR(all) + ARM_NAMES + ARM_LABELS. When non-empty the
	// binding has dynamic per-rule membership: each selector (rule_fp) is matched
	// against the feed per its arm (all-in-scope / by-id / by-label) and
	// materialized; the per-object tuples are derived from the selector's VERBS.
	// Empty ⇒ a thin binding with no materialized members (e.g. a legacy
	// permissions-only role — its tier tuples are the binding-level Create concern,
	// not here). Binding-time scope_grant emission is removed; the reconciler is the
	// SINGLE materialization path.
	Selectors []domain.RuleSelector
	// ScopeSelfVerbs — the role's verbs that apply to the binding's OWN scope
	// resource-type: a `*.*` superuser rule OR an
	// `iam.<scopeResource>` rule. When non-empty the reconciler materializes the
	// tier (+ verb-bearing v_*) tuple ON THE SCOPE OBJECT ITSELF (the write-authz /
	// no-access-loss anchor). Empty ⇒ a content-only role grants nothing on the
	// scope anchor (its access lives on the matched content objects). Derived by the
	// adapter from role.Rules.ScopeSelfVerbs(scope.resource).
	ScopeSelfVerbs []string
	// Target — the binding's per-object least-privilege selection (redesign-2026 F8,
	// IAM-1-21). When Target.Resources is non-empty the grant is restricted to EXACTLY
	// the listed objects: the role.rules ARM_ANCHOR arm is resolved by the target ids
	// (never MatchAllInScope), every arm's matches are INTERSECTED with the target set,
	// and the scope-self anchor grant is SUPPRESSED (a per-object target never grants
	// tier on the whole scope object). AllInScope / empty ⇒ the whole-anchor grant
	// (existing behaviour — the role.rules selectors drive membership across the scope).
	// Loaded by the adapter from the persisted access_bindings.target column.
	Target domain.AccessTarget
	// Active reports whether the binding is still ACTIVE (a REVOKED/expired
	// binding is not re-materialized).
	Active bool
}

// DesiredMember — one object the reconciler decided belongs to a binding's
// membership, with the containment verdict and the FGA tuples to emit when
// ACTIVE. ObjectType is the dotted closed-table key.
//
// RuleFP attributes the desired member to the producing role.rules ARM_LABELS rule
// — its content-hash. Tuples is the per-object FGA tuple set to emit
// on an ACTIVE transition, precomputed from the rule's verbs (carried here so
// applyDiff need not re-derive). In the rules-based RBAC model there
// is no legacy selector/byName arm — every member is rule-derived.
type DesiredMember struct {
	RuleFP     string
	ObjectType string
	ObjectID   string
	Status     domain.VerificationStatus
	Tuples     []domain.MembershipTuple
	// typeUnresolved — объект сопоставлен правилу и лежит в области выдачи, но его
	// тип не знает снимок каталога процесса: кортежей собрать нечем. Статуса у такого
	// члена нет, и сам по себе он ничего не выдаёт; исход решает строка каталога в
	// базе (catalog_lag.go, kaname#937).
	typeUnresolved bool
}

// MemberCoord — координата члена выдачи, выпустившего строку реестра: точечное имя
// типа и идентификатор объекта (`access_binding_target_members.object_type`,
// `.object_id`). Строка реестра отвечает ровно за свою координату, и снятие члена
// выбирает строки по ней, а не разбором объекта кортежа: суффикс `:<id>` у объектов
// разных типов одной выдачи совпадает, а имя типа модели из снимка каталога процесса
// у реплики бывает не тем, что было при выдаче (kaname#933). Нулевая координата —
// строка уровня выдачи (`source='binding'`), у неё члена нет.
type MemberCoord struct {
	ObjectType string
	ObjectID   string
}

// coordOf — координата материализованного члена.
func coordOf(m domain.TargetMember) MemberCoord {
	return MemberCoord{ObjectType: m.ObjectType, ObjectID: m.ObjectID}
}

// desiredCoord — координата желаемого члена.
func desiredCoord(d DesiredMember) MemberCoord {
	return MemberCoord{ObjectType: d.ObjectType, ObjectID: d.ObjectID}
}

// LedgerRow — строка реестра выпущенного: координата члена и кортеж. Ключ реестра —
// (выдача, координата, кортеж): один кортеж от двух координат одной выдачи — две
// строки, и уход одной координаты не забирает строку другой.
type LedgerRow struct {
	Member MemberCoord
	Tuple  domain.MembershipTuple
}

// EmittedTupleRef — одна запись реестра выданных кортежей вместе с выдачей и членом,
// которые её породили. Нужна затем, чтобы весь веер прохода записывался ОДНИМ
// обращением: реестр ключуется по (выдача, координата члена, субъект, отношение,
// объект), поэтому выдача и координата обязаны ехать вместе с кортежем, а не быть
// общими параметрами вызова.
type EmittedTupleRef struct {
	BindingID domain.AccessBindingID
	Member    MemberCoord
	Tuple     domain.MembershipTuple
}

// ReconcileStore — the tx-scoped port the reconciler drives. Every method runs
// inside the single writer-tx the implementation opens for one reconcile pass,
// so the membership writes + FGA tuple emits + containment audit all commit
// together or roll back together (ban #10). The implementation is the pg
// adapter. NOTE: reconcile commits its OWN tx; the resource_reconcile_outbox
// event is marked sent in a SEPARATE short tx by the worker after this commit
// (at-least-once, redelivery safe — the reconcile diff is idempotent), NOT in
// this tx.
type ReconcileStore interface {
	// AcquireBindingLock takes pg_advisory_xact_lock(hashtext(binding_id)) on the
	// reconcile writer-tx. It is the FIRST statement
	// of a per-binding reconcile so concurrent passes of the SAME binding serialize
	// on the xact-scoped lock (released automatically on commit/rollback — never
	// pool-scoped). This makes the concurrent integration assertion
	// deterministic and, together with the LoadBinding `SELECT … FOR NO KEY UPDATE`
	// row lock + the ledger partial-UNIQUE backstop, guarantees exactly-once
	// materialization under N replicas.
	//
	// SHARE-режима у этого порта НЕТ и он не нужен: аддитивный форвард не берёт
	// advisory вовсе (reconcile/forward.go, «LOCK CHOICE»). Прежний
	// AcquireBindingLockShared существовал ради одного — развести дочерние вставки
	// форварда с `FOR UPDATE` полного прохода; режим строки ослаблен до
	// `FOR NO KEY UPDATE`, конфликта нет, и метод снят, чтобы ожидание не завелось
	// обратно «по аналогии».
	AcquireBindingLock(ctx context.Context, bindingID domain.AccessBindingID) error

	// AcquireBindingLocks берёт advisory-замки СРАЗУ ВСЕГО набора, в переданном
	// порядке и ДО первой записи прохода. Набор приходит уже отсортированным по
	// возрастанию (dedupSortBindingIDs), поэтому порядок глобально согласован между
	// параллельными проходами.
	//
	// ЗАЧЕМ ОТДЕЛЬНЫЙ ПОРТ, А НЕ ЦИКЛ ИЗ AcquireBindingLock. Предмет здесь не в числе
	// обращений, а в ПОРЯДКЕ РОДОВ ресурсов внутри транзакции. Проход веера трогает
	// строки ПРЯМОГО ФАКТА, а они общие: ключуются субъектом, объектом и отношением,
	// а не выдачей, — поэтому две выдачи одного субъекта на одном объекте спорят за
	// ОДНУ строку. Пока замок брался перед работой КАЖДОЙ выдачи, проход вставал в
	// очередь за advisory очередной выдачи, УЖЕ удерживая строки прямого факта
	// предыдущей. Снятие выдачи берёт свой advisory первым стейтментом и трогает
	// прямой факт после него — то есть порядок родов у двух сторон обратный, и
	// Postgres выходит из него, снимая одну сторону (40P01).
	//
	// Свойство, которое даёт этот порт: пока проход ждёт чужой advisory, он НЕ
	// удерживает ни одной строки прямого факта. Тогда сторона, держащая этот
	// advisory, доводит свою работу до конца, и цикла ожидания не существует
	// by construction — а не «редко случается».
	//
	// Идемпотентен внутри транзакции: повторный захват уже удерживаемого ключа
	// возвращается немедленно.
	AcquireBindingLocks(ctx context.Context, bindingIDs []domain.AccessBindingID) error

	// LockBindingsAndRoles берёт строки выдач набора `FOR NO KEY UPDATE` (тот же
	// режим, что LoadBinding), а затем строки их ролей `FOR KEY SHARE` (тот же
	// режим, что чтение роли прохода), каждый род — одним оператором в порядке id и
	// ДО первой записи прохода (kaname#974).
	//
	// ЗАЧЕМ. Снятие регистрации объекта запирает выдачи, чья цель называет ключ, и
	// роли, чьи правила называют его, и только потом пишет (UnregisteredKeyWithdrawal).
	// Проход по объекту прежде брал строку выдачи и её роль ПЕРЕД работой каждой
	// выдачи веера — то есть приходил к роли следующей выдачи, уже записав прямой
	// факт предыдущей, а к выдаче следующей — уже держа роль предыдущей. Общий факт
	// двух выдач одного субъекта на одном объекте и роль с именем ключа замыкали
	// кольцо со снятием: Postgres снимал одну сторону (40P01). Порядок родов у обеих
	// сторон теперь один — выдачи, роли, затем записи, — и кольца нет by
	// construction. Идемпотентен внутри транзакции: последующие чтения прохода берут
	// уже удерживаемые замки.
	LockBindingsAndRoles(ctx context.Context, bindingIDs []domain.AccessBindingID) error

	// LoadBinding — минимальные факты выдачи: область, селекторы, роль. ok=false —
	// выдачи больше нет (удалена: проходу делать нечего, каскад уже снял её членов).
	//
	// Реализация берёт строку выдачи `SELECT … FOR NO KEY UPDATE`: два ПОЛНЫХ прохода
	// одной выдачи идут друг за другом, и снятие устаревшего не гонится само с собой.
	// Аддитивный форвард этим чтением не пользуется — см. LoadBindingForForward.
	LoadBinding(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// LoadBindingForForward — те же факты, что LoadBinding, но под замком строки
	// `FOR KEY SHARE` (и без advisory-замка выдачи). Это чтение АДДИТИВНОГО форварда
	// (ReconcileBindingForward): форвард только ДОБАВЛЯЕТ кортежи и устаревшего не
	// снимает, поэтому взаимного исключения с полным проходом той же выдачи ему не
	// нужно — `FOR KEY SHARE` совместим с `FOR NO KEY UPDATE` полного прохода, и
	// регистрации под одной выдачей редактора или владельца в очередь за ним не встают.
	// Держит замок другое: решение форварда «выдача жива» верно до его коммита. Снятие
	// выдачи (LockBindingForDeactivation, `FOR UPDATE`) с ним конфликтует и не прочитает
	// набор членов и реестр, пока форвард, увидевший выдачу ACTIVE, ещё пишет
	// (kaname#919, kaname#923). Тот же `FOR UPDATE` берёт отзыв по снятию регистрации
	// объекта (kaname#963, F1). ok=false — выдачи больше нет.
	LoadBindingForForward(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// LoadBindingsForForward — то же чтение, что LoadBindingForForward, но для ЦЕЛОГО НАБОРА
	// выдач за фиксированное число обращений к базе (не по два на выдачу).
	//
	// Веер материализации адресуется числом ВЫДАЧ, покрывающих область объекта, а не
	// числом объектов: меняется один объект, а кандидатов у него столько, сколько выдач
	// его области. Перепись по дереву выдач (8267 объектов зеркала) дала p50 = 9
	// кандидатов, p95 = 19, p99 = 226, максимум 227, поэтому поштучное чтение делало
	// хвост в 454 последовательных обращения внутри одной транзакции.
	//
	// Контракт: выдача, которой в базе нет (удалена), в карте ОТСУТСТВУЕТ — ровно как
	// ok=false у одиночного чтения; роль, удалённая из-под выдачи, даёт «нет покрытия»
	// (пустые селекторы), а не ошибку. Строки берутся тем же `FOR KEY SHARE`, что у
	// одиночного чтения, одним оператором в порядке `id` (kaname#919).
	LoadBindingsForForward(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]BindingScope, error)

	// MatchSelector returns the MIRROR objects matching a selector's
	// types+matchLabels (labels @> matchLabels) — the consumer-owned feed
	// (compute/vpc/nlb, FeedMirror). Used to compute the desired set on a
	// ReconcileBinding pass.
	MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// MatchAllInScope returns the mirror objects of the given types (ARM_ANCHOR /
	// `all` — no label filter) NARROWED to the binding's containment `scope`. The scope
	// is pushed into the SQL as a PROVEN SUPERSET of the reconciler's IsContainedIn
	// re-verify (which STILL runs — the SQL only PRE-filters), so the reconciler receives
	// O(scope) rows instead of O(cluster mirror). The consumer-owned feed (FeedMirror).
	// `types` contains ONLY mirror-fed types (the reconciler partitions by feed-source
	// before calling).
	MatchAllInScope(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error)

	// MatchByIDs returns the mirror objects of the given types whose object_id is in
	// `ids` (ARM_NAMES — exact-id selector). An id not
	// (yet) in the mirror is simply absent (PENDING until its RegisterResource lands,
	// then the forward path picks it up). The consumer-owned feed (FeedMirror).
	MatchByIDs(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchAllInScopeIAMDirect / MatchByIDsIAMDirect are the iam-direct
	// analogues for IAM's OWN objects (iam.project / iam.account + content) read SAME-DB
	// from the native tables. `types` contains ONLY iam-direct types. MatchAllInScopeIAMDirect
	// pushes the binding's containment `scope` into the SQL as a PROVEN SUPERSET of the
	// IsContainedIn re-verify (same as MatchAllInScope); MatchByIDsIAMDirect (names arm) stays
	// unscoped — a foreign-scope id-match is a wanted REJECTED-containment audit signal.
	MatchAllInScopeIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error)
	MatchByIDsIAMDirect(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchCreatedByIAMDirect — собственные объекты iam типов `types` в области
	// `scope`, создатель которых — учётка из `creators` (kaname#1003, селектор
	// создателя). Отбор — по индексу «аккаунт, создатель», а не перебором объектов
	// области: число строк пропорционально числу учёток создателя. Тип, факт
	// создателя которого не хранится, не даёт ни одного объекта. Сужение по
	// области — то же доказанное надмножество IsContainedIn, что у ветви якоря.
	MatchCreatedByIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor, creators []string) ([]domain.MirrorObject, error)

	// MatchIAMDirect returns IAM's OWN objects matching a selector's
	// types+matchLabels read SAME-DB from the native tables (FeedIAMDirect —
	// iam.project/iam.account). The returned MirrorObject carries the iam-hierarchy
	// parent (project→its account_id; account→its own id) so the SAME
	// IsContainedIn predicate decides containment. iam-direct objects are always
	// in their source table, so they are never PENDING. `types` here contains ONLY
	// iam-direct types (the reconciler partitions by feed-source before calling).
	MatchIAMDirect(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// GetMirrorObject returns the mirror row for one object (containment verify of
	// a specific member on a mirror-change event / byName ref). ok=false ⇒ not in
	// mirror ⇒ PENDING_VERIFICATION.
	GetMirrorObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error)
	// LockMirrorObjects запирает строки зеркала объектов `objs` под `FOR KEY SHARE`
	// одним оператором в порядке (тип, id) и возвращает те, что есть (kaname#975).
	// В `objs` — только объекты зеркала (не iam-direct).
	//
	// ЗАЧЕМ. Ветви отбора членов по зеркалу — область, метки, вложенное правило —
	// выбирают объект по его строке зеркала, а не по выдаче или роли, которые
	// запирает снятие регистрации. Снятие удаляет строку зеркала, а удаление
	// конфликтует с `FOR KEY SHARE`: проход, запирающий строку объекта перед записью
	// члена по нему, либо видит её и держит до коммита (снятие ждёт его, и
	// пост-фиксационный проход снятия снимает записанное), либо, придя после снятия,
	// её не находит и члена не пишет. Правка меток (`FOR NO KEY UPDATE`) с этим
	// режимом не конфликтует. Строку, которую снятие удаляет прямо сейчас, замок не
	// ждёт, а пропускает как отсутствующую (`SKIP LOCKED`): проход никогда не стоит
	// на строке зеркала и потому не замыкает кольца со снятием (URG-24).
	LockMirrorObjects(ctx context.Context, objs []MemberCoord) (map[MemberCoord]struct{}, error)
	// AncestorObjects — предки объекта из его зарегистрированной цепи, которые
	// есть в зеркале, с метками (kaname#874). По ним путь по объекту решает,
	// охватывает ли объект вложенное правило. Строки предков чтение запирает
	// `FOR KEY SHARE` (kaname#975): охват потомка держится на строке контейнера, и
	// снятие регистрации контейнера не проходит мимо прохода, который по ней решил.
	AncestorObjects(ctx context.Context, objectType, objectID string) ([]domain.MirrorObject, error)
	// MatchDescendants — объекты типов `types`, у которых среди предков есть
	// контейнер типа `containerType` с идентификатором из `containerIDs`, на любой
	// глубине (kaname#874): кандидаты вложенного правила на полном проходе.
	MatchDescendants(ctx context.Context, types []string, containerType string, containerIDs []string) ([]domain.MirrorObject, error)

	// GetIAMDirectObject returns the same-DB own-table projection (containment
	// parents + labels) of ONE iam-native object (iam.project / iam.account + the
	// content types user/serviceAccount/group/role/accessBinding). It is the
	// iam-direct analogue of GetMirrorObject, used by the ADDITIVE forward fast-path
	// for a brand-new iam-direct object — which lives in ITS OWN table, never the
	// mirror. The projection stamps the SAME containment parents (parentAccount /
	// parentProject) and labels the iam-direct match queries produce, so the shared
	// per-object verdict (IsContainedIn / selectorMatchesObject / desiredMemberForObject)
	// decides identically to the FULL path. ok=false when the type is not iam-direct
	// or the row does not exist. Never PENDING (an iam object is in its own table the
	// instant it exists) — same-DB read, no peer call (graph stays acyclic).
	GetIAMDirectObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error)

	// CurrentMembers returns the materialized members of a binding (the diff base) —
	// the WHOLE-binding read, used only by the binding-triggered passes (ReconcileBinding
	// / ExpireBinding / sweep), whose desired set genuinely spans the whole scope.
	CurrentMembers(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.TargetMember, error)

	// CurrentMembersForObject returns the materialized members of ONE binding on ONE
	// object — the NARROW diff base of the object-triggered pass (ReconcileObject). A
	// mirror upsert/delete changes exactly one object, so only that object's members can
	// change; reading the binding's WHOLE member set for it is the O(mirror) recompute
	// (the two hottest measured bindings carry 10 140 members each). Indexed by the
	// members' (binding_id, object_type, object_id) key.
	CurrentMembersForObject(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string) ([]domain.TargetMember, error)

	// BindingsForObject returns binding ids that have a member referencing the
	// object (used to fan a mirror-change event out to affected bindings).
	BindingsForObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// SelectorBindingsMatchingObject returns ACTIVE selector-binding ids whose
	// selector NOW matches the given mirror object (objectType ∈ selector.types
	// AND mirror.labels @> selector.match_labels) — INCLUDING bindings that do
	// NOT yet have a member row for it. This is the fast-path that lets a brand-
	// new matching object be picked up on the mirror-change event (≤2s) instead
	// of waiting for the periodic sweep. Same-DB read of the
	// selector spec + mirror labels (no peer call — graph stays acyclic).
	SelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// IAMDirectSelectorBindingsMatchingObject is the iam-direct analogue of
	// SelectorBindingsMatchingObject: ACTIVE selector-binding ids whose selector
	// NOW matches the given IAM-OWN object (objectType ∈ selector.types AND the
	// object's OWN-TABLE labels @> selector.match_labels), INCLUDING bindings with
	// no member row yet. Used by the Q2 trigger (Project/Account.Update labels) to
	// pick up a freshly-matching iam-direct object on the label-change event. Same-
	// DB read (own table), no mirror, no peer-call.
	IAMDirectSelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// UpsertMember / DeleteMember materialize/remove a membership row. The member
	// is keyed by the FULL rule coordinate (binding, role-via-binding, rule_fp,
	// object) — so the SAME object under two rules is two rows and a
	// removed rule deletes ONLY its row.
	UpsertMember(ctx context.Context, m domain.TargetMember) error
	DeleteMember(ctx context.Context, bindingID domain.AccessBindingID, ruleFP, objectType, objectID string) error

	// LedgerTuplesForMember — строки реестра, выпущенные ОДНИМ членом выдачи
	// (access_binding_emitted_tuples WHERE binding_id=… AND координата=…), по префиксу
	// первичного ключа. Источник снятия члена: глаголы снятого правила ушли, и кортежи
	// не вывести заново — снимается СОХРАНЁННЫЙ набор. Каталог процесса не читается:
	// координата — та же, что у строки члена (kaname#933).
	LedgerTuplesForMember(ctx context.Context, bindingID domain.AccessBindingID, member MemberCoord) ([]domain.MembershipTuple, error)

	// LedgerTuples — весь реестр выпущенного одной выдачей с координатами строк
	// (access_binding_emitted_tuples WHERE binding_id=…), одним обращением. Читает его
	// полный проход, чтобы довести неизменного члена выдачи нескольким субъектам до
	// полного набора кортежей (emitted_completion.go, kaname#880), и истечение выдачи,
	// снимающее весь учтённый набор.
	LedgerTuples(ctx context.Context, bindingID domain.AccessBindingID) ([]LedgerRow, error)

	// EmitTupleWrite / EmitTupleDelete enqueue the per-object FGA tuples (+ the
	// scope hierarchy parent-pointer is the binding-lifecycle concern handled at
	// Create/Delete, NOT per member) into fga_outbox on the tx.
	EmitTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error
	EmitTupleDelete(ctx context.Context, tuples []domain.MembershipTuple) error

	// RecordEmittedTuples / ForgetEmittedTuples co-commit the per-member FGA tuples
	// into the persisted emitted-tuple ledger (access_binding_emitted_tuples)
	// in the SAME reconcile writer-tx as the matching EmitTupleWrite /
	// EmitTupleDelete (ban #10). The ledger is the authoritative "what was emitted"
	// set the symmetric revoke (delete.go) replays and the Role.Update reconcile
	// fan-out diffs against — UNIFYING the selector arm's per-member tuples with the
	// all_in_scope / resources[] arms' tuples already in the ledger. Without this the
	// selector member-tuples were emitted to fga_outbox but never recorded, so the
	// revoke orphaned them and a role tier change never reconciled them.
	// RecordEmittedTuples пишет строки ОДНОГО члена — с его координатой, INSERT … ON
	// CONFLICT DO NOTHING по полному ключу (повтор идемпотентен); ForgetEmittedTuples
	// снимает ровно названные строки по полному ключу (eager-revoke / fell-out /
	// expiry). A deleted binding's rows are dropped by the FK ON DELETE CASCADE.
	RecordEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, member MemberCoord, tuples []domain.MembershipTuple) error

	// UpsertMembers / RecordEmittedTuplesBatch — те же записи, что UpsertMember и
	// RecordEmittedTuples, но НАБОРОМ и за фиксированное число обращений к базе, каким
	// бы ни был размер веера. Аддитивный форвард материализует по строке члена и по
	// записи реестра на КАЖДУЮ совпавшую выдачу, поэтому поштучная запись делала
	// стоимость прохода линейной по числу выдач области (p50 = 9 кандидатов, хвост 227
	// по дереву выдач) — при том что изменился ровно один объект.
	//
	// Семантика сохраняется дословно: тот же ON CONFLICT, та же идемпотентность повтора,
	// тот же порядок строк (а на порядке id очереди держится поголовный FIFO партиции —
	// выдача и отзыв одного ключа НЕ коммутативны). Пустой набор — no-op.
	UpsertMembers(ctx context.Context, members []domain.TargetMember) error
	RecordEmittedTuplesBatch(ctx context.Context, refs []EmittedTupleRef) error
	ForgetEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, rows []LedgerRow) error

	// EmitContainmentAudit writes the "rejected: not contained in scope" audit
	// event (not silent) on the tx.
	EmitContainmentAudit(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string, scope domain.ScopeAnchor) error

	// RevokeExpiredBinding atomically CAS-transitions an ACTIVE binding to REVOKED
	// (`UPDATE … WHERE status='ACTIVE' AND id=$id`, ban #10 — not TOCTOU). ok=false
	// when 0 rows updated (already revoked / concurrent Delete won). Used by the
	// expiry eager-revoke pass; the per-object tuple revokes are emitted
	// separately by the caller via the ACTIVE members it loaded.
	RevokeExpiredBinding(ctx context.Context, bindingID domain.AccessBindingID) (ok bool, err error)

	// LockBindingForDeactivation берёт строку выдачи `FOR UPDATE` — единственный режим
	// строки, конфликтующий с `FOR KEY SHARE` форварда (LoadBinding(s)ForForward).
	// Снятие (истечение срока) берёт его ДО чтения набора членов: снимаемый набор
	// включает всех членов, которых зафиксировал одновременный форвард, а форвард,
	// пришедший позже, читает выдачу REVOKED (kaname#919). Строки нет — не ошибка:
	// следующее LoadBinding вернёт ok=false.
	LockBindingForDeactivation(ctx context.Context, bindingID domain.AccessBindingID) error

	// EmitSubjectChangeEvent пишет строку журнала смены субъекта в транзакции прохода.
	// Вид события и `op` выбирает вызывающий use-case, порт только пишет: так
	// производитель журнала остаётся в слое, который обходит перепись производителей
	// (internal/check, TestSelfFlushCoversEveryProducerOfTheSubjectChangeQueue).
	EmitSubjectChangeEvent(ctx context.Context, evt abrepo.SubjectChangeEvent) error

	// EmitAuditEvent пишет строку журнала аудита в транзакции прохода — тем же
	// писателем, что отзыв и удаление. Содержимое строки выбирает use-case.
	EmitAuditEvent(ctx context.Context, ev abrepo.AuditEvent) error

	// LiveCatalogTypes — какие из точечных типов `types` имеют ЖИВУЮ строку каталога
	// (`catalog_resource.live`) по базе, а не по снимку процесса (kaname#937).
	// Спрашивается только о типах, которых снимок не знает, — в обычном проходе ни
	// одного обращения. Чтение без замка строк: удержание ограничено следующим
	// проходом, а не держит каталог (порядок замков транзакции сверки — ExpireBinding,
	// ReconcileObject; строк каталога она не запирает).
	LiveCatalogTypes(ctx context.Context, types []string) ([]string, error)
}

// ExpiredBindingSource lists bindings whose TTL has elapsed (expiry scan,
// index (status, expires_at)). Pool-scoped (the scan reads outside the per-binding
// revoke tx); each id is then revoked in its own writer-tx via ExpireBinding.
type ExpiredBindingSource interface {
	ListExpiredBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error)
}

// TxRunner runs fn inside a single writer-tx, committing on success and rolling
// back on error/panic. The reconciler's whole pass is one atomic unit.
type TxRunner interface {
	WithTx(ctx context.Context, fn func(ctx context.Context, s ReconcileStore) error) error
}

// Reconciler — the selector/containment reconciler use-case.
type Reconciler struct {
	tx     TxRunner
	logger *slog.Logger
	// cat — источник КАТАЛОЖНОГО ФАКТА: какие глаголы объявлены живым типом.
	//
	// Обязателен, а не опционален, как `size` ниже: без него проход не может
	// вычислить ни одного кортежа, и незаполненное поле дало бы не «наблюдение
	// выключено», а «выдача не материализуется» — тихо и целиком.
	cat catalog.Source
	// size — OPTIONAL recorder of how big one binding's materialization is. nil ⇒ the
	// observation is a no-op; the pass itself does not depend on it.
	size SizeRecorder
}

// SizeRecorder receives the SIZE of one binding's desired set: how many objects its
// selectors matched, and how many tuples those objects produce.
//
// A grant below the three cascading levels expands PER OBJECT, so its cost is «matched
// objects × the verbs of the rule». Nothing counted that expansion, which left «this
// grant grew large» indistinguishable from «this grant is ordinary» — and the
// difference surfaces not where the grant is issued but later, on somebody else's
// request, along a path that never mentions the binding. No ceiling is enforced here:
// the reachable size has not been measured, and a limit chosen before the measurement
// either refuses legitimate grants or refuses nothing while looking like a control.
type SizeRecorder interface {
	ObserveBindingMaterialization(objects, tuples int)
}

// SyncFGATuple — одна тройка набора, собираемого проходом реконсайлера.
//
// Имя историческое и оставлено намеренно: тип пересекает границу пакета, а
// переименование ради красоты стоило бы правки вызывающих без единого изменения
// свойства. Адресат у набора теперь один — вычитание переживших выдач в базе.
type SyncFGATuple struct {
	User     string
	Relation string
	Object   string
}

// ПРЯМОГО ПИСАТЕЛЯ В ЧУЖОЕ ХРАНИЛИЩЕ У РЕКОНСАЙЛЕРА БОЛЬШЕ НЕТ.
//
// Он применял вычисленный набор ПОСЛЕ коммита, чтобы закрыть окно между коммитом
// и дренажом очереди. Окна нет: прямой факт складывается из строки журнала
// триггером, в той же транзакции, — то есть материализация стала тождеством
// коммита, и догонять её нечем.
//
// Сбор набора (`syncFGACollector`) ОСТАЛСЯ и остался не по инерции: вычитание
// переживших выдач при снятии («кортеж, который держит другая действующая
// выдача, не снимается») делается его же данными и делается в базе.

// New constructs the reconciler.
//
// `cat` — источник каталожного факта; параметр ОБЯЗАТЕЛЬНЫЙ (см. поле `cat`).
func New(tx TxRunner, logger *slog.Logger, cat catalog.Source) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{tx: tx, logger: logger, cat: cat}
}

// WithSizeRecorder wires the OPTIONAL materialization-size recorder. nil-safe: an
// unwired recorder leaves the pass byte-identical, it only stops being measured.
func (r *Reconciler) WithSizeRecorder(rec SizeRecorder) *Reconciler {
	r.size = rec
	return r
}

// observeSize reports the size of a binding's desired set. Objects are counted as
// DISTINCT (type, id): the same object matched by two rules of one role is two members
// but ONE object, and counting members instead would inflate the object figure by the
// rule count, which the tuple figure already carries.
//
// A pass that matched nothing is reported as zero rather than skipped — a selector that
// stopped matching would otherwise look exactly like a binding nobody reconciles.
func (r *Reconciler) observeSize(desired []DesiredMember) {
	if r.size == nil {
		return
	}
	objects := make(map[string]struct{}, len(desired))
	tuples := 0
	for _, d := range desired {
		objects[d.ObjectType+":"+d.ObjectID] = struct{}{}
		tuples += len(d.Tuples)
	}
	r.size.ObserveBindingMaterialization(len(objects), tuples)
}

// syncFGACollector accumulates, across a single reconcile pass, the per-object tuples a
// reconcileBinding emitted to fga_outbox for ACTIVE members. NOTHING is applied anywhere
// after the pass commits — see the note above SyncFGATuple: the direct fact is folded out
// of the journal row by a trigger, inside the same transaction. What the collector is
// still FOR is the subtraction at the end of the pass: flushDeletes must not strip a
// tuple this very pass re-wrote. A nil collector de-duplicates nothing and the collect
// calls degrade to cheap pass-throughs. Not concurrency-shared: one collector per WithTx
// pass, and a pass runs single-goroutine under the per-binding advisory lock.
type syncFGACollector struct {
	// seen — что ЭТОТ проход уже записал. Единственный носитель, ради которого
	// сбор и существует: вычитание в конце прохода.
	//
	// Рядом лежали два накопителя — записанное и снятое, — и оба уезжали
	// пост-коммитным применителем в чужое хранилище. Применителя нет (стадия S6,
	// эпик kacho#747), и накопители сняты вместе с ним: срез, который заполняют и
	// никогда не читают, снаружи неотличим от работающего механизма.
	seen map[SyncFGATuple]struct{}
	// pendingDeletes — строки снятия выдач прохода, ОТЛОЖЕННЫЕ до его конца
	// (flushDeletes): вычитание записанного проходом идёт по ВСЕМУ проходу, от
	// порядка сверки выдач не завися. Факт, который держит ведомость другой действующей выдачи,
	// оставляет свёртка строки снятия под замком строки факта (kaname#919); снимок
	// соседей здесь не читается.
	pendingDeletes []pendingDelete
}

// pendingDelete — отложенные строки снятия одной выдачи (строки её реестра
// жадный отзыв уже забыл на месте; отложена лишь строка журнала).
type pendingDelete struct {
	binding domain.AccessBindingID
	tuples  []domain.MembershipTuple
}

// deferDelete records a binding's would-be tuple-deletes for the end-of-pass flush.
func (c *syncFGACollector) deferDelete(binding domain.AccessBindingID, tuples []domain.MembershipTuple) {
	if c == nil || len(tuples) == 0 {
		return
	}
	c.pendingDeletes = append(c.pendingDeletes, pendingDelete{binding: binding, tuples: tuples})
}

// collectNew records a member's ACTIVE-emit tuples DE-DUPLICATED across the whole pass
// and returns exactly the subset NOT already emitted in this pass — the set the caller
// must enqueue into fga_outbox.
//
// One reconcile pass (ReconcileObject fanning over many bindings, or the scope-self
// member plus a `*.*` content member that both target account:<X>, or two rules of one
// binding whose verb sets overlap) derives the SAME tuple more than once. The de-dup used
// to be mandatory for a second reason as well — the external engine's batch write refused
// a whole request that carried a duplicate — and that reason went away with the engine.
//
// What remains is producer cost, and it is enough on its own: a second fga_outbox row for
// a tuple this very transaction already enqueued buys nothing, because both rows fold
// into the same direct fact. The measured stand showed 27 outbox
// rows for 21 distinct tuples in a single pass — 2.2 rows per distinct tuple table-wide.
// The de-dup is strictly PER-PASS (per writer-tx) and keyed on the tuple, so it can never
// collapse a grant → revoke → grant sequence: those are three separate passes, each with
// its own collector, and the revoke in between clears the member row and the ledger.
//
// The per-binding LEDGER write is deliberately NOT de-duplicated by this set: the ledger
// PK is (binding_id, member coordinate, fga_user, relation, object), so two bindings (и
// две координаты одной выдачи) claiming the identical tuple must each keep their OWN
// row — по нему свёртка строки снятия и узнаёт, что факт ещё держит другой держатель
// (kaname#919, kaname#933).
//
// A nil collector (sync-FGA unwired) de-duplicates nothing and returns the input as-is.
func (c *syncFGACollector) collectNew(tuples []domain.MembershipTuple) []domain.MembershipTuple {
	if c == nil {
		return tuples
	}
	if c.seen == nil {
		c.seen = make(map[SyncFGATuple]struct{})
	}
	fresh := tuples[:0:0]
	for _, t := range tuples {
		st := SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}
		if _, dup := c.seen[st]; dup {
			continue
		}
		c.seen[st] = struct{}{}
		fresh = append(fresh, t)
	}
	return fresh
}

// flushDeletes кладёт ОТЛОЖЕННЫЕ строки снятия прохода в его пишущую транзакцию —
// ПОСЛЕ сверки всех выдач прохода, когда записанное им известно целиком. Из каждого
// набора вычитаются кортежи, ЗАПИСАННЫЕ любым членом этого же прохода (соседняя
// выдача выпустила тот же кортеж — col.seen): строка снятия того, что эта же
// транзакция только что записала, ничего не даёт.
//
// Ведомости ДРУГИХ выдач здесь не читаются. Факт, который держит ведомость другой
// действующей выдачи, оставляет свёртка строки снятия: вопрос о держателях она задаёт
// под замком строки факта, после коммита любого, кто держит эту строку, — свежим
// снимком (миграция 20261019180000, kaname#919). Снимок соседей, прочитанный здесь,
// устаревал раньше, чем применялся: два прохода, читавшие друг друга живыми, оба
// оставляли факт без держателя. Своя строка ведомости к этому моменту уже забыта
// (ForgetEmittedTuples в revokeMemberTuples) либо выдача снята — свой реестр факт не
// держит.
func (r *Reconciler) flushDeletes(ctx context.Context, s ReconcileStore, c *syncFGACollector) error {
	if c == nil || len(c.pendingDeletes) == 0 {
		return nil
	}
	for _, pd := range c.pendingDeletes {
		// Кандидаты, не записанные этим проходом заново.
		var revoke []domain.MembershipTuple
		for _, t := range pd.tuples {
			if _, written := c.seen[SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}]; written {
				continue
			}
			revoke = append(revoke, t)
		}
		if len(revoke) == 0 {
			continue
		}
		if err := s.EmitTupleDelete(ctx, revoke); err != nil {
			return fmt.Errorf("flush deletes: emit tuple delete for %s: %w", pd.binding, err)
		}
	}
	return nil
}

// ReconcileBinding recomputes the full desired membership of one binding from the
// mirror and diffs it against the materialized set (trigger (a) + sweep (c)).
func (r *Reconciler) ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	return r.fullPass(ctx, bindingID, false)
}

// ConvergeBinding — тот же полный проход, но СВОДЯЩИЙ: каждый неизменный
// действующий член доводится до своего желаемого набора кортежей при любом числе
// субъектов — недостающее дописывается, лишнее снимается (emitted_completion.go,
// kaname#1006). Его зовёт проход по всем действующим выдачам — при старте и
// затем по такту (seed/binding_converge.go): набор кортежей члена зависит не
// только от ключа члена, но и от вычисления (политика роли, каталог), а
// вычисление меняется выкаткой.
func (r *Reconciler) ConvergeBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	return r.fullPass(ctx, bindingID, true)
}

func (r *Reconciler) fullPass(ctx context.Context, bindingID domain.AccessBindingID, converge bool) error {
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		if err := r.reconcileBinding(ctx, s, bindingID, converge, col); err != nil {
			return err
		}
		// Отложенные строки снятия — в конце прохода; факт, который ещё держит
		// другая действующая выдача, оставляет свёртка журнала (kaname#919).
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	// После коммита не применяется НИЧЕГО: откат выше возвращает управление раньше,
	// а прямой факт складывается из строки журнала триггером в той же транзакции —
	// значит незакоммиченный diff не материализуется by construction.
	return nil
}

// ReconcileObject re-evaluates every binding that has a member referencing the
// changed object (trigger (b) — a resource_mirror upsert/delete). For each such
// binding it re-derives THAT OBJECT's membership and diffs it against THAT OBJECT's
// materialized members, so a label flip or a parent change is reflected — including
// the delete-stale revoke and the PENDING→ACTIVE/REJECTED transition.
//
// COST — the pass is O(1) in the binding's scope size (the producer-cost fix). The
// event carries exactly ONE changed object, so exactly one object's membership can
// change; the pass therefore re-derives only that object's desired members
// (desiredMembersForObject) and reads only that object's current members
// (CurrentMembersForObject). It previously ran reconcileBinding — a FULL O(scope)
// desired recompute (MatchAllInScope over every mirror object of the scope) plus the
// binding's WHOLE materialized member set — for each fanned-out binding. Measured on
// the stand: the two hottest bindings carry 10 140 members each over a 10 132-object
// account and one object change fans out to 3.2 bindings on average, so a single
// re-register or label update read ~64 000 rows while holding the per-binding
// EXCLUSIVE advisory lock that every sibling registration in that account queues
// behind. That is what pushed grant materialisation past the clients' retry budgets
// under load.
//
// WHY NARROWING IS EXACT, not an approximation:
//
//   - Members are keyed BY OBJECT (binding, rule_fp, object_type, object_id), so a
//     change to object X cannot add, remove or re-status a member on object Y. The
//     desired verdict for X is derived by desiredMemberForObject — the SAME per-object
//     decision point the full recompute uses — so the two paths stay byte-identical.
//   - The within-binding survivingClaims subtraction (applyDiff) that decides which
//     ledger rows are FORGOTTEN only ever involves members that SHARE a ledger row, and
//     the ledger PK is (binding_id, member coordinate, fga_user, relation, object): a
//     shared row implies the SAME coordinate, то есть тот же объект. Restricting the
//     desired set to one object therefore forgets exactly what the full set would have.
//     Строку снятия кортежа, который выдача ещё выпускает ДРУГОЙ координатой на том же
//     объекте движка (тип переименован с сохранением типа модели), сужение не вычитает
//     — её оставляет свёртка: строка той координаты держит факт (kaname#919).
//   - Удержание факта, который держит ДРУГАЯ выдача, — дело свёртки журнала: она
//     спрашивает реестр под замком строки факта (kaname#919) и желаемого набора не
//     читает вовсе, поэтому сужение до объекта её не касается.
//   - The fan-out itself was ALREADY object-narrowed (BindingsForObject ∪
//     SelectorBindingsMatchingObject) — only the per-binding recompute inside it was not.
//
// The binding-triggered passes (ReconcileBinding, ExpireBinding, the periodic sweep)
// keep the FULL O(scope) recompute: there the binding's role/selectors/scope changed,
// so the whole desired set genuinely has to be re-derived. They also remain the
// at-least-once backstop that re-converges anything an object pass could have missed.
func (r *Reconciler) ReconcileObject(ctx context.Context, objectType, objectID string) error {
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		// (1) Bindings that ALREADY have a member row referencing the object — a
		// label flip / parent change / object-left-the-mirror is reflected by the
		// full recompute below.
		existing, err := s.BindingsForObject(ctx, objectType, objectID)
		if err != nil {
			return fmt.Errorf("bindings for object %s:%s: %w", objectType, objectID, err)
		}
		// (2) FAST-PATH: selector-bindings whose selector NOW
		// matches the object but which do NOT yet have a member row for it (a
		// brand-new matching object). Without this, a just-arrived object only
		// gets access on the next periodic sweep (≤30s lag); with it, the change
		// event materializes membership within ~2s. The sweep remains as defense-
		// in-depth. The match source is per feed-source: mirror-fed
		// objects probe resource_mirror; iam-direct objects (Project/Account
		// label change) probe the OWN table.
		var matching []domain.AccessBindingID
		if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			matching, err = s.IAMDirectSelectorBindingsMatchingObject(ctx, objectType, objectID)
		} else {
			matching, err = s.SelectorBindingsMatchingObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("selector bindings matching object %s:%s: %w", objectType, objectID, err)
		}
		// The changed object's projection, read ONCE for the whole fan-out (every
		// binding diffs the same object). Absent from its source — a mirror DELETE, or
		// an iam row that raced a delete — leaves an EMPTY desired set for every
		// binding, which is exactly what drives the delete-stale revoke below.
		var obj domain.MirrorObject
		objPresent := false
		if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			obj, objPresent, err = s.GetIAMDirectObject(ctx, objectType, objectID)
		} else {
			obj, objPresent, err = s.GetMirrorObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("get object %s:%s: %w", objectType, objectID, err)
		}
		// Предки объекта — не более ОДНОГО раза на веер и лишь по спросу выдачи с
		// вложенным правилом (kaname#874): по ним каждая такая выдача решает свои
		// вложенные правила. Чтение — текущей цепи, поэтому перенос объекта под
		// другой контейнер (ND-09) переносит и члены. Память предков заводится ниже,
		// после замка строки объекта: её чтение ленивое и идёт уже под замками выдач.

		// Fan out over the de-duplicated union; the per-binding pass is an idempotent
		// diff of THIS OBJECT's membership, so reconciling a binding once is enough
		// regardless of which source it came from.
		//
		// DEADLOCK-CLASS: the pass takes pg_advisory_xact_lock(hashtext(binding_id))
		// for every binding of the fan-out inside the ONE writer-tx. The two source
		// queries return binding ids in NON-deterministic order, so locking in arrival
		// order lets two concurrent ReconcileObject passes (on different objects with
		// overlapping binding-sets) acquire the shared locks in DIFFERENT orders → ABBA
		// deadlock (40P01). Sorting the deduped union ASC gives every pass a
		// GLOBALLY-consistent acquisition order.
		union := dedupSortBindingIDs(existing, matching)
		// ВСЕ advisory-замки — ДО ПЕРВОЙ ЗАПИСИ прохода, в этом же порядке.
		//
		// Сортировки одной недостаточно, и это измерено, а не предположено. Она
		// разводит проходы веера МЕЖДУ СОБОЙ — там оба ресурса одного рода, и общий
		// порядок их упорядочивает. Но проход спорит ещё и со СНЯТИЕМ выдачи, а у
		// того ресурсы РАЗНЫХ родов: свой advisory он берёт первым стейтментом, а
		// общие строки прямого факта трогает после. Пока веер брал замок перед
		// работой каждой выдачи, он приходил к очередному advisory, уже удерживая
		// строку прямого факта предыдущей выдачи, — обратный порядок родов, из
		// которого Postgres выходит, снимая одну сторону как взаимную блокировку
		// (40P01). Наблюдалось на стороне арендатора: операция снятия завершалась
		// `done:true` с ABORTED, выдача оставалась жива, и следующее создание того же
		// набора получало ALREADY_EXISTS.
		//
		// Взяв весь набор вперёд, проход ждёт чужой advisory, НЕ удерживая ни одной
		// общей строки, — и цикла ожидания не существует by construction.
		if err := s.AcquireBindingLocks(ctx, union); err != nil {
			return fmt.Errorf("acquire binding locks for object %s:%s: %w", objectType, objectID, err)
		}
		// Строки выдач и их ролей — тоже ВСЕ вперёд, тем же порядком родов, что у
		// снятия регистрации объекта: выдачи, роли, затем записи (kaname#974, шапка
		// LockBindingsAndRoles). Иначе проход брал роль очередной выдачи, уже
		// записав общий прямой факт предыдущей, а снятие — наоборот.
		if err := s.LockBindingsAndRoles(ctx, union); err != nil {
			return fmt.Errorf("lock bindings and roles for object %s:%s: %w", objectType, objectID, err)
		}
		// Строка самого объекта — третьим родом, после выдач и ролей и до первой
		// записи (kaname#975): тот же порядок, что у снятия регистрации (выдачи, роли,
		// строка зеркала). Строки, снятой после чтения выше, под замком уже нет —
		// желаемое пусто, и проход снимает члены объекта, а не пишет их.
		if objPresent {
			live, err := liveObjects(ctx, s, []MemberCoord{{ObjectType: objectType, ObjectID: objectID}})
			if err != nil {
				return fmt.Errorf("object %s:%s: %w", objectType, objectID, err)
			}
			objPresent = live(MemberCoord{ObjectType: objectType, ObjectID: objectID})
		}
		ancestors := r.ancestorsOf(ctx, s, objectType, objectID, objPresent)
		for _, bID := range union {
			if err := r.reconcileBindingForObject(ctx, s, bID, objectType, objectID, obj, objPresent, ancestors, col); err != nil {
				return err
			}
		}
		// Отложенные строки снятия — ПОСЛЕ сверки всех выдач прохода: вычитание
		// записанного проходом видит его целиком, от порядка выдач не завися.
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	// AFTER commit only.
	return nil
}

// ExpireBinding снимает выдачу с истёкшим сроком в одной writer-транзакции:
// CAS-переход ACTIVE→REVOKED, затем снятие пообъектного кортежа каждого ACTIVE-члена
// и удаление строк членов. CAS (запрет #10) разводит истечение с одновременным
// удалением или активацией: 0 обновлённых строк (выдачу уже сняли) — кортежи снял
// тот путь, и проход останавливается. Выдача становится REVOKED, и следующая
// проверка права отказывает; строки членов удаляются, чтобы реконсайлер не выпустил
// их заново.
//
// ПОРЯДОК ЗАМКОВ транзакции истечения:
//
//	1  advisory-замок выдачи        pg_advisory_xact_lock(hashtext(id)) — против полного прохода, отзыва, удаления, второго истечения
//	2  строка access_bindings        FOR UPDATE (LockBindingForDeactivation) — против аддитивного форварда
//	3  строка access_bindings        FOR NO KEY UPDATE (LoadBinding) — уже покрыт шагом 2
//	4  дочерние строки выдачи        снятие членов и реестра, строки журналов
//
// Шаг 2 стоит ДО чтения членов (kaname#919): форвард решает «выдача жива» под
// `FOR KEY SHARE` и пишет членов позже, в своей транзакции; без шага 2 члены,
// легшие после чтения набора, снимать было бы некому — полный проход и сведение
// пропускают не-ACTIVE выдачу, а прямой факт вердикт читает и без неё. Отзыв и
// удаление берут тот же порядок шагов 1–2 (doRevoke, deleteOnce в access_binding,
// kaname#923), поэтому снятия одной выдачи между собой цикла не дают. Строки
// каталога (`catalog_module`, `catalog_resource` — порядок 2р→2а→4 применителей,
// kaname#913) транзакция не берёт вовсе, поэтому ребра ожидания с ними нет.
//
// Замка строки мало: исход снятия решает и ВЕРСИЯ строки журнала — свёртка в
// прямой факт снимает факт, лишь если его версия не новее версии строки снятия.
// Строка снятия несёт момент своей вставки, а не начало транзакции
// (fga_outbox, deleteStamp): иначе снятие, открывшее транзакцию раньше форварда и
// получившее строку после его коммита, писало бы строку старше факта, и факт её
// переживал. Оба порядка начала транзакций держит
// reconcile_deactivation_order_race_integration_test.go.
//
// Строку журнала смены субъекта и строку аудита снятия истечение пишет в той же
// транзакции, той же формы, что отзыв и удаление (kaname#920): по первой край
// сбрасывает кэш решений субъекта и закрывает его открытые потоки, вторая
// закрывает в следе соответствия выдачу, которую туда положило создание.
func (r *Reconciler) ExpireBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
			return fmt.Errorf("expire: acquire binding lock %s: %w", bindingID, err)
		}
		if err := s.LockBindingForDeactivation(ctx, bindingID); err != nil {
			return fmt.Errorf("expire: lock binding %s: %w", bindingID, err)
		}
		bs, ok, err := s.LoadBinding(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: load binding %s: %w", bindingID, err)
		}
		if !ok || !bs.Active {
			return nil // already gone / not ACTIVE — nothing to expire (idempotent)
		}
		// CAS ACTIVE→REVOKED first: if another path already revoked it, bail out
		// without touching tuples (they were revoked by that path).
		revoked, err := s.RevokeExpiredBinding(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: cas revoke %s: %w", bindingID, err)
		}
		if !revoked {
			return nil
		}
		if err := emitSubjectChangeOfExpiry(ctx, s, bs.Subjects); err != nil {
			return fmt.Errorf("expire: subject change %s: %w", bindingID, err)
		}
		if err := emitRevokedAuditOfExpiry(ctx, s, bs); err != nil {
			return fmt.Errorf("expire: revoked audit %s: %w", bindingID, err)
		}
		// Снимается ВЕСЬ реестр выдачи, прочитанный после замков и CAS (порядок тот же,
		// что у отзыва: advisory → FOR UPDATE → реестр), а не набор, выведенный из
		// снимка каталога процесса: тип члена мог выпасть из снимка этой реплики, и
		// ключ `<тип модели>:<id>` собрать было бы нечем (kaname#933). На истечении
		// уходят ВСЕ члены выдачи, так что ни один из них реестр не держит. Факт, который
		// держит другая действующая выдача того же субъекта, оставляет свёртка журнала
		// (kaname#919): строки реестра этой выдачи забыты здесь же, и она уже REVOKED.
		if err := r.revokeWholeLedger(ctx, s, bindingID, col); err != nil {
			return fmt.Errorf("expire: %w", err)
		}
		members, err := s.CurrentMembers(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: current members %s: %w", bindingID, err)
		}
		for _, m := range members {
			if err := s.DeleteMember(ctx, bindingID, m.RuleFP, m.ObjectType, m.ObjectID); err != nil {
				return fmt.Errorf("expire: delete member %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
			}
		}
		// Отложенные строки снятия; факт другой действующей выдачи оставит свёртка.
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	return nil
}

// emitSubjectChangeOfExpiry — строка журнала смены субъекта на КАЖДОГО субъекта
// снятой сроком выдачи, той же формы, что пишут отзыв и удаление (`revoke.go`,
// `delete.go`): вид события `binding_revoke`, `op` `binding_delete`. По строке край
// сбрасывает кэш решений субъекта и закрывает его открытые потоки; без неё снятие
// сроком край узнавал бы лишь по бюджету потока (kaname#920). Перечень субъектов
// уже несёт откат на легаси-одиночку (BindingScope.Subjects), поэтому выдача,
// записанная до многосубъектной модели, строки не теряет.
func emitSubjectChangeOfExpiry(ctx context.Context, s ReconcileStore, subjects []domain.Subject) error {
	for _, sub := range subjects {
		if err := s.EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
			SubjectID:   string(sub.ID),
			SubjectType: string(sub.Type),
			EventType:   "binding_revoke",
			Op:          "binding_delete",
		}); err != nil {
			return err
		}
	}
	return nil
}

// expiryAuditActor — действующее лицо аудита снятия сроком. Человека у истечения
// нет; имя называет путь, а не подставляет выдавшего, — по следу видно, что выдачу
// сняло истечение, а не тот, кто её выдал.
const expiryAuditActor = "system:expiry"

// emitRevokedAuditOfExpiry — строка аудита «отозвано» на КАЖДОГО субъекта снятой
// сроком выдачи, той же формы, что пишут отзыв и удаление (revokedAuditFor в
// access_binding): вид `iam.access_binding.revoked`, область, роль, выдача, область
// арендатора — аккаунт для выдачи на аккаунте, пусто для прочих (auditTenantAccountID
// там же). Одинаковость формы держит не перечень, а проба: строка истечения
// сверяется со строкой настоящего отзыва в той же базе
// (reconcile_expiry_revoked_audit_integration_test.go).
func emitRevokedAuditOfExpiry(ctx context.Context, s ReconcileStore, bs BindingScope) error {
	tenant := ""
	if bs.Scope.Type == "account" {
		tenant = bs.Scope.ID
	}
	for _, sub := range bs.Subjects {
		if err := s.EmitAuditEvent(ctx, abrepo.AuditEvent{
			EventType:       abrepo.AuditEventTypeRevoked,
			Actor:           expiryAuditActor,
			SubjectType:     string(sub.Type),
			SubjectID:       string(sub.ID),
			ResourceType:    bs.Scope.Type,
			ResourceID:      bs.Scope.ID,
			RoleID:          bs.RoleID,
			BindingID:       string(bs.BindingID),
			TenantAccountID: tenant,
		}); err != nil {
			return err
		}
	}
	return nil
}

// reconcileBinding is the core diff. It computes the desired member set for a
// binding and reconciles it against the materialized set within the caller's tx.
func (r *Reconciler) reconcileBinding(ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID, converge bool, col *syncFGACollector) error {
	// Serialize concurrent reconcile passes of the same binding on the
	// xact-scoped advisory lock BEFORE any read/write, so the exactly-once
	// materialization invariant holds under N replicas.
	if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
		return fmt.Errorf("acquire binding lock %s: %w", bindingID, err)
	}
	bs, ok, err := s.LoadBinding(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		// Deleted or no longer ACTIVE — do not re-materialize.
		return nil
	}

	desired, err := r.desiredMembers(ctx, s, bs)
	if err != nil {
		return err
	}
	// Размер материализации привязки — до диффа: величина относится к тому, что
	// привязка ТРЕБУЕТ, а не к тому, сколько строк изменилось в этом проходе.
	// Иначе повторный проход по неизменившейся привязке докладывал бы ноль, и
	// «крупная привязка» стала бы неотличима от «привязка ничего не материализует».
	r.observeSize(desired)

	current, err := s.CurrentMembers(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("current members %s: %w", bindingID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, bindingEmitted(s, bindingID, converge), col)
}

// reconcileBindingForObject is the OBJECT-NARROWED twin of reconcileBinding: it diffs
// ONE binding's membership ON ONE OBJECT, instead of recomputing the binding's whole
// desired set over its whole scope. It is what an object-change event (a mirror
// upsert/delete, a label UPDATE) actually needs — see the ReconcileObject doc for why
// the narrowing is exact rather than an approximation.
//
// It keeps everything the full path does per object: the ACTIVE/REJECTED verdict, the
// containment audit, the eager-revoke of a member that fell out, and the deferred
// delete flush. Взаимное исключение с параллельным проходом той же
// выдачи тоже сохраняется — тем же EXCLUSIVE advisory-замком, — но берёт его
// ВЫЗЫВАЮЩИЙ, сразу на весь веер и до первой записи прохода (см. тело функции). Only the SIZE of
// the diffed set changes: O(1) in the scope instead of O(scope). Because the critical
// section is now a handful of indexed rows rather than a whole-scope recompute, the
// per-binding lock every sibling registration in the account queues behind is held for
// a fraction of the time — which is the throughput property this fix is after.
//
// objPresent=false (the object left its source — a mirror DELETE) yields an EMPTY
// desired set, which drives exactly the delete-stale revoke the full path produced when
// the object stopped appearing in MatchAllInScope.
func (r *Reconciler) reconcileBindingForObject(
	ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID,
	objectType, objectID string, obj domain.MirrorObject, objPresent bool, ancestors *ancestorMemo,
	col *syncFGACollector,
) error {
	// ЗАМОК ЭТОЙ ВЫДАЧИ УЖЕ ВЗЯТ ВЫЗЫВАЮЩИМ — вместе со всеми остальными замками
	// веера и ДО первой записи прохода (ReconcileObject, AcquireBindingLocks).
	// Serialization против параллельного прохода той же выдачи от этого не слабеет:
	// ключ и режим те же, меняется только МОМЕНТ захвата. Брать его здесь повторно
	// нельзя не по стоимости, а по существу: тогда первый замок веера снова
	// оказывался бы взят после записей предыдущей выдачи, и обратный порядок родов
	// ресурсов вернулся бы вместе с ним.
	bs, ok, err := s.LoadBinding(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		// Deleted or no longer ACTIVE — do not re-materialize.
		return nil
	}

	// Изменился КОНТЕЙНЕР вложенного правила этой выдачи (метки, удаление):
	// от него зависит охват всех его потомков, а не только он сам (kaname#874).
	// Сужение до одного объекта здесь неверно — выдача пересчитывается целиком,
	// под уже взятым замком, тем же путём, что полный проход.
	if nestsUnder(bs, objectType) {
		desired, err := r.desiredMembers(ctx, s, bs)
		if err != nil {
			return err
		}
		current, err := s.CurrentMembers(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("current members %s: %w", bindingID, err)
		}
		return r.applyDiff(ctx, s, bs, desired, current, bindingEmitted(s, bindingID, false), col)
	}

	var desired []DesiredMember
	if objPresent {
		anc, err := ancestors.forBinding(bs)
		if err != nil {
			return err
		}
		desired = desiredMembersForObject(r.cat.Facts(), bs, obj, anc)
	}

	// The NARROW diff base: this binding's members ON THIS OBJECT only.
	current, err := s.CurrentMembersForObject(ctx, bindingID, objectType, objectID)
	if err != nil {
		return fmt.Errorf("current members for object %s %s:%s: %w", bindingID, objectType, objectID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, objectEmitted(s, bindingID, objectType, objectID), col)
}

// desiredMembersForObject derives the members ONE binding wants ON ONE OBJECT. It is
// the object-narrowed equivalent of desiredMembers/desiredRuleMembers, built from the
// SAME per-object decision points those use — selectorMatchesObject (the pure-Go mirror
// of the arm-match SQL), the per-object target intersection, desiredMemberForObject (the
// containment verdict + tuple derivation) and scopeSelfMember — so the narrow and full
// paths can never drift in what an object is granted.
//
// The full path resolves a candidate SET per arm (MatchAllInScope / MatchByIDs /
// MatchSelector) and then decides per candidate; here the candidate is given, so only
// the per-candidate half runs. The three arms map exactly:
//
//	ARM_ANCHOR → type membership (the scope push-down is subsumed: the object is the
//	             one that changed, and IsContainedIn re-verifies its scope as before)
//	ARM_NAMES  → id ∈ ResourceNames
//	ARM_LABELS → labels @> matchLabels
//
// The scope-self member (the binding's tier on account:<X>/project:<X>) belongs to this
// object's desired set exactly when the changed object IS the binding's own scope anchor
// — a project/account label update reaches it through the iam-direct feed. Suppressed for
// a per-object target, matching desiredRuleMembers (granting the whole scope anchor
// contradicts a least-priv per-object grant).
func desiredMembersForObject(cat *catalog.Facts, bs BindingScope, o domain.MirrorObject,
	ancestors []domain.MirrorObject) []DesiredMember {
	perObject := len(bs.Target.Resources) > 0

	var out []DesiredMember
	if len(bs.ScopeSelfVerbs) > 0 && !perObject &&
		o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		if sm, ok := scopeSelfMember(cat, grantees(bs, bs.ScopeSelfVerbs, false), bs.Scope.Type, bs.Scope.ID); ok {
			out = append(out, sm)
		}
	}
	// Контейнерные действия правил (kaname#1003, creator.go) — члены на объекте
	// ОБЛАСТИ: путь по объекту обязан их выводить, иначе событие аккаунта сняло бы
	// их как устаревшие.
	if o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		out = append(out, containerMembers(cat, bs)...)
	}
	// Per-object target least-priv (F8, IAM-1-21): a rule may only grant an object the
	// binding's target also lists. Uniform across all arms, exactly as
	// matchSelectorObjects intersects the matched set. Вложенное правило (kaname#874)
	// судит цель по КОНТЕЙНЕРУ среди предков объекта, а не по самому объекту.
	inTarget := !perObject || bs.Target.Contains(o.ObjectType, o.ObjectID)
	for _, sel := range bs.Selectors {
		gs := selectorGrantees(bs, sel)
		if len(gs) == 0 {
			continue
		}
		if sel.Container != nil {
			if !nestedCoversObject(sel, bs, o, ancestors) {
				continue
			}
		} else if !inTarget || !selectorMatchesObject(sel, o) {
			continue
		}
		dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope)
		if !ok {
			// Правило не даёт типу ни одного кортежа → объект не член (fail-closed).
			continue
		}
		out = append(out, dm)
	}
	// Публичное чтение детям (kaname#856): тот же вывод, что у полного прохода
	// (desiredRuleMembers), — иначе два пути разошлись бы в составе.
	return withPublicReaders(cat, bs, out)
}

// desiredMembers computes the desired member set + containment verdict for a
// binding. The flat explicit RBAC model uses the UNIFIED materializer — the only
// dynamic membership source is the role's materializing rules (ARM_ANCHOR(all) +
// ARM_NAMES + ARM_LABELS). A binding whose role carries no materializing selectors
// is thin — no materialized members (a legacy permissions-only role's tier tuples
// are the Create-time concern, not here).
func (r *Reconciler) desiredMembers(ctx context.Context, s ReconcileStore, bs BindingScope) ([]DesiredMember, error) {
	if len(bs.Selectors) > 0 {
		return r.desiredRuleMembers(ctx, s, bs)
	}
	return nil, nil // thin binding — no materialized members
}

// matchSelectorObjects resolves the candidate objects for ONE selector per its arm,
// across both feeds (mirror-fed + iam-direct, partitioned): ARM_ANCHOR(all) →
// MatchAllInScope; ARM_NAMES → MatchByIDs; ARM_LABELS → MatchSelector(labels @>).
// Containment is re-asserted by the caller (IsContainedIn); this only resolves the
// candidate set. The binding's `scope` is passed to the ANCHOR arm so the candidate set
// is pushed-down to O(scope) in SQL rather than scanned cluster-wide + narrowed in Go —
// the Go re-verify remains authoritative (the SQL predicate is a proven superset).
//
// PER-OBJECT TARGET (F8, IAM-1-21): when the binding carries a per-object target
// (target.Resources non-empty), the ANCHOR arm is resolved BY the target ids
// (MatchByIDs) instead of MatchAllInScope — so a least-priv grant never scans/materializes
// the whole scope — and the matched set of EVERY arm is finally INTERSECTED with the
// target (a role rule can only grant an object the target also lists).
func (r *Reconciler) matchSelectorObjects(ctx context.Context, s ReconcileStore, sel domain.RuleSelector, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	mirrorTypes, iamTypes := partitionByFeed(sel.ObjectTypes)
	var matched []domain.MirrorObject
	if len(mirrorTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, mirrorTypes, false, s, scope, target)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (mirror): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	if len(iamTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, iamTypes, true, s, scope, target)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (iam-direct): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	// Per-object target intersection: keep ONLY objects the target lists (uniform across
	// all arms — anchor already resolves by target ids, but names/labels may match objects
	// the target does not list, so intersect them out; least-priv, IAM-1-21).
	if len(target.Resources) > 0 {
		matched = filterMatchedToTarget(matched, target)
	}
	return matched, nil
}

// matchByArm dispatches the per-arm match to the right feed (mirror vs iam-direct). The
// ANCHOR arm passes the binding's `scope` for the SQL scope push-down; the NAMES/LABELS arms
// are already narrow (specific ids / labels) AND a foreign-scope match is a wanted
// REJECTED-containment audit signal, so they are LEFT UNSCOPED (the reconciler re-verifies).
//
// For a PER-OBJECT target the ANCHOR arm resolves the candidate set BY the target ids
// (MatchByIDs) rather than MatchAllInScope: a least-priv grant materializes only the listed
// objects, never the whole scope (IAM-1-21). The NAMES/LABELS arms keep their own narrow
// resolution and are intersected with the target by the caller (matchSelectorObjects).
func (r *Reconciler) matchByArm(ctx context.Context, sel domain.RuleSelector, types []string, iamDirect bool, s ReconcileStore, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	switch sel.Arm {
	case domain.ArmNames:
		if iamDirect {
			return s.MatchByIDsIAMDirect(ctx, types, sel.ResourceNames)
		}
		return s.MatchByIDs(ctx, types, sel.ResourceNames)
	case domain.ArmLabels:
		if iamDirect {
			return s.MatchIAMDirect(ctx, types, sel.MatchLabels)
		}
		return s.MatchSelector(ctx, types, sel.MatchLabels)
	default: // ArmAnchor (all)
		if len(target.Resources) > 0 {
			// Per-object target: resolve the anchor candidates by the target ids of these
			// types (never the whole-scope scan). Empty ⇒ no candidate of these types.
			ids := target.ResourceIDsForTypes(types)
			if len(ids) == 0 {
				return nil, nil
			}
			if iamDirect {
				return s.MatchByIDsIAMDirect(ctx, types, ids)
			}
			return s.MatchByIDs(ctx, types, ids)
		}
		if iamDirect {
			return s.MatchAllInScopeIAMDirect(ctx, types, scope)
		}
		return s.MatchAllInScope(ctx, types, scope)
	}
}

// filterMatchedToTarget keeps only the matched objects listed in a per-object target
// (exact dotted-type + id). It is the uniform intersection applied to EVERY arm when the
// binding carries a per-object target, so a role rule (anchor/names/labels) can only grant
// an object the target also lists (least-priv, IAM-1-21). Never called for an
// AllInScope/empty target (the caller gates on len(target.Resources) > 0).
func filterMatchedToTarget(matched []domain.MirrorObject, target domain.AccessTarget) []domain.MirrorObject {
	out := matched[:0:0]
	for _, o := range matched {
		if target.Contains(o.ObjectType, o.ObjectID) {
			out = append(out, o)
		}
	}
	return out
}

// desiredRuleMembers computes the desired per-rule membership for a role.rules-
// driven binding (unified materializer). For EACH materializing selector
// (rule_fp) it resolves the candidate objects per its arm, applies containment,
// and emits the per-object tuple set DERIVED FROM THE RULE'S VERBS (per-verb v_* +
// tier — the same domain helpers the prior emit path used). A matched-but-foreign
// object is REJECTED (no tuple + audit, cross-scope defence). The SAME object
// matched by two rules yields two desired members keyed by distinct rule_fp.
func (r *Reconciler) desiredRuleMembers(ctx context.Context, s ReconcileStore, bs BindingScope) ([]DesiredMember, error) {
	var out []DesiredMember
	// Каталожный факт берётся ОДИН раз на проход: обновление снимка подменяет
	// указатель, и три чтения могли бы увидеть два разных каталога — член
	// правила по одному, член `public_reader` по другому.
	cat := r.cat.Facts()

	// perObject — the binding carries a per-object target (Target.Resources non-empty):
	// the grant is restricted to EXACTLY the listed objects (least-priv, IAM-1-21). The
	// scope-self anchor grant is suppressed and every selector's matches are intersected
	// with the target set below.
	perObject := len(bs.Target.Resources) > 0

	// Scope-self member: the role's tier (+ verb-bearing v_*) ON
	// THE BINDING'S OWN SCOPE OBJECT (`account:<X>`/`project:<X>`). This is the
	// write-authz / no-access-loss anchor the removed binding-time scope-anchor emit
	// produced — now materialized by the SINGLE reconciler path. It is NOT a content
	// object matched by a selector: a `*.*` superuser role has empty selector
	// ObjectTypes (wildcard skipped), so without this the subject would lose the tier
	// on the scope entirely. Keyed by
	// a sentinel rule_fp so it has its own member row + ledger lineage (symmetric
	// revoke). The cluster super-admin path short-circuits and is not materialized here.
	//
	// SUPPRESSED for a per-object target: granting the tier on the WHOLE scope object
	// (account:<X>/project:<X>) contradicts a per-object least-priv grant — the target
	// lists specific content objects, not the scope anchor. So a per-object target never
	// materializes the scope-self member (over-grant guard, IAM-1-21).
	if len(bs.ScopeSelfVerbs) > 0 && !perObject {
		if sm, ok := scopeSelfMember(cat, grantees(bs, bs.ScopeSelfVerbs, false), bs.Scope.Type, bs.Scope.ID); ok {
			out = append(out, sm)
		}
	}

	for _, sel := range bs.Selectors {
		// Субъекты, которым правило что-то даёт: классу — только чтение, а
		// вложенное правило классу не применяется вовсе (subjects.go). Никому —
		// правило не материализует ничего и кандидатов не ищет.
		gs := selectorGrantees(bs, sel)
		if len(gs) == 0 {
			continue
		}
		if sel.Container != nil {
			// Вложенное правило (kaname#874): потомки контейнеров, выбранных
			// выдачей; классам выдачи — ни одного (ND-10, nested.go).
			matched, err := r.matchNestedObjects(ctx, s, sel, bs)
			if err != nil {
				return nil, err
			}
			for _, o := range matched {
				if dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope); ok {
					out = append(out, dm)
				}
			}
			continue
		}
		// Правило, которое на своих типах называет одни контейнерные действия
		// (kaname#1003), объектам не даёт ничего: его член — на объекте области
		// (containerMembers). Кандидатов оно не ищет вовсе — перебора учёток
		// аккаунта у выдачи роли создателя нет.
		if !selectorWritesObjects(cat, sel) {
			continue
		}
		var matched []domain.MirrorObject
		var err error
		if sel.CreatedBySubject {
			// Селектор создателя: кандидаты — объекты области, созданные
			// субъектами-учётками выдачи, отбором по индексу (аккаунт, создатель),
			// а не перебором объектов области (§3 приёмки, «производительность»).
			matched, err = r.matchCreatorObjects(ctx, s, sel, bs)
		} else {
			// Pass the binding's scope + target so the ANCHOR arm resolves the candidate set
			// per the target (by-id when per-object; O(scope) push-down otherwise), and every
			// arm's matches are intersected with the target. IsContainedIn below stays the
			// authoritative containment re-verify.
			matched, err = r.matchSelectorObjects(ctx, s, sel, bs.Scope, bs.Target)
		}
		if err != nil {
			return nil, err
		}
		for _, o := range matched {
			// Per-object verdict — SHARED with the forward fast-path
			// (desiredMemberForObject), so the full recompute and the forward path
			// derive BYTE-IDENTICAL tuples (idempotency: forward + async full both
			// emit the same set, and the read-delta FGA writer skips duplicates).
			dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope)
			if !ok {
				// Правило не даёт типу ни одного кортежа → объект не член (fail-closed).
				continue
			}
			out = append(out, dm)
		}
	}
	// Контейнерные действия правил (kaname#1003, creator.go): члены на объекте
	// области — тот же вывод, что у пути по объекту.
	out = append(out, containerMembers(cat, bs)...)
	// Публичное чтение детям (kaname#856): член `public_reader` на каждом
	// объявленном контейнере, который выдача уже даёт действующим членом, — тот
	// же вывод, что у прямого пути по объекту (desiredMembersForObject).
	return withPublicReaders(cat, bs, out), nil
}

// desiredMemberForObject computes the DesiredMember a materializing selector produces
// for ONE candidate object. It is the single per-object decision point SHARED by the
// full recompute (desiredRuleMembers) and the ADDITIVE forward fast-path
// (forwardObjectForBinding), so the two paths can never drift in what tuples an object
// grants (idempotency across forward + async-backstop).
//
//   - not contained in the binding's scope (cross-scope label-tampering / foreign parent)
//     → a REJECTED member (ok=true, no tuples). The full path records it + audits; the
//     forward path skips it (additive-only never writes a non-ACTIVE member).
//   - contained → an ACTIVE member with the per-object tuples derived from the RULE's
//     verbs (v_* + back-compat tier via ruleObjectTuples). ARM_LABELS/ANCHOR rules are
//     excluded from CompileRules, so the tuples come from the rule verbs, not RolePerms.
//   - тип объекта неизвестен снимку каталога процесса → член без статуса и кортежей
//     с признаком typeUnresolved (ok=true): ничего не выдаёт, а удержать его или снять
//     решает строка каталога в базе (catalog_lag.go, kaname#937). Форвард его
//     пропускает — он пишет только ACTIVE;
//   - правило не даёт типу ни одного кортежа → ok=false (не член, fail-closed).
func desiredMemberForObject(cat *catalog.Facts, policy domain.RulePolicy, gs []grantee, sel domain.RuleSelector, o domain.MirrorObject, scope domain.ScopeAnchor) (DesiredMember, bool) {
	// Селектор создателя (kaname#1003, creator.go): объект входит в охват правила
	// только для субъекта, который его создал. Никому — объект правилом не
	// выбран вовсе (ни члена, ни отвергнутого члена: охвата нет, а не вне области).
	gs = creatorGrantees(sel, gs, o)
	if len(gs) == 0 {
		return DesiredMember{}, false
	}
	if !o.IsContainedIn(scope) {
		return DesiredMember{
			RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
			Status: domain.VerificationRejected,
		}, true
	}
	// Тип, которого снимок каталога процесса не знает, — ещё не «тип снят»: снимок
	// отстаёт от строк каталога на период обновления (kaname#937). Член остаётся в
	// желаемом без статуса и кортежей, а выдать, удержать или снять его решает
	// applyDiff по строке каталога в базе (catalog_lag.go).
	if _, known := cat.FGAObjectType(o.ObjectType); !known {
		return DesiredMember{
			RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
			typeUnresolved: true,
		}, true
	}
	// Кортежи — объединение по субъектам `gs`, каждому со своими глаголами
	// (subjects.go, kaname#880). Отказ «у типа нет объекта модели» от субъекта
	// не зависит: первый же отказ — отказ всего члена.
	var tuples []domain.MembershipTuple
	for _, g := range gs {
		// Контейнерные действия кортежей на объекте не пишут (kaname#1003): их
		// отношение лежит на родителе (containerMembers). Правило, у которого на
		// типе объекта кроме них ничего нет, объекту не даёт ничего — даже яруса.
		verbs := objectVerbsOf(cat, o.ObjectType, g.verbs)
		if len(verbs) == 0 {
			continue
		}
		t, ok := ruleObjectTuples(cat, policy, g.subject, verbs, o.ObjectType, o.ObjectID)
		if !ok {
			return DesiredMember{}, false
		}
		if sel.CreatedBySubject {
			t = verbTuplesOnly(t)
		}
		tuples = append(tuples, t...)
	}
	if len(tuples) == 0 {
		return DesiredMember{}, false
	}
	return DesiredMember{
		RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
		Status: domain.VerificationActive, Tuples: tuples,
	}, true
}

// applyDiff reconciles the desired set against the current materialized set: it
// UPSERTs members whose status changed, emits/eager-revokes the per-object FGA
// tuple on ACTIVE transitions, writes the containment audit on REJECTED, and
// removes members no longer in the desired set (eager-revoke their tuple).
func (r *Reconciler) applyDiff(ctx context.Context, s ReconcileStore, bs BindingScope, desired []DesiredMember, current []domain.TargetMember, emitted *emittedView, col *syncFGACollector) error {
	// Key by (rule_fp, object): a member is attributed to the role.rules rule that
	// produced it, so the SAME object under two rules is two members
	// and a removed rule eager-revokes ONLY its members.
	currentByKey := make(map[string]domain.TargetMember, len(current))
	for _, m := range current {
		currentByKey[memberRuleKey(m.RuleFP, m.ObjectType, m.ObjectID)] = m
	}
	// Члены по типу, которого снимок каталога процесса ещё не знает, решаются строкой
	// каталога в базе ДО диффа (kaname#937): тип жив — член удерживается как есть, тип
	// снят — член выпадает и снимается ниже обычным путём.
	desired, held, err := r.settleUnresolved(ctx, s, bs, desired, currentByKey)
	if err != nil {
		return err
	}
	// Объект, по которому проход ПИШЕТ член, — под замком строки зеркала до первой
	// записи (kaname#975): объект, чью регистрацию сняли после чтения отбора, члена
	// не получает, а снятие ждёт фиксации прохода, если замок взят раньше.
	desired, err = keepLiveDesired(ctx, s, desired, currentByKey)
	if err != nil {
		return err
	}
	desiredByKey := make(map[string]struct{}, len(desired))

	// survivingClaims — кортежи, на которые после прохода ещё претендуют желаемые
	// ACTIVE-члены этой выдачи: целиком и по координате члена. Ключ реестра —
	// (выдача, координата члена, кортеж) без rule_fp, поэтому два члена ОДНОЙ
	// координаты (тот же объект под двумя правилами, член `public_reader` со сменой
	// ключа) делят одну строку: уходящий член забывает только строки, на которые не
	// претендует выживший член его же координаты. Строку снятия в движок получает
	// лишь кортеж, на который не претендует ни один выживший член выдачи. Набор
	// вычислен под advisory-блокировкой выдачи (параллельного прохода этой выдачи
	// нет), гонки в нём нет.
	survivingClaims := desiredActiveClaims(desired)
	// Удержанный член претендует на то, что уже выпустил: строки реестра его координаты
	// не забываются и не снимаются уходящим соседом той же координаты.
	held.claim(survivingClaims)

	for _, d := range desired {
		key := memberRuleKey(d.RuleFP, d.ObjectType, d.ObjectID)
		desiredByKey[key] = struct{}{}
		if d.typeUnresolved {
			// Удержан: ни записи, ни снятия, ни дописывания — проход по этому типу
			// повторит реплика, чей снимок его знает (сведение, событие объекта).
			continue
		}
		prev, existed := currentByKey[key]
		prevStatus := domain.VerificationStatus("")
		if existed {
			prevStatus = prev.VerificationStatus
		}
		if existed && prevStatus == d.Status {
			// Ключ и статус совпали. Набор кортежей члена ключом не определён: ключ
			// не несёт ни субъектов выдачи (kaname#880), ни политики роли и каталога
			// (kaname#1006), — член сводится к желаемому набору по реестру
			// выпущенного (emitted_completion.go).
			if d.Status == domain.VerificationActive {
				if err := r.convergeMemberTuples(ctx, s, bs, d, emitted, survivingClaims, col); err != nil {
					return err
				}
			}
			continue
		}

		// Persist the new member status (UPSERT keyed by the full rule coordinate).
		if err := s.UpsertMember(ctx, domain.TargetMember{
			BindingID: bs.BindingID, RoleID: domain.RoleID(bs.RoleID), RuleFP: d.RuleFP,
			ObjectType: d.ObjectType, ObjectID: d.ObjectID, VerificationStatus: d.Status,
		}); err != nil {
			return fmt.Errorf("upsert member %s/%s:%s: %w", d.RuleFP, d.ObjectType, d.ObjectID, err)
		}

		// The tuple set for this member: precomputed from the producing rule's verbs
		// (d.Tuples).
		tuples, tupleOK := r.memberTuples(d)
		switch d.Status {
		case domain.VerificationActive:
			if !tupleOK {
				return fmt.Errorf("membership tuple inconsistent for %s/%s:%s (role coverage desync)", d.RuleFP, d.ObjectType, d.ObjectID)
			}
			// Enqueue ONLY the tuples this pass has not already enqueued, and record the
			// same set in the pass collector — the set the deletion subtraction below
			// reads, so a tuple re-written here is never stripped by a sibling's revoke
			// in the same pass.
			if fresh := col.collectNew(tuples); len(fresh) > 0 {
				if err := s.EmitTupleWrite(ctx, fresh); err != nil {
					return fmt.Errorf("emit tuple write %s:%s: %w", d.ObjectType, d.ObjectID, err)
				}
			}
			// Co-commit the emitted member-tuple into the ledger under the member's
			// coordinate — the symmetric revoke + Role.Update reconcile both rest on it
			// (ban #10).
			if err := s.RecordEmittedTuples(ctx, bs.BindingID, desiredCoord(d), tuples); err != nil {
				return fmt.Errorf("record emitted tuple %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		case domain.VerificationRejected:
			// Was it ACTIVE before? Then eager-revoke the now-stale tuple + forget it.
			// The revoke set is the member's SAVED ledger (d.Tuples is empty for a
			// REJECTED transition), NOT d.Tuples.
			if prevStatus == domain.VerificationActive {
				if err := r.revokeMemberTuples(ctx, s, bs, prev, survivingClaims, col); err != nil {
					return err
				}
			}
			if err := s.EmitContainmentAudit(ctx, bs.BindingID, d.ObjectType, d.ObjectID, bs.Scope); err != nil {
				return fmt.Errorf("emit containment audit %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		case domain.VerificationPending:
			// No tuple; if it was ACTIVE before (object left the mirror), revoke + forget.
			if prevStatus == domain.VerificationActive {
				if err := r.revokeMemberTuples(ctx, s, bs, prev, survivingClaims, col); err != nil {
					return err
				}
			}
		}
	}

	// Members that fell out of the desired set entirely (rule removed / label
	// removed): eager-revoke their tuple + remove the row. The fell-out
	// member's tuple set is read from the member's recorded ledger rows
	// (revokeTuplesFor) — a removed rule's verbs are gone, so the ledger is the only
	// authority.
	for key, m := range currentByKey {
		if _, stillDesired := desiredByKey[key]; stillDesired {
			continue
		}
		if held.holds(key) {
			continue
		}
		if m.VerificationStatus == domain.VerificationActive {
			if err := r.revokeMemberTuples(ctx, s, bs, m, survivingClaims, col); err != nil {
				return err
			}
		}
		if err := s.DeleteMember(ctx, bs.BindingID, m.RuleFP, m.ObjectType, m.ObjectID); err != nil {
			return fmt.Errorf("delete member %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
		}
	}
	return nil
}

// mirrorFed — объект питается зеркалом регистраций: его строку удаляет снятие
// регистрации. Объекты собственных таблиц iam (`iam.*`) зеркала не имеют.
func mirrorFed(objectType string) bool {
	return domain.FeedSourceForType(objectType) == domain.FeedMirror
}

// liveObjects запирает строки зеркала объектов `objs` (LockMirrorObjects,
// kaname#975) и отвечает, есть ли строка объекта. Объект собственной таблицы iam
// замка зеркала не берёт и считается живым: его снятие — не снятие регистрации.
func liveObjects(ctx context.Context, s ReconcileStore, objs []MemberCoord) (func(MemberCoord) bool, error) {
	seen := make(map[MemberCoord]struct{}, len(objs))
	mirror := make([]MemberCoord, 0, len(objs))
	for _, o := range objs {
		if !mirrorFed(o.ObjectType) {
			continue
		}
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		mirror = append(mirror, o)
	}
	if len(mirror) == 0 {
		return func(MemberCoord) bool { return true }, nil
	}
	present, err := s.LockMirrorObjects(ctx, mirror)
	if err != nil {
		return nil, fmt.Errorf("lock mirror objects: %w", err)
	}
	return func(o MemberCoord) bool {
		if !mirrorFed(o.ObjectType) {
			return true
		}
		_, ok := present[o]
		return ok
	}, nil
}

// keepLiveDesired — желаемые члены без тех, чей объект проход собирается ЗАПИСАТЬ
// (член новый либо меняет статус), а строки его зеркала под замком уже нет
// (kaname#975). Такой объект выбыл из отбора между чтением и записью: член по нему
// не пишется, а прежний член той же координаты выпадает из желаемого и снимается
// тем же проходом. Члены без записи (статус прежний) замка не берут — их объект
// проход не трогает, и периодическое сведение не платит замком за каждый объект
// области. Ожидающий член (PENDING) объекта зеркала не имеет по определению и
// фильтром не судится. Удержанный член типа, которого снимок каталога ещё не знает
// (typeUnresolved, kaname#937), не пишется вовсе и замка тоже не берёт.
func keepLiveDesired(ctx context.Context, s ReconcileStore, desired []DesiredMember, current map[string]domain.TargetMember) ([]DesiredMember, error) {
	writes := make(map[MemberCoord]struct{})
	for _, d := range desired {
		if d.Status == domain.VerificationPending || d.typeUnresolved {
			continue
		}
		if prev, ok := current[memberRuleKey(d.RuleFP, d.ObjectType, d.ObjectID)]; ok && prev.VerificationStatus == d.Status {
			continue
		}
		writes[desiredCoord(d)] = struct{}{}
	}
	if len(writes) == 0 {
		return desired, nil
	}
	objs := make([]MemberCoord, 0, len(writes))
	for c := range writes {
		objs = append(objs, c)
	}
	live, err := liveObjects(ctx, s, objs)
	if err != nil {
		return nil, err
	}
	out := desired[:0:0]
	for _, d := range desired {
		c := desiredCoord(d)
		if _, written := writes[c]; written && d.Status != domain.VerificationPending && !d.typeUnresolved && !live(c) {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// memberTuples returns the FGA tuple set for a DESIRED member. In the rules-based
// RBAC model every materialized member comes from a role.rules
// ARM_LABELS rule, so its tuples were precomputed from the rule's verbs (d.Tuples).
// A member with no tuples is an unknown-FGA-type ACTIVE member the caller already
// skipped in desiredRuleMembers — treated as a coverage desync (fail-closed).
func (r *Reconciler) memberTuples(d DesiredMember) ([]domain.MembershipTuple, bool) {
	if len(d.Tuples) > 0 {
		return d.Tuples, true
	}
	return nil, false
}

// revokeMemberTuples eager-revokes the live FGA tuples of a previously-ACTIVE
// member (ACTIVE→REJECTED/PENDING transition OR a fell-out member) and forgets them
// from the ledger, in lock-step (ban #10). The revoke set is the member's SAVED
// tuple-set — строки реестра ЕГО координаты (revokeTuplesFor), NOT re-derived from a
// possibly-mutated role (a removed rule's verbs are gone, so the only authority is the
// ledger).
//
// Множеств два (claims — набор выживших ACTIVE-членов этой выдачи после прохода):
//   - ЗАБЫТЬ: строки своей координаты минус кортежи, на которые претендует выживший
//     член ТОЙ ЖЕ координаты, — его строка та же, и забытая она оставила бы его без
//     записи о выданном;
//   - СНЯТЬ в движке: свои кортежи минус кортежи ВСЕХ выживших членов выдачи —
//     кортеж, который выдача ещё выпускает другой координатой, не снимается.
//
// Строка снятия ОТЛОЖЕНА в коллектор (deferDelete) и уходит в конце прохода
// (flushDeletes). Факт, который держит другая действующая выдача того же субъекта либо
// строка другой координаты, оставляет свёртка строки снятия под замком строки факта
// (kaname#919) — для этого своя строка ведомости ОБЯЗАНА уйти до строки снятия, иначе
// выдача держит факт сама: ForgetEmittedTuples стоит здесь, inline, раньше любого
// flushDeletes.
func (r *Reconciler) revokeMemberTuples(ctx context.Context, s ReconcileStore, bs BindingScope, m domain.TargetMember, claims *memberClaims, col *syncFGACollector) error {
	coord := coordOf(m)
	tuples, err := r.revokeTuplesFor(ctx, s, bs, m)
	if err != nil {
		return err
	}
	var forget []LedgerRow
	var revoke []domain.MembershipTuple
	for _, t := range tuples {
		if claims.claimedAt(coord, t) {
			continue // выживший член той же координаты держит ту же строку.
		}
		forget = append(forget, LedgerRow{Member: coord, Tuple: t})
		if claims.claimed(t) {
			continue // выдача ещё выпускает кортеж другой координатой.
		}
		revoke = append(revoke, t)
	}
	if len(forget) == 0 {
		return nil
	}
	// Своя строка реестра — раньше строки снятия (kaname#919).
	if err := s.ForgetEmittedTuples(ctx, bs.BindingID, forget); err != nil {
		return fmt.Errorf("forget emitted tuple %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
	}
	if len(revoke) > 0 {
		// Строка снятия — в конец прохода (вычитание записанного тем же проходом).
		col.deferDelete(bs.BindingID, revoke)
	}
	return nil
}

// memberClaims — кортежи, на которые после прохода претендуют желаемые ACTIVE-члены
// выдачи: целиком (all) и по координате члена (byCoord). nil — не претендует никто
// (истечение снимает выдачу целиком).
type memberClaims struct {
	all     map[domain.MembershipTuple]struct{}
	byCoord map[MemberCoord]map[domain.MembershipTuple]struct{}
}

func (c *memberClaims) claimed(t domain.MembershipTuple) bool {
	if c == nil {
		return false
	}
	_, ok := c.all[t]
	return ok
}

func (c *memberClaims) claimedAt(coord MemberCoord, t domain.MembershipTuple) bool {
	if c == nil {
		return false
	}
	_, ok := c.byCoord[coord][t]
	return ok
}

// desiredActiveClaims collects every FGA tuple that a desired ACTIVE member will
// (re)emit this pass — the "still-claimed" sets the eager-revoke subtracts. Only ACTIVE
// desired members carry precomputed Tuples (REJECTED/PENDING members carry none), so
// they are the exact set of live claims after the pass.
func desiredActiveClaims(desired []DesiredMember) *memberClaims {
	c := &memberClaims{
		all:     make(map[domain.MembershipTuple]struct{}),
		byCoord: make(map[MemberCoord]map[domain.MembershipTuple]struct{}),
	}
	for _, d := range desired {
		if d.Status != domain.VerificationActive {
			continue
		}
		coord := desiredCoord(d)
		at := c.byCoord[coord]
		if at == nil {
			at = make(map[domain.MembershipTuple]struct{}, len(d.Tuples))
			c.byCoord[coord] = at
		}
		for _, t := range d.Tuples {
			c.all[t] = struct{}{}
			at[t] = struct{}{}
		}
	}
	return c
}

// revokeTuplesFor returns the FGA tuples to revoke for a member: the SAVED ledger rows
// of the member's coordinate (access_binding_emitted_tuples) — "revoke what was
// actually emitted, do NOT re-derive from the role", because the role may have been
// mutated out from under the member. Координата — та же, что у строки члена, и снимку
// каталога процесса здесь нечего решать: выпавший член, чьего типа снимок реплики не
// знает (тип снят — catalog_lag.go, kaname#937 — либо член выпал по другой причине),
// снимается тем же чтением, а строки члена ДРУГОГО типа с тем же идентификатором
// остаются нетронутыми (kaname#933). Empty ledger ⇒ nothing to revoke.
func (r *Reconciler) revokeTuplesFor(ctx context.Context, s ReconcileStore, bs BindingScope, m domain.TargetMember) ([]domain.MembershipTuple, error) {
	tuples, err := s.LedgerTuplesForMember(ctx, bs.BindingID, coordOf(m))
	if err != nil {
		// Ошибка чтения реестра не гасится: член удаляется следом, и молча проглоченное
		// чтение оставило бы его кортежи без владельца. Откат прохода повторит снятие.
		return nil, fmt.Errorf("ledger read for member revoke %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
	}
	return tuples, nil
}

// revokeWholeLedger снимает ВЕСЬ учтённый реестром набор выдачи: строки реестра всех
// координат забываются здесь же, в той же транзакции (ban #10), строки снятия — в
// коллектор (уходят в конце прохода), по кортежу один раз. Набор берётся из реестра,
// а не из каталога процесса.
func (r *Reconciler) revokeWholeLedger(ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID, col *syncFGACollector) error {
	rows, err := s.LedgerTuples(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("read ledger of binding %s: %w", bindingID, err)
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.ForgetEmittedTuples(ctx, bindingID, rows); err != nil {
		return fmt.Errorf("forget ledger of binding %s: %w", bindingID, err)
	}
	seen := make(map[domain.MembershipTuple]struct{}, len(rows))
	tuples := make([]domain.MembershipTuple, 0, len(rows))
	for _, row := range rows {
		if _, dup := seen[row.Tuple]; dup {
			continue
		}
		seen[row.Tuple] = struct{}{}
		tuples = append(tuples, row.Tuple)
	}
	col.deferDelete(bindingID, tuples)
	return nil
}

// partitionByFeed splits selector types into the mirror-fed set (compute/vpc/
// nlb) and the iam-direct set (iam.project/iam.account) by the pure-domain
// feed-source classifier. Order within each partition is preserved.
func partitionByFeed(types []string) (mirror, iamDirect []string) {
	for _, t := range types {
		switch domain.FeedSourceForType(t) {
		case domain.FeedIAMDirect:
			iamDirect = append(iamDirect, t)
		default:
			mirror = append(mirror, t)
		}
	}
	return mirror, iamDirect
}

// memberRuleKey joins (ruleFP, objectType, objectID) with NUL separators — the
// member identity. The rule_fp discriminates the SAME object selected
// by two different rules (distinct members at possibly distinct tiers), so the
// diff in applyDiff revokes exactly the removed rule's members. NUL never
// occurs in a hex fingerprint / dotted type / crockford id, so the join is
// unambiguous.
func memberRuleKey(ruleFP, objectType, objectID string) string {
	return ruleFP + "\x00" + objectType + "\x00" + objectID
}

// dedupSortBindingIDs merges the fan-out source id sets into a de-duplicated,
// sorted-ASC slice. The sort gives the ReconcileObject fan-out a GLOBALLY-consistent
// advisory-lock acquisition order across concurrent passes (deadlock-class fix):
// two passes on different objects with overlapping binding-sets
// acquire the shared locks in the SAME order, so they cannot deadlock (ABBA / 40P01).
func dedupSortBindingIDs(sets ...[]domain.AccessBindingID) []domain.AccessBindingID {
	seen := make(map[domain.AccessBindingID]struct{})
	for _, set := range sets {
		for _, id := range set {
			seen[id] = struct{}{}
		}
	}
	out := make([]domain.AccessBindingID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ancestorsOf — предки объекта пути по объекту (kaname#874), читаемые ЛЕНИВО: не
// более одного раза на веер и только когда их спросила выдача с вложенным
// селектором. Без вложенных правил путь по объекту не платит лишним обращением.
// Объекту, ушедшему из источника, и собственному объекту iam предки не читаются:
// первому желаемых членов нет вовсе, второй контейнера-предка в зеркале не имеет.
func (r *Reconciler) ancestorsOf(ctx context.Context, s ReconcileStore, objectType, objectID string, present bool) *ancestorMemo {
	return &ancestorMemo{load: func() ([]domain.MirrorObject, error) {
		if !present || domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			return nil, nil
		}
		out, err := s.AncestorObjects(ctx, objectType, objectID)
		if err != nil {
			return nil, fmt.Errorf("ancestors of %s:%s: %w", objectType, objectID, err)
		}
		return out, nil
	}}
}

// ancestorMemo — предки одного объекта, прочитанные не более одного раза. Живёт в
// одном проходе одной горутины.
type ancestorMemo struct {
	load func() ([]domain.MirrorObject, error)
	done bool
	out  []domain.MirrorObject
	err  error
}

// forBinding — предки объекта, если выдача `bs` их спрашивает (у неё есть
// вложенный селектор и её субъект не класс); иначе пусто без обращения к базе.
func (m *ancestorMemo) forBinding(bs BindingScope) ([]domain.MirrorObject, error) {
	if !hasNestedSelector(bs) {
		return nil, nil
	}
	if !m.done {
		m.out, m.err = m.load()
		m.done = true
	}
	return m.out, m.err
}
