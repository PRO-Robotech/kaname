// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// reconcile_adapter.go — pgx adapter implementing the
// reconcile.TxRunner + reconcile.ReconcileStore ports (Clean Architecture: the
// reconcile use-case depends only on these ports; this is the only place that
// touches pgx for the reconciler).
//
// WithTx opens ONE writer-tx for a whole reconcile pass: the membership UPSERTs/
// DELETEs + the per-object fga_outbox emits + the containment audit all commit
// together or roll back together (ban #10). On any error the tx rolls back, so a
// partially-applied diff is impossible. The reconcile commits its OWN tx; the
// resource_reconcile_outbox event is marked sent in a SEPARATE short tx
// (MarkReconcileEventSent) after this commit — at-least-once, redelivery safe
// (the reconcile diff is idempotent), NOT co-committed here.
//
// The store delegates to the existing pg helper packages (target_members,
// resource_mirror, reconcile_outbox) + the fga_outbox/audit_outbox emit
// helpers, all on the caller-owned tx.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/target_members"
)

// ReconcileAdapter — composition-root adapter for the reconciler. Holds the
// pool; each reconcile pass opens its own writer-tx.
type ReconcileAdapter struct {
	pool *pgxpool.Pool
	// cat — источник КАТАЛОЖНОГО ФАКТА (kacho#1816). Нужен здесь, потому что
	// набор глаголов якоря выводится при чтении выдачи (`bindingScopeFrom`), а
	// не при её материализации.
	cat catalog.Source
}

// NewReconcileAdapter constructs the adapter over a pool.
//
// `cat` — источник каталожного факта; параметр ОБЯЗАТЕЛЬНЫЙ: без него набор
// глаголов якоря пуст, и роль-суперпользователь молча понизилась бы с
// администратора до наблюдателя.
func NewReconcileAdapter(pool *pgxpool.Pool, cat catalog.Source) *ReconcileAdapter {
	return &ReconcileAdapter{pool: pool, cat: cat}
}

// WithTx runs fn inside a single writer-tx (reconcile.TxRunner). Commit on
// success, rollback on error/panic.
func (a *ReconcileAdapter) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	store := &reconcileStore{tx: tx, cat: a.cat.Facts()}
	if err := fn(ctx, store); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("reconcile: commit: %w", err)
	}
	committed = true
	return nil
}

// reconcileStore — tx-scoped reconcile.ReconcileStore implementation.
//
// roleCache — памятка ролей на ЖИЗНЬ ОДНОГО прохода (одна транзакция). Веер прохода
// адресуется числом выдач, а роли у них повторяются, поэтому без памятки полный проход
// перечитывал одну и ту же строку роли по разу на выдачу. Внутри одной транзакции ответ
// измениться не может; роль, изменённая в середине прохода, доводится своим собственным
// веером Role.Update — как и до памятки.
type reconcileStore struct {
	tx        pgx.Tx
	roleCache map[domain.RoleID]domain.Role
	// cat — каталожный факт, взятый ОДИН раз на весь проход. Брать его заново
	// на каждой выдаче значило бы допустить проход, собранный из разных
	// моментов времени.
	cat *catalog.Facts
}

// LoadBinding reads the minimal scope/selector/role facts for a binding inside
// the tx. ok=false when the binding row is gone (deleted).
//
// It takes a `SELECT … FOR NO KEY UPDATE` lock on the binding row
// (GetForNoKeyUpdate) as the FIRST statement of the reconcile writer-tx, so two
// concurrent reconcile passes of the same binding serialize on the row-lock
// (system-design ВЗ-1): the second pass blocks here until the first commits its
// diff, then sees the already-materialized member (no status change → idempotent
// skip) and emits no duplicate fga_outbox tuples. The expiry path (ExpireBinding)
// keeps its CAS guard (RevokeExpiredBinding) and ALSO benefits from the lock taken
// here. Почему режим именно NO KEY (и что это не ослабляет) — в godoc
// GetForNoKeyUpdate: он не конфликтует с `FOR KEY SHARE` дочерних вставок, поэтому
// аддитивный форвард пути создания больше не стоит в очереди за фоновым проходом.
func (s *reconcileStore) LoadBinding(ctx context.Context, bindingID domain.AccessBindingID) (reconcile.BindingScope, bool, error) {
	return s.loadBinding(ctx, bindingID, true /* forUpdate — full path serializes the delete-stale diff */)
}

// LoadBindingUnlocked loads the same BindingScope as LoadBinding but WITHOUT the
// `FOR NO KEY UPDATE` row-lock — the read the ADDITIVE forward fast-path
// (reconcile.ReconcileObjectForward) uses. Forward only WRITES the freshly-registered
// object's tuples (never a delete-stale diff), so it needs no serialization against a
// concurrent pass of the same binding; taking the row-lock here would re-serialize all
// registrations sharing one editor/owner binding — the exact bottleneck the fast-path
// removes. Correctness is preserved by the async FULL ReconcileObject backstop.
func (s *reconcileStore) LoadBindingUnlocked(ctx context.Context, bindingID domain.AccessBindingID) (reconcile.BindingScope, bool, error) {
	return s.loadBinding(ctx, bindingID, false /* no row-lock — additive forward path */)
}

// LoadBindingsUnlocked loads the SAME BindingScope facts as LoadBindingUnlocked for a
// WHOLE SET of bindings — in TWO round-trips total (one for the binding rows, one for
// their DISTINCT roles), instead of two PER BINDING.
//
// ЗАЧЕМ. Веер материализации адресуется числом ВЫДАЧ, совпавших с одним объектом, а не
// числом объектов: меняется ровно один объект, но кандидатов у него столько, сколько
// выдач покрывает его область. Перепись по дереву выдач стенда (8267 объектов зеркала,
// предикат — та же SQL-форма, что у SelectorBindingsMatchingObject) дала p50 = 9
// кандидатов, p95 = 19, p99 = 226, максимум 227. Поштучное чтение превращало хвост в 454
// последовательных обращения внутри ОДНОЙ транзакции пост-коммитного прохода, то есть
// стоимость видимости своего свежего ресурса росла линейно с числом выдач соседей.
// Замер (testcontainers PG16, 15 проходов на размер): 9 выдач — p50 14.6 мс, 227 выдач —
// p50 349.1 мс, то есть ~1.5 мс на выдачу.
//
// ЧТО НЕ МЕНЯЕТСЯ. Ни блокировок, ни порядка: путь аддитивен и advisory-блокировки не
// берёт (см. reconcile/forward.go «LOCK CHOICE»), а строчной блокировки у этого чтения не
// было и раньше. Проекция BindingScope собирается тем же bindingScopeFrom, что и у
// поштучного чтения, поэтому пакетный и одиночный пути выводят ПОБАЙТОВО те же факты.
// Отсутствующая выдача (удалена) просто не попадает в карту — ровно как ok=false у
// одиночного чтения; отсутствующая роль трактуется как «нет покрытия», а не как ошибка.
func (s *reconcileStore) LoadBindingsUnlocked(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]reconcile.BindingScope, error) {
	out := make(map[domain.AccessBindingID]reconcile.BindingScope, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	raw := make([]string, 0, len(ids))
	seen := make(map[domain.AccessBindingID]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		raw = append(raw, string(id))
	}
	rows, err := s.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = ANY($1) ORDER BY id ASC`, abCols), raw)
	if err != nil {
		return nil, fmt.Errorf("reconcile: load bindings batch: %w", err)
	}
	bindings := make([]domain.AccessBinding, 0, len(raw))
	roleIDs := make([]string, 0, len(raw))
	roleSeen := make(map[domain.RoleID]struct{}, len(raw))
	for rows.Next() {
		b, serr := scanAB(rows)
		if serr != nil {
			rows.Close()
			return nil, fmt.Errorf("reconcile: scan binding batch row: %w", serr)
		}
		bindings = append(bindings, b)
		if _, dup := roleSeen[b.RoleID]; !dup {
			roleSeen[b.RoleID] = struct{}{}
			roleIDs = append(roleIDs, string(b.RoleID))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reconcile: load bindings batch: %w", err)
	}

	// Роли — ОДНИМ обращением по различным идентификаторам. Их у веера заметно меньше,
	// чем выдач (на стенде при 227 кандидатах различных ролей 194, при медианных 9 —
	// четыре), но главное здесь не сжатие, а то, что число обращений перестаёт зависеть
	// от размера веера.
	roles := make(map[domain.RoleID]domain.Role, len(roleIDs))
	if len(roleIDs) > 0 {
		rrows, rerr := s.tx.Query(ctx,
			fmt.Sprintf(`SELECT %s FROM roles WHERE id = ANY($1)`, roleCols), roleIDs)
		if rerr != nil {
			return nil, fmt.Errorf("reconcile: load roles batch: %w", rerr)
		}
		for rrows.Next() {
			ro, serr := scanRole(rrows)
			if serr != nil {
				rrows.Close()
				return nil, fmt.Errorf("reconcile: scan role batch row: %w", serr)
			}
			roles[ro.ID] = ro
		}
		rrows.Close()
		if rerr := rrows.Err(); rerr != nil {
			return nil, fmt.Errorf("reconcile: load roles batch: %w", rerr)
		}
	}

	for _, b := range bindings {
		// Роль, удалённая из-под выдачи, — «нет покрытия» (пустая доменная роль), тот же
		// исход, что у одиночного чтения: реконсайлер не эмитит кортежей, а не падает.
		out[b.ID] = bindingScopeFrom(s.cat, b, roles[b.RoleID])
	}
	return out, nil
}

// loadBinding is the shared reader for LoadBinding (forUpdate=true) and
// LoadBindingUnlocked (forUpdate=false). The BindingScope projection is IDENTICAL in
// both modes — only the row-lock differs — so the full and forward paths derive the
// same scope/selector/subject facts.
func (s *reconcileStore) loadBinding(ctx context.Context, bindingID domain.AccessBindingID, forUpdate bool) (reconcile.BindingScope, bool, error) {
	r := &abReader{tx: s.tx}
	var (
		b   domain.AccessBinding
		err error
	)
	if forUpdate {
		b, err = r.GetForNoKeyUpdate(ctx, bindingID)
	} else {
		b, err = r.Get(ctx, bindingID)
	}
	if err != nil {
		if errors.Is(err, iamerr.ErrNotFound) {
			return reconcile.BindingScope{}, false, nil
		}
		return reconcile.BindingScope{}, false, err
	}

	// Role permissions (verb-bundle) — read inside the tx so the tier derivation
	// is consistent with the binding row read. Memoized per-tx (roleCache): a fan-out
	// pass reads the SAME role once per pass instead of once per binding, and within one
	// tx the answer cannot differ. A role changed mid-pass is re-materialized by its own
	// Role.Update fan-out, exactly as before.
	role, err := s.role(ctx, b.RoleID)
	if err != nil {
		// A dangling role (deleted out from under the binding) leaves no perms —
		// the reconciler then emits no tuples (membership stays non-ACTIVE). Treat
		// a missing role as "no coverage" rather than a hard error so a stale
		// mirror event does not crash the worker.
		if !errors.Is(err, iamerr.ErrNotFound) {
			return reconcile.BindingScope{}, false, fmt.Errorf("load role %s: %w", b.RoleID, err)
		}
	}

	return bindingScopeFrom(s.cat, b, role), true, nil
}

// role reads a role inside the tx, memoized for the lifetime of THIS pass. The per-binding
// full path (reconcileBindingForObject) fans out over the same candidate set as the
// forward path and re-read the SAME role row once per binding; the memo makes that read
// O(distinct roles) instead of O(bindings). A not-found role is memoized too (as "no
// coverage"), so a dangling role does not turn into a per-binding round-trip either.
func (s *reconcileStore) role(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	if s.roleCache == nil {
		s.roleCache = make(map[domain.RoleID]domain.Role)
	}
	if ro, ok := s.roleCache[id]; ok {
		return ro, nil
	}
	ro, err := (&roleReader{tx: s.tx}).Get(ctx, id)
	if err != nil {
		if errors.Is(err, iamerr.ErrNotFound) {
			s.roleCache[id] = domain.Role{}
		}
		return ro, err
	}
	s.roleCache[id] = ro
	return ro, nil
}

// bindingScopeFrom — ЕДИНСТВЕННАЯ точка вывода BindingScope из строки выдачи и её роли.
// Ею пользуются и поштучное чтение (loadBinding), и пакетное (LoadBindingsUnlocked),
// поэтому пакетный путь не может разойтись с одиночным ни в одном факте.
func bindingScopeFrom(cat *catalog.Facts, b domain.AccessBinding, role domain.Role) reconcile.BindingScope {
	return reconcile.BindingScope{
		BindingID:   b.ID,
		Scope:       scopeAnchorFor(b),
		SubjectType: string(b.SubjectType),
		SubjectID:   string(b.SubjectID),
		// RBAC explicit-model 2026 P4 (КФ-3): the dynamic membership source is the
		// role's UNIFIED materializing selectors — ARM_ANCHOR(all) + ARM_NAMES +
		// ARM_LABELS. Empty for a thin (legacy permissions-only) role → no
		// materialized members.
		//
		// SCOPE-AWARE (issue #224 / D-8a / D-9): a wildcard `*.*` rule expands to the
		// full materializable type set ONLY for a BOUNDED scope (ACCOUNT/PROJECT) so
		// the owner becomes an explicit per-object admin on the account's content; a
		// GLOBAL/CLUSTER `*.*` binding (cluster super-admin) yields no content
		// selectors — it is served by the D-9 flat short-circuit, never per-object.
		Selectors: role.Rules.MaterializingSelectorsInScope(b.Scope),
		// Scope-self verbs (D-7 / КФ-3 / C-01): the role's verbs that apply to the
		// binding's OWN scope resource-type, so the reconciler materializes the tier
		// (+ verb-bearing v_*) tuple on the scope object itself (the write-authz /
		// no-access-loss anchor the removed binding-time anchor emit produced).
		ScopeSelfVerbs: role.Rules.ScopeSelfVerbs(string(b.ResourceType),
			scopeTypeVerbs(cat, string(b.ResourceType))),
		// Target — the per-object least-privilege selection (F8, IAM-1-21). When
		// Target.Resources is non-empty the reconciler materializes ONLY the listed
		// objects (never the whole scope). Read from the persisted access_bindings.target
		// column by scanAB (unmarshalTarget). AllInScope/empty ⇒ whole-anchor grant.
		Target: b.Target,
		RoleID: string(b.RoleID),
		Active: b.Status == domain.AccessBindingStatusActive,
	}
}

// AcquireBindingLock takes pg_advisory_xact_lock(hashtext(binding_id)) on the
// reconcile writer-tx (КФ-1). xact-scoped → auto-released on commit/rollback (never
// pool-scoped). Concurrent reconcile passes of the same binding block here until the
// holder commits, then see the already-materialized member (idempotent skip).
func (s *reconcileStore) AcquireBindingLock(ctx context.Context, bindingID domain.AccessBindingID) error {
	if _, err := s.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(bindingID)); err != nil {
		return fmt.Errorf("reconcile: advisory-lock binding %s: %w", bindingID, err)
	}
	return nil
}

// MatchAllInScope returns the mirror objects of the given types NARROWED to the binding's
// containment scope (ARM_ANCHOR/`all`, P4) — no label filter. The scope is pushed into the
// SQL (resource_mirror.AllByTypes) as a PROVEN SUPERSET of the use-case's IsContainedIn
// re-verify, so the reconciler receives O(scope) rows instead of O(cluster mirror). The Go
// IsContainedIn re-verify STAYS authoritative — this only PRE-filters (over-broad is safe).
func (s *reconcileStore) MatchAllInScope(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error) {
	if len(types) == 0 {
		return nil, nil
	}
	rows, err := resource_mirror.AllByTypes(ctx, s.tx, types, scope.Type, scope.ID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

// MatchByIDs returns the mirror objects of the given types whose object_id ∈ ids
// (ARM_NAMES, P4). An id not yet in the mirror is absent (PENDING — the forward path
// picks it up on its RegisterResource).
func (s *reconcileStore) MatchByIDs(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	if len(types) == 0 || len(ids) == 0 {
		return nil, nil
	}
	rows, err := resource_mirror.ByTypesAndIDs(ctx, s.tx, types, ids)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

// MatchAllInScopeIAMDirect returns the IAM-OWN objects of the given iam-direct types
// (iam.project/iam.account + content) read SAME-DB, NARROWED to the binding's containment
// scope (ARM_ANCHOR/`all`, P4). Like MatchAllInScope it pushes the scope into the per-type
// SQL as a PROVEN SUPERSET of the IsContainedIn re-verify (which still runs), so the anchor
// arm no longer scans EVERY iam-native row of the type cluster-wide.
func (s *reconcileStore) MatchAllInScopeIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error) {
	return s.iamDirectQuery(ctx, types, "", nil, scope)
}

// MatchByIDsIAMDirect returns the IAM-OWN objects of the given iam-direct types
// whose id ∈ ids (ARM_NAMES, P4). The names arm is already narrow (specific ids) AND a
// foreign-scope match is a WANTED REJECTED-containment signal (cross-scope injection audit),
// so it is LEFT UNSCOPED — the reconciler still re-verifies + audits it.
func (s *reconcileStore) MatchByIDsIAMDirect(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return s.iamDirectQuery(ctx, types, "ids", ids, domain.ScopeAnchor{})
}

// iamDirectScanSpec describes how to read ONE iam-direct (D6) native table for the
// ARM_ANCHOR/ARM_NAMES arms and stamp its containment parents. The SELECT yields
// EXACTLY three columns in order: id, parent_account_id, parent_project_id — so the
// SAME IsContainedIn predicate decides account/project/cluster containment for every
// iam-native type. table/objectType/parentExpr are FIXED literals (never user input).
//
//   - iam.project  → parent_account = projects.account_id, parent_project = own id.
//   - iam.account  → parent_account = own id, parent_project = ” (account is contained
//     in account:<self> + cluster only).
//   - iam.role / iam.group / iam.serviceAccount — account-scoped content;
//     parent_account = account_id (COALESCED through the owning project for a
//     project-scoped role/SA so the account-scoped owner binding still contains it),
//     parent_project = project_id (NULL → ”).
//   - iam.user — аккаунты берутся из kacho_iam.memberships, а НЕ из колонки строки
//     (#1172); их бывает несколько, поэтому источник назван parentAccountsExpr.
//   - iam.accessBinding — scoped by (resource_type, resource_id): account-scoped →
//     parent_account; project-scoped → parent_project (+ its account via the projects
//     join); cluster-scoped → neither (contained only in cluster scope).
type iamDirectScanSpec struct {
	objectType string
	table      string
	// parentAccountExpr — СКАЛЯРНОЕ выражение над псевдонимом `o` (и `p`, если
	// задан join), дающее ЕДИНСТВЕННЫЙ аккаунт объекта из его СОБСТВЕННОЙ строки.
	// Пусто ровно тогда, когда принадлежность аккаунту не является свойством
	// строки (iam.user — она выражена связью, см. parentAccountsExpr).
	//
	// Поле остаётся отдельным от plural-формы, потому что у него есть свой
	// читатель: гейт согласия источников цепи областей сверяет ИМЕННО
	// колонку-указатель собственной строки (scopeedgesource_gate_test.go), и
	// каноническая форма ниже эту колонку в себе прячет.
	parentAccountExpr string
	// parentAccountsExpr — выражение, дающее ВЕСЬ набор аккаунтов объекта как
	// text[]. Задаётся там, где аккаунтов бывает больше одного и скалярная форма
	// их не выражает by construction. Ровно одно из двух полей непусто; инвариант
	// держит проба TestIAMDirectSpec_AccountSourceIsDeclaredExactlyOnce.
	parentAccountsExpr string
	parentProjectExpr  string
	// join is an optional LEFT JOIN clause (e.g. resolve a project's account_id).
	join string
}

// accountsExpr — КАНОНИЧЕСКАЯ форма источника аккаунтов: SQL-выражение типа
// text[] над псевдонимом `o` (+ `p`, если задан join).
//
// Единственная точка, где две формы объявления сводятся к одной: проекция
// SELECT, сужение по области и полоса «якорь» обратного подбора обязаны читать
// ОДНО выражение, иначе сужение перестанет быть доказанным надмножеством
// повторной проверки IsContainedIn — и разойдутся они молча, потому что на
// вырожденном наборе (один аккаунт) обе формы дают одно и то же.
//
// Пустые строки из набора вычищаются здесь же: «аккаунта нет» обязано быть
// ОТСУТСТВИЕМ элемента, иначе область с пустым идентификатором совпала бы с
// объектом, у которого аккаунта нет вовсе.
func (s iamDirectScanSpec) accountsExpr() string {
	if s.parentAccountsExpr != "" {
		return s.parentAccountsExpr
	}
	return "ARRAY_REMOVE(ARRAY[COALESCE(" + s.parentAccountExpr + ", '')], '')"
}

// iamDirectScanSpecs — the closed, per-type read plan. All identifiers are literals.
var iamDirectScanSpecs = map[string]iamDirectScanSpec{
	"iam.project": {
		objectType: "iam.project", table: "kacho_iam.projects",
		parentAccountExpr: "o.account_id", parentProjectExpr: "o.id",
	},
	"iam.account": {
		objectType: "iam.account", table: "kacho_iam.accounts",
		parentAccountExpr: "o.id", parentProjectExpr: "''",
	},
	// account-scoped content (a role may also be project-scoped; a service
	// account is account-scoped only — её проектная колонка снята вместе с
	// полем контракта, писателя у неё не было).
	"iam.role": {
		objectType: "iam.role", table: "kacho_iam.roles",
		// A project-scoped role has account_id NULL → resolve it through its project.
		parentAccountExpr: "COALESCE(o.account_id, p.account_id, '')",
		parentProjectExpr: "COALESCE(o.project_id, '')",
		join:              "LEFT JOIN kacho_iam.projects p ON p.id = o.project_id",
	},
	"iam.group": {
		objectType: "iam.group", table: "kacho_iam.groups",
		parentAccountExpr: "o.account_id", parentProjectExpr: "''",
	},
	"iam.serviceAccount": {
		objectType: "iam.serviceAccount", table: "kacho_iam.service_accounts",
		parentAccountExpr: "o.account_id", parentProjectExpr: "''",
	},
	// ЛИЧНОСТЬ — аккаунты из СВЯЗИ, а не из колонки строки (#1172).
	//
	// `kacho_iam.users.account_id` называет ОДИН аккаунт человека из многих:
	// принадлежность стала отдельной связью (#470/#471), и цепь областей читает
	// её из `kacho_iam.memberships` с #944. Колонка при этом осталась
	// легаси-полем перехода — её не правит ни исключение из аккаунта (#1127), ни
	// приглашение во второй, — поэтому опора на неё давала выдаче ДВА неверных
	// исхода сразу: второй аккаунт не находил своего человека, а первый
	// продолжал накрывать исключённого.
	//
	// Полнота источника — та же, что у ветви (4a) цепи: строка И ЕСТЬ связь
	// (`memberships.id` первичный ключ, пара уникальна, 470001), поэтому обойти
	// строку и получить членство нельзя ни через API, ни через посев.
	//
	// Состояние членства НЕ ЧИТАЕТСЯ — дословно то же решение, что в ветви (4a):
	// звено есть указатель ВВЕРХ, а не выдача. Приглашённый обязан быть достижим
	// распорядителю аккаунта, куда его пригласили, иначе приглашение нельзя ни
	// прочитать, ни отозвать до первого входа приглашённого.
	"iam.user": {
		objectType: "iam.user", table: "kacho_iam.users",
		parentAccountsExpr: "ARRAY(SELECT m.account_id FROM kacho_iam.memberships m" +
			" WHERE m.user_id = o.id AND COALESCE(m.account_id, '') <> ''" +
			" ORDER BY m.account_id)",
		parentProjectExpr: "''",
	},
	// access_binding is scoped by (resource_type, resource_id): map the scope anchor
	// onto the containment parents so the owner binding contains the bindings of its
	// account/projects (a cluster-scoped binding stays cluster-only — both empty).
	"iam.accessBinding": {
		objectType: "iam.accessBinding", table: "kacho_iam.access_bindings",
		parentAccountExpr: "CASE WHEN o.resource_type = 'account' THEN o.resource_id ELSE COALESCE(p.account_id, '') END",
		parentProjectExpr: "CASE WHEN o.resource_type = 'project' THEN o.resource_id ELSE '' END",
		join:              "LEFT JOIN kacho_iam.projects p ON o.resource_type = 'project' AND p.id = o.resource_id",
	},
}

// iamDirectScopePredicate builds the ANCHOR-arm scope narrowing for one iam-direct type as a
// PROVEN SUPERSET of the domain IsContainedIn re-verify. It reuses the SAME per-type
// parent-scope expressions the SELECT projects into ParentAccountIDs/ParentProjectID, so the
// WHERE selects EXACTLY the rows IsContainedIn(scope) accepts — never fewer (no under-grant):
//
//   - project scope → parentProjectExpr = $1   (IsContainedIn: ParentProjectID == scope.ID)
//   - account scope → $1 = ANY(accountsExpr) (IsContainedIn: scope.ID ∈ ParentAccountIDs)
//   - cluster / unknown → "" (no narrowing; IsContainedIn cluster=true, unknown handled by
//     the Go re-verify — over-broad is safe, under-broad is not).
//
// Аккаунт спрашивается ВХОЖДЕНИЕМ В НАБОР, потому что набор и есть то, что
// проецирует SELECT: у личности аккаунтов столько, сколько членств (#1172), и
// равенство скаляру отбросило бы человека, чьё членство в спрашиваемом аккаунте
// НЕ ПЕРВОЕ, — то есть дало бы недостачу, а не избыток.
//
// The expressions are fixed literals from the closed spec map (never user input) → the single
// bound $1 carries the caller-supplied scope id, so the interpolation is injection-safe.
func iamDirectScopePredicate(spec iamDirectScanSpec, scope domain.ScopeAnchor) (clause string, arg any) {
	switch scope.Type {
	case "project":
		return spec.parentProjectExpr + " = $1", scope.ID
	case "account":
		return "$1 = ANY(" + spec.accountsExpr() + ")", scope.ID
	default:
		return "", nil
	}
}

// iamDirectQuery is the shared iam-direct (D6) read for the ARM_ANCHOR/ARM_NAMES
// arms: it scans each requested iam-native table (per iamDirectScanSpecs) filtered by
// `mode` ("" → all-in-scope, "ids" → id = ANY(ids)), stamping the containment parents so the
// SAME IsContainedIn predicate decides containment. No peer-call (same-DB) — the
// graph stays acyclic. Extended from iam.project/iam.account to
// the full iam content set (role/group/serviceAccount/user/accessBinding) so a bounded
// owner `*.*` rule forward-materializes per-object admin on iam-native content.
//
// The ANCHOR mode ("") pushes the binding's containment `scope` into the SQL WHERE as a
// PROVEN SUPERSET of the IsContainedIn re-verify (SAME parent-scope expressions the SELECT
// projects), so the anchor arm receives O(scope) iam rows, not every row of the type. The
// NAMES mode ("ids") is LEFT UNSCOPED: it is already narrow (specific ids) and a foreign-scope
// id-match is a WANTED REJECTED-containment audit signal, so the reconciler must still see it.
func (s *reconcileStore) iamDirectQuery(ctx context.Context, types []string, mode string, ids []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error) {
	if len(types) == 0 {
		return nil, nil
	}
	var out []domain.MirrorObject
	for _, t := range types {
		spec, ok := iamDirectScanSpecs[t]
		if !ok {
			// Not an iam-direct materializable type — skip (the partitioner should
			// not have routed it here; defensive).
			continue
		}
		// All identifiers below are fixed literals from the closed spec map (never
		// user input), so the interpolation is injection-safe.
		q := "SELECT o.id, " + spec.accountsExpr() + ", " + spec.parentProjectExpr +
			" FROM " + spec.table + " o"
		if spec.join != "" {
			q += " " + spec.join
		}
		var rows pgx.Rows
		var err error
		if mode == "ids" {
			rows, err = s.tx.Query(ctx, q+" WHERE o.id = ANY($1) ORDER BY o.id ASC", ids)
		} else {
			// ANCHOR: narrow to scope via the SAME parent-scope expression IsContainedIn is
			// fed (project → parentProjectExpr; account → parentAccountExpr; cluster/unknown →
			// no narrowing, Go re-verify stays authoritative). Guaranteed superset.
			scopeClause, scopeArg := iamDirectScopePredicate(spec, scope)
			if scopeClause != "" {
				rows, err = s.tx.Query(ctx, q+" WHERE "+scopeClause+" ORDER BY o.id ASC", scopeArg)
			} else {
				rows, err = s.tx.Query(ctx, q+" ORDER BY o.id ASC")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("reconcile: iam-direct %s %s: %w", spec.objectType, mode, err)
		}
		objs, serr := scanIAMDirect(rows, spec.objectType)
		if serr != nil {
			return nil, serr
		}
		out = append(out, objs...)
	}
	return out, nil
}

// MatchSelector returns mirror objects matching types+matchLabels (labels @>).
func (s *reconcileStore) MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error) {
	rows, err := resource_mirror.MatchByLabels(ctx, s.tx, types, matchLabels)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

// MatchIAMDirect returns IAM's OWN objects matching the selector labels SAME-DB
// from the native tables (D6, FeedIAMDirect). Под единой моделью видимости —
// ВСЕ iam-native типы (project/account + content user/serviceAccount/group/role/
// accessBinding) label-selectable; их own-table несет колонку `labels` (migration
// 0041) с GIN(jsonb_path_ops) под `@>`. Containment-предикат тот же
// (parentAccountExpr/parentProjectExpr из iamDirectScanSpecs), что и для
// ARM_ANCHOR/ARM_NAMES, поэтому доменный IsContainedIn решает account/project/
// cluster containment единообразно.
//
// `types` содержит ТОЛЬКО iam-direct типы (reconciler партиционирует по feed). No
// peer-call (same-DB) — граф ацикличен, self-mirror отсутствует.
func (s *reconcileStore) MatchIAMDirect(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error) {
	if len(types) == 0 || len(matchLabels) == 0 {
		return nil, nil
	}
	labelsJSON, err := json.Marshal(matchLabels)
	if err != nil {
		return nil, fmt.Errorf("reconcile: marshal iam-direct match labels: %w", err)
	}
	var out []domain.MirrorObject
	for _, t := range types {
		spec, ok := iamDirectScanSpecs[t]
		if !ok {
			// Not an iam-direct type — the partitioner should not route it here.
			continue
		}
		// All identifiers below are fixed literals from the closed spec map (never
		// user input), so the interpolation is injection-safe. The own-table
		// `labels @> $1` probe is served by the per-table GIN index (migration 0041).
		q := "SELECT o.id, " + spec.accountsExpr() + ", " + spec.parentProjectExpr +
			" FROM " + spec.table + " o"
		if spec.join != "" {
			q += " " + spec.join
		}
		q += " WHERE o.labels @> $1::jsonb ORDER BY o.id ASC"
		rows, qerr := s.tx.Query(ctx, q, labelsJSON)
		if qerr != nil {
			return nil, fmt.Errorf("reconcile: iam-direct match labels %s: %w", spec.objectType, qerr)
		}
		objs, serr := scanIAMDirect(rows, spec.objectType)
		if serr != nil {
			return nil, serr
		}
		out = append(out, objs...)
	}
	return out, nil
}

// scanIAMDirect scans (object_id, parent_account_ids, parent_project_id) rows into
// MirrorObjects for an iam-direct object type. The three columns are produced by
// iamDirectQuery's per-type SELECT (accountsExpr / parentProjectExpr), so the
// SAME IsContainedIn predicate decides account/project/cluster containment uniformly
// across every iam-native type (project/account/role/group/serviceAccount/user/
// accessBinding). An EMPTY account set (e.g. a cluster-scoped binding) leaves the
// object contained only in a cluster-scope binding (IsContainedIn cluster=true).
//
// Строка на объект остаётся ОДНА и при нескольких аккаунтах: набор приезжает
// массивом, а не соединением. Соединение размножило бы строки, и один объект дал
// бы ДВА желаемых участника с одним ключом — накрытый и отвергнутый, — из которых
// последний записанный отобрал бы кортеж у первого.
func scanIAMDirect(rows pgx.Rows, objectType string) ([]domain.MirrorObject, error) {
	defer rows.Close()
	var out []domain.MirrorObject
	for rows.Next() {
		var id, parentProject string
		var parentAccounts []string
		if err := rows.Scan(&id, &parentAccounts, &parentProject); err != nil {
			return nil, fmt.Errorf("reconcile: scan iam-direct %s row: %w", objectType, err)
		}
		out = append(out, domain.MirrorObject{
			ObjectType:       objectType,
			ObjectID:         id,
			ParentAccountIDs: parentAccounts,
			ParentProjectID:  parentProject,
		})
	}
	return out, rows.Err()
}

// GetMirrorObject returns one mirror row (byName containment / PENDING verify).
func (s *reconcileStore) GetMirrorObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error) {
	row, ok, err := resource_mirror.GetByObject(ctx, s.tx, objectType, objectID)
	if err != nil {
		return domain.MirrorObject{}, false, err
	}
	if !ok {
		return domain.MirrorObject{}, false, nil
	}
	return mirrorRowToDomain(row), true, nil
}

// GetIAMDirectObject returns the same-DB own-table projection (containment parents +
// labels) of ONE iam-native object — the iam-direct analogue of GetMirrorObject used by
// the ADDITIVE forward fast-path (ReconcileObjectForward) for a brand-new iam.project /
// iam.account / iam content object, which lives in its OWN table (never the mirror).
//
// It reuses the SAME per-type read plan (iamDirectScanSpecs: table + parentAccountExpr /
// parentProjectExpr + optional join) the anchor/names/labels iam-direct match queries use,
// so the stamped containment parents are BYTE-IDENTICAL to what iamDirectQuery /
// MatchIAMDirect produce → the shared IsContainedIn / selectorMatchesObject verdict decides
// the same way the FULL path would. It ADDITIONALLY selects the own-table `labels` column
// (migration 0041 — every iam-native table carries it) so the forward path's ARM_LABELS
// re-check (selectorMatchesObject → MatchesLabels) is a faithful in-Go mirror of the SQL
// `labels @> match_labels` probe IAMDirectSelectorBindingsMatchingObject ran, with no drift.
//
// All identifiers below are fixed literals from the closed spec map (never user input); the
// single bound $1 carries the object id, so the interpolation is injection-safe. ok=false
// when the type is not iam-direct (spec absent) or the row does not exist (pgx.ErrNoRows).
func (s *reconcileStore) GetIAMDirectObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error) {
	spec, ok := iamDirectScanSpecs[objectType]
	if !ok {
		// Not an iam-direct materializable type — nothing to project (defensive; the
		// forward path only routes iam-direct types here).
		return domain.MirrorObject{}, false, nil
	}
	q := "SELECT o.id, " + spec.accountsExpr() + ", " + spec.parentProjectExpr + ", o.labels" +
		" FROM " + spec.table + " o"
	if spec.join != "" {
		q += " " + spec.join
	}
	q += " WHERE o.id = $1"
	var (
		id, parentProject string
		parentAccounts    []string
		labelsJSON        []byte
	)
	if err := s.tx.QueryRow(ctx, q, objectID).Scan(&id, &parentAccounts, &parentProject, &labelsJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.MirrorObject{}, false, nil
		}
		return domain.MirrorObject{}, false, fmt.Errorf("reconcile: get iam-direct object %s:%s: %w", spec.objectType, objectID, err)
	}
	obj := domain.MirrorObject{
		ObjectType:       spec.objectType,
		ObjectID:         id,
		ParentAccountIDs: parentAccounts,
		ParentProjectID:  parentProject,
	}
	if len(labelsJSON) > 0 {
		if err := json.Unmarshal(labelsJSON, &obj.Labels); err != nil {
			return domain.MirrorObject{}, false, fmt.Errorf("reconcile: unmarshal iam-direct labels %s:%s: %w", spec.objectType, objectID, err)
		}
	}
	return obj, true, nil
}

// CurrentMembers returns the materialized members (diff base) inside the tx.
func (s *reconcileStore) CurrentMembers(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.TargetMember, error) {
	rows, err := target_members.ListByBindingTx(ctx, s.tx, string(bindingID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.TargetMember, 0, len(rows))
	for _, m := range rows {
		out = append(out, domain.TargetMember{
			BindingID:          domain.AccessBindingID(m.BindingID),
			RoleID:             domain.RoleID(m.RoleID),
			RuleFP:             m.RuleFP,
			ObjectType:         m.ObjectType,
			ObjectID:           m.ObjectID,
			VerificationStatus: m.VerificationStatus,
		})
	}
	return out, nil
}

// CurrentMembersForObject returns the materialized members of ONE binding on ONE object
// — the NARROW diff base of the object-triggered pass. See ListByBindingObjectTx for why
// the read is driven off the by-object index rather than the binding-leading PK.
func (s *reconcileStore) CurrentMembersForObject(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string) ([]domain.TargetMember, error) {
	rows, err := target_members.ListByBindingObjectTx(ctx, s.tx, string(bindingID), objectType, objectID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.TargetMember, 0, len(rows))
	for _, m := range rows {
		out = append(out, domain.TargetMember{
			BindingID:          domain.AccessBindingID(m.BindingID),
			RoleID:             domain.RoleID(m.RoleID),
			RuleFP:             m.RuleFP,
			ObjectType:         m.ObjectType,
			ObjectID:           m.ObjectID,
			VerificationStatus: m.VerificationStatus,
		})
	}
	return out, nil
}

// BindingsForObject returns binding ids with a member referencing the object.
func (s *reconcileStore) BindingsForObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error) {
	ids, err := target_members.BindingsForObjectTx(ctx, s.tx, objectType, objectID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.AccessBindingID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.AccessBindingID(id))
	}
	return out, nil
}

// SelectorBindingsMatchingObject returns ACTIVE selector-binding ids whose
// selector now matches the object (objectType ∈ types AND mirror.labels @>
// match_labels) — the fast-path source (system-design ВЗ-2). The object's labels
// are read from resource_mirror and probed against each selector's match_labels;
// the GIN index on resource_mirror.labels + the type filter keep it cheap. A
// binding with NO member row yet for the object is INCLUDED (that is the point —
// a brand-new match). Bindings that no longer match are simply not returned.
func (s *reconcileStore) SelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error) {
	// RBAC rules-model 2026: the fast-path source is the
	// role.rules ARM_LABELS selectors (role_rule_selectors) carried by the binding's
	// ROLE — the legacy per-binding access_binding_selector arm is gone. A brand-new
	// matching object materializes membership for rules-role bindings on the
	// mirror-change event (≤2s), not only on the sweep.
	// RBAC explicit-model 2026 P4 (КФ-3): the fast-path matches ALL selector arms
	// carried by the binding's ROLE (role_rule_selectors now stores anchor/names/
	// labels). The arm decides the predicate: anchor → type only (every object of the
	// type); names → type + object_id ∈ resource_names; labels → type + labels @>
	// match_labels. This lets a freshly-registered object materialize membership for
	// anchor/names bindings on its mirror-change event (forward-mat, D-4), not only on
	// the periodic sweep.
	// SCOPE-NARROWING (bound fan-out): the ANCHOR arm matches every object of the type,
	// so a wildcard `*.*` anchor role (owner/admin/edit/view) bound at N account/project
	// scopes would fan out to ALL N bindings on every object-change event — then each
	// reconcileBinding re-verifies IsContainedIn and materializes only the contained
	// objects (correctness safe, but O(all bindings of the type) candidates). Push the
	// SAME IsContainedIn predicate into the JOIN for the anchor arm so only bindings whose
	// scope CONTAINS this object are candidates (O(containing bindings) — typically the
	// object's owner + its project-admin). cluster-scoped anchor bindings contain
	// everything (IsContainedIn cluster=true) and are kept. The names/labels arms are
	// already narrow (specific ids / labels) and their foreign-scope match is a wanted
	// REJECTED-containment signal, so they are LEFT UNFILTERED — the reconciler still
	// audits them.
	//
	// TRANSITIVE account containment: a mirror-fed object is registered with its owning
	// PROJECT (parent_project_id); an ACCOUNT-scoped binding contains it because the
	// project belongs to the account. The direct parent_account_id column may be empty
	// (legacy/unresolved register), so the account arm resolves the account through the
	// project→account hierarchy same-DB — COALESCE(NULLIF(m.parent_account_id,''),
	// pj.account_id) — mirroring the resource_mirror reader's projection so this fast-path
	// JOIN and the reconciler's IsContainedIn re-verify agree byte-for-byte. Bounded by
	// the account: the object's project resolves to exactly ONE account, so an owner of a
	// DIFFERENT account never matches (no cross-account over-grant). A cluster-scoped
	// anchor binding still matches everything.
	rows, err := s.tx.Query(ctx,
		`SELECT b.id
		   FROM kacho_iam.role_rule_selectors rrs
		   JOIN kacho_iam.access_bindings b ON b.role_id = rrs.role_id
		   JOIN kacho_iam.resource_mirror m
		     ON m.object_type = $1 AND m.object_id = $2
		   LEFT JOIN kacho_iam.projects pj ON pj.id = m.parent_project_id
		  WHERE b.status = 'ACTIVE'
		    AND $1 = ANY(rrs.object_types)
		    AND ( (rrs.arm = 'anchor' AND (
		                b.resource_type = 'cluster'
		             OR (b.resource_type = 'account'
		                 AND b.resource_id = COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id))
		             OR (b.resource_type = 'project' AND m.parent_project_id = b.resource_id)))
		       OR (rrs.arm = 'names'  AND $2 = ANY(rrs.resource_names))
		       OR (rrs.arm = 'labels' AND m.labels @> rrs.match_labels) )
		  ORDER BY b.id ASC`,
		objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: selector bindings matching object %s:%s: %w", objectType, objectID, err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan matching selector binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// IAMDirectSelectorBindingsMatchingObject is the iam-direct (D6) analogue of
// SelectorBindingsMatchingObject: ACTIVE selector-binding ids whose selector now
// matches the IAM-OWN object (objectType ∈ types AND the object's OWN-TABLE
// labels @> match_labels). The own table and the object's containment parents come
// from the SAME closed plan the projection uses (iamDirectScanSpecs), so this
// fast-path and the reconciler's IsContainedIn re-verify agree by construction; the
// labels @> probe is served by the per-table GIN index. Same-DB, no mirror. Used by
// the Q2 label-change trigger to pick up a freshly-matching iam-direct object.
//
// SCOPE-NARROWING OF THE ANCHOR ARM (parity with the mirror-fed sibling). The anchor
// arm matches every object of the type, so without a containment predicate a wildcard
// `*.*` anchor role bound at N account/project scopes fanned out to ALL N bindings on
// every object-change event — in EVERY account of the cluster, not just the object's
// own. Correctness never rested on this: each candidate then went through the
// per-binding IsContainedIn re-verify, which rejects the foreign-scope ones. The cost
// did: the fan-out was O(anchor bindings of the type ACROSS ALL ACCOUNTS) on the
// CREATE PATH of every iam-native object, and each surplus candidate is its own
// binding load. Measured on a populated stand before this narrowing, one
// iam.project / iam.accessBinding / iam.serviceAccount create produced ~1408
// candidates, while the already-narrowed mirror-fed arm returned 13 for a comparable
// object. It grew with every tenant the platform gained.
//
// The predicate below is the SAME one the mirror-fed branch pushes into its JOIN,
// written with the per-type parent-scope expressions of iamDirectScanSpecs — i.e. the
// expressions GetIAMDirectObject projects into ParentAccountIDs / ParentProjectID, the
// very fields IsContainedIn compares. It is therefore a PROVEN SUPERSET of the
// re-verify, never narrower:
//
//   - account scope → b.resource_id = ANY(accountsExpr) (IsContainedIn: scope.ID ∈ ParentAccountIDs)
//   - project scope → parentProjectExpr = b.resource_id  (IsContainedIn: ParentProjectID == scope.ID)
//   - cluster AND ANY UNKNOWN scope type → kept UNFILTERED. `cluster` contains
//     everything (IsContainedIn returns true), and an unrecognised scope type must
//     reach the Go re-verify rather than be silently dropped here: over-broad is a
//     cost, under-broad is an UNDER-GRANT. Hence `NOT IN ('account','project')`
//     rather than an explicit `= 'cluster'`.
//
// The names arm stays UNFILTERED for the same reason it does on the mirror-fed side:
// it is already narrow (specific ids) and a foreign-scope id-match is a WANTED
// REJECTED-containment audit signal the reconciler must still see. The labels arm is
// likewise left as it was.
func (s *reconcileStore) IAMDirectSelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error) {
	// The read plan — own table, optional join, and the containment parent
	// expressions — comes from the closed per-type spec map rather than a second,
	// local copy of the same switch. Two tables of one fact drift; this one is the
	// same source GetIAMDirectObject reads, so the WHERE below cannot disagree with
	// the projection the re-verify consumes.
	spec, ok := iamDirectScanSpecs[objectType]
	if !ok {
		// Not an iam-direct selectable type — no fast-path candidates.
		return nil, nil
	}
	// Все iam-native типы под единой моделью видимости label-selectable и несут
	// колонку labels, поэтому arm='labels'-ветка всегда активна.
	hasLabels := true
	// Every interpolated fragment is a fixed literal from the closed spec map (never
	// user input), so the interpolation is injection-safe; the two bound parameters
	// carry the object type and id.
	//
	// Источник fast-path — селекторы role.rules (role_rule_selectors), несомые ROLE
	// биндинга. Match по IAM-OWN-таблице arm-aware: anchor / names / labels
	// (labels @> match_labels через GIN).
	labelsBranch := ""
	if hasLabels {
		labelsBranch = " OR (rrs.arm = 'labels' AND o.labels @> rrs.match_labels)"
	}
	anchorBranch := `(rrs.arm = 'anchor' AND (
	                       b.resource_type NOT IN ('account','project')
	                    OR (b.resource_type = 'account' AND b.resource_id = ANY(` + spec.accountsExpr() + `))
	                    OR (b.resource_type = 'project' AND b.resource_id = ` + spec.parentProjectExpr + `)))`
	q := `SELECT b.id
	        FROM kacho_iam.role_rule_selectors rrs
	        JOIN kacho_iam.access_bindings b ON b.role_id = rrs.role_id
	        JOIN ` + spec.table + ` o ON o.id = $2 ` + spec.join + `
	       WHERE b.status = 'ACTIVE'
	         AND $1 = ANY(rrs.object_types)
	         AND ( ` + anchorBranch + `
	            OR (rrs.arm = 'names'  AND $2 = ANY(rrs.resource_names))` + labelsBranch + ` )
	       ORDER BY b.id ASC`
	rows, err := s.tx.Query(ctx, q, objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: iam-direct selector bindings matching %s:%s: %w", objectType, objectID, err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan iam-direct matching binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// UpsertMember materializes/updates a membership row (full rule coordinate).
func (s *reconcileStore) UpsertMember(ctx context.Context, m domain.TargetMember) error {
	return target_members.UpsertTx(ctx, s.tx, target_members.Member{
		BindingID:          string(m.BindingID),
		RoleID:             string(m.RoleID),
		RuleFP:             m.RuleFP,
		ObjectType:         m.ObjectType,
		ObjectID:           m.ObjectID,
		VerificationStatus: m.VerificationStatus,
	})
}

// UpsertMembers — тот же UPSERT, что UpsertMember, но НАБОРОМ: одно обращение к базе на
// весь веер прохода вместо одного на выдачу. Тот же ON CONFLICT, та же идемпотентность.
func (s *reconcileStore) UpsertMembers(ctx context.Context, members []domain.TargetMember) error {
	if len(members) == 0 {
		return nil
	}
	rows := make([]target_members.Member, 0, len(members))
	for _, m := range members {
		rows = append(rows, target_members.Member{
			BindingID:          string(m.BindingID),
			RoleID:             string(m.RoleID),
			RuleFP:             m.RuleFP,
			ObjectType:         m.ObjectType,
			ObjectID:           m.ObjectID,
			VerificationStatus: m.VerificationStatus,
		})
	}
	return target_members.UpsertManyTx(ctx, s.tx, rows)
}

// RecordEmittedTuplesBatch — тот же реестр, что RecordEmittedTuples, но набором,
// охватывающим НЕСКОЛЬКО выдач сразу: идентификатор выдачи едет вместе с кортежем,
// потому что ключ реестра — (выдача, субъект, отношение, объект).
func (s *reconcileStore) RecordEmittedTuplesBatch(ctx context.Context, refs []reconcile.EmittedTupleRef) error {
	if len(refs) == 0 {
		return nil
	}
	binds := make([]string, 0, len(refs))
	users := make([]string, 0, len(refs))
	rels := make([]string, 0, len(refs))
	objs := make([]string, 0, len(refs))
	// Дедуп по ПОЛНОМУ ключу конфликта: `ON CONFLICT … DO UPDATE` не вправе задеть одну
	// строку дважды в одном стейтменте (см. RecordEmittedTuples).
	seen := make(map[[4]string]struct{}, len(refs))
	for _, ref := range refs {
		t := ref.Tuple
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("reconcile: record emitted tuple: incomplete (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		k := [4]string{string(ref.BindingID), t.User, t.Relation, t.Object}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		binds = append(binds, string(ref.BindingID))
		users = append(users, t.User)
		rels = append(rels, t.Relation)
		objs = append(objs, t.Object)
	}
	if _, err := s.tx.Exec(ctx,
		`INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
		 SELECT b, u, r, o, 'member' FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS t(b, u, r, o)
		 ON CONFLICT (binding_id, fga_user, relation, object) DO UPDATE SET source = 'member'`,
		binds, users, rels, objs,
	); err != nil {
		return fmt.Errorf("reconcile: record emitted tuples batch: %w", err)
	}
	return nil
}

// DeleteMember removes a membership row scoped by rule_fp (so removing one rule's
// member never drops another rule's member of the same object, C-21).
func (s *reconcileStore) DeleteMember(ctx context.Context, bindingID domain.AccessBindingID, ruleFP, objectType, objectID string) error {
	return target_members.DeleteTx(ctx, s.tx, string(bindingID), ruleFP, objectType, objectID)
}

// LedgerTuplesForObject reads the recorded emitted tuples for one object of a
// binding from the access_binding_emitted_tuples ledger (the saved tuple-set the
// role.rules eager-revoke replays when a rule's verbs are gone, C-20/C-21).
func (s *reconcileStore) LedgerTuplesForObject(ctx context.Context, bindingID domain.AccessBindingID, object string) ([]domain.MembershipTuple, error) {
	rows, err := s.tx.Query(ctx,
		`SELECT fga_user, relation, object
		   FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND object = $2`,
		string(bindingID), object)
	if err != nil {
		return nil, fmt.Errorf("reconcile: ledger tuples for object %s: %w", object, err)
	}
	defer rows.Close()
	var out []domain.MembershipTuple
	for rows.Next() {
		var t domain.MembershipTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, fmt.Errorf("reconcile: scan ledger tuple: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TuplesStillClaimedByOtherBindings returns the subset of `tuples` still recorded in
// the emitted-tuple ledger of an ACTIVE binding OTHER than excludeBinding. The ledger
// PK is (binding_id, fga_user, relation, object) — per binding — so two bindings of the
// SAME subject that materialized the IDENTICAL FGA tuple on the SAME object hold TWO
// ledger rows for ONE non-refcounted tuple. Before deleting a tuple the
// reconciler subtracts this set so a shared cross-binding tuple is dropped only when the
// LAST owning binding releases it (label-revoke-vpc CHANGE-01). The join to
// access_bindings requires the other binding be ACTIVE — a REVOKED/expired binding does
// not keep a tuple alive. Empty `tuples` → empty result (no query).
func (s *reconcileStore) TuplesStillClaimedByOtherBindings(ctx context.Context, excludeBinding domain.AccessBindingID, tuples []domain.MembershipTuple) (map[domain.MembershipTuple]struct{}, error) {
	out := make(map[domain.MembershipTuple]struct{})
	if len(tuples) == 0 {
		return out, nil
	}
	// Probe each (fga_user, relation, object) triple against the ledger of every OTHER
	// active binding. The set is small (one member's tuple-set), so a per-tuple EXISTS
	// is cheap and keeps the query index-friendly (PK prefix on fga_user/relation/object
	// is not available, but the access_binding_emitted_tuples object index covers it).
	for _, t := range tuples {
		var exists bool
		err := s.tx.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1
			     FROM kacho_iam.access_binding_emitted_tuples et
			     JOIN kacho_iam.access_bindings ab ON ab.id = et.binding_id
			    WHERE et.binding_id <> $1
			      AND et.fga_user = $2
			      AND et.relation = $3
			      AND et.object   = $4
			      AND ab.status = 'ACTIVE'
			 )`,
			string(excludeBinding), t.User, t.Relation, t.Object).Scan(&exists)
		if err != nil {
			return nil, fmt.Errorf("reconcile: still-claimed probe for %s#%s@%s: %w", t.Object, t.Relation, t.User, err)
		}
		if exists {
			out[t] = struct{}{}
		}
	}
	return out, nil
}

// EmitTupleWrite / EmitTupleDelete enqueue per-object FGA tuples on the tx.
func (s *reconcileStore) EmitTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error {
	return fga_outbox.EmitWriteTx(ctx, s.tx, membershipTuplesToClients(tuples))
}

func (s *reconcileStore) EmitTupleDelete(ctx context.Context, tuples []domain.MembershipTuple) error {
	return fga_outbox.EmitDeleteTx(ctx, s.tx, membershipTuplesToClients(tuples))
}

// RecordEmittedTuples co-commits the per-member FGA tuples into the persisted
// emitted-tuple ledger (kacho_iam.access_binding_emitted_tuples — F3/#178) on the
// reconcile writer-tx, alongside the matching EmitTupleWrite (ban #10). The INSERT is
// `ON CONFLICT (binding_id,fga_user,relation,object) DO UPDATE SET source='member'` (the
// DO UPDATE only re-tags a pre-0032 source='binding' row; the object-spaces are disjoint,
// so no real binding↔member collision), so a repeated reconcile of the same ACTIVE member
// — or a forward + async-full overlap — is an idempotent no-op. len==0 is a no-op.
func (s *reconcileStore) RecordEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error {
	users := make([]string, 0, len(tuples))
	rels := make([]string, 0, len(tuples))
	objs := make([]string, 0, len(tuples))
	// Дедуп по ключу конфликта ОБЯЗАТЕЛЕН перед набором: `ON CONFLICT … DO UPDATE` не
	// вправе задеть одну и ту же строку дважды В ОДНОМ стейтменте (Postgres отвергает
	// такой набор целиком). Поштучная вставка этого не требовала, потому что каждая
	// строка ехала своим стейтментом; при переходе на набор дубль внутри одного вызова
	// обязан схлопываться здесь. Исход тот же: повтор был идемпотентен и раньше.
	seen := make(map[[3]string]struct{}, len(tuples))
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("reconcile: record emitted tuple: incomplete (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		k := [3]string{t.User, t.Relation, t.Object}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		users = append(users, t.User)
		rels = append(rels, t.Relation)
		objs = append(objs, t.Object)
	}
	if len(users) == 0 {
		return nil
	}
	if _, err := s.tx.Exec(ctx,
		// source='member': ARM_LABELS per-object tuples owned by the reconciler /
		// RoleMembershipFanout — kept distinct from binding-level rows so a
		// Role.Update binding-level reconcile (ReplaceEmittedTuples) never wipes them.
		// DO UPDATE SET source='member' self-heals any pre-0032 row that defaulted to
		// 'binding' (object-spaces are disjoint, so a real binding↔member collision
		// cannot occur — this only re-tags an existing member row).
		`INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
		 SELECT $1, u, r, o, 'member' FROM unnest($2::text[], $3::text[], $4::text[]) AS t(u, r, o)
		 ON CONFLICT (binding_id, fga_user, relation, object) DO UPDATE SET source = 'member'`,
		string(bindingID), users, rels, objs,
	); err != nil {
		return fmt.Errorf("reconcile: record emitted tuple: %w", err)
	}
	return nil
}

// ForgetEmittedTuples removes exactly the supplied member rows from the ledger on
// the writer-tx (eager-revoke / fell-out / expiry), keeping the ledger lock-step
// with the live FGA tuple set so a later symmetric revoke does not replay a tuple
// that was already revoked. A deleted BINDING's rows are dropped by the FK ON
// DELETE CASCADE (delete.go); this handles the member-level revocations that leave
// the binding row alive. len==0 is a no-op.
func (s *reconcileStore) ForgetEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error {
	for _, t := range tuples {
		if _, err := s.tx.Exec(ctx,
			`DELETE FROM kacho_iam.access_binding_emitted_tuples
			  WHERE binding_id = $1 AND fga_user = $2 AND relation = $3 AND object = $4`,
			string(bindingID), t.User, t.Relation, t.Object,
		); err != nil {
			return fmt.Errorf("reconcile: forget emitted tuple: %w", err)
		}
	}
	return nil
}

// EmitContainmentAudit writes the "rejected: not contained in scope" audit event
// (D1/D8 — not silent). Reuses the durable audit_outbox table.
//
// #2: tenant_account_id is the account-keyed compliance-scoping column, so it MUST
// carry the OWNING ACCOUNT id — never the binding's scope id verbatim. For an
// account-scope the scope id IS the account; for a PROJECT-scope the scope id is a
// `prj…` id, so the owning account is resolved on the tx; cluster / cross-service
// scopes write NULL (mirroring the use-case's auditTenantAccountID convention). The
// full scope_id remains in event_payload for tracing — only the account-keyed column
// changes.
func (s *reconcileStore) EmitContainmentAudit(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string, scope domain.ScopeAnchor) error {
	payload, err := json.Marshal(map[string]string{
		"binding_id":  string(bindingID),
		"object_type": objectType,
		"object_id":   objectID,
		"scope_type":  scope.Type,
		"scope_id":    scope.ID,
		"reason":      "not contained in scope",
	})
	if err != nil {
		return fmt.Errorf("reconcile: marshal containment audit: %w", err)
	}
	tenantAccountID, err := s.scopeTenantAccountID(ctx, scope)
	if err != nil {
		return err
	}
	if _, err := s.tx.Exec(ctx,
		`INSERT INTO kacho_iam.audit_outbox
			(id, event_type, tenant_account_id, event_payload, status, attempts, created_at, next_attempt_at)
		 VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now(), now())`,
		newAuditEventID(), "iam.access_binding.containment_rejected", tenantAccountID, payload,
	); err != nil {
		return fmt.Errorf("reconcile: emit containment audit: %w", err)
	}
	return nil
}

// scopeTenantAccountID resolves the account-keyed tenant_account_id value for a
// containment-audit row from the binding's scope anchor (#2):
//
//   - account scope → scope.ID IS the account.
//   - project scope → resolve the project's owning account_id on the tx.
//   - cluster / cross-service / unknown → NULL (no single owning account).
//
// A project that has vanished from under the binding yields NULL rather than an
// error (the audit must still be emitted — the event_payload already carries the
// scope_id for tracing).
func (s *reconcileStore) scopeTenantAccountID(ctx context.Context, scope domain.ScopeAnchor) (any, error) {
	switch scope.Type {
	case "account":
		return nullableString(scope.ID), nil
	case "project":
		var accountID string
		err := s.tx.QueryRow(ctx,
			`SELECT account_id FROM kacho_iam.projects WHERE id = $1`, scope.ID).Scan(&accountID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil // project gone → no resolvable account; emit with NULL.
			}
			return nil, fmt.Errorf("reconcile: resolve project owning account: %w", err)
		}
		return nullableString(accountID), nil
	default:
		// cluster / cross-service / unknown — no single owning account.
		return nil, nil
	}
}

// RevokeExpiredBinding CAS-transitions an ACTIVE binding to REVOKED on the tx
// (ban #10 — single-statement UPDATE WHERE status='ACTIVE'). ok=false ⇒ 0 rows
// (already revoked / concurrent Delete won). revoked_at is stamped to satisfy the
// access_bindings_revoked_consistency_ck CHECK.
func (s *reconcileStore) RevokeExpiredBinding(ctx context.Context, bindingID domain.AccessBindingID) (bool, error) {
	tag, err := s.tx.Exec(ctx,
		`UPDATE kacho_iam.access_bindings
		    SET status = 'REVOKED', revoked_at = now()
		  WHERE id = $1 AND status = 'ACTIVE'`,
		string(bindingID),
	)
	if err != nil {
		return false, fmt.Errorf("reconcile: cas revoke expired %s: %w", bindingID, err)
	}
	return tag.RowsAffected() == 1, nil
}

// ListExpiredBindingIDs scans ACTIVE bindings whose TTL has elapsed (D9 expiry,
// index (status, expires_at)). Pool-scoped read.
func (a *ReconcileAdapter) ListExpiredBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT id FROM kacho_iam.access_bindings
		  WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		return nil, fmt.Errorf("reconcile: list expired bindings: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan expired binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// membershipTuplesToClients maps the domain tuple to the fga_outbox INSERT shape.
func membershipTuplesToClients(tuples []domain.MembershipTuple) []clients.RelationTuple {
	out := make([]clients.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}

func mirrorRowToDomain(r resource_mirror.MirrorRow) domain.MirrorObject {
	return domain.MirrorObject{
		ObjectType:       r.ObjectType,
		ObjectID:         r.ObjectID,
		ParentProjectID:  r.ParentProjectID,
		ParentAccountIDs: singletonAccount(r.ParentAccountID),
		Labels:           r.Labels,
	}
}

// singletonAccount — вырожденный набор аккаунтов зеркального объекта: у него
// аккаунт ровно один (его разрешает читатель зеркала через иерархию
// проект→аккаунт), а «аккаунта нет» выражается ПУСТЫМ набором, а не
// элементом-пустышкой.
func singletonAccount(accountID string) []string {
	if accountID == "" {
		return nil
	}
	return []string{accountID}
}

// scopeAnchorFor maps a binding's (resource_type, resource_id) onto the
// containment scope-anchor. The binding's resource_type is "project" | "account"
// | "cluster"; the anchor id is the resource_id.
func scopeAnchorFor(b domain.AccessBinding) domain.ScopeAnchor {
	return domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}
}

// ── reconcile_outbox drain surface (pool-scoped; the worker claims then the
//    reconciler consumes inside its own tx) ────────────────────────────────────

// ClaimReconcileEvents reads the next unsent reconcile events (pool-scoped read).
func (a *ReconcileAdapter) ClaimReconcileEvents(ctx context.Context, limit int) ([]reconcile_outbox.Event, error) {
	return reconcile_outbox.ClaimBatch(ctx, a.pool, limit)
}

// MarkReconcileEventSent marks an event drained on its own short tx (called after
// the reconcile pass for that object committed).
func (a *ReconcileAdapter) MarkReconcileEventSent(ctx context.Context, id int64) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: begin mark-sent tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := reconcile_outbox.MarkSentTx(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListSelectorBindingIDs returns the ids of all bindings whose ROLE carries an
// ARM_LABELS selector (the periodic sweep target). RBAC rules-model 2026:
// the legacy per-binding access_binding_selector arm is gone
// — the sweep targets are exactly the role.rules ARM_LABELS bindings. Pool-scoped
// read; the sweep keeps the per-rule materialization defense-in-depth (a lost
// mirror-change event still re-converges).
func (a *ReconcileAdapter) ListSelectorBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT DISTINCT b.id
		   FROM kacho_iam.role_rule_selectors rrs
		   JOIN kacho_iam.access_bindings b ON b.role_id = rrs.role_id
		  WHERE b.status = 'ACTIVE'`)
	if err != nil {
		return nil, fmt.Errorf("reconcile: list selector bindings: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan selector binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// ЗДЕСЬ БЫЛ ПРЯМОЙ ПИСАТЕЛЬ В ЧУЖОЕ ХРАНИЛИЩЕ ОТНОШЕНИЙ — предмета нет.
//
// Реконсайлер применял свой набор кортежей ДВАЖДЫ: строкой намерения в журнал (та
// же транзакция, доставка «хотя бы один раз») и сразу после коммита — напрямую в
// движок, чтобы закрыть окно между коммитом и дренажом. Второй писатель нёс всю
// механику этого окна: упаковку по объектам, разбор конфликта записи, сильное
// чтение уже существующего, раунды с отступом.
//
// Окна нет: прямой факт складывается из строки журнала триггером, в той же
// транзакции. Материализация «после коммита» стала тождеством коммита, и всё, что
// её догоняло, снято вместе с ней.

// scopeTypeVerbs — набор глаголов, объявленный ТИПОМ якоря привязки
// (account/project); для якоря без собственного набора (cluster) — ВСЕ глаголы
// платформы.
//
// Запасной вариант нужен ради ЯРУСА, а не ради `v_*`: ярус выводится из
// развёрнутых глаголов правила, поэтому подстановка `*` на якоре без набора обязана
// по-прежнему давать полный набор — иначе роль-суперпользователь молча понизилась
// бы с администратора до наблюдателя. Отношения `v_*` на таком якоре не эмитятся
// всё равно (кластер обслуживается плоским коротким замыканием, не пообъектной
// материализацией).
//
// ЗДЕСЬ СТОЯЛО ПЕРЕСЕЧЕНИЕ наборов всех типов (`CommonVerbVocabulary`), и это была
// подмена по совпадению: пока наборы типов совпадали, пересечение равнялось «всем
// глаголам». Пересечение объявлено СУЖАЮЩИМСЯ, поэтому сужение набора у ЧУЖОГО
// типа отнимало глагол здесь — а понижение яруса на кластере ровно то, чего этот
// комментарий и обещал не допустить. Наблюдалось при #1189: пересечение стало
// `[get list]`, ярус подстановки — `viewer`. Держит `scope_anchor_tier_test.go`.
// Каталог приходит ПАРАМЕТРОМ, а не спрашивается у литерала (kacho#1816):
// «какие глаголы объявлены» может измениться в РАБОТАЮЩЕМ процессе снятием
// строки, и читатель на литерале продолжил бы считать снятый тип живым до
// следующего перезапуска.
func scopeTypeVerbs(cat *catalog.Facts, scopeType string) []string {
	if set := cat.VerbsOfType(scopeType); len(set) > 0 {
		return set
	}
	return cat.AllVerbVocabulary()
}
