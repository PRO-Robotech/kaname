// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// migrate_backfill.go — RBAC explicit-model migrate-step (part of
// expand→migrate→contract). The singleton single-shot backfill that
// re-materializes the explicit per-object FGA tuples for EVERY active binding
// BEFORE the contract step removes the FGA cascade.
//
// This step does NOT remove the FGA derivation cascade / scope_grant — that is
// the subsequent contract step (it removed the cascade + scope_grant + the dead
// org type). The backfill only ADDS the explicit materialization so no operator
// loses access in the contract window (no-access-loss).
//
// Two pieces:
//
//   BackfillOwnerBindings — the idempotent SQL data-migration body (mirror of
//     migration 0036) exposed so an account created AFTER goose.Up (which the
//     migration could not see) is still covered. Idempotent via the active-grant
//     partial-UNIQUE.
//
//   BackfillRunner.RunOnce — the reconcile-backfill SWEEP. Under a PROCESS-WIDE
//     singleton SESSION advisory lock (pg_advisory_lock — even at N replicas
//     exactly ONE process executes the sweep; the others skip), it lists every ACTIVE binding
//     in bounded CHUNKS (not one monster tx) and reconciles each through the
//     SAME single materialization path (the reconciler). Each binding reconcile
//     opens its OWN writer-tx and takes its OWN per-binding xact-lock, so the
//     materialization is idempotent and commutative with live forward-mat.
//
// Clean Architecture: the runner depends only on the ReconcileEngine surface +
// the narrow BackfillStore port (singleton-lock + chunked binding listing),
// implemented by the pg BackfillAdapter. No pgx here except the raw SQL helper
// BackfillOwnerBindings which is a composition-root data-migration utility.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
)

// ownerRoleIDExpr / the deterministic owner-binding-id expression mirror migration
// 0035 / 0036 so the SQL body here and the migration agree byte-for-byte.
const (
	// backfillOwnerBindingsSQL inserts an owner-binding for every account lacking an
	// ACTIVE owner-role binding (idempotent via NOT EXISTS + the active-grant
	// partial-UNIQUE).
	//
	// no-access-loss on re-grant after revoke: the id is a FRESH
	// NON-deterministic value, NOT the prior deterministic 'acb'||md5('owner-binding:'
	// ||a.id). A revoked owner-binding leaves a TOMBSTONE row carrying that deterministic
	// id (status=REVOKED, revoked_at set); the old `ON CONFLICT (id) DO NOTHING` then
	// silently DROPPED the needed re-grant (the PK collided with the tombstone) → the
	// account was left with NO active owner-binding. Keying off a fresh id makes the
	// re-grant a genuine new ACTIVE row; idempotency rests on the active-grant
	// partial-UNIQUE access_bindings_active_grant_uniq (WHERE revoked_at IS NULL AND
	// narrowed_at IS NULL — условие сужения, kaname#963; предикат ON CONFLICT обязан
	// совпадать с условием индекса, иначе вывод индекса отказывает 42P10) via
	// ON CONFLICT on that partial index — a revoked tombstone is NOT in it, so it never
	// suppresses a re-grant, while a concurrent double-insert of an ACTIVE grant is a
	// clean no-op (not a 23505 error). The id stays acb-prefixed (20 chars) so type
	// routing is unchanged.
	backfillOwnerBindingsSQL = `
INSERT INTO kaname.access_bindings
  (id, subject_type, subject_id, role_id, resource_type, resource_id,
   status, granted_by_user_id, deletion_protection)
SELECT
  'acb' || substr(md5(a.id || '|owner-binding|' || clock_timestamp()::text || random()::text), 1, 17),
  'user',
  a.owner_user_id,
  'rol' || substr(md5('owner'), 1, 17),
  'account',
  a.id,
  'ACTIVE',
  'system',
  true
FROM kaname.accounts a
WHERE NOT EXISTS (
  SELECT 1
    FROM kaname.access_bindings b
   WHERE b.subject_type  = 'user'
     AND b.subject_id    = a.owner_user_id
     AND b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
     AND b.resource_type = 'account'
     AND b.resource_id   = a.id
     AND b.revoked_at IS NULL
)
ON CONFLICT (subject_id, subject_type, role_id, resource_type, resource_id, target_digest)
  WHERE revoked_at IS NULL AND narrowed_at IS NULL
  DO NOTHING`

	// backfillOwnerSubjectsSQL projects the single-subject row for every active
	// owner-binding (parity with migration 0028). Identical to migration 0036
	// statement (2).
	backfillOwnerSubjectsSQL = `
INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
SELECT b.id, b.subject_type, b.subject_id, 0
  FROM kaname.access_bindings b
 WHERE b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
   AND b.resource_type = 'account'
   AND b.revoked_at IS NULL
ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING`
)

// backfillOwnerHierarchyTuplesSQL is a `var`, not a `const`, because its de-dup predicate
// is BUILT BY THE PACKAGE THAT OWNS THE ROW SHAPE (fga_outbox.RelationPredicate) rather
// than written again here. A second rendering of "does this row already carry that
// relation" is exactly the drift that made this backfill miss rows arriving in the set
// form — and it would miss them silently, enqueueing a duplicate intent instead.
var (
	// backfillOwnerHierarchyTuplesSQL emits the owner-binding OBJECT hierarchy
	// parent-pointer FGA tuple (account:<A>#account@iam_access_binding:<id>) for every
	// active owner-binding (no-access-loss). This boot-path is the SOLE home
	// for the hierarchy-pointer INTENT for EXISTING owner-bindings — migration 0037 was
	// reduced to a no-op precisely because a goose data-migration must not enqueue an
	// fga_outbox row (it pollutes every outbox-counting test/tool). The pointer is the
	// binding-lifecycle tuple the reconcile-sweep does NOT materialize; without it the
	// account owner has no viewer/editor path to its own owner-binding object and
	// Get/Delete authz-DENY. Idempotent via the NOT EXISTS payload de-dupe; the
	// journal row folds into a direct fact by trigger, in the same commit. It also covers
	// accounts created AFTER goose.Up, which a migration can never see.
	backfillOwnerHierarchyTuplesSQL = `
INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.write',
  jsonb_build_object(
    'user',     'account:' || b.resource_id,
    'relation', 'account',
    'object',   'iam_access_binding:' || b.id
  ),
  now()
FROM kaname.access_bindings b
WHERE b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
  AND b.resource_type = 'account'
  AND b.revoked_at IS NULL
  AND NOT EXISTS (
    SELECT 1
      FROM kaname.fga_outbox o
     WHERE o.event_type        = 'fga.tuple.write'
       AND o.payload->>'user'     = 'account:' || b.resource_id
       AND o.payload->>'object'   = 'iam_access_binding:' || b.id
       -- Отношение ищется в ОБЕИХ формах строки: одиночной и наборной. Читая только
       -- скалярное поле, этот де-дуп не увидел бы указатель, приехавший членом набора,
       -- и поставил бы вторую строку на уже поставленное. Повтор идемпотентен у
       -- хранилища прав, поэтому это не порча — но это работа, которой не должно быть,
       -- и молчаливое «не нашёл» там, где есть.
       AND ` + fga_outbox.RelationPredicate("o.payload", "'account'") + `
  )`
)

// BackfillOwnerBindings runs the idempotent owner-binding data-backfill on the pool,
// in ONE short tx: (1) the owner-binding row + (2) its projected subject row (the
// migration 0036 body, mirrored here so a post-goose.Up account is covered), and
// (3) the owner-binding OBJECT hierarchy parent-pointer fga_outbox intent
// (no-access-loss) — the latter lives ONLY here, NOT in a migration, so the
// outbox carries no migration side-effect (migration 0037 is a no-op). All three are
// lightweight one-row-per-account inserts — the per-object CONTENT tuples remain the
// reconcile-sweep's chunked concern. Safe to re-run: the active-grant partial-UNIQUE
// + the NOT EXISTS guards make it a no-op once every account has an owner-binding and
// its hierarchy pointer is queued/applied.
//
// Проекции глаголов системных ролей эта функция НЕ КАСАЕТСЯ. Пересчёт вынесен в
// собственную полосу (ReseedSystemRoleVerbs), у неё свои транзакции — по одной на
// роль — и свой вызов в композиционном корне. Прежде он делил транзакцию с
// выдачами: отказ одной пары откатывал выдачи, к проекции отношения не имеющие, и
// пересчёт всех прочих ролей заодно. Звать пересчёт ОТСЮДА нельзя и после
// разведения транзакций: своя полоса у него уже есть, поэтому на старте он шёл бы
// дважды, а его отказ приезжал бы вызывающему обёрнутым в чужую ошибку — то есть
// снова без собственного уровня. Это держит гейт дерева
// `internal/repohygiene/roleverbreseedwiring_test.go`.
func BackfillOwnerBindings(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("backfill owner-bindings: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, backfillOwnerBindingsSQL); err != nil {
		return fmt.Errorf("backfill owner-bindings: insert bindings: %w", err)
	}
	if _, err := tx.Exec(ctx, backfillOwnerSubjectsSQL); err != nil {
		return fmt.Errorf("backfill owner-bindings: insert subjects: %w", err)
	}
	if _, err := tx.Exec(ctx, backfillOwnerHierarchyTuplesSQL); err != nil {
		return fmt.Errorf("backfill owner-bindings: emit hierarchy tuples: %w", err)
	}
	if err := syncAllSystemRoleSelectorsTx(ctx, tx); err != nil {
		return fmt.Errorf("backfill owner-bindings: sync system role selectors: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("backfill owner-bindings: commit: %w", err)
	}
	committed = true
	return nil
}

// SyncAllSystemRoleSelectors projects EVERY materializing system-role's rules[] into
// kaname.role_rule_selectors (forward fast-path JOIN index) in one short tx. It is
// the idempotent self-healing seeder: a system role written by raw SQL (migrations
// 0031/0035) never has its selectors populated by ReplaceRuleSelectors (that runs only
// for custom roles via Role.Create/Update), so WITHOUT this seed the generic system
// roles (`admin`/`edit`/`view`, per-domain `vpc.network.admin`…) have `rules[]` but NO
// selector rows → their bindings are invisible to discovery
// (SelectorBindingsMatchingObject + the sweep's ListSelectorBindingIDs) → a
// project-scoped grantee (`edit`@PROJECT) never materializes v_* on a freshly-created
// object (403 forever on its own resource). This generalizes the former owner-only seed
// (syncAllSystemRoleSelectorsTx) to all system roles. Safe to re-run (idempotent UPSERT +
// stale-fp self-heal). Boot calls it via BackfillOwnerBindings; exposed standalone for
// tests + operational re-seed.
//
// Пересеивает ОДНУ сторону правила — селекторы, отвечающие «подходит ли объект».
// Вторая сторона, проекция глаголов («разрешено ли действие»), — отдельная полоса
// со своими транзакциями (ReseedSystemRoleVerbs) и своим вызовом в композиционном
// корне; на старте обе исполняются всегда. Зовущий эту функцию РУКАМИ получает
// половину правила: роль с одними селекторами адресует объект и не разрешает на
// нём ничего, а вердикт по её выдаче отказывает МОЛЧА, — поэтому вслед за ней
// зовут и ReseedSystemRoleVerbs. Порознь эти стороны уже заводили, и тихая
// пережила громкую на годы; здесь они разведены НАМЕРЕННО и по одной причине:
// у отказа пересчёта обязана быть собственная полоса, а вход у него —
// порт записи, которого у этой функции нет.
func SyncAllSystemRoleSelectors(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("sync system role selectors: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := syncAllSystemRoleSelectorsTx(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("sync system role selectors: commit: %w", err)
	}
	committed = true
	return nil
}

// pgxExecer is the minimal Exec surface (pgx.Tx / pgxpool.Pool both satisfy it).
type pgxExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// pgxQuerierExecer is the Exec+Query surface the all-system-role selector sync needs
// (it reads roles.rules then UPSERTs selectors). pgx.Tx satisfies it.
type pgxQuerierExecer interface {
	pgxExecer
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// systemRoleRules is one system role's authored policy read from the roles table.
type systemRoleRules struct {
	id    string
	rules domain.Rules
}

// syncAllSystemRoleSelectorsTx projects EVERY materializing system-role's rules[] into
// role_rule_selectors (the forward fast-path JOIN index) inside the caller tx. For each
// system role it reads roles.rules, projects the UNIFIED materializing selectors
// (domain.Rules.MaterializingSelectors — arm-aware anchor/names/labels; the wildcard
// `*.*` rule of admin/edit/view/owner expanded to the full materializable type set),
// then, keyed by role_id:
//   - DELETEs stale selector rows whose rule_fp no current rule produces (self-heal when
//     a rules[] edit moved the fingerprint), and
//   - UPSERTs the current selectors ON CONFLICT (role_id, rule_fp).
//
// Idempotent + commutative with the migration seed (identical (role_id, rule_fp) rows).
// It SUBSUMES the former owner-only path: owner is a system role, and its `*.*.*`
// projection reproduces the migration-0038/0039/0043-seeded row byte-for-byte (stable
// fp), so the owner selector is always in currentFPs → never pruned (owner path
// preserved). A selector with empty ObjectTypes (a GLOBAL-only wildcard projection) is
// skipped — role_rule_selectors_types_nonempty forbids a 0-type row.
func syncAllSystemRoleSelectorsTx(ctx context.Context, tx pgxQuerierExecer) error {
	// (1) Read every system role's authored rules. Fully drain the Rows BEFORE issuing
	// any Exec on the same tx (pgx forbids interleaving a live Rows with another query
	// on the same conn).
	rows, err := tx.Query(ctx,
		// Снятая роль ПРОПУСКАЕТСЯ, а не отвергается ключом (kacho#1913).
		//
		// Отзыв есть ПОМЕТКА: `is_system` и `rules` у снятой роли остаются
		// прежними навсегда, поэтому предикат без живости достаёт её всякий раз.
		// Её проекцию отвергает ключ `role_rule_selectors_role_live_fk` — и радиус
		// отказа не одна роль, а ВСЯ эта транзакция: вместе с ней откатывается
		// посев субъектов-владельцев и эмиссия кортежей иерархии для всех
		// системных ролей, а следующий старт даёт то же самое.
		//
		// Пропуск, а не обработка отказа: у снятой роли проекции быть НЕ ДОЛЖНО,
		// и ключ здесь работает как задуман. Неверен был отбор.
		`SELECT id, rules FROM kaname.roles
		  WHERE is_system = true
		    AND live
		    AND rules IS NOT NULL
		    AND jsonb_typeof(rules) = 'array'
		    AND jsonb_array_length(rules) > 0`)
	if err != nil {
		return fmt.Errorf("sync system role selectors: list system roles: %w", err)
	}
	var all []systemRoleRules
	for rows.Next() {
		var (
			id  string
			raw []byte
		)
		if serr := rows.Scan(&id, &raw); serr != nil {
			rows.Close()
			return fmt.Errorf("sync system role selectors: scan role: %w", serr)
		}
		parsed, derr := domain.DecodeRules(raw)
		if derr != nil {
			rows.Close()
			return fmt.Errorf("sync system role selectors: decode rules of %s: %w", id, derr)
		}
		all = append(all, systemRoleRules{id: id, rules: parsed})
	}
	if rerr := rows.Err(); rerr != nil {
		rows.Close()
		return fmt.Errorf("sync system role selectors: iterate system roles: %w", rerr)
	}
	rows.Close()

	// (2) Per role: self-heal stale fps, then UPSERT the current materializing selectors.
	for _, rr := range all {
		selectors := rr.rules.MaterializingSelectors()
		currentFPs := make([]string, 0, len(selectors))
		for _, sel := range selectors {
			if len(sel.ObjectTypes) == 0 {
				continue // GLOBAL-only wildcard projection → nothing to materialize
			}
			currentFPs = append(currentFPs, sel.RuleFP)
		}
		// Self-heal: drop selector rows whose fingerprint no current rule produces (a
		// rules[] edit moved the fp). currentFPs empty → deletes every row (role with no
		// materializing selector). The owner's stable `*.*.*` fp is always present, so
		// its migration-seeded row survives.
		if _, derr := tx.Exec(ctx,
			`DELETE FROM kaname.role_rule_selectors
			  WHERE role_id = $1 AND NOT (rule_fp = ANY($2))`,
			rr.id, currentFPs); derr != nil {
			return fmt.Errorf("sync system role selectors: prune stale selectors for %s: %w", rr.id, derr)
		}
		for _, sel := range selectors {
			if len(sel.ObjectTypes) == 0 {
				continue
			}
			if uerr := upsertRoleSelectorTx(ctx, tx, rr.id, sel); uerr != nil {
				return uerr
			}
		}
	}
	return nil
}

// upsertRoleSelectorTx UPSERTs one materializing selector into role_rule_selectors,
// arm-aware (anchor/names/labels), keyed by (role_id, rule_fp). Mirrors the pg
// roleWriter.ReplaceRuleSelectors row shape (pgx encodes a nil []string as SQL NULL,
// which violates NOT NULL — normalize to '{}'; a nil match_labels marshals to "null" —
// normalize to '{}') so the seed and the custom-role path agree byte-for-byte.
func upsertRoleSelectorTx(ctx context.Context, tx pgxExecer, roleID string, sel domain.RuleSelector) error {
	labelsJSON, err := json.Marshal(sel.MatchLabels)
	if err != nil {
		return fmt.Errorf("sync system role selectors: marshal match_labels for %s: %w", roleID, err)
	}
	if string(labelsJSON) == "null" {
		labelsJSON = []byte("{}")
	}
	resourceNames := sel.ResourceNames
	if resourceNames == nil {
		resourceNames = []string{}
	}
	// Контейнер вложенного правила (kaname#874) — та же форма строки, что у
	// `ReplaceRuleSelectors`: тип и ветвь NULL у правила верхнего уровня,
	// модельное имя типа контейнера выводит страж базы.
	//
	// Глаголы правила (`verbs_by_type`, kaname#878) здесь НЕ вычисляются: у этого
	// досева нет каталожного факта. Строка, чей охват новый (вставка либо смена
	// `object_types`), ложится в состоянии «не вычислено»: карта — верхняя
	// граница (живые глаголы типа, `role_selector_verbs_upper_bound`), роль — в
	// очереди пересчёта. Пустая карта значила бы «правило не даёт ничего», и это
	// была бы ложь. Строка с прежним охватом сохраняет свою карту: отпечаток —
	// хэш всего правила, и при прежнем охвате набор прежний.
	//
	// Точные карты пишет пересчёт проекции глаголов (ReseedSystemRoleVerbs),
	// который на старте идёт следом за этим досевом и обходит каждую системную
	// роль, а то, что он не снял, — пересчёт очереди (DrainSelectorVerbsQueue).
	// Очередь ставится ТЕМ ЖЕ оператором, что строка: прежний охват читается
	// снимком оператора до записи.
	var containerType, containerArm *string
	containerNames, containerLabels := []string{}, []byte("{}")
	if c := sel.Container; c != nil {
		typ, arm := c.Type, selectorArmText(c.Arm)
		containerType, containerArm = &typ, &arm
		if c.ResourceNames != nil {
			containerNames = c.ResourceNames
		}
		if len(c.MatchLabels) > 0 {
			raw, merr := json.Marshal(c.MatchLabels)
			if merr != nil {
				return fmt.Errorf("sync system role selectors: marshal container match_labels for %s: %w", roleID, merr)
			}
			containerLabels = raw
		}
	}
	if _, err := tx.Exec(ctx,
		`WITH prior AS (
		   SELECT object_types FROM kaname.role_rule_selectors WHERE role_id = $1 AND rule_fp = $2
		 ), upsert AS (
		   INSERT INTO kaname.role_rule_selectors
		     (role_id, rule_fp, arm, object_types, resource_names, match_labels,
		      container_type, container_arm, container_resource_names, container_match_labels,
		      verbs_by_type, created_by_subject, created_at, updated_at)
		   VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb,
		           kaname.role_selector_verbs_upper_bound($4), $11, now(), now())
		   ON CONFLICT (role_id, rule_fp) DO UPDATE
		      SET arm                      = EXCLUDED.arm,
		          object_types             = EXCLUDED.object_types,
		          resource_names           = EXCLUDED.resource_names,
		          match_labels             = EXCLUDED.match_labels,
		          container_type           = EXCLUDED.container_type,
		          container_arm            = EXCLUDED.container_arm,
		          container_resource_names = EXCLUDED.container_resource_names,
		          container_match_labels   = EXCLUDED.container_match_labels,
		          created_by_subject       = EXCLUDED.created_by_subject,
		          verbs_by_type            = CASE
		              WHEN kaname.role_rule_selectors.object_types IS DISTINCT FROM EXCLUDED.object_types
		              THEN EXCLUDED.verbs_by_type
		              ELSE kaname.role_rule_selectors.verbs_by_type END,
		          updated_at               = now()
		   RETURNING 1
		 )
		 INSERT INTO kaname.role_selector_verbs_pending (role_id)
		 SELECT $1 FROM upsert
		  WHERE NOT EXISTS (SELECT 1 FROM prior)
		     OR EXISTS (SELECT 1 FROM prior WHERE prior.object_types IS DISTINCT FROM $4::text[])
		 ON CONFLICT (role_id) DO NOTHING`,
		roleID, sel.RuleFP, selectorArmText(sel.Arm), sel.ObjectTypes, resourceNames, labelsJSON,
		containerType, containerArm, containerNames, containerLabels,
		sel.CreatedBySubject,
	); err != nil {
		return fmt.Errorf("sync system role selectors: upsert selector %s/%s: %w", roleID, sel.RuleFP, err)
	}
	return nil
}

// selectorArmText maps a domain Arm to the role_rule_selectors.arm enum text.
func selectorArmText(a domain.Arm) string {
	switch a {
	case domain.ArmNames:
		return "names"
	case domain.ArmLabels:
		return "labels"
	default:
		return "anchor"
	}
}

// BackfillReconcileEngine — the reconcile surface the sweep drives (one binding at
// a time; the reconciler opens its own writer-tx + per-binding xact-lock).
//
// Проход — СВОДЯЩИЙ (`ConvergeBinding`, kaname#1006): набор кортежей члена
// зависит от вычисления (политика роли, каталог), а вычисление меняется
// выкаткой; проход доводит до нового вычисления и неизменных членов. Идёт он
// при старте, после пересчёта проекций ролей, и затем по такту (`RunEvery`,
// binding_converge.go). Обход по таймеру реконсайлера этого не делает — чтение
// реестра каждой выдачи платилось бы каждые полминуты
// (reconcile/emitted_completion.go).
type BackfillReconcileEngine interface {
	ConvergeBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// BackfillStore — the narrow port the runner needs: the process-wide singleton
// try-lock + chunked listing of all active binding ids. Implemented by the pg
// BackfillAdapter.
type BackfillStore interface {
	// TryAcquireSingletonBackfillLock takes a SESSION-scoped pg_advisory_lock on a
	// well-known key with the NON-blocking try variant. ok=false ⇒ another process
	// already holds it ⇒ this RunOnce skips (exactly one executor). The release
	// closure MUST be called to free the session lock after the sweep.
	TryAcquireSingletonBackfillLock(ctx context.Context) (ok bool, release func(context.Context), err error)

	// ListActiveBindingIDsChunk returns up to `limit` ACTIVE binding ids whose id is
	// strictly greater than `afterID` (keyset pagination, ORDER BY id ASC). An empty
	// result ⇒ the sweep is done. Pool-scoped read OUTSIDE the per-binding reconcile
	// tx (each binding reconciles in its own tx).
	ListActiveBindingIDsChunk(ctx context.Context, afterID string, limit int) ([]domain.AccessBindingID, error)
}

// BackfillConfig — runner tunables.
type BackfillConfig struct {
	// ChunkSize bounds the listing batch. Defaults to 500 when ≤0.
	ChunkSize int
	// Logger — optional; slog.Default() when nil.
	Logger *slog.Logger
	// BindingTimeout — срок ОДНОГО вызова сведения выдачи; ≤0 —
	// DefaultBindingConvergeTimeout. Без него зависшее ожидание замка выдачи
	// держало бы замок-одиночку прохода, и проходы всех реплик пропускались бы.
	BindingTimeout time.Duration
	// Observer — исход по каждой выдаче (счётчик); nil — не сообщается.
	Observer BindingConvergeObserver
}

// BackfillResult — перепись одного прохода.
type BackfillResult struct {
	// Executed reports whether THIS RunOnce acquired the singleton lock and ran the
	// sweep (false ⇒ another process was the executor).
	Executed bool
	// BindingsExamined — выдач, до которых проход дошёл.
	BindingsExamined int
	// BindingsReconciled — выдач, сведённых проходом (с первой попытки либо
	// повтором).
	BindingsReconciled int
	// Chunks — number of listing batches consumed (Executed=true only).
	Chunks int
	// BindingsFailed — выдач, не сведённых и после повтора.
	BindingsFailed int
	// FailedBindings — их id, в порядке обхода.
	FailedBindings []domain.AccessBindingID
}

// BackfillRunner — сводящий проход по всем действующим выдачам под
// замком-одиночкой.
type BackfillRunner struct {
	engine         BackfillReconcileEngine
	store          BackfillStore
	chunkSize      int
	bindingTimeout time.Duration
	observer       BindingConvergeObserver
	logger         *slog.Logger
}

// NewBackfillRunner constructs the runner.
func NewBackfillRunner(engine BackfillReconcileEngine, store BackfillStore, cfg BackfillConfig) *BackfillRunner {
	chunk := cfg.ChunkSize
	if chunk <= 0 {
		chunk = 500
	}
	timeout := cfg.BindingTimeout
	if timeout <= 0 {
		timeout = DefaultBindingConvergeTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &BackfillRunner{
		engine: engine, store: store, chunkSize: chunk,
		bindingTimeout: timeout, observer: cfg.Observer, logger: logger,
	}
}

// RunOnce — один сводящий проход по всем действующим выдачам.
//
// Замок-одиночка процесса берётся неблокирующе: занят — проход пропускается
// (Executed=false), его сделает держатель либо следующий такт `RunEvery`.
// Выдачи обходятся страницами по ключу, каждая — в своей пишущей транзакции
// (её открывает сверка) и со своим сроком.
//
// ОТКАЗ ОДНОЙ ВЫДАЧИ НЕ ОСТАНАВЛИВАЕТ ПРОХОД (kaname#1006). У выдачи одному
// субъекту этот проход — единственный путь, которым снимается лишний кортеж
// после смены вычисления. Выход на первой ошибке оставлял все выдачи дальше по
// порядку id с лишним правом до следующего старта, а при детерминированной
// ошибке (рассинхрон покрытия роли, обрыв по сроку на крупной выдаче) —
// навсегда. Поэтому отказавшая выдача запоминается, обход идёт дальше, в конце
// отказавшие повторяются ОДИН раз (транзиентный отказ — взаимная блокировка на
// горячей выдаче — сходится повтором), а оставшиеся называются в ошибке, в
// переписи и в счётчике наблюдателя. Перепись печатается на любом исходе
// исполненного прохода: без неё «ноль сведённых» неотличимо от «ноль
// прочитанных».
//
// Сверка идемпотентна и коммутативна с живой материализацией, поэтому повтор
// прохода по сошедшейся выдаче ничего не пишет.
func (r *BackfillRunner) RunOnce(ctx context.Context) (BackfillResult, error) {
	ok, release, err := r.store.TryAcquireSingletonBackfillLock(ctx)
	if err != nil {
		return BackfillResult{}, fmt.Errorf("backfill: acquire singleton lock: %w", err)
	}
	if !ok {
		r.logger.InfoContext(ctx, "сводящий проход по выдачам пропущен: замок-одиночку держит другой процесс")
		return BackfillResult{Executed: false}, nil
	}
	defer release(ctx)

	res := BackfillResult{Executed: true}
	var failed []bindingFailure
	walkErr := r.walk(ctx, &res, &failed)

	// Повтор отказавших — один раз, в том же проходе, после обхода: транзиентный
	// отказ к этому моменту обычно снят, а детерминированный не задерживает
	// остальные выдачи.
	var still []bindingFailure
	for _, f := range failed {
		if ctx.Err() != nil {
			still = append(still, f)
			continue
		}
		if rerr := r.convergeOne(ctx, f.id); rerr != nil {
			still = append(still, bindingFailure{id: f.id, err: rerr})
			continue
		}
		res.BindingsReconciled++
		r.observe(BindingConvergeOutcomeConverged)
	}
	for _, f := range still {
		res.FailedBindings = append(res.FailedBindings, f.id)
		r.observe(BindingConvergeOutcomeFailed)
	}
	res.BindingsFailed = len(still)

	var errs []error
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	if len(still) > 0 {
		errs = append(errs, fmt.Errorf("backfill: %d of %d bindings not converged, first %s: %w",
			len(still), res.BindingsExamined, still[0].id, still[0].err))
	}
	perr := errors.Join(errs...)
	r.logCensus(ctx, res, perr)
	return res, perr
}

// walk обходит действующие выдачи страницами по ключу. Отказ выдачи
// копится в failed и обход не останавливает; останавливают его только отказ
// чтения страницы (следующую страницу без него не назвать) и отмена прохода.
func (r *BackfillRunner) walk(ctx context.Context, res *BackfillResult, failed *[]bindingFailure) error {
	afterID := ""
	for {
		chunk, lerr := r.store.ListActiveBindingIDsChunk(ctx, afterID, r.chunkSize)
		if lerr != nil {
			return fmt.Errorf("backfill: list active bindings (after %q): %w", afterID, lerr)
		}
		if len(chunk) == 0 {
			return nil
		}
		res.Chunks++
		for _, bID := range chunk {
			if cerr := ctx.Err(); cerr != nil {
				return fmt.Errorf("backfill: sweep cancelled before %s: %w", bID, cerr)
			}
			res.BindingsExamined++
			if rerr := r.convergeOne(ctx, bID); rerr != nil {
				*failed = append(*failed, bindingFailure{id: bID, err: rerr})
			} else {
				res.BindingsReconciled++
				r.observe(BindingConvergeOutcomeConverged)
			}
			afterID = string(bID)
		}
		// Короткая страница — конец перечня, лишний пустой запрос не нужен.
		if len(chunk) < r.chunkSize {
			return nil
		}
	}
}
