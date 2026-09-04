// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// catalog_plan_reader.go — ПРОИЗВОДИТЕЛЬ ПЛАНОВОЙ СТОРОНЫ состояния каталога
// модуля: отпечаток, который затем предъявляется `Apply`, и оценка последствий
// снятия по трём популяциям (задача продукта #1034, объём О6 + О8).
//
// Порт объявлен у потребителя — `apps/kacho/api/module`.`PlanStateSource`;
// адаптер живёт здесь, рядом с писателем, чей отбор он и считает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЛАН НЕ ПИШЕТ — И ЭТО ДЕРЖИТ СЕРВЕР, А НЕ АККУРАТНОСТЬ АВТОРА
//
// Транзакция открывается `AccessMode: pgx.ReadOnly`, то есть `BEGIN TRANSACTION
// READ ONLY`. Всякая запись в ней отвергается сервером (`25006`,
// `read_only_sql_transaction`) — включая ту, которую сюда впишет следующий
// правящий этот файл. Свойство «оценка сделана чтением» перестаёт быть
// обещанием: оно невыразимо иначе by construction.
//
// Оценка через СУХОЙ ПРОГОН ЗАПИСИ С ОТКАТОМ отвергнута, и не по вкусу:
//
//	след           откат оставляет его в счётчиках последовательностей и в
//	               журнале упреждающей записи — план становится наблюдаем там,
//	               где он ничего не менял
//	блокировки     `DELETE`/`UPDATE` берут строчные блокировки арендаторских
//	               ролей на всё время оценки; план — глагол чтения, и держать на
//	               нём чужие строки он не вправе
//	замок          сухой прогон, честный к применению, обязан был бы брать и
//	               замок каталога, то есть сериализовать план с применением
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДНО ЧТЕНИЕ — ЭТО ОДИН СНИМОК, А НЕ ОДИН ОПЕРАТОР
//
// Порт требует, чтобы отпечаток и оценки описывали ОДНО состояние: собранные из
// разных моментов, они описывали бы состояние, которого не было ни в один из них.
// Операторов при этом два — отпечаток и последствия, — и держит их вместе
// `IsoLevel: pgx.RepeatableRead`: оба видят снимок, взятый первым из них.
//
// Свести их в один оператор нельзя, не заведя второй копии отпечатка:
// `ModuleStateExpr` читает имя модуля как `$1`, а общий вход отбора
// (`catalogStaleInputCTE`) читает как `$1`…`$5` пять массивов. Уровень изоляции
// решает это, ничего не удваивая.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОТБОР — ОБЩИЙ С ПРИМЕНЕНИЕМ, А НЕ ВТОРОЙ
//
// Предикаты обеих популяций переселения и приведение третьей проекции взяты
// ДОСЛОВНО из `catalog_consequence_sql.go` — из того же объявления, которое
// вставляет в свои `DELETE`/`UPDATE` писатель. Отпечаток читается
// `ModuleStateExpr` — тем же выражением, которым его сверяет CAS применителя.
// Ни одного из двух здесь не выписано заново: копия разошлась бы молча, и
// разошлась бы именно там, где расхождение не видно.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	moduleapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/module"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
)

// planConsequencesSQL — ОЦЕНКА последствий снятия, три популяции одним
// оператором.
//
// Величины считаются из тех же отношений, из которых писатель их СНИМАЕТ:
// первая и вторая — счётом строк, попадающих под предикат его `DELETE`; третья —
// разбивкой `changed` ровно тем признаком, которым писатель разводит `stripped` и
// `emptied`. Пять чисел, а не три и не сумма: у популяций разные последствия для
// арендатора, и сложив их, план потерял бы именно это различие.
const planConsequencesSQL = `
	WITH ` + catalogStaleInputCTE + `, ` + catalogSelectorPruneCTE + `
	SELECT (SELECT count(*) FROM kacho_iam.role_rule_ref rr
	         WHERE ` + catalogStaleRuleRefPredicate + `),
	       (SELECT count(*) FROM kacho_iam.role_verb rv
	         WHERE ` + catalogStaleRoleVerbPredicate + `),
	       (SELECT count(*) FROM changed WHERE cardinality(alive) > 0),
	       (SELECT count(*) FROM changed WHERE cardinality(alive) = 0),
	       (SELECT coalesce(sum(cardinality(was) - cardinality(alive)), 0) FROM changed)`

// CatalogPlanRepo — производитель плановой стороны над пулом.
//
// Над пулом, а не за `kacho.Reader`: каталог — данные ПЛАТФОРМЫ, и читатель
// каталога (`catalog_repo.go`) по тому же доводу живёт над пулом. Плановая
// сторона следует за ним.
type CatalogPlanRepo struct {
	pool *pgxpool.Pool
}

// NewCatalogPlanRepo собирает производителя плановой стороны поверх пула.
func NewCatalogPlanRepo(pool *pgxpool.Pool) *CatalogPlanRepo {
	return &CatalogPlanRepo{pool: pool}
}

// PlanState читает отпечаток состояния модуля и оценивает последствия снятия
// названных строк — одним снимком и ничего не записывая.
//
// Отказ приходит завёрнутым в предмет («прочитать отпечаток», «оценить
// последствия»), а не сырым: у этой стороны, в отличие от писателя, имени
// нарушенного ограничения не бывает — читающая транзакция ограничений не
// нарушает, — и заворачивать здесь нечего терять.
func (r *CatalogPlanRepo) PlanState(
	ctx context.Context,
	module string,
	staleResources []catalog.ResourceRow,
	staleVerbs []catalog.VerbRow,
) (moduleapp.PlanState, error) {
	var out moduleapp.PlanState

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{
		// Один снимок на оба оператора: см. шапку.
		IsoLevel: pgx.RepeatableRead,
		// Запись отвергает СЕРВЕР, а не наша дисциплина: см. шапку.
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return moduleapp.PlanState{}, fmt.Errorf(
			"открыть читающую транзакцию плана для модуля %s: %w", module, err)
	}
	// Откат, а не коммит: транзакция ничего не произвела, и коммит её был бы
	// утверждением о записи, которой не было.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx, `SELECT `+ModuleStateExpr, module).
		Scan(&out.ExpectedState); err != nil {
		return moduleapp.PlanState{}, fmt.Errorf(
			"прочитать отпечаток состояния каталога модуля %s: %w", module, err)
	}

	resModules, resNames, verbModules, verbResources, verbNames :=
		staleRowArrays(staleResources, staleVerbs)

	if err := tx.QueryRow(ctx, planConsequencesSQL,
		resModules, resNames, verbModules, verbResources, verbNames,
	).Scan(
		&out.Resettled.RuleRefs, &out.Resettled.RoleVerbs,
		&out.Pruned.Rows, &out.Pruned.Dropped, &out.Pruned.Elements,
	); err != nil {
		return moduleapp.PlanState{}, fmt.Errorf(
			"оценить последствия снятия для модуля %s: %w", module, err)
	}

	return out, nil
}

// Проверка соответствия порту — на этапе сборки, а не в рантайме.
var _ moduleapp.PlanStateSource = (*CatalogPlanRepo)(nil)
