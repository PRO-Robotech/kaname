// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// catalog_apply_cost_integration_test.go — СТОИМОСТЬ ПРИМЕНЕНИЯ КАТАЛОГА как
// функция числа арендаторских ролей. Закрывает раздел «ЧЕСТНО: ЧТО НЕ ИЗМЕРЕНО»
// эпика #1027.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭПИК УТВЕРЖДАЛ И ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ
//
// Дословно: «пересчёт проекций всех задетых ролей в одной транзакции равен сумме
// по ролям (типы × глаголы) — на установке с тысячей ролей это сотни тысяч строк
// с блокировками… ровно тот пересчёт вселенной, который мы отвергаем в других
// местах».
//
// Это ПОСЫЛКА, а не факт: она записана до того, как применитель был написан, и
// описывает форму, которой у него могло бы и не быть. Проба спрашивает дерево, а
// не текст эпика, и мерит ДВЕ разные полосы, потому что у них разные производители:
//
//	S0  применение БЕЗ снятия — штатный режим установки и обновления. Переселение
//	    не зовётся вовсе (`apply.go`: `if len(staleResources) > 0 || len(staleVerbs) > 0`),
//	    поэтому гипотеза «стоимость растёт с числом ролей» здесь ОПРОВЕРЖИМА;
//	S1  применение, СНИМАЮЩЕЕ ОДИН ресурс, который называет КАЖДАЯ роль, —
//	    правдоподобное худшее: так выглядит снятие ресурса в релизе модуля;
//	S2  применение, снимающее ПОЧТИ ВЕСЬ модуль (все ресурсы, кроме одного), —
//	    предел сверху: больше проекций одним применением задеть нельзя, и именно
//	    к этой полосе относится «сотни тысяч строк» из текста эпика.
//
// ─────────────────────────────────────────────────────────────────────────────
// НЕСУЩАЯ ВЕЛИЧИНА — СТРОКИ, А ВРЕМЯ РЯДОМ И С НАЗВАННОЙ ПОСАДКОЙ
//
// Та же дисциплина, что у прибора порядков (`pg/scalegrid`): миллисекунды суть
// свойство машины и на другой машине ложны, поэтому вердикт «помещается ли»
// выносится по строкам и по ФОРМЕ КРИВОЙ, а время печатается вместе с посадкой,
// на которой снято, — иначе число сказано неизвестно о чём (`writing.md` §2).
//
// Посадку прибор печатает САМ (версия сервера, ядра, память, режим шифрования):
// выписанная в комментарии, она разошлась бы с машиной, на которой прогон идёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗАМОК — ГЛАВНАЯ ИЗМЕРЯЕМАЯ ВЕЛИЧИНА, А НЕ ВРЕМЯ ОТВЕТА
//
// Замок каталога ГЛОБАЛЬНЫЙ и транзакционный (`pg_advisory_xact_lock`), берётся
// ПЕРВЫМ оператором и отпускается коммитом. Значит длительность применения и есть
// окно, на которое каталог заперт для ЛЮБОГО другого применения во всей установке.
// Вопрос «помещается ли» — про это окно, а не про задержку одного запроса.
//
// Отдельно и честно: пути ЧТЕНИЯ вердикта замок не трогает вовсе — арендатор
// продолжает получать ответы о доступе, пока применение идёт. Блокируются строки
// `role_verb` / `role_rule_ref` ЗАДЕТЫХ ролей, то есть правка именно этих ролей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ПРОГОН ПОКАЗАЛ — 2026-09-03, задача продукта #1959
//
// Посадка обеих сеток одна: PostgreSQL 16.15 (shared_buffers 128MB, work_mem 4MB),
// linux/amd64, 32 ядра, `statement_timeout = 30000` из платформенного пула
// (`pkg/db/pool.go`). Числа — ориентир, а не гейт: их воспроизводит прогон, а не
// эта таблица.
//
//	ролей	посеяно	S0	S1 БЫЛО	S1 СТАЛО	S2 БЫЛО	S2 СТАЛО
//	 1000	 30 000	7.1 мс	 3 358 мс	 453.6 мс	12 631 мс	1 684.0 мс
//	 2000	 60 000	6.9 мс	12 618 мс	 797.0 мс	ПОРОГ 57014	3 104.8 мс
//	 3000	 90 000	7.3 мс	24 054 мс	1 236.0 мс	ПОРОГ 57014	4 897.9 мс
//
// ЧЕТЫРЕ ВЫВОДА, и первый опровергает посылку эпика, а третий — первоначальный
// разбор самой задачи #1959:
//
//  1. S0 ПЛОСКАЯ на трёх порядках роста ролей (7.1 → 7.3 мс). Штатное применение
//     проекций не трогает вовсе, поэтому «стоимость применения равна сумме по
//     ролям» верно ТОЛЬКО для применения, что-то снимающего;
//  2. полосы снятия БЫЛИ сверхлинейны (строк ×2 → времени ×3.76) и СТАЛИ линейны
//     (×1.84 при ×2 ролей, при этом мкс_на_строку 42.1 · 38.8 · 40.8 — константа);
//  3. дорог был НЕ пооперационный триггер ключа, как назвал первоначальный
//     разбор, а ПОВТОР КЛЮЧА в предикате снятия: ключ проекции правила несёт
//     допускающий NULL глагол, сравнение через `IS NOT DISTINCT FROM` не
//     хешируется и не мержится, и планировщик сводил соединение к паре
//     (модуль, ресурс) — сто миллионов пар ради двадцати тысяч снятий.
//     Почему разбор ошибся, названо числом: та же SQL после `ANALYZE` выбирает
//     hash join и укладывается в 824 мс вместо 17 054 мс. Разбор снимали на
//     собранной статистике, применитель на свежей установке встречает первый
//     план. Разбор дефекта ОБЯЗАН называть, на какой статистике снят план;
//  4. ПОРОГ никуда не делся и деться не может — это `statement_timeout`, — но
//     переехал и стал вычислимым. Цена одной строки замерена постоянной от
//     10 000 до 750 000 строк одного оператора (42.1 · 38.8 · 40.8 · 41.5 ·
//     43.7 мкс), поэтому 30-секундный бюджет ОДНОГО оператора исчерпывается около
//     690 000 строк, то есть около 27 000 ролей на модуле этой формы. Верхние две
//     точки замерены отдельным прогоном и здесь НЕ воспроизводятся сеткой: посев
//     30 000 ролей сам не помещается в `statement_timeout`, а снимать его на
//     соединении пула значит вернуть соединение в пул с уже снятым потолком — то
//     есть измерить СКОРОСТЬ, а не стену. Прибор этого не делает намеренно.
//
// ─────────────────────────────────────────────────────────────────────────────
// СЕТКА ЖИВЁТ КОНСТАНТОЙ, ПЕРЕМЕННАЯ РЕШАЕТ ТОЛЬКО «ЗАПУСКАТЬ ЛИ»
//
// Ровно как у прибора порядков: отчёт, снятый на сокращённой сетке, неотличим от
// полного и читается как полный, если сетку задаёт окружение. Поэтому окружение
// выбирает ОДНУ ИЗ ТРЁХ объявленных здесь сеток и никогда не задаёт своей.

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// fullCostGridEnv / stressCostGridEnv — ручки «какую ОБЪЯВЛЕННУЮ сетку гнать», и
// только это. Своей сетки окружение не задаёт: отчёт, снятый на сокращённой
// сетке, неотличим от полного и читается как полный.
const (
	fullCostGridEnv   = "KACHO_CATALOG_APPLY_COST_FULL"
	stressCostGridEnv = "KACHO_CATALOG_APPLY_COST_STRESS"
)

// costModule — синтетический модуль стоимости.
//
// Свой, а не поставляемый: на поставляемом снятие ресурса отвергла бы ссылка
// посеянной СИСТЕМНОЙ роли (`TestModuleCatalogApplierRefusesToStripASystemRole`),
// и прибор мерил бы отказ вместо переселения.
const costModule = "costmod"

// costResources / costVerbs — форма модуля. Числа взяты у САМОГО КРУПНОГО
// поставляемого модуля этого дерева, а не назначены: применитель на нём и будет
// работать. Перепись поставляемого — гейт `modulecatalog.TestManifestRowsReproduceTheSeededCatalog`
// (27 ресурсов, 135 глаголов на шесть модулей), то есть около пяти глаголов на
// ресурс; здесь ресурсов меньше, а глаголов на ресурс столько же.
const (
	costResources = 6
	costVerbs     = 5
)

// costGridSmall / costGridFull / costGridStress — число АРЕНДАТОРСКИХ ролей,
// называющих модуль.
//
// Верхняя точка полной сетки — тысяча, потому что именно её назвал эпик
// («на установке с тысячей ролей»). Мерить надо ту величину, о которой сделано
// утверждение, иначе опровержение относится к другому числу.
// Сетка напряжения идёт ВЫШЕ названной эпиком тысячи, потому что порог
// приемлемости на ней и находится: между 1000 и 10000 время растёт быстрее
// строк, и назвать порог экстраполяцией по двум точкам значило бы выдать
// вычисление за замер.
var (
	costGridSmall  = []int{10, 100}
	costGridFull   = []int{10, 100, 1000}
	costGridStress = []int{1000, 2000, 3000}
)

// costManifest — манифест модуля стоимости из n ресурсов.
func costManifest(n int) *manifest.Manifest {
	m := &manifest.Manifest{APIVersion: "iam/v1", Module: costModule}
	for i := 0; i < n; i++ {
		// `objectType` проставляется, потому что манифест без него негоден:
		// загрузчик, схема и деривация отвергают такой ресурс каждый своим
		// отказом. Фикстура, оставлявшая поле пустым, была снисходительнее
		// продукта (#1816).
		name := fmt.Sprintf("res%02d", i)
		r := manifest.Resource{Name: name, ObjectType: costModule + "_" + name}
		for v := 0; v < costVerbs; v++ {
			r.Verbs = append(r.Verbs, manifest.Verb{Name: fmt.Sprintf("verb%02d", v)})
		}
		m.Resources = append(m.Resources, r)
	}
	return m
}

// costPosture — посадка, на которой снято число. Спрашивается У СЕРВЕРА.
func costPosture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var version, shared, workMem string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT current_setting('server_version'), current_setting('shared_buffers'), current_setting('work_mem')`,
	).Scan(&version, &shared, &workMem))
	return fmt.Sprintf("PostgreSQL %s (shared_buffers %s, work_mem %s) · %s/%s · ядер %d · один процесс, одна транзакция",
		version, shared, workMem, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
}

// seedCostRoles сажает T арендаторских ролей, КАЖДАЯ из которых называет ВСЕ
// ресурсы модуля всеми глаголами: и объявлением правила (`role_rule_ref`), и
// развёрнутой выдачей (`role_verb`).
//
// Обе популяции, а не одна: переселение идёт ДВУМЯ операторами по разным таблицам
// (`catalog_writer.go` `ResettleTenantProjections`), и посеяв одну, прибор измерил
// бы половину и назвал бы её целым.
//
// Возвращает перепись ПО ФАКТУ — запросом к таблицам, а не «сколько собирались
// вставить»: молчаливый недосев выглядит как «величина не выросла»
// (`scalegrid/census.go`, та же норма).
func seedCostRoles(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roles int) (ruleRefs, roleVerbs int64) {
	t.Helper()

	// Один аккаунт на всю сетку: предмет замера — число РОЛЕЙ, и заводить аккаунт
	// на роль значило бы менять две оси сразу.
	//
	// Пользователь и аккаунт ссылаются друг на друга, поэтому кладутся ОДНОЙ
	// транзакцией: ключи объявлены отложенными ради независимости порядка посева
	// (`data-integrity.md`), и вне транзакции отложить их нечем.
	uid := ids.NewID(domain.PrefixUser)
	accID := ids.NewID(domain.PrefixAccount)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		uid, accID, "ext-cost-"+uid, "u-cost-"+uid+"@example.com", "cost seed")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "cost-acc-"+accID[len(accID)-6:], uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	roleIDs := make([]string, 0, roles)
	names := make([]string, 0, roles)
	for i := 0; i < roles; i++ {
		roleIDs = append(roleIDs, ids.NewID(domain.PrefixRole))
		names = append(names, fmt.Sprintf("cost_%06d", i))
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions)
		SELECT r.id, $1, r.name, 'cost grid', '["iam.users.*.read"]'::jsonb
		  FROM unnest($2::text[], $3::text[]) AS r(id, name)`,
		accID, roleIDs, names)
	require.NoError(t, err)

	// Проекции — одним оператором на популяцию: посев в цикле мерил бы стоимость
	// посева, а не применения, и на тысяче ролей занял бы больше самого замера.
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
		SELECT rid, $2, 'res' || to_char(r, 'FM00'), 'verb' || to_char(v, 'FM00')
		  FROM unnest($1::text[]) AS rid,
		       generate_series(0, $3::int - 1) AS r,
		       generate_series(0, $4::int - 1) AS v`,
		roleIDs, costModule, costResources, costVerbs)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
		SELECT rid, $2 || '.res' || to_char(r, 'FM00'), 'verb' || to_char(v, 'FM00')
		  FROM unnest($1::text[]) AS rid,
		       generate_series(0, $3::int - 1) AS r,
		       generate_series(0, $4::int - 1) AS v`,
		roleIDs, costModule, costResources, costVerbs)
	require.NoError(t, err)

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref WHERE module = $1`, costModule).Scan(&ruleRefs))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE object_type LIKE $1`, costModule+".%").Scan(&roleVerbs))

	if ruleRefs == 0 || roleVerbs == 0 {
		t.Fatalf("условие замера не создано: role_rule_ref %d, role_verb %d при %d ролях",
			ruleRefs, roleVerbs, roles)
	}
	return ruleRefs, roleVerbs
}

// costOutcome — исход ОДНОГО применения, и исходов ТРИ, а не два.
//
// Третий — «порог достигнут»: оператор переселения не уложился в
// `statement_timeout`, объявленный платформенным пулом (`pkg/db/pool.go`), и
// сервер снял его `57014`. Для ПРИБОРА, который ищет порог, это не отказ, а
// ИСКОМОЕ: смешав его с красным, прибор объявлял бы поломкой собственную находку
// и был бы снят первым же срабатыванием.
//
// Для ПРОДУКТА это, наоборот, полный отказ операции: транзакция откачена,
// каталог прежний, и повтор даст то же самое — порог не обходится ожиданием.
type costOutcome struct {
	ms        float64
	resettled modulecatalog.Resettled
	// threshold — операция снята сервером по `statement_timeout`.
	threshold bool
	// err — иной отказ; он остаётся красным.
	err error
}

// String — исход одной строкой: число либо причина, по которой числа нет.
func (o costOutcome) String() string {
	switch {
	case o.err != nil:
		return "ОТКАЗ"
	case o.threshold:
		return "ПОРОГ 57014"
	default:
		return fmt.Sprintf("%.1f мс", o.ms)
	}
}

// costRow — одна точка отчёта.
type costRow struct {
	roles       int
	seededRefs  int64
	seededVerbs int64
	steady      costOutcome
	retire      costOutcome
	wipe        costOutcome
	retiredRes  int
	retiredVerb int
}

// resettledRows — переселено строк обеих популяций.
func resettledRows(r modulecatalog.Resettled) int { return r.RuleRefs + r.RoleVerbs }

// timedApply применяет манифест и КЛАССИФИЦИРУЕТ исход, а не только замеряет.
//
// Снятие по `statement_timeout` распознаётся по SQLSTATE `57014`, а не по тексту:
// текст сервера локализуем и меняется между версиями, код — нет.
func timedApply(ctx context.Context, a *modulecatalog.Applier, m *manifest.Manifest) (costOutcome, modulecatalog.Report) {
	t0 := time.Now()
	rep, err := a.Apply(ctx, m)
	out := costOutcome{ms: float64(time.Since(t0).Microseconds()) / 1000, resettled: rep.Resettled}
	if err != nil {
		if code, _ := pgCode(err); code == "57014" {
			out.threshold = true
			return out, rep
		}
		out.err = err
	}
	return out, rep
}

// TestModuleCatalogApplyCostAgainstTenantRoles — СКОЛЬКО СТОИТ ПРИМЕНЕНИЕ и от
// чего эта стоимость зависит.
//
// Проба ничего не утверждает о «приемлемости» окна: приемлемость — суждение, а не
// предикат, и назначать её порогом внутри прибора значило бы прятать решение в
// код. Прибор ПЕЧАТАЕТ величины и форму кривой; порог называет тот, кто читает.
//
// Что проба всё же УТВЕРЖДАЕТ — и это её единственное отрицание: применение БЕЗ
// снятия не трогает ни одной проекции ни при каком числе ролей. Это опровержимо:
// сломай `apply.go` так, чтобы переселение звалось безусловно, — и утверждение
// покраснеет.
func TestModuleCatalogApplyCostAgainstTenantRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("нужна Postgres")
	}

	grid, gridName := costGridSmall, "МАЛАЯ"
	switch {
	case os.Getenv(stressCostGridEnv) != "":
		grid, gridName = costGridStress, "НАПРЯЖЕНИЯ"
	case os.Getenv(fullCostGridEnv) != "":
		grid, gridName = costGridFull, "ПОЛНАЯ"
	}

	rows := make([]costRow, 0, len(grid))
	var posture string

	for _, roles := range grid {
		t.Run(fmt.Sprintf("ролей_%d", roles), func(t *testing.T) {
			ctx, pool := catalogPool(t)
			if posture == "" {
				posture = costPosture(t, ctx, pool)
			}
			applier := applierOver(t, pool)

			// Каталог заводится ДО посева: проекция ссылается на живую строку, и
			// без неё посев отвергнет ключ.
			full := costManifest(costResources)
			rep, err := applier.Apply(ctx, full)
			require.NoError(t, err, "заведение каталога модуля стоимости")
			require.Equal(t, costResources, rep.WrittenResources, "каталог заведён не целиком: %s", rep)

			refs, verbs := seedCostRoles(t, ctx, pool, roles)

			// Точка записывается ДАЖЕ на отказе: измеренное до него — тоже замер,
			// и потеряв его, прибор объявил бы неизвестным то, что уже знает.
			row := costRow{roles: roles, seededRefs: refs, seededVerbs: verbs}
			defer func() { rows = append(rows, row) }()

			// S0 — применение БЕЗ снятия. Оно же проба идемпотентности: тот же
			// манифест второй раз обязан не менять ни строки.
			var steady modulecatalog.Report
			row.steady, steady = timedApply(ctx, applier, full)
			require.NoError(t, row.steady.err)
			require.False(t, row.steady.threshold,
				"штатное применение упёрлось в порог — предмет замера изменился")
			require.False(t, steady.Changed(),
				"повторное применение изменило строки — прибор мерит не тот режим: %s", steady)
			require.Zero(t, resettledRows(steady.Resettled),
				"применение без снятия переселило проекции: %s", steady)

			// S1 — снят ОДИН ресурс, названный КАЖДОЙ ролью.
			var retire modulecatalog.Report
			row.retire, retire = timedApply(ctx, applier, costManifest(costResources-1))
			require.NoError(t, row.retire.err, "снятие ресурса под живыми арендаторскими ролями")
			if row.retire.threshold {
				t.Logf("ПОРОГ на снятии ОДНОГО ресурса при %d ролях: оператор переселения "+
					"снят сервером по statement_timeout, транзакция откачена", roles)
				return
			}
			row.retiredRes, row.retiredVerb = retire.RetiredResources, retire.RetiredVerbs
			require.Equal(t, 1, retire.RetiredResources, "снят не один ресурс: %s", retire)

			// Переселено РОВНО то, что называли роли на снятом ресурсе.
			require.Equal(t, roles*costVerbs, retire.Resettled.RuleRefs,
				"переселено объявлений не по числу ролей: %s", retire)
			require.Equal(t, roles*costVerbs, retire.Resettled.RoleVerbs,
				"переселено выдач не по числу ролей: %s", retire)

			// Переселено, а не отобрано молча.
			var orphans int64
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.role_grant_orphan WHERE object_type = $1`,
				costModule+".res"+fmt.Sprintf("%02d", costResources-1)).Scan(&orphans))
			require.Equal(t, int64(roles*costVerbs*2), orphans,
				"сироты не покрывают обе популяции — право отобрано молча")

			// S2 — предел сверху: снят ВЕСЬ остаток модуля, кроме одного ресурса.
			// Больше проекций одним применением задеть нельзя by construction:
			// применитель трогает только СВОЙ модуль (шапка `apply.go`, п. 1).
			var wipe modulecatalog.Report
			row.wipe, wipe = timedApply(ctx, applier, costManifest(1))
			require.NoError(t, row.wipe.err, "снятие почти всего модуля под живыми ролями")
			if row.wipe.threshold {
				t.Logf("ПОРОГ на снятии МОДУЛЯ при %d ролях: оператор переселения снят "+
					"сервером по statement_timeout, транзакция откачена, каталог прежний", roles)
				return
			}
			require.Equal(t, costResources-2, wipe.RetiredResources, "снят не весь остаток: %s", wipe)
			require.Equal(t, roles*costVerbs*(costResources-2), wipe.Resettled.RoleVerbs,
				"предел сверху посчитан не по всем оставшимся ресурсам: %s", wipe)
		})
	}

	if len(rows) == 0 {
		t.Fatal("сетка пуста — вердикт беспредметен")
	}

	t.Logf("\n=== СТОИМОСТЬ ПРИМЕНЕНИЯ КАТАЛОГА · сетка %s ===\nпосадка: %s\n"+
		"модуль стоимости: ресурсов %d, глаголов на ресурс %d\n",
		gridName, posture, costResources, costVerbs)
	t.Logf("%7s %11s %11s %14s %14s %14s %10s %10s %13s",
		"ролей", "посеяно_ref", "посеяно_vrb", "S0_без_снятия", "S1_один_рес",
		"S2_весь_модуль", "S1_строк", "S2_строк", "мкс_на_строку")
	for _, r := range rows {
		perRow := "—"
		if !r.wipe.threshold && r.wipe.err == nil && resettledRows(r.wipe.resettled) > 0 {
			perRow = fmt.Sprintf("%.1f", r.wipe.ms*1000/float64(resettledRows(r.wipe.resettled)))
		}
		t.Logf("%7d %11d %11d %14s %14s %14s %10d %10d %13s",
			r.roles, r.seededRefs, r.seededVerbs,
			r.steady, r.retire, r.wipe,
			resettledRows(r.retire.resettled), resettledRows(r.wipe.resettled), perRow)
	}

	// Форма кривой печатается ЧИСЛОМ, а не словом: «растёт линейно» без отношения
	// соседних точек есть впечатление, а не замер. Отношение считается только там,
	// где ОБЕ точки — числа: делить на порог нечего.
	ratio := func(cur, prev costOutcome) string {
		if cur.threshold || prev.threshold || cur.err != nil || prev.err != nil || prev.ms == 0 {
			return "—"
		}
		return fmt.Sprintf("×%.2f", cur.ms/prev.ms)
	}
	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		t.Logf("рост ролей ×%.1f → S0 %s · S1 %s · S2 %s",
			float64(cur.roles)/float64(prev.roles),
			ratio(cur.steady, prev.steady), ratio(cur.retire, prev.retire), ratio(cur.wipe, prev.wipe))
	}

	// Окно замка названо прямо: замок берётся ПЕРВЫМ оператором и отпускается
	// коммитом, поэтому длительность применения И ЕСТЬ окно, на которое каталог
	// заперт для любого другого применения во всей установке.
	last := rows[len(rows)-1]
	t.Logf("окно ГЛОБАЛЬНОГО замка каталога на верхней точке сетки (%d ролей): "+
		"без снятия %s · снятие одного ресурса %s · снятие модуля %s",
		last.roles, last.steady, last.retire, last.wipe)
}
