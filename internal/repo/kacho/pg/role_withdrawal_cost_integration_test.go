// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_withdrawal_cost_integration_test.go — ПОЛОСА ОТЗЫВА РОЛИ в приборе
// стоимости.
//
// Приёмка `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// §2.7, §10 шаг 7; сценарий IAM-RW-1-23. Задача продукта #1913.
//
// # Зачем СВОЯ полоса, а не строка в соседней сетке
//
// Сосед (`catalog_apply_cost_integration_test.go`) мерит применение КАТАЛОГА и
// его последствия для АРЕНДАТОРСКИХ ролей: там снимается строка каталога, а роли
// остаются. Здесь предмет обратный — снимается САМА РОЛЬ модуля, — и популяция
// другая: системные роли кластерного яруса с владельцем-модулем. Слить их в одну
// сетку значило бы мерить две оси одним числом.
//
// # НЕСУЩАЯ ВЕЛИЧИНА — СТРОКИ, а время рядом и с названной посадкой
//
// Та же дисциплина, что у соседа: миллисекунды суть свойство машины и на другой
// машине ложны, поэтому вердикт «помещается ли» выносится по строкам и по ФОРМЕ
// КРИВОЙ, а время печатается вместе с посадкой, которую прибор спрашивает У
// СЕРВЕРА. Цена одной строки называется ВЕЛИЧИНОЙ, а не словом «приемлемо».
//
// # Что мерится — ВНУТРЕННЯЯ ПЕТЛЯ производственного пути
//
// Отзыв идёт по одной роли за оператор пометки, и это решение §2.7: ролей у
// модуля единицы (замер приёмки: максимум 19), поэтому цикл по ним ценой не
// является. Дорого другое — ПЕРЕСЕЛЕНИЕ проекций, и оно у каждой роли своё.
// Поэтому сетка растит число ролей, а перепись печатает переселённые строки:
// именно они, а не роли, задают стоимость.
//
// Замок здесь ТОТ ЖЕ, что у всякой писательской транзакции iam, и глобального
// замка каталога полоса не берёт: отзыв роли трогает строки СВОИХ ролей и их
// проекций, а не каталог.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// withdrawalCostGrid — сетка полосы. Малая по умолчанию: полоса идёт в общем
// прогоне, и мерить на ней тысячи значило бы платить временем каждого прогона за
// величину, которая нужна раз в релиз.
var withdrawalCostGrid = []int{10, 100}

// withdrawalCostRow — одна точка сетки.
type withdrawalCostRow struct {
	roles      int
	seededRefs int64
	seededVrbs int64
	retired    int
	resettled  int
	ms         float64
}

// TestRoleWithdrawalCostAgainstModuleRoles — цена отзыва как функция числа
// ролей модуля.
//
// Утверждается ТРИ вещи, и ни одна не является временем: снято ровно столько
// ролей, сколько посеяно; переселено ровно столько строк, сколько было проекций;
// ни одна строка не отобрана молча — вся она лежит в ведомости.
func TestRoleWithdrawalCostAgainstModuleRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("нужна Postgres")
	}

	rows := make([]withdrawalCostRow, 0, len(withdrawalCostGrid))
	var posture string

	for _, roles := range withdrawalCostGrid {
		t.Run(fmt.Sprintf("ролей_%d", roles), func(t *testing.T) {
			ctx, pool := catalogPool(t)
			if posture == "" {
				posture = costPosture(t, ctx, pool)
			}
			// Каталог модуля стоимости заводится ТЕМ ЖЕ манифестом, что у соседа:
			// проекции ролей ссылаются на живые строки каталога, и без них посев
			// отвергнет ключ.
			applier := applierOver(t, pool)
			rep, err := applier.Apply(ctx, costManifest(costResources))
			require.NoError(t, err, "заведение каталога модуля стоимости")
			require.Equal(t, costResources, rep.WrittenResources, "каталог заведён не целиком: %s", rep)

			roleIDs, refs, vrbs := seedWithdrawalCostRoles(t, ctx, pool, roles)

			repo := kachopg.New(pool, nil)
			runner := moduleroles.NewRepoTxRunner(repo)

			var (
				retired   int
				resettled int
			)
			start := time.Now()
			require.NoError(t, runner.RunInWriteTx(ctx,
				func(ctx context.Context, w moduleroles.RoleWriter) error {
					for _, id := range roleIDs {
						out, rerr := w.RetireRole(ctx, id, costModule,
							"полоса стоимости отзыва роли", "cost-lane")
						if rerr != nil {
							return rerr
						}
						if out.Marked {
							retired++
						}
						resettled += out.ResettledVerbs + out.ResettledRuleRefs
					}
					return nil
				}), "отзыв ролей модуля")
			ms := float64(time.Since(start).Microseconds()) / 1000

			require.Equal(t, roles, retired, "снято ролей не по числу посеянных")
			require.Equal(t, int(refs+vrbs), resettled,
				"переселено строк не по числу посеянных проекций: часть отобрана молча")

			// Переселено, а не отобрано молча: обе популяции лежат в ведомости.
			var orphans int64
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.role_grant_orphan WHERE cause = 'role_retired'`).
				Scan(&orphans))
			require.Equal(t, int64(resettled), orphans,
				"ведомость не покрывает переселённое — право отобрано молча")

			rows = append(rows, withdrawalCostRow{
				roles: roles, seededRefs: refs, seededVrbs: vrbs,
				retired: retired, resettled: resettled, ms: ms,
			})
		})
	}

	if len(rows) == 0 {
		t.Fatal("сетка пуста — вердикт беспредметен")
	}

	t.Logf("\n=== СТОИМОСТЬ ОТЗЫВА РОЛИ МОДУЛЯ ===\nпосадка: %s\n"+
		"модуль стоимости: ресурсов %d, глаголов на ресурс %d\n", posture, costResources, costVerbs)
	t.Logf("%7s %11s %11s %8s %11s %10s %13s",
		"ролей", "посеяно_ref", "посеяно_vrb", "снято", "переселено", "мс", "мкс_на_строку")
	for _, r := range rows {
		// Цена одной строки — ВЕЛИЧИНА, а не слово: без неё «приемлемо» есть
		// впечатление, и сравнить два прогона нечем.
		perRow := "—"
		if r.resettled > 0 {
			perRow = fmt.Sprintf("%.1f", r.ms*1000/float64(r.resettled))
		}
		t.Logf("%7d %11d %11d %8d %11d %10.1f %13s",
			r.roles, r.seededRefs, r.seededVrbs, r.retired, r.resettled, r.ms, perRow)
	}
}

// seedWithdrawalCostRoles сажает N ролей МОДУЛЯ — системных, кластерного яруса,
// с владельцем, — каждая со всеми проекциями модуля стоимости.
//
// Популяция здесь ДРУГАЯ, чем у соседа: тот сеет арендаторские роли, потому что
// переселение последствий каталога сужено `is_system = false`. Отзыв роли,
// наоборот, касается ровно системных с владельцем-модулем, и посеять
// арендаторские значило бы измерить множество, которого производитель не
// касается вовсе.
//
// Перепись возвращается ПО ФАКТУ — запросом к таблицам, а не «сколько собирались
// вставить»: молчаливый недосев выглядит как «величина не выросла».
func seedWithdrawalCostRoles(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roles int) (
	roleIDs []domain.RoleID, ruleRefs, roleVerbs int64,
) {
	t.Helper()

	names := make([]string, 0, roles)
	rawIDs := make([]string, 0, roles)
	for i := 0; i < roles; i++ {
		// Имя СОСТАВЛЕНО из владельца — этого требует `roles_owner_module_name_prefix`;
		// `id` выводится из имени той же функцией, что в проде, а не чеканится
		// заново: иной вывод дал бы строки, которых производитель не адресует.
		name := domain.RoleName(fmt.Sprintf("%s.cost%06d", costModule, i))
		names = append(names, string(name))
		id := domain.SystemRoleID(name)
		rawIDs = append(rawIDs, string(id))
		roleIDs = append(roleIDs, id)
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, cluster_id, name, description, permissions, rules, owner_module)
		SELECT r.id, $1, r.name, 'cost withdrawal grid', $3::jsonb, '[]'::jsonb, $2
		  FROM unnest($4::text[], $5::text[]) AS r(id, name)`,
		domain.ClusterSingletonID, costModule,
		fmt.Sprintf(`["%s.res00.*.verb00"]`, costModule), rawIDs, names)
	require.NoError(t, err, "посев ролей модуля")

	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
		SELECT rid, $2, 'res' || to_char(r, 'FM00'), 'verb' || to_char(v, 'FM00')
		  FROM unnest($1::text[]) AS rid,
		       generate_series(0, $3::int - 1) AS r,
		       generate_series(0, $4::int - 1) AS v`,
		rawIDs, costModule, costResources, costVerbs)
	require.NoError(t, err, "посев проекции сегментов")

	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
		SELECT rid, $2 || '.res' || to_char(r, 'FM00'), 'verb' || to_char(v, 'FM00')
		  FROM unnest($1::text[]) AS rid,
		       generate_series(0, $3::int - 1) AS r,
		       generate_series(0, $4::int - 1) AS v`,
		rawIDs, costModule, costResources, costVerbs)
	require.NoError(t, err, "посев проекции глаголов")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref WHERE role_id = ANY($1::text[])`,
		rawIDs).Scan(&ruleRefs))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = ANY($1::text[])`,
		rawIDs).Scan(&roleVerbs))

	if ruleRefs == 0 || roleVerbs == 0 {
		t.Fatalf("условие замера не создано: role_rule_ref %d, role_verb %d при %d ролях",
			ruleRefs, roleVerbs, roles)
	}
	return roleIDs, ruleRefs, roleVerbs
}
