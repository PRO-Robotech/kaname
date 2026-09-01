// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed_test

// system_role_verbs_integration_test.go — у системной роли обязаны быть ОБЕ
// стороны её правила, а не одна.
//
// # Предмет
//
// Правило роли читают с двух сторон: селекторы отвечают «подходит ли объект»,
// проекция глаголов — «разрешено ли действие». Обе стороны пишет `Role.Create` /
// `Role.Update`, то есть путь ПОЛЬЗОВАТЕЛЬСКОЙ роли. Системная роль заводится
// сырым SQL миграции и этим путём не проходит НИКОГДА.
//
// Для селекторов это уже было замечено и закрыто досевом на старте
// (`SyncAllSystemRoleSelectors`). Для проекции глаголов — нет, и тихий близнец
// пережил громкий: выдача системной роли адресует объект, но не разрешает на нём
// ни одного действия, поэтому вердикт по выдаче — отказ. Отказ этот молчаливый:
// пустое соединение не отличается от честного «права нет».
//
// # Почему утверждение выводится из КАТАЛОГА, а не из перечня ролей
//
// Именной перечень пережил бы свой предмет: роли заводятся и снимаются
// миграциями. Утверждается СВОЙСТВО — селектор, адресующий тип с объявленными
// глаголами, обязан иметь пару в проекции, — и оно остаётся верным для ролей,
// которых сегодня нет.
//
// Предпосылка утверждения при этом проверяется: перепись печатает, сколько
// селекторов осмотрено и сколько из них тип-глагольные. «Ноль расхождений» на
// пустом наборе не значит ничего.

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

// Здесь стоял ПОИМЁННЫЙ СЧЁТНЫЙ ДОЛГ `unresolvableSelectorTypes = 14` —
// селекторы системных ролей, чей тип не резолвился каталогом, потому что
// правила называли ресурс в змеином написании (`iam.service_account`), а
// каталог несёт верблюжье (`iam.serviceAccount`).
//
// Долг закрыт миграцией 0101 (kacho#513): имена приведены к словарю каталога,
// нерезолвящихся селекторов ноль. Запись снята вместе со своим предметом —
// закрепление, которому больше нечего закреплять, пережило бы то, что им
// обозначалось, и следующий такой селектор въехал бы в дерево незамеченным под
// его прикрытием.
//
// Свойство теперь утверждается ПРЯМО: нерезолвящихся селекторов нет ни одного.
// Расти долгу по-прежнему нельзя молча — любой новый селектор вне каталога
// роняет пробу и называет себя поимённо.

// IAM-RV-1-01 — системная роль получает проекцию на старте (характеризующий
// замок приёмки `role-verb-projection-sole-writer.md`, §5.0: требовать от него
// красноты запрещено — поведение дерево уже даёт, и оно обязано ПЕРЕЖИТЬ снятие
// второй реализации записи).
func TestSystemRoleVerbProjectionIsSeededAlongsideItsSelectors(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	require.NoError(t, bootSeedLanes(ctx, pool))

	rows, err := pool.Query(ctx,
		`SELECT r.id, r.name, s.object_types FROM kacho_iam.role_rule_selectors s
		   JOIN kacho_iam.roles r ON r.id = s.role_id
		  WHERE r.is_system
		  ORDER BY r.id`)
	require.NoError(t, err)
	type want struct{ roleID, roleName, dotted string }
	var (
		selectors   int
		verbBearing []want
		unresolved  []string
	)
	for rows.Next() {
		var roleID, roleName string
		var types []string
		require.NoError(t, rows.Scan(&roleID, &roleName, &types))
		for _, dotted := range types {
			selectors++
			fgaType, ok := authzmap.FGAObjectType(dotted)
			if !ok {
				unresolved = append(unresolved, fmt.Sprintf("%s→%s", roleName, dotted))
				continue
			}
			if !authzmap.TypeHasVerbRelations(fgaType) {
				continue
			}
			verbBearing = append(verbBearing, want{roleID, roleName, dotted})
		}
	}
	require.NoError(t, rows.Err())
	rows.Close()

	sort.Strings(unresolved)
	t.Logf("осмотрено селекторов системных ролей %d; тип-глагольных пар %d; "+
		"нерезолвящихся типов %d", selectors, len(verbBearing), len(unresolved))
	require.Positivef(t, len(verbBearing),
		"ни один селектор системной роли не адресует тип с глаголами — утверждение ниже "+
			"было бы вакуумным (осмотрено селекторов %d)", selectors)

	// Селектор, чей тип каталогом не резолвится, инертен ЦЕЛИКОМ: по нему не
	// находит объекта ни материализатор кортежей, ни проекция глаголов, — и роль,
	// собранная только из таких селекторов, не даёт вызывающему ничего. Отказ при
	// этом молчит: пустое соединение неотличимо от честного «права нет».
	require.Emptyf(t, unresolved,
		"селектор системной роли адресует тип вне каталога: %v — такой селектор инертен "+
			"целиком (ни кортежей, ни глаголов), а выдача роли выглядит сделанной и не даёт "+
			"ничего (kacho#513)", unresolved)

	// Свойство: тип с глаголами обязан иметь пару в проекции.
	var missing []string
	for _, w := range verbBearing {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1 AND object_type = $2`,
			w.roleID, w.dotted).Scan(&n))
		if n == 0 {
			missing = append(missing, fmt.Sprintf("%s→%s", w.roleName, w.dotted))
		}
	}
	sort.Strings(missing)
	require.Emptyf(t, missing,
		"системная роль адресует тип с глаголами, но не разрешает на нём ни одного "+
			"действия: %v — вердикт по её выдаче отказывает молча", missing)
}

// ЗАКОННЫЙ БЛИЗНЕЦ: роль БЕЗ материализующих правил глаголов не получает.
//
// Легаси-роль адресует область целиком уровневым отношением, а не пообъектным
// глаголом, и досев, раздающий глаголы и ей, расширил бы доступ. Без этого
// близнеца проба выше зеленела бы на досеве «выдать всем всё».
// IAM-RV-1-10 — системная роль без материализующих правил получает ПУСТУЮ
// проекцию, а не отказ (характеризующий замок той же приёмки).
func TestSystemRoleWithoutMaterializingRulesGetsNoVerbs(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Роль системная (cluster_id непуст ⇒ is_system вычисляется), правил нет.
	// Разрешение — четырёхсегментное, как требует грамматика схемы.
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ('rol-no-rules', 'test.no.rules', '["iam.role.*.get"]'::jsonb, '[]'::jsonb,
		         'cluster_kacho_root')`)
	require.NoError(t, err)

	require.NoError(t, bootSeedLanes(ctx, pool))

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = 'rol-no-rules'`).Scan(&n))
	require.Zerof(t, n, "роль без материализующих правил получила %d глаголов", n)
}
