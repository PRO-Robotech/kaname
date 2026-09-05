// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_rules_module_scalar_constraint_integration_test.go — ограничение
// `roles_rules_valid` принимает СКАЛЯРНЫЙ модуль правила и отвергает массивную
// форму.
//
// # Что здесь предмет, и почему он пережил свою миграцию
//
// Форму `module: m` вместо `modules: [m, ...]` завела миграция 0033: она
// переписала хранимые правила и заменила функцию `iam_rules_valid`, на которую
// ссылается ограничение. Свод 171 миграции в одну первичную снял ШАГ — переписи
// массивной формы в скалярную больше нет и быть не может: свежая установка
// заводит правила сразу скалярными.
//
// ФУНКЦИЯ И ОГРАНИЧЕНИЕ ОСТАЛИСЬ, и они живые: всякая запись правила проходит
// через них сегодня. Поэтому от прежней пробы шага здесь остаётся ровно её
// живая половина, а четыре утверждения о самом переходе (перепись массива в
// скаляр, оборонительное расщепление многомодульного правила, идемпотентный
// повтор тела, круговой путь вверх-вниз-вверх) сняты вместе с предметом.
//
// Прежде проба поднимала схему РОВНО до версии 33 и сеяла фикстуру той эпохи.
// Лестницы версий больше нет: база поднимается в конечное состояние
// (`setupTestDB`), а строка сеется тем, что арендатор вправе записать сегодня.
//
// # Почему обе стороны
//
// Отрицание («массивная форма отвергнута») зеленело бы на ограничении,
// отвергающем ВСЁ, — в том числе на таблице, куда вообще нельзя вставить строку.
// Поэтому первым идёт положительный контроль: скалярная форма обязана быть
// ПРИНЯТА. Отказ утверждается вместе с ИМЕНЕМ ограничения-производителя: без
// него «отвергнуто» неотличимо от отказа по любой другой причине — по грамматике
// имени, по внешнему ключу, по чему угодно.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// sanitizeName приводит хвост идентификатора к грамматике имени пользовательской
// роли [a-z0-9_] (`roles_custom_name_check`): крокфордов идентификатор несёт
// заглавные.
func sanitizeName(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			// годен как есть
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// TestRoleRulesConstraintAcceptsScalarModuleAndRejectsTheArrayForm — живой
// предмет прежней пробы миграции 0033.
func TestRoleRulesConstraintAcceptsScalarModuleAndRejectsTheArrayForm(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: голый `defer pool.Close()` на удерживаемом соединении
	// висит без срока, пакет умирает по таймауту целиком, и вердикта не остаётся
	// НИ У ОДНОЙ пробы — включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)

	// Предпосылка: ограничение, о котором проба говорит, в схеме ЕСТЬ. Без этой
	// строки снятие ограничения превратило бы отрицания ниже в утверждения о
	// таблице без правил — они бы просто перестали срабатывать.
	var constraints int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint c
		  JOIN pg_class t ON t.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = t.relnamespace
		 WHERE n.nspname = 'kacho_iam' AND t.relname = 'roles'
		   AND c.conname = 'roles_rules_valid'`).Scan(&constraints))
	require.Equalf(t, 1, constraints,
		"ограничения `roles_rules_valid` на kacho_iam.roles нет — отрицания ниже "+
			"утверждали бы о правиле, которого не существует")

	uid := mustSeedUser(t, ctx, pool, "rulescalar")
	accID := ids.NewID(domain.PrefixAccount)
	_, err = pool.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "rulescalar-acc-"+accID[len(accID)-6:], string(uid))
	require.NoError(t, err)

	// `is_system` не перечисляется намеренно: в конечном состоянии это
	// вычисляемая колонка, и присланное значение отвергается (428C9). Роль,
	// заводимая арендатором, системной не бывает — умолчание и есть верный вход.
	insert := func(rules string) error {
		rid := ids.NewID(domain.PrefixRole)
		_, e := pool.Exec(ctx, fmt.Sprintf(`
			INSERT INTO roles (id, account_id, name, description, permissions, rules)
			VALUES ($1, $2, $3, '', '["vpc.subnet.*.get"]'::jsonb, '%s'::jsonb)`, rules),
			rid, accID, "rulescalar_"+sanitizeName(rid[len(rid)-6:]))
		return e
	}

	// (а) ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: скалярный модуль принимается.
	require.NoError(t, insert(`[{"module":"iam","resources":["account"],"verbs":["get"]}]`),
		"скалярный модуль обязан приниматься `roles_rules_valid` — иначе отрицания ниже "+
			"получены даром: их дала бы любая непринимающая таблица")

	// (б) массивная форма отвергается — И ИМЕННО ЭТИМ ограничением.
	err = insert(`[{"modules":["iam"],"resources":["account"],"verbs":["get"]}]`)
	require.Error(t, err, "массивная форма `modules` обязана отвергаться")
	require.ErrorContains(t, err, "roles_rules_valid",
		"отказ пришёл не от `roles_rules_valid` — проба утверждала бы о чужом производителе")

	// (в) правило без модуля отвергается тем же ограничением.
	err = insert(`[{"resources":["account"],"verbs":["get"]}]`)
	require.Error(t, err, "правило без модуля обязано отвергаться")
	require.ErrorContains(t, err, "roles_rules_valid",
		"отказ пришёл не от `roles_rules_valid` — проба утверждала бы о чужом производителе")
}
