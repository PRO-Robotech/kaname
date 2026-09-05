// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// authored_verb_dictionary_integration_test.go — АВТОРСКИЙ словарь глаголов
// отделён от ПООБЪЕКТНОГО, и `create` живёт в первом (задача продукта #1863).
//
// # Что здесь утверждается — ОБЕ половины предиката снятия, а не одна
//
// Роль с `verbs: ["create", "list"]` на `storage.volumes` создаётся успешно И не
// даёт пообъектного отношения `v_create` ни на одном объекте. Утверждать первую
// половину без второй значило бы зеленеть на дереве, где `create` вернули в
// пообъектный набор, — а это возврат 41 087 кортежей, снятых осознанно
// (`services/iam/docs/engineering/architecture/verb-create-withdrawal.md`).
//
// # Почему словари РАЗНЫЕ — предмет задачи одной фразой
//
// `catalog_verb` посеян из `authzmap.typeVerbRelations`, то есть из набора
// ПООБЪЕКТНЫХ отношений типа. Ключ `role_rule_ref_verb_fk` судил по нему
// АВТОРСКИЙ глагол правила роли — два разных множества, и различаются они на
// `create`: у него пообъектного референта нет by construction, потому что в
// момент решения объекта ещё не существует, и вопрос задают родителю (ярус
// записи). Отсюда признак строки — `per_object`, и ключ ссылается на живые
// строки независимо от него.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// TestAuthoredCreateIsAcceptedAndProducesNoPerObjectRelation — предикат снятия
// задачи #1863 целиком.
//
// Ресурс — `storage.volumes`, и он выбран не наугад: ровно эта пара стоит в
// посеве матрицы прав (`tests/authz-fixtures/prodseed_matrix.py`,
// предъявитель разреза `AUTHZ-VOL-VERB-CUT-NOT-TIER`), и ровно на ней посев
// падал отказом `verbs: create is not a live verb of resource volumes`.
func TestAuthoredCreateIsAcceptedAndProducesNoPerObjectRelation(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	mods, res, verbs := liveCatalogCounts(t, ctx, pool)
	t.Logf("осмотрено живых строк каталога: модулей %d, ресурсов %d, пар %d", mods, res, verbs)
	require.NotZero(t, res, "каталог пуст — обе половины пробы были бы вакуумны")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Пообъектный глагол того же ресурса проходит —
	// иначе утверждение ниже зеленело бы на схеме, где не проходит ничто.
	control := catalogRole(t, ctx, pool, "avdcontrol")
	require.NoError(t, writeRuleRefs(t, ctx, repo, control,
		[]domain.RoleRuleRef{{Module: "storage", Resource: "volumes", Verb: "list"}}),
		"пообъектный глагол ресурса обязан проходить")

	// ПРЕДМЕТ. Документированный пример продукта: `create` рядом с чтением.
	role := catalogRole(t, ctx, pool, "avd")
	require.NoError(t, writeRuleRefs(t, ctx, repo, role,
		[]domain.RoleRuleRef{
			{Module: "storage", Resource: "volumes", Verb: "create"},
			{Module: "storage", Resource: "volumes", Verb: "list"},
		}),
		"`create` — авторский глагол платформы: он назван закрытым набором классов "+
			"действия и показан примером роли в клиентской документации; ключ обязан "+
			"судить его по АВТОРСКОМУ словарю, а не по набору пообъектных отношений")

	var refs int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref WHERE role_id = $1`,
		string(role)).Scan(&refs))
	require.Equal(t, 2, refs, "оба объявленных сегмента обязаны лечь строками проекции")

	// ВТОРАЯ ПОЛОВИНА ПРЕДИКАТА: пообъектного отношения `create` не даёт.
	//
	// Спрашивается тот же читатель, которым каталожный факт наполняется на
	// пути запроса, — второй запрос об одном предмете разошёлся бы с первым
	// молча.
	rows, err := kachopg.NewCatalogRepo(pool).ReadLiveCatalog(ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(rows)
	require.NoError(t, err)

	fgaType, ok := authzmap.ObjectType("storage", "volumes")
	require.True(t, ok, "переходник обязан знать пару — иначе проба ниже вакуумна")

	typeVerbs := facts.VerbsOfType(fgaType)
	require.NotEmpty(t, typeVerbs, "набор типа пуст — утверждение об отсутствии было бы вакуумным")
	require.NotContains(t, typeVerbs, "create",
		"`create` обязан остаться ВНЕ пообъектного набора типа: строка в наборе немедленно "+
			"вернула бы материализацию `v_create`, снятую осознанно")

	granted := facts.GrantedVerbs(fgaType, []string{"create", "list"}, typeVerbs)
	require.NotContains(t, granted, "create",
		"правило с `create` не даёт пообъектного кортежа — создание авторизуется ярусом "+
			"записи на родителе")
	require.Contains(t, granted, "list",
		"положительный контроль к предыдущему: пообъектный глагол правила даётся")
}
