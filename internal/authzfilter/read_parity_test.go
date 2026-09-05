// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzfilter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// catalogReadRelation — отношение, которым per-RPC Check шлюза энфорсит ЧТЕНИЕ одиночного
// объекта iam (`<Service>/Get` в сгенерированном каталоге прав → `v_get`).
//
// Выписано здесь отдельной константой НАМЕРЕННО: тест обязан провалиться, если
// предикат страницы разойдётся с чтением, — а не переехать вслед за ним. Репо-широкую
// сверку этого значения с каталогом делает
// `internal/repohygiene/listreadrelationparity_test.go`.
const catalogReadRelation = "v_get"

// gatedType — тип, чьё чтение каталог гейтит `catalogReadRelation` (шесть из семи
// потребителей: account, project, iam_user, iam_group, iam_service_account,
// iam_access_binding). Берём один как представителя класса; репо-широкий гейт
// проверяет их все.
const gatedType = "iam_group"

// Страница не может быть ШИРЕ чтения.
//
// Объект попадает в страницу публичного List по предикату этого пакета, а прочитать
// его одиночным Get можно по `catalogReadRelation`. Пока это РАЗНЫЕ множества, вызывающий
// узнаёт о существовании объекта, которого не вправе читать, — и, поскольку List
// отдаёт то же самое сообщение ресурса, что и Get, получает его СОДЕРЖИМОЕ целиком.
//
// Ярусные (`viewer`/`editor`/`admin`) и глагольные (`v_*`) отношения в модели
// развязаны намеренно (Design B, fga_model.fga): ни одно не выводится из другого.
// Поэтому «держит ярус, не держит глагол» — не гипотеза, а штатное состояние
// субъекта, чью роль отреконсайлили частично либо чей глагольный грант отозвали.
//
// Отрицание идёт В ПАРЕ с положительным: одиночное «не видит» зеленеет сильнее всего
// тогда, когда фильтр не видит НИЧЕГО.
func TestVisibleSet_PageMembershipRequiresReadRelation(t *testing.T) {
	const (
		outsiderID = "grp_tier_only" // держит ярус (и v_list), не держит глагол чтения
		legitID    = "grp_readable"  // держит ровно то, чем гейтится Get
	)

	f := newFakeChecker(
		"viewer|"+gatedType+":"+outsiderID,
		"v_list|"+gatedType+":"+outsiderID,
		catalogReadRelation+"|"+gatedType+":"+legitID,
	)

	got, err := VisibleSet(context.Background(), f, "user:usr_x", gatedType,
		[]string{outsiderID, legitID})
	require.NoError(t, err)

	assert.False(t, got[outsiderID],
		"держатель яруса без глагола чтения не должен попадать в страницу: Get ему этот "+
			"объект не отдаст, а страница вернула бы его содержимое целиком")
	assert.True(t, got[legitID],
		"держатель отношения чтения обязан видеть объект в собственном списке — "+
			"иначе отрицание выше зеленело бы просто оттого, что фильтр не видит ничего")
}

// Единственный тип, у чьего Get отношения нет ВОВСЕ, — iam_role: его запись каталога
// объявлена `<exempt>`, а одиночное чтение кастомной роли энфорсится В СЕРВИСЕ той же
// самой функцией, что фильтрует страницу (`role.resolveVisibleRoleIDs`, общая для
// ListRoles и GetRole). Обе поверхности задают ОДИН вопрос, поэтому разойтись не
// могут по построению, и сужать здесь нечего: `v_list`-грант по селектору роли —
// объявленный контракт «видно в перечне», и Get его чтит ровно так же.
//
// Тест держит это как СВОЙСТВО, а не как комментарий: если предикат роли молча
// сведут к общему, объявленное поведение отвалится здесь.
func TestVisibleSet_RoleKeepsTheUnionItsOwnGetEnforces(t *testing.T) {
	const roleID = "rol_selector_granted"

	f := newFakeChecker("v_list|iam_role:" + roleID)

	got, err := VisibleSet(context.Background(), f, "user:usr_x", "iam_role", []string{roleID})
	require.NoError(t, err)

	assert.True(t, got[roleID],
		"грант по селектору роли (`v_list` без яруса) обязан оставаться видимым: "+
			"GetRole энфорсит ТОТ ЖЕ предикат, расхождения нет и прятать нечего")
}
