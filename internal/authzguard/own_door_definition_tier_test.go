// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_definition_tier_test.go — дверь резолвит КАНОНИЧЕСКИЙ якорь роли, а
// не только легаси-поле, которое называет аннотация.
//
// # Предмет
//
// `RoleService/Create` объявляет `scope_extractor{account, account_id}`, и
// комментарий контракта тут же говорит, что этим объявлением предмет НЕ
// исчерпан: «`scope_extractor` can name only ONE request field, so the catalog
// entry below states the ACCOUNT arm, and the api-gateway resolves the other two
// inputs code-side, FQN-bound to this method» — с порядком старшинства
// `definition_tier` (канон) → `account_id` (легаси) → `project_id` (легаси).
//
// Край это и делает: `ResolveDefinitionTierScope`. Дверь — нет: она выводит
// карту из аннотаций и ничего, кроме названного поля, не читает. Тогда
// канонический запрос — тот, что несёт `definition_tier` и НЕ несёт
// `account_id`, — даёт пустой идентификатор объекта, а пустой отвергается
// `FormatObject` ДО вопроса к модели, то есть и до плоского надзора
// администратора облака. Отказ наступает раньше любого решения.
//
// # Почему это не «ещё одна копия» правила
//
// Источник истины здесь — домен iam: `domain.CustomDefinitionTierToScope`, и
// шапка края прямо объявляет себя ЕГО зеркалом («Mirrors
// domain.CustomDefinitionTierToScope; the gateway cannot import the iam
// domain»). Дверь берёт первоисточник, а не третью копию.
//
// # Что наблюдалось
//
// Сквозные пробы, голова `d1c7a4a89b`, шард iam: `POST /iam/v1/roles` → 403
// `AUTHZ_DENIED`, `action=iam.roles.create`, `scope=account`, тело запроса несёт
// `definitionTier{iam.account, …}` и не несёт `accountId`. Этим объясняются 133
// отказа из 145 (30 прямых + 103 каскадом по непойманным идентификаторам).
//
// # Инъекция в обе стороны
//
// Каждое отрицание идёт с законным близнецом: тот же вызывающий БЕЗ выдачи на
// том же якоре обязан остаться отвергнутым, а легаси-полоса — продолжать
// работать. Без первого «прошёл» зеленело бы на двери, снятой с глагола; без
// второго починка могла бы заменить одну полосу другой.

import (
	"testing"

	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

const (
	roleCreate  = "/kacho.cloud.iam.v1.RoleService/Create"
	homeAccount = "acc00000000000000077"
	homeProject = "prj00000000000000077"
)

// roleByTier — канонический вход: якорь задан, легаси-поля пусты.
func roleByTier(tierType, tierID string) *iamv1.CreateRoleRequest {
	return &iamv1.CreateRoleRequest{
		Name:           "own-door-probe",
		DefinitionTier: &iamv1.DefinitionTier{TierType: tierType, TierId: tierID},
	}
}

// ОТРИЦАНИЕ (RED до починки): якорь уровня аккаунта резолвится, и выданный
// проходит.
func TestOwnDoor_AccountTierAnchorIsResolved(t *testing.T) {
	store := &grantStore{allow: map[string]bool{
		"user:" + ownerUser + "|editor|account:" + homeAccount: true,
	}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		roleByTier("iam.account", homeAccount),
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("роль по каноническому якорю аккаунта отвергнута: err=%v достигнут=%v.\n"+
			"  спрошено у модели: %v\n"+
			"  аннотация называет ЛЕГАСИ-поле `account_id`; канонический запрос его не несёт,\n"+
			"  поэтому объект пуст и отвергается до вопроса к модели — и до надзора",
			err, hit, store.asked)
	}
}

// ОТРИЦАНИЕ ВТОРОЕ: якорь уровня проекта меняет и ВИД объекта, не только его
// идентификатор.
//
// Отдельная проба, потому что полоса другая: аннотация объявляет вид `account`,
// а канонический якорь проекта требует спросить о `project`. Проба, взявшая
// только аккаунтную арму, зеленела бы на починке, которая вид не меняет.
func TestOwnDoor_ProjectTierAnchorChangesTheObjectTypeToo(t *testing.T) {
	store := &grantStore{allow: map[string]bool{
		"user:" + ownerUser + "|editor|project:" + homeProject: true,
	}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		roleByTier("iam.project", homeProject),
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("роль по каноническому якорю проекта отвергнута: err=%v достигнут=%v.\n"+
			"  спрошено у модели: %v", err, hit, store.asked)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: тот же канонический якорь БЕЗ выдачи остаётся отвергнутым.
//
// Молчит и до починки, и после. Без него отрицания выше зеленели бы на двери,
// снятой с глагола создания роли.
func TestOwnDoor_TierAnchorWithoutAGrantStaysRefused(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(strangerUser),
		roleByTier("iam.account", homeAccount),
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("посторонний завёл роль в чужом аккаунте: достигнут=%v err=%v.\n"+
			"  спрошено у модели: %v", hit, err, store.asked)
	}
	// Вопрос обязан быть ЗАДАН — иначе отказ вынесен пустым объектом, то есть
	// тем же дефектом, а проба зеленела бы на нём.
	if len(store.asked) == 0 {
		t.Fatalf("модель не спрошена — отказ вынесен не по объекту, а пустым якорем")
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ ВТОРОЙ: легаси-полоса не отобрана.
//
// Старшинство объявлено контрактом: канон СТАРШЕ легаси, но легаси остаётся
// рабочим. Проба держит вторую половину — починка обязана добавить арму, а не
// заменить одну другой.
func TestOwnDoor_LegacyAccountFieldKeepsWorking(t *testing.T) {
	store := &grantStore{allow: map[string]bool{
		"user:" + ownerUser + "|editor|account:" + homeAccount: true,
	}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		&iamv1.CreateRoleRequest{Name: "own-door-probe", AccountId: homeAccount},
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("легаси-поле перестало работать: err=%v достигнут=%v.\n"+
			"  спрошено у модели: %v", err, hit, store.asked)
	}
}

// СТАРШИНСТВО: канон побеждает легаси, когда заданы оба.
//
// Контракт объявляет порядок («when definition_tier is set it takes
// precedence»), и без этой пробы он остался бы объявлением: дверь, читающая
// легаси первым, прошла бы обе предыдущие пробы.
func TestOwnDoor_TierAnchorOutranksTheLegacyField(t *testing.T) {
	other := "acc00000000000000099"
	store := &grantStore{allow: map[string]bool{
		// Выдано на ЛЕГАСИ-якорь. Канон указывает на другой аккаунт, поэтому
		// дверь, спросившая канон, обязана ОТКАЗАТЬ.
		"user:" + ownerUser + "|editor|account:" + other: true,
	}}
	req := roleByTier("iam.account", homeAccount)
	req.AccountId = other
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		req,
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("дверь спросила про ЛЕГАСИ-якорь при заданном каноне: достигнут=%v err=%v.\n"+
			"  спрошено у модели: %v\n"+
			"  тогда вызывающий выбирает область проверки сам, подставив легаси-поле,\n"+
			"  тогда как обработчик действует по канону", hit, err, store.asked)
	}
}

// ОТРИЦАНИЕ ТРЕТЬЕ: легаси-поле ПРОЕКТА — тоже арма, и аннотация её не несёт.
//
// Контракт называет три входа с порядком старшинства: `definition_tier` (канон)
// → `account_id` (легаси) → `project_id` (легаси). Аннотация несёт ТОЛЬКО
// второй, поэтому третий давал пустой объект ровно так же, как канон, — и с тем
// же исходом: отказ до вопроса к модели.
//
// Найдено доразбором остатка, а не сразу: 8 отказов шарда iam, приписанных было
// «прочему», оказались одним случаем, чей первый шаг заводит роль проекта
// ЛЕГАСИ-полем. Проба существует потому, что починка канона его не покрывает.
func TestOwnDoor_LegacyProjectFieldIsAnArmToo(t *testing.T) {
	store := &grantStore{allow: map[string]bool{
		"user:" + ownerUser + "|editor|project:" + homeProject: true,
	}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		&iamv1.CreateRoleRequest{Name: "own-door-probe", ProjectId: homeProject},
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("роль проекта по легаси-полю отвергнута: err=%v достигнут=%v.\n"+
			"  спрошено у модели: %v", err, hit, store.asked)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: ни одна арма не задана — отказ остаётся.
//
// Контракт объявляет это состояние явно: «neither anchor set → `account:*` →
// no path 403 at the edge (fail-closed)». Проба держит нижнюю границу починки:
// три армы добавлены, четвёртой — «пусто значит можно» — не заведено.
func TestOwnDoor_NoAnchorAtAllStaysRefused(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		&iamv1.CreateRoleRequest{Name: "own-door-probe"},
		&grpc.UnaryServerInfo{FullMethod: roleCreate},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("роль без якоря заведена: достигнут=%v err=%v", hit, err)
	}
}
