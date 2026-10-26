// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seedgrantceiling.go — ПОТОЛОК выдач посева: закрытый перечень того, что
// посев модуля вправе выдать (kaname#979).
//
// # Что было неверно
//
// Связность выдачи судила, ЧТО названо: роль объявлена этим манифестом, субъект
// заведён этим же посевом, якорь — кластер. ЦЕНЫ выдачи не судил никто. Манифест
// модуля наделял свою служебную запись администрированием всей установки
// (`system_admin`, `admin`, `editor` на кластере) либо ролью чужого модуля — и
// загрузчик принимал документ, потому что ни одно правило связности о цене не
// спрашивало.
//
// # Перечень — ЗАКРЫТЫЙ, а не запрет отдельных имён
//
// Отношение, которое модель заведёт у кластера завтра, по умолчанию посеву НЕ
// дано: перечень разрешённого расширяется решением, а не тем, что запрет забыли
// дописать. Запрет по именам молчал бы ровно на новом отношении.
//
// # Что посеву дано и почему именно это
//
// Отношением на кластере (`grantedRelation`) — только то, что не даёт глагола
// изменения установки:
//
//   - `system_viewer` — чтение каталога установки; его выдают себе живые посевы
//     модулей, которым на пути запроса нужно читать соседей;
//   - `fga_writer` — право писать кортежи отношений через iam; его несёт группа,
//     в которую вступают модули, и это право уровня кластера by construction.
//
// `editor`, `admin`, `system_admin` дают изменение и удаление на кластере — то
// есть администрирование установки, которое не является назначением ни одного
// модуля; `viewer` выдаётся каждому вошедшему системной выдачей и посеву не
// нужен. Вычисляемое `any_admin` выдать напрямую нечем вовсе — это отказ канона.
//
// Ролью (`roleId`) — только роль СВОЕГО модуля, определённая на ярусе якоря.
// Идентификатор роли — `<модуль>.<имя>` (контракт `roleId` опубликованной
// схемы): модуль-владелец назван в самом идентификаторе, и он обязан совпадать с
// модулем манифеста. Идентификатор строки хранилища (`rol…`) владельца не несёт,
// и выдать по нему можно роль любого модуля — поэтому он отвергается тем же
// отказом. Роль, определённая на аккаунте либо проекте, на якоре кластера
// действовала бы на всю установку правом, объявленным для одного объекта.
//
// # Вступления в группы этот судья НЕ судит
//
// Вступление своей личностью в группу другого модуля законно (MOD-MF-24): оно
// не выдача посева, и правила у него свои (`validateJoin`).
package manifest

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	// ErrSeedGrantForeignModule — выдача посева называет роль не своего модуля:
	// чужого, системную либо идентификатором строки, владельца не несущим.
	ErrSeedGrantForeignModule = errors.New("manifest: seed access binding grants a role of another module")
	// ErrSeedGrantBeyondTier — выдача посева выходит за ярус модуля: отношение
	// кластера вне закрытого перечня посева либо роль, определённая ниже якоря.
	ErrSeedGrantBeyondTier = errors.New("manifest: seed access binding grants beyond the module tier")
)

// seedGrantableRelations — ЗАКРЫТЫЙ перечень отношений кластера, которые посев
// вправе выдать. Почему именно эти — шапка файла.
var seedGrantableRelations = []string{"system_viewer", "fga_writer"}

// SeedGrantableRelations — перечень посева копией: вызывающий не расширит приём,
// правя чужой срез.
func SeedGrantableRelations() []string { return slices.Clone(seedGrantableRelations) }

// validateSeedGrantCeiling — одна выдача посева против закрытого перечня.
//
// canonRefused — канон модели прав уже отверг выдачу отношением (отношение не
// объявлено, вычисляемое, получатель не того вида). Тогда перечень не
// спрашивается: выдача уже отвергнута, и второй отказ за одну ошибку отправил
// бы автора чинить не то. Без внесённого канона судит только перечень — и он
// отвергает имя вне себя сам, ничего не зная о модели.
//
// Роль, которой манифест при объявленном разделе `roles` не объявляет, здесь не
// судится по той же причине: её уже отверг отказ связности «роль не объявлена».
func validateSeedGrantCeiling(m *Manifest, doc *yaml.Node, i int, b AccessBinding, roles roleIDs, canonRefused bool) []error {
	if relation := strings.TrimSpace(b.GrantedRelation); relation != "" {
		if canonRefused || slices.Contains(seedGrantableRelations, relation) {
			return nil
		}
		return []error{linkFault{
			kind:  ErrSeedGrantBeyondTier,
			coord: locate(doc, "seed", "accessBindings", i, "grantedRelation"),
			detail: fmt.Sprintf(
				"seed.accessBindings[%d].grantedRelation: отношение %q посев модуля не выдаёт — оно выходит "+
					"за ярус модуля; посеву даны: %s", i, relation, strings.Join(seedGrantableRelations, ", ")),
		}}
	}

	roleID := strings.TrimSpace(b.RoleID)
	if roleID == "" || (roles.declared && !roles.has(roleID)) {
		return nil
	}
	if owner, _, ok := strings.Cut(roleID, "."); !ok || owner != m.Module {
		return []error{linkFault{
			kind:  ErrSeedGrantForeignModule,
			coord: locate(doc, "seed", "accessBindings", i, "roleId"),
			detail: fmt.Sprintf(
				"seed.accessBindings[%d].roleId: роль %q не принадлежит модулю %q манифеста — посев выдаёт "+
					"только роли своего модуля, названные идентификатором `<модуль>.<имя>`; идентификатор "+
					"строки хранилища модуля-владельца не несёт", i, roleID, m.Module),
		}}
	}
	for _, r := range m.Roles {
		if r.ID != roleID || r.Tier == nil || r.Tier.TierType == seedGrantAnchorScopeType {
			continue
		}
		return []error{linkFault{
			kind:  ErrSeedGrantBeyondTier,
			coord: locate(doc, "seed", "accessBindings", i, "roleId"),
			detail: fmt.Sprintf(
				"seed.accessBindings[%d].roleId: роль %q определена на ярусе %q, а выдача посева стоит на "+
					"якоре %q — она действовала бы на всю установку правом, объявленным для одного объекта "+
					"яруса ниже", i, roleID, r.Tier.TierType, seedGrantAnchorScopeType),
		}}
	}
	return nil
}
