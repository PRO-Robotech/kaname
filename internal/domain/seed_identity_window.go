// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "sort"

// seed_identity_window.go — ЕДИНСТВЕННОЕ объявление окна двух написаний
// посевной идентичности (приёмка
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md` §2.4).
//
// # ПОЧЕМУ ОКНО ЖИВЁТ У ЧИТАТЕЛЯ, А НЕ У СТРОКИ
//
// `accounts_name_unique` глобален: двух аккаунтов с двумя написаниями не бывает
// by construction. Значит переходное состояние не в базе, а у того, кто имя
// ЧИТАЕТ: применитель манифестов чужого продукта продолжает присылать прежнее
// написание, пока манифест не переведён, — и обязан попадать в ту же строку.
//
// # ПОЧЕМУ ОБЪЯВЛЕНИЕ ОДНО
//
// Читателей у имени трое — применитель манифестов, разбор прав и опубликованная
// схема. Три копии пары написаний разошлись бы МОЛЧА: каждая по отдельности
// осталась бы синтаксически верной и перестала бы находить строку, а наблюдаемо
// это лишь отказом в доступе у арендатора, которому право не отзывали. Тот же
// довод, по которому объявлена один раз деривация идентификатора
// (`derived_id.go`).
//
// # ПОЧЕМУ ЭТО НЕ ОТСРОЧКА (ban #11)
//
// У каждой записи есть ПРЕДМЕТ и предикат снятия: запись живёт, пока в дереве
// остаётся хоть один читатель прежнего написания. Когда переведён последний
// манифест (П3 приёмки), записи нечего прощать — и это находка, а не тишина:
// перепись посевной идентичности печатает ведомость и её остаток, а гейт
// `TestSeedIdentityCensusMatchesItsAcceptance` судит расхождение.
//
// # ЧЕГО ЗДЕСЬ НЕТ — НАЗВАНО, ЧТОБЫ НЕ ИСКАЛИ
//
//   - имени кластера (`kacho-root` → `root`, класс A). Читателей имени в
//     прод-коде ноль, поэтому окна оно не требует и записи здесь не имеет:
//     запись без читателя была бы послаблением без предмета;
//   - идентификатора клиента OAuth. Он живёт у внешнего провайдера, а не в нашей
//     базе (П1 приёмки), и написание его не меняется вовсе.

// Объявленные написания посевной идентичности (§2.3 приёмки). Имя называет
// УСТАНОВКУ, а не продукт: у стороннего оператора ею не владеет ни платформа, ни
// служба, поэтому различитель в имени лгал бы в обе стороны.
//
// Названы здесь, рядом с окном, а не у каждого читателя: иначе объявлений стало
// бы столько же, сколько читателей, и разошлись бы они молча.
const (
	// SystemAccountName — имя системного аккаунта, в котором живут служебные
	// записи модулей.
	SystemAccountName = "system"
	// SystemAdminRoleName — имя встроенной роли администратора установки.
	SystemAdminRoleName = "system.admin"
	// SystemViewerRoleName — имя встроенной роли пола каталога.
	SystemViewerRoleName = "system.viewer"
	// BootstrapAdminSAName — имя служебной записи, которой чеканят первый
	// неинтерактивный токен.
	BootstrapAdminSAName = "bootstrap-admin"
)

// SeedIdentityRename — одно переименование посевной идентичности: как её звали в
// применённом своде и как зовут по объявленному решению.
type SeedIdentityRename struct {
	// Previous — написание применённого свода. Его продолжают присылать
	// непереведённые манифесты.
	Previous string
	// Declared — написание, объявленное §2.3 приёмки.
	Declared string
	// Subject — ЧИТАТЕЛЬ, ради которого запись существует. Без него запись
	// неотличима от послабления «на всякий случай».
	Subject string
}

// seedIdentityWindow — окно целиком. Порядок объявления несущий только для
// печати: сверка идёт по написанию.
var seedIdentityWindow = []SeedIdentityRename{
	{
		Previous: "kacho-system",
		Declared: SystemAccountName,
		Subject:  "применитель манифестов: `seed.serviceAccounts[].account`, `seed.groups[].account`, `seed.joins[].serviceAccount.account`",
	},
	{
		Previous: "kacho-system.admin",
		Declared: SystemAdminRoleName,
		Subject:  "разбор прав: `PermissionRegistry.PermissionsForRole`",
	},
	{
		Previous: "kacho-system.viewer",
		Declared: SystemViewerRoleName,
		Subject:  "разбор прав: `PermissionRegistry.PermissionsForRole`",
	},
	{
		Previous: "kacho-bootstrap-admin",
		Declared: BootstrapAdminSAName,
		Subject:  "применитель манифестов: резолв служебной записи по паре (аккаунт, имя)",
	},
}

// SeedIdentityWindow возвращает окно целиком. Копия — чтобы вызывающий не мог
// расширить приём, правя чужой срез.
func SeedIdentityWindow() []SeedIdentityRename {
	out := make([]SeedIdentityRename, len(seedIdentityWindow))
	copy(out, seedIdentityWindow)
	return out
}

// SeedIdentitySpellings — ВСЕ написания, которыми сегодня адресуется тот же
// объект: само присланное имя плюс его пара по окну, если она есть.
//
// Отношение симметрично: присланное прежнее написание резолвится в объявленное и
// наоборот. Асимметричное окно приняло бы манифест чужого продукта и отвергло
// свой собственный, переведённый, — а перевод идёт своим порядком (П3).
//
// Имя вне окна возвращается ОДНИМ элементом, а не пустым срезом: окно расширяет
// приём ровно на объявленные пары и ничего не решает про остальные имена.
func SeedIdentitySpellings(name string) []string {
	out := []string{name}
	for _, r := range seedIdentityWindow {
		switch name {
		case r.Previous:
			out = append(out, r.Declared)
		case r.Declared:
			out = append(out, r.Previous)
		}
	}
	sort.Strings(out)
	return dedupeSorted(out)
}

// dedupeSorted снимает повторы из отсортированного среза. Повтор возникает, если
// окно однажды объявит запись, где прежнее написание равно объявленному, —
// такая запись беспредметна, и молча раздваивать её в запросе нельзя.
func dedupeSorted(in []string) []string {
	out := in[:0:0]
	for i, s := range in {
		if i > 0 && s == in[i-1] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// SeedIdentityDeclared приводит написание к ОБЪЯВЛЕННОМУ: имя из окна отдаётся
// своей парой, имя вне окна — собой.
//
// Нужен там, где имя есть КЛЮЧ ДИСПЕТЧЕРИЗАЦИИ, а не значение запроса: разбор
// ветвится по одному написанию, и приводить к нему обязан один помощник, а не
// каждая ветвь по-своему.
func SeedIdentityDeclared(name string) string {
	for _, r := range seedIdentityWindow {
		if name == r.Previous {
			return r.Declared
		}
	}
	return name
}
