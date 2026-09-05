// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// excluding_from_an_account_is_an_account_right_test.go — гейт на КЛАСС:
// ИСКЛЮЧИТЬ ЧЕЛОВЕКА ИЗ СВОЕГО АККАУНТА — право уровня АККАУНТА, и оно есть
// ровно у того, кто вправе туда пригласить.
//
// # Предмет — вторая строка таблицы областей #1102 (#1127)
//
// Директива владельца (2026-08-23): «тот кто пригласил может только
// удалить/добавить права». Таблица областей развела три вещи:
//
//	имя и почта человека              — его собственное;
//	исключение ИЗ МОЕГО аккаунта      — аккаунта;
//	запрет ЛИЧНОСТИ на платформе      — облака.
//
// #1102 закрыл третью строку (`identity_suspender`), #1131 — снятие самой
// строки. Вторая осталась БЕЗ ДЕЙСТВИЯ вовсе: у членства не было ни состояния
// приостановки, ни RPC снятия, поэтому «исключить человека из моего аккаунта»
// выражалось только снятием выдач. Это НЕ исключение, и разница наблюдаема:
// членство оставалось, человек оставался в списке людей аккаунта, а предел
// приёма продолжал его считать.
//
// # Этот гейт — ЗЕРКАЛО соседних, и утверждает он ОБРАТНОЕ
//
// Соседи (#1086/#1102/#1131/#1133/#1140) требуют ОТСУТСТВИЯ источников уровня
// аккаунта: их предмет — глобальная личность. Здесь предмет ЧЛЕНСТВО, то есть
// участие человека в ОДНОМ аккаунте, и источники уровня аккаунта обязаны БЫТЬ.
// Без этого зеркала перечень запретов читался бы как «аккаунту не оставлено
// ничего», а директива владельца оставляет ему ровно две вещи — права и состав
// участников.
//
// # Круг равен кругу ПРИГЛАШЕНИЯ, и это утверждение с предикатом
//
// Приглашение и исключение — одна пара: тот, кто вправе ввести человека в
// аккаунт, вправе его оттуда вывести. Иначе аккаунт накапливает людей, которых
// не может убрать, — а это и есть сегодняшнее состояние.
//
// Утверждается РАВЕНСТВОМ множеств, а не вхождением, и утверждается ОТДЕЛЬНЫМ
// отношением, а не тем же самым: при одном отношении «пара согласна» —
// тавтология, которую нельзя нарушить, а значит и проверить. Отдельное имя
// делает будущее сужение одной половины КРАСНЫМ, а не молчаливым.
//
// # Отношение НЕ на объекте личности — это отдельное утверждение
//
// Исключение — действие над ЧЛЕНСТВОМ, и его область — аккаунт. Гейт на объекте
// `iam_user` означал бы, что решение принимается «про человека», и немедленно
// вернул бы класс, закрытый #1102: держатель права на строку личности
// распоряжается ею во всех её аккаунтах.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

const (
	// accountExclusionRPC — RPC исключения из аккаунта.
	accountExclusionRPC = "kacho.cloud.iam.v1.UserService/RemoveFromAccount"
	// accountAdmissionRPC — вторая половина пары: приглашение в аккаунт.
	accountAdmissionRPC = "kacho.cloud.iam.v1.UserService/Invite"
)

// exclusionVerdict — то, что предикат ГОВОРИТ о паре «приглашение ↔ исключение».
//
// Отдельным типом, потому что ровно этот предикат прогоняется дважды: гейтом
// ниже — по каноническому дереву и настоящему каталогу, и опытом инъекции — по
// дереву с возвращённым дефектом. Копия предиката в опыте доказывала бы, что
// работает копия.
type exclusionVerdict struct {
	ExclusionType    string                // объект, на котором принимается решение
	SameRelationName bool                  // приглашение и исключение — одно имя отношения
	AccountLevel     int                   // источников НА САМОМ аккаунте
	HasCloud         bool                  // надзор облака среди источников
	CirclesEqual     bool                  // круг исключения равен кругу приглашения
	Exclusion        map[planSource]string // источники исключения
	Admission        map[planSource]string // источники приглашения
}

// inspectExclusionPair — единственный предикат этого класса.
//
// Берёт РАЗОБРАННЫЕ записи каталога, а не имена: опыт инъекции правит и модель,
// и запись каталога (объект решения объявляется каталогом, а не моделью), и оба
// плеча обязаны проходить через ОДИН предикат.
func inspectExclusionPair(t *testing.T, model *authzplan.Model, admission, exclusion catalogGate) exclusionVerdict {
	t.Helper()
	v := exclusionVerdict{
		ExclusionType:    exclusion.objectType,
		SameRelationName: admission.relation == exclusion.relation,
	}
	exPlan, err := model.Compile(exclusion.objectType, exclusion.relation)
	require.NoErrorf(t, err, "компиляция %s.%s", exclusion.objectType, exclusion.relation)
	adPlan, err := model.Compile(admission.objectType, admission.relation)
	require.NoErrorf(t, err, "компиляция %s.%s", admission.objectType, admission.relation)
	v.Exclusion = sourcesOf(t, exPlan)
	v.Admission = sourcesOf(t, adPlan)

	for src := range v.Exclusion {
		// Источник УРОВНЯ АККАУНТА здесь — тот, что лежит на САМОМ объекте
		// решения (объект решения и есть аккаунт), плюс всякая выдача на нём.
		// Признак — вид источника и предок, а не имя: перечень имён промахнулся
		// бы, как только ярус получил бы ещё одно слагаемое.
		if src.ParentType == "" {
			v.AccountLevel++
		}
	}
	_, v.HasCloud = v.Exclusion[cloudSource]
	v.CirclesEqual = sameSourceSet(v.Admission, v.Exclusion)
	return v
}

// sameSourceSet — равенство множеств источников (не вхождение).
func sameSourceSet(a, b map[planSource]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// TestExcludingFromAnAccountIsAnAccountRight — гейт класса.
func TestExcludingFromAnAccountIsAnAccountRight(t *testing.T) {
	model := canonicalModel(t)
	catalog := catalogByFQN(t)

	require.NotEmpty(t, catalog, "каталог прав разобран в ноль записей — предпосылка гейта сломана")

	admission, ok := catalog[accountAdmissionRPC]
	require.Truef(t, ok, "каталог не знает %s — вторая половина пары отсутствует, и равенство "+
		"кругов ниже не с чем сверять", accountAdmissionRPC)
	require.Equalf(t, "account", admission.objectType,
		"%s гейтится не на объекте аккаунта (%s) — предмет пробы сменился",
		accountAdmissionRPC, admission.objectType)

	exclusion, ok := catalog[accountExclusionRPC]
	require.Truef(t, ok,
		"каталог не знает %s: исключения человека из аккаунта НЕ СУЩЕСТВУЕТ как действия.\n"+
			"Директива владельца оставляет распорядителю аккаунта состав участников и права; "+
			"без этого RPC «исключить» выражается только снятием выдач, а членство остаётся — "+
			"человек продолжает числиться в аккаунте и считаться пределом приёма (#1127).",
		accountExclusionRPC)

	v := inspectExclusionPair(t, model, admission, exclusion)

	// ОТРИЦАНИЕ — решение принимается НЕ про строку личности.
	require.NotEqualf(t, "iam_user", v.ExclusionType,
		"%s гейтится на объекте ЛИЧНОСТИ (%s.%s). Исключение — действие над ЧЛЕНСТВОМ, и его "+
			"область — аккаунт; гейт на личности вернул бы класс, закрытый #1102: держатель "+
			"права на глобальную строку распоряжается ею во ВСЕХ её аккаунтах.",
		accountExclusionRPC, exclusion.objectType, exclusion.relation)
	require.Equalf(t, "account", v.ExclusionType,
		"%s гейтится на объекте %s, а обязан — на аккаунте: исключают ИЗ аккаунта, и он же "+
			"является областью решения", accountExclusionRPC, v.ExclusionType)

	// ОТРИЦАНИЕ 2 — имя отдельное. Иначе «пара согласна» тавтологична.
	require.Falsef(t, v.SameRelationName,
		"приглашение и исключение гейтятся ОДНИМ отношением %q. Круги у них обязаны быть "+
			"равны — но равенство, выраженное тождеством, нельзя нарушить, а значит и "+
			"проверить: следующее сужение одной половины пройдёт молча.", exclusion.relation)

	// КОНТРОЛЬ 1 — источники уровня аккаунта ЕСТЬ. Зеркало соседних гейтов.
	require.Positivef(t, v.AccountLevel,
		"%s гейтится отношением %s.%s, у которого нет НИ ОДНОГО источника на самом аккаунте.\n"+
			"Тогда исключение недостижимо распорядителю аккаунта — то есть действие заведено, "+
			"а адресату не досталось.\nИсточники плана: %v",
		accountExclusionRPC, exclusion.objectType, exclusion.relation, sortedKeys(v.Exclusion))

	// КОНТРОЛЬ 2 — надзор облака.
	require.Truef(t, v.HasCloud,
		"%s гейтится отношением %s.%s, у которого НЕТ надзора облака (%+v).\nИсточники плана: %v",
		accountExclusionRPC, exclusion.objectType, exclusion.relation, cloudSource, sortedKeys(v.Exclusion))

	// РАВЕНСТВО ПАРЫ.
	require.Truef(t, v.CirclesEqual,
		"круги приглашения (%s.%s) и исключения (%s.%s) РАЗОШЛИСЬ.\n"+
			"приглашение: %v\nисключение:  %v\n"+
			"Тот, кто вправе ввести человека в аккаунт, обязан быть вправе его оттуда вывести: "+
			"иначе аккаунт копит людей, которых не может убрать, — и это ровно то состояние, "+
			"ради выхода из которого заведено исключение (#1127).",
		admission.objectType, admission.relation, exclusion.objectType, exclusion.relation,
		sortedKeys(v.Admission), sortedKeys(v.Exclusion))

	t.Logf("перепись: записей каталога прочитано %d · приглашение %s.%s (источников %d) · "+
		"исключение %s.%s (источников %d, на самом аккаунте %d)",
		len(catalog), admission.objectType, admission.relation, len(v.Admission),
		exclusion.objectType, exclusion.relation, len(v.Exclusion), v.AccountLevel)
}
