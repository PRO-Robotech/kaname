// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_removal_expires_invite_test.go — ГЕЙТ MAIL-46 по не-тестовому
// дереву службы.
//
// Норма, предмет обеих величин переписи и граница разбора — в шапке
// `membership_removal_expires_invite.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// membership_removal_expires_invite_injection_test.go.
package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestMAIL46MembershipRemovalDevaluesTheUnredeemedInvite — сам гейт.
//
// Что делать, если он сработал, — исходов два, третьего нет: добавить в тот же
// оператор плечо, обесценивающее невыкупленное приглашение, ЛИБО доказать, что
// этот глагол участия не снимает, и тогда чинить надо его SQL, а не гейт.
// Приписать имя функции в перечень прощённых исходом не является: перечня
// прощённых у разбора нет и заводить его нельзя — каждая такая запись есть
// место, куда предъявителя, пережившего снятие участия, вносят незамеченным.
func TestMAIL46MembershipRemovalDevaluesTheUnredeemedInvite(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	sites, census, err := check.ScanMembershipRemovals(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева не состоялся: %v", err)
	}
	t.Log(census.String())

	// ПРЕДПОСЫЛКИ. Пустой обход молчит так же, как исправное дерево.
	if census.Read == 0 || census.Funcs == 0 {
		t.Fatalf("прочитано %d файлов, осмотрено %d функций — обход пуст, вердикт беспредметен",
			census.Read, census.Funcs)
	}
	if census.Literals == 0 {
		t.Fatalf("осмотрено ноль строковых литералов при %d функциях — разбирается не то дерево",
			census.Funcs)
	}
	// Предмет обязан существовать: глагол, снимающий участие, в дереве ЕСТЬ.
	// Ноль здесь означал бы, что разбор перестал его узнавать, — и тогда
	// молчание гейта значит «не искали», а не «нет».
	if census.Removing == 0 {
		t.Fatalf("глаголов, снимающих строку участия, не найдено ни одного при %d "+
			"осмотренных функциях — предикат перестал их узнавать; это отказ, а не тишина",
			census.Funcs)
	}

	for _, s := range sites {
		if s.Devalues {
			continue
		}
		t.Errorf("%s:%d %s — снимает строку участия и НЕ обесценивает невыкупленное "+
			"приглашение. Строка приглашения глобальна: сняв членство и оставив её ждущей "+
			"выкупа, продукт оставляет приглашение действующим — первый вход человека "+
			"вернёт его в аккаунт, из которого его исключили, и сигнала не будет ни одного. "+
			"Плечо обязано стоять в ТОМ ЖЕ операторе: между двумя, разнесёнными по "+
			"функциям, есть окно, в котором вход видит членств ноль и срок живым.",
			s.File, s.Line, s.Func)
	}
}
