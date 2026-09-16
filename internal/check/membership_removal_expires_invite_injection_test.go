// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_removal_expires_invite_injection_test.go — доказательство
// падучести MAIL-46 в обе стороны, на синтетике.
//
// Дефект, внесённый здесь, — ДОСЛОВНО то состояние, которое дерево несло до
// правки: оператор снимал членство и строки приглашения не трогал.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// membershipRemovalBeforeTheFix — ДЕФЕКТ: снимает участие, приглашение не
// обесценивает.
const membershipRemovalBeforeTheFix = "package pg\n\n" +
	"func (w *userWriter) RemoveMembership(ctx int, userID, accountID string) (bool, error) {\n" +
	"\ttag, err := w.tx.Exec(ctx,\n" +
	"\t\t`DELETE FROM memberships WHERE user_id = $1 AND account_id = $2`,\n" +
	"\t\tuserID, accountID)\n" +
	"\t_ = tag\n" +
	"\treturn true, err\n" +
	"}\n"

// membershipRemovalAfterTheFix — ЗАКОННЫЙ БЛИЗНЕЦ: оба плеча в одном операторе.
const membershipRemovalAfterTheFix = "package pg\n\n" +
	"func (w *userWriter) RemoveMembership(ctx int, userID, accountID string) (bool, error) {\n" +
	"\tconst q = `\n" +
	"\t\tWITH gone AS (\n" +
	"\t\t\tDELETE FROM memberships WHERE user_id = $1 AND account_id = $2\n" +
	"\t\t\tRETURNING 1\n" +
	"\t\t), expired AS (\n" +
	"\t\t\tUPDATE users SET invite_expires_at = now() WHERE id = $1\n" +
	"\t\t\tRETURNING 1\n" +
	"\t\t)\n" +
	"\t\tSELECT 1`\n" +
	"\t_ = q\n" +
	"\treturn true, nil\n" +
	"}\n"

// membershipRemovalOfAnotherTable — ВТОРОЙ законный близнец: снятие строки
// ДРУГОЙ таблицы обесценивания не требует, и гейт обязан молчать. Без него
// предикат, судящий любое удаление, выглядел бы работающим.
const membershipRemovalOfAnotherTable = "package pg\n\n" +
	"func (w *userWriter) DropGrant(ctx int, id string) error {\n" +
	"\t_, err := w.tx.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, id)\n" +
	"\treturn err\n" +
	"}\n"

// membershipRemovalInProse — ТРЕТИЙ близнец: те же слова ПОСРЕДИ предложения.
// Образец привязан к началу строки именно затем, чтобы гейт не краснел на
// собственном объяснении.
const membershipRemovalInProse = "package pg\n\n" +
	"func explain() string {\n" +
	"\treturn `этот путь не делает DELETE FROM memberships и делать не должен`\n" +
	"}\n"

func scanRemoval(t *testing.T, src string) ([]check.MembershipRemovalSite, check.MembershipRemovalCensus) {
	t.Helper()
	s, c, err := check.ScanMembershipRemovalFile("synthetic/repo.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if c.Funcs == 0 || c.Literals == 0 {
		t.Fatalf("осмотрено функций %d, литералов %d — разбирается не то", c.Funcs, c.Literals)
	}
	return s, c
}

// TestMAIL46Injection_RemovalWithoutDevaluationIsAFinding — дефект: находка с
// координатой и ИМЕНЕМ функции. Находка без них не есть действие.
func TestMAIL46Injection_RemovalWithoutDevaluationIsAFinding(t *testing.T) {
	t.Parallel()
	sites, census := scanRemoval(t, membershipRemovalBeforeTheFix)
	if census.Removing != 1 {
		t.Fatalf("снимающих участие найдено %d, ожидалась 1", census.Removing)
	}
	if census.Devaluing != 0 {
		t.Fatalf("обесценивающих найдено %d, ожидался 0 — дефект не внесён", census.Devaluing)
	}
	if len(sites) != 1 || sites[0].Devalues {
		t.Fatalf("дефект не опознан: %+v", sites)
	}
	if sites[0].Func != "RemoveMembership" {
		t.Errorf("находка не называет функцию: %+v", sites[0])
	}
	if sites[0].Line == 0 {
		t.Errorf("находка без координаты: %+v", sites[0])
	}
}

// TestMAIL46Injection_BothArmsInOneStatementAreSilent — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
func TestMAIL46Injection_BothArmsInOneStatementAreSilent(t *testing.T) {
	t.Parallel()
	sites, census := scanRemoval(t, membershipRemovalAfterTheFix)
	if census.Removing != 1 || census.Devaluing != 1 {
		t.Fatalf("перепись законного близнеца: снимающих %d, обесценивающих %d — ожидалось 1 и 1",
			census.Removing, census.Devaluing)
	}
	if len(sites) != 1 || !sites[0].Devalues {
		t.Fatalf("законный близнец объявлен находкой: %+v", sites)
	}
}

// TestMAIL46Injection_RemovingAnotherTableIsSilent — второй близнец: предикат
// судит ПРЕДМЕТ снятия, а не глагол `DELETE`.
func TestMAIL46Injection_RemovingAnotherTableIsSilent(t *testing.T) {
	t.Parallel()
	_, census := scanRemoval(t, membershipRemovalOfAnotherTable)
	if census.Removing != 0 {
		t.Fatalf("снятие строки ДРУГОЙ таблицы принято за снятие участия: %d", census.Removing)
	}
}

// TestMAIL46Injection_ProseIsNotAStatement — третий близнец: те же слова
// посреди предложения объявлением не являются.
func TestMAIL46Injection_ProseIsNotAStatement(t *testing.T) {
	t.Parallel()
	_, census := scanRemoval(t, membershipRemovalInProse)
	if census.Removing != 0 {
		t.Fatalf("проза о запрете прочитана как оператор: %d", census.Removing)
	}
}

// TestMAIL46Injection_ArmsInDifferentFunctionsAreAFinding — плечи, разнесённые
// по функциям, находкой ОСТАЮТСЯ: между двумя операторами есть окно, в котором
// первый вход видит членств ноль и срок живым.
func TestMAIL46Injection_ArmsInDifferentFunctionsAreAFinding(t *testing.T) {
	t.Parallel()
	src := membershipRemovalBeforeTheFix + "\n" +
		"func (w *userWriter) expireLater(ctx int, id string) error {\n" +
		"\t_, err := w.tx.Exec(ctx, `UPDATE users SET invite_expires_at = now() WHERE id = $1`, id)\n" +
		"\treturn err\n" +
		"}\n"
	sites, census := scanRemoval(t, src)
	if census.Devaluing != 0 {
		t.Fatalf("плечо из ДРУГОЙ функции зачтено снимающей: %d", census.Devaluing)
	}
	var found bool
	for _, s := range sites {
		if s.Func == "RemoveMembership" && !s.Devalues {
			found = true
		}
	}
	if !found {
		t.Fatalf("разнесённые плечи не дали находки: %+v", sites)
	}
	if !strings.Contains(census.String(), "снимающих участие, найдено 1") {
		t.Errorf("перепись не называет обе величины: %s", census.String())
	}
}
