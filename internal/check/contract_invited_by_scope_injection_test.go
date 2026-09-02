// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта областей УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем контракте, и это не говорит ничего о том, умеет
// ли он краснеть. Здесь ему подаётся СИНТЕТИЧЕСКИЙ контракт: по одному дефекту на
// каждое из трёх требований, и рядом с каждым — законный близнец, на котором гейт
// обязан молчать. Инъекция снимает РОВНО одно свойство: остальные два в каждой
// пробе остаются целыми, иначе красное приходило бы от соседнего требования и
// про снятое не говорило бы ничего.

// syntheticInvitedBy — минимальный контракт с полем «кто пригласил».
func syntheticInvitedBy(comment string) string {
	// Пустой строки между комментарием и объявлением быть НЕ должно: блок
	// комментария поля обрывается первой же не-комментарной строкой.
	return fmt.Sprintf("message X {\n%s  string invited_by = 1;\n}\n", comment)
}

const (
	syntheticScopeUser = "" +
		"  // Кто завёл ЛИЧНОСТЬ на платформе.\n" +
		"  //\n" +
		"  // ОБЛАСТЬ — ПЛАТФОРМА. НЕ ПУТАТЬ с `Membership.invited_by`.\n"
	syntheticScopeMembership = "" +
		"  // Кто позвал человека в этот аккаунт.\n" +
		"  //\n" +
		"  // ОБЛАСТЬ — АККАУНТ. НЕ ПУТАТЬ с `User.invited_by`.\n"
)

var syntheticRows = []invitedByField{
	{"user.proto", "string invited_by = 1;", "Membership.invited_by"},
	{"membership.proto", "string invited_by = 1;", "User.invited_by"},
}

func readerOfPair(user, membership string) func(string) (string, error) {
	return func(name string) (string, error) {
		switch name {
		case "user.proto":
			return syntheticInvitedBy(user), nil
		case "membership.proto":
			return syntheticInvitedBy(membership), nil
		default:
			return "", fmt.Errorf("синтетический контракт не несёт %s", name)
		}
	}
}

// TestScopeGateIsSilentOnAContractThatDeclaresBothScopes — положительный
// контроль. Без него отрицания ниже зеленели бы на чём угодно.
func TestScopeGateIsSilentOnAContractThatDeclaresBothScopes(t *testing.T) {
	findings, inspected, scopes := auditInvitedByScopes(t,
		readerOfPair(syntheticScopeUser, syntheticScopeMembership), syntheticRows)
	require.Equal(t, 2, inspected)
	require.Equal(t, 2, scopes)
	require.Empty(t, findings, "законный контракт объявлен находкой")
}

// TestScopeGateFlagsAFieldWithoutADeclaredScope — снята примета области, всё
// остальное цело.
func TestScopeGateFlagsAFieldWithoutADeclaredScope(t *testing.T) {
	noScope := "" +
		"  // User.id того, кто пригласил (nullable для self-signup bootstrap-row).\n" +
		"  // Близнец — `Membership.invited_by`.\n"
	findings, _, _ := auditInvitedByScopes(t,
		readerOfPair(noScope, syntheticScopeMembership), syntheticRows)
	require.Len(t, findings, 1, "поле без объявленной области прошло молча: %v", findings)
	require.Contains(t, findings[0], "область поля не объявлена")
}

// TestScopeGateFlagsTwoFieldsDeclaringOneScope — «различие не объявлено» в форме
// «объявлено одно и то же дважды». Примета на месте у обоих, близнецы названы.
func TestScopeGateFlagsTwoFieldsDeclaringOneScope(t *testing.T) {
	sameAsUser := "" +
		"  // Кто позвал человека в этот аккаунт.\n" +
		"  //\n" +
		"  // ОБЛАСТЬ — ПЛАТФОРМА. НЕ ПУТАТЬ с `User.invited_by`.\n"
	findings, _, scopes := auditInvitedByScopes(t,
		readerOfPair(syntheticScopeUser, sameAsUser), syntheticRows)
	require.Len(t, findings, 1, "две одинаковые области прошли молча: %v", findings)
	require.Contains(t, findings[0], "различие так и не названо")
	require.Equal(t, 1, scopes, "перепись обязана назвать ОДНУ область на два поля")
}

// TestScopeGateFlagsACommentThatDoesNotNameItsTwin — область объявлена верно, но
// читателя не отправляют ко второму полю.
func TestScopeGateFlagsACommentThatDoesNotNameItsTwin(t *testing.T) {
	noTwin := "" +
		"  // Кто позвал человека в этот аккаунт.\n" +
		"  //\n" +
		"  // ОБЛАСТЬ — АККАУНТ.\n"
	findings, _, _ := auditInvitedByScopes(t,
		readerOfPair(syntheticScopeUser, noTwin), syntheticRows)
	require.Len(t, findings, 1, "комментарий без близнеца прошёл молча: %v", findings)
	require.Contains(t, findings[0], "не называет близнеца")
}

// TestLeadingCommentStopsAtTheNearestNonCommentLine — распознаватель берёт
// комментарий ЭТОГО поля, а не всё, что выше в файле. Иначе примета соседнего
// поля гасила бы находку.
func TestLeadingCommentStopsAtTheNearestNonCommentLine(t *testing.T) {
	text := "" +
		"  // ОБЛАСТЬ — ПЛАТФОРМА (это комментарий ЧУЖОГО поля).\n" +
		"  string other = 1;\n" +
		"\n" +
		"  // Комментарий нужного поля, области не называет.\n" +
		"  string invited_by = 2;\n"
	comment, ok := leadingCommentOf(text, "string invited_by = 2;")
	require.True(t, ok)
	require.Contains(t, comment, "нужного поля")
	_, declared := declaredScope(comment)
	require.False(t, declared, "распознаватель прихватил комментарий соседнего поля")
}
