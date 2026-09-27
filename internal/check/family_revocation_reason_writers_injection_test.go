// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_revocation_reason_writers_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт
// KN-FRV-17 способен упасть по каждой ветви и молчит на законном близнеце
// (приёмка §7.6 п.12).
//
// Деревья синтетические: слово, домен и писатели подаются входом, а не
// читаются из дерева, иначе падучесть зависела бы от того, что в дереве
// лежит сегодня.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const frvSynthDomain = "example.test/svc/internal/domain"

// frvSynthDomainSrc — объявления словаря синтетического домена. Константа без
// явного типа и константа чужого типа в перепись не входят.
const frvSynthDomainSrc = `package domain

type FamilyRevocationReason string

type OtherReason string

const (
	FamilyRevokedByCodeReplay       FamilyRevocationReason = "code-replay"
	FamilyRevokedByLogout           FamilyRevocationReason = "logout"
	FamilyRevokedByClientRevocation FamilyRevocationReason = "client-revoke"
	OtherLogout                     OtherReason            = "logout"
	untyped                                                = "logout"
)
`

// frvWriterSrc — писатель повтора кода: ссылка селектором в коде.
const frvWriterSrc = `package pg

import "example.test/svc/internal/domain"

func revoke() any { return domain.FamilyRevokedByCodeReplay }
`

// frvLogoutWriterSrc — ЗАКОННЫЙ БЛИЗНЕЦ находки: ссылка на константу в коде,
// под псевдонимом импорта.
const frvLogoutWriterSrc = `package humansession

import d "example.test/svc/internal/domain"

func end() any { return d.FamilyRevokedByLogout }
`

// frvMentionOnlySrc — константа названа только комментарием и строкой.
// Писателем это не является: гейт судит узел, а не текст.
const frvMentionOnlySrc = `package humansession

import "example.test/svc/internal/domain"

// Выход мог бы писать domain.FamilyRevokedByLogout — но не пишет.
const note = "domain.FamilyRevokedByLogout"

var _ domain.FamilyRevocationReason
`

// frvForeignSelectorSrc — одноимённый селектор ЧУЖОГО пакета с тем же
// именем: ссылкой на словарь он не является.
const frvForeignSelectorSrc = `package other

import "example.test/other/domain"

func end() any { return domain.FamilyRevokedByLogout }
`

func frvSynthConstants(t *testing.T) map[string]string {
	t.Helper()
	constants, err := check.FamilyReasonConstants(map[string]string{"domain/oauth.go": frvSynthDomainSrc},
		"FamilyRevocationReason")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if len(constants) != 3 {
		t.Fatalf("констант типа словаря обязано быть три, разобрано %d: %v", len(constants), constants)
	}
	return constants
}

// frvOnlyClientRevoke — ветвь сопряжения синтетического фундамента: по
// значению сопрягается только слово отзыва клиентом.
func frvOnlyClientRevoke(word string) bool { return word == "client-revoke" }

func frvFindings(t *testing.T, files map[string]string, vocabulary []string,
	conjugated func(string) bool) (check.FamilyReasonWritersCensus, []string) {
	t.Helper()
	census, err := check.FamilyReasonWriters(files, frvSynthDomain, frvSynthConstants(t), vocabulary, conjugated)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: %s", census)
	return census, check.FamilyReasonWriterFindings(census)
}

// TestFamilyReasonWritersGate_KN_FRV_17_NamesAWordWithoutAWriter — слово без
// писателя красно и названо поимённо; близнец со ссылкой в коде зелёный.
func TestFamilyReasonWritersGate_KN_FRV_17_NamesAWordWithoutAWriter(t *testing.T) {
	t.Parallel()
	vocabulary := []string{"code-replay", "logout", "client-revoke"}

	_, findings := frvFindings(t, map[string]string{"pg/repo.go": frvWriterSrc}, vocabulary, frvOnlyClientRevoke)
	if len(findings) != 1 || !strings.Contains(findings[0], `"logout"`) {
		t.Fatalf("слово без писателя обязано быть ровно одной находкой и названо: %q", findings)
	}

	// Близнец — одно изменение: ссылка на константу в коде, под псевдонимом.
	census, findings := frvFindings(t, map[string]string{
		"pg/repo.go":          frvWriterSrc,
		"humansession/end.go": frvLogoutWriterSrc,
	}, vocabulary, frvOnlyClientRevoke)
	if len(findings) != 0 {
		t.Fatalf("законный близнец обязан быть зелёным: %q", findings)
	}
	if census.Words[1].ConstantRefs != 1 {
		t.Fatalf("ссылка под псевдонимом импорта обязана считаться: %+v", census.Words[1])
	}
}

// TestFamilyReasonWritersGate_KN_FRV_17_AMentionIsNotAWriter — константа,
// названная комментарием и строкой, писателем не является, и одноимённый
// селектор чужого пакета — тоже.
func TestFamilyReasonWritersGate_KN_FRV_17_AMentionIsNotAWriter(t *testing.T) {
	t.Parallel()
	census, findings := frvFindings(t, map[string]string{
		"pg/repo.go":          frvWriterSrc,
		"humansession/end.go": frvMentionOnlySrc,
		"other/end.go":        frvForeignSelectorSrc,
	}, []string{"code-replay", "logout"}, nil)
	if len(findings) != 1 || !strings.Contains(findings[0], `"logout"`) {
		t.Fatalf("упоминание не пишет слова: находка обязана быть одна и назвать logout: %q", findings)
	}
	if census.FilesParsed != 2 {
		t.Fatalf("разобраны обязаны быть ровно два файла, импортирующих домен: %d", census.FilesParsed)
	}
}

// TestFamilyReasonWritersGate_KN_FRV_17_ConjugationIsAWriter — без ветви
// сопряжения слово, которое пишется по значению, названо беспризорным; с
// ветвью — нет.
func TestFamilyReasonWritersGate_KN_FRV_17_ConjugationIsAWriter(t *testing.T) {
	t.Parallel()
	files := map[string]string{"pg/repo.go": frvWriterSrc}
	vocabulary := []string{"code-replay", "client-revoke"}

	_, findings := frvFindings(t, files, vocabulary, nil)
	if len(findings) != 1 || !strings.Contains(findings[0], `"client-revoke"`) {
		t.Fatalf("гейт без ветви сопряжения обязан назвать client-revoke: %q", findings)
	}

	census, findings := frvFindings(t, files, vocabulary, frvOnlyClientRevoke)
	if len(findings) != 0 {
		t.Fatalf("с ветвью сопряжения слово по значению обязано быть записанным: %q", findings)
	}
	if !census.Words[1].Conjugated || census.Words[1].ConstantRefs != 0 {
		t.Fatalf("client-revoke пишется сопряжением, а не константой: %+v", census.Words[1])
	}
}

// TestFamilyReasonWritersGate_KN_FRV_17_EmptyTraversalIsRed — ноль
// прочитанного и пустой перечень — красные исходы, а не «ноль находок».
func TestFamilyReasonWritersGate_KN_FRV_17_EmptyTraversalIsRed(t *testing.T) {
	t.Parallel()

	_, findings := frvFindings(t, map[string]string{}, []string{"code-replay"}, frvOnlyClientRevoke)
	if len(findings) == 0 || !strings.Contains(findings[0], "обход пуст") {
		t.Fatalf("ноль прочитанных файлов обязан быть красным: %q", findings)
	}

	_, findings = frvFindings(t, map[string]string{
		"x/none.go": "package x\n\nconst y = `SELECT 1`\n",
	}, []string{"code-replay"}, frvOnlyClientRevoke)
	if len(findings) == 0 || !strings.Contains(findings[0], "обход пуст") {
		t.Fatalf("ни одного файла, импортирующего домен, — тоже «ноль прочитанного»: %q", findings)
	}

	_, findings = frvFindings(t, map[string]string{"pg/repo.go": frvWriterSrc}, nil, frvOnlyClientRevoke)
	if len(findings) != 1 || !strings.Contains(findings[0], "перечень словаря пуст") {
		t.Fatalf("пустой перечень обязан быть красным: %q", findings)
	}
}
