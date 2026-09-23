// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_verdict_single_reader_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт
// одного читателя семейства способен упасть на каждой своей оси и молчит на
// законных близнецах (kaname#319).
//
// Вход синтетический: гейт, чья самопроверка стоит на живом дереве, краснел бы
// при уборке своего же предмета и зеленел бы там, где разбор ослеп.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Законная форма дерева: один читающий литерал у слоя доступа, три поверхности
// зовут правило, порт зовёт только правило.
const (
	fvReaderSrc = `package pg

const familyRevokedOfIssuanceSQL = ` + "`" + `SELECT family_live IS NOT TRUE FROM kaname.access_tokens WHERE jti = $1` + "`" + `

// Законные близнецы: вставка и уборка открываются не словом чтения.
const recordAccessTokenSQL = ` + "`" + `INSERT INTO kaname.access_tokens (jti, family_id, issued_at, expires_at) VALUES ($1,$2,$3,$4)` + "`" + `
const sweepAccessTokensSQL = ` + "`" + `DELETE FROM kaname.access_tokens WHERE ctid IN (SELECT ctid FROM kaname.access_tokens LIMIT 1)` + "`" + `

// SELECT family_live FROM kaname.access_tokens — упоминание в комментарии.

type Repo struct{}

func (Repo) FamilyRevoked(jti string) (bool, error) { return familyRevokedOf(jti) }

func familyRevokedOf(string) (bool, error) { return false, nil }
`
	fvRuleSrc = `package tokenrevocation

type FamilyReader interface{ FamilyRevoked(jti string) (bool, error) }

func FamilyRevoked(r FamilyReader, jti string) (bool, error) { return r.FamilyRevoked(jti) }

func Revoked(r FamilyReader, jti string) (bool, error) { return FamilyRevoked(r, jti) }
`
	fvIsRevokedSrc = `package session_revocations

import "github.com/PRO-Robotech/kaname/internal/tokenrevocation"

func isRevoked(r tokenrevocation.FamilyReader, jti string) (bool, error) {
	return tokenrevocation.FamilyRevoked(r, jti)
}
`
	fvIntrospectSrc = `package tokenintrospecthttp

import rule "github.com/PRO-Robotech/kaname/internal/tokenrevocation"

func judge(r rule.FamilyReader, jti string) (bool, error) { return rule.Revoked(r, jti) }
`
	fvPresentedSrc = `package presentedcred

import "github.com/PRO-Robotech/kaname/internal/tokenrevocation"

func revoked(r tokenrevocation.FamilyReader, jti string) (bool, error) {
	return tokenrevocation.Revoked(r, jti)
}
`
)

func fvLawfulTree() map[string]string {
	return map[string]string{
		"internal/repo/kaname/pg/access_token.go":                 fvReaderSrc,
		"internal/tokenrevocation/rule.go":                        fvRuleSrc,
		"internal/apps/kaname/api/session_revocations/handler.go": fvIsRevokedSrc,
		"internal/handler/tokenintrospecthttp/handler.go":         fvIntrospectSrc,
		"internal/presentedcred/reader.go":                        fvPresentedSrc,
	}
}

func fvFindings(t *testing.T, files map[string]string) (check.FamilyVerdictCensus, []string) {
	t.Helper()
	census, err := check.FamilyVerdict(files)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return census, check.FamilyVerdictFindings(census, familyVerdictSurfaces)
}

// TestFamilyVerdictGate_LawfulTreeIsSilent — контроль: законная форма, включая
// близнецов (вставка, уборка, упоминание в комментарии, объявление метода порта у
// адаптера), не даёт ни одной находки.
func TestFamilyVerdictGate_LawfulTreeIsSilent(t *testing.T) {
	t.Parallel()
	census, found := fvFindings(t, fvLawfulTree())
	if len(found) != 0 {
		t.Fatalf("законная форма дала находки: %v", found)
	}
	if len(census.Readers) != 1 || len(census.RuleCallers) < len(familyVerdictSurfaces) {
		t.Fatalf("контроль не увидел предмета: читателей %d, каталогов правила %d",
			len(census.Readers), len(census.RuleCallers))
	}
}

// TestFamilyVerdictGate_SecondReaderIsFound — I4: вторая копия чтения у
// поверхности.
func TestFamilyVerdictGate_SecondReaderIsFound(t *testing.T) {
	t.Parallel()
	files := fvLawfulTree()
	files["internal/apps/kaname/api/session_revocations/family.go"] = `package session_revocations

const ownFamilySQL = ` + "`" + `SELECT f.revoked_at IS NOT NULL FROM kaname.access_tokens a JOIN kaname.token_families f ON f.id = a.family_id WHERE a.jti = $1` + "`" + `
`
	_, found := fvFindings(t, files)
	if len(found) != 1 || !strings.Contains(found[0], "session_revocations/family.go") {
		t.Fatalf("вторая копия чтения обязана дать ОДНУ находку с координатой, получено %v", found)
	}
}

// TestFamilyVerdictGate_PortCalledPastTheRuleIsFound — порт позван мимо
// правила.
func TestFamilyVerdictGate_PortCalledPastTheRuleIsFound(t *testing.T) {
	t.Parallel()
	files := fvLawfulTree()
	files["internal/apps/kaname/api/session_revocations/bypass.go"] = `package session_revocations

type port interface{ FamilyRevoked(string) (bool, error) }

func direct(p port, jti string) (bool, error) { return p.FamilyRevoked(jti) }
`
	_, found := fvFindings(t, files)
	if len(found) != 1 || !strings.Contains(found[0], "bypass.go") || !strings.Contains(found[0], "мимо правила") {
		t.Fatalf("вызов порта мимо правила обязан дать ОДНУ находку с координатой, получено %v", found)
	}
}

// TestFamilyVerdictGate_SurfaceThatDoesNotAskTheRuleIsFound — I2/I3:
// поверхность судит без правила.
func TestFamilyVerdictGate_SurfaceThatDoesNotAskTheRuleIsFound(t *testing.T) {
	t.Parallel()
	files := fvLawfulTree()
	files["internal/handler/tokenintrospecthttp/handler.go"] = `package tokenintrospecthttp

func judge(jti string) (bool, error) { return jti == "", nil }
`
	_, found := fvFindings(t, files)
	if len(found) != 1 || !strings.Contains(found[0], "internal/handler/tokenintrospecthttp") {
		t.Fatalf("поверхность без правила обязана дать ОДНУ находку, получено %v", found)
	}
}

// TestFamilyVerdictGate_NoReaderIsFound — предмет потерян: читающего литерала
// нет вовсе.
func TestFamilyVerdictGate_NoReaderIsFound(t *testing.T) {
	t.Parallel()
	files := fvLawfulTree()
	files["internal/repo/kaname/pg/access_token.go"] = `package pg

const recordAccessTokenSQL = ` + "`" + `INSERT INTO kaname.access_tokens (jti) VALUES ($1)` + "`" + `
`
	_, found := fvFindings(t, files)
	if len(found) != 1 || !strings.Contains(found[0], "НОЛЬ") {
		t.Fatalf("потерянный предмет обязан дать ОДНУ находку, получено %v", found)
	}
}

// TestFamilyVerdictGate_EmptyWalkIsNotGreen — пустой обход зелёного не даёт.
func TestFamilyVerdictGate_EmptyWalkIsNotGreen(t *testing.T) {
	t.Parallel()
	_, found := fvFindings(t, map[string]string{})
	if len(found) == 0 {
		t.Fatal("пустой обход дал «находок ноль» — неотличимо от чистого дерева")
	}
}
