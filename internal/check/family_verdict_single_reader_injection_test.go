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
const recordIssuanceSQL = ` + "`" + `INSERT INTO kaname.access_tokens (jti, family_id, issued_at, expires_at) VALUES ($1,$2,$3,$4)` + "`" + `
const sweepIssuancesSQL = ` + "`" + `DELETE FROM kaname.access_tokens WHERE ctid IN (SELECT ctid FROM kaname.access_tokens LIMIT 1)` + "`" + `

// SELECT family_live FROM kaname.access_tokens — упоминание в комментарии.

type Repo struct{}

func (Repo) FamilyRevoked(jti string) (bool, error) { return familyRevokedOf(jti) }

func familyRevokedOf(string) (bool, error) { return false, nil }
`
	fvRuleSrc = `package tokenrevocation

import "github.com/golang-jwt/jwt/v5"

type FamilyReader interface{ FamilyRevoked(jti string) (bool, error) }

// Утверждения — ключи отсечки: закрытый перечень клиентов.
var subjectClaims = []string{"kaname_user_token_id", "kaname_sa_key_id"}

func Keys(claims jwt.MapClaims) []string {
	var out []string
	if sub, _ := claims["sub"].(string); sub != "" {
		out = append(out, sub)
	}
	for _, name := range subjectClaims {
		if v, _ := claims[name].(string); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func FamilyRevoked(r FamilyReader, jti string) (bool, error) { return r.FamilyRevoked(jti) }

func Revoked(r FamilyReader, claims jwt.MapClaims) (bool, error) {
	_ = Keys(claims)
	jti, _ := claims["jti"].(string)
	return FamilyRevoked(r, jti)
}
`
	// fvWriterSrc — объявление писателя записи выпуска: предмет оси «выпуск
	// пишет запись».
	fvWriterSrc = `package pg

type OAuthCeremonyRepo struct{}

func (r *OAuthCeremonyRepo) RecordAccessToken(jti, familyID string) error { return nil }
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
		"internal/repo/kaname/pg/access_token_writer.go":          fvWriterSrc,
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

const recordIssuanceSQL = ` + "`" + `INSERT INTO kaname.access_tokens (jti) VALUES ($1)` + "`" + `
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

// ── Ось «решение о семействе не имеет второго хранилища» ─────────────────────
//
// Правило читает утверждения токена. Каждое прочитанное утверждение решено:
// ключ отсечки субъекта или клиента либо идентификатор выпуска — единственный
// вход к записи выпуска. Утверждение, несущее семейство, превратило бы отсечку
// по ключу во ВТОРОЕ хранилище решения о семействе (К10, вариант А: семейство
// судит только запись выпуска по jti).

// fvRuleWith — правило законной формы плюс файл с добавочным чтением.
func fvRuleWith(extra string) map[string]string {
	files := fvLawfulTree()
	files["internal/tokenrevocation/family_key.go"] = extra
	return files
}

// TestFamilyVerdictGate_FamilyKeyAmongCutoffKeysIsFound — I4, вариант «в
// правиле свой ключ семейства»: утверждение семейства читается через
// константу и уходит в отсечку.
func TestFamilyVerdictGate_FamilyKeyAmongCutoffKeysIsFound(t *testing.T) {
	t.Parallel()
	_, found := fvFindings(t, fvRuleWith(`package tokenrevocation

import "github.com/golang-jwt/jwt/v5"

const FamilyKeyClaim = "kaname_token_family_id"

func familyKey(claims jwt.MapClaims) string {
	family, _ := claims[FamilyKeyClaim].(string)
	return family
}
`))
	if len(found) != 1 || !strings.Contains(found[0], "kaname_token_family_id") ||
		!strings.Contains(found[0], "tokenrevocation/family_key.go") {
		t.Fatalf("ключ семейства среди ключей отсечки обязан дать ОДНУ находку с именем и координатой, получено %v", found)
	}
}

// TestFamilyVerdictGate_UndecidedClaimByLiteralIsFound — то же чтение прямым
// литералом, без константы.
func TestFamilyVerdictGate_UndecidedClaimByLiteralIsFound(t *testing.T) {
	t.Parallel()
	_, found := fvFindings(t, fvRuleWith(`package tokenrevocation

import "github.com/golang-jwt/jwt/v5"

func grantKey(claims jwt.MapClaims) string {
	g, _ := claims["kaname_grant_id"].(string)
	return g
}
`))
	if len(found) != 1 || !strings.Contains(found[0], "kaname_grant_id") {
		t.Fatalf("нерешённое утверждение обязано дать ОДНУ находку с именем, получено %v", found)
	}
}

// TestFamilyVerdictGate_RuleThatStopsAskingTheIssuanceIsFound — I1 на уровне
// узлов: правило перестало читать идентификатор выпуска — о семействе оно не
// спрашивает вовсе.
func TestFamilyVerdictGate_RuleThatStopsAskingTheIssuanceIsFound(t *testing.T) {
	t.Parallel()
	files := fvLawfulTree()
	files["internal/tokenrevocation/rule.go"] = strings.Replace(fvRuleSrc,
		"jti, _ := claims[\"jti\"].(string)", "jti := \"\"", 1)
	if files["internal/tokenrevocation/rule.go"] == fvRuleSrc {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: инъекция не внесена")
	}
	_, found := fvFindings(t, files)
	if len(found) != 1 || !strings.Contains(found[0], "\"jti\"") {
		t.Fatalf("правило без вопроса о выпуске обязано дать ОДНУ находку, получено %v", found)
	}
}

// ── Ось «выпуск пишет запись выпуска» ────────────────────────────────────────
//
// Отсутствие записи правило читает как «семейству не принадлежит». Значит
// выпуск церемонии, не пишущий запись, выпускает токен, который отзыв
// семейства не снимает. Реализация порта выпуска фундамента
// (`IssueAccessToken` либо `StoreAccessToken`) без единого вызова писателя в
// дереве — находка.

// fvIssuancePortMethods — методы портов выпуска фундамента, по каждому из
// которых ось обязана уметь упасть: `AccessTokenIssuer.IssueAccessToken` и
// `AccessTokenVault.StoreAccessToken` (`corelib/oauthceremony`, с тега
// v1.10.0-rc.1). Перечень выписан ЗДЕСЬ, а не взят из гейта: имя, выпавшее из
// набора гейта, иначе выпало бы и из опыта, и ось по нему смолкла бы без
// единого красного.
var fvIssuancePortMethods = []string{"IssueAccessToken", "StoreAccessToken"}

// fvIssuanceSrc — адаптер порта выпуска методом method; records — зовёт ли он
// писателя записи выпуска. Вход и его близнец отличаются ровно этим вызовом.
func fvIssuanceSrc(method string, records bool) string {
	body := "return nil"
	if records {
		body = "return a.rec.RecordAccessToken(jti, family)"
	}
	return `package ceremonyport

type recorder interface{ RecordAccessToken(jti, familyID string) error }

type AccessTokens struct{ rec recorder }

func (a *AccessTokens) ` + method + `(jti, family string) error { ` + body + ` }
`
}

// TestFamilyVerdictGate_IssuanceWithoutRecordIsFound — по каждому методу порта
// выпуска: выпуск есть, писатель записи не позван нигде.
func TestFamilyVerdictGate_IssuanceWithoutRecordIsFound(t *testing.T) {
	t.Parallel()
	for _, method := range fvIssuancePortMethods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			files := fvLawfulTree()
			files["internal/ceremonyport/access_tokens.go"] = fvIssuanceSrc(method, false)
			_, found := fvFindings(t, files)
			if len(found) != 1 || !strings.Contains(found[0], "ceremonyport/access_tokens.go") ||
				!strings.Contains(found[0], "RecordAccessToken") {
				t.Fatalf("выпуск %s без записи обязан дать ОДНУ находку с координатой, получено %v",
					method, found)
			}
		})
	}
}

// TestFamilyVerdictGate_IssuanceThatRecordsIsSilent — близнец по каждому методу:
// тот же выпуск, и писатель позван.
func TestFamilyVerdictGate_IssuanceThatRecordsIsSilent(t *testing.T) {
	t.Parallel()
	for _, method := range fvIssuancePortMethods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			files := fvLawfulTree()
			files["internal/ceremonyport/access_tokens.go"] = fvIssuanceSrc(method, true)
			if _, found := fvFindings(t, files); len(found) != 0 {
				t.Fatalf("выпуск %s, пишущий запись, дал находки: %v", method, found)
			}
		})
	}
}

// TestFamilyVerdictGate_WriterLostIsFound — предпосылка оси: объявления
// писателя в дереве нет — ось потеряла предмет, и это сказано, а не умолчано.
func TestFamilyVerdictGate_WriterLostIsFound(t *testing.T) {
	t.Parallel()
	files := fvLawfulTree()
	delete(files, "internal/repo/kaname/pg/access_token_writer.go")
	_, found := fvFindings(t, files)
	if len(found) != 1 || !strings.Contains(found[0], "RecordAccessToken") {
		t.Fatalf("потерянный писатель обязан дать ОДНУ находку, получено %v", found)
	}
}
