// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// exemptclaim_test.go — комментарий use-case не объявляет полосу `<exempt>`
// там, где контракт объявил `scope_filtered` (задача продукта #2047).
//
// # Предмет
//
// Комментарий описывает ПОЛОСУ АВТОРИЗАЦИИ, и потому его неправда дороже
// обычной: прочитавший «Get is `<exempt>`» заключит, что пообъектного гейта у
// единичного чтения роли нет, — и либо заведёт его второй раз, либо снимет тот,
// что стоит. Контракт при этом лежит рядом и сам объясняет, почему выбрана
// другая полоса (`role_service.proto`, шапки `rpc Get` и `rpc List`).
//
// # Премиса берётся из КОНТРАКТА, а не выписывается
//
// Гейт не утверждает «`<exempt>` в этом пакете запрещён навсегда». Он читает
// объявления `RoleService` и судит только при условии, что НИ ОДИН её rpc не
// объявлен `<exempt>`: тогда всякое такое слово в комментарии — заведомо ложь.
// Объявят какой-нибудь rpc действительно освобождённым — гейт отойдёт в сторону
// и скажет об этом переписью, вместо того чтобы краснеть на верном коде.
//
// Это и есть проверка собственной предпосылки (`testing.md` §«Гейт на класс»,
// п. 3): запрет обоснован фактом о контракте, факт может измениться, и гейт
// обязан заявить об этом сам.
//
// # Судится КОММЕНТАРИЙ, а не текст файла
//
// Слово `<exempt>` стоит и в строковых литералах контракта, и в прозе о самом
// гейте. Предикат по подстроке краснел бы на собственном объяснении
// (`testing.md` §«Гейт на класс», п. 4), поэтому суждение выносится по
// РАЗОБРАННЫМ комментариям — узлам дерева разбора, а не по строкам файла.
//
// # Границы, названные честно
//
// Судятся только НЕ-ТЕСТОВЫЕ файлы каталога, и это не забывчивость: слово стоит
// в шапке этого самого гейта и в его инъекции, поэтому охват на тестовое дерево
// сделал бы гейт красным на собственном объяснении — ровно тот класс, который он
// и ловит. Комментарий пробы, называвший ту же несуществующую полосу, поправлен
// тем же изменением ВРУЧНУЮ, и держателя у него нет; сказано, чтобы «ноль
// находок» не читалось шире, чем есть.
package role_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	// exemptToken — как полоса освобождения записывается в контракте и в прозе.
	exemptToken = "<exempt>"
	// roleContract — контракт, у которого живёт объявление полос.
	roleContract = "../../../../../../../proto/kacho/cloud/iam/v1/role_service.proto"
	// roleUseCaseDir — каталог use-case, чьи комментарии судятся.
	roleUseCaseDir = "."
)

// reExemptOption — объявление освобождённой полосы в контракте.
var reExemptOption = regexp.MustCompile(`permission\s*\)?\s*=\s*"` + regexp.QuoteMeta(exemptToken) + `"`)

type exemptCensus struct {
	ContractExempts int // rpc RoleService, объявленных `<exempt>`
	FilesRead       int // не-тестовых файлов use-case прочитано
	CommentBlocks   int // блоков комментария разобрано
	Claims          int // блоков, называющих `<exempt>`
}

func (c exemptCensus) String() string {
	return fmt.Sprintf("объявлений `%s` в контракте %d · файлов use-case прочитано %d · "+
		"блоков комментария разобрано %d · из них называют полосу %d",
		exemptToken, c.ContractExempts, c.FilesRead, c.CommentBlocks, c.Claims)
}

// auditExemptClaims судит комментарии при условии, что контракт освобождённых
// полос не объявляет. Оба входа принимаются параметром — инъекция подаёт
// синтетику, не трогая дерево.
func auditExemptClaims(contract string, sources map[string]string) ([]string, exemptCensus, error) {
	var (
		findings []string
		census   exemptCensus
	)
	census.ContractExempts = len(reExemptOption.FindAllString(contract, -1))
	if strings.TrimSpace(contract) == "" {
		return nil, census, fmt.Errorf("контракт пуст — премиса не прочитана, судить не по чему")
	}

	fset := token.NewFileSet()
	for name, src := range sources {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			return nil, census, fmt.Errorf("%s не разобран: %w", name, err)
		}
		census.FilesRead++
		for _, group := range f.Comments {
			census.CommentBlocks++
			text := group.Text()
			if !strings.Contains(text, exemptToken) {
				continue
			}
			census.Claims++
			// Премиса: пока контракт не объявил ни одной освобождённой полосы,
			// такое слово в комментарии — заведомо ложь.
			if census.ContractExempts > 0 {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"%s:%d: комментарий называет полосу `%s`, а контракт RoleService не объявил "+
					"её НИ У ОДНОГО rpc — обе читающие полосы объявлены `scope_filtered`, и "+
					"контракт сам объясняет почему.\n"+
					"    читатель заключит, что пообъектного гейта нет, и либо заведёт его "+
					"второй раз, либо снимет тот, что стоит",
				name, fset.Position(group.Pos()).Line, exemptToken))
		}
	}
	return findings, census, nil
}

// roleUseCaseSources — не-тестовые исходники каталога use-case.
func roleUseCaseSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(roleUseCaseDir)
	if err != nil {
		t.Fatalf("каталог use-case не прочитан: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(roleUseCaseDir, name))
		if rerr != nil {
			t.Fatalf("файл %s не прочитан: %v", name, rerr)
		}
		out[name] = string(b)
	}
	return out
}

// TestUseCaseDoesNotClaimAnExemptLaneTheContractNeverDeclared — вердикт о
// НАСТОЯЩЕМ дереве.
//
// Способность падать доказывает не этот прогон, а инъекция
// (`exemptclaim_injection_test.go`).
func TestUseCaseDoesNotClaimAnExemptLaneTheContractNeverDeclared(t *testing.T) {
	contract, err := os.ReadFile(roleContract)
	if err != nil {
		t.Fatalf("контракт не прочитан (%s): %v", roleContract, err)
	}
	findings, census, aerr := auditExemptClaims(string(contract), roleUseCaseSources(t))
	if aerr != nil {
		t.Fatalf("сверка не отработала: %v", aerr)
	}
	t.Logf("объём осмотренного: %s", census)

	// Премисы: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	if census.FilesRead == 0 {
		t.Fatal("файлов use-case прочитано 0 — обход пуст, вердикт беспредметен")
	}
	if census.CommentBlocks == 0 {
		t.Fatal("блоков комментария разобрано 0 — разбор пуст, судить не по чему")
	}
	if census.ContractExempts > 0 {
		t.Logf("контракт объявил освобождённых полос %d — гейт отходит в сторону: "+
			"слово в комментарии перестало быть заведомой ложью", census.ContractExempts)
	}

	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}
