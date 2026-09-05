// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rule_wildcard_contract_agrees_test.go — гейт класса «два места об одном
// предмете»: комментарий контракта о подстановке `*` в поле `Rule` обязан
// сходиться с тем, что домен ДЕЛАЕТ с этой подстановкой (задача продукта #1961).
//
// # Предмет
//
// Комментарий поля контракта — клиентская поверхность: он уезжает в порождённые
// стабы и в документацию. Заявление «подстановка system-only» там, где домен
// принимает её у арендатора, стоит читателю либо неиспользованной законной
// возможности, либо лишней системной роли на месте своей.
//
// Обратная сторона столь же реальна: подстановка, ОГРАНИЧЕННАЯ политикой, но не
// названная таковой, оставляет вызывающего без объяснения отказа.
//
// # Ось поведения — ПОЛИТИКОЗАВИСИМОСТЬ, а не «отвергается ли»
//
// Заявление «system-only» есть утверждение об ЯРУСЕ: системной роли можно,
// арендаторской нельзя. Поэтому производитель поведения спрашивается ДВАЖДЫ —
// арендаторской политикой и платформенной, — и подстановка считается
// политикозависимой ровно тогда, когда первая её отвергает, а вторая принимает.
//
// Различение несущее. Без него `resource_names` (подстановка запрещена ВСЕГДА,
// обоим ярусам) читалась бы как system-only и требовала бы заявления, которого
// делать нельзя: она не системная возможность, а запрет. В настоящем дереве это
// поле и служит законным близнецом — гейт обязан о нём молчать.
//
// # Формы записи заявления, которые распознаватель знает
//
// Корпус двуязычен, поэтому обе половины обязательны: предикат на одном языке
// недобирает МОЛЧА (`testing.md` §«Предикат по ДВУЯЗЫЧНОМУ корпусу»). Каждая
// форма доказана своей инъекцией в `rule_wildcard_contract_agrees_injection_test.go`.
//
//	F1-en  SYSTEM-ONLY / system-only рядом с литералом подстановки
//	F2-ru  корень «системн» (только системной роли, системная роль, …)
//
// Заявление засчитывается лишь тогда, когда в том же блоке комментария стоит
// САМ ЛИТЕРАЛ подстановки: слово «системная» встречается в прозе о ярусах ролей
// и без него означало бы другое.
package domain_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// wildcardProbe — производитель ПОВЕДЕНИЯ поля: строит правило, у которого
// подстановка стоит ровно в этом поле, и отдаёт вердикт домена.
type wildcardProbe func(domain.RulePolicy) error

// ruleWildcardProbes — поля `Rule`, у которых подстановка вообще представима.
// Ключ — имя поля В КОНТРАКТЕ (snake_case), чтобы сверка шла по той же
// координате, которую читает клиент.
func ruleWildcardProbes() map[string]wildcardProbe {
	mods := fixtureModules()
	validate := func(r domain.Rule) wildcardProbe {
		return func(p domain.RulePolicy) error { return r.Validate(p, mods) }
	}
	return map[string]wildcardProbe{
		"module": validate(domain.Rule{
			Module: "*", Resources: []string{"network"}, Verbs: []string{"get"},
		}),
		"resources": validate(domain.Rule{
			Module: "vpc", Resources: []string{"*"}, Verbs: []string{"get"},
		}),
		"verbs": validate(domain.Rule{
			Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"},
		}),
		"resource_names": validate(domain.Rule{
			Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"},
			ResourceNames: []string{"*"},
		}),
	}
}

type ruleWildcardCensus struct {
	Fields    int // полей message Rule прочитано
	Claims    int // из них заявляют подстановку системной возможностью
	Probed    int // полей, у которых есть производитель поведения
	Dependent int // из пробованных — политикозависимых по факту
}

func (c ruleWildcardCensus) String() string {
	return fmt.Sprintf("полей message Rule прочитано %d · заявлений о системности %d · "+
		"полей с производителем поведения %d · политикозависимых по факту %d",
		c.Fields, c.Claims, c.Probed, c.Dependent)
}

var (
	// reRuleField — объявление поля внутри message. Имя берётся перед `=`.
	reRuleField = regexp.MustCompile(`^\s*(?:repeated\s+|optional\s+)?[A-Za-z0-9_.<>, ]+?\s+([a-z][a-z0-9_]*)\s*=\s*\d+\s*;`)
	// reSystemOnly — обе половины двуязычного корпуса (F1, F2).
	reSystemOnly = regexp.MustCompile(`(?i)system-only|системн`)
	// reWildcardLiteral — сам литерал подстановки в любом обрамлении.
	reWildcardLiteral = regexp.MustCompile("`\"\\*\"`|`'\\*'`|`\\*`|\"\\*\"")
)

// auditRuleWildcardContract выносит вердикт по ТЕКСТУ контракта и ПОВЕДЕНИЮ
// домена. Текст принимается параметром, чтобы инъекция подавала синтетику, не
// трогая дерево.
func auditRuleWildcardContract(
	protoText string, probes map[string]wildcardProbe,
) ([]string, ruleWildcardCensus, error) {
	var (
		findings []string
		census   ruleWildcardCensus
		block    []string
		inRule   bool
	)
	for _, line := range strings.Split(protoText, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !inRule:
			if strings.HasPrefix(trimmed, "message Rule ") || trimmed == "message Rule{" {
				inRule = true
			}
			continue
		case trimmed == "}":
			inRule = false
			continue
		case strings.HasPrefix(trimmed, "//"):
			block = append(block, trimmed)
			continue
		case trimmed == "":
			// Пустая строка рвёт блок комментария: иначе заявление из шапки
			// соседнего поля приписалось бы следующему.
			block = nil
			continue
		}

		m := reRuleField.FindStringSubmatch(line)
		if m == nil {
			block = nil
			continue
		}
		field := m[1]
		comment := strings.Join(block, "\n")
		block = nil
		census.Fields++

		claim := reSystemOnly.MatchString(comment) && reWildcardLiteral.MatchString(comment)
		if claim {
			census.Claims++
		}

		probe, ok := probes[field]
		if !ok {
			if claim {
				findings = append(findings, fmt.Sprintf(
					"поле %s: контракт заявляет подстановку системной возможностью, "+
						"а производителя поведения у поля нет — заявление некому проверить",
					field))
			}
			continue
		}
		census.Probed++

		tenantErr := probe(domain.TenantPolicy())
		platformErr := probe(domain.PolicyOfRole(true, ""))
		dependent := tenantErr != nil && platformErr == nil
		if dependent {
			census.Dependent++
		}

		switch {
		case claim && !dependent:
			findings = append(findings, fmt.Sprintf(
				"поле %s: контракт заявляет подстановку системной возможностью, "+
					"а домен её так не судит (арендаторская политика: %v; платформенная: %v)",
				field, tenantErr, platformErr))
		case !claim && dependent:
			findings = append(findings, fmt.Sprintf(
				"поле %s: домен ограничивает подстановку ярусом роли, "+
					"а контракт об этом молчит (арендаторская политика: %v)", field, tenantErr))
		}
	}
	if inRule {
		return nil, census, fmt.Errorf("объявление message Rule не закрыто — разбор недостоверен")
	}
	return findings, census, nil
}

// TestRuleWildcardContractAgreesWithTheDomain — вердикт о НАСТОЯЩЕМ дереве.
//
// Способность падать доказывает не этот прогон, а инъекция
// (`rule_wildcard_contract_agrees_injection_test.go`).
func TestRuleWildcardContractAgreesWithTheDomain(t *testing.T) {
	text := readRoleContract(t)
	findings, census, err := auditRuleWildcardContract(text, ruleWildcardProbes())
	if err != nil {
		t.Fatalf("разбор контракта не отработал: %v", err)
	}
	t.Logf("объём осмотренного: %s", census)

	// Премисы: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	if census.Fields == 0 {
		t.Fatal("полей message Rule прочитано 0 — обход пуст, вердикт беспредметен")
	}
	if census.Probed == 0 {
		t.Fatal("ни одно поле не спрошено у домена — сверка не состоялась ни разу")
	}
	if census.Dependent == 0 {
		t.Fatal("политикозависимых подстановок по факту 0 — производители поведения " +
			"негодны: ярус роли не различается ни на одном поле")
	}

	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}

// roleContractRel — координата контракта роли ОТНОСИТЕЛЬНО дерева, которое его
// несёт. Объявлена здесь и одна.
var roleContractRel = filepath.Join("proto", "kacho", "cloud", "iam", "v1", "role.proto")

// readRoleContract читает контракт роли из дерева продукта.
//
// Контракты живут в `proto/` КОРНЯ и остаются там при выносе iam отдельным
// репозиторием.
func readRoleContract(t *testing.T) string {
	t.Helper()
	path := filepath.Join(contractTreeRoot(t), roleContractRel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("контракт роли не прочитан (%s): %v", path, err)
	}
	return string(b)
}

// contractTreeRoot — ближайший предок, который НЕСЁТ контракт.
//
// # Здесь стоял подъём до ближайшего `go.mod`, и он перестал попадать
//
// Пока сервис был пакетом монорепо, ближайший `go.mod` и был корнем, несущим
// `proto/`. С выносом iam отдельным модулем ближайшим стал `services/iam/go.mod`
// — каталога `proto/` под ним нет, и гейт перестал выносить вердикт вовсе.
// Прежний комментарий этот случай ПРЕДСКАЗЫВАЛ («путь меняется вместе с
// зависимостью»), но подъём остался прежним: предупреждение пережило свой
// предмет и молчало, потому что отказ выглядел как обычное красное.
//
// Якорь теперь — САМ КОНТРАКТ, а не признак модуля: он не зависит от того,
// сколько `go.mod` лежит по дороге.
//
// # Граница названа: отдельный клон сервиса контракта НЕ несёт
//
// Тогда его придётся брать из кеша модулей, и это другой вопрос — вопрос ЛИНИИ
// выноса, а не этого гейта. Здесь такой прогон обязан назваться словами, а не
// притвориться находкой о дереве.
func contractTreeRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, serr := os.Stat(filepath.Join(dir, roleContractRel)); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: над рабочим каталогом нет дерева, несущего %s — "+
		"в отдельном клоне сервиса контракт приезжает зависимостью, и читать его "+
		"из дерева нечем. Это не вердикт о продукте", roleContractRel)
	return ""
}

// moduleRootDir — ближайший предок с `go.mod`: корень МОДУЛЯ сервиса.
//
// Отдельно от `contractTreeRoot` намеренно: якоря разные. Страница арендатора
// живёт ВНУТРИ модуля, контракт — НАД ним, и один подъём обслужить оба не может.
func moduleRootDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("не найден корень модуля (каталог с go.mod) над %s", dir)
	return ""
}

// TestTenantRoleVerbWildcard_BothSides — НАБЛЮДАЕМОЕ поведение, которое
// контракт теперь объявляет (задача продукта #1961).
//
// Обе стороны обязательны: односторонняя проба зеленела бы и на домене,
// отвергающем всё, и на домене, принимающем всё.
func TestTenantRoleVerbWildcard_BothSides(t *testing.T) {
	mods := fixtureModules()
	tenant := domain.TenantPolicy()

	sole := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}
	if err := sole.Validate(tenant, mods); err != nil {
		t.Errorf("арендаторское правило с verbs=[\"*\"] отвергнуто, а контракт объявляет "+
			"его законным: %v", err)
	}

	withPeer := domain.Rule{
		Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*", "get"},
	}
	err := withPeer.Validate(tenant, mods)
	if err == nil {
		t.Fatal("verbs=[\"*\", \"get\"] принято, а контракт объявляет подстановку " +
			"единственным элементом")
	}
	if !strings.Contains(err.Error(), "wildcard '*' must be sole element") {
		t.Errorf("отказ не называет действительное правило (единственный элемент): %v", err)
	}
	t.Logf("обе стороны: [\"*\"] принято · [\"*\",\"get\"] отвергнуто с %q", err)
}
