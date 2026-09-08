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
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
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

// roleContractRel — координата контракта роли ОТ КОРНЯ ДЕРЕВА ПЛАТФОРМЫ.
// Объявлена здесь и одна.
const roleContractRel = "proto/kaname/cloud/iam/v1/role.proto"

// readRoleContract читает контракт роли — ЛИБО называет третий исход.
//
// # Предпосылку назначает ДЕТЕКТОР ПОСАДКИ, а не наличие файла
//
// Контракты живут в `proto/` корня платформы и в поставку модуля не входят BY
// CONSTRUCTION: у арендатора, склонировавшего модуль, их не будет. Значит здесь
// два законных исхода, и второй — «условие не создано», а не находка о продукте.
//
// Кто их различает — вопрос не оформления. Прежняя редакция поднималась по
// дереву своим циклом и объявляла условие созданным, ЕСЛИ НАХОДИЛА ФАЙЛ. Клон,
// стоящий под чужим деревом с той же координатой, читал ЧУЖОЙ контракт и
// печатал находку о нём — измерено: та же посадка, две пробы, соседняя (через
// `platformtree`) назвала «УСЛОВИЕ НЕ СОЗДАНО» и вышла кодом 0, эта вынесла
// вердикт о чужом дереве и вышла кодом 1 (задача #2160).
//
// `platformtree.RequirePath` спрашивает ПОСАДКУ — лежит ли модуль в каталоге
// модулей ЭТОГО дерева, — и потому отвечает одинаково при любом соседе сверху.
// Заодно у метки третьего исхода остаётся ОДИН производитель: перепись
// `scripts/test-standalone.sh` считает по ней, и вторая её редакция разошлась бы
// с первой молча.
func readRoleContract(t *testing.T) string {
	t.Helper()
	path := platformtree.RequirePath(t, roleContractRel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("контракт роли не прочитан (%s): %v", path, err)
	}
	return string(b)
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
