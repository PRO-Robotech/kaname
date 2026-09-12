// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rule_policy_single_source_injection_test.go — доказательство, что гейт
// СПОСОБЕН упасть и СПОСОБЕН смолчать (порт одноимённой пробы репозитория
// платформы, снят там вынесением службы доступа — `kacho#2597`; задача
// продукта #1032).
//
// Инъекция подаёт вход синтетическим деревом: настоящее дерево править нельзя,
// а без подачи входа гейт остаётся утверждением о самом себе.
//
// Оси — четыре, и каждая своим входом:
//
//	второй литерал политики в чужом файле  → находка, называющая ФАЙЛ и СТРОКУ
//	литерал в своём файле                  → молчание (законный близнец)
//	вывод объявлен ДВАЖДЫ                   → находка про перечень
//	вывода нет вовсе                        → находка про перечень
//
// Законный близнец не украшение: без него гейт ловил бы форму («литерал есть»),
// а не существо («литерал не там»), и запретил бы самому носителю политики
// существовать.
package domain_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
)

// rulePolicyFixture — синтетическое дерево с каталогом домена.
//
// Возвращает путь к каталогу домена внутри синтетики — обход гейта зовётся
// именно с ним, а не с корнем репозитория.
func rulePolicyFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	domainDir := filepath.Join(root, "internal", "domain")
	for rel, body := range files {
		full := filepath.Join(domainDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("подготовить каталог %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("записать %s: %v", rel, err)
		}
	}

	// Состав гейт берёт у ИНДЕКСА, значит синтетика обязана быть
	// РЕПОЗИТОРИЕМ, а не каталогом. Репозиторий заводится ВНУТРИ `t.TempDir()`
	// и своим окружением — иначе `git init`/`git add`, исполненные в каталоге,
	// лежащем внутри родительского репозитория, писали бы в ЕГО индекс.
	git := func(args ...string) {
		t.Helper()
		cmd := gitenv.Command(root, args...)
		cmd.Env = append(cmd.Env,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-qm", "синтетика инъекции")
	return domainDir
}

// rulePolicyHome — законное содержимое своего файла: вывод плюс литералы.
const rulePolicyHome = `package domain

type policyTier uint8

const (
	tierUnset policyTier = iota
	tierTenant
	tierModule
	tierPlatform
)

type RulePolicy struct {
	tier  policyTier
	owner string
}

func PolicyOfRole(isSystem bool, ownerModule string) RulePolicy {
	if !isSystem {
		return RulePolicy{tier: tierTenant}
	}
	if ownerModule != "" {
		return RulePolicy{tier: tierModule, owner: ownerModule}
	}
	return RulePolicy{tier: tierPlatform}
}
`

// rulePolicyFiller — соседние файлы домена: обход обязан прочитать больше
// одного, иначе порог переписи в пробе гейта не проверял бы ничего.
func rulePolicyFiller() map[string]string {
	out := map[string]string{}
	for _, name := range []string{"role.go", "rule.go", "permission.go", "labels.go", "name.go"} {
		out[name] = "package domain\n\n// наполнитель обхода\n"
	}
	return out
}

func rulePolicyScan(t *testing.T, files map[string]string) []string {
	t.Helper()
	all := rulePolicyFiller()
	for k, v := range files {
		all[k] = v
	}
	domainDir := rulePolicyFixture(t, all)
	sites, census, err := scanRulePolicySites(domainDir)
	if err != nil {
		t.Fatalf("обход синтетического дерева не состоялся: %v", err)
	}
	t.Logf("перепись синтетики: файлов %d · литералов %d · выводов %d",
		census.FilesRead, census.Literals, census.Derivers)
	return rulePolicyFindings(sites, census)
}

// TestRulePolicyGateIsSilentOnItsOwnHome — законный близнец: литералы в своём
// файле молчат.
func TestRulePolicyGateIsSilentOnItsOwnHome(t *testing.T) {
	t.Parallel()
	findings := rulePolicyScan(t, map[string]string{
		rulePolicyHomeFile: rulePolicyHome,
	})
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на СВОЁМ файле — он ловит форму, а не существо:\n%s",
			strings.Join(findings, "\n"))
	}
}

// TestRulePolicyGateRedsOnASecondDeclarationSite — инъекция: политика
// собирается вторым местом.
func TestRulePolicyGateRedsOnASecondDeclarationSite(t *testing.T) {
	t.Parallel()
	const intruder = "rule.go"
	findings := rulePolicyScan(t, map[string]string{
		rulePolicyHomeFile: rulePolicyHome,
		intruder: `package domain

func relaxedForSeed() RulePolicy { return RulePolicy{tier: tierPlatform} }
`,
	})
	if len(findings) == 0 {
		t.Fatal("второе место сборки политики принято — гейт не способен упасть")
	}
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, intruder) {
		t.Errorf("находка не называет ФАЙЛ — по ней нечего чинить:\n%s", joined)
	}
	if !strings.Contains(joined, ":3:") {
		t.Errorf("находка не называет СТРОКУ:\n%s", joined)
	}
	if strings.Contains(joined, rulePolicyHomeFile+":") {
		t.Errorf("инъекция уронила заодно СВОЙ файл — красное пришло не только от "+
			"проверяемого:\n%s", joined)
	}
}

// TestRulePolicyGateRedsOnASecondDeriver — вторая функция вывода означает
// второй словарь политик.
func TestRulePolicyGateRedsOnASecondDeriver(t *testing.T) {
	t.Parallel()
	findings := rulePolicyScan(t, map[string]string{
		rulePolicyHomeFile: rulePolicyHome,
		"role.go": `package domain

func PolicyOfRole(isSystem bool, owner string) RulePolicy { return RulePolicy{} }
`,
	})
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "объявлений PolicyOfRole — 2") {
		t.Fatalf("второе объявление вывода принято:\n%s", joined)
	}
}

// TestRulePolicyGateRedsWhenTheDeriverIsGone — обратная сторона той же оси:
// вывода нет вовсе. Без неё «ровно одно» проверялось бы в одну сторону.
func TestRulePolicyGateRedsWhenTheDeriverIsGone(t *testing.T) {
	t.Parallel()
	findings := rulePolicyScan(t, map[string]string{
		rulePolicyHomeFile: `package domain

type RulePolicy struct{ tier uint8 }

func TenantPolicy() RulePolicy { return RulePolicy{} }
`,
	})
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "объявлений PolicyOfRole — 0") {
		t.Fatalf("отсутствие вывода принято:\n%s", joined)
	}
}
