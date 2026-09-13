// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// trunk_verdict_holder.go — РАЗБОР ПРОВЯЗКИ держателя вердикта ствола
// (задача PRO-Robotech/kaname#62).
//
// # ПРЕДМЕТ
//
// Ствол был красен ДВА ВЛИВАНИЯ ПОДРЯД, и красное не читалось никем. Держатель
// заведён; здесь проверяется не то, что он работает (это доказывает его
// собственная самопроверка инъекцией), а то, что он ОСТАНЕТСЯ ЗВАНЫМ и
// ОСТАНЕТСЯ ПОЛНЫМ.
//
// # ТРИ СВОЙСТВА, И КАЖДОЕ ЛОМАЕТСЯ СВОИМ СПОСОБОМ, МОЛЧА
//
//  1. ДЕРЖАТЕЛЯ ЗОВУТ. Снятый шаг не краснеет: процесс идёт как шёл, а красное
//     ствола снова остаётся без читателя;
//  2. ПЕРЕЧЕНЬ ЗАВИСИМОСТЕЙ ПОЛОН. `needs` выписан, а не выведен: заведут
//     двенадцатое задание — держатель его исхода не увидит и промолчит о
//     красном. Поэтому перечень сверяется с составом заданий процесса В ОБЕ
//     СТОРОНЫ;
//  3. САМОПРОВЕРКУ ЗОВУТ ДО ВЕРДИКТА. Держатель, потерявший способность
//     производить событие, молчит ровно так же, как исправный на зелёном стволе,
//     и различить их можно только инъекцией — то есть до того, как поверить
//     его молчанию.
//
// # ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ПОДСТРОКЕ
//
// Имя держателя встречается и в комментариях — в шапке самого задания, где оно
// объяснено. Гейт по подстроке зеленел бы на собственном объяснении. Здесь
// читается РАЗОБРАННЫЙ YAML: задания, их `needs`, их права и тела `run:` без
// строк оболочечных комментариев.

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// TrunkHolderScript — держатель вердикта ствола. ОДНО объявление координаты:
// вторая копия разошлась бы с первой молча.
const TrunkHolderScript = ".github/scripts/trunk-verdict-holder.sh"

// TrunkHolderJob — идентификатор задания, которое его зовёт.
const TrunkHolderJob = "trunkverdict"

// trunkWorkflowDoc — то немногое из объявления процесса, что нужно этому гейту.
type trunkWorkflowDoc struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		If          string            `yaml:"if"`
		Needs       []string          `yaml:"needs"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Run string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// TrunkHolderCensus — объём осмотренного.
type TrunkHolderCensus struct {
	// Jobs — заданий в процессе; Needed — сколько из них перечислено держателем.
	Jobs   int
	Needed int
	// Steps — шагов у держателя; RunBodies — из них с непустым телом.
	Steps      int
	RunBodies  int
	SelfTests  int
	Verdicts   int
	JobPerms   int
	FlowPerms  int
	HolderSeen bool
}

// String — перепись одной строкой.
func (c TrunkHolderCensus) String() string {
	return fmt.Sprintf("заданий процесса %d · перечислено держателем %d · держатель найден %t · "+
		"шагов %d (с телом %d) · вызовов самопроверки %d · вызовов вердикта %d · "+
		"прав задания %d · прав процесса %d",
		c.Jobs, c.Needed, c.HolderSeen, c.Steps, c.RunBodies, c.SelfTests, c.Verdicts,
		c.JobPerms, c.FlowPerms)
}

// AuditTrunkHolderWiring — вердикт о провязке держателя.
//
// Вынесено ЧИСТОЙ функцией от текста объявления затем, чтобы способность гейта
// упасть доказывалась подачей входа, а не чтением.
func AuditTrunkHolderWiring(raw string) ([]string, TrunkHolderCensus, error) {
	var doc trunkWorkflowDoc
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, TrunkHolderCensus{}, fmt.Errorf("объявление процесса не разобрано: %w", err)
	}
	census := TrunkHolderCensus{Jobs: len(doc.Jobs), FlowPerms: len(doc.Permissions)}
	if census.Jobs == 0 {
		return nil, census, fmt.Errorf("в объявлении процесса ноль заданий — вердикт беспредметен")
	}

	holder, ok := doc.Jobs[TrunkHolderJob]
	if !ok {
		return []string{fmt.Sprintf(
			"задания %q в процессе НЕТ: красное ствола снова остаётся без читателя — "+
				"перечень прогонов смотрят по одному, и первый в списке не вердикт линии",
			TrunkHolderJob)}, census, nil
	}
	census.HolderSeen = true
	census.Needed = len(holder.Needs)
	census.Steps = len(holder.Steps)
	census.JobPerms = len(holder.Permissions)

	var findings []string

	// (1) ДЕРЖАТЕЛЯ ЗОВУТ — и зовут ДВАЖДЫ: самопроверкой и вердиктом.
	for _, st := range holder.Steps {
		body := executableLines(st.Run)
		if strings.TrimSpace(body) == "" {
			continue
		}
		census.RunBodies++
		if !strings.Contains(body, TrunkHolderScript) {
			continue
		}
		if strings.Contains(body, "--self-test") {
			census.SelfTests++
			continue
		}
		census.Verdicts++
	}
	if census.SelfTests == 0 {
		findings = append(findings, fmt.Sprintf(
			"самопроверка %s --self-test не зовётся: держатель, потерявший способность "+
				"производить событие, молчит ровно так же, как исправный на зелёном стволе",
			TrunkHolderScript))
	}
	if census.Verdicts == 0 {
		findings = append(findings, fmt.Sprintf(
			"вердикт %s не зовётся ни одним шагом задания %q — провязка есть форма без "+
				"содержания", TrunkHolderScript, TrunkHolderJob))
	}

	// (2) ПЕРЕЧЕНЬ ЗАВИСИМОСТЕЙ ПОЛОН — сверка с составом заданий В ОБЕ СТОРОНЫ.
	declared := map[string]bool{}
	for _, n := range holder.Needs {
		declared[n] = true
	}
	var missing, extra []string
	for name := range doc.Jobs {
		if name == TrunkHolderJob {
			if declared[name] {
				extra = append(extra, name+" (сам держатель)")
			}
			continue
		}
		if !declared[name] {
			missing = append(missing, name)
		}
	}
	for n := range declared {
		if _, ok := doc.Jobs[n]; !ok {
			extra = append(extra, n+" (задания с таким именем нет)")
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		findings = append(findings, fmt.Sprintf(
			"держатель НЕ ВИДИТ исхода заданий: %s. Их красное пройдёт мимо него молча — "+
				"перечень `needs` выписан, а не выведен, и потому стареет с каждым новым "+
				"заданием", strings.Join(missing, ", ")))
	}
	if len(extra) > 0 {
		findings = append(findings, fmt.Sprintf(
			"держатель перечисляет то, чего судить не может: %s", strings.Join(extra, ", ")))
	}

	// (3) ЗАДАНИЕ ИДЁТ НА СТВОЛЕ И ТОЛЬКО ТАМ, и исход соседей его не отменяет.
	if !strings.Contains(holder.If, "always()") {
		findings = append(findings, "условие задания не несёт always(): умолчание `if: success()` "+
			"снимает держателя ровно тогда, когда он нужен — на красном стволе")
	}
	if !strings.Contains(holder.If, "refs/heads/main") {
		findings = append(findings, "условие задания не сужено по стволу: на запросе слияния "+
			"держателя заводить не из чего — там красное видно тому, кто его открыл")
	}

	// (4) ПРАВО ПИСАТЬ ЗАДАЧИ — У ЗАДАНИЯ, А НЕ У ПРОЦЕССА.
	if holder.Permissions["issues"] != "write" {
		findings = append(findings, "у задания нет права `issues: write` — держателю нечем "+
			"произвести событие, и его молчание будет означать отказ, а не зелёный ствол")
	}
	if doc.Permissions["issues"] == "write" {
		findings = append(findings, "право `issues: write` выдано ВСЕМУ процессу: поверхность "+
			"шире достаточной — писать задачи нужно одному заданию")
	}
	return findings, census, nil
}

// executableLines — тело `run:` без строк оболочечных комментариев.
//
// Своя реализация, а не вызов соседа: тому нужен разбор всего процесса, а здесь
// уже есть разобранный шаг. Предмет тот же и потому назван так же — проверка,
// читающая комментарий как код, краснеет на собственном объяснении.
func executableLines(run string) string {
	var code []string
	for _, ln := range strings.Split(run, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		code = append(code, ln)
	}
	return strings.Join(code, "\n")
}
