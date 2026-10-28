// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ci_wiring_test.go — адъюдикатор ЗОВЁТСЯ, и зовётся ТАМ, ГДЕ ИСТЕКАЕТ ЕГО ПРЕДМЕТ.
//
// Пробы рядом доказывают, что ядро способно упасть. Они ничего не говорят о том,
// исполняется ли оно: гейт, не провязанный ни одним шагом, зелен by construction
// и неотличим от исправного. Здесь судится ОБЪЯВЛЕНИЕ конвейера.
//
// РАЗБОРОМ YAML, А НЕ ПОДСТРОКОЙ. Имя шага и слово `buf breaking` встречаются в
// комментариях объявления — проверка по подстроке считала бы собственное
// объяснение. Тот же порядок, что требует корпус от всякого гейта, читающего
// объявление конвейера.
package declaredbreak_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const workflowPath = "../../.github/workflows/ci.yml"

type wfStep struct {
	Name string            `yaml:"name"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Env  map[string]string `yaml:"env"`
}

type wfJob struct {
	Steps []wfStep `yaml:"steps"`
	If    string   `yaml:"if"`
}

type workflow struct {
	On   map[string]any   `yaml:"on"`
	Jobs map[string]wfJob `yaml:"jobs"`
}

func readWorkflow(t *testing.T) workflow {
	t.Helper()
	body, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: объявление конвейера не прочитано: %v", err)
	}
	var wf workflow
	if err := yaml.Unmarshal(body, &wf); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: объявление не разобрано: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("в объявлении не прочитано ни одного задания — вердикт беспредметен")
	}
	return wf
}

// adjudicationSteps — шаги, ИСПОЛНЯЮЩИЕ адъюдикацию. Опознаются по вызову
// испытуемого в теле `run:`, а не по имени шага: имя правят свободно, и проверка
// по нему краснела бы на переименовании и молчала бы на снятии вызова.
func adjudicationSteps(wf workflow) map[string][]wfStep {
	out := map[string][]wfStep{}
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if strings.Contains(s.Run, "declaredbreak/cmd/adjudicate-declared-breaks") {
				out[name] = append(out[name], s)
			}
		}
	}
	return out
}

// TestAdjudicationIsWiredIntoThePipeline — испытуемый ЗОВЁТСЯ.
func TestAdjudicationIsWiredIntoThePipeline(t *testing.T) {
	wf := readWorkflow(t)
	steps := adjudicationSteps(wf)
	total := 0
	for _, ss := range steps {
		total += len(ss)
	}
	t.Logf("осмотрено заданий %d · шагов адъюдикации %d в заданиях %v",
		len(wf.Jobs), total, keysOf(steps))
	if total == 0 {
		t.Fatal("адъюдикатор не зовёт НИ ОДИН шаг конвейера — его зелёное ничего не " +
			"утверждает: гейт, который не исполняется, неотличим от исправного")
	}
}

func keysOf(m map[string][]wfStep) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestGateRunsWhereItsSubjectExpires — ШАГ НЕ СУЖЕН СОБЫТИЕМ.
//
// Предмет записи перечня истекает при ВЛИВАНИИ, а не при правке контракта: база
// сравнения поднимается, и разрыв становится историей. Сузи шаг до
// `pull_request` — и проверка не смотрит ровно туда, где её предмет истекает.
func TestGateRunsWhereItsSubjectExpires(t *testing.T) {
	wf := readWorkflow(t)

	// Конвейер обязан вообще запускаться на push в ствол.
	if _, ok := wf.On["push"]; !ok {
		t.Fatal("конвейер не запускается на push — адъюдикация не увидит ствола ни разу")
	}

	steps := adjudicationSteps(wf)
	if len(steps) == 0 {
		t.Fatal("шагов адъюдикации нет — ось беспредметна, и её молчание неотличимо от смерти")
	}
	for job, ss := range steps {
		if cond := wf.Jobs[job].If; strings.Contains(cond, "event_name") {
			t.Errorf("задание %s сужено событием (%q) — на стволе адъюдикация не "+
				"исполнится, и истёкшая запись перечня не будет названа никогда", job, cond)
		}
		for _, s := range ss {
			if strings.Contains(s.If, "event_name") {
				t.Errorf("шаг адъюдикации в задании %s сужен событием (%q) — предмет записи "+
					"перечня истекает при ВЛИВАНИИ, то есть ровно там, куда шаг перестал "+
					"смотреть", job, s.If)
			}
		}
	}
}

// TestGateReadsBufReturnCode — код возврата buf РАЗБИРАЕТСЯ.
//
// Без разбора сетевой отказ (`buf` не достал базу сравнения) даёт пустой вывод, и
// адъюдикатор честно печатает «находок 0» — то есть третья категория предъявлена
// как вердикт «разрывов нет».
func TestGateReadsBufReturnCode(t *testing.T) {
	wf := readWorkflow(t)
	steps := adjudicationSteps(wf)
	if len(steps) == 0 {
		t.Fatal("шагов адъюдикации нет — ось беспредметна")
	}
	for job, ss := range steps {
		for _, s := range ss {
			// Тело шага — `run:` и сценарий, который он зовёт (kaname#1055):
			// разбор кода buf живёт в сценарии.
			body := s.Run + stepScriptBody(t, s)
			if !strings.Contains(body, "buf breaking") {
				t.Errorf("задание %s: шаг зовёт адъюдикатор, но не зовёт buf breaking — "+
					"на вход ему нечего подать", job)
			}
			if !strings.Contains(body, "100") {
				t.Errorf("задание %s: код 100 («есть находки») не разбирается — штатный "+
					"вход адъюдикатора читался бы как отказ", job)
			}
			if !strings.Contains(body, "exit 2") {
				t.Errorf("задание %s: у шага нет третьего исхода — любой иной код buf "+
					"читался бы как «разрывов нет»", job)
			}
		}
	}
}

// TestLedgerIsNamedByTheStepThatReadsIt — перечень, который зовёт шаг, СУЩЕСТВУЕТ.
//
// Провязка в пустоту есть та же форма без содержания: шаг звал бы файл, которого
// нет, и выходил бы третьей категорией на каждом прогоне.
func TestLedgerIsNamedByTheStepThatReadsIt(t *testing.T) {
	wf := readWorkflow(t)
	named := 0
	for job, ss := range adjudicationSteps(wf) {
		for _, s := range ss {
			for _, tok := range strings.Fields(s.Run) {
				if !strings.HasSuffix(tok, ".yaml") || !strings.Contains(tok, "declared-breaks") {
					continue
				}
				named++
				if _, err := os.Stat("../../" + tok); err != nil {
					t.Errorf("задание %s зовёт перечень %s, которого в дереве нет: %v",
						job, tok, err)
				}
			}
		}
	}
	if named == 0 {
		t.Fatal("ни один шаг не называет перечня — адъюдикатор звался бы без предмета")
	}
	t.Logf("перечней названо шагами: %d", named)
}

// stepScriptBody — текст сценариев `tools/declaredbreak/*.sh`, которые зовёт шаг.
func stepScriptBody(t *testing.T, s wfStep) string {
	t.Helper()
	var b strings.Builder
	for _, tok := range strings.Fields(s.Run) {
		if !strings.HasPrefix(tok, "tools/declaredbreak/") || !strings.HasSuffix(tok, ".sh") {
			continue
		}
		body, err := os.ReadFile("../../" + tok)
		if err != nil {
			t.Fatalf("шаг зовёт сценарий %s, которого в дереве нет: %v", tok, err)
		}
		b.Write(body)
	}
	return b.String()
}

// TestStepNamesTheRequestHead — шаг передаёт сценарию голову ЗАПРОСА.
//
// На pull_request клон стоит на коммите слияния головы с базой; общий предок
// этого коммита с базой — сама база, и отказ назвал бы «предмет есть» у любой
// находки. Голова запроса приходит из события, а на push — коммит прогона
// (kaname#1055, пункт 5).
func TestStepNamesTheRequestHead(t *testing.T) {
	wf := readWorkflow(t)
	n := 0
	for job, ss := range adjudicationSteps(wf) {
		for _, s := range ss {
			n++
			v := s.Env["HEAD_SHA"]
			if !strings.Contains(v, "github.event.pull_request.head.sha") || !strings.Contains(v, "github.sha") {
				t.Errorf("задание %s: HEAD_SHA шага адъюдикации — %q, а не голова запроса "+
					"с откатом на коммит прогона", job, v)
			}
		}
	}
	if n == 0 {
		t.Fatal("шагов адъюдикации нет — ось беспредметна")
	}
}

// TestRequestBaseProbeRunsWhereBufIs — проба TestStepJudgesTheRequestAgainstItsBase
// ИСПОЛНЯЕТСЯ: под `-short` (задание unit) она пропускается, потому что сцене
// нужен buf. Значит в задании, где стоит адъюдикация, после установки buf обязан
// быть прогон пакета без `-short` — иначе её зелёное не наблюдал бы никто.
func TestRequestBaseProbeRunsWhereBufIs(t *testing.T) {
	wf := readWorkflow(t)
	jobs := adjudicationSteps(wf)
	if len(jobs) == 0 {
		t.Fatal("шагов адъюдикации нет — ось беспредметна")
	}
	for job := range jobs {
		bufAt, probeAt := -1, -1
		for i, s := range wf.Jobs[job].Steps {
			if strings.HasPrefix(s.Uses, "bufbuild/buf-setup-action@") && bufAt < 0 {
				bufAt = i
			}
			if strings.Contains(s.Run, "go test") && strings.Contains(s.Run, "./tools/declaredbreak/") &&
				!strings.Contains(s.Run, "-short") && strings.Contains(s.Run, "TestStepJudgesTheRequestAgainstItsBase") {
				probeAt = i
			}
		}
		switch {
		case bufAt < 0:
			t.Errorf("задание %s: buf не ставится — пробе базы запроса нечем сравнивать", job)
		case probeAt < 0:
			t.Errorf("задание %s: проба базы запроса не зовётся без -short — её пропуск под -short "+
				"оставил бы шаг без единого исполненного опыта", job)
		case probeAt < bufAt:
			t.Errorf("задание %s: проба зовётся до установки buf", job)
		}
	}
}
