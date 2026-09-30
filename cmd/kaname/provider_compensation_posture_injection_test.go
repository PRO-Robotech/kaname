// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_posture_injection_test.go — доказательство, что судья
// тела корня (`judgeCompensationScheduling`, задача kaname#368) СПОСОБЕН упасть
// и СПОСОБЕН смолчать.
//
// Пара «красное · зелёное» снята и на ЖИВОМ дереве: снятая из `serve.go`
// проверка задачи на nil дала находку с координатой употребления, возвращённая —
// молчание при той же переписи. Здесь то же свойство закреплено воспроизводимо,
// на синтетике: доказательство, требующее испортить рабочую копию, в конвейере
// не исполняется никогда.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый дефект отличается от живой формы РОВНО одним фактом: снята проверка,
// перевёрнут оператор, в ветвь «задачи нет» поставлено одно действие, условие
// дополнено одним членом. У законных форм, которых живое дерево сегодня не
// пишет (без ветви «задачи нет», обратный порядок операндов, скобки), — свой
// случай молчания: распознаватель, знающий одну форму, краснел бы на
// исправном корне, а знающий меньше — молчал бы на дефектном.
//
// Судится не только «покраснел», но и ЧТО назвал: причину словами и строку
// дефекта. Находка, называющая не ту строку, чинится не там.
package main

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// compensationMarker — метка строки, которую находка обязана назвать.
const compensationMarker = "/*here*/"

// compensationRoot — синтетическое тело корня: связывание результата сборщика,
// проверка ошибки и переданный фрагмент постановки задачи.
func compensationRoot(fragment string) string {
	return `package main

func runServe() error {
	compensationDrainerTask, cerr := buildProviderCompensationDrainer(pool, cfg, obs, roadObs, logger)
	if cerr != nil {
		return fmt.Errorf("provider compensation drainer wiring: %w", cerr)
	}
` + fragment + `
	tasks = append(tasks, func() error { return metricsScan(taskCtx) })
	return group.Wait()
}
`
}

// Живая форма `serve.go`: ветвь «задачи нет» называет отсутствие, ветвь
// «задача есть» ставит задачу в группу.
const compensationLiveForm = `
	if compensationDrainerTask == nil {
		logger.Info("дренаж очереди компенсаций не поднят")
	} else {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`

type compensationInjectionCase struct {
	name        string
	src         string
	wantErr     bool     // отказ предпосылки: «не выполнилось», а не находка
	wantPhrases []string // каждая — хотя бы в одной находке; пусто — молчание
	wantCount   int      // сколько находок
	wantUses    int      // перепись: употреблений задачи
	wantGuarded int      // перепись: из них под проверкой «задача есть»
}

func compensationInjectionCases() []compensationInjectionCase {
	return []compensationInjectionCase{
		// ── молчание: законные формы ───────────────────────────────────────
		{
			name: "живая форма — молчание", src: compensationRoot(compensationLiveForm),
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "проверка «задача есть» без ветви «задачи нет» — молчание",
			src: compensationRoot(`
	if compensationDrainerTask != nil {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "обратный порядок операндов и скобки — молчание",
			src: compensationRoot(`
	if (nil == compensationDrainerTask) {
		logger.Info("дренаж очереди компенсаций не поднят")
	} else {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantUses: 1, wantGuarded: 1,
		},

		// ── находки: задача без проверки ───────────────────────────────────
		{
			name: "проверка снята — находка",
			src: compensationRoot(`
	tasks = append(tasks, func() error { return /*here*/compensationDrainerTask(taskCtx) })
`),
			wantPhrases: []string{"без проверки «задача есть»"}, wantCount: 1,
			wantUses: 1,
		},
		{
			name: "употребление ПОСЛЕ ветви проверки — находка",
			src: compensationRoot(`
	if compensationDrainerTask == nil {
		logger.Info("дренаж очереди компенсаций не поднят")
	}
	tasks = append(tasks, func() error { return /*here*/compensationDrainerTask(taskCtx) })
`),
			wantPhrases: []string{"без проверки «задача есть»"}, wantCount: 1,
			wantUses: 1,
		},
		{
			name: "оператор перевёрнут — задача ставится там, где её нет",
			src: compensationRoot(`
	if compensationDrainerTask == nil {
		tasks = append(tasks, func() error { return /*here*/compensationDrainerTask(taskCtx) })
	}
`),
			wantPhrases: []string{"без проверки «задача есть»", "действие вне словаря"},
			wantCount:   2, wantUses: 1,
		},
		{
			name: "сравнение в составном условии — находка",
			src: compensationRoot(`
	if /*here*/compensationDrainerTask == nil || drainDisabled {
		logger.Info("дренаж очереди компенсаций не поднят")
	} else {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantPhrases: []string{"вне условия ветви", "без проверки «задача есть»"},
			wantCount:   2, wantUses: 1,
		},

		// ── находки: ветвь «задачи нет» отказывает либо ставит работу ─────
		{
			name: "в ветви «задачи нет» корень возвращается — находка",
			src: compensationRoot(`
	if compensationDrainerTask == nil {
		/*here*/return fmt.Errorf("дренажа компенсаций нет")
	} else {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantPhrases: []string{"корень возвращается"}, wantCount: 1,
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "в ветви «задачи нет» гасится процесс — находка",
			src: compensationRoot(`
	if compensationDrainerTask == nil {
		logger.Info("дренаж очереди компенсаций не поднят")
		/*here*/triggerShutdown()
	} else {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantPhrases: []string{"действие вне словаря"}, wantCount: 1,
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "в ветви «задачи нет» ставится работа — находка",
			src: compensationRoot(`
	if compensationDrainerTask == nil {
		/*here*/tasks = append(tasks, func() error { return nil })
	} else {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantPhrases: []string{"действие вне словаря"}, wantCount: 1,
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "ветвь «задачи нет» продолжена условием — находка",
			src: compensationRoot(`
	if compensationDrainerTask != nil {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	} else /*here*/if drainRequired {
		logger.Info("дренаж очереди компенсаций не поднят")
	}
`),
			wantPhrases: []string{"продолжена условием"}, wantCount: 1,
			wantUses: 1, wantGuarded: 1,
		},

		// ── находки: задача потеряна либо подменена ────────────────────────
		{
			name: "задача собрана и не поставлена — находка",
			src: `package main

func runServe() error {
	compensationDrainerTask, cerr := /*here*/buildProviderCompensationDrainer(pool, cfg, obs, roadObs, logger)
	if cerr != nil {
		return cerr
	}
	if compensationDrainerTask == nil {
		logger.Info("дренаж очереди компенсаций не поднят")
	}
	return group.Wait()
}
`,
			wantPhrases: []string{"собрана и не поставлена"}, wantCount: 1,
		},
		{
			name: "задача переприсвоена — находка",
			src: compensationRoot(`
	/*here*/compensationDrainerTask = noopDrainer
` + compensationLiveForm),
			wantPhrases: []string{"связано второй раз"}, wantCount: 1,
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "имя задачи затенено в ветви — находка",
			src: compensationRoot(`
	if compensationDrainerTask != nil {
		/*here*/compensationDrainerTask := wrapDrainer(nil)
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
`),
			wantPhrases: []string{"связано второй раз"}, wantCount: 1,
			wantUses: 1, wantGuarded: 1,
		},
		{
			name: "задача выброшена при связывании — находка",
			src: `package main

func runServe() error {
	_, cerr := /*here*/buildProviderCompensationDrainer(pool, cfg, obs, roadObs, logger)
	if cerr != nil {
		return cerr
	}
	return group.Wait()
}
`,
			wantPhrases: []string{"связывание результата сборщика вне словаря"}, wantCount: 1,
		},
		{
			name: "сборщик взят значением, а не вызовом — находка",
			src: `package main

func runServe() error {
	build := /*here*/buildProviderCompensationDrainer
	compensationDrainerTask, cerr := build(pool, cfg, obs, roadObs, logger)
	if cerr != nil {
		return cerr
	}
	if compensationDrainerTask != nil {
		tasks = append(tasks, func() error { return compensationDrainerTask(taskCtx) })
	}
	return group.Wait()
}
`,
			wantPhrases: []string{"упомянут не вызовом"}, wantCount: 1,
		},
		{
			name: "сборщик позван дважды — находка",
			src: compensationRoot(compensationLiveForm + `
	second, serr := /*here*/buildProviderCompensationDrainer(pool, cfg, obs, roadObs, logger)
	_, _ = second, serr
`),
			wantPhrases: []string{"2 раз(а)"}, wantCount: 1,
		},

		// ── предпосылка: судить нечего ─────────────────────────────────────
		{
			name: "тело корня не зовёт сборщик — не выполнилось",
			src: `package main

func runServe() error {
	// buildProviderCompensationDrainer(pool, cfg, obs, roadObs, logger) — только проза
	return group.Wait()
}
`,
			wantErr: true,
		},
		{
			name: "тела корня нет — не выполнилось",
			src: `package main

func serve() error {
	compensationDrainerTask, cerr := buildProviderCompensationDrainer(pool, cfg, obs, roadObs, logger)
	_, _ = compensationDrainerTask, cerr
	return nil
}
`,
			wantErr: true,
		},
	}
}

func TestCompensationDrainerPostureInjection_JudgeRedsEveryDefectAndKeepsQuietOnLawfulForms(t *testing.T) {
	for _, tc := range compensationInjectionCases() {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "serve.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("синтетика не разобрана: %v", err)
			}
			census, findings, jerr := judgeCompensationScheduling(fset, file)
			t.Logf("%s", census.Summary())
			for _, f := range findings {
				t.Logf("находка: %s", f)
			}

			if tc.wantErr {
				if jerr == nil {
					t.Fatalf("предпосылки нет, а судья вынес вердикт (находок %d) — "+
						"«ноль находок» стал бы неотличим от «ноль прочитанного»", len(findings))
				}
				return
			}
			if jerr != nil {
				t.Fatalf("судья отказал в предпосылке на синтетике, где предмет есть: %v", jerr)
			}
			if len(findings) != tc.wantCount {
				t.Fatalf("находок %d, ожидалось %d", len(findings), tc.wantCount)
			}
			if census.Uses != tc.wantUses || census.Guarded != tc.wantGuarded {
				t.Fatalf("перепись: употреблений %d под проверкой %d, ожидалось %d и %d",
					census.Uses, census.Guarded, tc.wantUses, tc.wantGuarded)
			}
			for _, phrase := range tc.wantPhrases {
				if !anyContains(findings, phrase) {
					t.Errorf("ни одна находка не называет причину %q — судья краснеет, "+
						"но не говорит, что чинить", phrase)
				}
			}
			if line := markerLine(tc.src); line > 0 {
				coord := "serve.go:" + strconv.Itoa(line) + ":"
				if !anyContains(findings, coord) {
					t.Errorf("ни одна находка не называет строку дефекта %s — чинить "+
						"пошли бы не туда", coord)
				}
			}
		})
	}
}

func anyContains(findings []string, sub string) bool {
	for _, f := range findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

// markerLine — номер строки с меткой дефекта, либо 0.
func markerLine(src string) int {
	for i, line := range strings.Split(src, "\n") {
		if strings.Contains(line, compensationMarker) {
			return i + 1
		}
	}
	return 0
}

// Обход пакета: упоминание сборщика вне тела корня — находка, объявление и
// тело корня — молчание.
func TestCompensationDrainerPostureInjection_SweepRedsACallerOutsideTheRootAndSeesTheDeclaration(t *testing.T) {
	const declAndRoot = `package main

func buildProviderCompensationDrainer() (func(context.Context) error, error) { return nil, nil }

func runServe() error {
	compensationDrainerTask, cerr := buildProviderCompensationDrainer()
	_, _ = compensationDrainerTask, cerr
	return nil
}
`
	const helperCallsTheBuilder = `package main

func startCompensation() {
	task, _ := /*here*/buildProviderCompensationDrainer()
	go task(ctx)
}
`
	// ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, другой сборщик.
	const helperCallsAnotherBuilder = `package main

func startMail() {
	task, _ := buildInviteMailDrainer()
	go task(ctx)
}
`
	for _, tc := range []struct {
		name      string
		src       string
		wantDecl  bool
		wantCount int
	}{
		{"объявление и тело корня — молчание", declAndRoot, true, 0},
		{"помощник зовёт сборщик — находка", helperCallsTheBuilder, false, 1},
		{"помощник зовёт другой сборщик — молчание", helperCallsAnotherBuilder, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "helper.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("синтетика не разобрана: %v", err)
			}
			declSeen, refs, findings := judgeBuilderReferencesOutsideRoot(fset, file)
			t.Logf("объявление найдено: %t · упоминаний вне тела корня %d", declSeen, refs)
			if declSeen != tc.wantDecl {
				t.Fatalf("объявление найдено=%t, ожидалось %t — перепись не отличает "+
					"предмет от его отсутствия", declSeen, tc.wantDecl)
			}
			if len(findings) != tc.wantCount {
				t.Fatalf("находок %d, ожидалось %d: %v", len(findings), tc.wantCount, findings)
			}
			if line := markerLine(tc.src); line > 0 {
				coord := "helper.go:" + strconv.Itoa(line) + ":"
				if !anyContains(findings, coord) || !anyContains(findings, "вне тела runServe") {
					t.Errorf("находка не называет строку %s и причину: %v", coord, findings)
				}
			}
		})
	}
}
