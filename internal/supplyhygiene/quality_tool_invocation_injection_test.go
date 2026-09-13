// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quality_tool_invocation_injection_test.go — доказательство, что гейт согласия
// обращений СПОСОБЕН упасть и способен СМОЛЧАТЬ.
//
// Инъекция подаёт вход, а не читает код. Каждый отрицательный случай меняет
// РОВНО ОДИН факт против своего положительного близнеца: иначе неизвестно, какой
// из двух дал красное, и вердикт недействителен, оставаясь на вид зелёным.
//
// Мир строится КОПИЕЙ настоящего дерева службы, а не выдумывается: синтетика,
// собранная из частей, доказывает работу механизма на синтетике.
//
// ЗАКОННЫЕ БЛИЗНЕЦЫ ВЫНЕСЕНЫ В ОТДЕЛЬНЫЙ РАЗДЕЛ И ИХ ЧЕТЫРЕ. Гейт судит
// исполняемую часть, и доказывать это обязана проба, а не комментарий: без неё
// первое же красное на чужом объяснении гейт бы и отключило.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

// qualityWorldFiles — что копируется в мир. Гейт читает рецепт, каталог
// объявлений и названную конфигурацию — больше ничего.
var qualityWorldFiles = []string{
	qualityMakefile,
	".github/golangci.yml",
	qualityWorkflowDir + "/ci.yml",
	qualityWorkflowDir + "/docker-build.yml",
	qualityWorkflowDir + "/e2e-newman.yml",
}

// qualityRecipeLine — строка рецепта, несущая ЕДИНСТВЕННОЕ судящее обращение
// службы. Она же — предмет одно-фактных правок ниже.
const qualityRecipeLine = "\tgolangci-lint run --timeout=10m --config=.github/golangci.yml ./..."

// qualityCIInvocation — обращение задания конвейера, дословно.
const qualityCIInvocation = "golangci-lint run --timeout=10m --config=.github/golangci.yml"

func qualityWorld(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// База ПРИВЕДЁННАЯ, а не выведенная: корень спрашивается у детектора, а не
	// собирается относительным путём от каталога пакета. Этого требует гейт
	// координат (`internal/domain`), и требует по существу: выведенная база
	// зависит от места вызова, поэтому та же координата читалась бы из разных
	// деревьев в зависимости от того, откуда позвали, — и вердикт стал бы
	// свойством рабочего каталога, а не коммита.
	moduleRoot, rootErr := treeroot.ModuleRootFrom(".")
	if rootErr != nil {
		t.Fatalf("предпосылка инъекции не выполняется: корень модуля не назван: %v", rootErr)
	}

	for _, rel := range qualityWorldFiles {
		raw, err := os.ReadFile(filepath.Join(moduleRoot, rel))
		if err != nil {
			t.Fatalf("предпосылка инъекции не выполняется: %s не прочитан у службы: %v", rel, err)
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("каталог не заведён: %v", err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatalf("файл не записан: %v", err)
		}
	}
	return root
}

// qualitySubst — ОДНА текстовая подмена в названном файле мира. Отсутствие
// образца — отказ подготовки, а не тихая правка нуля мест: инъекция, ничего не
// изменившая, доказала бы лишь то, что гейт молчит на нетронутом дереве.
func qualitySubst(t *testing.T, root, rel, old, new string) {
	t.Helper()
	p := filepath.Join(root, rel)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	s := string(raw)
	if strings.Count(s, old) != 1 {
		t.Fatalf("подготовка не удалась: образец встречается %d раз, а не единожды — "+
			"инъекция перестала быть одно-фактной:\n%s", strings.Count(s, old), old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(s, old, new, 1)), 0o644); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
}

// qualityRequireSilent — гейт СМОЛЧАЛ. Половина доказательства, без которой
// проверка ловила бы форму, а не существо: первый ложный срабат её отключит.
func qualityRequireSilent(t *testing.T, findings []string, why string) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (%s):\n%s", why, strings.Join(findings, "\n"))
	}
}

// ── КОНТРОЛЬ ────────────────────────────────────────────────────────────────
// Без него всякое красное ниже могло бы приходить от копирования, а не от
// внесённого дефекта.
func TestQualityInjectionControl_UntouchedWorldIsSilent(t *testing.T) {
	t.Parallel()
	census, invocations, pins, findings := scanQualityToolInvocations(qualityWorld(t))
	if len(findings) != 0 {
		t.Fatalf("контроль не прошёл: нетронутая копия дала находки — красное ниже будет от копии, "+
			"а не от дефекта:\n%s", strings.Join(findings, "\n"))
	}
	if census.fromMakefile == 0 || census.fromWorkflows == 0 {
		t.Fatalf("контроль не прошёл: обращений в рецепте %d, в конвейере %d — одна из сторон "+
			"не прочитана, и молчание ниже было бы молчанием о нечитанном",
			census.fromMakefile, census.fromWorkflows)
	}
	if len(invocations) != 2 {
		t.Fatalf("контроль не прошёл: обращений найдено %d, ожидалось 2", len(invocations))
	}
	if len(pins) != 2 {
		t.Fatalf("контроль не прошёл: объявлений пина найдено %d, ожидалось 2 — "+
			"ось версии сверяла бы сторону саму с собой", len(pins))
	}
}

// ── ОСЬ 1: ЯВНОСТЬ ──────────────────────────────────────────────────────────

// Дословное восстановление дефекта #54: та самая строка рецепта, что стояла на
// стволе. Гейт обязан назвать её координатой.
func TestQualityInjection_RecipeWithoutConfigIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, qualityRecipeLine, "\tgolangci-lint run ./...")
	_, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, qualityMakefile)
	requireFindingMentions(t, findings, "--config")
}

func TestQualityInjection_WorkflowWithoutConfigIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityWorkflowDir+"/ci.yml", qualityCIInvocation,
		"golangci-lint run --timeout=10m")
	_, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, "ci.yml")
	requireFindingMentions(t, findings, "--config")
}

// ── ОСЬ 2: СОГЛАСИЕ ─────────────────────────────────────────────────────────

func TestQualityInjection_DifferentConfigsAreFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	// Файл кладётся рядом: иначе покраснела бы ось СУЩЕСТВОВАНИЯ, и случай
	// перестал бы быть одно-фактным.
	other := ".github/golangci-other.yml"
	if err := os.WriteFile(filepath.Join(root, other), []byte("version: \"2\"\n"), 0o644); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	qualitySubst(t, root, qualityMakefile, "--config=.github/golangci.yml ./...",
		"--config="+other+" ./...")
	_, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, other)
}

// ── ОСЬ 3: СУЩЕСТВОВАНИЕ ────────────────────────────────────────────────────

// Обе стороны переведены на ОДИН несуществующий файл: согласие сохранено,
// меняется ровно факт наличия. Инъекция, попутно рассогласовавшая стороны,
// доказывала бы ось 2, а не эту.
func TestQualityInjection_MissingConfigIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	ghost := ".github/golangci-ghost.yml"
	qualitySubst(t, root, qualityMakefile, "--config=.github/golangci.yml ./...", "--config="+ghost+" ./...")
	qualitySubst(t, root, qualityWorkflowDir+"/ci.yml", "--config=.github/golangci.yml", "--config="+ghost)
	_, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, ghost)
	requireFindingMentions(t, findings, "в дереве НЕТ")
}

// ── ОСЬ 4: ОБЛАСТЬ ──────────────────────────────────────────────────────────

func TestQualityInjection_DifferentScopeIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, "--config=.github/golangci.yml ./...",
		"--config=.github/golangci.yml ./internal/...")
	_, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, "./internal/...")
}

// Положительный близнец оси 4: конвейер позиционных доводов НЕ даёт, рецепт
// пишет `./...` — записано по-разному, означает одно. Без этой пробы ось 4
// краснела бы на нетронутом дереве, и её пришлось бы снять целиком.
func TestQualityInjection_DefaultScopeEqualsExplicitDotsIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, "--config=.github/golangci.yml ./...",
		"--config=.github/golangci.yml")
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "опущенная область есть `./...` по умолчанию инструмента")
}

// ── ОСЬ 5: ПИН ──────────────────────────────────────────────────────────────

func TestQualityInjection_DivergentPinIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, qualityPinVariable+" := v2.12.2",
		qualityPinVariable+" := v2.11.0")
	_, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, "v2.11.0")
}

// Положительный близнец оси 5: `v2.12.2` и `2.12.2` — одна версия. Конвейер
// ставит с приставкой, инструмент о себе сообщает без неё.
func TestQualityInjection_PinWithoutVPrefixIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, qualityPinVariable+" := v2.12.2",
		qualityPinVariable+" := 2.12.2")
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "приставка `v` версии не меняет")
}

// ── ЗАКОННЫЕ БЛИЗНЕЦЫ: гейт судит ИСПОЛНЯЕМУЮ часть ─────────────────────────

// Комментарий рецепта. Он не исполняется шеллом, и объяснение, положенное рядом
// с целью, обязано остаться законным: гейт, краснеющий на собственном
// объяснении, — ровно тот класс, который корпус ловит.
func TestQualityInjection_MakefileCommentIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, qualityRecipeLine,
		"# прежняя редакция звала `golangci-lint run ./...` — без конфигурации\n"+qualityRecipeLine)
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "комментарий рецепта обращением не является")
}

// Комментарий внутри самой строки рецепта — шелл его отбрасывает, и гейт обязан
// тоже. Случай отдельный от предыдущего: там комментарий стоит СТРОКОЙ, здесь —
// хвостом исполняемой строки.
func TestQualityInjection_TrailingShellCommentIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, qualityRecipeLine,
		qualityRecipeLine+" # не `golangci-lint run ./...`, как было раньше")
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "хвостовой комментарий шелла обращением не является")
}

// Комментарий YAML. Разборщик его отбрасывает by construction — проба это
// ДОКАЗЫВАЕТ, а не полагает.
func TestQualityInjection_WorkflowYamlCommentIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityWorkflowDir+"/ci.yml",
		"        run: "+qualityCIInvocation,
		"        # прежде здесь стояло `golangci-lint run ./...`\n        run: "+qualityCIInvocation)
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "комментарий YAML обращением не является")
}

// Подпись шага. `name:` читается человеком, а исполняется `run:` — и подписи в
// этом конвейере действительно несут имя инструмента.
func TestQualityInjection_WorkflowStepNameIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityWorkflowDir+"/ci.yml",
		"      - name: golangci-lint\n",
		"      - name: golangci-lint run ./... (прежняя форма)\n")
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "подпись шага обращением не является")
}

// Иная подкоманда. `golangci-lint version` в проверке пина ничего не судит,
// поэтому требовать от неё набор правил значило бы требовать формы.
func TestQualityInjection_NonJudgingSubcommandIsSilent(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	qualitySubst(t, root, qualityMakefile, qualityRecipeLine,
		"\tgolangci-lint version\n"+qualityRecipeLine)
	_, _, _, findings := scanQualityToolInvocations(root)
	qualityRequireSilent(t, findings, "подкоманда, не выносящая вердикта, обращением не является")
}

// ── ПУСТОЙ ОБХОД ────────────────────────────────────────────────────────────

// Рецепта нет — вердикта о согласии сторон нет тоже. «Ноль находок» обязано быть
// отличимо от «ноль прочитанного».
func TestQualityInjection_MissingMakefileIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	if err := os.Remove(filepath.Join(root, qualityMakefile)); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	census, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, qualityMakefile)
	if census.fromMakefile != 0 {
		t.Fatalf("рецепта нет, а обращений из него насчитано %d", census.fromMakefile)
	}
}

// Каталога объявлений нет — вторая сторона сверки отсутствует.
func TestQualityInjection_MissingWorkflowDirIsFound(t *testing.T) {
	t.Parallel()
	root := qualityWorld(t)
	if err := os.RemoveAll(filepath.Join(root, qualityWorkflowDir)); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	census, _, _, findings := scanQualityToolInvocations(root)
	requireFindingMentions(t, findings, qualityWorkflowDir)
	if census.fromWorkflows != 0 {
		t.Fatalf("объявлений нет, а обращений из них насчитано %d", census.fromWorkflows)
	}
}
