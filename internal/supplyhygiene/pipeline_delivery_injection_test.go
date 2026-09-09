// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pipeline_delivery_injection_test.go — доказательство, что гейт поставки
// конвейера СПОСОБЕН упасть и способен смолчать.
//
// Инъекция подаёт вход, а не читает код. Каждый отрицательный случай меняет
// РОВНО ОДИН факт против своего положительного близнеца: иначе неизвестно, какой
// из двух дал красное, и вердикт недействителен, оставаясь на вид зелёным.
//
// Мир строится КОПИЕЙ настоящего дерева службы, а не выдумывается: синтетика,
// собранная из частей, доказывает работу механизма на синтетике. Копируется
// только каталог конвейера — больше гейт ничего не читает.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pipelineWorld — копия каталога конвейера службы во временном корне.
// Возвращает корень, готовый к одно-фактной правке.
func pipelineWorld(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range deliveredPipelineFiles {
		raw, err := os.ReadFile(filepath.Join(serviceRoot, rel))
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

// writeWorkflow — подменяет объявление процесса в мире, оставляя всё прочее.
func writeWorkflow(t *testing.T, root, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, deliveredWorkflow), []byte(body), 0o644); err != nil {
		t.Fatalf("объявление не записано: %v", err)
	}
}

// requireFindingMentions — находка есть, и она НАЗЫВАЕТ предмет. Проверять надо
// не только «покраснел», но и «что напечатал»: находка, называющая симптом,
// посылает читателя искать не там.
func requireFindingMentions(t *testing.T, findings []string, want string) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatalf("гейт смолчал там, где обязан был найти %q — он не способен упасть", want)
	}
	if !strings.Contains(strings.Join(findings, "\n"), want) {
		t.Fatalf("находка есть, но не называет %q:\n%s", want, strings.Join(findings, "\n"))
	}
}

// ── КОНТРОЛЬ: нетронутый мир молчит ─────────────────────────────────────────
// Без него всякое красное ниже могло бы приходить от копирования, а не от
// внесённого дефекта.
func TestPipelineInjectionControl_UntouchedWorldIsSilent(t *testing.T) {
	t.Parallel()
	census, findings := scanDeliveredPipeline(pipelineWorld(t))
	if len(findings) != 0 {
		t.Fatalf("контроль не прошёл: нетронутая копия дала находки — красное ниже будет от копии, "+
			"а не от дефекта:\n%s", strings.Join(findings, "\n"))
	}
	if census.filesFound != census.filesWanted {
		t.Fatalf("контроль не прошёл: найдено %d файлов из %d", census.filesFound, census.filesWanted)
	}
	if census.jobs == 0 {
		t.Fatal("контроль не прошёл: заданий осмотрено ноль — разбор не дошёл до `jobs:`")
	}
}

// ── ОСЬ 1: присутствие ──────────────────────────────────────────────────────

func TestPipelineInjection_MissingWorkflowIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	if err := os.Remove(filepath.Join(root, deliveredWorkflow)); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, deliveredWorkflow)
}

func TestPipelineInjection_MissingCalledScriptIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	victim := ".github/scripts/gosec-gate.sh"
	if err := os.Remove(filepath.Join(root, victim)); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, victim)
}

// Присутствие ИМЕНИ не есть присутствие содержимого: файл нулевой длины
// проходит `os.Stat` и не проходит здесь.
func TestPipelineInjection_EmptyFileIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	victim := ".github/scripts/run-integration.sh"
	if err := os.WriteFile(filepath.Join(root, victim), nil, 0o644); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, victim)
}

// ── ОСЬ 2: разбираемость ────────────────────────────────────────────────────

func TestPipelineInjection_UnparseableDeclarationIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	writeWorkflow(t, root, "jobs:\n  build:\n   - это: не отображение\n  \tтабуляция: рвёт разбор\n")
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, "не разобран YAML")
}

func TestPipelineInjection_DeclarationWithoutJobsIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	writeWorkflow(t, root, "name: ci\non:\n  push:\n    branches: [main]\n")
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, "заданий не объявлено")
}

// ── ОСЬ 3: машиночитаемость идентификатора (ban #17) ────────────────────────

func TestPipelineInjection_CyrillicJobKeyIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	writeWorkflow(t, root, "name: ci\non:\n  push:\n    branches: [main]\njobs:\n"+
		"  сборка:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, "идентификатор задания")
}

func TestPipelineInjection_CyrillicStepIDIsFound(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	writeWorkflow(t, root, "name: ci\non:\n  push:\n    branches: [main]\njobs:\n"+
		"  build:\n    runs-on: ubuntu-latest\n    steps:\n      - id: шаг\n        run: echo\n")
	_, findings := scanDeliveredPipeline(root)
	requireFindingMentions(t, findings, "идентификатор шага")
}

// ЗАКОННЫЙ БЛИЗНЕЦ, и он несущий: запрет — про ИДЕНТИФИКАТОР, а не про язык.
// Кириллица в подписи `name:` и в комментарии законна, обязана остаться и
// обязана молчать; иначе гейт ловит форму записи, а не существо, и его снимут
// на первом же ложном срабатывании. Отличие от близнеца выше — РОВНО ОДНО:
// кириллица переехала с ключа на подпись.
func TestPipelineInjection_CyrillicNameAndCommentStaySilent(t *testing.T) {
	t.Parallel()
	root := pipelineWorld(t)
	writeWorkflow(t, root, "name: сборка и пробы\non:\n  push:\n    branches: [main]\njobs:\n"+
		"  # задание собирает службу\n"+
		"  build:\n    name: сборка\n    runs-on: ubuntu-latest\n    steps:\n"+
		"      - id: compile\n        name: компиляция\n        run: echo\n")
	_, findings := scanDeliveredPipeline(root)
	if len(findings) != 0 {
		t.Fatalf("гейт покраснел на ЗАКОННОМ близнеце — он судит язык, а не идентификатор:\n%s",
			strings.Join(findings, "\n"))
	}
}

// ── Пустой обход отличим от чистого дерева ──────────────────────────────────

func TestPipelineInjection_EmptyRootIsNotSilentlyGreen(t *testing.T) {
	t.Parallel()
	census, findings := scanDeliveredPipeline(t.TempDir())
	if len(findings) == 0 {
		t.Fatal("пустой корень дал ноль находок — «ноль прочитанного» неотличимо от «ноль находок»")
	}
	if census.filesFound != 0 {
		t.Fatalf("перепись лжёт: в пустом корне найдено %d файлов", census.filesFound)
	}
	if census.jobs != 0 {
		t.Fatalf("перепись лжёт: в пустом корне осмотрено %d заданий", census.jobs)
	}
}
