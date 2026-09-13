// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// judge_target_wiring.go — разбор: у ЕДИНСТВЕННОГО судьи оси обязан быть
// вызывающий среди того, что исполняется само.
//
// # Предмет
//
// Часть осей этого дерева судит ровно один исполнитель, поднимаемый целью
// рецепта: форму манифеста модуля — загрузчик `internal/manifest` (цель
// `module-manifest-check`), сходимость блоков модели доступов с манифестами —
// `tools/model-canon-check.sh` (цель `model-canon-check`). Единственность судьи
// назначена намеренно, и второго заводить нельзя: две копии одного суждения
// расходятся молча и расходятся там, где обе зелены.
//
// У единственности есть цена. Если у такого судьи нет ВЫЗЫВАЮЩЕГО, то ось,
// которую судит только он, не встречает НИ ОДНОЙ автоматической проверки — и
// молчание неотличимо от исправной работы. Это вторая половина класса «проверка
// с формой, но без содержания»: страж, который ничего не проверяет, и страж,
// которого никто не зовёт. Здесь — вторая.
//
// # Чем этот разбор НЕ является
//
// Он не судит форму манифеста и не сверяет блоки модели: второй судья тех же
// осей запрещён. Его предмет — ПРОВЯЗКА.
//
// # Почему разобранный YAML, а не текст
//
// Имя цели встречается в носителях чаще, чем её вызов: в заголовке шага, в
// условии, в комментарии, который эту же провязку объясняет. Поиск подстрокой
// зеленел бы на собственном объяснении и оставался бы зелёным при СНЯТОЙ
// провязке. Поэтому вызов ищется в теле `run:` разобранного задания, а
// комментарии из тела снимаются (`ExecutableRunBodies`), и форма вызова
// требуется исполняемая (`CallsMakeTarget`).
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/gatetargetwiring.go`
// вместе с двумя его семействами (`modulemanifestcheckwiring`,
// `modelcanoncheckwiring`; сняты вынесением службы — `kacho#2598`, предмет жив
// здесь, задача #17). Изменилось: операндов у обхода не «Makefile каждого
// сервиса», а ОДИН корневой рецепт — у самостоятельного модуля сервисных
// подкаталогов нет by construction; носителей провязки тоже один род (задания
// конвейера), потому что локального прогонщика `scripts/ci-local.sh` в этом
// дереве не существует. Примитивы разбора не копируются: они уже живут в
// пакете (`MakefileDeclaresTarget`, `ExecutableRunBodies`, `CallsMakeTarget`) и
// приехали сюда портом гейта сверки каталога прав.
//
// Близнеца в платформе у этого разбора нет: оба семейства сняты там вместе со
// службой, поэтому пары файлов порт НЕ заводит (ban #20).
package check

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// WorkflowsDirRel — дом заданий конвейера, единственный род носителей провязки
// в этом дереве.
const WorkflowsDirRel = ".github/workflows"

// JudgeTargetWiring — что дерево говорит о ПРОВЯЗКЕ одной цели-судьи.
//
// Перепись хранится рядом с вердиктом намеренно: «вызова нет» и «не прочитано
// ничего» выглядят одинаково, пока объём осмотренного не назван числом.
type JudgeTargetWiring struct {
	// Target — имя цели, о которой всё нижеследующее.
	Target string
	// Declared — объявлена ли цель корневым рецептом.
	Declared bool
	// Callers — файлы заданий, чьё тело `run:` зовёт цель исполняемой формой.
	Callers []string

	// MakefilesRead — прочитано рецептов (в этом дереве обязан быть ровно один).
	MakefilesRead int
	// WorkflowsRead — найдено файлов заданий.
	WorkflowsRead int
	// WorkflowsParsed — из них разобрано как YAML.
	WorkflowsParsed int
	// RunStepsRead — шагов с непустым телом `run:`.
	RunStepsRead int
	// Unreadable — файлы, которые прочитать или разобрать не удалось; НЕ
	// проверены, и молчать о них нельзя.
	Unreadable []string
}

// Census — объём осмотренного. Печатается ВСЕГДА: без него «вызывающий есть»
// неотличимо от «читать было нечего».
func (w JudgeTargetWiring) Census() string {
	callers := "нет"
	if len(w.Callers) > 0 {
		callers = strings.Join(w.Callers, ", ")
	}
	return fmt.Sprintf(
		"перепись провязки цели %s: рецептов прочитано %d · цель объявлена %t · "+
			"заданий найдено %d (разобрано %d) · тел `run:` %d · вызывающих %d (%s) · "+
			"не прочитано %d",
		w.Target, w.MakefilesRead, w.Declared, w.WorkflowsRead, w.WorkflowsParsed,
		w.RunStepsRead, len(w.Callers), callers, len(w.Unreadable))
}

// ReadJudgeTargetWiring — обход дерева: кто объявляет цель и кто её зовёт.
//
// Ошибка возвращается там, где обход БЕСПРЕДМЕТЕН (нет рецепта, нет каталога
// заданий): «ноль находок» обязано быть отличимо от «ноль прочитанного», и
// различать их обязан сам разбор, а не читатель его вывода.
func ReadJudgeTargetWiring(root, target string) (JudgeTargetWiring, error) {
	w := JudgeTargetWiring{Target: target}

	makefile, err := os.ReadFile(filepath.Join(root, "Makefile")) // #nosec G304 -- имя файла — литерал, корень назвал вызывающий
	if err != nil {
		return w, fmt.Errorf("корневой рецепт не прочитан: %w", err)
	}
	w.MakefilesRead = 1
	w.Declared = MakefileDeclaresTarget(string(makefile), target)

	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(WorkflowsDirRel)))
	if err != nil {
		return w, fmt.Errorf("каталог заданий %s не прочитан: %w", WorkflowsDirRel, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		w.WorkflowsRead++
		rel := WorkflowsDirRel + "/" + name
		raw, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- имя из перечня собственного каталога заданий
		if rerr != nil {
			w.Unreadable = append(w.Unreadable, rel+": "+rerr.Error())
			continue
		}
		bodies, steps, perr := ExecutableRunBodies(string(raw))
		if perr != nil {
			w.Unreadable = append(w.Unreadable, rel+": "+perr.Error())
			continue
		}
		w.WorkflowsParsed++
		w.RunStepsRead += steps
		for _, b := range bodies {
			if CallsMakeTarget(b, target) {
				w.Callers = append(w.Callers, rel)
				break
			}
		}
	}
	sort.Strings(w.Callers)
	if w.WorkflowsRead == 0 {
		return w, fmt.Errorf("в %s не найдено ни одного файла задания", WorkflowsDirRel)
	}
	return w, nil
}

// JudgeTargetWiringFaults — находки по ОБЕИМ сторонам провязки.
//
// Сверка идёт в обе стороны намеренно. Односторонняя («объявлена — обязана быть
// звана») пропускала бы обратный случай: носитель зовёт цель, которой рецепт не
// объявляет, — шаг молча зеленеет на несуществующей цели, потому что `make`
// такого имени не знает и... отказывает; а под `|| true` или в подстановке не
// отказывает вовсе. Это провязка в пустоту, и она хуже отсутствующей: выглядит
// исполненной.
func JudgeTargetWiringFaults(w JudgeTargetWiring) []string {
	var out []string
	switch {
	case w.Declared && len(w.Callers) == 0:
		out = append(out, fmt.Sprintf(
			"цель %s объявлена корневым рецептом, и НИ ОДИН шаг конвейера её не зовёт "+
				"(осмотрено заданий %d, тел `run:` %d).\n"+
				"  Ось, которую судит только эта цель, не встречает ни одной автоматической "+
				"проверки, и её молчание неотличимо от исправной работы.\n"+
				"  Что делать: провязать цель шагом конвейера, читая её код возврата ЧЕТЫРЬМЯ "+
				"исходами (0 годно · 1 находка · 2 проверять нечего · 3 не исполнялась). "+
				"Третий исход не схлопывать в успех: пустое дерево отчитывалось бы зелёным "+
				"так же уверенно, как проверенное. Заводить второго судью взамен провязки — нельзя",
			w.Target, w.WorkflowsRead, w.RunStepsRead))
	case !w.Declared && len(w.Callers) > 0:
		out = append(out, fmt.Sprintf(
			"цель %s зовётся шагами конвейера (%s), а корневой рецепт её НЕ объявляет — "+
				"провязка в пустоту: она позеленеет ни на чём",
			w.Target, strings.Join(w.Callers, ", ")))
	case !w.Declared && len(w.Callers) == 0:
		out = append(out, fmt.Sprintf(
			"цель %s не объявлена корневым рецептом и никем не звана — распознавание сломано "+
				"либо цель сняли; в обоих случаях молчание про провязку ничего не значит",
			w.Target))
	}
	for _, u := range w.Unreadable {
		out = append(out, "файл конвейера НЕ проверен: "+u)
	}
	return out
}
