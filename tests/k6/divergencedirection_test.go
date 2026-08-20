// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package k6

// divergencedirection_test.go — R7-4-12: РАСХОЖДЕНИЕ КЛАССИФИЦИРОВАНО
// ПО НАПРАВЛЕНИЮ И ПО ТИПУ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОДНОЙ ДОЛИ НЕДОСТАТОЧНО
//
// Доля отвечает «сколько», и по ней НЕЛЬЗЯ действовать. Направления два, и они
// не равноценны:
//
//	форма отказала, решатель разрешил — НЕДОДАННЫЙ доступ. Виден пользователю
//	    сразу: он приходит с жалобой;
//	форма разрешила, решатель отказал — ЛИШНИЙ доступ. Не виден НИКОМУ, и
//	    именно поэтому опаснее.
//
// Слитые в одно число, они теряют ту сторону, которая тише. Разложение по ТИПУ
// нужно по второй причине: класс «проектная роль» ожидается заранее (форма
// отвечает «да» раньше модельного каскада, потому что арма «от проекта» у типа
// `iam_role` в модели нет вовсе), и растворённый в общей доле он либо объявит
// достройку неудачной, либо научит читателя игнорировать долю.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАЗЛОЖЕНИЕ НЕ ИЗОБРЕТАЕТСЯ ПРИБОРОМ — ОНО УЖЕ ЕСТЬ В СВОДКЕ
//
// Сравнитель кладёт в сводку `class_breakdown` ключами вида
// `<вопрос>|<тип объекта>|<отношение>|движок=<да|нет>`, и при расхождении
// `движок=true` означает «решатель разрешил, форма отказала», а `движок=false` —
// обратное. Прибор РАЗБИРАЕТ эту строку; заводить второй счётчик значило бы
// завести второе место об одном предмете и разойтись с первым молча.
//
// Отсюда предмет пробы: разбор обязан быть верен на НАСТОЯЩЕЙ форме ключа и
// обязан ОТКАЗЫВАТЬ на форме, которой он не знает, — потому что «сколько» без
// «в какую сторону» есть число, по которому нельзя действовать, а молчаливый
// разбор выдаёт его за полное.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/gitenv"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam/shadowverdict"
)

const shadowProbeRel = "deploy/load-tests/iam-shadow-divergence-probe.sh"

// splitClassesUnderTest достаёт из прибора функцию разбора и исполняет её на
// подложенной строке сводки.
//
// Исполняется ПРИБОР, а не его пересказ: проба, переписавшая разбор у себя,
// доказывала бы согласие двух своих же записей и осталась бы зелёной при любой
// правке скрипта.
func splitClassesUnderTest(t *testing.T, breakdown string) (string, int) {
	t.Helper()
	root := repoRootForK6(t)
	script := filepath.Join(root, shadowProbeRel)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("прибора нет в дереве (%v): разбирать нечего, и молчание пробы не "+
			"означало бы, что разложение верно", err)
	}
	body, err := os.ReadFile(script) // #nosec G304 -- путь собран из корня СОБСТВЕННОГО дерева и константы пакета
	if err != nil {
		t.Fatalf("прибор не прочитан: %v", err)
	}
	fn := extractShellFunc(t, string(body), "split_classes")

	// `classes_breakdown` подменяется НА ОДНУ строку — ту, что печатает
	// сравнитель. Подменяется именно источник, а не разбор: разбор обязан
	// исполниться тот самый.
	harness := "set -uo pipefail\n" +
		"classes_breakdown() { printf '%s' \"$BREAKDOWN\"; }\n" + fn + "\nsplit_classes\n"
	cmd := exec.Command("bash", "-c", harness) // #nosec G204 -- сценарий собран из текста СОБСТВЕННОГО прибора и константы пакета
	cmd.Env = append(os.Environ(), "BREAKDOWN="+breakdown)
	out, runErr := cmd.CombinedOutput()
	code := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("разбор не запустился (%v): это НЕ вердикт, а «условие не создано» на "+
			"стороне пробы.\n%s", runErr, out)
	}
	return string(out), code
}

// extractShellFunc вырезает одну функцию прибора по её имени.
func extractShellFunc(t *testing.T, body, name string) string {
	t.Helper()
	start := strings.Index(body, name+"() {")
	if start < 0 {
		t.Fatalf("функция %s() в приборе не найдена: проба судила бы не тот код.\n"+
			"Прибор: %s", name, shadowProbeRel)
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("конец функции %s() не найден", name)
	}
	return body[start : start+end+3]
}

// repoRootForK6 — корень СВОЕГО дерева.
//
// Через [gitenv.Command], а не напрямую: `GIT_DIR` сильнее рабочего каталога,
// и под ней (то есть внутри любого хука git) `rev-parse --show-toplevel`
// отвечает про ЧУЖОЙ репозиторий. Наблюдалось дословно: под выставленной
// `GIT_DIR` команда печатала ПУСТО, корень становился пустой строкой, путь к
// прибору — относительным, и четыре пробы этого файла объявляли «прибора нет в
// дереве» — утверждение о продукте, которого никто не делал.
//
// Пустой ответ поэтому отвергается отдельно: он означает «репозиторий не
// определён», а не «корень — текущий каталог». Без этой ветки отказ читался бы
// как находка о приборе.
func repoRootForK6(t *testing.T) string {
	t.Helper()
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("корень дерева не установлен (%v): пробе негде взять прибор", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		t.Fatalf("корень дерева пуст: git не определил репозиторий. Это «условие не " +
			"создано» на стороне пробы, а НЕ находка о приборе — не читай следующий " +
			"отказ как утверждение о дереве")
	}
	return root
}

// TestR7_4_12_DivergenceIsSplitByDirectionAndByType — R7-4-12.
//
// Утверждается ИСХОД разбора на НАСТОЯЩЕЙ форме ключа сравнителя, а не
// «функция существует».
func TestR7_4_12_DivergenceIsSplitByDirectionAndByType(t *testing.T) {
	// Форма ключа взята у сравнителя дословно:
	// `<вопрос>|<тип объекта>|<отношение>|движок=<да|нет>`.
	// Разделитель берётся У САМОГО СРАВНИТЕЛЯ, а не выписывается здесь.
	//
	// Выписанный был бы третьим местом об одном предмете — после сравнителя и
	// прибора — и разошёлся бы молча: фикстура продолжала бы собираться прежним
	// разделителем, разбор видел бы в ней ОДИН класс вместо трёх, и проба
	// упала бы, называя виновником прибор. Так и случилось при смене
	// разделителя с пробела: ключ класса содержит пробелы, и поле было
	// неразбираемо by construction.
	breakdown := strings.Join([]string{
		"Check|iam_role|v_get|движок=false×7",
		"Check|iam_group|v_get|движок=true×3",
		"Check|iam_access_binding|v_delete|движок=true×1",
	}, shadowverdict.ClassBreakdownSeparator)

	out, code := splitClassesUnderTest(t, breakdown)
	if code != 0 {
		t.Fatalf("разбор отказал на настоящей форме ключа (код %d):\n%s", code, out)
	}

	// ── направление разложено, и обе стороны считаются РАЗДЕЛЬНО ────────────
	wantAllowedByEngine := "форма отказала, решатель разрешил"
	wantAllowedByForm := "форма разрешила, решатель отказал"
	for _, want := range []string{wantAllowedByEngine, wantAllowedByForm} {
		if !strings.Contains(out, want) {
			t.Errorf("направление %q не названо разбором:\n%s", want, out)
		}
	}
	// ── тип объекта разложен ────────────────────────────────────────────────
	for _, ty := range []string{"iam_role", "iam_group", "iam_access_binding"} {
		if !strings.Contains(out, ty) {
			t.Errorf("тип объекта %q не назван разбором:\n%s", ty, out)
		}
	}
	// ── класс «проектная роль» отделим по ТИПУ и НАПРАВЛЕНИЮ ────────────────
	//
	// Ожидается заранее и с причиной: у типа `iam_role` в модели нет
	// отношения-указателя `project`, поэтому по проектным ролям форма отвечает
	// «да» раньше каскада, и направление у этого класса всегда одно —
	// «форма разрешила». Проба требует, чтобы его можно было ВЫЧЕСТЬ, а не
	// искать в общей доле.
	var roleLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "iam_role") {
			roleLine = line
		}
	}
	if roleLine == "" {
		t.Fatalf("строки по типу iam_role нет: класс «проектная роль» неотделим от общей "+
			"доли, а растворённый в ней он либо объявит достройку неудачной, либо научит "+
			"игнорировать долю.\n%s", out)
	}
	if !strings.Contains(roleLine, wantAllowedByForm) {
		t.Errorf("класс «проектная роль» отнесён не к тому направлению: ждали %q\n%s",
			wantAllowedByForm, roleLine)
	}
	if !strings.Contains(roleLine, "7") {
		t.Errorf("число расхождений класса потеряно при разборе:\n%s", roleLine)
	}
}

// TestR7_4_12_InjectionUnknownKeyShapeIsRefusedNotCounted — ОБЯЗАН ОТКАЗАТЬ.
//
// Форма ключа сравнителя разошлась с разбором прибора. Промолчать здесь значило
// бы отдать «сколько» без «в какую сторону» — число, по которому нельзя
// действовать, поданное как полное.
func TestR7_4_12_InjectionUnknownKeyShapeIsRefusedNotCounted(t *testing.T) {
	out, _ := splitClassesUnderTest(t, "Check|iam_role|v_get|engine=false×7")
	if !strings.Contains(out, "НЕ РАЗОБРАНО") {
		t.Fatalf("разбор МОЛЧА принял ключ незнакомой формы: «сколько» осталось, «в какую "+
			"сторону» пропало, и по такому числу действовали бы как по полному.\n%s", out)
	}
}

// TestR7_4_12_InjectionKnownShapeIsNotFlaggedUnparsed — ОБЯЗАН МОЛЧАТЬ.
//
// ЗАКОННЫЙ БЛИЗНЕЦ: без него «НЕ РАЗОБРАНО» появлялось бы и на верной форме, и
// первый ложный срабат выключил бы отказ выше.
func TestR7_4_12_InjectionKnownShapeIsNotFlaggedUnparsed(t *testing.T) {
	out, _ := splitClassesUnderTest(t, "Check|iam_group|v_get|движок=true×2")
	if strings.Contains(out, "НЕ РАЗОБРАНО") {
		t.Fatalf("разбор назвал НЕРАЗОБРАННОЙ настоящую форму ключа: отказ сработает на "+
			"исправном приборе и будет выключен первым же читателем.\n%s", out)
	}
}

// TestR7_4_12_EmptyBreakdownIsNotReadAsNoDivergence — ТРЕТИЙ ИСХОД.
//
// Пустое разложение означает «сводка не доехала», а не «расхождений нет». Прибор
// обязан сказать это словами: тот же пустой вывод даёт и здоровое дерево, и
// не доехавшая сводка.
func TestR7_4_12_EmptyBreakdownIsNotReadAsNoDivergence(t *testing.T) {
	root := repoRootForK6(t)
	body, err := os.ReadFile(filepath.Join(root, shadowProbeRel)) // #nosec G304 -- путь из корня собственного дерева
	if err != nil {
		t.Fatalf("прибор не прочитан: %v", err)
	}
	if !strings.Contains(string(body), "Это НЕ «расхождений нет»") {
		t.Fatalf("прибор не оговаривает, что пустое разложение НЕ является утверждением "+
			"об отсутствии расхождений: «ноль находок» осталось бы неотличимо от «ноль "+
			"прочитанного».\nПрибор: %s", shadowProbeRel)
	}
}
