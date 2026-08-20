// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// feedcomposition_test.go — R7-4-04: подача теневой сверки обязана НАЗЫВАТЬ свой
// состав, а её доля обязана быть УСЛОВИЕМ ПРОХОЖДЕНИЯ, а не отчётом.
//
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ — ИСХОД, А НЕ ОБЪЯВЛЕНИЕ. Проба не ищет строк в
// исходнике прибора: она ЗАПУСКАЕТ прибор целиком на подставном окружении и
// читает его код возврата и его отчёт. Проба, сверяющая текст скрипта, осталась
// бы зелёной на приборе, который нужные слова печатает и решения по ним не
// принимает, — а предмет R7-4-04 ровно в решении.
//
// ПОЧЕМУ ПОДСТАВНОЕ ОКРУЖЕНИЕ, А НЕ СТЕНД. Стенд общий: подача нагрузки на него
// из проб запрещена, и вердикт, снятый с общего стенда, принадлежал бы его
// данным на минуту замера, а не дереву. Подставные `kubectl` и `docker`
// герметичны: пробе не нужны ни кластер, ни k6, ни сеть, поэтому она исполняется
// в конвейере, где ничего этого нет.
//
// ЧЕГО ЭТА ПРОБА НЕ ДЕРЖИТ — сказано прямо: она НЕ проверяет, что сам
// `internal_check.js` правильно считает состав (это исполняется движком k6,
// которого в конвейере нет). Она держит договор МЕЖДУ ними: получив состав, где
// пяти собственных типов iam ноль, прибор обязан отказаться выдавать вердикт;
// получив состав с ними — обязан считать по ним ОТДЕЛЬНЫЙ знаменатель и падать,
// когда доля выше объявленного бюджета. Разбор состава на стороне k6 держит
// `make k6-dry-run` и сверка md5 прибора с деревом внутри самой пробы.
package k6

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	probeRel  = "../../../../deploy/load-tests/iam-shadow-divergence-probe.sh"
	scriptRel = "internal_check.js"

	// Пять собственных типов iam — предмет R7-4. Здесь они выписаны НАМЕРЕННО:
	// проба обязана уметь предъявить прибору состав, в котором их нет, а
	// выведенный из того же места перечень такой подачи построить не смог бы.
	ownTypesCSV = "iam_access_binding,iam_group,iam_role,iam_service_account,iam_user"
)

// composition собирает канонический отчёт о составе подачи — ровно тот, что
// печатает `internal_check.js` в режиме COMPOSITION_ONLY.
//
// Строки ОБРАМЛЕНЫ так, как их обрамляет настоящий k6 (`time=… level=info
// msg="…" source=console`). Подставной вход, устроенный удобнее настоящего,
// сделал бы невидимым ровно тот дефект, ради которого его подставляют: первая
// редакция разбора в приборе якорилась на начало строки и не совпала бы ни разу.
func composition(total int, byType map[string]int, own, projectRole int) string {
	var b strings.Builder
	say := func(format string, a ...any) {
		fmt.Fprintf(&b, "time=\"2026-08-20T09:19:39+03:00\" level=info msg=%q source=console\n",
			fmt.Sprintf(format, a...))
	}
	say("ФИКСТУРА-СОСТАВ всего %d из %d в фикстуре", total, total)
	for _, t := range []string{"account", "project", "vpc_network", "iam_user", "iam_access_binding"} {
		if n, ok := byType[t]; ok {
			say("ФИКСТУРА-ТИП %s %d", t, n)
		}
	}
	say("ФИКСТУРА-СВОИ-ТИПЫ %s", ownTypesCSV)
	say("ФИКСТУРА-СВОИ %d", own)
	say("ФИКСТУРА-КЛАСС project_role %d", projectRole)
	return b.String()
}

// runProbe исполняет прибор на подставном окружении и возвращает его вывод и код.
//
// armDeltas — строки «подстрока-в-аргументах|прирост сравнено|прирост разошлось».
// Первое совпадение выигрывает; без совпадения берётся 1000|0. Так проба задаёт
// РАЗНЫЕ доли разным рукам, не трогая ни стенда, ни службы.
func runProbe(t *testing.T, comp string, armDeltas []string) (string, int) {
	t.Helper()

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("каталог подставных команд не создан: %v", err)
	}

	probe, err := filepath.Abs(probeRel)
	if err != nil {
		t.Fatalf("путь прибора не разрешён: %v", err)
	}
	if _, err := os.Stat(probe); err != nil {
		t.Fatalf("прибора нет по координате %s: %v", probeRel, err)
	}
	script, err := filepath.Abs(scriptRel)
	if err != nil {
		t.Fatalf("путь сценария не разрешён: %v", err)
	}
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("сценарий %s не прочитан: %v", scriptRel, err)
	}
	sum := md5.Sum(raw)

	compFile := filepath.Join(dir, "composition.txt")
	if err := os.WriteFile(compFile, []byte(comp), 0o644); err != nil {
		t.Fatalf("состав подачи не записан: %v", err)
	}
	state := filepath.Join(dir, "counters")
	if err := os.WriteFile(state, []byte("100000 0\n"), 0o644); err != nil {
		t.Fatalf("счётчики не записаны: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "kubectl"), []byte(stubKubectl), 0o755); err != nil {
		t.Fatalf("подставной kubectl не записан: %v", err)
	}
	// Провенанс спрашивает клеймо образа через docker; на герметичном прогоне
	// его нет, и прибор обязан это пережить, назвав ревизию неустановленной.
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("подставной docker не записан: %v", err)
	}

	cmd := exec.Command("bash", probe, "10", "1s")
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_COMPOSITION_FILE="+compFile,
		"STUB_STATE="+state,
		"STUB_MD5="+hex.EncodeToString(sum[:]),
		"STUB_ARM_DELTAS="+strings.Join(armDeltas, "\n"),
		// Часы прибора — управляемые: ожидание свежей сводки службы на
		// герметичном прогоне ждать нечего, а недетерминированный вход сделал
		// бы пробу медленной и мигающей.
		"SETTLE=0",
	)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("прибор не запустился вовсе: %v\n%s", err, out)
		}
	}
	return string(out), code
}

// hasTypeCount — строка отчёта, чьи поля суть «тип» и «число». Разбор по полям,
// а не по подстроке: отчёт выровнен колонками, и число пробел между ними меняется
// от длины самого длинного имени типа.
func hasTypeCount(out, ty, n string) bool {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == ty && f[1] == n {
			return true
		}
	}
	return false
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// TestR7_4_04_FeedCompositionIsNamedAndZeroOwnTypesIsNotAVerdict — R7-4-04,
// первая половина: прибор печатает состав подачи по типу объекта, а подача без
// пяти собственных типов iam даёт ТРЕТИЙ исход, а не вердикт.
//
// Инъекция обратной стороны — в TestR7_4_04_OwnTypeShareIsItsOwnDenominator…:
// на подаче С этими типами прибор обязан дойти до вердикта. Без пары «отказ»
// был бы неотличим от прибора, который не работает вовсе.
func TestR7_4_04_FeedCompositionIsNamedAndZeroOwnTypesIsNotAVerdict(t *testing.T) {
	out, code := runProbe(t,
		composition(273, map[string]int{"account": 60, "project": 60, "vpc_network": 42}, 0, 0),
		nil)

	if code != 3 {
		t.Fatalf("подача без пяти собственных типов iam обязана дать ТРЕТИЙ исход "+
			"«условие не создано» (код 3), получен код %d.\n"+
			"Ноль расхождений на подаче, где предмета нет, — это «ноль прочитанного», "+
			"поданное как «ноль находок»: ровно то, из-за чего проба показывала 0.00 %% "+
			"одновременно с переписью, называвшей 15 085 потерянных объектов.\nвывод:\n%s", code, out)
	}
	if !strings.Contains(out, "состав подачи") {
		t.Errorf("в отчёте прибора нет раздела состава подачи\nвывод:\n%s", out)
	}
	// Состав утверждается ПОСТРОЧНО по полям, а не подстрокой: отчёт выровнен
	// колонками, и проверка подстрокой «account 60» была бы ложно-красной на
	// верном приборе — то есть ловила бы разметку, а не свойство.
	for ty, n := range map[string]string{"account": "60", "project": "60", "vpc_network": "42"} {
		if !hasTypeCount(out, ty, n) {
			t.Errorf("в составе подачи нет строки «%s %s»\nвывод:\n%s", ty, n, out)
		}
	}
	if !strings.Contains(out, "пяти собственных типов iam") {
		t.Errorf("прибор не сказал ВСЛУХ, что пяти собственных типов iam в подаче ноль.\nвывод:\n%s", out)
	}
	// Доля не должна быть засчитана как утверждение о пяти типах: вердикта о
	// бюджете на такой подаче не бывает вовсе.
	if strings.Contains(out, "бюджет выдержан") || strings.Contains(out, "бюджет по пяти типам выдержан") {
		t.Errorf("прибор выдал вердикт о бюджете на подаче, где предмета нет, — "+
			"это и есть «доля засчитана как утверждение о пяти типах».\nвывод:\n%s", out)
	}
}

// TestR7_4_04_OwnTypeShareIsItsOwnDenominator — R7-4-04, вторая половина, и
// одновременно законный близнец первой: на подаче С пятью типами прибор обязан
// дойти до вердикта, посчитать по ним ОТДЕЛЬНЫЙ знаменатель и назвать «сравнено»
// рядом с «разошлось».
func TestR7_4_04_OwnTypeShareIsItsOwnDenominator(t *testing.T) {
	out, code := runProbe(t,
		composition(445, map[string]int{"account": 60, "project": 60, "vpc_network": 42, "iam_user": 60, "iam_access_binding": 60}, 145, 0),
		[]string{"FEED_TYPES=only:" + ownTypesCSV + "|1000|3"})

	if code != 0 {
		t.Fatalf("на подаче с пятью типами и долей ниже бюджета прибор обязан пройти, получен код %d\nвывод:\n%s", code, out)
	}
	if !hasTypeCount(out, "iam_user", "60") {
		t.Errorf("состав подачи по типу не напечатан\nвывод:\n%s", out)
	}
	// Отдельный знаменатель: строка руки по пяти типам обязана нести И «сравнено», И «разошлось».
	var armLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "пять собственных типов iam") && strings.Contains(l, "сравнено") {
			armLine = l
			break
		}
	}
	if armLine == "" {
		t.Fatalf("нет отдельной руки по пяти собственным типам iam — доля растворена в общем знаменателе\nвывод:\n%s", out)
	}
	if !strings.Contains(armLine, "разошлось") {
		t.Errorf("рядом с «разошлось» обязано стоять «сравнено»: доля без знаменателя вердиктом не является\nстрока: %s", armLine)
	}
	if !strings.Contains(out, "бюджет по пяти типам выдержан") {
		t.Errorf("прибор не объявил ВЕРДИКТ по бюджету пяти типов — значит бюджет остался отчётом\nвывод:\n%s", out)
	}
	// Класс «проектная роль» назван ЗАРАНЕЕ, даже когда его объектов ноль:
	// иначе он всплывёт в общей доле и либо объявит достройку неудачной, либо
	// научит игнорировать долю.
	if !strings.Contains(out, "проектная роль") {
		t.Errorf("класс «проектная роль» не назван заранее\nвывод:\n%s", out)
	}
}

// TestR7_4_04_OwnTypeBudgetIsAPassingConditionNotAReport — S2 DoD: «у прибора
// расхождения есть УСЛОВИЕ ПРОХОЖДЕНИЯ, а не только отчёт».
//
// Инъекция: доля по пяти типам поднята выше бюджета при исправной общей руке.
// Прибор обязан ОТКАЗАТЬ и назвать, какой именно бюджет не выдержан. Без этой
// пробы «доля посчитана» было бы неотличимо от «доля удерживается».
func TestR7_4_04_OwnTypeBudgetIsAPassingConditionNotAReport(t *testing.T) {
	out, code := runProbe(t,
		composition(445, map[string]int{"account": 60, "iam_user": 60, "iam_access_binding": 60}, 145, 0),
		[]string{"FEED_TYPES=only:" + ownTypesCSV + "|1000|900"})

	if code == 0 {
		t.Fatalf("доля по пяти типам 90 %% при бюджете 1 %% обязана РОНЯТЬ прибор, получен успех\nвывод:\n%s", out)
	}
	if !strings.Contains(out, "ОТКАЗ") || !strings.Contains(out, "пяти типам") {
		t.Errorf("отказ обязан назвать, какой бюджет не выдержан\nвывод:\n%s", out)
	}
	// Отрицательный контроль внутри того же прогона: общая рука исправна, и
	// прибор не вправе валить её заодно — иначе он ловит форму, а не существо.
	if strings.Contains(out, "ОТКАЗ: доля на настоящих выдачах") {
		t.Errorf("общая рука исправна (0 из 1000), но прибор объявил отказ и по ней\nвывод:\n%s", out)
	}
}

// stubKubectl — подставной kubectl. Он эмулирует РОВНО те обращения, которые
// делает прибор, и ничего сверх: обращение, которого он не знает, он не глотает
// молча — оно просто не влияет на счётчики, и рука сообщит «сравнений 0».
const stubKubectl = `#!/usr/bin/env bash
set -uo pipefail
args="$*"
verb=""
for a in "$@"; do
  case "$a" in get|exec|logs|create|apply) verb="$a"; break;; esac
done
case "$verb" in
  get)
    case "$args" in
      *"app.kubernetes.io/name=kacho-iam"*) echo "kacho-iam-0";;
      *imageID*) echo "sha256:0000000000000000";;
    esac
    ;;
  create) echo "apiVersion: v1";;
  apply)  cat >/dev/null;;
  logs)
    read -r c d < "$STUB_STATE"
    echo "level=info msg=\"shadow verdict: сводка\" \"compared\":$c,\"diverged\":$d"
    ;;
  exec)
    case "$args" in
      *md5sum*) echo "$STUB_MD5  /scripts/internal_check.js";;
      *COMPOSITION_ONLY*) cat "$STUB_COMPOSITION_FILE";;
      *"k6 run"*)
        dc=1000; dd=0
        while IFS='|' read -r match mc md; do
          [ -n "$match" ] || continue
          case "$args" in *"$match"*) dc="$mc"; dd="$md"; break;; esac
        done <<< "${STUB_ARM_DELTAS:-}"
        read -r c d < "$STUB_STATE"
        echo "$((c + dc)) $((d + dd))" > "$STUB_STATE"
        ;;
    esac
    ;;
esac
exit 0
`
