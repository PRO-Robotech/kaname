// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Вердикт суит ничего не вычитает.
//
// ЧТО ЭТО ЗА ФАЙЛ И ЧЕМ ОН НЕ ЯВЛЯЕТСЯ. Здесь стоял гейт `newmanmask` — три
// проверки о том, что вычитание «известного красного» не шире, чем называет, и не
// переживает свой предмет. Вычитание снято целиком 2026-07-30 (третье сужение
// подряд доказало, что предикат по ИМЕНИ не может отличать свой предмет от чужого:
// причина отказа в имени не выражена). Вместе с механизмом предмета лишился и
// гейт — все три его проверки стали красными, потому что судить стало не о чем.
//
// Правило дерева на этот случай однозначно: исключение живёт, пока у него есть
// предмет, а запись, которой больше нечего исключать, — находка. Поэтому охрана
// снятого механизма УДАЛЕНА, а не подогнана под пустоту.
//
// НО ЭТО НЕ ТО ЖЕ САМОЕ УТВЕРЖДЕНИЕ, ПЕРЕИМЕНОВАННОЕ. Прежний гейт говорил «у
// маски есть предмет». Здесь утверждается обратное и НОВОЕ свойство, у которого
// предмет есть прямо сейчас: **вердикт не вычитает ничего**. Оно проверяемо
// (скрипт существует, вычитание либо есть, либо нет) и оно то самое, что можно
// потерять молча — достаточно одной строки `fails=$((fails - …))`, и суита снова
// начнёт отчитываться не тем, что сообщил newman.
//
// Читается ИСПОЛНЯЕМАЯ часть скрипта, а не текст: слова «known_red» и
// «whitelist» законно встречаются в объяснении, почему вычитания больше нет, и
// гейт по сырому тексту краснел бы на собственной документации.
package newmanverdict

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const verdictScript = "services/iam/tests/newman/scripts/assert-suites-green.sh"

func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(self)
	for range 12 {
		if fi, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil && fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find .github/workflows above this test file")
	return ""
}

// codeLines — строки скрипта БЕЗ комментариев и без пустых. Разбор грубый и этого
// достаточно: shell-комментарий начинается с `#`, а внутристрочный `… # …` нас не
// интересует — искомые конструкции стоят самостоятельными стейтментами.
func codeLines(t *testing.T) []string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), verdictScript))
	if err != nil {
		t.Fatalf("read %s: %v", verdictScript, err)
	}
	var out []string
	for _, ln := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		t.Fatalf("%s has no executable lines — this gate inspected nothing", verdictScript)
	}
	return out
}

// Любое присваивание, УМЕНЬШАЮЩЕЕ счётчик отказов, — это вычитание из вердикта,
// как бы оно ни называлось. Ловим форму, а не имя переменной-источника: имя может
// быть любым (`known_red`, `expected`, `flaky`), а вот `fails=$((fails - …))`
// придётся написать.
var subtractsFromFailures = regexp.MustCompile(
	`(fails|failed|tot_fails|total_failed)\s*=\s*\$\(\(\s*(fails|failed|tot_fails|total_failed)\s*-`)

func TestVerdictSubtractsNothingFromFailures(t *testing.T) {
	lines := codeLines(t)
	var hits []string
	for i, ln := range lines {
		if subtractsFromFailures.MatchString(ln) {
			hits = append(hits, ln)
			t.Errorf("исполняемая строка %d вычитает из счётчика упавших утверждений: %s\n"+
				"Вердикт обязан сообщать то, что сообщил newman. Вычитание «известного красного» "+
				"снято 2026-07-30: предикат ключевался на ИМЕНИ, а утверждение «этот отказ — "+
				"известный лаг, а не настоящий отказ» есть утверждение о ПРИЧИНЕ, которой в имени "+
				"нет. Механизм, работающий по причине, уже есть — ограниченный повтор шага "+
				"(retry_until_*): он повторяет, пока ОТВЕТ говорит о конкретном временном "+
				"состоянии, а по исчерпании бюджета настоящее утверждение исполняется на "+
				"терминальном ответе. Красноту вести числом и списком в docs/RESULTS.md.", i+1, ln)
		}
	}
	// Перепись — отдельное утверждение: «ноль находок» обязано отличаться от
	// «ноль прочитанного».
	t.Logf("осмотрено %d исполняемых строк(и) %s; вычитаний найдено: %d",
		len(lines), verdictScript, len(hits))
}

// Вердикт обязан гейтить ВСЕ ЧЕТЫРЕ исхода запроса, а не только упавшие
// утверждения. Три из них — «проверка не исполнилась»: упавший скрипт, неотвеченный
// запрос, отчёт без утверждений. Каждый когда-то отсутствовал в этом скрипте, и
// каждый раз это выглядело как зелёная суита.
func TestVerdictGatesAllFourOutcomes(t *testing.T) {
	joined := strings.Join(codeLines(t), "\n")
	for _, want := range []struct{ name, needle string }{
		{"упавшие утверждения", "assertions.failed"},
		{"неотвеченные запросы", "requests.failed"},
		{"упавшие скрипты", "testScripts.failed"},
		{"отчёт без утверждений", "assertions.total"},
		{"отсутствующий отчёт", "no-report"},
	} {
		if !strings.Contains(joined, want.needle) {
			t.Errorf("вердикт не читает %s (%q отсутствует в исполняемой части). "+
				"Исход, который вердикт не читает, неотличим от «ничего не упало».",
				want.name, want.needle)
		}
	}
}
