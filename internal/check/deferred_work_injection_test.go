// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// deferred_work_injection_test.go — доказательство способности
// TestNoDeferredWorkInTheTree упасть и смолчать.
//
// Обе стороны гоняют ТУ ЖЕ функцию, что и гейт по дереву (check.AuditDeferredWork),
// на синтетическом репозитории во временном каталоге: своей рабочей копии
// инъекция не касается.
//
// Каждый мир отличается от своего законного близнеца ОДНИМ фактом: иначе
// неизвестно, какой из двух дал красное, и вердикт недействителен, хотя выглядит
// обычным зелёным.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// synthDeferralTree — синтетическое ОТСЛЕЖИВАЕМОЕ дерево.
//
// Отслеживаемое, а не просто разложенное по диску: область обхода разбор берёт
// у индекса git, и дерево без индекса дало бы «прочитано 0» — то есть зелёное
// по отсутствию предмета вместо вердикта.
//
// Подкаталоги НЕ засеиваются: корни выводятся из индекса, поэтому корни
// синтетики — ровно те, которые написала сама проба. Иначе проба про восьмой
// корень была бы неотличима от пробы про первый.
func synthDeferralTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "--quiet", "-b", "main")
	// Дерево обязано быть непустым: обход берёт состав у индекса и «смотреть не
	// на что» есть отказ, а не успех.
	write("README.md", "# синтетическое дерево пробы\n")
	for rel, body := range files {
		write(rel, body)
	}
	run("add", "-A")
	return root
}

// TestDeferralGateCatchesAMarkerInProductionCode — сторона ДЕФЕКТА: маркер в
// прод-коде роняет разбор и называет координату.
func TestDeferralGateCatchesAMarkerInProductionCode(t *testing.T) {
	t.Parallel()
	root := synthDeferralTree(t, map[string]string{
		"internal/thing/thing.go": "package thing\n\n// " + "TODO" +
			": дочинить после выпуска\nfunc F() {}\n",
	})
	findings, census, err := check.AuditDeferredWork(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Where, "internal/thing/thing.go:3") {
		t.Fatalf("маркер в прод-коде не пойман с координатой: %+v", findings)
	}
}

// TestDeferralGateCatchesAMarkerOutsideTheHandwrittenRoots — сторона дефекта,
// которую ВЫПИСАННАЯ область не ловила бы: маркер в корне, которого в перечне
// быть не могло.
//
// Область обхода обязана ВЫВОДИТЬСЯ из индекса: каталог, появившийся после
// написания перечня, иначе покрыт не будет, и об этом никто не узнает.
func TestDeferralGateCatchesAMarkerOutsideTheHandwrittenRoots(t *testing.T) {
	t.Parallel()
	root := synthDeferralTree(t, map[string]string{
		"deploy/helm/kaname/values.yaml": "replicas: 1\n# " + "FIXME" +
			": поднять предел после выпуска\n",
	})
	findings, census, err := check.AuditDeferredWork(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Where, "deploy/helm/kaname/values.yaml") {
		t.Fatalf("маркер вне кода не пойман (%+v): область обхода обязана ВЫВОДИТЬСЯ "+
			"из индекса дерева", findings)
	}
}

// TestDeferralGateStaysSilentOnLawfulTree — ЗАКОННЫЙ БЛИЗНЕЦ: тест с формой
// дефекта и шаблон без маркера разбор не трогает.
//
// Без этой половины запрет ловил бы форму, а не существо: первая же фикстура
// соседнего гейта, обязанная написать форму дефекта, красила бы прогон.
func TestDeferralGateStaysSilentOnLawfulTree(t *testing.T) {
	t.Parallel()
	root := synthDeferralTree(t, map[string]string{
		"internal/thing/thing_test.go": "package thing\n\n// " + "TODO" +
			": фикстура гейта пишет форму дефекта\n",
		"deploy/chart.yaml": "kind: ConfigMap\n# объяснение без отсрочки\n",
	})
	findings, census, err := check.AuditDeferredWork(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(findings) != 0 {
		t.Fatalf("разбор нашёл дефект в законном дереве: %+v", findings)
	}
	if census.Skipped["тестовый корпус"] != 1 {
		t.Fatalf("вычтено из тестового корпуса %d, ожидался 1 — иначе молчание "+
			"объясняется не вычитанием, а тем, что разбор не дошёл до файла",
			census.Skipped["тестовый корпус"])
	}
}

// TestDeferralGateStaysSilentOnStdlibContextTODO — ЗАКОННЫЙ БЛИЗНЕЦ, живой в
// ЭТОМ дереве: имя функции стандартной библиотеки отсрочкой не является.
//
// Близнец не гипотетический: то же имя стоит в прод-коде службы и в фикстурах
// соседнего гейта — запрет, ловящий слово, красил бы прогон на стандартной
// библиотеке.
//
// Положительный контроль стоит РЯДОМ и отличается ОДНИМ фактом: в той же строке
// добавлена форма обращения к читателю кода. Без него молчание на имени функции
// было бы неотличимо от разучившегося падать разбора.
func TestDeferralGateStaysSilentOnStdlibContextTODO(t *testing.T) {
	t.Parallel()
	root := synthDeferralTree(t, map[string]string{
		"internal/a/lawful.go": "package a\n\nimport \"context\"\n\n" +
			"func F() { _ = context." + "TODO" + "() }\n",
		"internal/b/defect.go": "package b\n\nimport \"context\"\n\n" +
			"func F() { _ = context." + "TODO" + "() } // " + "TODO" + ": убрать\n",
	})
	findings, census, err := check.AuditDeferredWork(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	var lawful, defect bool
	for _, f := range findings {
		if strings.Contains(f.Where, "internal/a/lawful.go") {
			lawful = true
		}
		if strings.Contains(f.Where, "internal/b/defect.go") {
			defect = true
		}
	}
	if lawful {
		t.Errorf("имя функции стандартной библиотеки объявлено отсрочкой: %+v — "+
			"запрет ловит слово, а не форму обращения", findings)
	}
	if !defect {
		t.Fatalf("положительный контроль не сработал: обещание в той же строке, где "+
			"стоит имя стандартной функции, не поймано (%+v) — тогда молчание на "+
			"законном близнеце ничего не доказывает", findings)
	}
}

// TestDeferralGateStaysSilentOnAQuotedMentionOfTheMarker — разговор О маркере
// обещанием не является, и порядок слов в нём ничего не решает.
//
// Проба несёт ОБЕ стороны в одном дереве: цитата обязана молчать, а настоящее
// обещание рядом с ней — краснеть. Без положительного контроля «ноль находок»
// было бы неотличимо от разбора, разучившегося падать.
func TestDeferralGateStaysSilentOnAQuotedMentionOfTheMarker(t *testing.T) {
	t.Parallel()
	root := synthDeferralTree(t, map[string]string{
		// Упоминание в прямом порядке слов — в кавычках.
		"docs/a.md": "То, что задача не делает, названо явно\n" +
			"— не «" + "потом " + "доделаем», а другой предмет с другим номером.\n",
		// Упоминание в обратном порядке слов — то же по существу.
		"docs/b.md": "| Р8 | Полнота: нет «" + "доделаем " + "потом» | ДА |\n",
		// Положительный контроль В ТОМ ЖЕ ВИДЕ ФАЙЛА: та же фраза, отличается
		// ТОЛЬКО отсутствием кавычек.
		"docs/c.md": "Порт закрыт наполовину, " + "потом " + "доделаем.\n",
		// Положительный контроль в прод-коде.
		"internal/thing/thing.go": "package thing\n\n// " + "пока " + "заглушка\nfunc F() {}\n",
	})
	findings, census, err := check.AuditDeferredWork(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Where] = true
		if strings.HasPrefix(f.Where, "docs/a.md") || strings.HasPrefix(f.Where, "docs/b.md") {
			t.Errorf("разбор объявил находкой ЦИТАТУ маркера: %s — %q\n"+
				"Разговор о маркере не есть обещание; запрет, ловящий слово, заставляет "+
				"переписывать собственную документацию о запрете — и первым делом "+
				"снимают сам запрет", f.Where, f.Line)
		}
	}
	if census.Mentions != 2 {
		t.Errorf("цитат отсечено %d, а их в дереве пробы две — перепись обязана "+
			"называть объём отсечённого, иначе «находок ноль» неотличимо от "+
			"«фильтр съел всё»", census.Mentions)
	}
	for _, want := range []string{"docs/c.md:1", "internal/thing/thing.go:3"} {
		if !seen[want] {
			t.Fatalf("положительный контроль не сработал: обещание %s не поймано (%+v) — "+
				"тогда молчание на цитатах ничего не доказывает", want, findings)
		}
	}
}

// TestDeferralGateCatchesTheReversedRussianWordOrder — порядок слов не есть
// существо: обе перестановки откладывают одно и то же.
//
// Порядок слов в русском свободен, поэтому распознаватель, знающий одну
// перестановку из двух, оставляет вторую вне наблюдения — не находкой и не
// чистотой, а невидимостью (`testing.md` §«Гейт на класс», п. 7).
func TestDeferralGateCatchesTheReversedRussianWordOrder(t *testing.T) {
	t.Parallel()
	root := synthDeferralTree(t, map[string]string{
		"internal/thing/thing.go": "package thing\n\n// " + "доделаем " +
			"потом\nfunc F() {}\n",
	})
	findings, census, err := check.AuditDeferredWork(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Where, "thing.go") {
		t.Fatalf("обратный порядок слов прошёл мимо разбора (%+v): распознаватель "+
			"различает ПЕРЕСТАНОВКУ, а не предмет", findings)
	}
}

// TestDeferralGateRefusesAnEmptyWalk — пустой обход есть ОТКАЗ, а не успех.
//
// Отказ приходит из состава дерева и НЕ маскируется разбором: «ноль находок» на
// «ноль прочитанного» неотличимо от чистого дерева, поэтому обход, которому
// нечего читать, обязан вернуть признак, а не пустой перечень находок.
//
// Проба утверждает ОБЕ половины: признак есть и находок нет. Без второй
// половины отказ был бы неотличим от «разбор успел что-то насчитать и упал».
func TestDeferralGateRefusesAnEmptyWalk(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if out, err := gitenv.Command(root, "init", "--quiet", "-b", "main").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	// Файл есть на диске, но НЕ в индексе: область берётся у индекса, а не с
	// диска — иначе в неё заезжает игнорируемое, и вердикт не о поставке.
	if err := os.WriteFile(filepath.Join(root, "thing.go"),
		[]byte("package thing\n\n// "+"TODO"+": не в индексе\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, census, err := check.AuditDeferredWork(root)
	if err == nil {
		t.Fatalf("пустой обход прошёл БЕЗ признака: прочитано %d, находок %d — "+
			"тогда «маркеров нет» означает «ничего не читал», и отличить это нечем",
			census.Read, len(findings))
	}
	if census.Read != 0 || len(findings) != 0 {
		t.Fatalf("при отказе разбор всё же что-то насчитал: прочитано %d, находок %d",
			census.Read, len(findings))
	}
	if !strings.Contains(err.Error(), "состав дерева") {
		t.Errorf("признак не называет предмет отказа: %v — читатель пойдёт искать "+
			"причину не там", err)
	}
}
