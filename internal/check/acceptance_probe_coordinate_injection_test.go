// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_probe_coordinate_injection_test.go — доказательство способности
// гейта УПАСТЬ и СМОЛЧАТЬ.
//
// Инъекция подаётся судящему ядру значениями и синтетическому дереву в своём
// временном каталоге: писать в индекс, настройки или дерево, из которого
// запущена проба, запрещено. Ронять она обязана ТОЛЬКО проверяемое — поэтому
// вход собирается из законных документов, у которых снято ровно одно
// свойство.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/kaname/internal/check"
)

// liveProbeNames — объявления, играющие роль дерева проб. Две формы записи
// координаты, обе законные: полное имя и идентификатор сценария.
var liveProbeNames = []string{
	"TestIAMCT112_CatalogProbesDoNotDeferEverything",
	"TestIAMCT112_SecondProbeOfTheSameScenario",
	"TestMODMR10RolesSectionLoads",
}

// TestAcceptanceProbeCoordinateInjection — три прогона на одной оси: контроль,
// инъекция, законный близнец.
func TestAcceptanceProbeCoordinateInjection(t *testing.T) {
	findings := func(body string) []string {
		return check.JudgeProbeCoordinates(
			map[string]string{"docs/engineering/acceptance/x.md": body},
			liveProbeNames, nil).Findings
	}

	// ── Прогон 1. КОНТРОЛЬ: обе законные формы координаты живы ────────────────
	control := "Полное имя: `TestMODMR10RolesSectionLoads` — положительный контроль.\n" +
		"Идентификатором сценария: `TestIAMCT112` — отбирает семейство.\n" +
		"С подпробой: `TestIAMCT112/случай` — судится основание.\n"
	if f := findings(control); len(f) != 0 {
		t.Fatalf("КОНТРОЛЬ: гейт покраснел на живых координатах — он ловит форму, "+
			"а не существо: %v", f)
	}

	// ── Прогон 2. ИНЪЕКЦИЯ: координата не резолвится ──────────────────────────
	dead := control + "Мёртвая: `TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule`.\n"
	f := findings(dead)
	if len(f) != 1 {
		t.Fatalf("ИНЪЕКЦИЯ: находок %d, ожидалась ровно одна — гейт ловит не то, "+
			"что инъекция сняла: %v", len(f), f)
	}
	if !strings.Contains(f[0], "TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule") {
		t.Errorf("находка не называет мёртвую координату: %q", f[0])
	}
	if !strings.Contains(f[0], "x.md:4") {
		t.Errorf("находка не называет место (документ и строку): %q", f[0])
	}

	// ── Прогон 3. ЗАКОННЫЕ БЛИЗНЕЦЫ: то же имя, но НЕ координата ──────────────
	twins := control +
		"Проба TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule снята " +
		"вместе со своим предметом — это проза, а не адрес.\n" +
		"Предикат внутри пролёта кода: " +
		"`go test -run '^TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule$'`\n" +
		"```sh\ngo test ./... -run TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule\n```\n"
	if f := findings(twins); len(f) != 0 {
		t.Errorf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на прозе разбора либо на предикате — "+
			"он судит слово, а не координату: %v", f)
	}

	// ── Самоистечение послабления: оба конца ─────────────────────────────────
	used := check.JudgeProbeCoordinates(
		map[string]string{"a.md": "`TestGoneForGood`"}, liveProbeNames,
		[]check.DeadProbeCoordinate{{Name: "TestGoneForGood", Issue: 1}}).Findings
	if len(used) != 0 {
		t.Errorf("послабление С ПРЕДМЕТОМ обязано молчать: %v", used)
	}
	for name, why := range map[string]string{
		"TestGoneForGood":              "имя больше не стоит ни в одной приёмке",
		"TestMODMR10RolesSectionLoads": "имя снова резолвится функцией в дереве",
	} {
		got := check.JudgeProbeCoordinates(
			map[string]string{"a.md": "`TestMODMR10RolesSectionLoads`"}, liveProbeNames,
			[]check.DeadProbeCoordinate{{Name: name, Issue: 1}}).Findings
		if len(got) != 1 || !strings.Contains(got[0], why) {
			t.Errorf("послабление БЕЗ ПРЕДМЕТА (%s) не найдено либо названо не тем: %v", name, got)
		}
	}
}

// TestAcceptanceProbeCoordinateWalkersInjection — вторая половина: обходчики
// действительно находят корпус и объявления. Ядро выше судит поданные
// значения и о том, ОТКУДА они взялись, не утверждает ничего.
//
// Отличие от монорепо-версии: там синтетика несла ДВА каталога приёмок разных
// служб (`services/iam/…`, `services/nlb/…`), потому что обходчик смотрел под
// `services/*`. Самостоятельный клон службы каталог `services/` не несёт
// вовсе — обходчик смотрит под `docs/engineering/acceptance` от корня модуля,
// и синтетика ниже это отражает: один каталог приёмок, документ вне него
// корпусом не является.
func TestAcceptanceProbeCoordinateWalkersInjection(t *testing.T) {
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "gate@example.invalid")
	run("config", "user.name", "gate")

	write("docs/engineering/acceptance/live.md", "`TestSynthetic`\n`TestSyntheticGone`\n")
	// Приёмка ВНЕ каталога приёмок корпусом не является.
	write("docs/engineering/design.md", "`TestNotACoordinate`\n")
	write("internal/x/x_test.go", "package x\n\nfunc TestSynthetic(t *testing.T) {}\n")
	run("add", "-A")
	run("commit", "--quiet", "-m", "синтетика")

	docs, err := check.AcceptanceDocsOfTree(root)
	if err != nil {
		t.Fatalf("обходчик приёмок отказал: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("обходчик приёмок нашёл %d документов, ожидался 1 (файл вне каталога приёмок "+
			"и файл не с суффиксом .md корпусом не являются): %v", len(docs), docs)
	}
	declared, err := check.DeclaredProbesOfTree(root)
	if err != nil {
		t.Fatalf("обходчик объявлений отказал: %v", err)
	}
	if len(declared) != 1 || declared[0] != "TestSynthetic" {
		t.Fatalf("обходчик объявлений нашёл %v, ожидалось [TestSynthetic]", declared)
	}
	c := check.JudgeProbeCoordinates(docs, declared, nil)
	if c.Coordinates != 2 || c.Resolved != 1 || len(c.Findings) != 1 {
		t.Fatalf("перепись синтетики: координат %d (ожидалось 2), резолвится %d (1), "+
			"находок %d (1)", c.Coordinates, c.Resolved, len(c.Findings))
	}
	if !strings.Contains(c.Findings[0], "TestSyntheticGone") {
		t.Errorf("находка не называет мёртвую координату: %q", c.Findings[0])
	}
}

// TestAcceptanceProbeCoordinateNamedHomeInjection — оси НАЗВАННОГО ДОМА.
//
// Предмет этих осей появился вместе с выносом службы: приёмка уехала, а гейт,
// который она называет держателем, остался в монорепо. Координата обязана
// называть дом, и названный чужой дом — ВНЕ суждения по построению: ни
// подтвердить, ни опровергнуть объявление в чужом репозитории этот гейт не
// может. Доктрина в дереве уже есть — `carried_coordinate_ledger.go` §«Кросс-репо
// координата — вне суждения ОБОИХ сторон».
//
// «Вне суждения» отличается от «прощено» ровно одним: чужая координата
// СЧИТАЕТСЯ и её дом ПЕЧАТАЕТСЯ. Поэтому оси ниже требуют, чтобы пролёт с
// названным домом был РАСПОЗНАН координатой (иначе он уходит из переписи, и
// приставка становится способом спрятать адрес), и чтобы приставка, домом НЕ
// являющаяся, была находкой (иначе `kacho:TestFoo` — та же дыра, но без формы).
func TestAcceptanceProbeCoordinateNamedHomeInjection(t *testing.T) {
	judge := func(body string) check.ProbeCoordinateCensus {
		return check.JudgeProbeCoordinates(
			map[string]string{"docs/engineering/acceptance/x.md": body},
			liveProbeNames, nil)
	}

	// ── Ось 1. Чужой дом РАСПОЗНАН координатой и находкой НЕ является ─────────
	c := judge("Держатель живёт в монорепо: `PRO-Robotech/kacho:TestNotHereAtAll`.\n")
	if c.Coordinates != 1 {
		t.Errorf("координат %d, ожидалась 1: пролёт с названным домом обязан попасть "+
			"в перепись — иначе приставка прячет адрес, а не называет его", c.Coordinates)
	}
	if len(c.Findings) != 0 {
		t.Errorf("чужой дом обязан быть ВНЕ суждения, а не находкой: %v", c.Findings)
	}

	// ── Ось 2. Ревизия у чужого дома — законная форма, тоже вне суждения ──────
	c = judge("Гейт снят вынесением службы: " +
		"`PRO-Robotech/kacho@d941344bd9:TestGoneWithTheExtraction`.\n")
	if c.Coordinates != 1 {
		t.Errorf("координат %d, ожидалась 1: ревизия у названного дома — законная "+
			"форма координаты, а не мусор", c.Coordinates)
	}
	if len(c.Findings) != 0 {
		t.Errorf("координата, связанная ревизией чужого дома, находкой не является: %v",
			c.Findings)
	}

	// ── Ось 3. Приставка, домом НЕ являющаяся, — НАХОДКА ──────────────────────
	// Иначе любой не-разобранный префикс снимает координату с суждения.
	for _, bad := range []string{"kacho", "PRO-Robotech/", "IAM-MV-04"} {
		c = judge("Плохой дом: `" + bad + ":TestNotHereAtAll`.\n")
		if len(c.Findings) != 1 {
			t.Errorf("приставка %q домом не является, а находок %d (ожидалась 1): "+
				"приставка без формы дома — та же дыра, что мёртвая координата: %v",
				bad, len(c.Findings), c.Findings)
		}
	}

	// ── Ось 4. ЗАКОННЫЕ БЛИЗНЕЦЫ с двоеточием координатами НЕ являются ────────
	// Пути с номером строки стоят в этом корпусе сотнями; принять их за
	// координату значило бы краснеть на верных документах.
	twins := "Дом гейта — `internal/repohygiene/acceptanceledger_test.go:116`, " +
		"вторая координата — `:108`, каталог — `internal/repohygiene`, " +
		"а срез — `internal/check/x_test.go:47`.\n"
	if c = judge(twins); c.Coordinates != 0 || len(c.Findings) != 0 {
		t.Errorf("законные близнецы: координат %d (ожидалось 0), находок %d (0): %v",
			c.Coordinates, len(c.Findings), c.Findings)
	}
}

// TestAcceptanceProbeCoordinateHomeCensusInjection — оси ПЕРЕПИСИ чужих домов и
// обоих сторожей гейта.
//
// Сторожа живут в самом гейте (`acceptance_probe_coordinate_test.go`), потому что
// им нужен дом ЭТОГО дерева, а ядро судит значения. Способность сторожа
// сработать доказывается здесь: предпосылка каждого — величина переписи, и она
// подаётся значениями.
func TestAcceptanceProbeCoordinateHomeCensusInjection(t *testing.T) {
	judge := func(body string) check.ProbeCoordinateCensus {
		return check.JudgeProbeCoordinates(
			map[string]string{"docs/engineering/acceptance/x.md": body},
			liveProbeNames, nil)
	}

	// ── Ось 5. Дома ПЕЧАТАЮТСЯ и различаются, ревизия в дом не входит ──────────
	c := judge("`PRO-Robotech/kacho:TestOne` и `PRO-Robotech/kacho@d941344bd9:TestTwo` " +
		"и `PRO-Robotech/corelib:TestThree`\n")
	if c.Foreign != 3 {
		t.Errorf("чужих координат %d, ожидалось 3", c.Foreign)
	}
	// Связанных ревизией ровно одна из трёх: величина отвечает на другой вопрос —
	// сколько координат указывает в ПРОШЛОЕ состояние чужого дерева.
	if c.RevisionBound != 1 {
		t.Errorf("связанных ревизией %d, ожидалась 1 из трёх", c.RevisionBound)
	}
	want := "PRO-Robotech/corelib · PRO-Robotech/kacho"
	if got := strings.Join(c.ForeignHomes, " · "); got != want {
		t.Errorf("перепись домов %q, ожидалась %q: ревизия в имя дома не входит, "+
			"иначе один дом двоится на каждую названную ревизию", got, want)
	}

	// ── Ось 6. ПРЕДПОСЫЛКА сторожа 1: корпус, где судить нечего ───────────────
	if c.Coordinates != c.Foreign {
		t.Errorf("корпус из одних чужих координат: координат %d, чужих %d — сторож, "+
			"отвергающий такой корпус, не смог бы сработать", c.Coordinates, c.Foreign)
	}
	// Обратная сторона: хотя бы одна МЕСТНАЯ координата снимает предпосылку.
	c = judge("`TestMODMR10RolesSectionLoads` и `PRO-Robotech/kacho:TestOne`\n")
	if c.Coordinates == c.Foreign {
		t.Errorf("местная координата в корпусе есть, а предпосылка сторожа 1 держится: "+
			"координат %d, чужих %d — сторож ронял бы верный корпус",
			c.Coordinates, c.Foreign)
	}

	// ── Ось 7. ПРЕДПОСЫЛКА сторожа 2: свой дом виден в переписи ───────────────
	c = judge("`PRO-Robotech/kaname:TestNotHereAtAll`\n")
	if len(c.ForeignHomes) != 1 || c.ForeignHomes[0] != "PRO-Robotech/kaname" {
		t.Errorf("перепись домов %v — сторож 2 сверяет её со своим домом и без записи "+
			"сработать не может", c.ForeignHomes)
	}
	if len(c.Findings) != 0 {
		t.Errorf("ядро о СВОЁМ доме не знает и находки давать не должно — её даёт "+
			"сторож гейта: %v", c.Findings)
	}
}

// TestAcceptanceProbeCoordinateOwnHomeInjection — обходчик дома дерева.
//
// Три исхода, и каждый обязан быть отличим: дом выведен · строки `module` нет ·
// путь модуля короче трёх сегментов. Второй и третий — ОТКАЗ, а не пустая
// строка: пустой дом сделал бы сторожа 2 всеразрешающим.
func TestAcceptanceProbeCoordinateOwnHomeInjection(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}

	got, err := check.OwnHomeOfTree(write(t, "module github.com/PRO-Robotech/kaname\n\ngo 1.26.0\n"))
	if err != nil || got != "PRO-Robotech/kaname" {
		t.Errorf("дом выведен как %q при ошибке %v, ожидалось PRO-Robotech/kaname", got, err)
	}
	if _, err = check.OwnHomeOfTree(write(t, "go 1.26.0\n")); err == nil {
		t.Error("go.mod без строки module обязан быть ОТКАЗОМ: пустой дом сделал бы " +
			"сторожа своего дома всеразрешающим")
	}
	if _, err = check.OwnHomeOfTree(write(t, "module kaname\n")); err == nil {
		t.Error("путь модуля из одного сегмента дома не даёт — обязан быть отказ")
	}
	if _, err = check.OwnHomeOfTree(t.TempDir()); err == nil {
		t.Error("дерево без go.mod обязано быть ОТКАЗОМ, а не пустым домом")
	}
}
