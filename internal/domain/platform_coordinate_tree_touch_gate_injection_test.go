// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_coordinate_tree_touch_gate_injection_test.go — гейт касаний СПОСОБЕН
// упасть и СПОСОБЕН смолчать, и это доказано ПО КАЖДОМУ ВИДУ БАЗЫ ПОРОЗНЬ.
//
// Инъекция идёт по СИНТЕТИЧЕСКИМ исходникам, а не по настоящему дереву: вернуть
// дефект в дерево значило бы править файл, чей вердикт этим же прогоном и
// читается.
//
// # У КАЖДОЙ НАХОДКИ ЕСТЬ ЗАКОННЫЙ БЛИЗНЕЦ, ОТЛИЧАЮЩИЙСЯ ОДНИМ ФАКТОМ
//
// Иначе неизвестно, от чего пришло красное. Пары здесь такие:
//
//	побег ↔ первый маркер   — ветвь попадания ЗАПИСЫВАЕТ каталог против
//	                          ВОЗВРАЩАЕТ его. Ни одного другого различия;
//	вычислено ↔ детектор    — та же координата, тот же вызов, другая база;
//	вычислено ↔ синтетика   — та же фикстура, корень от `t.TempDir()`. Это и
//	                          есть различитель из предиката задачи;
//	касание ↔ упоминание    — та же строка: в `os.ReadFile` против сообщения.
//
// # ПОЧЕМУ ОЖИДАНИЕ ОБЪЯВЛЯЕТСЯ ДВУМЯ ВЕЛИЧИНАМИ
//
// «Находок нет» приходит и от чистого исходника, и от того, что распознаватель
// не увидел касания вовсе. Различает их только число касаний, поэтому каждый
// случай объявляет ОБЕ величины — сколько касаний распознано и какой вид базы им
// приписан.
package domain_test

import (
	"strings"
	"testing"
)

// treeTouchFixture — минимальный разбираемый исходник Go.
//
// Импорты стоят все и всегда: разбор не проверяет типы, зато их отсутствие
// заставляло бы каждый случай нести свою шапку — и различие случаев перестало бы
// быть одним фактом.
func treeTouchFixture(body string) string {
	return "package p\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\n" +
		"var _, _, _ = fmt.Sprintf, os.ReadFile, filepath.Join\n\n" + body
}

func TestPlatformCoordinateTreeTouchGate_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantTouches int
		wantBase    baseKind
		wantFinding string
		why         string
	}{
		// ── ПОБЕГ ПРОТИВ ПЕРВОГО МАРКЕРА: различие СТРОЕНИЯ, не имени ────────
		{
			name: "НАХОДКА: подъём к САМОМУ ВНЕШНЕМУ маркеру — ветвь ЗАПИСЫВАЕТ и идёт выше",
			body: `
func repoRoot() string {
	dir, _ := os.Getwd()
	outer := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outer = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return outer
		}
		dir = parent
	}
}

func read() {
	_, _ = os.ReadFile(filepath.Join(repoRoot(), "proto/kaname/cloud/iam/v1/role.proto"))
}`,
			wantTouches: 1,
			wantBase:    baseEscaping,
			wantFinding: "побег за корень модуля",
			why:         "подъём не останавливается на своём корне — под чужим деревом даст чужой",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: тот же подъём ВОЗВРАЩАЕТ каталог на первом маркере",
			body: `
func repoRoot() string {
	dir, _ := os.Getwd()
	outer := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return outer
		}
		dir = parent
	}
}

func read() {
	_, _ = os.ReadFile(filepath.Join(repoRoot(), "proto/kaname/cloud/iam/v1/role.proto"))
}`,
			wantTouches: 1,
			wantBase:    baseModuleRoot,
			why:         "остановка на ПЕРВОМ маркере за корень модуля не выходит by construction",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: подъём к первому маркеру вынесен в СОСЕДНЮЮ функцию пакета",
			body: `
func rootFrom(start string) string {
	dir := start
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func serviceRoot() string {
	wd, _ := os.Getwd()
	return rootFrom(wd)
}

func read() {
	_, _ = os.ReadFile(filepath.Join(serviceRoot(), "deploy/values.yaml"))
}`,
			wantTouches: 1,
			wantBase:    baseModuleRoot,
			why:         "вид помощника наследуется по цепочке вызовов своего пакета",
		},

		// ── ВЫЧИСЛЕНО ЗДЕСЬ ПРОТИВ ДЕТЕКТОРА ────────────────────────────────
		{
			name: "НАХОДКА: база вычислена локальной функцией, ничего не резолвящей",
			body: `
func someRoot() string {
	wd, _ := os.Getwd()
	return filepath.Dir(wd)
}

func read() {
	_, _ = os.ReadFile(filepath.Join(someRoot(), "proto/kaname/cloud/iam/v1/role.proto"))
}`,
			wantTouches: 1,
			wantBase:    baseLocal,
			wantFinding: "вычислена здесь",
			why:         "посадку назначает арифметика пути, а не детектор",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: та же координата на базе от детектора",
			body: `
func read(t *testingT) {
	_, _ = os.ReadFile(filepath.Join(platformtree.Require(t), "proto/kaname/cloud/iam/v1/role.proto"))
}`,
			wantTouches: 1,
			wantBase:    baseDetector,
			why:         "различие ровно одно — чем получена база",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: координата приведена детектором целиком",
			body: `
const rel = "proto/kaname/cloud/iam/v1/role.proto"

func read(t *testingT) {
	_, _ = os.ReadFile(platformtree.RequirePath(t, rel))
}`,
			wantTouches: 1,
			wantBase:    baseDetector,
			why:         "координата в файловой константе, приведена по имени",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: ТРЕТИЙ детектор — treeroot, корень по индексу дерева",
			body: `
const rel = "proto/kaname/cloud/iam/v1/fga_model.fga"

func read(start string) {
	root, err := treeroot.Of(start)
	if err != nil {
		return
	}
	_, _ = os.ReadFile(filepath.Join(root, rel))
}`,
			wantTouches: 1,
			wantBase:    baseDetector,
			why:         "распознаватель обязан знать ВСЕ законные формы резолва, а не две из трёх",
		},

		// ── СИНТЕТИКА: НЕСУЩИЙ ЗАКОННЫЙ БЛИЗНЕЦ ИЗ ПРЕДИКАТА ЗАДАЧИ ─────────
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: фикстура строит СИНТЕТИЧЕСКОЕ дерево под t.TempDir()",
			body: `
func writeTree(t *testingT) string {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "services/vpc/manifest.yaml"), nil, 0o600)
	return root
}`,
			wantTouches: 1,
			wantBase:    baseSynthetic,
			why:         "координата под синтетическим корнем настоящего дерева не трогает",
		},
		{
			name: "ПАРНЫЙ НАРУШИТЕЛЬ: та же фикстура, корень вычислен здесь вместо t.TempDir()",
			body: `
func ownRoot() string {
	wd, _ := os.Getwd()
	return filepath.Dir(wd)
}

func writeTree(t *testingT) string {
	root := ownRoot()
	_ = os.WriteFile(filepath.Join(root, "services/vpc/manifest.yaml"), nil, 0o600)
	return root
}`,
			wantTouches: 1,
			wantBase:    baseLocal,
			wantFinding: "вычислена здесь",
			why:         "различие ровно одно — откуда взят корень",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: синтетика через помощника СВОЕГО пакета",
			body: `
func tempRoot(t *testingT) string { return t.TempDir() }

func writeTree(t *testingT) {
	_ = os.WriteFile(filepath.Join(tempRoot(t), "services/vpc/manifest.yaml"), nil, 0o600)
}`,
			wantTouches: 1,
			wantBase:    baseSynthetic,
			why:         "вид помощника выводится, а не берётся из перечня имён",
		},

		// ── КАСАНИЕ ПРОТИВ УПОМИНАНИЯ ───────────────────────────────────────
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: координата УПОМЯНУТА в сообщении и дерева не трогает",
			body: `
func report() string {
	return fmt.Sprintf("отчёт: %s", "services/iam/internal/repo/kaname/pg/scalegrid/REPORT.txt")
}`,
			wantTouches: 0,
			why:         "строка в тексте отказа путём не становится никогда",
		},
		{
			name: "ПАРА К НЕМУ: та же строка отдана os.ReadFile",
			body: `
func report() {
	_, _ = os.ReadFile("services/iam/internal/repo/kaname/pg/scalegrid/REPORT.txt")
}`,
			wantTouches: 1,
			wantBase:    baseNone,
			wantFinding: "нет базы (рабочий каталог)",
			why:         "голая координата открывается от рабочего каталога прогона",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: голое имя каталога координатой не является",
			body: `
func read(t *testingT) {
	_, _ = os.ReadFile(filepath.Join(someRoot(), "deploy"))
}

func someRoot() string {
	wd, _ := os.Getwd()
	return wd
}`,
			wantTouches: 0,
			why:         "без разделителя это имя каталога, и краснеть на слове гейт не вправе",
		},

		// ── БАЗА ОТ ВЫЗЫВАЮЩЕГО ─────────────────────────────────────────────
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: база — ПАРАМЕТР функции: посадку назначает вызывающий",
			body: `
func scan(root string) {
	_, _ = os.ReadFile(filepath.Join(root, ".github/workflows/ci.yml"))
}`,
			wantTouches: 1,
			wantBase:    baseCallerGiven,
			why:         "этот файл посадки не выбирает, и судить её надо у вызывающего",
		},

		// ── ОБХОД, САМ ПРИВЕДЁННЫЙ ДЕТЕКТОРОМ ───────────────────────────────
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: обход приведён детектором, элементы наследуют посадку",
			body: `
const rel = "services/iam/internal/migrations/*.sql"

func read(t *testingT) {
	files, _ := treecorpus.Glob(platformtree.RequirePath(t, rel))
	for _, f := range files {
		_, _ = os.ReadFile(f)
	}
}`,
			wantTouches: 1,
			wantBase:    baseDetector,
			why:         "путь пришёл из обхода, который сам приведён детектором",
		},
		{
			name: "ПАРА К НЕМУ: тот же обход от локально вычисленного корня",
			body: `
const rel = "services/iam/internal/migrations/*.sql"

func ownRoot() string {
	wd, _ := os.Getwd()
	return filepath.Dir(wd)
}

func read() {
	files, _ := treecorpus.Glob(filepath.Join(ownRoot(), rel))
	for _, f := range files {
		_, _ = os.ReadFile(f)
	}
}`,
			wantTouches: 1,
			wantBase:    baseLocal,
			wantFinding: "вычислена здесь",
			why:         "различие ровно одно — чем приведён корень обхода",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, census, err := auditTreeTouch(
				[]sourceFile{{Name: "fixture.go", Depth: 1, Text: treeTouchFixture(c.body)}})
			if err != nil {
				t.Fatalf("разбор не отработал: %v", err)
			}
			t.Logf("перепись: %s · найдено %d", census, len(findings))

			if census.Touches != c.wantTouches {
				t.Errorf("касаний распознано %d, хотел %d (%s)", census.Touches, c.wantTouches, c.why)
			}
			if c.wantTouches > 0 && census.ByBase[c.wantBase] != c.wantTouches {
				t.Errorf("вид базы %q приписан %d касаниям, хотел %d (%s); перепись: %s",
					baseKindName[c.wantBase], census.ByBase[c.wantBase], c.wantTouches, c.why, census)
			}

			joined := strings.Join(findings, "\n")
			if c.wantFinding == "" {
				if joined != "" {
					t.Errorf("гейт краснеет на законном исходнике (%s):\n%s", c.why, joined)
				}
				return
			}
			if len(findings) != 1 {
				t.Errorf("находок %d, хотел 1 (%s):\n%s", len(findings), c.why, joined)
			}
			// Проверяется не только «покраснел», но и ЧТО НАПЕЧАТАЛ: находка,
			// называющая симптом вместо причины, посылает читателя искать не там.
			if !strings.Contains(joined, c.wantFinding) {
				t.Errorf("находка не назвала вид базы (%s).\nхотел подстроку: %q\nполучил:\n%s",
					c.why, c.wantFinding, joined)
			}
			if !strings.Contains(joined, "fixture.go:") {
				t.Errorf("находка не назвала координату файла и строку:\n%s", joined)
			}
		})
	}
	t.Logf("перепись инъекции: случаев %d", len(cases))
}

// TestPlatformCoordinateTreeTouchGate_HelpersAreResolvedWithinThePackage —
// вид помощника выводится по ВСЕМУ пакету, а не по одному файлу.
//
// Отдельный случай, потому что харнесс выше подаёт один исходник, а разнесение
// резолва по файлам пакета — обычная и законная раскладка. Не знать её значило бы
// краснеть на верном коде ровно там, где подъём вынесен в свой файл.
func TestPlatformCoordinateTreeTouchGate_HelpersAreResolvedWithinThePackage(t *testing.T) {
	helper := treeTouchFixture(`
func serviceRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}`)
	reader := treeTouchFixture(`
func read() {
	_, _ = os.ReadFile(filepath.Join(serviceRoot(), "deploy/values.yaml"))
}`)

	same, census, err := auditTreeTouch([]sourceFile{
		{Name: "pkg/root.go", Depth: 1, Text: helper},
		{Name: "pkg/read.go", Depth: 1, Text: reader},
	})
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	t.Logf("один пакет: %s · найдено %d", census, len(same))
	if len(same) != 0 {
		t.Errorf("гейт краснеет на подъёме, вынесенном в свой файл ТОГО ЖЕ пакета:\n%s",
			strings.Join(same, "\n"))
	}

	// Зеркало: тот же помощник в ЧУЖОМ пакете виден быть не должен, и молчать на
	// этом нельзя — «не выведена» есть находка, а не согласие.
	other, census2, err := auditTreeTouch([]sourceFile{
		{Name: "one/root.go", Depth: 1, Text: helper},
		{Name: "two/read.go", Depth: 1, Text: reader},
	})
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	t.Logf("разные пакеты: %s · найдено %d", census2, len(other))
	if len(other) != 1 {
		t.Fatalf("помощник ЧУЖОГО пакета принят за свой: находок %d, хотел 1", len(other))
	}
	if !strings.Contains(other[0], baseKindName[baseLocal]) {
		t.Errorf("находка не назвала вид базы:\n%s", other[0])
	}
}

// TestPlatformCoordinateTreeTouchGate_UnparsableSourceIsNotAVerdict —
// неразбираемый исходник даёт ОТКАЗ РАЗБОРА, а не «находок ноль».
func TestPlatformCoordinateTreeTouchGate_UnparsableSourceIsNotAVerdict(t *testing.T) {
	_, _, err := auditTreeTouch([]sourceFile{{Name: "broken.go", Text: "package p\n\nfunc ( {"}})
	if err == nil {
		t.Fatal("неразбираемый исходник принят за прочитанный — вердикт был бы беспредметным")
	}
	t.Logf("отказ разбора, как и должно: %v", err)
}

// TestPlatformCoordinateTreeTouchGate_EmptyWalkIsCountedAsZero — пустой вход даёт
// нулевую перепись, и именно она отличает «ноль находок» от «ноль прочитанного».
func TestPlatformCoordinateTreeTouchGate_EmptyWalkIsCountedAsZero(t *testing.T) {
	findings, census, err := auditTreeTouch(nil)
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("находки на пустом входе: %v", findings)
	}
	if census.Files != 0 || census.Touches != 0 {
		t.Fatalf("перепись лжёт на пустом входе: %s", census)
	}
	t.Logf("перепись: %s — премисы `Files == 0` и `Touches == 0` роняют пробу дерева", census)
}
