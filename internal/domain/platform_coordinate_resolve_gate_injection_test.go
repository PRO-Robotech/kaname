// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_coordinate_resolve_gate_injection_test.go — гейт СПОСОБЕН упасть и
// СПОСОБЕН смолчать, и это доказано ПО КАЖДОЙ ФОРМЕ ПОРОЗНЬ.
//
// Инъекция идёт по СИНТЕТИЧЕСКИМ исходникам, а не по настоящему дереву: вернуть
// дефект в дерево значило бы править файл, чей вердикт этим же прогоном и
// читается. У каждого случая-находки есть ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся ровно
// одним фактом, — иначе неизвестно, от чего пришло красное.
//
// # Почему «по каждой форме порознь» — это требование, а не аккуратность
//
// Форма записи, о которой распознаватель не знает, не даёт ни красного, ни
// зелёного: она МОЛЧИТ. Одна инъекция, покрасневшая на одной форме, о двух
// остальных не утверждает ничего — ровно так прежняя редакция и была зелена при
// живом экземпляре в дереве (#2289). Поэтому форм здесь три, и каждая внесена
// отдельным случаем со своим близнецом:
//
//	цикл           — прямая и двухшаговая записи, `filepath` и `path`;
//	фиксированный  — `Join` с литеральными `..`, обе стороны арифметики глубины;
//	литерал        — одна строка, обе стороны той же арифметики.
//
// # Почему ожидание объявляется ПО ОСЯМ, а не одним списком
//
// Оси у гейта две, и фикстура подъёма ЗАКОННО задевает обе: путь, чей якорь —
// подъём, якоря-детектора не имеет by construction. Слитое ожидание («находок
// нет») заставило бы подгонять фикстуру под инструмент, пряча вторую ось. Здесь
// каждый случай объявляет ОБЕ величины, поэтому видно, что именно сказала каждая
// ось и какая из них меняется тем самым «одним фактом».
package domain_test

import (
	"strings"
	"testing"
)

// resolveFixture — минимальный исходник Go: гейт разбирает синтаксическое
// дерево, поэтому фикстура обязана быть разбираемой, а не похожей на код.
//
// Импорты стоят все и всегда: разбор не проверяет типы, зато их отсутствие
// заставляло бы каждый случай нести свою шапку — и различие случаев перестало бы
// быть одним фактом.
func resolveFixture(body string) string {
	return "package p\n\nimport (\n\t\"os\"\n\t\"path\"\n\t\"path/filepath\"\n)\n\n" +
		"var _, _, _ = os.ReadFile, filepath.Join, path.Join\n\n" + body
}

func TestPlatformCoordinateResolveGate_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		depth          int
		wantFinding    string
		wantCoords     int
		wantResolves   int
		wantAscents    int
		wantUnanchored int
		why            string
	}{
		// ── ФОРМА 1: ЦИКЛ ───────────────────────────────────────────────────
		{
			name: "форма 1 (цикл), прямая запись: dir = filepath.Dir(dir), щупает координату",
			body: `
func root() string {
	dir, _ := os.Getwd()
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "proto/kaname/cloud/iam/v1/role.proto")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}`,
			depth:          2,
			wantFinding:    "собственный подъём по дереву (цикл)",
			wantCoords:     1,
			wantAscents:    1,
			wantUnanchored: 1,
			why:            "ровно то, чем три пробы задачи #2160 читали контракт до правки",
		},
		{
			name: "форма 1 (цикл), ДВУХШАГОВАЯ запись: parent := Dir(dir); dir = parent",
			body: `
func root() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}`,
			depth:          2,
			wantFinding:    "собственный подъём по дереву (цикл)",
			wantCoords:     1,
			wantAscents:    1,
			wantUnanchored: 1,
			why: "ЖИВАЯ форма: так записаны и сам детектор, и второй экземпляр класса " +
				"в tools/newmanverdict. Распознаватель, знающий только прямую запись, молчал бы",
		},
		{
			name: "форма 1 (цикл), пакет path вместо filepath",
			body: `
func root() string {
	dir, _ := os.Getwd()
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(path.Join(dir, "proto/kaname/cloud/iam/v1/role.proto")); err == nil {
			return dir
		}
		dir = path.Dir(dir)
	}
	return ""
}`,
			depth:          2,
			wantFinding:    "собственный подъём по дереву (цикл)",
			wantCoords:     1,
			wantAscents:    1,
			wantUnanchored: 1,
			why:            "второй пакет той же формы; прежняя редакция знала только filepath",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: тот же цикл щупает МАРКЕР МОДУЛЯ, а не координату",
			body: `
func moduleRoot() string {
	dir, _ := os.Getwd()
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && st.Mode().IsRegular() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}`,
			depth: 2,
			why: "один факт против случая выше — что щупает цикл. Подъём к go.mod " +
				"останавливается на СВОЁМ корне; так устроен сам детектор, и краснеть на нём " +
				"значило бы запретить единственный правильный способ",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: Dir в цикле БЕЗ переприсваивания — это не подъём",
			body: `
func chartDirs(t *testingT, paths []string) []string {
	root := platformtree.Require(t)
	out := []string{}
	for _, vp := range paths {
		if _, err := os.Stat(filepath.Join(root, "deploy", "values.yaml")); err == nil {
			out = append(out, filepath.Dir(vp))
		}
	}
	return out
}

type testingT struct{}`,
			depth:        2,
			wantCoords:   1,
			wantResolves: 1,
			why: "один факт против случая выше — переприсваивается ли аргумент Dir. Взятие " +
				"каталога у элемента обхода подъёмом не является; такой код в дереве есть " +
				"(deploy/schema_mechanism_precedes_the_service_test.go), и грубая проверка " +
				"«Dir внутри цикла» краснела бы на нём",
		},

		// ── ФОРМА 2: ФИКСИРОВАННАЯ ГЛУБИНА ──────────────────────────────────
		{
			name: "форма 2 (фиксированная глубина): Join с .. выше корня модуля",
			body: `
var rel = filepath.Join("..", "..", "..", "..", "proto", "kaname", "cloud", "iam", "v1", "fga_model.fga")`,
			depth:       2,
			wantFinding: "собственный подъём по дереву (фиксированная глубина)",
			wantCoords:  1,
			wantAscents: 1,
			why: "ДОСЛОВНО живой экземпляр из internal/migrations: подъём 4 при глубине 2. " +
				"Прежняя редакция не видела его ВОВСЕ — ни координатой, ни подъёмом",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: тот же Join, подъём РАВЕН глубине — попадает в свой модуль",
			body: `
var rel = filepath.Join("..", "..", "deploy", "values.yaml")`,
			depth: 2,
			why: "один факт против случая выше — арифметика. Подъём 2 при глубине 2 приводит " +
				"в СОБСТВЕННЫЙ каталог поставки модуля; так записан cmd/kaname, и это верный " +
				"код. Координатой ПЛАТФОРМЫ такой путь не является — он не выходит за модуль",
		},
		{
			name: "форма 2, пакет path вместо filepath",
			body: `
var rel = path.Join("..", "..", "..", "services", "iam", "manifest.yaml")`,
			depth:       2,
			wantFinding: "собственный подъём по дереву (фиксированная глубина)",
			wantCoords:  1,
			wantAscents: 1,
			why:         "второй пакет той же формы",
		},

		// ── ФОРМА 3: ЛИТЕРАЛ ────────────────────────────────────────────────
		{
			name: "форма 3 (литерал): одна строка, подъём выше корня модуля",
			body: `
var rel = "../../../../proto/kaname/cloud/iam/v1/fga_model.fga"`,
			depth:       2,
			wantFinding: "собственный подъём по дереву (литерал)",
			wantCoords:  1,
			wantAscents: 1,
			why: "третья форма записи того же предмета; голова строки не корневой сегмент, " +
				"поэтому прежняя редакция её не видела",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: тот же литерал, подъём РАВЕН глубине",
			body: `
var rel = "../../deploy/values.yaml"`,
			depth: 2,
			why:   "один факт против случая выше — арифметика; путь остаётся внутри модуля",
		},

		// ── ОСЬ ЯКОРЯ: ПОКООРДИНАТНАЯ ───────────────────────────────────────
		{
			name: "ПОКООРДИНАТНАЯ ось: законный резолв рядом НЕ маскирует чужую координату",
			body: `
func a(t *testingT) string {
	return platformtree.RequirePath(t, "proto/kaname/cloud/iam/v1/role.proto")
}

var other = "services/iam/docs/content/api/role.mdx"

type testingT struct{}`,
			depth:          2,
			wantFinding:    `координата "services/iam/docs/content/api/role.mdx" не имеет якоря-детектора`,
			wantCoords:     2,
			wantResolves:   1,
			wantUnanchored: 1,
			why: "ГЛАВНАЯ регрессия #2289: пофайловая ось была зелена на этом файле, потому " +
				"что один Require в файле искупал любое число нерезолвнутых координат",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: обе координаты через детектор",
			body: `
func a(t *testingT) string {
	return platformtree.RequirePath(t, "proto/kaname/cloud/iam/v1/role.proto")
}

func b(t *testingT) string {
	return platformtree.RequirePath(t, "services/iam/docs/content/api/role.mdx")
}

type testingT struct{}`,
			depth:        2,
			wantCoords:   2,
			wantResolves: 2,
			why:          "один факт против случая выше — якорь у ВТОРОЙ координаты",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: координата через ИМЯ, переданное детектору",
			body: `
const rel = "proto/kaname/cloud/iam/v1/role.proto"

func a(t *testingT) string { return platformtree.RequirePath(t, rel) }

type testingT struct{}`,
			depth:        2,
			wantCoords:   1,
			wantResolves: 1,
			why:          "живая форма всех трёх координат пакета: const рядом, Require ниже",
		},
		{
			name: "координата без якоря вовсе",
			body: `
var rel = "proto/kaname/cloud/iam/v1/role.proto"`,
			depth:          2,
			wantFinding:    "не имеет якоря-детектора",
			wantCoords:     1,
			wantUnanchored: 1,
			why:            "один факт против близнеца выше — имя никому не передаётся",
		},
		{
			name: "форма 2 как ЗАКОННАЯ координата: Join по сегментам на базе от детектора",
			body: `
func a(t *testingT) string {
	root := platformtree.Require(t)
	return filepath.Join(root, "services", "iam", "manifest.yaml")
}

type testingT struct{}`,
			depth:        2,
			wantCoords:   1,
			wantResolves: 1,
			why: "третья законная форма якоря — приставка к базе детектора. Прежняя редакция " +
				"смотрела только на ПЕРВЫЙ аргумент Join и такой координаты не видела вовсе",
		},
		{
			name: "тот же Join, база НЕ от детектора",
			body: `
func a() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "services", "iam", "manifest.yaml")
}`,
			depth:          2,
			wantFinding:    "не имеет якоря-детектора",
			wantCoords:     1,
			wantUnanchored: 1,
			why:            "один факт против случая выше — откуда взята база",
		},

		// ── ГРАНИЦЫ РАСПОЗНАВАТЕЛЯ ──────────────────────────────────────────
		{
			name: "гейт читает ИСПОЛНЯЕМУЮ часть: координата в комментарии не координата",
			body: `
// Здесь названа координата "proto/kaname/cloud/iam/v1/role.proto" — но она
// стоит в объяснении, а не в коде.
func nothing() {}`,
			depth: 2,
			why:   "проверка по подстроке краснела бы на собственном объяснении гейта",
		},
		{
			name:  "голое имя каталога координатой не является",
			body:  "\nvar seg = \"deploy\"\n",
			depth: 2,
			why:   "без разделителя это слово, а не путь от корня платформы",
		},
		{
			name:  "ЗАКОННЫЙ БЛИЗНЕЦ: подъём БЕЗ корневого сегмента платформы",
			body:  "\nvar rel = \"../../internal/repo/kaname/pg\"\n",
			depth: 2,
			why:   "подъём сам по себе законен: до чужого дерева он не достаёт",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, census, err := auditPlatformCoordinateResolve(
				[]sourceFile{{Name: "fixture.go", Depth: c.depth, Text: resolveFixture(c.body)}})
			if err != nil {
				t.Fatalf("разбор не отработал: %v", err)
			}
			t.Logf("перепись: %s · найдено: якорь %d, подъём %d",
				census, len(findings.Unanchored), len(findings.Ascents))

			if census.Coords != c.wantCoords {
				t.Errorf("координат распознано %d, хотел %d (%s)", census.Coords, c.wantCoords, c.why)
			}
			if census.Resolves != c.wantResolves {
				t.Errorf("резолвов распознано %d, хотел %d", census.Resolves, c.wantResolves)
			}
			if census.Ascents != c.wantAscents {
				t.Errorf("подъёмов распознано %d, хотел %d (%s)", census.Ascents, c.wantAscents, c.why)
			}
			// Оси объявляются ПОРОЗНЬ: фикстура подъёма законно задевает обе, и
			// слитое ожидание пряло бы вторую.
			if len(findings.Ascents) != c.wantAscents {
				t.Errorf("находок оси подъёма %d, хотел %d:\n%s",
					len(findings.Ascents), c.wantAscents, strings.Join(findings.Ascents, "\n"))
			}
			if len(findings.Unanchored) != c.wantUnanchored {
				t.Errorf("находок оси якоря %d, хотел %d (%s):\n%s",
					len(findings.Unanchored), c.wantUnanchored, c.why,
					strings.Join(findings.Unanchored, "\n"))
			}

			joined := strings.Join(append(append([]string{}, findings.Unanchored...), findings.Ascents...), "\n")
			if c.wantFinding == "" {
				if joined != "" {
					t.Errorf("гейт краснеет на законном исходнике (%s):\n%s", c.why, joined)
				}
				return
			}
			// Проверяется не только «покраснел», но и ЧТО НАПЕЧАТАЛ: находка,
			// называющая симптом вместо причины, посылает читателя искать не там.
			if !strings.Contains(joined, c.wantFinding) {
				t.Errorf("находка не названа (%s).\nхотел подстроку: %q\nполучил:\n%s",
					c.why, c.wantFinding, joined)
			}
			if !strings.Contains(joined, "fixture.go:") {
				t.Errorf("находка не назвала координату файла и строку:\n%s", joined)
			}
		})
	}

	t.Logf("перепись инъекции: случаев %d", len(cases))
}

// TestPlatformCoordinateResolveGate_UnparsableSourceIsNotAVerdict — неразбираемый
// исходник даёт ОТКАЗ РАЗБОРА, а не «находок ноль».
//
// Без этого случая гейт, споткнувшийся о разбор, печатал бы зелёное — то есть
// «ноль прочитанного» под видом согласия.
func TestPlatformCoordinateResolveGate_UnparsableSourceIsNotAVerdict(t *testing.T) {
	_, _, err := auditPlatformCoordinateResolve(
		[]sourceFile{{Name: "broken.go", Text: "package p\n\nfunc ( {"}})
	if err == nil {
		t.Fatal("неразбираемый исходник принят за прочитанный — вердикт был бы беспредметным")
	}
	t.Logf("отказ разбора, как и должно: %v", err)
}

// TestPlatformCoordinateResolveGate_EmptyWalkIsCountedAsZero — пустой вход даёт
// нулевую перепись, и именно она отличает «ноль находок» от «ноль прочитанного».
func TestPlatformCoordinateResolveGate_EmptyWalkIsCountedAsZero(t *testing.T) {
	findings, census, err := auditPlatformCoordinateResolve(nil)
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	if len(findings.Unanchored)+len(findings.Ascents) != 0 {
		t.Errorf("находки на пустом входе: %v", findings)
	}
	if census.Files != 0 {
		t.Fatalf("файлов прочитано %d на пустом входе — перепись лжёт", census.Files)
	}
	t.Logf("перепись: %s — премиса `Files == 0` в пробах дерева роняет прогон", census)
}
