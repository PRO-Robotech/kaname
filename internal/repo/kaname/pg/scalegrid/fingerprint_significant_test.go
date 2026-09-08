// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ОТПЕЧАТОК ЧУВСТВИТЕЛЕН К ПОВЕДЕНИЮ, А НЕ К БАЙТАМ (задача продукта #2039)
//
// Предмет — цена ложной несвежести. Пересъёмка одного отчёта стоит до двух часов
// прогона на поднятой базе, а обесценивала их правка, ни одного оператора не
// касавшаяся: смена заголовка лицензии в 90 файлах объявила несвежими четыре
// отчёта разом. Отпечаток ловил «файл тронут», а обязан ловить «предмет замера
// сдвинулся».
//
// Обе стороны обязательны и проверяются здесь порознь. Без второй половины
// сужение вырождается в вечно зелёный гейт — то есть в отчёт, который выглядит
// свежим и не является им, а это дороже лишнего прогона: ложное число уходит
// читателю как измеренное.

// TestSignificantContent_ProvenByInjection — сужение доказано в обе стороны на
// СИНТЕТИЧЕСКОМ входе, поэтому проба не зависит от того, что сегодня в дереве.
//
// Законный близнец у каждой отрицательной строки — положительная того же вида:
// «комментарий сменился» против «оператор сменился» в одном и том же файле.
func TestSignificantContent_ProvenByInjection(t *testing.T) {
	const base = `// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

import "github.com/PRO-Robotech/kacho/services/iam/internal/repo/prevhome/pg/resource_mirror"

// reportPath — куда кладётся отчёт.
const reportPath = "services/iam/internal/repo/prevhome/pg/scalegrid/REPORT-R7-2-strength.txt"

// sameSubject — литерал С КОСОЙ ЧЕРТОЙ, координатой НЕ являющийся.
const sameSubject = "kaname.roles/updated_at"

// askVerdict — вердикт о доступе.
func askVerdict() string {
	_ = resource_mirror.Nothing
	_ = reportPath
	_ = sameSubject
	return "SELECT id FROM kaname.access_bindings WHERE scope_id = $1"
}
`

	cases := []struct {
		name  string
		rel   string
		other string
		moved bool
	}{
		{
			name: "заголовок лицензии сменился — предмет замера НЕ сдвинулся",
			rel:  "a.go",
			other: strings.Replace(base,
				"SPDX-License-Identifier: BUSL-1.1",
				"SPDX-License-Identifier: AGPL-3.0-or-later", 1),
			moved: false,
		},
		{
			name:  "проза комментария переписана — НЕ сдвинулся",
			rel:   "a.go",
			other: strings.Replace(base, "// askVerdict — вердикт о доступе.", "// askVerdict — отвечает на вопрос о доступе; переписано.", 1),
			moved: false,
		},
		{
			name:  "комментарий снят целиком — НЕ сдвинулся",
			rel:   "a.go",
			other: strings.Replace(base, "// askVerdict — вердикт о доступе.\n", "", 1),
			moved: false,
		},
		{
			name:  "тело запроса переписано — СДВИНУЛСЯ",
			rel:   "a.go",
			other: strings.Replace(base, "WHERE scope_id = $1", "WHERE scope_id = $1 AND role_id = $2", 1),
			moved: true,
		},
		{
			name:  "набор колонок изменился — СДВИНУЛСЯ",
			rel:   "a.go",
			other: strings.Replace(base, "SELECT id FROM", "SELECT id, role_id FROM", 1),
			moved: true,
		},
		{
			name: "две косые ЧЕРТЫ ВНУТРИ строкового литерала — это КОД, СДВИНУЛСЯ",
			// Ради этой строки отбор берётся РАЗБОРОМ, а не текстовой заменой:
			// текстовая срезала бы хвост литерала и объявила правку запроса
			// незначащей — то есть открыла бы дыру ровно там, где она дороже
			// всего.
			rel:   "a.go",
			other: strings.Replace(base, `WHERE scope_id = $1"`, `WHERE scope_id = $1 -- // не комментарий"`, 1),
			moved: true,
		},
		{
			name:  "импорт сменился — СДВИНУЛСЯ",
			rel:   "a.go",
			other: strings.Replace(base, "package relverdict\n", "package relverdict\n\nimport _ \"github.com/jackc/pgx/v5\"\n", 1),
			moved: true,
		},
		{
			name: "директива сборки заведена — СДВИНУЛСЯ",
			// Директива — не проза: `//go:build` решает, компилируется ли файл
			// вообще. Снять её вместе с комментариями значило бы перестать
			// замечать смену состава собираемого кода.
			rel:   "a.go",
			other: "//go:build !race\n\n" + base,
			moved: true,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ переезда: путь импорта СВОЕГО модуля — адрес
			// кода, а не его поведение. Каталог `repo/prevhome/pg` переехал в
			// `repo/kaname/pg`, ни один оператор не изменился.
			name: "каталог переехал в пути импорта своего модуля — НЕ сдвинулся",
			rel:  "a.go",
			other: strings.Replace(base,
				"kacho/services/iam/internal/repo/prevhome/pg/resource_mirror",
				"kacho/services/iam/internal/repo/kaname/pg/resource_mirror", 1),
			moved: false,
		},
		{
			// Тот же переезд, второй вид координаты: путь от корня
			// репозитория. Отчёт лежит по новому адресу, измеренная стоимость
			// операций от этого не меняется.
			name: "каталог переехал в пути отчёта — НЕ сдвинулся",
			rel:  "a.go",
			other: strings.Replace(base,
				"services/iam/internal/repo/prevhome/pg/scalegrid/REPORT",
				"services/iam/internal/repo/kaname/pg/scalegrid/REPORT", 1),
			moved: false,
		},
		{
			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к двум предыдущим: литерал с косой чертой,
			// который координатой НЕ является (первый сегмент — не каталог
			// верхнего уровня и не путь модуля). Без этой строки правило
			// «литерал с косой чертой незначащ» зеленело бы на любой правке
			// запроса, где встретилась косая черта.
			name: "литерал с косой чертой, координатой НЕ являющийся — СДВИНУЛСЯ",
			rel:  "a.go",
			other: strings.Replace(base,
				`"kaname.roles/updated_at"`, `"kaname.roles/created_at"`, 1),
			moved: true,
		},
		{
			// Второй положительный контроль: правка ВНУТРИ запроса, у которого
			// есть косая черта в соседнем литерале. Замена координат не смеет
			// затрагивать текст, отправляемый в базу.
			name: "оператор запроса сменился при живых координатах рядом — СДВИНУЛСЯ",
			rel:  "a.go",
			other: strings.Replace(base,
				"WHERE scope_id = $1", "WHERE scope_id = $1 AND live", 1),
			moved: true,
		},
		{
			name: "заголовок лицензии в .sql — СДВИНУЛСЯ (граница названа)",
			// Комментарии SQL в этом дереве НЕ проза: `-- +goose Up` и
			// `-- +goose Down` читает мигратор, а `-- +kacho point-of-no-return`
			// — гейт отката. Сняв их, мы перестали бы отличать миграцию,
			// поменявшую Up и Down местами, — то есть купили бы отсутствие
			// лишнего прогона ценой неразличимости настоящей правки схемы.
			rel:   "m.sql",
			other: "-- SPDX-License-Identifier: AGPL-3.0-or-later\n-- +goose Up\nALTER TABLE kaname.roles ADD COLUMN updated_at timestamptz;\n",
			moved: true,
		},
	}

	const sqlBase = "-- SPDX-License-Identifier: BUSL-1.1\n-- +goose Up\nALTER TABLE kaname.roles ADD COLUMN updated_at timestamptz;\n"

	coords := coordsFor(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := base
			if strings.HasSuffix(tc.rel, ".sql") {
				src = sqlBase
			}
			before, err := significantContent(tc.rel, []byte(src), coords)
			if err != nil {
				t.Fatalf("значащее содержимое исходного %s: %v", tc.rel, err)
			}
			after, err := significantContent(tc.rel, []byte(tc.other), coords)
			if err != nil {
				t.Fatalf("значащее содержимое правленого %s: %v", tc.rel, err)
			}
			moved := string(before) != string(after)
			if moved != tc.moved {
				t.Fatalf("предмет замера: сдвинулся=%v, ожидалось %v\n  было:\n%s\n  стало:\n%s",
					moved, tc.moved, before, after)
			}
		})
	}
	t.Logf("перепись: осмотрено правок %d, из них обязаны двигать отпечаток %d",
		len(cases), countMoving(cases))
}

func countMoving(cases []struct {
	name  string
	rel   string
	other string
	moved bool
}) int {
	n := 0
	for _, c := range cases {
		if c.moved {
			n++
		}
	}
	return n
}

// TestSignificantContent_UnparsableGoIsRefusal — файл, который не разбирается,
// это ОТКАЗ, а не молчаливый возврат к байтам.
//
// Молчаливый возврат восстановил бы байтовую чувствительность ровно там, где её
// никто не ждёт, и отличить это от исправной работы было бы нечем.
func TestSignificantContent_UnparsableGoIsRefusal(t *testing.T) {
	if _, err := significantContent("broken.go", []byte("package ; ??? {"), coordsFor(t)); err == nil {
		t.Fatal("неразбираемый .go обязан быть отказом, а не молчаливым возвратом байтов")
	}
}

// TestFingerprintIsBlindToCommentsAndDeafToStatements — то же свойство на
// НАСТОЯЩЕЙ точке входа, а не только на её составной части.
//
// Проба на `significantContent` доказывает, что функция умеет; эта — что её
// РЕЗУЛЬТАТ доезжает до отпечатка. Без второй половины сужение могло бы быть
// написано верно и никем не позвано.
func TestFingerprintIsBlindToCommentsAndDeafToStatements(t *testing.T) {
	root := syntheticRoot(t)

	base, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток исходного дерева: %v", err)
	}
	if len(base.Files) == 0 {
		t.Fatal("пустой обход: отпечаток беспредметен, а значит его совпадение ничего не доказывает")
	}

	verdict := filepath.Join(root, verdictDir, "query.go")
	src, err := os.ReadFile(verdict) // #nosec G304 -- путь построен пробой в собственном временном каталоге
	if err != nil {
		t.Fatalf("чтение %s: %v", verdict, err)
	}

	// (а) правка, поведения НЕ меняющая, — отпечаток обязан устоять.
	commentOnly := strings.Replace(string(src),
		"SPDX-License-Identifier: BUSL-1.1", "SPDX-License-Identifier: AGPL-3.0-or-later", 1)
	if commentOnly == string(src) {
		t.Fatal("фикстура не изменилась: инъекция ничего не доказывает")
	}
	writeFile(t, verdict, commentOnly)

	quiet, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток после правки комментария: %v", err)
	}
	if quiet.Content != base.Content {
		t.Fatalf("смена заголовка лицензии сдвинула отпечаток содержимого: было %s, стало %s",
			base.Content, quiet.Content)
	}

	// (б) правка, поведение МЕНЯЮЩАЯ, — отпечаток обязан сдвинуться.
	statement := strings.Replace(commentOnly,
		"WHERE scope_id = $1", "WHERE scope_id = $1 AND role_id = $2", 1)
	if statement == commentOnly {
		t.Fatal("фикстура не изменилась: положительная половина инъекции беспредметна")
	}
	writeFile(t, verdict, statement)

	loud, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток после правки запроса: %v", err)
	}
	if loud.Content == base.Content {
		t.Fatalf("правка тела запроса отпечаток НЕ сдвинула (%s) — гейт выродился в вечно зелёный",
			loud.Content)
	}

	t.Logf("перепись: файлов под отпечатком %d, таблиц выведено %d", len(base.Files), len(base.Tables))
}

// TestContentOfNarrowsToo — пофайловый отпечаток, которым гейт называет
// ВИНОВНИКА, сужен тем же правилом.
//
// Разойдись он с итоговым — гейт печатал бы «сдвинули его: …» под списком
// файлов, ни один из которых итоговый хэш не двигал.
func TestContentOfNarrowsToo(t *testing.T) {
	root := syntheticRoot(t)
	rel := verdictDir + "/query.go"

	before := ContentOf(root, rel)
	src, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- путь построен пробой в собственном временном каталоге
	if err != nil {
		t.Fatalf("чтение %s: %v", rel, err)
	}
	writeFile(t, filepath.Join(root, rel), strings.Replace(string(src),
		"SPDX-License-Identifier: BUSL-1.1", "SPDX-License-Identifier: AGPL-3.0-or-later", 1))

	if after := ContentOf(root, rel); after != before {
		t.Fatalf("пофайловый отпечаток сдвинут сменой заголовка лицензии: было %s, стало %s", before, after)
	}
}

// syntheticRoot — минимальное дерево той же формы, что настоящее.
//
// Синтетика, а не настоящее дерево: инъекция на настоящем потребовала бы правки
// настоящих файлов, то есть была бы невоспроизводима и опасна для соседа.
func syntheticRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	for _, dir := range []string{verdictDir, gridDir, migrateDir} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatalf("создание %s: %v", dir, err)
		}
	}

	writeFile(t, filepath.Join(root, verdictDir, "query.go"), `// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// askVerdict — вердикт о доступе.
func askVerdict() string {
	return "SELECT id FROM kaname.access_bindings WHERE scope_id = $1"
}
`)
	// Оснастка отпечатка: обязана существовать и обязана оставаться оснасткой,
	// иначе `withoutScaffolding` справедливо откажет.
	writeFile(t, filepath.Join(root, gridDir, "fingerprint.go"), "package scalegrid\n\nfunc fp() int { return 1 }\n")
	writeFile(t, filepath.Join(root, gridDir, "report.go"), "package scalegrid\n\nfunc rep() int { return 2 }\n")
	writeFile(t, filepath.Join(root, gridDir, "grid.go"), "package scalegrid\n\n// grid — сетка замера.\nfunc grid() int { return 3 }\n")
	writeFile(t, filepath.Join(root, migrateDir, "0001_initial.sql"),
		"-- +goose Up\nCREATE TABLE kaname.access_bindings (id text PRIMARY KEY);\n")
	// `go.mod` в корне: без него распознаватель координат не знает пути своего
	// модуля, и клаузу про импорт проверять было бы нечем — проба зеленела бы
	// на половине правила, не сказав об этом.
	writeFile(t, filepath.Join(root, "go.mod"), "module github.com/PRO-Robotech/kacho\n\ngo 1.26.0\n")

	return root
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("запись %s: %v", path, err)
	}
}

// coordsFor — распознаватель координат по СИНТЕТИЧЕСКОМУ дереву той же формы.
//
// Синтетика, а не настоящее дерево: проба обязана утверждать о ПРАВИЛЕ, а не о
// сегодняшнем составе каталогов. На настоящем дереве она молча меняла бы смысл
// вместе с ним — и однажды позеленела бы оттого, что каталог переименовали.
func coordsFor(t *testing.T) repoCoordinates {
	t.Helper()
	coords, err := newRepoCoordinates(syntheticRoot(t))
	if err != nil {
		t.Fatalf("распознаватель координат не построен: %v", err)
	}
	if len(coords.topLevel) == 0 {
		t.Fatalf("каталогов верхнего уровня НОЛЬ — распознаватель не узнал бы ни одной " +
			"координаты, и проба зеленела бы на пустом правиле")
	}
	t.Logf("перепись распознавателя: каталогов верхнего уровня %d", len(coords.topLevel))
	return coords
}
