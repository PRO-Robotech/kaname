// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// grantarm_home_gate_test.go — у предиката ветви выдач ОДИН дом (kaname#857).
//
// Предмет: текст, решающий «достаёт ли выдача роли до объекта», — сравнение
// ветви правила (`arm`) и колонки её селектора (`resource_names`,
// `match_labels`). Он живёт в `grantArmPredicate`, и только там. Копия рядом —
// ровно та форма, в которой три запроса пакета перестали читать цель привязки:
// правка одного места не доезжает до второго, и расходятся они в сторону
// лишнего доступа.
//
// Гейт читает ИСПОЛНЯЕМОЕ: строковые литералы непробных файлов пакета, разбором
// синтаксиса, с отброшенными SQL-комментариями. Комментарий Go и комментарий
// внутри запроса домом предиката не считаются. Единица счёта — объявление
// верхнего уровня (функция, константа, переменная), а не литерал: тело одного
// предиката законно разбито на несколько литералов вокруг подставленных
// выражений.
//
// Распознаватель — от класса, а не от одного написания: любое сравнение ветви
// (`x.arm = …`, `… = x.arm`, `arm IN (…)`, с любым псевдонимом и без него) и любое
// упоминание колонок селектора. Перепись печатается, пустой обход — не зелёный.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// grantArmText — признак текста ветви выдач в SQL-литерале.
var grantArmText = regexp.MustCompile(
	`(?i)\barm\s*(=|<>|!=|\bin\b)|(=|<>|!=)\s*(\w+\.)?arm\b|\bresource_names\b|\bmatch_labels\b`)

// sqlLineComment — комментарий внутри запроса: о предикате не свидетельствует.
var sqlLineComment = regexp.MustCompile(`--[^\n]*`)

type grantArmHome struct {
	pos  string // файл:строка объявления
	decl string // имя объявления
}

type grantArmCensus struct {
	files    int // прочитано непробных .go
	literals int // прочитано строковых литералов
}

// scanGrantArmHomes обходит непробные .go каталога и называет объявления
// верхнего уровня, в чьих строковых литералах стоит текст ветви выдач.
func scanGrantArmHomes(dir string) (grantArmCensus, []grantArmHome, error) {
	var c grantArmCensus
	entries, err := os.ReadDir(dir)
	if err != nil {
		return c, nil, err
	}
	fset := token.NewFileSet()
	var homes []grantArmHome
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return c, nil, fmt.Errorf("разбор %s: %w", name, err)
		}
		c.files++
		for _, d := range f.Decls {
			hit := false
			ast.Inspect(d, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				c.literals++
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					text = lit.Value
				}
				if grantArmText.MatchString(sqlLineComment.ReplaceAllString(text, "")) {
					hit = true
				}
				return true
			})
			if hit {
				homes = append(homes, grantArmHome{
					pos:  fmt.Sprintf("%s:%d", name, fset.Position(d.Pos()).Line),
					decl: declName(d),
				})
			}
		}
	}
	sort.Slice(homes, func(i, j int) bool { return homes[i].pos < homes[j].pos })
	return c, homes, nil
}

func declName(d ast.Decl) string {
	switch d := d.(type) {
	case *ast.FuncDecl:
		return d.Name.Name
	case *ast.GenDecl:
		var names []string
		for _, s := range d.Specs {
			if vs, ok := s.(*ast.ValueSpec); ok {
				for _, n := range vs.Names {
					names = append(names, n.Name)
				}
			}
		}
		return strings.Join(names, ",")
	}
	return "?"
}

// judgeGrantArmHomes — вердикт по переписи: ровно один дом, и это функция
// grantArmPredicate. Пустой обход и ноль домов — отказ предпосылки, а не зелёное.
func judgeGrantArmHomes(c grantArmCensus, homes []grantArmHome) error {
	if c.files == 0 || c.literals == 0 {
		return fmt.Errorf("предпосылка: прочитано файлов %d, литералов %d — обход не видит пакета, "+
			"вердикта нет", c.files, c.literals)
	}
	if len(homes) == 0 {
		return fmt.Errorf("предпосылка: текст ветви выдач не найден ни в одном объявлении " +
			"(файлов прочитано больше нуля) — распознаватель не читает своего предмета, вердикта нет")
	}
	if len(homes) == 1 && homes[0].decl == "grantArmPredicate" {
		return nil
	}
	var b strings.Builder
	for _, h := range homes {
		fmt.Fprintf(&b, "\n  %s %s", h.pos, h.decl)
	}
	return fmt.Errorf("текст ветви выдач стоит в %d объявлениях — дом у него один, "+
		"grantArmPredicate (grantarm.go); прочие подставляют его, а не повторяют:%s", len(homes), b.String())
}

func TestGrantArmPredicateHasASingleHome(t *testing.T) {
	c, homes, err := scanGrantArmHomes(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("перепись: файлов %d · литералов %d · домов текста ветви выдач %d", c.files, c.literals, len(homes))
	if err := judgeGrantArmHomes(c, homes); err != nil {
		t.Fatal(err)
	}
}

// ── Инъекции: тот же обход на синтетическом дереве ─────────────────────────────

const injShared = "package p\n\nfunc grantArmPredicate(id string) string {\n" +
	"\treturn `rs.arm = 'anchor' OR (rs.arm = 'names' AND ` + id + ` = ANY (rs.resource_names))`\n}\n"

func injTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func injJudge(t *testing.T, files map[string]string) (grantArmCensus, []grantArmHome, error) {
	t.Helper()
	c, homes, err := scanGrantArmHomes(injTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return c, homes, judgeGrantArmHomes(c, homes)
}

// Законный близнец: один дом; тот же текст в комментарии Go, в SQL-комментарии
// запроса и в пробном файле домом не считается.
func TestGrantArmHomeInjection_LawfulTwinIsSilent(t *testing.T) {
	_, homes, err := injJudge(t, map[string]string{
		"shared.go": injShared,
		"other.go": "package p\n\n// rs.arm = 'names' AND x = ANY (rs.resource_names)\n" +
			"const q = `SELECT 1 -- rs.arm = 'labels' AND m.labels @> rs.match_labels\n FROM t`\n",
		"seed_test.go": "package p\n\nconst seed = `INSERT INTO s (arm, resource_names) VALUES ('names', '{}')`\n",
	})
	if err != nil {
		t.Fatalf("законный близнец дал находку: %v (дома %v)", err, homes)
	}
}

// Вторая копия ловится в каждой законной форме записи и называет координату.
func TestGrantArmHomeInjection_SecondCopyIsFoundWithItsCoordinate(t *testing.T) {
	for name, copySrc := range map[string]string{
		"тот же текст":          "package p\n\nconst listSQL = `WHERE (rs.arm = 'anchor' OR rs.arm = 'names')`\n",
		"другой псевдоним":      "package p\n\nconst q = `WHERE (rrs.arm='anchor')`\n",
		"сравнение справа":      "package p\n\nconst q = `WHERE 'labels' = rs.arm`\n",
		"перечень ветвей":       "package p\n\nconst q = `WHERE rs.arm IN ('anchor', 'names')`\n",
		"только колонка имён":   "package p\n\nconst q = `WHERE x = ANY (sel.resource_names)`\n",
		"только колонка меток":  "package p\n\nvar q = `WHERE m.labels @> sel.match_labels`\n",
		"внутри функции":        "package p\n\nfunc f() string { return \"rs.arm = 'anchor'\" }\n",
		"без псевдонима, в IN":  "package p\n\nconst q = `WHERE arm in ('names')`\n",
		"неравенство с ветвью":  "package p\n\nconst q = `WHERE rs.arm <> 'labels'`\n",
		"литерал в кавычках Go": "package p\n\nconst q = \"WHERE rs.arm = 'anchor'\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, homes, err := injJudge(t, map[string]string{"shared.go": injShared, "copy.go": copySrc})
			if err == nil {
				t.Fatalf("вторая копия (%s) не найдена: дома %v", name, homes)
			}
			if !strings.Contains(err.Error(), "copy.go:3") {
				t.Fatalf("находка не называет координату копии: %v", err)
			}
		})
	}
}

// Дом есть, но это не общая функция, — находка, а не зелёное.
func TestGrantArmHomeInjection_SoleHomeElsewhereIsFound(t *testing.T) {
	_, _, err := injJudge(t, map[string]string{
		"q.go": "package p\n\nconst q = `WHERE rs.arm = 'anchor'`\n",
	})
	if err == nil || !strings.Contains(err.Error(), "q.go:3") {
		t.Fatalf("единственный дом вне grantArmPredicate не назван: %v", err)
	}
}

// Пустой обход и обход без предмета — «не выполнилось», а не зелёное.
func TestGrantArmHomeInjection_EmptyWalkIsNotAVerdict(t *testing.T) {
	c, _, err := injJudge(t, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "предпосылка") {
		t.Fatalf("пустой обход (файлов %d) дал %v — ждали отказ предпосылки", c.files, err)
	}
	_, _, err = injJudge(t, map[string]string{"x.go": "package p\n\nconst q = `SELECT 1`\n"})
	if err == nil || !strings.Contains(err.Error(), "предпосылка") {
		t.Fatalf("обход без текста ветви дал %v — ждали отказ предпосылки", err)
	}
}
