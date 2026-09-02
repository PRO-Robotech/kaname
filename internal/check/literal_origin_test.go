// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

// literal_origin_test.go — сценарий IAM-CT-2-11 (kacho#1816): литерал НЕ
// производится из строк каталога.
//
// # Зачем это отдельное утверждение
//
// Приёмка (§2.1) отвергает снятие литерала: он производная канона
// `fga_model.fga`, и без него строки каталога остались бы без якоря к канону
// вовсе. Но у отвергнутого снятия есть тихий двойник: литерал ОСТАВИТЬ, а
// производить его ИЗ СТРОК. Тогда обе проверки паритета — гейт дерева и страж
// старта — продолжают исполняться, продолжают быть зелёными и перестают что-либо
// утверждать: они сверяют источник с самим собой. Форма проверки при отсутствии
// содержания, и снаружи неотличима от исправной.
//
// # Как это проверяется, а не обещается
//
// Двумя утверждениями, потому что произвести литерал из строк можно двумя
// путями:
//
//	 1. КОДОМ — пакет-литерал сам дотягивается до строк. Отвергается по ГРАФУ
//	    ИМПОРТОВ: пакету, не достающему до базы, неоткуда взять строки;
//	 2. ГЕНЕРАЦИЕЙ — цель сборки или директива пишет файл литерала. Отвергается
//	    перечислением директив генерации и целей, называющих файл литерала.
//
// Перепись печатает объём осмотренного по каждой оси. Ноль ДИРЕКТИВ — законный
// факт дерева (их в сервисе нет), а вот ноль ПРОЧИТАННЫХ ФАЙЛОВ — пустой обход,
// и он роняет прогон: «ноль находок» обязано быть отличимо от «ноль
// прочитанного».

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/treecorpus"
)

// literalPackageRel — пакет, объявляющий литерал каталога.
const literalPackageRel = "services/iam/internal/authzmap"

// literalFileName — файл, в котором объявлены оба словаря-литерала.
const literalFileName = "fga_types.go"

// rowReachingImports — пути, достающие до СТРОК каталога. Пакету-литералу
// запрещены все: имея любой из них, он мог бы производить себя из того, с чем
// его сверяют.
//
// Перечень задан ПРЕФИКСАМИ, а не точными путями: запрещён не конкретный пакет,
// а способность дотянуться до базы, и новый адаптер под другим именем обязан
// подпадать под тот же запрет, не требуя правки этого перечня.
var rowReachingImports = []string{
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog",
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo",
	"github.com/jackc/pgx",
}

// literalOriginCensus — объём осмотренного по каждой оси.
type literalOriginCensus struct {
	GoFiles          int
	GenerateDirs     int
	MakefilesScanned int
	MakeLines        int
}

// auditLiteralOrigin — ядро утверждения. Вынесено функцией от КОРНЯ, чтобы
// инъекция могла подать ему синтетическое дерево: доказательство способности
// упасть, поставленное на живом дереве, потребовало бы порчи живого дерева.
// СОСТАВ ПАКЕТА-ЛИТЕРАЛА приходит параметром по той же причине, что и у соседнего
// гейта: в живом дереве его даёт ИНДЕКС git (обход диска читал бы игнорируемое, и
// вердикт стал бы свойством рабочего каталога, а не коммита), а инъекция подаёт
// синтетический перечень.
func auditLiteralOrigin(root string, pkgFiles, makefiles []string) (findings []string, c literalOriginCensus, err error) {
	fset := token.NewFileSet()
	for _, path := range pkgFiles {
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil {
			return nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.GoFiles++
		for _, imp := range file.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			for _, banned := range rowReachingImports {
				if p == banned || strings.HasPrefix(p, banned+"/") {
					findings = append(findings, fmt.Sprintf(
						"%s/%s импортирует %q — пакет-литерал дотянулся до СТРОК каталога; "+
							"производный от строк литерал превращает паритет в сверку источника "+
							"с самим собой", literalPackageRel, name, p))
				}
			}
		}
		for _, group := range file.Comments {
			for _, com := range group.List {
				text := strings.TrimPrefix(com.Text, "//")
				if !strings.HasPrefix(text, "go:generate") {
					continue
				}
				c.GenerateDirs++
				if strings.Contains(text, literalFileName) {
					findings = append(findings, fmt.Sprintf(
						"%s/%s: директива генерации называет файл литерала (%s) — "+
							"литерал обязан оставаться рукописной производной канона",
						literalPackageRel, name, com.Text))
				}
			}
		}
	}

	for _, mf := range makefiles {
		body, mrerr := os.ReadFile(filepath.Join(root, mf))
		if mrerr != nil {
			if os.IsNotExist(mrerr) {
				continue
			}
			return nil, c, fmt.Errorf("прочитать %s: %w", mf, mrerr)
		}
		c.MakefilesScanned++
		for i, line := range strings.Split(string(body), "\n") {
			c.MakeLines++
			if !strings.Contains(line, literalFileName) {
				continue
			}
			// Цель, называющая файл литерала И таблицу каталога, производит
			// первое из второго. Называющая только файл — законна (форматирование,
			// линт, перечисление источников).
			if strings.Contains(line, "catalog_") {
				findings = append(findings, fmt.Sprintf(
					"%s:%d: цель сборки производит файл литерала из строк каталога: %s",
					mf, i+1, strings.TrimSpace(line)))
			}
		}
	}
	return findings, c, nil
}

// literalOriginMakefiles — файлы сборки, которые обходит утверждение.
var literalOriginMakefiles = []string{"Makefile", "services/iam/Makefile"}

// TestIAMCT2_11_LiteralIsNotDerivedFromRows — сценарий `-11`.
func TestIAMCT2_11_LiteralIsNotDerivedFromRows(t *testing.T) {
	root := catalogRepoRoot(t)
	pkgFiles, err := treecorpus.UnderWithSuffix(filepath.Join(root, literalPackageRel), ".go")
	if err != nil {
		t.Fatalf("состав пакета-литерала: %v", err)
	}
	findings, c, err := auditLiteralOrigin(root, pkgFiles, literalOriginMakefiles)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	t.Logf("осмотрено файлов Go: %d; директив генерации: %d; файлов сборки: %d (строк %d)",
		c.GoFiles, c.GenerateDirs, c.MakefilesScanned, c.MakeLines)

	// Ноль ДИРЕКТИВ — законный факт дерева. Ноль ПРОЧИТАННЫХ — пустой обход.
	if c.GoFiles == 0 {
		t.Fatalf("в %s не прочитано ни одного файла — вердикт беспредметен", literalPackageRel)
	}
	if c.MakefilesScanned == 0 || c.MakeLines == 0 {
		t.Fatalf("файлов сборки прочитано %d (строк %d) — вторая ось утверждения беспредметна",
			c.MakefilesScanned, c.MakeLines)
	}
	for _, f := range findings {
		t.Errorf("литерал производится из строк: %s", f)
	}
}

// TestIAMCT2_11_Injection — доказательство способности упасть, в ОБЕ стороны.
//
// Инъекция подаётся синтетическим деревом: портить живое ради доказательства
// нельзя, а утверждение, чью способность падать не показали, от вакуумного
// неотличимо.
func TestIAMCT2_11_Injection(t *testing.T) {
	write := func(t *testing.T, root, rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("создать каталог: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("записать %s: %v", rel, err)
		}
	}

	cases := []struct {
		name     string
		goFile   string
		makefile string
		wantHit  bool
	}{
		{
			name:     "контроль: законный близнец молчит",
			goFile:   "package authzmap\n\nimport \"github.com/PRO-Robotech/kacho/services/iam/internal/domain\"\n\nvar _ = domain.KnownModules\n",
			makefile: "lint:\n\tgofmt -l services/iam/internal/authzmap/fga_types.go\n",
			wantHit:  false,
		},
		{
			name:     "инъекция: пакет-литерал импортирует порт строк",
			goFile:   "package authzmap\n\nimport \"github.com/PRO-Robotech/kacho/services/iam/internal/catalog\"\n\nvar _ = catalog.Rows{}\n",
			makefile: "lint:\n\techo ok\n",
			wantHit:  true,
		},
		{
			name:     "инъекция: пакет-литерал дотянулся до адаптера базы",
			goFile:   "package authzmap\n\nimport \"github.com/jackc/pgx/v5/pgxpool\"\n\nvar _ *pgxpool.Pool\n",
			makefile: "lint:\n\techo ok\n",
			wantHit:  true,
		},
		{
			name:     "инъекция: директива генерации пишет файл литерала",
			goFile:   "package authzmap\n\n//go:generate go run ./tools/gen -out fga_types.go\n",
			makefile: "lint:\n\techo ok\n",
			wantHit:  true,
		},
		{
			name:     "инъекция: цель сборки производит литерал из строк каталога",
			goFile:   "package authzmap\n",
			makefile: "gen:\n\tpsql -c 'select * from catalog_resource' > services/iam/internal/authzmap/fga_types.go\n",
			wantHit:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, filepath.Join(literalPackageRel, literalFileName), tc.goFile)
			write(t, root, "Makefile", tc.makefile)

			findings, c, err := auditLiteralOrigin(root,
				[]string{filepath.Join(root, literalPackageRel, literalFileName)},
				[]string{"Makefile"})
			if err != nil {
				t.Fatalf("обход синтетического дерева: %v", err)
			}
			if c.GoFiles == 0 || c.MakeLines == 0 {
				t.Fatalf("синтетическое дерево не прочитано (файлов %d, строк сборки %d) — "+
					"инъекция ничего не доказывает", c.GoFiles, c.MakeLines)
			}
			if got := len(findings) > 0; got != tc.wantHit {
				t.Fatalf("находок %d (ожидалось hit=%v): %v", len(findings), tc.wantHit, findings)
			}
		})
	}
}
