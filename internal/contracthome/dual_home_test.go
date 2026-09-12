// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// dual_home_test.go — ОБЕ копии одного контракта не доезжают до одного
// двоичного.
//
// # ПРЕДМЕТ, И ЦЕНА ЕГО ИЗМЕРЕНА
//
// Решением владельца 2026-09-13 контракты службы уехали в её репозиторий
// (kacho#2616), и на время переезда один и тот же контракт порождает заглушки в
// ДВУХ модулях: у платформы (`<модуль платформы>/pkg/api/kaname/…`) и у службы
// (`<модуль службы>/pkg/api/kaname/…`). Дубликат пути безвреден ровно до тех
// пор, пока ни одно двоичное не слинковало обе копии.
//
// Слинкует — и отказ приходит НЕ СБОРКОЙ:
//
//	panic: proto: file "kaname/cloud/iam/v1/authorize_service.proto" is already registered
//	        previously from: "…/kacho/pkg/api/kaname/cloud/iam/v1"
//	        currently from:  "…/kaname/pkg/api/kaname/cloud/iam/v1"
//
// Это вывод настоящего бинаря службы, собранного из дерева, где переключение
// импортов было сделано: `go build` дал код 0, запуск — код 2 в инициализации, до
// первой строки `main`.
//
// # ПОЧЕМУ ПРЕДИКАТ ПО ПРЯМЫМ ИМПОРТАМ ДАЁТ ЛОЖНОЕ ЗЕЛЁНОЕ
//
// Предикат «в дереве службы нет узла импорта платформенных заглушек» СЛЕП к
// самому дорогому случаю. Заглушки платформы приезжают ТРАНЗИТИВНО: пакеты
// объявленного остатка (`internal/supplyhygiene`, ведомость `platformResidual`)
// импортируют их своим НЕ-тестовым кодом, и двоичное получает вторую копию, не
// называя ни одного её пути. Замерено:
//
//	pkg/ownerregister/ownerregister.go  → pkg/api/kaname/cloud/iam/v1
//	pkg/subjectchange/reader.go         → pkg/api/kaname/cloud/iam/v1
//
// Поэтому гейт читает НЕ ТОЛЬКО дерево службы: для каждого платформенного
// пакета, названного её импортом, он обходит исходники этого пакета в кэше
// модулей и ищет путь к каталогу заглушек платформы. Носитель найден — значит
// вторая копия приедет, сколько бы прямых импортов ни было снято.
//
// # ЧЕГО ГЕЙТ НЕ УТВЕРЖДАЕТ
//
// Он не говорит «переезд завершён»: у него другой предмет — что промежуточное
// состояние НЕ ДЕТОНИРУЕТ. Завершённость переезда (ни один узел не читает
// заглушку у платформы) — предмет своей задачи и своего гейта, и она упирается
// в перенос двух названных выше пакетов (kacho#2614).
package contracthome

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const (
	// platformModulePath — модуль платформы, остающийся внешней зависимостью
	// службы по её объявленному остатку (kacho#2614).
	platformModulePath = "github.com/PRO-Robotech/kacho"
	// serviceModulePath — модуль самой службы.
	serviceModulePath = "github.com/PRO-Robotech/kaname"
	// stubDirName — каталог порождённых заглушек в обоих модулях: пути внутри
	// него совпадают, потому что оба порождены из одного контракта.
	stubDirName = "pkg/api"
	// duplicatedContractRoot — корень, порождаемый сегодня в ОБОИХ модулях.
	duplicatedContractRoot = "kaname"
)

const (
	dualHomeGroundDirect = "то же двоичное читает заглушку контракта и у платформы, и у службы: " +
		"дескриптор регистрируется дважды, и отказ приходит паникой инициализации, а не сборкой"
	dualHomeGroundTransitive = "заглушка платформы приезжает ТРАНЗИТИВНО пакетом объявленного " +
		"остатка, и двоичное получает вторую копию, не называя ни одного её пути"
)

// dualHomeFinding — одна пара, доезжающая до одного двоичного.
type dualHomeFinding struct {
	Ground  string
	Carrier string // платформенный пакет-носитель; пусто для прямого импорта
	Via     string // путь заглушки платформы, к которому ведёт носитель
	Detail  string
}

func (f dualHomeFinding) String() string {
	if f.Carrier == "" {
		return fmt.Sprintf("%s (%s)", f.Ground, f.Detail)
	}
	return fmt.Sprintf("%s: %s → %s (%s)", f.Ground, f.Carrier, f.Via, f.Detail)
}

// dualHomeCensus — объём осмотренного.
type dualHomeCensus struct {
	ServiceFiles    int
	ServiceImports  int
	OwnStubNodes    int
	PlatformStubs   int
	PlatformModule  int
	PlatformPkgs    int
	PlatformFiles   int
	Carriers        int
	OwnStubFiles    int
	PlatformVersion string
}

func (c dualHomeCensus) String() string {
	return fmt.Sprintf("дерево службы: файлов Go %d, узлов импорта %d — своих заглушек %d, "+
		"платформенных заглушек %d, платформенного модуля %d; заглушек в дереве %d файлов; "+
		"кэш модуля платформы %s: пакетов осмотрено %d, файлов разобрано %d, носителей %d",
		c.ServiceFiles, c.ServiceImports, c.OwnStubNodes, c.PlatformStubs, c.PlatformModule,
		c.OwnStubFiles, c.PlatformVersion, c.PlatformPkgs, c.PlatformFiles, c.Carriers)
}

// platformSourceRoot — каталог исходников платформенного модуля в кэше.
//
// Версия берётся из `go.mod` службы, а путь экранируется тем же правилом, каким
// его пишет сам Go: заглавная буква превращается в `!строчную`. Собирать этот
// путь вручную нельзя — модуль `PRO-Robotech` весь в заглавных, и невыполненное
// экранирование дало бы «кэша нет» на машине, где он есть.
func platformSourceRoot(serviceTreeRoot string) (string, string, error) {
	raw, err := os.ReadFile(filepath.Join(serviceTreeRoot, "go.mod"))
	if err != nil {
		return "", "", fmt.Errorf("go.mod службы не прочитан: %w", err)
	}
	mf, err := modfile.Parse("go.mod", raw, nil)
	if err != nil {
		return "", "", fmt.Errorf("go.mod службы не разобран: %w", err)
	}
	version := ""
	for _, r := range mf.Require {
		if r.Mod.Path == platformModulePath {
			version = r.Mod.Version
			break
		}
	}
	if version == "" {
		return "", "", fmt.Errorf("go.mod службы не требует %s: либо зависимость снята целиком "+
			"(тогда предмет этого гейта исчерпан вместе с ней), либо имя модуля сменилось",
			platformModulePath)
	}
	cache := os.Getenv("GOMODCACHE")
	if cache == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", version, fmt.Errorf("кэш модулей не установлен: ни GOMODCACHE, ни домашний каталог")
		}
		cache = filepath.Join(home, "go", "pkg", "mod")
	}
	escaped, err := module.EscapePath(platformModulePath)
	if err != nil {
		return "", version, fmt.Errorf("экранирование пути модуля: %w", err)
	}
	return filepath.Join(cache, escaped+"@"+version), version, nil
}

// platformCarriers обходит платформенные пакеты, названные импортами службы, и
// возвращает те, чей НЕ-тестовый код ведёт к каталогу заглушек платформы.
//
// Обход транзитивный внутри платформенного модуля: носитель может лежать на
// второй позиции цепи, и один шаг его не увидел бы.
//
// Тестовые файлы платформы исключены ОСОЗНАННО: они не линкуются в потребителя,
// поэтому носителем не являются. Тестовые файлы СЛУЖБЫ, наоборот, считаются —
// пробный бинарь линкует их наравне с прод-кодом.
func platformCarriers(sourceRoot string, seeds []string) (map[string]string, int, int, error) {
	stubPrefix := platformModulePath + "/" + stubDirName + "/" + duplicatedContractRoot
	carriers := map[string]string{}
	seen := map[string]bool{}
	queue := append([]string(nil), seeds...)
	pkgs, files := 0, 0
	fset := token.NewFileSet()

	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		inner := strings.TrimPrefix(pkg, platformModulePath+"/")
		dir := filepath.Join(sourceRoot, filepath.FromSlash(inner))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // пакета нет в этой версии модуля — не носитель и не находка
		}
		pkgs++
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
			if perr != nil {
				return nil, pkgs, files, fmt.Errorf("%s/%s: разбор импортов платформы: %w", inner, name, perr)
			}
			files++
			for _, spec := range f.Imports {
				v, uerr := strconv.Unquote(spec.Path.Value)
				if uerr != nil || !strings.HasPrefix(v, platformModulePath+"/") {
					continue
				}
				if v == stubPrefix || strings.HasPrefix(v, stubPrefix+"/") {
					if _, ok := carriers[pkg]; !ok {
						carriers[pkg] = v
					}
					continue
				}
				queue = append(queue, v)
			}
		}
	}
	return carriers, pkgs, files, nil
}

// scanServiceStubUse читает ДЕРЕВО СЛУЖБЫ: сколько узлов импорта ведёт к своим
// заглушкам, сколько к платформенным, и какие платформенные пакеты названы
// (они же — семена обхода носителей).
//
// СОСТАВ ПРИНОСИТ ВЫЗЫВАЮЩИЙ: индекс git у настоящего дерева, обход диска у
// синтетики инъекции.
func scanServiceStubUse(tree *treecorpus.Tree) (dualHomeCensus, []string, []string, error) {
	var census dualHomeCensus
	root := tree.Root()

	platformStubPrefix := platformModulePath + "/" + stubDirName + "/"
	ownStubPrefix := serviceModulePath + "/" + stubDirName + "/"

	directPlatform := map[string]bool{}
	platformPkgs := map[string]bool{}
	fset := token.NewFileSet()

	for _, rel := range tree.SortedFiles() {
		if strings.HasPrefix(rel, stubDirName+"/") {
			census.OwnStubFiles++
		}
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, path.Join(root, rel), nil, parser.ImportsOnly)
		if err != nil {
			return census, nil, nil, fmt.Errorf("%s: разбор импортов: %w", rel, err)
		}
		census.ServiceFiles++
		for _, spec := range f.Imports {
			census.ServiceImports++
			v, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				continue
			}
			switch {
			case strings.HasPrefix(v, ownStubPrefix):
				census.OwnStubNodes++
			case strings.HasPrefix(v, platformModulePath+"/"):
				census.PlatformModule++
				if strings.HasPrefix(v, platformStubPrefix) {
					census.PlatformStubs++
					directPlatform[v] = true
					continue
				}
				platformPkgs[v] = true
			}
		}
	}

	return census, sortedKeys(platformPkgs), sortedKeys(directPlatform), nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dualHomeFindings сводит два независимо полученных факта: линкует ли служба
// свои заглушки и приезжает ли к ней вторая копия — прямо либо носителем.
//
// Ноль своих узлов означает, что детонировать нечему: вторая копия лежит в
// дереве, но ни одно двоичное её не линкует. Это и есть промежуточное состояние
// переезда, безопасное по построению.
func dualHomeFindings(census dualHomeCensus, direct []string, carriers map[string]string) []dualHomeFinding {
	if census.OwnStubNodes == 0 {
		return nil
	}
	var findings []dualHomeFinding
	if len(direct) > 0 {
		findings = append(findings, dualHomeFinding{
			Ground: dualHomeGroundDirect,
			Detail: fmt.Sprintf("своих узлов %d, платформенных %d: %s",
				census.OwnStubNodes, census.PlatformStubs, strings.Join(direct, " ")),
		})
	}
	names := make([]string, 0, len(carriers))
	for c := range carriers {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		findings = append(findings, dualHomeFinding{
			Ground: dualHomeGroundTransitive, Carrier: c, Via: carriers[c],
			Detail: fmt.Sprintf("своих узлов %d", census.OwnStubNodes),
		})
	}
	return findings
}

// scanDualHome — полный вопрос над настоящим деревом: дерево службы плюс
// исходники платформенного модуля из кэша.
func scanDualHome(tree *treecorpus.Tree) (dualHomeCensus, []dualHomeFinding, error) {
	census, seeds, direct, err := scanServiceStubUse(tree)
	if err != nil {
		return census, nil, err
	}

	sourceRoot, version, err := platformSourceRoot(tree.Root())
	census.PlatformVersion = version
	if err != nil {
		return census, nil, err
	}
	carriers, pkgs, files, err := platformCarriers(sourceRoot, seeds)
	census.PlatformPkgs, census.PlatformFiles, census.Carriers = pkgs, files, len(carriers)
	if err != nil {
		return census, nil, err
	}
	if census.PlatformModule > 0 && census.PlatformFiles == 0 {
		return census, nil, fmt.Errorf("исходников платформенного модуля в кэше не разобрано ни "+
			"одного файла (искали в %s) — транзитивного носителя назвать нечем, и вердикт был бы "+
			"шире проверенного. Это «условие не создано»: прогони `go mod download` и повтори",
			sourceRoot)
	}
	return census, dualHomeFindings(census, direct, carriers), nil
}

// TestBothCopiesOfAContractNeverReachOneBinary — сам гейт.
func TestBothCopiesOfAContractNeverReachOneBinary(t *testing.T) {
	t.Parallel()

	tree, err := treecorpus.NewTree(serviceRoot)
	if err != nil {
		t.Fatalf("состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: %v",
			serviceRoot, err)
	}

	census, findings, err := scanDualHome(tree)
	if err != nil {
		t.Fatalf("перепись: %s\n%v", census, err)
	}
	t.Logf("перепись: %s", census)

	if census.ServiceFiles == 0 || census.ServiceImports == 0 {
		t.Fatal("обход пуст: файлов Go либо узлов импорта не осмотрено ни одного — " +
			"вердикт беспредметен")
	}
	// Предпосылка, несущая: вторая копия в дереве ЕСТЬ. Ноль означал бы, что
	// дубликата не существует, и «обе копии не сходятся» стало бы утверждением ни
	// о чём — тогда гейт снимают вместе с предметом, а не оставляют зелёным.
	if census.OwnStubFiles == 0 {
		t.Fatalf("под %s/ не прочитано ни одного файла — своих заглушек у службы нет, "+
			"дубликата пути не существует, и предмета у этого гейта тоже", stubDirName)
	}

	for _, f := range findings {
		t.Errorf("%s. Дубликат пути безвреден ровно до момента, когда обе копии сходятся в "+
			"одном двоичном; снять его целиком — предмет kacho#2616, а названный носитель "+
			"снимается переносом пакетов остатка (kacho#2614)", f)
	}
}
