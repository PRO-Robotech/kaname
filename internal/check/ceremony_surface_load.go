// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// ceremony_surface_load.go — РАДИУС разбора гейта единственности поверхности
// церемонии: что линкуется в бинарь службы и что из этого читается исходником.
//
// # Радиус — бинарь, а не каталог
//
// Регистрация маршрута живёт там, где её написали: в корне, в конструкторе
// пакета полосы, в порождённой привязке шлюза, в петле по записям данных. Обход
// одного файла корня (так была устроена прежняя проба) слеп ко всему, что
// переехало в пакет; обход одного каталога — к тому, что приехало из
// фундамента. Поэтому радиус — ВСЁ, что `go list -deps` называет зависимостью
// композиционного корня.
//
// Исходником читается семейство модулей владельца (путь модуля с тем же
// префиксом организации, что у модуля службы: служба и её фундамент), прочее —
// данными экспорта того же прогона `go list`: его типы нужны, чтобы разбор
// видел, ЧТО за значение течёт, а регистрировать маршруты на наших
// мультиплексорах чужой код может лишь через переданный ему мультиплексор — и
// такая передача считается отдельно. Пакет, объявивший тип мультиплексора
// (net/http, runtime шлюза), — его собственное API и передачей не считается.
//
// # Наложение
//
// Инъекции правят копию пакета в каталоге пробы. Наложение заменяет файлы
// пакета (или заводит новый пакет), а заново проверяются ровно пакеты,
// зависящие от наложенного: остальные берутся из уже разобранного.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// surfaceListed — одна строка `go list -deps -export -json`.
type surfaceListed struct {
	ImportPath string
	Name       string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Export     string
	Standard   bool
	DepOnly    bool
	Imports    []string
	Module     *struct {
		Path      string
		GoVersion string
		Main      bool
		Dir       string
	}
	Error *struct{ Err string }
}

// surfaceSrcPkg — пакет радиуса, прочитанный исходником.
type surfaceSrcPkg struct {
	path  string
	own   bool
	root  bool
	files []*ast.File
	types *types.Package
	info  *types.Info
}

// surfaceListing — перечень бинаря и разобранная база; одна на корень.
type surfaceListing struct {
	mu          sync.Mutex
	moduleRoot  string
	rootPkg     string
	modulePath  string
	ownerPrefix string
	order       []*surfaceListed
	byPath      map[string]*surfaceListed
	fset        *token.FileSet
	gc          types.Importer
	base        *surfaceProgram
}

// surfaceProgram — разобранный радиус одного прогона.
type surfaceProgram struct {
	fset   *token.FileSet
	pkgs   []*surfaceSrcPkg
	byPath map[string]*surfaceSrcPkg
	root   *surfaceSrcPkg
}

var (
	surfaceListingsMu sync.Mutex
	surfaceListings   = map[string]*surfaceListing{}
)

// ownerPrefixOf — префикс организации пути модуля: первые два сегмента.
func ownerPrefixOf(modulePath string) string {
	parts := strings.SplitN(modulePath, "/", 3)
	if len(parts) < 2 {
		return modulePath + "/"
	}
	return parts[0] + "/" + parts[1] + "/"
}

// listingFor — перечень бинаря для корня (разбирается один раз на процесс).
func listingFor(ctx context.Context, moduleRoot, rootPkg string) (*surfaceListing, error) {
	key := moduleRoot + "\x00" + rootPkg
	surfaceListingsMu.Lock()
	defer surfaceListingsMu.Unlock()
	if l, ok := surfaceListings[key]; ok {
		return l, nil
	}
	l, err := newListing(ctx, moduleRoot, rootPkg, surfaceListTimeout)
	if err != nil {
		return nil, err
	}
	surfaceListings[key] = l
	return l, nil
}

// surfaceListTimeout — срок `go list`, называющего радиус.
//
// Без своего срока зависший `go list` (сеть модулей, блокировка кэша) съел
// бы весь бюджет прогона, и пакет проб оборвался бы паникой без причины.
// Замер: холодная сборка данных экспорта радиуса под -race (пустой GOCACHE,
// 4 ядра, 605 пакетов) — 29 с. Срок в 10 раз выше замера и в 5 раз ниже
// бюджета прогона конвейера (-timeout 25m).
const surfaceListTimeout = 5 * time.Minute

func newListing(ctx context.Context, moduleRoot, rootPkg string, timeout time.Duration) (*surfaceListing, error) {
	if rootPkg == "" {
		return nil, errors.New("радиус: композиционный корень не назван")
	}
	args := []string{"list", "-deps", "-export",
		"-json=ImportPath,Name,Dir,GoFiles,CgoFiles,Export,Standard,DepOnly,Imports,Module,Error"}
	if surfaceListRace {
		args = append(args, "-race")
	}
	args = append(args, rootPkg)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- путь пакета приходит из пробы дерева, не из запроса
	cmd.Dir = moduleRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("радиус: go list -deps %s в %s не уложился в срок %s: %w", rootPkg, moduleRoot, timeout, ctx.Err())
	case ctx.Err() != nil:
		return nil, fmt.Errorf("радиус: go list -deps %s в %s отменён вызывающим: %w", rootPkg, moduleRoot, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("радиус: go list -deps %s в %s: %w\n%s", rootPkg, moduleRoot, err, strings.TrimSpace(stderr.String()))
	}
	l := &surfaceListing{moduleRoot: moduleRoot, rootPkg: rootPkg, byPath: map[string]*surfaceListed{}, fset: token.NewFileSet()}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p surfaceListed
		if derr := dec.Decode(&p); errors.Is(derr, io.EOF) {
			break
		} else if derr != nil {
			return nil, fmt.Errorf("радиус: разбор вывода go list: %w", derr)
		}
		if p.Error != nil {
			return nil, fmt.Errorf("радиус: пакет %s: %s", p.ImportPath, p.Error.Err)
		}
		pp := p
		l.order = append(l.order, &pp)
		l.byPath[p.ImportPath] = &pp
	}
	root, ok := l.byPath[rootPkg]
	if !ok || root.DepOnly || root.Module == nil {
		return nil, fmt.Errorf("радиус: go list не назвал корень %s пакетом главного модуля", rootPkg)
	}
	// Судится ровно названный корень модуля. Вне модуля `go list` под
	// GOFLAGS=-mod=mod способен назвать пакет из кэша модулей (чужая ревизия),
	// из подкаталога — модуль выше него: и то и другое — не то, что названо.
	if !root.Module.Main || !sameDir(root.Module.Dir, moduleRoot) {
		return nil, fmt.Errorf("радиус: корень модуля %s не тот, что назван: go list назвал пакет %s модулем %s "+
			"в %s (главный модуль: %v) — судилось бы не это дерево", moduleRoot, rootPkg, root.Module.Path,
			root.Module.Dir, root.Module.Main)
	}
	l.modulePath = root.Module.Path
	l.ownerPrefix = ownerPrefixOf(l.modulePath)
	l.gc = importer.ForCompiler(l.fset, "gc", func(path string) (io.ReadCloser, error) {
		p, ok := l.byPath[path]
		if !ok || p.Export == "" {
			return nil, fmt.Errorf("данных экспорта для %s нет", path)
		}
		return os.Open(p.Export)
	})
	return l, nil
}

// sameDir — два пути называют один каталог (после приведения к абсолютному
// и раскрытия ссылок).
func sameDir(a, b string) bool {
	norm := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		return filepath.Clean(p)
	}
	return a != "" && b != "" && norm(a) == norm(b)
}

// inRadius — читается ли пакет исходником.
func (l *surfaceListing) inRadius(p *surfaceListed) bool {
	return !p.Standard && p.Module != nil && strings.HasPrefix(p.Module.Path+"/", l.ownerPrefix)
}

// displayDir — каталог пакета так, как его называет находка.
func (l *surfaceListing) displayDir(importPath string) string {
	if importPath == l.modulePath {
		return "."
	}
	if strings.HasPrefix(importPath, l.modulePath+"/") {
		return strings.TrimPrefix(importPath, l.modulePath+"/")
	}
	return importPath
}

// program — разобранный радиус с наложением.
func (l *surfaceListing) program(overlay map[string]string) (*surfaceProgram, error) {
	if len(overlay) == 0 && l.base != nil {
		return l.base, nil
	}
	if len(overlay) > 0 && l.base == nil {
		// База разбирается один раз: наложение перепроверяет лишь зависящих.
		if _, err := l.program(nil); err != nil {
			return nil, err
		}
	}
	affected := map[string]bool{}
	for path := range overlay {
		affected[path] = true
	}
	// Зависящие от наложенного перепроверяются: тип из прежней проверки
	// несовместим с типом из новой.
	for changed := true; changed; {
		changed = false
		for _, p := range l.order {
			if affected[p.ImportPath] || !l.inRadius(p) {
				continue
			}
			for _, imp := range p.Imports {
				if affected[imp] {
					affected[p.ImportPath] = true
					changed = true
					break
				}
			}
		}
	}
	prog := &surfaceProgram{fset: l.fset, byPath: map[string]*surfaceSrcPkg{}}
	checking := map[string]bool{}
	var ensure func(path string) (*surfaceSrcPkg, error)
	imp := surfaceImporterFunc(func(path string) (*types.Package, error) {
		p, ok := l.byPath[path]
		_, over := overlay[path]
		if over || (ok && l.inRadius(p)) {
			sp, err := ensure(path)
			if err != nil {
				return nil, err
			}
			return sp.types, nil
		}
		return l.gc.Import(path)
	})
	ensure = func(path string) (*surfaceSrcPkg, error) {
		if sp, ok := prog.byPath[path]; ok {
			return sp, nil
		}
		if !affected[path] && l.base != nil {
			if sp, ok := l.base.byPath[path]; ok {
				prog.byPath[path] = sp
				return sp, nil
			}
		}
		if checking[path] {
			return nil, fmt.Errorf("радиус: цикл импорта через %s", path)
		}
		checking[path] = true
		sp, err := l.check(path, overlay[path], imp)
		if err != nil {
			return nil, err
		}
		prog.byPath[path] = sp
		return sp, nil
	}
	for _, p := range l.order {
		if !l.inRadius(p) {
			continue
		}
		if _, err := ensure(p.ImportPath); err != nil {
			return nil, err
		}
	}
	// Новые пакеты наложения — те, которых нет в перечне бинаря. Их может
	// уже разобрать импорт корня, но в состав прогона они входят всё равно.
	var extra []string
	for path := range overlay {
		if _, listed := l.byPath[path]; !listed {
			extra = append(extra, path)
		}
	}
	sort.Strings(extra)
	for _, path := range extra {
		if _, err := ensure(path); err != nil {
			return nil, err
		}
	}
	for _, p := range l.order {
		if sp, ok := prog.byPath[p.ImportPath]; ok {
			prog.pkgs = append(prog.pkgs, sp)
		}
	}
	for _, path := range extra {
		prog.pkgs = append(prog.pkgs, prog.byPath[path])
	}
	prog.root = prog.byPath[l.rootPkg]
	if prog.root == nil {
		return nil, fmt.Errorf("радиус: корень %s не разобран", l.rootPkg)
	}
	if len(overlay) == 0 {
		l.base = prog
	}
	return prog, nil
}

type surfaceImporterFunc func(path string) (*types.Package, error)

func (f surfaceImporterFunc) Import(path string) (*types.Package, error) { return f(path) }

// sourceFiles — файлы пакета: перечень go list либо каталог наложения.
func (l *surfaceListing) sourceFiles(path, overlayDir string) (names []string, dir string, err error) {
	if overlayDir == "" {
		p := l.byPath[path]
		if len(p.CgoFiles) > 0 {
			return nil, "", fmt.Errorf("радиус: пакет %s собирается с cgo — исходником его не прочесть", path)
		}
		return append([]string(nil), p.GoFiles...), p.Dir, nil
	}
	entries, rerr := os.ReadDir(overlayDir)
	if rerr != nil {
		return nil, "", fmt.Errorf("радиус: наложение %s: %w", path, rerr)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		ok, merr := build.Default.MatchFile(overlayDir, name)
		if merr != nil {
			return nil, "", fmt.Errorf("радиус: наложение %s/%s: %w", path, name, merr)
		}
		if ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, overlayDir, nil
}

// check разбирает и проверяет типами один пакет радиуса.
func (l *surfaceListing) check(path, overlayDir string, imp types.Importer) (*surfaceSrcPkg, error) {
	names, dir, err := l.sourceFiles(path, overlayDir)
	if err != nil {
		return nil, err
	}
	display := l.displayDir(path)
	sp := &surfaceSrcPkg{path: path, root: path == l.rootPkg}
	goVersion := ""
	if p, ok := l.byPath[path]; ok && p.Module != nil {
		sp.own = p.Module.Path == l.modulePath
		goVersion = p.Module.GoVersion
	} else {
		sp.own = strings.HasPrefix(path+"/", l.modulePath+"/")
		goVersion = l.byPath[l.rootPkg].Module.GoVersion
	}
	for _, name := range names {
		src, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			return nil, fmt.Errorf("радиус: %s/%s: %w", display, name, rerr)
		}
		f, perr := parser.ParseFile(l.fset, display+"/"+name, src, parser.SkipObjectResolution)
		if perr != nil {
			return nil, fmt.Errorf("радиус: разбор %w", perr)
		}
		sp.files = append(sp.files, f)
	}
	sp.info = &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Implicits:  map[ast.Node]types.Object{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	var typeErrs []string
	conf := types.Config{
		Importer: imp,
		Error: func(err error) {
			if len(typeErrs) < 5 {
				typeErrs = append(typeErrs, err.Error())
			}
		},
	}
	if goVersion != "" {
		conf.GoVersion = "go" + goVersion
	}
	tp, _ := conf.Check(path, l.fset, sp.files, sp.info)
	if len(typeErrs) > 0 {
		return nil, fmt.Errorf("радиус: проверка типов %s:\n  %s", display, strings.Join(typeErrs, "\n  "))
	}
	sp.types = tp
	return sp, nil
}
