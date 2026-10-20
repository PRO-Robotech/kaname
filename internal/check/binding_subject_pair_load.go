// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// binding_subject_pair_load.go — радиус гейта пары субъекта выдачи
// (kaname#917): ВСЕ пакеты каталогов радиуса в конфигурации прод-сборки.
//
// # Почему не бинарь службы
//
// Прежняя редакция судила то, что слинковано в `cmd/kaname`, и печатала
// прочее «вне бинаря». Опыт проверки показал две дыры: пакет каталога радиуса,
// слинкованный только в `cmd/iamctl`, и файл под ограничением сборки, которого
// нет в сборке пробы, но есть в прод-сборке. Теперь радиус — каждый пакет
// каталогов (`<каталог>/...`) независимо от того, какой бинарь его линкует, а
// файлы отбираются ограничениями ПРОД-сборки (`Dockerfile`: `CGO_ENABLED=0`,
// `GOOS=linux`), а не той, в которой идёт проба. Непроверочный файл радиуса,
// не попавший и в прод-сборку, судится ведомостью: новый такой файл — находка.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"go/importer"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// BindingPairProdEnv — конфигурация прод-сборки, в которой отбираются файлы
// радиуса (Dockerfile, сборка `cmd/kaname`). Архитектура — хоста пробы:
// ограничений по архитектуре в радиусе нет, и это печатает перепись
// (файлы вне сборки).
var BindingPairProdEnv = []string{"CGO_ENABLED=0", "GOOS=linux"}

var (
	bindingPairListingsMu sync.Mutex
	bindingPairListings   = map[string]*surfaceListing{}
)

// bindingPairListingFor — перечень радиуса (разбирается один раз на процесс).
func bindingPairListingFor(ctx context.Context, moduleRoot string, dirs []string) (*surfaceListing, error) {
	var patterns []string
	for _, d := range dirs {
		if st, err := os.Stat(filepath.Join(moduleRoot, filepath.FromSlash(d))); err == nil && st.IsDir() {
			patterns = append(patterns, "./"+d+"/...")
		}
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("обход пуст: ни одного каталога радиуса %v в %s — «ноль находок» здесь "+
			"означало бы «ноль прочитанного»", dirs, moduleRoot)
	}
	key := moduleRoot + "\x00" + strings.Join(patterns, "\x00")
	bindingPairListingsMu.Lock()
	defer bindingPairListingsMu.Unlock()
	if l, ok := bindingPairListings[key]; ok {
		return l, nil
	}
	l, err := newProdListing(ctx, moduleRoot, patterns)
	if err != nil {
		return nil, err
	}
	bindingPairListings[key] = l
	return l, nil
}

// newProdListing — `go list -deps -export` по шаблонам в прод-конфигурации.
// Детектор гонок не включается: под `CGO_ENABLED=0` он не собирается, а
// данные экспорта нужны лишь для проверки типов.
func newProdListing(ctx context.Context, moduleRoot string, patterns []string) (*surfaceListing, error) {
	args := append([]string{"list", "-deps", "-export",
		"-json=ImportPath,Name,Dir,GoFiles,CgoFiles,Export,Standard,DepOnly,Imports,Module,Error"}, patterns...)
	ctx, cancel := context.WithTimeout(ctx, surfaceListTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- шаблоны — каталоги радиуса гейта
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), BindingPairProdEnv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("радиус: go list %v в %s не уложился в срок %s: %w", patterns, moduleRoot, surfaceListTimeout, ctx.Err())
	case ctx.Err() != nil:
		return nil, fmt.Errorf("радиус: go list %v отменён вызывающим: %w", patterns, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("радиус: go list %v в %s: %w\n%s", patterns, moduleRoot, err, strings.TrimSpace(stderr.String()))
	}
	l := &surfaceListing{moduleRoot: moduleRoot, byPath: map[string]*surfaceListed{}, fset: token.NewFileSet()}
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
		if l.rootPkg == "" && !p.DepOnly && p.Module != nil && p.Module.Main {
			l.rootPkg = p.ImportPath
		}
	}
	if l.rootPkg == "" {
		return nil, fmt.Errorf("обход пуст: шаблоны %v не назвали ни одного пакета главного модуля", patterns)
	}
	root := l.byPath[l.rootPkg]
	if !sameDir(root.Module.Dir, moduleRoot) {
		return nil, fmt.Errorf("радиус: модуль %s в %s, а назван %s — судилось бы не это дерево",
			root.Module.Path, root.Module.Dir, moduleRoot)
	}
	l.modulePath = root.Module.Path
	l.ownerPrefix = ownerPrefixOf(l.modulePath)
	ctxt := build.Default
	ctxt.CgoEnabled = false
	ctxt.GOOS = "linux"
	l.ctxt = &ctxt
	l.gc = importer.ForCompiler(l.fset, "gc", func(path string) (io.ReadCloser, error) {
		p, ok := l.byPath[path]
		if !ok || p.Export == "" {
			return nil, fmt.Errorf("данных экспорта для %s нет", path)
		}
		return os.Open(p.Export)
	})
	return l, nil
}
