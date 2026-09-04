// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// catalog_snapshot_wiring_injection_test.go — доказательство, что гейт
// `TestIAM1945_CatalogSnapshotBuiltByTheRootIsAlsoStartedByIt` способен упасть и
// способен смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до провязки гейт
// назвал `serve.go:241` и переменную `catalogSnapshot`, после — молчание. Здесь
// то же свойство закреплено воспроизводимо, на синтетике: доказательство,
// требующее вынуть провязку из рабочей копии, в конвейере не исполняется никогда.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const snapshotBuiltAndStarted = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/catalog"

func serve() error {
	snap, err := catalog.NewSnapshot(rows, src, log, obs)
	if err != nil {
		return err
	}
	tasks = append(tasks, func() error {
		snap.Run(ctx, period)
		return nil
	})
	return nil
}
`

const snapshotBuiltNotStarted = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/catalog"

func serve() error {
	snap, err := catalog.NewSnapshot(rows, src, log, obs)
	if err != nil {
		return err
	}
	use(snap.Facts())
	return nil
}
`

// snapshotAliasedNotStarted — тот же дефект под ПСЕВДОНИМОМ импорта. Гейт,
// знающий одно написание, молчал бы на форме столь же законной.
const snapshotAliasedNotStarted = `package main

import cat "github.com/PRO-Robotech/kacho/services/iam/internal/catalog"

func serve() error {
	snap, err := cat.NewSnapshot(rows, src, log, obs)
	if err != nil {
		return err
	}
	use(snap.Facts())
	return nil
}
`

// snapshotNotStartedButNeighbourIs — соседний цикл запущен, снимок нет. Гейт,
// довольствующийся «в корне есть хоть один вызов Run», молчал бы здесь — то есть
// ровно на живом дефекте, который и наблюдался.
const snapshotNotStartedButNeighbourIs = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/catalog"

func serve() error {
	snap, err := catalog.NewSnapshot(rows, src, log, obs)
	if err != nil {
		return err
	}
	growth := newIdentityGrowthSampler(repo)
	tasks = append(tasks, func() error {
		growth.Run(ctx, log)
		return nil
	})
	use(snap.Facts())
	return nil
}
`

// snapshotDiscarded — снимок не связан вовсе. Предмета нет, находки быть не должно.
const snapshotDiscarded = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/catalog"

func probe() { _, _ = catalog.NewSnapshot(rows, src, log, obs) }
`

// startedElsewhere — запуск в ДРУГОМ файле того же пакета: законная раскладка,
// и гейт обязан на ней молчать.
const startedElsewhere = `package main

func startCatalogRefresh() {
	tasks = append(tasks, func() error {
		snap.Run(ctx, period)
		return nil
	})
}
`

type wiringFile struct {
	rel  string
	body string
}

func writeSyntheticRoot(t *testing.T, files []wiringFile) (root string, paths []string) {
	t.Helper()
	root = t.TempDir()
	for _, f := range files {
		abs := filepath.Join(root, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatalf("каталог для %s: %v", f.rel, err)
		}
		if err := os.WriteFile(abs, []byte(f.body), 0o600); err != nil {
			t.Fatalf("записать %s: %v", f.rel, err)
		}
		paths = append(paths, abs)
	}
	return root, paths
}

func TestIAM1945_InjectionRedsTheUnstartedSnapshotAndKeepsQuietOnTheStartedOne(t *testing.T) {
	cases := []struct {
		name  string
		files []wiringFile
		finds bool
	}{
		{
			name:  "построен и запущен — молчание",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", snapshotBuiltAndStarted}},
		},
		{
			name:  "построен и НЕ запущен — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", snapshotBuiltNotStarted}},
			finds: true,
		},
		{
			name:  "под псевдонимом и НЕ запущен — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", snapshotAliasedNotStarted}},
			finds: true,
		},
		{
			name:  "запущен СОСЕД, снимок нет — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", snapshotNotStartedButNeighbourIs}},
			finds: true,
		},
		{
			name:  "снимок отброшен связыванием — молчание",
			files: []wiringFile{{"cmd/kacho-iam/probe.go", snapshotDiscarded}},
		},
		{
			name: "построен в одном файле, запущен в другом — молчание",
			files: []wiringFile{
				{"cmd/kacho-iam/serve.go", snapshotBuiltNotStarted},
				{"cmd/kacho-iam/refresh.go", startedElsewhere},
			},
		},
		{
			name:  "проба, строящая снимок, предметом не является — молчание",
			files: []wiringFile{{"cmd/kacho-iam/serve_test.go", snapshotBuiltNotStarted}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, paths := writeSyntheticRoot(t, tc.files)
			built, started, census, err := snapshotWiring(root, paths)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("%s", census.Summary())

			var unstarted []snapshotBinding
			for _, b := range built {
				if !started[b.Name] {
					unstarted = append(unstarted, b)
				}
			}
			switch {
			case tc.finds && len(unstarted) == 0:
				t.Fatalf("гейт СМОЛЧАЛ на внесённом дефекте — он не способен упасть "+
					"(построено %d, запущено получателей %d)", census.Built, census.RunRecvs)
			case !tc.finds && len(unstarted) > 0:
				t.Fatalf("гейт покраснел на ЗАКОННОЙ раскладке: %s:%d `%s` — "+
					"ложная находка отключает гейт первой",
					unstarted[0].File, unstarted[0].Line, unstarted[0].Name)
			}
			if !tc.finds {
				return
			}
			// Находка обязана НАЗВАТЬ переменную и координату: покрасневший молча
			// гейт посылает читателя искать не там.
			u := unstarted[0]
			if u.Name != "snap" || u.Line == 0 || !strings.HasSuffix(u.File, "serve.go") {
				t.Fatalf("находка не назвала ни переменную, ни координату: %+v", u)
			}
		})
	}
}

// TestIAM1945_InjectionProvesTheEmptyWalkIsRefused — премиса гейта: обход, не
// прочитавший ничего, обязан быть отказом, а не молчаливым успехом. Живой гейт
// превращает обе нулевые величины переписи в отказ; здесь доказано, что на
// пустом составе они действительно нулевые.
func TestIAM1945_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	built, started, census, err := snapshotWiring(root, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(built) != 0 || len(started) != 0 {
		t.Fatalf("на пустом составе найдено построенных %d, запущенных %d — ядро выдумывает",
			len(built), len(started))
	}
	if census.Parsed != 0 || census.Built != 0 {
		t.Fatalf("перепись пустого состава непуста: %s", census.Summary())
	}
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", census.Summary())
}
