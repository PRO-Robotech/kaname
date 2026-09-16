// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// singleton_lock_keys_distinct_test.go — у каждого прохода старта СВОЙ ключ
// общего на кластер замка (IAM-PNE-2-03, полоса Б; дом Д).
//
// Два разных прохода не вправе исключать друг друга: одинаковый ключ у двух
// проходов означает, что второй молча пропускает прогон, пока идёт первый, —
// и его перепись не печатается никому. Довод записан у самого соседа
// (`orphan_mirror_adapter.go`, `orphanMirrorSingletonLockKey`).
//
// # Что проверяется — объявления, а не поведение
//
// Читаются константы формы `<имя>SingletonLockKey int64 = <литерал>` во всех
// не-тестовых файлах пакета; значения разбираются из литерала (шестнадцатеричная
// форма с подчёркиваниями) и сверяются попарно. Ключей обязано быть не меньше
// четырёх — иначе «различен» зеленело бы на обходе, не нашедшем соседей.
//
// Способность упасть и смолчать доказана инъекцией — ниже, в этом же файле.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// lockKeyDecl — одно объявление ключа.
type lockKeyDecl struct {
	name  string
	value int64
	file  string
}

// readLockKeys — константы `…SingletonLockKey int64 = <литерал>` из исходника.
func readLockKeys(t *testing.T, name string, src any) []lockKeyDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, 0)
	require.NoErrorf(t, err, "%s не разобран", name)
	var out []lockKeyDecl
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if !strings.HasSuffix(ident.Name, "SingletonLockKey") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					continue
				}
				raw := strings.ReplaceAll(lit.Value, "_", "")
				v, perr := strconv.ParseInt(raw, 0, 64)
				require.NoErrorf(t, perr, "%s: литерал ключа %s не разобран: %s", name, ident.Name, lit.Value)
				out = append(out, lockKeyDecl{name: ident.Name, value: v, file: name})
			}
		}
	}
	return out
}

// judgeLockKeys — вердикт: не меньше четырёх ключей и все попарно различны.
func judgeLockKeys(keys []lockKeyDecl) []string {
	if len(keys) < 4 {
		return []string{"ключей замка прочитано " + strconv.Itoa(len(keys)) +
			" — меньше четырёх: обход не нашёл соседей, и «различен» был бы вакуумным"}
	}
	var findings []string
	sorted := append([]lockKeyDecl(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].value < sorted[j].value })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].value == sorted[i-1].value {
			findings = append(findings, "ключи "+sorted[i-1].name+" ("+sorted[i-1].file+") и "+
				sorted[i].name+" ("+sorted[i].file+") совпадают: два прохода исключают друг друга")
		}
	}
	return findings
}

// TestDanglingProjectMirrorSweep_PNE_2_03B — живой гейт над пакетом.
func TestDanglingProjectMirrorSweep_PNE_2_03B(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var keys []lockKeyDecl
	read := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		read++
		keys = append(keys, readLockKeys(t, f, nil)...)
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, k.name)
	}
	t.Logf("перепись: файлов прочитано %d · ключей замка %d: %v", read, len(keys), names)
	require.NotZero(t, read, "не прочитано ни одного файла пакета")
	for _, f := range judgeLockKeys(keys) {
		t.Errorf("%s", f)
	}
	if _, serr := os.Stat("dangling_project_mirror_adapter.go"); serr != nil {
		t.Errorf("адаптера прохода по строкам с несуществующим родителем нет: %v", serr)
	}
}

// ── Инъекция ────────────────────────────────────────────────────────────────

const lockKeysLive = `package pg

const aSingletonLockKey int64 = 0x50_38_42_46
const bSingletonLockKey int64 = 0x4F_4D_53_57
const cSingletonLockKey int64 = 0x4F_53_53_57
const dSingletonLockKey int64 = 0x4F_4D_50_4E
`

const lockKeysCollision = `package pg

const aSingletonLockKey int64 = 0x50_38_42_46
const bSingletonLockKey int64 = 0x4F_4D_53_57
const cSingletonLockKey int64 = 0x4F_53_53_57
const dSingletonLockKey int64 = 0x4F_4D_53_57
`

const lockKeysTooFew = `package pg

const aSingletonLockKey int64 = 0x50_38_42_46
const bSingletonLockKey int64 = 0x4F_4D_53_57
`

func TestDanglingProjectMirrorSweep_PNE_2_03B_Injection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		src         string
		wantFinding bool
		wantInText  string
	}{
		{name: "четыре различных ключа — гейт молчит", src: lockKeysLive},
		{name: "два прохода делят ключ", src: lockKeysCollision, wantFinding: true, wantInText: "совпадают"},
		{name: "соседей не нашли", src: lockKeysTooFew, wantFinding: true, wantInText: "меньше четырёх"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := judgeLockKeys(readLockKeys(t, "synthetic.go", tc.src))
			if tc.wantFinding && len(findings) == 0 {
				t.Fatalf("инъекция не покраснела")
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Fatalf("законный близнец покраснел: %v", findings)
			}
			if tc.wantInText != "" && !strings.Contains(strings.Join(findings, " | "), tc.wantInText) {
				t.Fatalf("находка не называет %q: %v", tc.wantInText, findings)
			}
		})
	}
}
