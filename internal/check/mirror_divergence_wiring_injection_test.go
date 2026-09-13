// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// mirror_divergence_wiring_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт провязки
// способен упасть и способен смолчать (kacho#1828).
//
// Утверждения строятся на СИНТЕТИЧЕСКОМ дереве, а не на настоящем: проверка,
// доказанная «оно сейчас зелёное», доказывает состояние дерева, а не свойство
// проверки. Каждая ось несёт законного близнеца — без него гейт ловил бы форму,
// а не существо, и первый же ложный срабат его выключил бы.

import (
	"os"
	"path/filepath"
	"testing"
)

const mirrorImportLine = `	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"`

// TestMirrorWiringInjection_CallIsSeen — контроль: настоящий вызов виден.
func TestMirrorWiringInjection_CallIsSeen(t *testing.T) {
	scan := scanSynthetic(t, `package main

import (
	"context"
`+mirrorImportLine+`
)

func boot(ctx context.Context, pool any) {
	rows, scanned, err := resource_mirror.Divergence(ctx, pool)
	_, _, _ = rows, scanned, err
}
`)
	if scan.Calls != 1 {
		t.Fatalf("настоящий вызов не увиден: вызовов %d при разобранных %d", scan.Calls, scan.Files)
	}
}

// TestMirrorWiringInjection_CallRemovedIsAFinding — инъекция: вызов снят,
// импорт остался.
//
// Одно-фактная: от контроля мир отличается РОВНО вызовом. Снять вместе с
// импортом значило бы менять два факта сразу, и красное могло бы прийти от
// второго.
func TestMirrorWiringInjection_CallRemovedIsAFinding(t *testing.T) {
	scan := scanSynthetic(t, `package main

import (
	"context"
`+mirrorImportLine+`
)

var _ = resource_mirror.CatalogLive

func boot(ctx context.Context, pool any) {
	_, _ = ctx, pool
}
`)
	if scan.Files == 0 {
		t.Fatalf("обход синтетики пуст — инъекция сказана ни о чём")
	}
	if scan.Calls != 0 {
		t.Fatalf("вызовов %d при снятом вызове — гейт считает не узлы вызова", scan.Calls)
	}
}

// TestMirrorWiringInjection_WordInProseIsNotACall — законный близнец: имя в
// комментарии и в строковом литерале вызовом НЕ является.
//
// Без него гейт зеленел бы на закомментированном вызове и краснел бы на
// собственном объяснении.
func TestMirrorWiringInjection_WordInProseIsNotACall(t *testing.T) {
	scan := scanSynthetic(t, `package main

import (
	"fmt"
`+mirrorImportLine+`
)

// Здесь когда-то звали resource_mirror.Divergence(ctx, pool) — и это ПРОЗА.
//	resource_mirror.Divergence(ctx, pool)
var _ = resource_mirror.CatalogLive

func boot() {
	fmt.Println("resource_mirror.Divergence(ctx, pool)")
}
`)
	if scan.Calls != 0 {
		t.Fatalf("вызовов %d — гейт судит слово, а не узел вызова", scan.Calls)
	}
}

// TestMirrorWiringInjection_AliasedCallIsSeen — законный близнец: вызов через
// АЛИАС импорта.
//
// Форма в Go законна ровно так же, и распознаватель, о ней не знающий, не даёт
// ни красного, ни зелёного — он молчит, а провязка уезжает из-под наблюдения.
func TestMirrorWiringInjection_AliasedCallIsSeen(t *testing.T) {
	scan := scanSynthetic(t, `package main

import (
	"context"

	mirror "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

func boot(ctx context.Context, pool any) {
	rows, scanned, err := mirror.Divergence(ctx, pool)
	_, _, _ = rows, scanned, err
}
`)
	if scan.Calls != 1 {
		t.Fatalf("вызов через алиас не увиден: вызовов %d", scan.Calls)
	}
}

// TestMirrorWiringInjection_NeighbourFuncIsNotTheReader — близкий сосед не
// засчитывается за читателя.
//
// `UnresolvableDivergence` отбирает строки УЖЕ ПРОЧИТАННОЙ разности: вызвать её
// можно, не спросив базу ни разу. Засчитать её значило бы объявить провязку
// там, где величина не производится.
func TestMirrorWiringInjection_NeighbourFuncIsNotTheReader(t *testing.T) {
	scan := scanSynthetic(t, `package main

import (
`+mirrorImportLine+`
)

func boot(rows []resource_mirror.DivergenceRow) int {
	return len(resource_mirror.UnresolvableDivergence(rows))
}
`)
	if scan.Calls != 0 {
		t.Fatalf("вызовов %d — соседняя функция засчитана за читателя", scan.Calls)
	}
}

// TestMirrorWiringInjection_ForeignPackageIsNotTheReader — законный близнец:
// одноимённая функция ЧУЖОГО пакета.
//
// Гейт ключуется на пару «локальное имя пакета-читателя + имя функции», а не на
// имя функции: иначе любой чужой `Divergence` объявлял бы провязку исполненной.
func TestMirrorWiringInjection_ForeignPackageIsNotTheReader(t *testing.T) {
	scan := scanSynthetic(t, `package main

import (
	"context"

	other "example.com/other/divergence"
)

func boot(ctx context.Context, pool any) {
	_, _, _ = other.Divergence(ctx, pool)
}
`)
	if scan.Calls != 0 {
		t.Fatalf("вызовов %d — чужой пакет засчитан за читателя", scan.Calls)
	}
}

// TestMirrorWiringInjection_EmptyTreeIsVoidNotGreen — пустой обход не «чисто».
//
// Ноль разобранных файлов даёт ноль вызовов, и без этого различения гейт
// объявлял бы провязку отсутствующей всякий раз, когда обход обвалился, —
// и наоборот, читался бы зелёным на пустом каталоге.
func TestMirrorWiringInjection_EmptyTreeIsVoidNotGreen(t *testing.T) {
	dir := t.TempDir()
	scan, err := ScanMirrorDivergenceWiring(dir)
	if err != nil {
		t.Fatalf("обход пустого каталога: %v", err)
	}
	if scan.Files != 0 || scan.Calls != 0 {
		t.Fatalf("пустой каталог дал перепись %d файлов и %d вызовов", scan.Files, scan.Calls)
	}
}

// TestMirrorWiringInjection_TestFileIsOutOfScope — проба вызывающим не является.
//
// Интеграционная проба зовёт читателя и сегодня; засчитать её значило бы
// объявить провязку исполненной ровно в том состоянии, из которого задача и
// заведена.
func TestMirrorWiringInjection_TestFileIsOutOfScope(t *testing.T) {
	dir := t.TempDir()
	body := `package main

import (
	"context"
` + mirrorImportLine + `
)

func boot(ctx context.Context, pool any) {
	_, _, _ = resource_mirror.Divergence(ctx, pool)
}
`
	if err := os.WriteFile(filepath.Join(dir, "boot_test.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	scan, err := ScanMirrorDivergenceWiring(dir)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if scan.Files != 0 || scan.Calls != 0 {
		t.Fatalf("файл проб засчитан: файлов %d, вызовов %d", scan.Files, scan.Calls)
	}
}

// scanSynthetic — обход синтетического дерева из одного не-тестового файла.
func scanSynthetic(t *testing.T, body string) MirrorWiringScan {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "boot.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	scan, err := ScanMirrorDivergenceWiring(dir)
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	if scan.Files != 1 {
		t.Fatalf("разобрано %d файлов, ожидался 1 — синтетика не прочитана", scan.Files)
	}
	return scan
}
