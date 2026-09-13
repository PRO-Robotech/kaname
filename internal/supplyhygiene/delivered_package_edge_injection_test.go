// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package supplyhygiene

// delivered_package_edge_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт рёбер
// поставки способен упасть и способен смолчать (kaname#48).
//
// Утверждения строятся на СИНТЕТИЧЕСКОМ дереве: «оно сейчас зелёное» доказывает
// состояние дерева, а не свойство проверки. У каждой оси законный близнец — без
// него гейт ловил бы форму, а не существо.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeliveredEdgeInjection_ExternalImportIsNotAnEdge — контроль: чужой импорт
// ребром не является.
func TestDeliveredEdgeInjection_ExternalImportIsNotAnEdge(t *testing.T) {
	scan := scanSyntheticPkg(t, "band", `package band

import (
	"context"

	"google.golang.org/grpc/status"
)

var _ = context.Background
var _ = status.New
`)
	if len(scan.Edges) != 0 {
		t.Fatalf("рёбер %d при чужих импортах: %v", len(scan.Edges), scan.Edges)
	}
	if scan.Imports == 0 {
		t.Fatalf("импортов 0 — разбор не прочитал блок импортов, и молчание сказано ни о чём")
	}
}

// TestDeliveredEdgeInjection_InternalImportIsAnEdge — инъекция: ребро видно.
//
// Одно-фактная: от контроля мир отличается РОВНО одним импортом.
func TestDeliveredEdgeInjection_InternalImportIsAnEdge(t *testing.T) {
	scan := scanSyntheticPkg(t, "band", `package band

import (
	"context"

	"`+ModulePath+`/internal/refusaldomain"
)

var _ = context.Background
var _ = refusaldomain.ProductSuffix
`)
	if len(scan.Edges) != 1 {
		t.Fatalf("рёбер %d, ожидалось 1: %v", len(scan.Edges), scan.Edges)
	}
	if got := scan.Edges[0].To; got != ModulePath+"/internal/refusaldomain" {
		t.Fatalf("ребро ведёт в %q", got)
	}
}

// TestDeliveredEdgeInjection_UndeclaredEdgeIsAFinding — необъявленное ребро есть
// находка, а объявленное — молчание. Обе стороны в одной пробе: порознь каждая
// зеленела бы на ведомости, прощающей всё либо не прощающей ничего.
func TestDeliveredEdgeInjection_UndeclaredEdgeIsAFinding(t *testing.T) {
	edge := DeliveredEdge{From: "band/producer.go", To: ModulePath + "/internal/refusaldomain"}

	if _, ok := EdgeIsDeclared(edge, nil); ok {
		t.Fatal("пустая ведомость объявила ребро — гейт прощает всё")
	}
	declared := []DeclaredEdge{{FromPkg: "band", To: ModulePath + "/internal/refusaldomain"}}
	if _, ok := EdgeIsDeclared(edge, declared); !ok {
		t.Fatal("объявленное ребро не признано — гейт не прощает ничего")
	}
}

// TestDeliveredEdgeInjection_DeclarationCoversThePackageNotTheFile — запись
// покрывает ПАКЕТ.
//
// Иначе разбиение файла на два заводило бы находку на ровном месте, и первый же
// такой срабат гейт выключил бы.
func TestDeliveredEdgeInjection_DeclarationCoversThePackageNotTheFile(t *testing.T) {
	declared := []DeclaredEdge{{FromPkg: "band", To: ModulePath + "/internal/refusaldomain"}}
	second := DeliveredEdge{From: "band/another_file.go", To: ModulePath + "/internal/refusaldomain"}
	if _, ok := EdgeIsDeclared(second, declared); !ok {
		t.Fatal("второй файл того же пакета не покрыт записью — запись судит файл, а не пакет")
	}
	foreign := DeliveredEdge{From: "otherpkg/x.go", To: ModulePath + "/internal/refusaldomain"}
	if _, ok := EdgeIsDeclared(foreign, declared); ok {
		t.Fatal("запись покрыла ЧУЖОЙ пакет — она перестала быть поимённой")
	}
}

// TestDeliveredEdgeInjection_ForeignInternalIsNotOurs — законный близнец: чужой
// `internal/` ребром поставки НЕ является.
//
// Предикат по слову `internal` краснел бы на всякой сторонней библиотеке с таким
// каталогом, и его выключили бы первым.
func TestDeliveredEdgeInjection_ForeignInternalIsNotOurs(t *testing.T) {
	scan := scanSyntheticPkg(t, "band", `package band

import (
	"example.com/vendorlib/internal/codec"
	"github.com/PRO-Robotech/corelib/internal/ids"
)

var _ = codec.X
var _ = ids.Y
`)
	if len(scan.Edges) != 0 {
		t.Fatalf("чужой `internal/` засчитан ребром поставки: %v", scan.Edges)
	}
	if scan.Imports != 2 {
		t.Fatalf("импортов %d, ожидалось 2 — разбор прочитал не тот блок", scan.Imports)
	}
}

// TestDeliveredEdgeInjection_TestFileIsOutOfScope — файл проб поставкой не едет.
func TestDeliveredEdgeInjection_TestFileIsOutOfScope(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "band")
	if err := os.MkdirAll(pkg, 0o750); err != nil {
		t.Fatalf("завести синтетику: %v", err)
	}
	body := `package band

import "` + ModulePath + `/internal/refusaldomain"

var _ = refusaldomain.ProductSuffix
`
	if err := os.WriteFile(filepath.Join(pkg, "band_test.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	scan, err := ScanDeliveredEdges(dir)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if scan.Files != 0 || len(scan.Edges) != 0 {
		t.Fatalf("файл проб засчитан: файлов %d, рёбер %d", scan.Files, len(scan.Edges))
	}
}

// TestDeliveredEdgeInjection_EmptyTreeIsVoidNotGreen — пустой обход не «чисто».
func TestDeliveredEdgeInjection_EmptyTreeIsVoidNotGreen(t *testing.T) {
	scan, err := ScanDeliveredEdges(t.TempDir())
	if err != nil {
		t.Fatalf("обход пустого каталога: %v", err)
	}
	if scan.Files != 0 || scan.Imports != 0 || len(scan.Edges) != 0 {
		t.Fatalf("пустой каталог дал перепись: файлов %d, импортов %d, рёбер %d",
			scan.Files, scan.Imports, len(scan.Edges))
	}
}

// scanSyntheticPkg — обход синтетического `pkg/` из одного пакета.
func scanSyntheticPkg(t *testing.T, pkgName, body string) DeliveredEdgeScan {
	t.Helper()
	dir := t.TempDir()
	pkg := filepath.Join(dir, pkgName)
	if err := os.MkdirAll(pkg, 0o750); err != nil {
		t.Fatalf("завести синтетику: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "producer.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	scan, err := ScanDeliveredEdges(dir)
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	if scan.Files != 1 {
		t.Fatalf("разобрано %d файлов, ожидался 1 — синтетика не прочитана", scan.Files)
	}
	return scan
}
