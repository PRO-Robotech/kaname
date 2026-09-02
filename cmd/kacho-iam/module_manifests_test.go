// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// module_manifests_test.go — ручка каталога манифестов ЧИТАЕТСЯ на пути старта
// и МЕНЯЕТ его исход (задача #1875).
//
// Объявленная и никем не читаемая ручка есть мёртвый страж: служба поднимается,
// называя себя настроенной. Поэтому утверждается не «поле есть», а «значение
// меняет исход старта» — в обе стороны, и отдельно то, что композиционный корень
// читателя ЗОВЁТ: страж, объявленный и не позванный, мёртв ровно так же.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// captureBoot — логгер, чей вывод можно прочитать: перепись доставки печатается
// ВСЕГДА, и проба обязана уметь это утверждать.
func captureBoot() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func writeDelivery(t *testing.T, docs map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range docs {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("каталог не заведён: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("манифест не записан: %v", err)
		}
	}
	return root
}

func TestBootRefusesWhenDeclaredDeliveryIsEmpty(t *testing.T) {
	logger, buf := captureBoot()
	// Каталог ПУСТ, а не «с посторонним файлом»: посторонний файл в каталоге
	// доставки стал отдельной находкой (задача #1901 — каталог доставки есть
	// закрытый набор), и отказ по нему утверждал бы о другом предмете, чем
	// заголовок этой пробы.
	root := writeDelivery(t, nil)

	err := loadDeliveredManifests(logger, config.ManifestsConfig{Dir: root, Required: true})
	if err == nil {
		t.Fatal("объявленная и пустая доставка пущена в старт — сорванное монтирование " +
			"стало бы неотличимо от «модулей нет»")
	}
	if !strings.Contains(buf.String(), "перепись доставки манифестов модулей") {
		t.Errorf("перепись не напечатана при отказе — «доставка сорвана» неотличимо от "+
			"«каталог прочитан и он пуст»: %s", buf.String())
	}
}

func TestBootPassesOnADeliveredManifestAndSaysWhatArrived(t *testing.T) {
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию выше: без него отказ неотличим от
	// читателя, отвергающего всякий вход.
	logger, buf := captureBoot()
	root := writeDelivery(t, map[string]string{
		"vpc/manifest.yaml": "apiVersion: iam/v1\nmodule: vpc\n",
	})

	if err := loadDeliveredManifests(logger, config.ManifestsConfig{Dir: root, Required: true}); err != nil {
		t.Fatalf("годная доставка отвергнута: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "manifests_read=1") {
		t.Errorf("перепись не называет прочитанного: %s", out)
	}
	if !strings.Contains(out, "vpc") {
		t.Errorf("перепись не называет доставленных модулей — «доставлен один манифест» "+
			"не отличается от «доставлена копия чужого»: %s", out)
	}
}

func TestBootSaysAloudThatDeliveryIsNotDeclared(t *testing.T) {
	// Незаявленная доставка — законное состояние, но МОЛЧАТЬ о ней нельзя: она
	// снаружи неотличима от доставки объявленной и сорванной.
	logger, buf := captureBoot()
	if err := loadDeliveredManifests(logger, config.ManifestsConfig{}); err != nil {
		t.Fatalf("незаявленная доставка отвергнута — стенд, её не объявивший, перестал бы подниматься: %v", err)
	}
	if !strings.Contains(buf.String(), "не объявлена посадкой") {
		t.Errorf("о незаявленной доставке процесс промолчал: %s", buf.String())
	}
}

// TestServeReadsTheManifestsKnobBeforeTheCatalogParityGuard — читатель ПОЗВАН, и
// позван в объявленном порядке.
//
// Своя проба у читателя ничего не говорит о том, зовёт ли его композиционный
// корень; а порядок относительно стража паритета есть часть решения: сорванная
// доставка обязана называться своим именем ДО того, как о расхождении заговорит
// страж, иначе оператор пойдёт чинить не то.
func TestServeReadsTheManifestsKnobBeforeTheCatalogParityGuard(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, 0)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанное есть НАХОДКА", err)
	}

	var loadPos, parityPos token.Pos
	var callsSeen int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callsSeen++
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "loadDeliveredManifests" && !loadPos.IsValid() {
				loadPos = call.Pos()
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == "AssertCatalogParity" && !parityPos.IsValid() {
				parityPos = call.Pos()
			}
		}
		return true
	})

	t.Logf("осмотрено вызовов в serve.go: %d", callsSeen)
	if callsSeen == 0 {
		t.Fatal("обход не нашёл ни одного вызова — вердикт беспредметен")
	}
	if !loadPos.IsValid() {
		t.Fatal("serve.go не зовёт loadDeliveredManifests — ручка manifests.dir объявлена " +
			"и не читается на пути старта: мёртвый страж класса AuthMode")
	}
	if !parityPos.IsValid() {
		t.Fatal("serve.go не зовёт AssertCatalogParity — предпосылка проверки о порядке исчезла, " +
			"и порядок больше нечем судить")
	}
	if loadPos > parityPos {
		t.Errorf("доставка манифестов читается ПОСЛЕ стража паритета (%s против %s) — "+
			"сорванная доставка придёт оператору расхождением каталога, и он пойдёт чинить не то",
			fset.Position(loadPos), fset.Position(parityPos))
	}
}
