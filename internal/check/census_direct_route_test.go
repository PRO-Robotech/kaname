// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"github.com/stretchr/testify/require"
)

func directRouteCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	root, prefix := platformtree.RequireCorpus(t)
	root = filepath.Join(root, filepath.FromSlash(prefix))
	paths, err := treecorpus.UnderWithSuffix(root, ".go")
	require.NoError(t, err)
	corpus := map[string][]byte{}
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		require.NoError(t, err)
		body, err := os.ReadFile(p)
		require.NoError(t, err)
		corpus[filepath.ToSlash(rel)] = body
	}
	return corpus
}

// Близнец использует настоящий production-путь; меняется только вход распознавателя.
func directRouteFixture(corpus map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for p, b := range corpus {
		if !strings.HasSuffix(p, "_test.go") {
			out[p] = b
		}
	}
	out["fixture/world_test.go"] = []byte(`package fixture
import (
 "testing"
 app "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
 pg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
 api "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)
type world struct { reg *app.RegisterResourceUseCase }
func newWorld(t *testing.T) *world {
 w := &world{}
 w.reg = app.NewRegisterResourceUseCase(nil,pg.NewResourceMirrorEmitter(),nil,nil,nil,nil,nil,nil)
 w.seed()
 return w
}
func(w *world) seed() { if err := w.reg.Register(nil,&api.RegisterResourceRequest{}); err != nil { panic(err) } }
func TestWorld(t *testing.T) { w := newWorld(t); _ = w }
func setup() error { return nil }
func setupPair() (int,error) { return 0,nil }
func referencePair(t *testing.T) (int,*testing.T) { return 0,t }
func referenceFirst(t *testing.T) (*testing.T,error) { return t,nil }
`)
	return out
}

func TestCensusDirectProducerRouteControls(t *testing.T) {
	corpus := directRouteCorpus(t)
	producers, count, err := check.CensusDirectProducers(corpus)
	require.NoError(t, err)
	require.Positive(t, count)
	require.True(t, producers["internal/apps/kaname/api/access_binding/publicreadmodule/publicreadmodule_test"], "настоящий newP2 сеет через свой concrete use-case")
	// RPC остаётся отдельным доказательством: direct path не зависит от регистрации сервера.
	fixture := directRouteFixture(corpus)
	producers, count, err = check.CensusDirectProducers(fixture)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, map[string]bool{"fixture/fixture": true}, producers)
	for _, tc := range []struct{ name, old, replacement string }{
		{"чужой constructor", "app.NewRegisterResourceUseCase(", "app.NewOtherUseCase("},
		{"чужой import", "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam", "example.invalid/internal_iam"},
		{"чужой emitter", "pg.NewResourceMirrorEmitter()", "pg.NewOtherEmitter()"},
		{"emitter import подменён", "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg", "example.invalid/pg"},
		{"поле другого типа", "reg *app.RegisterResourceUseCase", "reg *app.OtherUseCase"},
		{"перезапись поля", "w.seed()", "w.reg = nil; w.seed()"},
		{"перезапись world", "w.seed()", "w = &world{}; w.seed()"},
		{"повторное short declaration", "w.seed()", "w := &world{}; w.seed()"},
		{"shadow world во вложенной области", "w.seed()", "{w := &world{}; _ = w}; w.seed()"},
		{"перезапись через указатель", "w.seed()", "*w = world{}; w.seed()"},
		{"alias world", "w.seed()", "other := w; other.reg = nil; w.seed()"},
		{"скрытая запись через dereference", "w.seed()", "(*w).reg = nil; w.seed()"},
		{"method value", "w.seed()", "seed := w.seed; seed()"},
		{"helper возвращает alias world", "func(w *world) seed() {", "func(w *world) seed() *world { return w;"},
		{"рекурсивный helper", "if err := w.reg.Register", "w.seed(); if err := w.reg.Register"},
		{"ранний panic", "w.seed()", `panic("stop"); w.seed()`},
		{"panic перед constructor", "w := &world{}", `panic("stop"); w := &world{}`},
		{"цикл перед constructor", "w := &world{}", "for {}; w := &world{}"},
		{"escape поля", "w.seed()", "change(w.reg); w.seed()"},
		{"escape world", "w.seed()", "change(w); w.seed()"},
		{"теневой alias", "w := &world{}", "app := fakePackage{}; w := &world{}"},
		{"нет вызова producer", "w.reg.Register(nil,", "w.reg.Other(nil,"},
		{"helper не вызван", "w.seed()", "_ = w"},
		{"helper только в ветке", "w.seed()", "if false { w.seed() }"},
		{"helper только в closure", "w.seed()", "unused := func(){ w.seed() }; _ = unused"},
		{"helper только после return", "w.seed()\n return w", "return w; w.seed()"},
		{"Test не вызывает factory", "w := newWorld(t)", "w := &world{}"},
		{"вызов только в мёртвой функции", "func TestWorld(", "func unusedWorld("},
		{"Test только в ветке", "w := newWorld(t); _ = w", "if false { w := newWorld(t); _ = w }"},
		{"Test после return", "w := newWorld(t); _ = w", "return; w := newWorld(t); _ = w"},
		{"Test после условного return", "w := newWorld(t); _ = w", "if true { return }; w := newWorld(t); _ = w"},
		{"Test после Skip", "w := newWorld(t); _ = w", "t.SkipNow(); w := newWorld(t); _ = w"},
		{"Test в closure", "w := newWorld(t); _ = w", "unused := func(){w := newWorld(t); _ = w}; _ = unused"},
		{"теневой factory", "w := newWorld(t)", "newWorld := fakeFactory; w := newWorld(t)"},
		{"не тот возвращённый world", "return w", "return &world{}"},
		{"метод сбрасывает поле", "if err := w.reg.Register", "w.reg=nil; if err := w.reg.Register"},
		{"метод только в строке", "if err := w.reg.Register(nil,&api.RegisterResourceRequest{}); err != nil { panic(err) }", "_ = `w.reg.Register(nil,&api.RegisterResourceRequest{})`"},
		{"метод только в комментарии", "if err := w.reg.Register(nil,&api.RegisterResourceRequest{}); err != nil { panic(err) }", "/* w.reg.Register(nil,&api.RegisterResourceRequest{}) */"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			requireDirectFixture(t, copy)
			source := string(copy["fixture/world_test.go"])
			require.Equal(t, 1, strings.Count(source, tc.old), "одно место мутации")
			copy["fixture/world_test.go"] = []byte(strings.Replace(source, tc.old, tc.replacement, 1))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			require.Zero(t, n)
			require.Empty(t, got)
		})
	}
	t.Run("соседний пакет не даёт producer", func(t *testing.T) {
		copy := directRouteFixture(corpus)
		source := string(copy["fixture/world_test.go"])
		source = strings.Replace(source, "func TestWorld(t *testing.T) { w := newWorld(t); _ = w }", "", 1)
		copy["fixture/world_test.go"] = []byte(source)
		copy["other/world_test.go"] = []byte(`package fixture; import "testing"; func TestWorld(t *testing.T){w:=newWorld(t);_=w}`)
		got, n, err := check.CensusDirectProducers(copy)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Empty(t, got)
	})
	t.Run("пустой корпус", func(t *testing.T) {
		got, n, err := check.CensusDirectProducers(map[string][]byte{})
		require.Error(t, err)
		require.Zero(t, n)
		require.Empty(t, got)
	})
	t.Run("RPC registration не prerequisite direct пути", func(t *testing.T) {
		copy := directRouteFixture(corpus)
		delete(copy, "cmd/kaname/grpc_register.go")
		got, n, err := check.CensusDirectProducers(copy)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.True(t, got["fixture/fixture"])
	})
}

func TestCensusDirectProducerProductionEdges(t *testing.T) {
	corpus := directRouteCorpus(t)
	for _, tc := range []struct{ name, path, old, replacement string }{
		{"use-case не зовёт emitter", "internal/apps/kaname/api/internal_iam/register_resource.go", "uc.mirror.UpsertTx(ctx,", "uc.other.UpsertTx(ctx,"},
		{"Register не зовёт свой helper", "internal/apps/kaname/api/internal_iam/register_resource.go", "uc.emit(ctx,", "uc.otherEmit(ctx,"},
		{"constructor не сохраняет emitter", "internal/apps/kaname/api/internal_iam/register_resource.go", "mirror: mirror,", "mirror: nil,"},
		{"adapter не зовёт нижнего производителя", "internal/repo/kaname/pg/resource_mirror_emitter.go", "resource_mirror.UpsertTx(ctx,", "resource_mirror.Other(ctx,"},
		{"adapter возвращает другую реализацию", "internal/repo/kaname/pg/resource_mirror_emitter.go", "return &ResourceMirrorEmitter{}", "return &OtherEmitter{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			requireDirectFixture(t, copy)
			body := string(copy[tc.path])
			require.Contains(t, body, tc.old)
			copy[tc.path] = []byte(strings.ReplaceAll(body, tc.old, tc.replacement))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			require.Zero(t, n)
			require.Empty(t, got)
		})
	}
	// Законная форма сохраняет identity imports и связи при смене всех локальных имён.
	t.Run("локальные имена не являются allowlist", func(t *testing.T) {
		copy := directRouteFixture(corpus)
		copy["fixture/world_test.go"] = []byte(strings.NewReplacer(
			"app ", "iamapp ", "app.", "iamapp.", "world", "scene", "newWorld", "buildScene",
			" reg ", " registrar ", ".reg ", ".registrar ", ".reg.", ".registrar.",
		).Replace(string(copy["fixture/world_test.go"])))
		got, n, err := check.CensusDirectProducers(copy)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.True(t, got["fixture/fixture"])
	})
	t.Run("RPC не получает разрешение от direct", func(t *testing.T) {
		copy := directRouteFixture(corpus)
		direct, n, err := check.CensusDirectProducers(copy)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.True(t, direct["fixture/fixture"])
		rpc, n, err := check.CensusRPCProducers(copy)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Empty(t, rpc)
	})
}

// Каждый negative начинает с того же admitted lawful input, иначе F1 мог бы
// снова сделать весь набор отрицаний бессодержательным.
func requireDirectFixture(t *testing.T, corpus map[string][]byte) {
	t.Helper()
	got, n, err := check.CensusDirectProducers(corpus)
	require.NoError(t, err)
	require.Equal(t, 1, n, "lawful baseline до одно-фактного изменения")
	require.Equal(t, map[string]bool{"fixture/fixture": true}, got)
}

func TestCensusDirectProducerTerminalBranches(t *testing.T) {
	corpus := directRouteCorpus(t)
	for _, tc := range []struct {
		name, old, replacement string
		admitted               bool
	}{
		{"F1 единственное initial declaration", "w := &world{}", "w := (&world{})", true},
		{"F3 terminal argument перед factory", "w := newWorld(t)", "w := choose(panic(1), newWorld(t))", false},
		{"F3 terminal argument перед Register", "w.reg.Register(nil,", "w.reg.Register(panic(1),", false},
		{"F3 closure argument перед Register", "w.reg.Register(nil,", "w.reg.Register(func(){panic(1)}(),", false},
		{"F3 conditional SkipNow перед factory", "w := newWorld(t)", "if true { t.SkipNow() }; w := newWorld(t)", false},
		{"F3 conditional Fatal перед factory", "w := newWorld(t)", `if true { t.Fatal("stop") }; w := newWorld(t)`, false},
		{"F3 conditional panic перед factory", "w := newWorld(t)", `if true { panic("stop") }; w := newWorld(t)`, false},
		{"F3 conditional FailNow перед factory", "w := newWorld(t)", "if true { t.FailNow() }; w := newWorld(t)", false},
		{"F3 conditional Goexit перед factory", "w := newWorld(t)", "if true { runtime.Goexit() }; w := newWorld(t)", false},
		{"F3 block terminal перед factory", "w := newWorld(t)", "{ t.SkipNow() }; w := newWorld(t)", false},
		{"F3 invoked closure terminal", "w := newWorld(t)", "func(){t.SkipNow()}(); w := newWorld(t)", false},
		{"F3 branch invoked closure", "w := newWorld(t)", "if true {func(){t.SkipNow()}()}; w := newWorld(t)", false},
		{"F3 неизвестный terminal guard", "w := newWorld(t)", "if condition {t.SkipNow()}; w := newWorld(t)", false},
		{"F3 terminal перед constructor", "w := &world{}", `if true {t.Fatalf("stop")}; w := &world{}`, false},
		{"F3 conditional panic перед method", "w.seed()", `if true {panic("stop")}; w.seed()`, false},
		{"F3 conditional panic внутри method", "if err := w.reg.Register", `if true {panic("stop")}; if err := w.reg.Register`, false},
		{"F3 conditional return внутри method", "if err := w.reg.Register", "if true {return}; if err := w.reg.Register", false},
		{"F3 shadow false не делает terminal мёртвым", "w := newWorld(t)", "false := true; if false {t.SkipNow()}; w := newWorld(t)", false},
		{"F3 package false не делает terminal мёртвым", "func TestWorld(t *testing.T) {", "const false = true; func TestWorld(t *testing.T) {if false {t.SkipNow()};", false},
		{"F3 false Skip twin", "w := newWorld(t)", "if false {t.SkipNow()}; w := newWorld(t)", true},
		{"F3 false return twin", "w := newWorld(t)", "if false {return}; w := newWorld(t)", true},
		{"F3 false Fatal twin", "w := newWorld(t)", `if false {t.Fatal("stop")}; w := newWorld(t)`, true},
		{"F3 false panic twin", "w.seed()", `if false {panic("stop")}; w.seed()`, true},
		{"F3 production-shaped error guard", "w := &world{}", `err := setup(); if err != nil {t.Fatalf("setup: %v",err)}; w := &world{}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			requireDirectFixture(t, copy)
			source := string(copy["fixture/world_test.go"])
			require.Equal(t, 1, strings.Count(source, tc.old))
			copy["fixture/world_test.go"] = []byte(strings.Replace(source, tc.old, tc.replacement, 1))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			if tc.admitted {
				require.Equal(t, 1, n)
				require.True(t, got["fixture/fixture"])
			} else {
				require.Zero(t, n)
				require.Empty(t, got)
			}
		})
	}
}

func TestCensusDirectProducerWriteIntent(t *testing.T) {
	corpus := directRouteCorpus(t)
	const file = "internal/apps/kaname/api/internal_iam/register_resource.go"
	for _, tc := range []struct {
		name, method, old, replacement string
		admitted                       bool
	}{
		{"F4 Register delete intent", "Register", "}, true)", "}, false)", false},
		{"F4 Register true binding shadow", "Register", "t, err := validateTuple(in)", "true := false; t, err := validateTuple(in)", false},
		{"F4 Register row не из object", "Register", "ObjectID:        objID,", "ObjectID:        otherID,", false},
		{"F4 emit constant false", "emit", "row, write, hints", "row, false, hints", false},
		{"F4 emit другой аргумент", "emit", "row, write, hints", "row, otherWrite, hints", false},
		{"F4 emit другой row", "emit", "ctx, t, row, write, hints", "ctx, t, otherRow, write, hints", false},
		{"F4 emit write overwrite", "emit", "hints := make", "write = false; hints := make", false},
		{"F4 emit write shadow", "emit", "hints := make", "{write := false; _ = write}; hints := make", false},
		{"F4 emit row overwrite", "emit", "hints := make", "row = service.ResourceMirrorRow{}; hints := make", false},
		{"F4 emit wrong parameter type", "emit", "write bool", "write string", false},
		{"F4 emit shadow retry bound", "emit", "hints := make", "unregisterClosureAttempts := 0; hints := make", false},
		{"F4 Register unconditional return", "Register", "t, err := validateTuple(in)", "return nil; t, err := validateTuple(in)", false},
		{"F4 Register true return", "Register", "t, err := validateTuple(in)", "if true {return nil}; t, err := validateTuple(in)", false},
		{"F4 Register false return twin", "Register", "t, err := validateTuple(in)", "if false {return nil}; t, err := validateTuple(in)", true},
		{"F4 attempt true return", "emitAttempt", "module, err := uc.authorizeIntent", "if write {return}; module, err := uc.authorizeIntent", false},
		{"F4 attempt false return twin", "emitAttempt", "module, err := uc.authorizeIntent", "if !write {return}; module, err := uc.authorizeIntent", true},
		{"F4 emit пустой цикл", "emit", "attempt < unregisterClosureAttempts", "attempt < 0", false},
		{"F4 emit call в dead branch", "emit", "objectType, changed, unchanged, err := uc.emitAttempt(ctx, t, row, write, hints, extra...)", "if false {objectType, changed, unchanged, err := uc.emitAttempt(ctx, t, row, write, hints, extra...)}", false},
		{"F4 attempt write overwrite", "emitAttempt", "module, err := uc.authorizeIntent", "write = false; module, err := uc.authorizeIntent", false},
		{"F4 attempt write shadow", "emitAttempt", "module, err := uc.authorizeIntent", "{write := false; _ = write}; module, err := uc.authorizeIntent", false},
		{"F4 attempt row overwrite", "emitAttempt", "module, err := uc.authorizeIntent", "row = service.ResourceMirrorRow{}; module, err := uc.authorizeIntent", false},
		{"F4 attempt write address escape", "emitAttempt", "module, err := uc.authorizeIntent", "overwrite(&write); module, err := uc.authorizeIntent", false},
		{"F4 attempt row address escape", "emitAttempt", "module, err := uc.authorizeIntent", "overwrite(&row); module, err := uc.authorizeIntent", false},
		{"F4 Upsert opposite branch", "emitAttempt", "changed = true\n\tif write {", "changed = true\n\tif !write {", false},
		{"F4 Upsert dead branch", "emitAttempt", "changed = true\n\tif write {", "changed = true\n\tif false {", false},
		{"F4 Upsert другой row", "emitAttempt", "uc.mirror.UpsertTx(ctx, tx, row)", "uc.mirror.UpsertTx(ctx, tx, otherRow)", false},
		{"F4 Upsert чужая TX", "emitAttempt", "uc.mirror.UpsertTx(ctx, tx, row)", "uc.mirror.UpsertTx(ctx, otherTx, row)", false},
		{"F4 literal true в скобках", "Register", "}, true)", "}, (true))", true},
		{"F4 неизменённые args в скобках", "emit", "row, write, hints", "(row), (write), hints", true},
		{"F4 положительный literal bound", "emit", "attempt < unregisterClosureAttempts", "attempt < 8", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			requireDirectFixture(t, copy)
			copy[file] = []byte(mutateRouteFunction(t, file, string(copy[file]), "RegisterResourceUseCase", tc.method, func(declaration string) string {
				require.Equal(t, 1, strings.Count(declaration, tc.old), "одна целевая позиция production source")
				return strings.Replace(declaration, tc.old, tc.replacement, 1)
			}))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			if tc.admitted {
				require.Equal(t, 1, n)
				require.True(t, got["fixture/fixture"])
			} else {
				require.Zero(t, n)
				require.Empty(t, got)
			}
		})
	}
}

// R3 проверяет не имя err, а свежий результат прямого вызова и его guard.
// Все новые snippets используют допустимые Go bindings и типы.
func TestCensusDirectProducerErrorBinding(t *testing.T) {
	corpus := directRouteCorpus(t)
	actual, count, err := check.CensusDirectProducers(corpus)
	require.NoError(t, err)
	require.Positive(t, count)
	require.True(t, actual["internal/apps/kaname/api/access_binding/publicreadmodule/publicreadmodule_test"])
	for _, tc := range []struct {
		name, old, replacement string
		admitted               bool
	}{
		{"F3R2 testing parameter before factory", "w := newWorld(t)", `if t != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 testing parameter before constructor", "w := &world{}", `if t != nil {t.Fatal("stop")}; w := &world{}`, false},
		{"F3R2 parameter renamed err", "func TestWorld(t *testing.T) { w := newWorld(t); _ = w }", `func TestWorld(err *testing.T) {if err != nil {err.Fatal("stop")}; w := newWorld(err); _ = w}`, false},
		{"F3R2 alias parameter", "w := newWorld(t)", `other := t; if other != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 reference literal", "w := newWorld(t)", `other := &testing.T{}; if other != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 nil nonerror", "w := newWorld(t)", `var other *testing.T; if other != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 local reference result", "w := newWorld(t)", `_, result := referencePair(t); if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 wrong result position", "w := newWorld(t)", `result, _ := referenceFirst(t); if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 dead result declaration", "w := newWorld(t)", `var result error; if false {_, result = setupPair()}; if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 error result reassigned", "w := newWorld(t)", `_, result := setupPair(); result = setup(); if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 result alias", "w := newWorld(t)", `_, original := setupPair(); result := original; if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 result shadow", "w := newWorld(t)", `_, result := setupPair(); {result := t; if result != nil {t.Fatal("stop")}}; _ = result; w := newWorld(t)`, false},
		{"F3R2 nonadjacent result", "w := newWorld(t)", `_, result := setupPair(); _ = 0; if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 shadow function value", "w := newWorld(t)", `setupPair := referencePair; _, result := setupPair(t); if result != nil {t.Fatal("stop")}; w := newWorld(t)`, false},
		{"F3R2 error guard else stops", "w := newWorld(t)", `_, result := setupPair(); if result != nil {t.Fatal("stop")} else {t.SkipNow()}; w := newWorld(t)`, false},
		{"F3R2 shadow builtin error type", "func setupPair() (int,error)", "type error = *testing.T; func setupPair() (int,error)", false},
		{"F3R2 shadow nil binding", "w := newWorld(t)", `nil := error(nil); _, result := setupPair(); if result != nil {t.Fatal(result)}; w := newWorld(t)`, false},
		{"F3R2 direct local error pair", "w := newWorld(t)", `_, result := setupPair(); if result != nil {t.Fatal(result)}; w := newWorld(t)`, true},
		{"F3R2 local error single", "w := newWorld(t)", `result := setup(); if result != nil {t.Fatal(result)}; w := newWorld(t)`, true},
		{"F3R2 local error if init", "w := newWorld(t)", `if _, result := setupPair(); result != nil {t.Fatal(result)}; w := newWorld(t)`, true},
		{"F3R2 local error assigned if init", "w := newWorld(t)", `var result error; if _, result = setupPair(); result != nil {t.Fatal(result)}; w := newWorld(t)`, true},
		{"F3R2 fresh setup before constructor", "w := &world{}", `_, result := setupPair(); if result != nil {t.Fatalf("setup: %v", result)}; w := &world{}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			if tc.name == "F3R2 shadow builtin error type" {
				copy["fixture/world_test.go"] = []byte(strings.Replace(string(copy["fixture/world_test.go"]), "w := newWorld(t)", "_, result := setupPair(); if result != nil {t.Fatal(result)}; w := newWorld(t)", 1))
			}
			requireDirectFixture(t, copy)
			source := string(copy["fixture/world_test.go"])
			require.Equal(t, 1, strings.Count(source, tc.old))
			copy["fixture/world_test.go"] = []byte(strings.Replace(source, tc.old, tc.replacement, 1))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			if tc.admitted {
				require.Equal(t, 1, n)
				require.True(t, got["fixture/fixture"])
			} else {
				require.Zero(t, n)
				require.Empty(t, got)
			}
		})
	}
}

// R3: comparison/continuation proof при единственном поддержанном write=true.
func TestCensusDirectProducerBooleanContinuation(t *testing.T) {
	corpus := directRouteCorpus(t)
	actual, count, err := check.CensusDirectProducers(corpus)
	require.NoError(t, err)
	require.Positive(t, count)
	require.True(t, actual["internal/apps/kaname/api/access_binding/publicreadmodule/publicreadmodule_test"])
	const file = "internal/apps/kaname/api/internal_iam/register_resource.go"
	for _, tc := range []struct {
		name, prefix string
		admitted     bool
	}{
		{"F4R2 true comparison return", "if write == true {return};", false},
		{"F4R2 fixed value self comparison", "if write == write {return};", false},
		{"F4R2 unknown value self comparison", "if ctx == ctx {return};", false},
		{"F4R2 constant comparison", "if 1 == 1 {return};", false},
		{"F4R2 alias bool conversion", "aliasWrite := write; if bool(aliasWrite) {return};", false},
		{"F4R2 self inequality false twin", "if write != write {return};", true},
		{"F4R2 reversed comparison return", "if true == write {return};", false},
		{"F4R2 inequality return", "if write != false {return};", false},
		{"F4R2 negated comparison return", "if !(write != true) {return};", false},
		{"F4R2 conjunction return", "if write && true {return};", false},
		{"F4R2 disjunction return", "if write || false {return};", false},
		{"F4R2 nested comparison return", "if (write == true) == true {return};", false},
		{"F4R2 both comparison branches return", "if write == true {return} else {return};", false},
		{"F4R2 both unknown branches return", "if ctx.Err() != nil {return} else {return};", false},
		{"F4R2 both nested unknown branches return", "if ctx.Err() != nil {if write {return}} else {return};", false},
		{"F4R2 unknown fixed-write expression", "if write == (len([]int{}) == 0) {return};", false},
		{"F4R2 opaque closure condition", "if func(value bool) bool {return value}(write) {return};", false},
		{"F4R2 bool alias return", "aliasWrite := write; if aliasWrite {return};", false},
		{"F4R2 bool alias comparison return", "aliasWrite := write; if aliasWrite != false {return};", false},
		{"F4R2 unsupported loop branch", "if ctx.Err() != nil {for {}};", false},
		{"F4R2 false comparison twin", "if write == false {return};", true},
		{"F4R2 false inequality twin", "if write != true {return};", true},
		{"F4R2 false conjunction twin", "if !write && true {return};", true},
		{"F4R2 false literal conjunction twin", "if write && false {return};", true},
		{"F4R2 error return twin", "if setupErr := ctx.Err(); setupErr != nil {return};", true},
		{"F4R2 else continuation twin", "if ctx.Err() != nil {return} else {_ = 0};", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			requireDirectFixture(t, copy)
			copy[file] = []byte(mutateRouteFunction(t, file, string(copy[file]), "RegisterResourceUseCase", "emitAttempt", func(declaration string) string {
				const target = "module, err := uc.authorizeIntent"
				require.Equal(t, 1, strings.Count(declaration, target))
				return strings.Replace(declaration, target, tc.prefix+target, 1)
			}))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			if tc.admitted {
				require.Equal(t, 1, n)
				require.True(t, got["fixture/fixture"])
			} else {
				require.Zero(t, n)
				require.Empty(t, got)
			}
		})
	}
}

// Безопасность вычисления условия проверяется раньше bool folding. Closure
// здесь намеренно не поддержана даже на short-circuited стороне выражения.
func TestCensusDirectProducerConditionEvaluation(t *testing.T) {
	corpus := directRouteCorpus(t)
	actual, count, err := check.CensusDirectProducers(corpus)
	require.NoError(t, err)
	require.Positive(t, count)
	require.True(t, actual["internal/apps/kaname/api/access_binding/publicreadmodule/publicreadmodule_test"])
	const file = "internal/apps/kaname/api/internal_iam/register_resource.go"
	for _, tc := range []struct {
		name, condition string
		admitted        bool
	}{
		{"F4R3 executed left panic and false", `func() bool {panic("stop")}() && false`, false},
		{"F4R3 executed left panic or true", `func() bool {panic("stop")}() || true`, false},
		{"F4R3 executed right panic after true", `true && func() bool {panic("stop")}()`, false},
		{"F4R3 executed right panic after false", `false || func() bool {panic("stop")}()`, false},
		{"F4R3 executed left panic and write", `func() bool {panic("stop")}() && write`, false},
		{"F4R3 executed right panic after write", `write && func() bool {panic("stop")}()`, false},
		{"F4R3 unknown left and right panic", `ctx.Err() != nil && func() bool {panic("stop")}()`, false},
		{"F4R3 unknown left or right panic", `ctx.Err() != nil || func() bool {panic("stop")}()`, false},
		{"F4R3 nested absorbing condition", `(func() bool {panic("stop")}() && false) == false`, false},
		{"F4R3 negated absorbing condition", `!(func() bool {panic("stop")}() || true)`, false},
		{"F4R3 conservative unreachable right and", `false && func() bool {panic("stop")}()`, false},
		{"F4R3 conservative unreachable right or", `true || func() bool {panic("stop")}()`, false},
		{"F4R3 conservative unreachable right write", `write || func() bool {panic("stop")}()`, false},
		{"F4R3 conservative nonterminal left closure", `func() bool {return true}() && false`, false},
		{"F4R3 conservative nonterminal right closure", `true && func() bool {return true}()`, false},
		{"F4R3 conservative unused closure argument", `fmt.Sprint(func(){panic("stop")}) != "" && false`, false},
		{"F4R3 conservative terminal method in closure", `func() bool {var stop interface{SkipNow()}; stop.SkipNow(); return false}() && false`, false},
		{"F4R3 terminal selector before absorbing false", `interface{Fatal() bool}(nil).Fatal() && false`, false},
		{"F4R3 terminal selector before absorbing true", `interface{SkipNow() bool}(nil).SkipNow() || true`, false},
		{"F4R3 conservative unreachable terminal selector", `false && interface{Fatal() bool}(nil).Fatal()`, false},
		{"F4R3 pure literal and twin", "true && false", true},
		{"F4R3 pure literal or twin", "false || true", true},
		{"F4R3 pure write and twin", "write && false", true},
		{"F4R3 pure write or twin", "write || true", true},
		{"F4R3 pure comparison twin", "(write == true) && !false", true},
		{"F4R3 supported dynamic left and twin", "ctx.Err() != nil && false", true},
		{"F4R3 supported dynamic left or twin", "ctx.Err() != nil || true", true},
		{"F4R3 supported dynamic right and twin", "false && (ctx.Err() != nil)", true},
		{"F4R3 supported dynamic right or twin", "true || (ctx.Err() != nil)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := directRouteFixture(corpus)
			requireDirectFixture(t, copy)
			copy[file] = []byte(mutateRouteFunction(t, file, string(copy[file]), "RegisterResourceUseCase", "emitAttempt", func(declaration string) string {
				const target = "module, err := uc.authorizeIntent"
				require.Equal(t, 1, strings.Count(declaration, target))
				// Тело не останавливает путь: отрицание относится именно к Cond.
				return strings.Replace(declaration, target, "if "+tc.condition+" {_ = 0};"+target, 1)
			}))
			got, n, err := check.CensusDirectProducers(copy)
			require.NoError(t, err)
			if tc.admitted {
				require.Equal(t, 1, n)
				require.True(t, got["fixture/fixture"])
			} else {
				require.Zero(t, n)
				require.Empty(t, got)
			}
		})
	}
}
