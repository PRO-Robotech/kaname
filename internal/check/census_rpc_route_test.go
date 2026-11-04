// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestCensusRPCProducerRouteControls(t *testing.T) {
	root, prefix := platformtree.RequireCorpus(t)
	root = filepath.Join(root, filepath.FromSlash(prefix))
	paths, err := treecorpus.UnderWithSuffix(root, ".go")
	require.NoError(t, err)
	corpus := map[string][]byte{}
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		require.NoError(t, err)
		src, err := os.ReadFile(p)
		require.NoError(t, err)
		corpus[filepath.ToSlash(rel)] = src
	}
	_, baselineCount, err := check.CensusRPCProducers(corpus)
	require.NoError(t, err)
	require.Positive(t, baselineCount)
	for _, tc := range []struct{ name, file, old, replacement string }{
		{"сервер не зарегистрирован", "cmd/kaname/grpc_register.go", "iamv1.RegisterInternalIAMServiceServer(srv, svcs.internalIAMHandler)", "iamv1.RegisterDifferentServer(srv, svcs.internalIAMHandler)"},
		{"регистратор не wired", "cmd/kaname/wiring.go", "WithResourceRegistrar(registerResourceUC, regGate)", "WithResourceRegistrar(otherUseCase, regGate)"},
		{"подменён adapter", "cmd/kaname/wiring.go", "kanamepg.NewResourceMirrorEmitter()", "kanamepg.NewOtherEmitter()"},
		{"adapter не зовёт mirror", "internal/repo/kaname/pg/resource_mirror_emitter.go", "resource_mirror.UpsertTx(ctx,", "resource_mirror.Other(ctx,"},
		{"usecase не зовёт adapter", "internal/apps/kaname/api/internal_iam/register_resource.go", "uc.mirror.UpsertTx(ctx,", "uc.other.UpsertTx(ctx,"},
		{"не вызван helper", "internal/apps/kaname/api/internal_iam/register_resource.go", "uc.emit(ctx,", "uc.otherEmit(ctx,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[string][]byte{}
			for p, b := range corpus {
				copy[p] = b
			}
			require.Contains(t, string(copy[tc.file]), tc.old)
			copy[tc.file] = []byte(strings.ReplaceAll(string(copy[tc.file]), tc.old, tc.replacement))
			_, count, err := check.CensusRPCProducers(copy)
			require.NoError(t, err)
			require.Zero(t, count)
		})
	}
	// Синтетический test corpus отделён от рабочих fixtures, production путь тот же.
	for _, tc := range []struct {
		name, body string
		red        bool
	}{
		{"один lexical binding", `client := api.NewInternalIAMServiceClient(conn); client.RegisterResource(ctx,&api.RegisterResourceRequest{})`, false},
		{"shadowed client", `client := fakeClient{}; { client := api.NewInternalIAMServiceClient(conn); _ = client }; client.RegisterResource(ctx,&api.RegisterResourceRequest{})`, true},
		{"unused closure", `client := fakeClient{}; unused := func(){ client := api.NewInternalIAMServiceClient(conn); _ = client }; _ = unused; client.RegisterResource(ctx,&api.RegisterResourceRequest{})`, true},
		{"import alias shadow", `api := fakePackage{}; client := api.NewInternalIAMServiceClient(conn); client.RegisterResource(ctx,&realapi.RegisterResourceRequest{})`, true},
		{"reassignment", `client := api.NewInternalIAMServiceClient(conn); client = fakeClient{}; client.RegisterResource(ctx,&api.RegisterResourceRequest{})`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[string][]byte{}
			for p, b := range corpus {
				if !strings.HasSuffix(p, "_test.go") {
					copy[p] = b
				}
			}
			copy["fixture/control_test.go"] = []byte(`package fixture
import api "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
import realapi "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
func probe(){ ` + tc.body + ` }`)
			_, count, err := check.CensusRPCProducers(copy)
			require.NoError(t, err)
			if tc.red {
				require.Zero(t, count)
			} else {
				require.Equal(t, 1, count)
			}
		})
	}

	for _, name := range []string{"fake same-name client", "only-comment producer"} {
		t.Run(name, func(t *testing.T) {
			copy := map[string][]byte{}
			for p, b := range corpus {
				if p == "cmd/kaname/installation_midrun_fixture_test.go" || p == "cmd/kaname/installation_public_lifecycle_fixture_test.go" {
					s := string(b)
					if name == "fake same-name client" {
						s = strings.ReplaceAll(s, "iamv1.NewInternalIAMServiceClient(conn)", "fake.NewInternalIAMServiceClient(conn)")
					} else {
						lines := strings.Split(s, "\n")
						for i, line := range lines {
							if strings.Contains(line, "_, err = module.RegisterResource(") {
								lines[i] = "// " + line
							}
						}
						s = strings.Join(lines, "\n")
					}
					copy[p] = []byte(s)
				} else {
					copy[p] = b
				}
			}
			_, count, err := check.CensusRPCProducers(copy)
			require.NoError(t, err)
			require.Less(t, count, baselineCount)
		})
	}
}

// Все новые production counterexamples опираются на тот же настоящий source
// route; отдельный client fixture исключает случайное доказательство соседним RPC.
func TestCensusRPCProductionBindingCounterexamples(t *testing.T) {
	root, prefix := platformtree.RequireCorpus(t)
	root = filepath.Join(root, filepath.FromSlash(prefix))
	paths, err := treecorpus.UnderWithSuffix(root, ".go")
	require.NoError(t, err)
	corpus := map[string][]byte{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		rel, err := filepath.Rel(root, p)
		require.NoError(t, err)
		src, err := os.ReadFile(p)
		require.NoError(t, err)
		corpus[filepath.ToSlash(rel)] = src
	}
	corpus["fixture/route_test.go"] = []byte(`package fixture
import rpc "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
func fixture(){client:=rpc.NewInternalIAMServiceClient(conn);client.RegisterResource(ctx,&rpc.RegisterResourceRequest{})}`)
	_, count, err := check.CensusRPCProducers(corpus)
	require.NoError(t, err)
	require.Equal(t, 1, count, "реальная registration/wiring, включая WithMetrics, обязана оставаться доказанной")
	const app = "internal/apps/kaname/api/internal_iam/"
	const wire = "cmd/kaname/wiring.go"
	const handler = app + "handler.go"
	const uc = app + "register_resource.go"
	const adapter = "internal/repo/kaname/pg/resource_mirror_emitter.go"
	negativeCasesExecuted := 0
	for _, tc := range []struct{ name, path, receiver, function, body, old, replacement, appendSource string }{
		{"F03 registration только в decoy", "cmd/kaname/grpc_register.go", "", "registerInternalServices", "", "iamv1.RegisterInternalIAMServiceServer(srv, svcs.internalIAMHandler)", "iamv1.RegisterDifferentServer(srv, svcs.internalIAMHandler)", `func neverCalled(srv grpc.ServiceRegistrar,svcs *services){iamv1.RegisterInternalIAMServiceServer(srv,svcs.internalIAMHandler)}`},
		{"F03 правильный returned handler только в decoy", wire, "", "buildServices", "", "internalIAMHandler:     internalIAMHandler,", "internalIAMHandler: nil,", `func neverBuilt(internalIAMHandler *internaliamapp.Handler)*services{return &services{internalIAMHandler:internalIAMHandler}}`},
		{"F03 returned handler отсутствует", wire, "", "buildServices", "", "internalIAMHandler:     internalIAMHandler,", "", `func neverBuilt(internalIAMHandler *internaliamapp.Handler)*services{return &services{internalIAMHandler:internalIAMHandler}}`},
		{"F03 UC constructor только в decoy", wire, "", "buildServices", "", "internaliamapp.NewRegisterResourceUseCase(", "internaliamapp.NewOtherUseCase(", `func neverConstructed(){registerResourceUC:=internaliamapp.NewRegisterResourceUseCase(nil,kanamepg.NewResourceMirrorEmitter());_=registerResourceUC}`},
		{"F03 shadowed UC binding", wire, "", "buildServices", "", "internalIAMHandler := internaliamapp.NewHandler", `{registerResourceUC:=internaliamapp.NewRegisterResourceUseCase(nil,kanamepg.NewResourceMirrorEmitter());_=registerResourceUC}; internalIAMHandler := internaliamapp.NewHandler`, ""},
		{"F03 handler rewire после chain", wire, "", "buildServices", "", "basicCredentialCells(), basicCredentialOutcomeReader(internalIAMHandler))", "basicCredentialCells(), basicCredentialOutcomeReader(internalIAMHandler)); internalIAMHandler = internalIAMHandler.WithResourceRegistrar(nil,regGate)", ""},
		{"F03 WithMetrics возвращает иной UC", uc, "RegisterResourceUseCase", "WithMetrics", "return &RegisterResourceUseCase{metrics:m}", "", "", ""},
		{"F03 неизвестное UC reassignment", wire, "", "buildServices", "", "registerResourceUC = registerResourceUC.WithMetrics(metricsReg.NewRegisterPostCommitRecorder())", "registerResourceUC = otherResourceUseCase", ""},
		{"F04 adapter constructor иной implementation", adapter, "", "NewResourceMirrorEmitter", "return &OtherResourceMirrorEmitter{}", "*ResourceMirrorEmitter", "service.ResourceMirrorEmitter", `type OtherResourceMirrorEmitter struct{*ResourceMirrorEmitter}`},
		{"F04 правильный UC literal discarded", uc, "", "NewRegisterResourceUseCase", "_ = &RegisterResourceUseCase{mirror:mirror}; return &RegisterResourceUseCase{}", "", "", ""},
		{"F04 mirror parameter overwritten", uc, "", "NewRegisterResourceUseCase", "mirror=nil; return &RegisterResourceUseCase{mirror:mirror}", "", "", ""},
		{"F04 Handler constructor nil", handler, "", "NewHandler", "return nil", "", "", ""},
		{"F04 Handler constructor недоказанный объект", handler, "", "NewHandler", "return newHandlerElsewhere(l,authz)", "", "", ""},
		{"F05 RPC witness в dead closure", handler, "Handler", "RegisterResource", `unused:=func(){h.registrar.Register(ctx,req)};_=unused;return &iamv1.RegisterResourceResponse{},nil`, "", "", ""},
		{"F05 UC helper в dead closure", uc, "RegisterResourceUseCase", "Register", `unused:=func(){uc.emit(ctx,tupleIntent{},service.ResourceMirrorRow{},true)};_=unused;return nil`, "", "", ""},
		{"F05 adapter witness в dead closure", adapter, "ResourceMirrorEmitter", "UpsertTx", `unused:=func(){resource_mirror.UpsertTx(ctx,txAsPgx(tx),resource_mirror.Row{})};_=unused;return false,false,nil`, "", "", ""},
		{"F05 shadowed RPC receiver", handler, "Handler", "RegisterResource", `{h:=fakeHandler{};h.registrar.Register(ctx,req)};return &iamv1.RegisterResourceResponse{},nil`, "", "", ""},
		{"F05 reassigned RPC receiver", handler, "Handler", "RegisterResource", `h=&Handler{};h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", ""},
		{"F05 setter parameter overwritten", handler, "Handler", "WithResourceRegistrar", `registrar=nil;h.registrar=registrar;h.regGate=gate;return h`, "", "", ""},
		{"F05 whole receiver overwrite", uc, "RegisterResourceUseCase", "WithMetrics", `*uc=RegisterResourceUseCase{};uc.metrics=m;return uc`, "", "", ""},
		{"F05 unproved mutating helper", uc, "RegisterResourceUseCase", "WithMetrics", `uc.clearMirror();uc.metrics=m;return uc`, "", "", `func(uc *RegisterResourceUseCase)clearMirror(){uc.mirror=nil}`},
		{"F05 method value скрывает mutation", handler, "Handler", "RegisterResource", `clear:=h.clearRegistrar;clear();h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", `func(h *Handler)clearRegistrar(){h.registrar=nil}`},
		{"F03 observer callback меняет registrar", "cmd/kaname/basic_credential_lane.go", "", "basicCredentialOutcomeReader", `return func() map[metrics.BasicCredentialCell]uint64 {h.WithResourceRegistrar(nil,nil);return nil}`, "", "", ""},
		{"F05 receiver passed to helper", handler, "Handler", "RegisterResource", `clearRegistrar(h);h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", `func clearRegistrar(h *Handler){h.registrar=nil}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[string][]byte{}
			for p, b := range corpus {
				copy[p] = b
			}
			src := string(copy[tc.path])
			src = mutateRouteFunction(t, tc.path, src, tc.receiver, tc.function, func(declaration string) string {
				if tc.body != "" {
					declaration = replaceRouteBody(t, declaration, tc.body)
				}
				if tc.old != "" {
					require.Contains(t, declaration, tc.old)
					declaration = strings.Replace(declaration, tc.old, tc.replacement, 1)
				}
				return declaration
			})
			copy[tc.path] = []byte(src + "\n" + tc.appendSource + "\n")
			_, count, err := check.CensusRPCProducers(copy)
			require.NoError(t, err)
			require.Zero(t, count, "неподдержанная форма не является доказательством production route")
			negativeCasesExecuted++
		})
	}
	require.Equal(t, 24, negativeCasesExecuted, "все прежние24negative controls должны завершиться после positive baseline")
	t.Logf("production negative controls завершено: %d", negativeCasesExecuted)
	t.Run("F05 реальные receiver aliases", func(t *testing.T) {
		copy := map[string][]byte{}
		for p, b := range corpus {
			copy[p] = b
		}
		for _, change := range []struct{ file, typ, fn, old, new string }{{handler, "Handler", "RegisterResource", "h", "boundHandler"}, {uc, "RegisterResourceUseCase", "Register", "uc", "boundUC"}, {adapter, "ResourceMirrorEmitter", "UpsertTx", "e", "boundEmitter"}} {
			copy[change.file] = []byte(mutateRouteFunction(t, change.file, string(copy[change.file]), change.typ, change.fn, func(declaration string) string {
				declaration = strings.Replace(declaration, "("+change.old+" *", "("+change.new+" *", 1)
				return strings.ReplaceAll(declaration, change.old+".", change.new+".")
			}))
		}
		_, count, err := check.CensusRPCProducers(copy)
		require.NoError(t, err)
		require.Equal(t, 1, count)
	})
	// Правильные aliases сохраняют import identity во всех трёх constructors.
	t.Run("F04 правильные production import aliases", func(t *testing.T) {
		copy := map[string][]byte{}
		for p, b := range corpus {
			copy[p] = b
		}
		for _, change := range []struct{ file, old, new string }{{wire, "internaliamapp", "appAlias"}, {"cmd/kaname/grpc_register.go", "iamv1", "rpcAlias"}, {adapter, "resource_mirror", "mirrorAlias"}} {
			src := string(copy[change.file])
			if change.old == "resource_mirror" {
				src = strings.Replace(src, `"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"`, `mirrorAlias "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"`, 1)
			} else {
				src = strings.Replace(src, change.old+` "github.com`, change.new+` "github.com`, 1)
			}
			src = strings.ReplaceAll(src, change.old+".", change.new+".")
			copy[change.file] = []byte(src)
		}
		_, count, err := check.CensusRPCProducers(copy)
		require.NoError(t, err)
		require.Equal(t, 1, count)
	})
}

// Helpers меняют ровно выбранное declaration, а не одноимённый текст в decoy.
func mutateRouteFunction(t *testing.T, path, src, receiver, name string, change func(string) string) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	require.NoError(t, err)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		actual := ""
		if fn.Recv != nil {
			typ := fn.Recv.List[0].Type
			if ptr, ok := typ.(*ast.StarExpr); ok {
				typ = ptr.X
			}
			if id, ok := typ.(*ast.Ident); ok {
				actual = id.Name
			}
		}
		if actual != receiver {
			continue
		}
		start, end := fset.Position(fn.Pos()).Offset, fset.Position(fn.End()).Offset
		return src[:start] + change(src[start:end]) + src[end:]
	}
	t.Fatalf("не найдено declaration %s.%s", receiver, name)
	return ""
}
func replaceRouteBody(t *testing.T, declaration, body string) string {
	t.Helper()
	fset := token.NewFileSet()
	src := "package fixture\n" + declaration
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.SkipObjectResolution)
	require.NoError(t, err)
	fn, ok := file.Decls[0].(*ast.FuncDecl)
	require.True(t, ok)
	require.NotNil(t, fn.Body)
	start, end := fset.Position(fn.Body.Lbrace).Offset-len("package fixture\n"), fset.Position(fn.Body.Rbrace).Offset-len("package fixture\n")
	return declaration[:start+1] + "\n" + body + "\n" + declaration[end:]
}

// R2: результат доказанного nested observer отделён от самого receiver;
// binding observer и скобки проверяются тем же production predicate.
func TestCensusRPCObserverAndParenthesesControls(t *testing.T) {
	root, prefix := platformtree.RequireCorpus(t)
	root = filepath.Join(root, filepath.FromSlash(prefix))
	paths, err := treecorpus.UnderWithSuffix(root, ".go")
	require.NoError(t, err)
	corpus := map[string][]byte{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		rel, err := filepath.Rel(root, p)
		require.NoError(t, err)
		src, err := os.ReadFile(p)
		require.NoError(t, err)
		corpus[filepath.ToSlash(rel)] = src
	}
	corpus["fixture/route_test.go"] = []byte(`package fixture
import rpc "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
func fixture(){client:=rpc.NewInternalIAMServiceClient(conn);client.RegisterResource(ctx,&rpc.RegisterResourceRequest{})}`)
	_, count, err := check.CensusRPCProducers(corpus)
	require.NoError(t, err)
	require.Equal(t, 1, count, "полный production source с реальным nested observer — обязательная premise")
	const wire = "cmd/kaname/wiring.go"
	const handler = "internal/apps/kaname/api/internal_iam/handler.go"
	const observer = "cmd/kaname/basic_credential_lane.go"
	for _, tc := range []struct {
		name, path, receiver, function, body, old, replacement, appendSource string
		green                                                                bool
	}{
		{"R2 nested package observer", wire, "", "buildServices", "", "basicCredentialOutcomeReader(internalIAMHandler)", "(basicCredentialOutcomeReader)((internalIAMHandler))", "", true},
		{"R2 local mutating observer", wire, "", "buildServices", "", "metricsReg.NewBasicCredentialOutcomeCollector(", `basicCredentialOutcomeReader:=func(other *internaliamapp.Handler)func()map[metrics.BasicCredentialCell]uint64{other.WithResourceRegistrar(nil,nil);return nil};metricsReg.NewBasicCredentialOutcomeCollector(`, "", false},
		{"R2 observer function parameter", wire, "", "buildServices", "", "func buildServices(", "func buildServices(basicCredentialOutcomeReader func(*internaliamapp.Handler)func()map[metrics.BasicCredentialCell]uint64, ", "", false},
		{"R2 observer local function value", wire, "", "buildServices", "", "metricsReg.NewBasicCredentialOutcomeCollector(", "basicCredentialOutcomeReader:=unsafeObserver;metricsReg.NewBasicCredentialOutcomeCollector(", "", false},
		{"R2 observer range binding", wire, "", "buildServices", "", "metricsReg.NewBasicCredentialOutcomeCollector(", "for basicCredentialOutcomeReader:=range observers {_=basicCredentialOutcomeReader};metricsReg.NewBasicCredentialOutcomeCollector(", "", false},
		{"R2 direct helper escape", wire, "", "buildServices", "", "metricsReg.NewBasicCredentialOutcomeCollector(", "leakHandler(internalIAMHandler);metricsReg.NewBasicCredentialOutcomeCollector(", `func leakHandler(other *internaliamapp.Handler){other.WithResourceRegistrar(nil,nil)}`, false},
		{"R2 unknown nested helper", wire, "", "buildServices", "", "basicCredentialOutcomeReader(internalIAMHandler)", "unknownNestedObserver(internalIAMHandler)", "", false},
		{"R3 unknown helper receives fluent receiver", wire, "", "buildServices", "", "basicCredentialOutcomeReader(internalIAMHandler)", "unknownNestedObserver(internalIAMHandler.WithLogger(nil))", `func unknownNestedObserver(other *internaliamapp.Handler)func()map[metrics.BasicCredentialCell]uint64{other.WithResourceRegistrar(nil,nil);return nil}`, false},
		{"R3 parenthesized fluent receiver escape", wire, "", "buildServices", "", "basicCredentialOutcomeReader(internalIAMHandler)", "(unknownNestedObserver)((((internalIAMHandler).WithLogger)(nil)))", `func unknownNestedObserver(other *internaliamapp.Handler)func()map[metrics.BasicCredentialCell]uint64{other.WithResourceRegistrar(nil,nil);return nil}`, false},
		{"R3 fluent receiver alias", wire, "", "buildServices", "", "metricsReg.NewBasicCredentialOutcomeCollector(", "escapedHandler := internalIAMHandler.WithLogger(nil); unknownNestedObserver(escapedHandler); metricsReg.NewBasicCredentialOutcomeCollector(", `func unknownNestedObserver(other *internaliamapp.Handler)func()map[metrics.BasicCredentialCell]uint64{other.WithResourceRegistrar(nil,nil);return nil}`, false},
		{"R2 mutating package observer", observer, "", "basicCredentialOutcomeReader", `return func()map[metrics.BasicCredentialCell]uint64{h.WithResourceRegistrar(nil,nil);return nil}`, "", "", "", false},
		{"R2 observer wrong callback shape", observer, "", "basicCredentialOutcomeReader", `unused:=func()map[metrics.BasicCredentialCell]uint64{return h.BasicCredentialOutcomes()};_=unused;return otherCallback`, "", "", "", false},
		{"R2 plain protected field write", handler, "Handler", "RegisterResource", `h.registrar=nil;h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", "", false},
		{"R2 parenthesized protected field write", handler, "Handler", "RegisterResource", `(h.registrar)=nil;h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", "", false},
		{"R2 plain whole receiver write", handler, "Handler", "RegisterResource", `*h=Handler{};h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", "", false},
		{"R2 parenthesized whole receiver write", handler, "Handler", "RegisterResource", `(*h)=Handler{};h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", "", false},
		{"R2 parenthesized mutating receiver call", handler, "Handler", "RegisterResource", `(h).clearRegistrar();h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", `func(h *Handler)clearRegistrar(){(h.registrar)=nil}`, false},
		{"R2 parenthesized mutating method value", handler, "Handler", "RegisterResource", `clear:=((h).clearRegistrar);clear();h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", `func(h *Handler)clearRegistrar(){(*h)=Handler{}}`, false},
		{"R2 parenthesized address escape", handler, "Handler", "RegisterResource", `mutate(&((h).registrar));h.registrar.Register(ctx,req);return &iamv1.RegisterResourceResponse{},nil`, "", "", "", false},
		{"R2 safe parenthesized receiver", handler, "Handler", "RegisterResource", "", "h.registrar.Register(ctx, req)", "((h).registrar.Register)(ctx,req)", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[string][]byte{}
			for p, b := range corpus {
				copy[p] = b
			}
			copy[tc.path] = []byte(mutateRouteFunction(t, tc.path, string(copy[tc.path]), tc.receiver, tc.function, func(declaration string) string {
				if tc.body != "" {
					declaration = replaceRouteBody(t, declaration, tc.body)
				}
				if tc.old != "" {
					require.Contains(t, declaration, tc.old)
					declaration = strings.Replace(declaration, tc.old, tc.replacement, 1)
				}
				return declaration
			}) + "\n" + tc.appendSource + "\n")
			_, count, err := check.CensusRPCProducers(copy)
			require.NoError(t, err)
			if tc.green {
				require.Equal(t, 1, count)
			} else {
				require.Zero(t, count)
			}
		})
	}
}
