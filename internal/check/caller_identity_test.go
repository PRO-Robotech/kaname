// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func TestCallerIdentityDeclarationsCoverTheTree(t *testing.T) {
	r := callerUnmodifiedTreeReport(t, moduleRoot(t))
	want := check.CallerIdentityRead{RPC: "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/RoleService/Update", Producer: "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext", Site: "(*github.com/PRO-Robotech/corelib/operations.pgRepo).Create"}
	found := false
	for _, read := range r.Reads {
		if read.RPC == want.RPC && read.Producer == want.Producer && read.Site == want.Site {
			found = true
		}
	}
	if !found {
		t.Error("не раскрыта реальная Role.Update → TerminalRefusalRepo.FullRepo → pgRepo.Create")
	}
	for _, rpc := range r.Roots {
		t.Log("ROOT " + rpc)
	}
	for _, read := range r.Reads {
		t.Logf("READ rpc=%s producer=%s site=%s at=%s", read.RPC, read.Producer, read.Site, read.Coordinate)
	}
	for _, pkg := range r.ExternalLeaves {
		t.Log("LEAF transitive-imports-without-identity-api " + pkg)
	}
	for _, position := range r.IdentityFreeBindings {
		t.Log("SOURCE-TARGETS-IDENTITY-FREE " + position)
	}
	for _, finding := range r.Findings {
		t.Error(finding)
	}
}

func TestCallerIdentityDeclarationInventoryIsExact(t *testing.T) {
	root := moduleRoot(t)
	observed := callerRequireLawfulBaseline(t, root)
	base := liveCallerDeclarations()
	for name, declared := range map[string][]check.CallerReadDeclaration{
		"overlap": append(append([]check.CallerReadDeclaration{}, base...), base[0]),
		"stale":   append(append([]check.CallerReadDeclaration{}, base...), check.CallerReadDeclaration{RPC: "absent", Producer: "absent", Site: "absent", Kind: check.CallerObservation, Reason: "Контроль снятого потребителя."}),
	} {
		t.Run(name, func(t *testing.T) {
			findings, err := observed.DeclarationFindingsForTest(declared)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			if name == "stale" {
				want = []string{"устаревшее описание чтения: absent\x00absent\x00absent"}
			} else {
				for _, row := range observed.Reads {
					if row.RPC == base[0].RPC && row.Producer == base[0].Producer && row.Site == base[0].Site {
						want = append(want, row.Coordinate+": пересечение описаний "+row.RPC)
					}
				}
			}
			if len(want) == 0 || !reflect.DeepEqual(findings, want) {
				t.Fatalf("инъекция %s: находки %q, ожидались %q", name, findings, want)
			}
		})
	}
	used := map[string]bool{}
	for _, ids := range callerDeclaredConsumers {
		for _, id := range ids {
			used[id] = true
			if _, ok := callerDeclaredSites[id]; !ok {
				t.Errorf("неизвестный узел %s", id)
			}
		}
	}
	for id := range callerDeclaredSites {
		if !used[id] {
			t.Errorf("описание без потребителя %s", id)
		}
	}
}

// TestCallerIdentityAliasAndSharedHelper — типизированные формы настоящего
// reader. Чужой метод того же обработчика не наследует описание помощника.
func TestCallerIdentityAliasAndSharedHelper(t *testing.T) {
	root := moduleRoot(t)
	callerRequireLawfulBaseline(t, root)
	const pkg = "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	const rpcPrefix = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/"
	const producer = "github.com/PRO-Robotech/kaname/internal/moduleidentity.Roster.FromContext"
	const handler = "(*github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam.Handler)."
	for _, form := range []string{"alias", "helper", "new_consumer", "interface", "embedded_interface", "embedded_interface_benign", "constructor_field", "constructor_field_benign", "constructor_field_uncovered", "nil_factory_embedded", "type_switch", "interface_benign", "interface_external_leaf", "interface_uncovered", "factory", "generic_callback", "callback", "callback_field", "registration_helper", "principal_alias", "certificate", "certificate_domain", "imported_helper", "benign", "unreachable", "unresolved"} {
		t.Run(form, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, "internal/apps/kaname/api/internal_iam"))); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "handler.go")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			extraOverlay := map[string]string{}
			actualProducer := producer
			body := "\n\tread := h.modules.FromContext\n\t_, _ = read(ctx)"
			site := handler + "LookupSubject"
			if form != "alias" {
				body = "\n\th.callerIdentityFixture(ctx)"
				text += "\nfunc (h *Handler) callerIdentityFixture(ctx context.Context) { _, _ = h.modules.FromContext(ctx) }\n"
				site = handler + "callerIdentityFixture"
			}
			switch form {
			case "interface", "interface_benign", "embedded_interface", "embedded_interface_benign", "constructor_field", "constructor_field_benign", "constructor_field_uncovered", "nil_factory_embedded", "type_switch", "factory":
				text += "\ntype callerFixtureReader interface { read(context.Context) }\ntype callerFixtureConcrete struct { h *Handler }\nfunc (c callerFixtureConcrete) read(ctx context.Context) { _, _ = c.h.modules.FromContext(ctx) }\n"
				body = "\n\tvar reader callerFixtureReader = callerFixtureConcrete{h:h}\n\treader.read(ctx)"
				site = "(" + pkg + ".callerFixtureConcrete).read"
				if form == "interface_benign" || form == "embedded_interface_benign" || form == "constructor_field_benign" {
					text += "\ntype callerFixtureBenign struct{}\nfunc(c callerFixtureBenign)read(ctx context.Context){}\n"
					body = "\n\tvar reader callerFixtureReader=callerFixtureBenign{}\n\treader.read(ctx)"
				}
				if form == "embedded_interface" || form == "embedded_interface_benign" {
					text += "\ntype callerFixtureOuter struct{callerFixtureReader}\ntype callerFixtureOuterAgain struct{callerFixtureOuter}\n"
					concrete := "callerFixtureConcrete{h:h}"
					if form == "embedded_interface_benign" {
						concrete = "callerFixtureBenign{}"
					}
					body = "\n\tvar reader callerFixtureReader=callerFixtureOuterAgain{callerFixtureOuter:callerFixtureOuter{callerFixtureReader:" + concrete + "}}\n\treader.read(ctx)"
				}
				if form == "constructor_field" || form == "constructor_field_benign" || form == "constructor_field_uncovered" {
					text += "\ntype callerFixtureBox struct{reader callerFixtureReader}\nfunc callerFixtureUnused(reader callerFixtureReader)*callerFixtureBox{return &callerFixtureBox{reader:reader}}\n"
					concrete := "callerFixtureConcrete{h:h}"
					if form == "constructor_field_benign" {
						concrete = "callerFixtureBenign{}"
					}
					text += "\nfunc callerFixtureBoxNew(h *Handler)*callerFixtureBox{return &callerFixtureBox{reader:" + concrete + "}}\n"
					body = "\n\tbox:=callerFixtureBoxNew(h)\n\tbox.reader.read(ctx)"
					if form == "constructor_field_uncovered" {
						body = "\n\treader,_:=ctx.Value(\"callerIdentityFixture\").(callerFixtureReader)\n\tbox:=callerFixtureUnused(reader)\n\tbox.reader.read(ctx)"
					}
				}
				if form == "nil_factory_embedded" {
					text += "\ntype callerFixtureOuter struct{callerFixtureConcrete}\nfunc callerFixtureOuterNew(h *Handler)*callerFixtureOuter{if h==nil{return nil};return &callerFixtureOuter{callerFixtureConcrete:callerFixtureConcrete{h:h}}}\n"
					body = "\n\treader:=callerFixtureOuterNew(h)\n\treader.read(ctx)"
				}
				if form == "type_switch" {
					body = "\n\tvar boxed any=callerFixtureConcrete{h:h}\n\tswitch reader:=boxed.(type){case callerFixtureReader:reader.read(ctx)}"
				}
				if form == "factory" {
					text += "\nfunc callerFixtureFactory(h *Handler)(callerFixtureReader,error){return callerFixtureConcrete{h:h},nil}\n"
					body = "\n\treader,_:=callerFixtureFactory(h)\n\treader.read(ctx)"
				}
			case "generic_callback":
				text += "\ntype callerFixtureBox[T any]struct{read func(context.Context,T)}\nfunc(c callerFixtureBox[T])run(ctx context.Context,value T){c.read(ctx,value)}\nfunc(h *Handler)callerFixtureGeneric(ctx context.Context,value int){_,_=h.modules.FromContext(ctx)}\n"
				body = "\n\tc:=callerFixtureBox[int]{read:h.callerFixtureGeneric}\n\tc.run(ctx,0)"
				site = handler + "callerFixtureGeneric"
			case "callback":
				text += "\nfunc callerFixtureCallback(ctx context.Context, read func(context.Context)) {read(ctx)}\n"
				body = "\n\tcallerFixtureCallback(ctx,h.callerIdentityFixture)"
			case "callback_field":
				text += "\ntype callerFixtureCallbacks struct { read func(context.Context) }\nfunc (c callerFixtureCallbacks) run(ctx context.Context) {c.read(ctx)}\n"
				body = "\n\tc:=callerFixtureCallbacks{read:h.callerIdentityFixture}\n\tc.run(ctx)"
			case "benign":
				text += "\ntype callerFixtureLogger struct{}\nfunc (callerFixtureLogger) FromContext(ctx context.Context) {}\n"
				body = "\n\tcallerFixtureLogger{}.FromContext(ctx)"
			case "unreachable":
				body = ""
			case "interface_external_leaf":
				body = "\n\tvar reader interface{Error()string}=stderrors.New(\"external leaf\")\n\t_ = reader.Error()"
			case "interface_uncovered":
				text += "\ntype callerFixtureReader interface{read(context.Context)}\ntype callerFixtureConcrete struct{h *Handler}\nfunc(c callerFixtureConcrete)read(ctx context.Context){_,_=c.h.modules.FromContext(ctx)}\n"
				body = "\n\treader,_:=ctx.Value(\"callerIdentityFixture\").(callerFixtureReader)\n\tif reader!=nil {reader.read(ctx)}"
			case "unresolved":
				body = "\n\tmissing,_:=ctx.Value(\"callerIdentityFixture\").(func(context.Context))\n\tif missing!=nil {missing(ctx)}"
			case "principal_alias", "certificate", "certificate_domain":
				importPath := "github.com/PRO-Robotech/corelib/operations"
				statement := "_,_ = identityAlias.PrincipalFromContextOK(ctx)"
				actualProducer = importPath + ".PrincipalFromContextOK"
				if form != "principal_alias" {
					importPath = "github.com/PRO-Robotech/corelib/grpcsrv"
					name := "CertIdentityFromContext"
					if form == "certificate_domain" {
						name = "CertIdentityDomainFromContext"
					}
					actualProducer = importPath + "." + name
					statement = "_,_ = identityAlias." + name + "(ctx)"
					if form == "certificate_domain" {
						statement = "_ = identityAlias." + name + "(ctx)"
					}
				}
				code := "package internal_iam\nimport(\"context\";identityAlias \"" + importPath + "\")\nfunc(h *Handler) callerOtherIdentityFixture(ctx context.Context){" + statement + "}\n"
				if err := os.WriteFile(filepath.Join(dir, "identity_fixture.go"), []byte(code), 0o600); err != nil {
					t.Fatal(err)
				}
				body = "\n\th.callerOtherIdentityFixture(ctx)"
				site = handler + "callerOtherIdentityFixture"
			case "imported_helper":
				other := t.TempDir()
				if err := os.CopyFS(other, os.DirFS(filepath.Join(root, "internal/authzguard"))); err != nil {
					t.Fatal(err)
				}
				code := "package authzguard\nimport(\"context\";identityAlias \"github.com/PRO-Robotech/corelib/operations\")\nfunc CallerIdentityFixture(ctx context.Context){_,_=identityAlias.PrincipalFromContextOK(ctx)}\n"
				if err := os.WriteFile(filepath.Join(other, "identity_fixture.go"), []byte(code), 0o600); err != nil {
					t.Fatal(err)
				}
				extraOverlay["github.com/PRO-Robotech/kaname/internal/authzguard"] = other
				body = "\n\tauthzguard.CallerIdentityFixture(ctx)"
				site = "github.com/PRO-Robotech/kaname/internal/authzguard.CallerIdentityFixture"
				actualProducer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContextOK"
			}
			text = callerInsertMethodBody(t, text, "LookupSubject", body)
			if form == "new_consumer" {
				text = callerInsertMethodBody(t, text, "PollSubjectChanges", "\n\th.callerIdentityFixture(ctx)")
			}
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			overlay := map[string]string{pkg: dir}
			for path, dir := range extraOverlay {
				overlay[path] = dir
			}
			if form == "registration_helper" {
				wrapper := `package internal_iam
import("google.golang.org/grpc"; iam "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1")
func RegisterFixture(srv grpc.ServiceRegistrar,h iam.InternalIAMServiceServer) {iam.RegisterInternalIAMServiceServer(srv,h)}
`
				if err := os.WriteFile(filepath.Join(dir, "registration_fixture.go"), []byte(wrapper), 0o600); err != nil {
					t.Fatal(err)
				}
				cmdDir := t.TempDir()
				if err := os.CopyFS(cmdDir, os.DirFS(filepath.Join(root, "cmd/kaname"))); err != nil {
					t.Fatal(err)
				}
				regPath := filepath.Join(cmdDir, "grpc_register.go")
				reg, err := os.ReadFile(regPath)
				if err != nil {
					t.Fatal(err)
				}
				fset := token.NewFileSet()
				f, err := parser.ParseFile(fset, regPath, reg, 0)
				if err != nil {
					t.Fatal(err)
				}
				var target *ast.SelectorExpr
				ast.Inspect(f, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RegisterInternalIAMServiceServer" {
							if target != nil {
								t.Fatal("фикстура: регистрация неоднозначна")
							}
							target = sel
						}
					}
					return true
				})
				if target == nil {
					t.Fatal("фикстура: регистрация отсутствует")
				}
				start, end := fset.Position(target.Pos()).Offset, fset.Position(target.End()).Offset
				changed := string(reg[:start]) + "registrationfixture.RegisterFixture" + string(reg[end:])
				at := fset.Position(f.Imports[0].Pos()).Offset
				changed = changed[:at] + "registrationfixture \"" + pkg + "\"\n\t" + changed[at:]
				if err := os.WriteFile(regPath, []byte(changed), 0o600); err != nil {
					t.Fatal(err)
				}
				overlay["github.com/PRO-Robotech/kaname/cmd/kaname"] = cmdDir
			}
			declared := append(liveCallerDeclarations(), check.CallerReadDeclaration{RPC: rpcPrefix + "LookupSubject", Producer: actualProducer, Site: site, Kind: check.CallerObservation, Reason: "Экспериментальный reader без изменения ответа существующего RPC."})
			lookupOnly := declared
			if form == "new_consumer" {
				declared = append(declared, check.CallerReadDeclaration{RPC: rpcPrefix + "PollSubjectChanges", Producer: producer, Site: site, Kind: check.CallerObservation, Reason: "Тот же helper имеет отдельного объявленного RPC-потребителя."})
			}
			if form == "benign" || form == "interface_benign" || form == "embedded_interface_benign" || form == "constructor_field_benign" || form == "unreachable" || form == "unresolved" || form == "interface_external_leaf" || form == "interface_uncovered" || form == "constructor_field_uncovered" {
				declared = liveCallerDeclarations()
			}
			ctx, cancel := callerFullTreeTestContext(t)
			defer cancel()
			r, err := check.CallerIdentityFindings(ctx, root, declared, overlay)
			if err != nil {
				t.Fatalf("фикстура НЕ ИСПОЛНИЛАСЬ: %v", err)
			}
			if form == "unresolved" || form == "interface_uncovered" || form == "constructor_field_uncovered" {
				for _, finding := range r.Findings {
					if strings.Contains(finding, "неразрешённый вызов") {
						return
					}
				}
				t.Fatalf("неразрешённый callback ошибочно принят: %v", r.Findings)
			}
			if len(r.Findings) != 0 {
				t.Fatalf("законный %s: %v", form, r.Findings)
			}
			// Меняется только декларация. Полный обход этих же исходников
			// уже собрал фактические чтения и основания для сверки.
			if form == "new_consumer" {
				findings, err := r.DeclarationFindingsForTest(lookupOnly)
				if err != nil || len(findings) != 1 || !strings.Contains(findings[0], rpcPrefix+"PollSubjectChanges") || !strings.Contains(findings[0], "чтение личности без объявления") {
					t.Fatalf("новый потребитель не изолирован: %v %v", err, findings)
				}
			}
			if form != "new_consumer" && form != "benign" && form != "interface_benign" && form != "embedded_interface_benign" && form != "constructor_field_benign" && form != "unreachable" && form != "interface_external_leaf" {
				findings, err := r.DeclarationFindingsForTest(liveCallerDeclarations())
				if err != nil {
					t.Fatal(err)
				}
				if len(findings) != 1 || !strings.Contains(findings[0], rpcPrefix+"LookupSubject") || !strings.Contains(findings[0], "чтение личности без объявления") {
					t.Fatalf("отсутствующее описание %s не изолировано: %v", form, findings)
				}
			}
			if form == "embedded_interface" {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				r, err = check.CallerIdentityFindings(ctx, root, declared, overlay)
				if err != nil || len(r.Findings) != 1 || !strings.Contains(r.Findings[0], "устаревшее описание") {
					t.Fatalf("изменённый источник того же наложения: %v %v", err, r.Findings)
				}
				if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
				r, err = check.CallerIdentityFindings(ctx, root, declared, overlay)
				if err != nil || len(r.Findings) != 0 {
					t.Fatalf("возвращённый источник того же наложения: %v %v", err, r.Findings)
				}
			}
		})
	}
}

func TestCallerIdentityRepeatedBaselineReusesOnlyImmutableAnalysis(t *testing.T) {
	root := moduleRoot(t)
	first := callerJudgeTree(t, root)
	if len(first.Findings) != 0 {
		t.Fatalf("условие измерения не создано: %v", first.Findings)
	}
	second := callerJudgeTree(t, root)
	if !reflect.DeepEqual(first.Roots, second.Roots) || !reflect.DeepEqual(first.Reads, second.Reads) || !reflect.DeepEqual(first.Findings, second.Findings) || !reflect.DeepEqual(first.ExternalLeaves, second.ExternalLeaves) || first.ExcludedExternalCalls != second.ExcludedExternalCalls {
		t.Fatal("повтор изменил конкретное множество RPC/producer/consumer/callsite или отсечения")
	}
	w := second.Work
	if w.GraphBuilds != 0 || w.GraphHits != 1 || w.MayBuilds != 0 || w.MayHits != 1 || w.TypeVisits != 0 {
		t.Fatalf("неизменяемый анализ пересчитан: %+v", w)
	}
	if w.SolveRounds == 0 {
		t.Fatal("повтор не исполнил фактический обход RPC")
	}
	t.Logf("повтор без пересборки MAY, фактический RPC solve исполнен: %+v", w)
}

func callerRequireLawfulBaseline(t *testing.T, root string) check.CallerIdentityReport {
	t.Helper()
	r := callerUnmodifiedTreeReport(t, root)
	if len(r.Findings) != 0 {
		t.Fatalf("пробы НЕ ИСПОЛНИЛИСЬ: законный baseline красный, находок %d: %v", len(r.Findings), r.Findings)
	}
	return r
}

var callerUnmodifiedTrees = struct {
	sync.Mutex
	reports map[string]check.CallerIdentityReport
}{reports: make(map[string]check.CallerIdentityReport)}

// Только исходный checkout. Пробы изменений используют собственные временные
// исходники и заново исполняют обход при каждой физической правке.
func callerUnmodifiedTreeReport(t *testing.T, root string) check.CallerIdentityReport {
	t.Helper()
	callerUnmodifiedTrees.Lock()
	defer callerUnmodifiedTrees.Unlock()
	if report, ok := callerUnmodifiedTrees.reports[root]; ok {
		return report
	}
	report := callerJudgeTree(t, root)
	callerUnmodifiedTrees.reports[root] = report
	return report
}

func TestCallerIdentityBrokenLoadIsNotGreen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := check.CallerIdentityFindings(ctx, t.TempDir(), nil, nil)
	if err == nil {
		t.Fatalf("отсутствующее дерево ошибочно принято: %+v", r)
	}
}

func callerInsertMethodBody(t *testing.T, src, name, body string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, callerHandlerSource, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == name {
			at := fset.Position(fn.Body.Lbrace).Offset + 1
			return src[:at] + body + src[at:]
		}
	}
	t.Fatalf("фикстура: настоящий метод %s отсутствует", name)
	return ""
}
