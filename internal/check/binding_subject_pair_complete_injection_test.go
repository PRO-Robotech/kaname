// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const bindingPairCompletePkg = "internal/repo/kaname/pg"
const bindingPairCompleteFile = "zz_binding_pair_complete_probe.go"

// Фиксируем positive control каждого actual production места. Ни исторический
// зелёный результат, ни общий SetEvidence не заменяют новый structural proof.
func TestBindingSubjectPairCompleteProductionControls(t *testing.T) {
	control, _ := bindingPairCensuses(t)
	places := []struct {
		suffix string
		class  check.BindingPairClass
	}{
		{"invite_preparation.go::inviteBinding", check.BindingPairSingleton},
		{"grant_delegation_revoke_stage.go::grantDelegationRevokeTx.WithdrawGrantDelegation", check.BindingPairGuardedFanout},
		{"role_mutation_stage.go::roleMutationStage.stageBinding", check.BindingPairStagedSet},
		{"group_native_questions.go::var groupNativeCarrierQueries", check.BindingPairCompleteSetSQL},
		{"policy_partition_plan.go::const policyActorSources", check.BindingPairCompleteSetSQL},
		{"policy_partition_plan.go::const policyMutationCarriers", check.BindingPairCompleteSetSQL},
		{"policy_partition_plan.go::const policyOldBindingSubjects", check.BindingPairCompleteSetSQL},
	}
	for _, target := range places {
		place := bindingPairCompletePkg + "/" + target.suffix
		entry, ok := check.BindingSubjectPairLedger[place]
		if !ok || entry.Class != target.class {
			t.Fatalf("нет ожидаемой strict declaration %s (class %s)", place, target.class)
		}
		accesses := control.Places()[place]
		goN, sqlN := 0, 0
		for _, access := range accesses {
			if access.Form == check.BindingPairFormSQL {
				sqlN++
			} else {
				goN++
			}
		}
		if len(accesses) != entry.Go+entry.SQL || goN != entry.Go || sqlN != entry.SQL {
			t.Errorf("actual SOURCE census потерян: %s: Go %d, SQL %d; ожидается Go %d, SQL %d", place, goN, sqlN, entry.Go, entry.SQL)
			continue
		}
		if findings := bindingPairCanonicalVerdict(control, place, entry); len(findings) != 0 {
			t.Errorf("actual SOURCE positive control не доказан: %v", findings)
		}
	}
	for _, suffix := range []string{
		"actor_provenance.go::const producerSourcesCapturedSQL",
		"actor_provenance.go::semanticAuthorityWriteTx.producerSourcesQueryForFact",
		"captured_producer_population.go::const capturedProducerKeySQL",
		"resource_registration_executor.go::executeResourceReceipt",
	} {
		place := bindingPairCompletePkg + "/" + suffix
		if accesses := control.Places()[place]; len(accesses) != 0 {
			t.Errorf("qualified receipt fragment остался неразрешённым: %s: %v", place, accesses)
		}
	}
}

// Копируется фактическая AST declaration, а не сокращённый двойник. Rename
// меняет только имя declaration; все тела/SQL/типы сохраняются. Поэтому набор
// same-count mutation проверяет настоящую форму, на которую выдан proof.
func bindingPairCompleteClone(t *testing.T, root, file, old, name string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(bindingPairCompletePkg), file)
	data, err := os.ReadFile(path) // #nosec G304 -- точный production source fixture
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found ast.Node
	var identifier *ast.Ident
	prefix := ""
	for _, decl := range parsed.Decls {
		switch node := decl.(type) {
		case *ast.FuncDecl:
			if node.Name.Name == old {
				found, identifier = node, node.Name
			}
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if ok && len(value.Names) == 1 && value.Names[0].Name == old {
					found, identifier, prefix = value, value.Names[0], node.Tok.String()+" "
				}
			}
		}
	}
	if found == nil {
		t.Fatalf("actual declaration %s::%s отсутствует", file, old)
	}
	start, end := fset.Position(found.Pos()).Offset, fset.Position(found.End()).Offset
	at := fset.Position(identifier.Pos()).Offset
	return prefix + string(data[start:at]) + name + string(data[at+len(old):end]) + "\n"
}

func bindingPairCompleteMutate(t *testing.T, source, before, after string) string {
	t.Helper()
	if strings.Count(source, before) != 1 {
		t.Fatalf("mutation не создана: %q должно присутствовать ровно один раз", before)
	}
	return strings.Replace(source, before, after, 1)
}

func TestBindingSubjectPairCompleteSameCountInjections(t *testing.T) {
	root := ceremonyModuleRoot(t)
	dir := t.TempDir()
	if err := bindingPairCopy(root, bindingPairCompletePkg, dir); err != nil {
		t.Fatal(err)
	}
	var fixture strings.Builder
	fixture.WriteString(`package pg
import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "slices"
 "strings"
 "time"
 "github.com/PRO-Robotech/kaname/internal/domain"
 "github.com/PRO-Robotech/kaname/internal/granteffect"
 kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
 abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
 "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
 "github.com/jackc/pgx/v5"
)
`)
	type expectation struct {
		name  string
		entry check.BindingPairEntry
		ok    bool
	}
	var expectations []expectation
	add := func(name, body string, class check.BindingPairClass, goN, sqlN int, ok bool) {
		fixture.WriteString(body)
		expectations = append(expectations, expectation{name, check.BindingPairEntry{Go: goN, SQL: sqlN, Class: class, Why: "paired actual SOURCE structural injection"}, ok})
	}
	for _, c := range []struct {
		suffix, before, after string
		ok                    bool
	}{
		{"Control", "", "", true},
		{"NilSet", "Subjects: []domain.Subject{sub}", "Subjects: nil", false},
		{"ForeignMember", "Subjects: []domain.Subject{sub}", "Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: \"other\"}}", false},
	} {
		name := "probePairInvite" + c.suffix
		body := bindingPairCompleteClone(t, root, "invite_preparation.go", "inviteBinding", name)
		if !c.ok {
			body = bindingPairCompleteMutate(t, body, c.before, c.after)
		}
		add(name, body, check.BindingPairSingleton, 2, 0, c.ok)
	}
	for _, c := range []struct {
		suffix, before, after string
		ok                    bool
	}{
		{"Control", "", "", true},
		{"CompactAudit", "ExtraPayload: map[string]any{\"delegation_id\": string(d.ID), \"revocation_reason\": \"delegation_revoked\"},\n\t\t\t}); err != nil {", "ExtraPayload: map[string]any{\"delegation_id\": string(d.ID), \"revocation_reason\": \"delegation_revoked\"}}); err != nil {", true},
		{"Subset", "subjects := b.Subjects", "subjects := b.Subjects[:1]", false},
		{"WrongEmpty", "if len(subjects) == 0", "if len(subjects) <= 1", false},
		{"FirstOnly", "for _, s := range subjects", "for _, s := range subjects[:1]", false},
		{"ForeignBinding", "subjects := b.Subjects", "other := domain.AccessBinding{}\n\t\tsubjects := b.Subjects", false},
		{"FirstSubjectEvent", "abrepo.SubjectChangeEvent{SubjectID: string(s.ID)", "abrepo.SubjectChangeEvent{SubjectID: string(subjects[0].ID)", false},
		{"FirstAuditEvent", "Actor: actor, SubjectType: string(s.Type), SubjectID: string(s.ID)", "Actor: actor, SubjectType: string(s.Type), SubjectID: string(subjects[0].ID)", false},
		{"SwallowedSubjectError", "abrepo.SubjectChangeEvent{SubjectID: string(s.ID), SubjectType: string(s.Type), EventType: \"binding_revoke\", Op: \"binding_delete\"}); err != nil {\n\t\t\t\treturn err", "abrepo.SubjectChangeEvent{SubjectID: string(s.ID), SubjectType: string(s.Type), EventType: \"binding_revoke\", Op: \"binding_delete\"}); err != nil {\n\t\t\t\treturn nil", false},
	} {
		name := "probePairDelegation" + c.suffix
		body := bindingPairCompleteClone(t, root, "grant_delegation_revoke_stage.go", "WithdrawGrantDelegation", name)
		if c.before != "" {
			body = bindingPairCompleteMutate(t, body, c.before, c.after)
		}
		if c.suffix == "ForeignBinding" {
			body = bindingPairCompleteMutate(t, body, "ID: b.SubjectID", "ID: other.SubjectID")
		}
		add("grantDelegationRevokeTx."+name, body, check.BindingPairGuardedFanout, 2, 0, c.ok)
	}
	for _, c := range []struct {
		suffix, before, after string
		ok                    bool
	}{
		{"Control", "", "", true},
		{"WrongBinding", "WHERE binding_id=$1 ORDER BY ordinal,subject_type,subject_id", "WHERE binding_id<>$1 ORDER BY ordinal,subject_type,subject_id", false},
		{"TruncatedQuery", "domain.MaxSubjectsPerBinding+1", "1", false},
		{"DroppedSet", "domain.NormalizeSubjects(subjects, b.SubjectType, b.SubjectID)", "domain.NormalizeSubjects(nil, b.SubjectType, b.SubjectID)", false},
	} {
		name := "probePairStage" + c.suffix
		body := bindingPairCompleteClone(t, root, "role_mutation_stage.go", "stageBinding", name)
		body = strings.ReplaceAll(body, "ab.", "abrepo.")
		if !c.ok {
			body = bindingPairCompleteMutate(t, body, c.before, c.after)
		}
		add("roleMutationStage."+name, body, check.BindingPairStagedSet, 2, 0, c.ok)
	}
	for _, c := range []struct {
		suffix    string
		sql, loop bool
		ok        bool
	}{
		{"Control", false, false, true}, {"WrongJoin", true, false, false}, {"FirstPhase", false, true, false},
	} {
		array := "probePairGroupQueries" + c.suffix
		declaration := bindingPairCompleteClone(t, root, "group_native_questions.go", "groupNativeCarrierQueries", array)
		body := bindingPairCompleteClone(t, root, "group_native_questions.go", "discoverGroupNativeQuestions", "probePairGroup"+c.suffix)
		body = strings.ReplaceAll(body, "groupNativeCarrierQueries", array)
		if c.sql {
			declaration = bindingPairCompleteMutate(t, declaration, "b.id=s.binding_id", "b.id<>s.binding_id")
		}
		if c.loop {
			body = bindingPairCompleteMutate(t, body, "range "+array, "range "+array+"[:1]")
		}
		add("var "+array, declaration+body, check.BindingPairCompleteSetSQL, 0, 2, c.ok)
	}
	for _, c := range []struct {
		original, before, after string
		count                   int
	}{
		{"policyActorSources", "OR EXISTS(SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id AND (s.subject_type", "AND EXISTS(SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id AND (s.subject_type", 4},
		{"policyMutationCarriers", "JOIN carriers b ON b.id=s.binding_id", "JOIN carriers b ON b.id<>s.binding_id", 5},
		{"policyOldBindingSubjects", "FROM kaname.access_binding_subjects WHERE binding_id=$3", "FROM kaname.access_binding_subjects WHERE binding_id<>$3", 7},
	} {
		for _, good := range []bool{true, false} {
			suffix := "Control"
			if !good {
				suffix = "BadSet"
			}
			name := "probePair" + c.original + suffix
			body := bindingPairCompleteClone(t, root, "policy_partition_plan.go", c.original, name)
			if !good {
				body = bindingPairCompleteMutate(t, body, c.before, c.after)
			}
			body += fmt.Sprintf("func(p *policyPlan) %s(ctx context.Context, tx pgx.Tx, args ...any) error { return p.scan(ctx,tx,%s,args...) }\n", name, name)
			add("const "+name, body, check.BindingPairCompleteSetSQL, 0, c.count, good)
		}
	}
	// Те же четыре доступа SQL: полнота зависит и от реального consumer.
	// Ни поглощённый budget error, ни остановка на полной странице не дают proof.
	for _, c := range []struct {
		name, before, after string
		ok                  bool
	}{
		{"Control", "", "", true},
		{"SwallowedBudget", "return errors.Join(err, errPolicyDiscoveryBudget)", "return nil", false},
		{"FullPageExit", "if count < limit", "if count <= limit", false},
	} {
		name := "probePairScan" + c.name
		body := bindingPairCompleteClone(t, root, "policy_partition_plan.go", "policyActorSources", name+"SQL")
		consumer := bindingPairCompleteClone(t, root, "policy_partition_plan.go", "scan", name)
		if !c.ok {
			consumer = bindingPairCompleteMutate(t, consumer, c.before, c.after)
		}
		body += consumer + fmt.Sprintf("func(p *policyPlan) %sUse(ctx context.Context, tx pgx.Tx, args ...any) error { return p.%s(ctx,tx,%sSQL,args...) }\n", name, name, name)
		add("const "+name+"SQL", body, check.BindingPairCompleteSetSQL, 0, 4, c.ok)
	}
	// Один fragment object во всех конечных SQL uses. Неизвестная или смешанная
	// lineage должна остаться доступом пары даже при чужом соседнем alias r.
	type receiptCase struct {
		name, query         string
		bad, mixed, dynamic bool
	}
	receipts := []receiptCase{
		{"Physical", "SELECT %s FROM kaname.producer_source_receipt r", false, false, false},
		{"CTEProjection", "WITH page AS (SELECT r.* FROM kaname.producer_source_receipt r) SELECT %s FROM page r", false, false, false},
		{"Binding", "SELECT %s FROM kaname.access_bindings r", true, false, false},
		{"Shadow", "SELECT %s FROM kaname.producer_source_receipt r WHERE EXISTS(SELECT 1 FROM kaname.access_bindings r)", true, false, false},
		{"ChangedCTE", "WITH page AS (SELECT r.* FROM kaname.access_bindings r) SELECT %s FROM page r", true, false, false},
		{"Materialized", "WITH page AS MATERIALIZED (SELECT r.* FROM kaname.producer_source_receipt r) SELECT %s FROM page r", true, false, false},
		{"Derived", "SELECT %s FROM (SELECT * FROM kaname.producer_source_receipt) r", true, false, false},
		{"Mixed", "SELECT %s FROM kaname.producer_source_receipt r", true, true, false},
		{"Dynamic", "SELECT %s FROM kaname.producer_source_receipt r", true, false, true},
		{"UnknownAlias", "SELECT %s FROM kaname.producer_source_receipt other", true, false, false},
		{"Record", "SELECT %s FROM jsonb_populate_record(NULL::kaname.producer_source_receipt,$1::jsonb) r", false, false, false},
		{"RecordWrongType", "SELECT %s FROM jsonb_populate_record(NULL::kaname.access_bindings,$1::jsonb) r", true, false, false},
		{"RecordWrongFunction", "SELECT %s FROM custom.jsonb_populate_record(NULL::kaname.producer_source_receipt,$1::jsonb) r", true, false, false},
		{"RecordShadow", "SELECT %s FROM jsonb_populate_record(NULL::kaname.producer_source_receipt,$1::jsonb) r WHERE EXISTS(SELECT 1 FROM kaname.access_bindings r)", true, false, false},
	}
	receiptExpressions := []struct{ name, text string }{
		{"Key", "jsonb_build_array(r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id)"},
		{"Subject", "r.subject_type||':'||r.subject_id"},
	}
	for _, fragment := range receiptExpressions {
		for _, c := range receipts {
			name := "probePairReceipt" + fragment.name + c.name
			fmt.Fprintf(&fixture, "const %s = %q\n", name, fragment.text)
			parts := strings.Split(c.query, "%s")
			expression := fmt.Sprintf("%q+%s+%q", parts[0], name, parts[1])
			if c.dynamic {
				expression += "+suffix"
			}
			method := "Query"
			if strings.HasPrefix(c.name, "Record") {
				method = "Exec"
			}
			fmt.Fprintf(&fixture, "func probePairReceiptUse%s%s(ctx context.Context,tx pgx.Tx,suffix string) error { _,err:=tx.%s(ctx,%s);", fragment.name, c.name, method, expression)
			if c.mixed {
				fmt.Fprintf(&fixture, "if err!=nil{return err}; _,err=tx.Query(ctx,\"SELECT \"+%s+\" FROM kaname.access_bindings r\");", name)
			}
			fixture.WriteString("return err}\n")
		}
	}
	// Реальная цепочка из четырёх const и двух typed Query consumers: состояние
	// содержит to_jsonb(r), а ключ повторяется в SELECT/cursor/ORDER BY/EXISTS.
	// Меняется источник лишь одного terminal use — остальные не дают ему waiver.
	captured := []struct {
		suffix, target, before, after string
		bad                           bool
	}{
		{"Control", "", "", "", false},
		{"WrongCaptureSource", "captureProducerPopulationSQL", "FROM kaname.producer_source_receipt r", "FROM kaname.access_bindings r", true},
		{"WrongRereadSource", "rereadCapturedProducerSQL", "FROM kaname.producer_source_receipt r", "FROM kaname.access_bindings r", true},
		{"ShadowRow", "capturedProducerStateSQL", "to_jsonb(r)", "(SELECT to_jsonb(r) FROM kaname.access_bindings r LIMIT 1)", true},
		{"OtherRowFunction", "capturedProducerStateSQL", "to_jsonb(r)", "row_to_json(r)", true},
		{"QualifiedRowFunction", "capturedProducerStateSQL", "to_jsonb(r)", "custom.to_jsonb(r)", true},
		{"DynamicTerminal", "captureProducerPopulation", "tx.Query(ctx, captureProducerPopulationSQL,", "tx.Query(ctx, captureProducerPopulationSQL+cursor,", true},
	}
	for _, c := range captured {
		keyName := "probePairCapturedKey" + c.suffix
		names := []struct{ old, name string }{
			{"capturedProducerKeySQL", keyName},
			{"capturedProducerStateSQL", "probePairCapturedState" + c.suffix},
			{"captureProducerPopulationSQL", "probePairCapturedPopulationSQL" + c.suffix},
			{"rereadCapturedProducerSQL", "probePairCapturedRereadSQL" + c.suffix},
			{"captureProducerPopulation", "probePairCapture" + c.suffix},
			{"rereadCapturedProducerState", "probePairReread" + c.suffix},
		}
		for _, name := range names {
			body := bindingPairCompleteClone(t, root, "captured_producer_population.go", name.old, name.name)
			if name.old == "capturedProducerKeySQL" && strings.Count(body, "r.subject_type")+strings.Count(body, "r.subject_id") != 2 {
				t.Fatal("actual captured key потерял исходные два SQL-доступа")
			}
			if name.old == c.target {
				body = bindingPairCompleteMutate(t, body, c.before, c.after)
			}
			for _, dependency := range names[:4] {
				body = strings.ReplaceAll(body, dependency.old, dependency.name)
			}
			fixture.WriteString(body)
		}
	}
	path := filepath.Join(dir, bindingPairCompleteFile)
	if err := os.WriteFile(path, []byte(fixture.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	census, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{ModuleRoot: root, Overlay: map[string]string{ceremonyModulePath(t, root) + "/" + bindingPairCompletePkg: dir}})
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ на typed injection: %v", err)
	}
	for _, c := range captured {
		place := bindingPairCompletePkg + "/" + bindingPairCompleteFile + "::const probePairCapturedKey" + c.suffix
		accesses := census.Places()[place]
		want := 0
		if c.bad {
			want = 2
		}
		if len(accesses) != want {
			t.Errorf("actual captured lineage %s: accesses=%d, want %d", c.suffix, len(accesses), want)
		}
		findings := check.JudgeBindingSubjectPair(check.BindingPairCensus{Accesses: accesses}, map[string]check.BindingPairEntry{})
		if (!c.bad && len(findings) != 0) || (c.bad && (len(findings) != 1 || !strings.Contains(findings[0], bindingPairCompleteFile+":"))) {
			t.Errorf("actual captured lineage bad=%v не подтверждён с координатой: %s: %v", c.bad, c.suffix, findings)
		}
	}
	for _, fragment := range receiptExpressions {
		for _, c := range receipts {
			place := bindingPairCompletePkg + "/" + bindingPairCompleteFile + "::const probePairReceipt" + fragment.name + c.name
			want := 0
			if c.bad {
				want = 2
			}
			if got := len(census.Places()[place]); got != want {
				t.Errorf("receipt lineage %s/%s: accesses=%d, want %d", fragment.name, c.name, got, want)
			}
			if c.bad {
				findings := check.JudgeBindingSubjectPair(check.BindingPairCensus{Accesses: census.Places()[place]}, map[string]check.BindingPairEntry{})
				if len(findings) != 1 || !strings.Contains(findings[0], bindingPairCompleteFile+":") {
					t.Errorf("unknown receipt lineage не RED с координатой: %s/%s: %v", fragment.name, c.name, findings)
				}
			}
		}
	}
	for _, want := range expectations {
		place := bindingPairCompletePkg + "/" + bindingPairCompleteFile + "::" + want.name
		accesses := census.Places()[place]
		if len(accesses) != want.entry.Go+want.entry.SQL {
			t.Errorf("same-count условие потеряно: %s: %v", place, accesses)
			continue
		}
		findings := bindingPairCanonicalVerdict(census, place, want.entry)
		if (len(findings) == 0) != want.ok {
			t.Errorf("неверный verdict ok=%v %s: %v", want.ok, place, findings)
		}
		if !want.ok && (len(findings) != 1 || !strings.Contains(findings[0], "структурное доказательство") || !strings.Contains(findings[0], bindingPairCompleteFile+":")) {
			t.Errorf("negative не доказан причинной находкой с координатой: %s: %v", place, findings)
		}
		if want.ok && len(check.JudgeBindingSubjectPair(check.BindingPairCensus{Accesses: accesses}, map[string]check.BindingPairEntry{})) != 1 {
			t.Errorf("structural proof молча разрешил unlisted место %s", place)
		}
	}
}
