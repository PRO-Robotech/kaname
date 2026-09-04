// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// iamctl_test.go — обе стороны по каждому из пяти действий (задача #1036).
//
// # Почему дублёр порта, а не живая служба
//
// Предмет проб — ИНСТРУМЕНТ: разбор вызова, классификация чужого отказа,
// перепись и текст, восстанавливающий следующий шаг. Служба применения — чужой
// предмет со своими пробами; поднимать её здесь значило бы мерить её, а не его.
//
// Дублёр НЕ снисходительнее настоящего: отказы он отдаёт `status.Error` с теми
// же кодами, что приходят по проводу, а ответы — теми же сообщениями контракта.
// Он не выдумывает ни одного поля, которого нет в контракте.
package iamctl

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
)

// --- дублёр порта -----------------------------------------------------------

type stubService struct {
	planResp *iamv1.PlanModuleResponse
	planErr  error
	applyOp  *operationv1.Operation
	applyErr error
	getCat   map[string]*iamv1.ModuleCatalog
	getErr   error
	listResp *iamv1.ListModulesResponse
	listErr  error

	planCalls  []*iamv1.PlanModuleRequest
	applyCalls []*iamv1.ApplyModuleRequest
	getCalls   []string
	listCalls  int
}

func (s *stubService) Plan(_ context.Context, in *iamv1.PlanModuleRequest) (*iamv1.PlanModuleResponse, error) {
	s.planCalls = append(s.planCalls, in)
	if s.planErr != nil {
		return nil, s.planErr
	}
	if s.planResp != nil {
		return s.planResp, nil
	}
	return &iamv1.PlanModuleResponse{Module: in.GetModule(), ExpectedState: "fp-" + in.GetModule(),
		Verdict: iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_APPLY}, nil
}

func (s *stubService) Apply(_ context.Context, in *iamv1.ApplyModuleRequest) (*operationv1.Operation, error) {
	s.applyCalls = append(s.applyCalls, in)
	if s.applyErr != nil {
		return nil, s.applyErr
	}
	return s.applyOp, nil
}

func (s *stubService) Get(_ context.Context, in *iamv1.GetModuleRequest) (*iamv1.ModuleCatalog, error) {
	s.getCalls = append(s.getCalls, in.GetModule())
	if s.getErr != nil {
		return nil, s.getErr
	}
	if c, ok := s.getCat[in.GetModule()]; ok {
		return c, nil
	}
	return nil, status.Errorf(codes.NotFound, "module %s not found", in.GetModule())
}

func (s *stubService) List(_ context.Context, _ *iamv1.ListModulesRequest) (*iamv1.ListModulesResponse, error) {
	s.listCalls++
	if s.listErr != nil {
		return nil, s.listErr
	}
	if s.listResp != nil {
		return s.listResp, nil
	}
	return &iamv1.ListModulesResponse{}, nil
}

// --- оснастка ---------------------------------------------------------------

type runResult struct {
	code   int
	stdout string
	stderr string
}

func (r runResult) both() string { return r.stdout + "\n" + r.stderr }

// exercise зовёт инструмент и снимает ОБА потока по отдельности: перепись идёт
// в вывод, находки — в поток ошибок, и слипание их скрыло бы ровно то различие,
// на котором стоит контракт.
func exercise(t *testing.T, deps Deps, args ...string) runResult {
	t.Helper()
	var out, errBuf strings.Builder
	code := Run(context.Background(), args, &out, &errBuf, deps)
	return runResult{code: code, stdout: out.String(), stderr: errBuf.String()}
}

// depsWith — зависимости, у которых соединение ДАЁТ названный дублёр, а
// локальная проверка падает вызовом: действие, позвавшее не свой порт, обязано
// уронить пробу, а не тихо пройти.
func depsWith(t *testing.T, svc ModuleService) Deps {
	t.Helper()
	return Deps{
		Endpoint: "iam-internal.kacho.svc:9091",
		Connect: func(context.Context) (ModuleService, func() error, error) {
			return svc, func() error { return nil }, nil
		},
		Validate: func(string, io.Writer, io.Writer) int {
			t.Fatalf("действие службы позвало локальную проверку дерева")
			return ExitNotRun
		},
	}
}

func mustContain(t *testing.T, hay, needle, why string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Fatalf("%s: в выводе нет %q\n--- вывод ---\n%s", why, needle, hay)
	}
}

// --- validate ---------------------------------------------------------------

// Положительная сторона: действие зовёт ЕДИНСТВЕННОГО производителя, передаёт
// ему корень и отдаёт его код возврата, НЕ трогая службу.
func TestValidateCallsTheSingleProducerAndNeverDials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantRoot string
		code     int
	}{
		{"корень по умолчанию", []string{"validate"}, ".", ExitOK},
		{"корень назван", []string{"validate", "-root=/tmp/tree"}, "/tmp/tree", ExitOK},
		{"код производителя проходит наружу", []string{"validate"}, ".", ExitFinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotRoot string
			deps := Deps{
				Connect: func(context.Context) (ModuleService, func() error, error) {
					t.Fatalf("validate обязан работать без сети: он позвал соединение")
					return nil, nil, nil
				},
				Validate: func(root string, stdout, stderr io.Writer) int {
					gotRoot = root
					_, _ = io.WriteString(stdout, "перепись: осмотрено файлов 9008\n")
					return tc.code
				},
			}
			got := exercise(t, deps, tc.args...)
			if gotRoot != tc.wantRoot {
				t.Fatalf("корень: получено %q, ожидалось %q", gotRoot, tc.wantRoot)
			}
			if got.code != tc.code {
				t.Fatalf("код: получено %d, ожидалось %d", got.code, tc.code)
			}
			mustContain(t, got.stdout, "перепись:", "вывод производителя обязан доехать до оператора")
		})
	}
}

// Отрицательная сторона: отказ называет ПОЛЕ и правило.
func TestValidateRefusalNamesTheFieldAndTheRule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		needs []string
	}{
		{"пустой корень", []string{"validate", "-root="}, []string{"-root", "пуст"}},
		{"лишний аргумент", []string{"validate", "лишнее"}, []string{"-root", "лишн"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := Deps{
				Connect: func(context.Context) (ModuleService, func() error, error) { return nil, nil, nil },
				Validate: func(string, io.Writer, io.Writer) int {
					t.Fatalf("негодный вызов дошёл до проверки")
					return 0
				},
			}
			got := exercise(t, deps, tc.args...)
			if got.code != ExitNotRun {
				t.Fatalf("код: получено %d, ожидалось %d (проверка НЕ ИСПОЛНЯЛАСЬ)", got.code, ExitNotRun)
			}
			for _, n := range tc.needs {
				mustContain(t, got.stderr, n, "отказ обязан называть поле и правило")
			}
		})
	}
}

// --- plan -------------------------------------------------------------------

func TestPlanPrintsTheCensusAndTheFingerprint(t *testing.T) {
	svc := &stubService{planResp: &iamv1.PlanModuleResponse{
		Module:               "vpc",
		WrittenResourceCount: 7,
		WrittenVerbCount:     31,
		WithdrawnResources:   []string{"addressPool"},
		WithdrawnVerbCount:   2,
		ExpectedState:        "sha256:1c0ffee",
		Verdict:              iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_APPLY,
	}}
	got := exercise(t, depsWith(t, svc), "plan", "vpc")
	if got.code != ExitOK {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitOK, got.both())
	}
	if len(svc.planCalls) != 1 || svc.planCalls[0].GetModule() != "vpc" {
		t.Fatalf("глагол службы позван неверно: %+v", svc.planCalls)
	}
	for _, n := range []string{"vpc", "7", "31", "addressPool", "sha256:1c0ffee"} {
		mustContain(t, got.stdout, n, "план обязан называть последствия ЧИСЛОМ и отпечаток")
	}
	mustContain(t, got.stdout, "iamctl apply", "план обязан назвать следующий шаг оператора")
}

// Вердикт «за якорем» — НАХОДКА, и она называет расхождение и путь починки.
func TestPlanBeyondTheAnchorIsAFindingThatNamesTheRepair(t *testing.T) {
	svc := &stubService{planResp: &iamv1.PlanModuleResponse{
		Module:              "vpc",
		ExpectedState:       "sha256:dead",
		BeyondAnchorExtra:   []string{"vpc/routeTable"},
		BeyondAnchorMissing: []string{"vpc/gateway"},
		Verdict:             iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_BEYOND_ANCHOR,
	}}
	got := exercise(t, depsWith(t, svc), "plan", "vpc")
	if got.code != ExitFinding {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitFinding, got.both())
	}
	for _, n := range []string{"vpc/routeTable", "vpc/gateway"} {
		mustContain(t, got.both(), n, "находка обязана назвать расхождение поимённо")
	}
	mustContain(t, got.both(), "повтор", "отказ обязан сказать, что повтор НЕ поможет")
}

func TestPlanWithoutModuleNamesTheFieldAndTheNextStep(t *testing.T) {
	svc := &stubService{}
	got := exercise(t, depsWith(t, svc), "plan")
	if got.code != ExitNotRun {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
	}
	if len(svc.planCalls) != 0 {
		t.Fatalf("негодный вызов дошёл до службы: %+v", svc.planCalls)
	}
	mustContain(t, got.stderr, "module", "отказ обязан назвать поле")
	mustContain(t, got.stderr, "iamctl export --all", "отказ обязан назвать, чем узнать имена модулей")
}

// --- классификация чужого отказа -------------------------------------------

// Отказ службы разводится ПО ПОЛОСЕ: вердикт о предмете — находка; отсутствие
// вердикта — «не выполнилось». Смешать их значило бы объявить недоступность
// соседа находкой о манифесте.
func TestServiceRefusalsAreSplitByLane(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		code  int
		needs []string
	}{
		{"сосед недоступен", status.Error(codes.Unavailable, "connection refused"),
			ExitNotRun, []string{"iam-internal.kacho.svc:9091", "вердикт"}},
		{"права не выданы", status.Error(codes.PermissionDenied, "no path"),
			ExitNotRun, []string{"system_admin"}},
		{"срок вышел", status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			ExitNotRun, []string{"iam-internal.kacho.svc:9091"}},
		{"поле негодно", status.Error(codes.InvalidArgument, "module: required"),
			ExitFinding, []string{"module: required"}},
		{"состояние не позволяет", status.Error(codes.FailedPrecondition, "delivery declares no manifest for module vpc"),
			ExitFinding, []string{"delivery declares no manifest for module vpc"}},
		{"модуля нет", status.Error(codes.NotFound, "Module vpc not found"),
			ExitFinding, []string{"Module vpc not found"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := exercise(t, depsWith(t, &stubService{planErr: tc.err}), "plan", "vpc")
			if got.code != tc.code {
				t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, tc.code, got.both())
			}
			for _, n := range tc.needs {
				mustContain(t, got.stderr, n, "отказ обязан восстановить следующий шаг")
			}
		})
	}
}

// Соединение не установилось — это «не выполнилось», и адрес назван.
func TestConnectFailureIsNotAVerdict(t *testing.T) {
	deps := Deps{
		Endpoint: "iam-internal.kacho.svc:9091",
		Connect: func(context.Context) (ModuleService, func() error, error) {
			return nil, nil, errors.New("dial tcp: i/o timeout")
		},
		Validate: func(string, io.Writer, io.Writer) int { return ExitOK },
	}
	got := exercise(t, deps, "plan", "vpc")
	if got.code != ExitNotRun {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
	}
	mustContain(t, got.stderr, "iam-internal.kacho.svc:9091", "отказ соединения обязан назвать адрес")
}

// --- apply ------------------------------------------------------------------

func TestApplyRequiresTheFingerprintAndNamesWhereToGetIt(t *testing.T) {
	svc := &stubService{}
	got := exercise(t, depsWith(t, svc), "apply", "vpc")
	if got.code != ExitNotRun {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
	}
	if len(svc.applyCalls) != 0 {
		t.Fatalf("применение без отпечатка дошло до службы: %+v", svc.applyCalls)
	}
	mustContain(t, got.stderr, "-expected-state", "отказ обязан назвать поле")
	mustContain(t, got.stderr, "iamctl plan vpc", "отказ обязан назвать, ЧЕМ получить отпечаток")
}

func TestApplyCarriesTheFingerprintAndPrintsWhatChanged(t *testing.T) {
	resp, err := anypb.New(&iamv1.ApplyModuleResponse{
		Module: "vpc", Changed: true, ModuleWritten: true,
		WrittenResources: 7, WrittenVerbs: 31,
		RetiredResources: 1, RetiredVerbs: 2,
		ResettledRuleRefs: 4, ResettledRoleVerbs: 5,
	})
	if err != nil {
		t.Fatalf("подготовка входа: %v", err)
	}
	svc := &stubService{applyOp: &operationv1.Operation{
		Id: "opr-1", Done: true, Result: &operationv1.Operation_Response{Response: resp},
	}}
	got := exercise(t, depsWith(t, svc), "apply", "vpc", "-expected-state=sha256:1c0ffee")
	if got.code != ExitOK {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitOK, got.both())
	}
	if len(svc.applyCalls) != 1 || svc.applyCalls[0].GetExpectedState() != "sha256:1c0ffee" {
		t.Fatalf("отпечаток не доехал до службы: %+v", svc.applyCalls)
	}
	for _, n := range []string{"7", "31", "1", "2", "4", "5"} {
		mustContain(t, got.stdout, n, "применение обязано назвать сделанное ЧИСЛОМ")
	}
}

// Потолки — ПРИСУТСТВИЕ, а не значение: ноль задан и ноль не задан значат
// разное, и инструмент не вправе схлопнуть их в одно.
func TestApplyCeilingsKeepTheirPresence(t *testing.T) {
	resp, _ := anypb.New(&iamv1.ApplyModuleResponse{Module: "vpc"})
	newOp := func() *operationv1.Operation {
		return &operationv1.Operation{Id: "o", Done: true, Result: &operationv1.Operation_Response{Response: resp}}
	}
	t.Run("не задан — поле отсутствует", func(t *testing.T) {
		svc := &stubService{applyOp: newOp()}
		got := exercise(t, depsWith(t, svc), "apply", "vpc", "-expected-state=fp")
		if len(svc.applyCalls) != 1 {
			t.Fatalf("применение до службы не дошло (вызовов %d)\n%s", len(svc.applyCalls), got.both())
		}
		if svc.applyCalls[0].MaxResettledRuleRefs != nil {
			t.Fatalf("незаданный потолок доехал значением: %v", *svc.applyCalls[0].MaxResettledRuleRefs)
		}
	})
	t.Run("задан нулём — поле присутствует", func(t *testing.T) {
		svc := &stubService{applyOp: newOp()}
		res := exercise(t, depsWith(t, svc), "apply", "vpc", "-expected-state=fp", "-max-resettled-rule-refs=0")
		if len(svc.applyCalls) != 1 {
			t.Fatalf("применение до службы не дошло (вызовов %d)\n%s", len(svc.applyCalls), res.both())
		}
		got := svc.applyCalls[0].MaxResettledRuleRefs
		if got == nil || *got != 0 {
			t.Fatalf("потолок, заданный нулём, потерял присутствие: %v", got)
		}
	})
}

// Операция, пришедшая с ошибкой, — находка, а не успех.
func TestApplyOperationErrorIsAFinding(t *testing.T) {
	svc := &stubService{applyOp: &operationv1.Operation{Id: "opr-1", Done: true,
		Result: &operationv1.Operation_Error{Error: status.New(codes.FailedPrecondition, "state moved since plan").Proto()}}}
	got := exercise(t, depsWith(t, svc), "apply", "vpc", "-expected-state=fp")
	if got.code != ExitFinding {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitFinding, got.both())
	}
	mustContain(t, got.stderr, "state moved since plan", "отказ операции обязан доехать дословно")
	mustContain(t, got.stderr, "iamctl plan vpc", "отказ обязан назвать следующий шаг")
}

// --- export -----------------------------------------------------------------

func catalogOf(module string, res, verbs int) *iamv1.ModuleCatalog {
	c := &iamv1.ModuleCatalog{Module: module}
	for i := 0; i < res; i++ {
		c.Resources = append(c.Resources, &iamv1.ModuleResourceRow{})
	}
	for i := 0; i < verbs; i++ {
		c.Verbs = append(c.Verbs, &iamv1.ModuleVerbRow{})
	}
	return c
}

// Выгрузка НАЗЫВАЕТ свой источник: строки каталога и манифест — разные предметы,
// и «выгружено» без источника читается как то, что читателю удобнее.
func TestExportNamesItsSource(t *testing.T) {
	svc := &stubService{getCat: map[string]*iamv1.ModuleCatalog{"vpc": catalogOf("vpc", 7, 31)}}
	got := exercise(t, depsWith(t, svc), "export", "vpc")
	if got.code != ExitOK {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitOK, got.both())
	}
	mustContain(t, got.stdout, "источник:", "выгрузка обязана назвать источник")
	mustContain(t, got.stdout, "каталог", "источник — строки каталога, прочитанные службой")
}

// Полнота выгрузки: число выгруженных строк сходится с числом, названным
// перечнем, и объём осмотренного печатается.
func TestExportAllReadsEveryListedModuleAndCounts(t *testing.T) {
	svc := &stubService{
		listResp: &iamv1.ListModulesResponse{Modules: []*iamv1.ModuleSummary{
			{Module: "vpc", LiveResourceCount: 7, LiveVerbCount: 31},
			{Module: "storage", LiveResourceCount: 4, LiveVerbCount: 12},
		}},
		getCat: map[string]*iamv1.ModuleCatalog{
			"vpc":     catalogOf("vpc", 7, 31),
			"storage": catalogOf("storage", 4, 12),
		},
	}
	got := exercise(t, depsWith(t, svc), "export", "-all")
	if got.code != ExitOK {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitOK, got.both())
	}
	if len(svc.getCalls) != 2 {
		t.Fatalf("прочитано модулей %d, перечень назвал 2: %v", len(svc.getCalls), svc.getCalls)
	}
	mustContain(t, got.stdout, "перепись:", "выгрузка обязана печатать объём осмотренного")
	for _, n := range []string{"vpc", "storage", "11", "43"} {
		mustContain(t, got.stdout, n, "перепись обязана свести числа выгруженного")
	}
}

// Расхождение перечня и прочитанного — НАХОДКА, а не тихо усечённая выгрузка.
func TestExportAllRefusesWhenTheCensusDisagrees(t *testing.T) {
	svc := &stubService{
		listResp: &iamv1.ListModulesResponse{Modules: []*iamv1.ModuleSummary{
			{Module: "vpc", LiveResourceCount: 7, LiveVerbCount: 31},
		}},
		getCat: map[string]*iamv1.ModuleCatalog{"vpc": catalogOf("vpc", 6, 31)},
	}
	got := exercise(t, depsWith(t, svc), "export", "-all")
	if got.code != ExitFinding {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitFinding, got.both())
	}
	mustContain(t, got.both(), "vpc", "находка обязана назвать модуль, на котором числа разошлись")
}

func TestExportRefusesAnAmbiguousForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"ни модуля, ни --all", []string{"export"}},
		{"и модуль, и --all", []string{"export", "-all", "vpc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &stubService{}
			got := exercise(t, depsWith(t, svc), tc.args...)
			if got.code != ExitNotRun {
				t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
			}
			if svc.listCalls != 0 || len(svc.getCalls) != 0 {
				t.Fatalf("негодный вызов дошёл до службы")
			}
			mustContain(t, got.stderr, "-all", "отказ обязан назвать обе законные формы")
		})
	}
}

// Пустой каталог — VOID, а не успех: «выгружено ноль» обязано быть отличимо от
// «выгружать было нечего».
func TestExportAllOnAnEmptyCatalogIsVoidNotSuccess(t *testing.T) {
	svc := &stubService{listResp: &iamv1.ListModulesResponse{}}
	got := exercise(t, depsWith(t, svc), "export", "-all")
	if got.code != ExitVoid {
		t.Fatalf("код: получено %d, ожидалось %d (VOID)\n%s", got.code, ExitVoid, got.both())
	}
	// Утверждается СУЩЕСТВО фразы, а не её начертание: «НЕ успех» — то, ради
	// чего третий исход отделён от нулевого, и подмена этой проверки на регистр
	// слова сделала бы её проверкой оформления.
	mustContain(t, got.stderr, "НЕ успех", "VOID обязан сказать словами, что это НЕ успех")
	mustContain(t, got.stderr, "НИ ОДНОГО", "VOID обязан назвать, чего именно нет")
}

// --- doctor -----------------------------------------------------------------

// Каждая строка разбора несёт ТРИ части: что неверно · чем проверено · что
// сделать. Мнение («похоже, есть проблема») ответом не является, и структура
// строки — единственное, чем это держится машинно.
func TestDoctorAnswersWithAPredicateNotAnOpinion(t *testing.T) {
	svc := &stubService{
		listResp: &iamv1.ListModulesResponse{Modules: []*iamv1.ModuleSummary{
			{Module: "vpc", LiveResourceCount: 7, LiveVerbCount: 31},
		}},
		planResp: &iamv1.PlanModuleResponse{
			Module: "vpc", ExpectedState: "sha256:dead",
			BeyondAnchorExtra: []string{"vpc/routeTable"},
			Verdict:           iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_BEYOND_ANCHOR,
		},
	}
	got := exercise(t, depsWith(t, svc), "doctor")
	if got.code != ExitFinding {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitFinding, got.both())
	}
	for _, part := range []string{"неверно:", "проверено:", "сделать:"} {
		mustContain(t, got.both(), part, "разбор обязан отвечать предикатом, а не мнением")
	}
	mustContain(t, got.both(), "vpc/routeTable", "разбор обязан назвать предмет поимённо")
}

// Положительная сторона: на сошедшемся каталоге разбор молчит находками, но
// перепись печатает — иначе «ноль находок» неотличимо от «ноль проверенного».
func TestDoctorOnAConvergedCatalogPrintsTheCensus(t *testing.T) {
	svc := &stubService{
		listResp: &iamv1.ListModulesResponse{Modules: []*iamv1.ModuleSummary{
			{Module: "vpc", LiveResourceCount: 7, LiveVerbCount: 31},
			{Module: "storage", LiveResourceCount: 4, LiveVerbCount: 12},
		}},
	}
	got := exercise(t, depsWith(t, svc), "doctor")
	if got.code != ExitOK {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitOK, got.both())
	}
	mustContain(t, got.stdout, "перепись:", "разбор обязан печатать объём осмотренного")
	mustContain(t, got.stdout, "проверок", "перепись обязана назвать число проверок")
	if strings.Contains(got.stderr, "неверно:") {
		t.Fatalf("на сошедшемся каталоге разбор выдал находку:\n%s", got.stderr)
	}
}

// Пустой каталог: разбору нечего проверять — VOID, а не «всё в порядке».
func TestDoctorOnAnEmptyCatalogIsVoid(t *testing.T) {
	got := exercise(t, depsWith(t, &stubService{listResp: &iamv1.ListModulesResponse{}}), "doctor")
	if got.code != ExitVoid {
		t.Fatalf("код: получено %d, ожидалось %d (VOID)\n%s", got.code, ExitVoid, got.both())
	}
}

// --- разбор вызова ----------------------------------------------------------

func TestUnknownAndMissingActionNameTheFive(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"действия нет вовсе", nil},
		{"действие неизвестно", []string{"aply"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := exercise(t, depsWith(t, &stubService{}), tc.args...)
			if got.code != ExitNotRun {
				t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
			}
			for _, a := range []string{"validate", "plan", "apply", "export", "doctor"} {
				mustContain(t, got.stderr, a, "отказ обязан назвать все пять действий")
			}
		})
	}
}

// --- порядок: разбор вызова ДО соединения -----------------------------------

// Негодный вызов отвергается РАЗБОРОМ, а не соединением.
//
// Иначе опечатка оператора приходит к нему сообщением о посадке: «сертификат не
// задан» вместо «имя модуля не названо». Оба утверждения верны, но чинятся в
// разных местах, и первое уводит от второго. Тот же порядок, что у чтения
// списка: сперва форма запроса, потом всё остальное.
//
// Проверяется соединением, которое ПАДАЕТ: пока разбор стоит первым, его отказ
// доезжает до оператора и при мёртвой сети.
func TestCallIsParsedBeforeTheServiceIsDialled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		needs   string
		notWant string
	}{
		{"plan без модуля", []string{"plan"}, "module", "посадка"},
		{"apply без отпечатка", []string{"apply", "vpc"}, "-expected-state", "посадка"},
		{"export без формы", []string{"export"}, "-all", "посадка"},
		{"doctor с лишним именем", []string{"doctor", "vpc"}, "имён не принимает", "посадка"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialled := false
			deps := Deps{
				Endpoint: "iam-internal.kacho.svc:9091",
				Connect: func(context.Context) (ModuleService, func() error, error) {
					dialled = true
					return nil, nil, errors.New("посадка неполна — не заданы: -cert, -key")
				},
				Validate: func(string, io.Writer, io.Writer) int { return ExitOK },
			}
			got := exercise(t, deps, tc.args...)
			if got.code != ExitNotRun {
				t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
			}
			if dialled {
				t.Fatalf("негодный вызов дошёл до соединения — разбор обязан стоять первым\n%s", got.both())
			}
			mustContain(t, got.stderr, tc.needs, "отказ обязан называть предмет ВЫЗОВА")
			if strings.Contains(got.stderr, tc.notWant) {
				t.Fatalf("отказ вызова подменён отказом посадки:\n%s", got.stderr)
			}
		})
	}
}

// Положительный близнец: годный вызов до соединения ДОХОДИТ — иначе проверка
// выше зеленела бы на инструменте, не соединяющемся никогда.
func TestAWellFormedCallDoesReachTheService(t *testing.T) {
	dialled := false
	svc := &stubService{}
	deps := Deps{
		Endpoint: "iam-internal.kacho.svc:9091",
		Connect: func(context.Context) (ModuleService, func() error, error) {
			dialled = true
			return svc, func() error { return nil }, nil
		},
		Validate: func(string, io.Writer, io.Writer) int { return ExitOK },
	}
	got := exercise(t, deps, "plan", "vpc")
	if !dialled {
		t.Fatalf("годный вызов до службы не дошёл\n%s", got.both())
	}
	if got.code != ExitOK {
		t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitOK, got.both())
	}
}

// Отказ соединения не вправе печатать ПУСТОЙ адрес.
//
// «по адресу ␣ не установлено» не восстанавливает следующий шаг: читатель видит
// пропуск там, где ожидает координату, и не узнаёт, что адрес и не задавали.
// Пустое значение обязано означать «не задан» словами.
func TestConnectRefusalNeverPrintsAnEmptyAddress(t *testing.T) {
	failing := func(context.Context) (ModuleService, func() error, error) {
		return nil, nil, errors.New("посадка неполна")
	}

	t.Run("адрес не задан — сказано словами", func(t *testing.T) {
		got := exercise(t, Deps{Endpoint: "", Connect: failing}, "plan", "vpc")
		if got.code != ExitNotRun {
			t.Fatalf("код: получено %d, ожидалось %d\n%s", got.code, ExitNotRun, got.both())
		}
		if strings.Contains(got.stderr, "адресу  ") || strings.Contains(got.stderr, "адрес  ") {
			t.Fatalf("в отказе стоит ПУСТОЙ адрес:\n%s", got.stderr)
		}
		mustContain(t, got.stderr, "-endpoint", "отказ обязан назвать флаг, которым адрес задают")
	})

	// Положительный близнец: заданный адрес в отказе НАЗЫВАЕТСЯ — иначе
	// проверка выше зеленела бы на инструменте, не печатающем адрес никогда.
	t.Run("адрес задан — назван", func(t *testing.T) {
		got := exercise(t, Deps{Endpoint: "iam-internal.kacho.svc:9091", Connect: failing}, "plan", "vpc")
		mustContain(t, got.stderr, "iam-internal.kacho.svc:9091", "заданный адрес обязан быть назван")
	})
}
