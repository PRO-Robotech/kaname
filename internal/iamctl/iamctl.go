// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Пакет iamctl — инструмент оператора над каталогом прав модуля: пять действий,
// не двенадцать (задача #1036).
//
//	validate  форма манифестов дерева — без базы и сети, годится в pre-commit
//	plan      что применение СДЕЛАЛО БЫ: последствия числом плюс отпечаток
//	apply     применение под подтверждаемый отпечаток
//	export    действующий каталог, с НАЗВАННЫМ источником
//	doctor    разбор состояния предикатом, а не мнением
//
// # Инструмент — КЛИЕНТ платформы, а не её часть
//
// Ни одно действие не повторяет логику, у которой уже есть производитель:
//
//	validate → services/iam/internal/manifestcheckrun (тот же исполнитель, что
//	           у сборочной цели module-manifest-check)
//	plan     → InternalModuleService/Plan
//	apply    → InternalModuleService/Apply
//	export   → InternalModuleService/List + /Get
//	doctor   → композиция List и Plan; своей проверки не заводит
//
// В базу инструмент не ходит и решений службы не воспроизводит: план и
// применение — её глаголы. Вторая реализация любого из них разошлась бы со
// службой молча и выдавала бы разрешение, которого служба не подтвердит.
//
// # Исходов ЧЕТЫРЕ, и третий не вычитается из вердикта
//
//	0  годно
//	1  находка — вердикт о предмете получен, и он отрицательный
//	2  VOID    — предмета нет: проверять и выгружать нечего
//	3  НЕ ИСПОЛНЯЛОСЬ — вердикта не получено вовсе
//
// Разведение находки и «не выполнилось» здесь несущее: недоступность службы,
// невыданное право и устаревший образ — НЕ вердикты о манифесте, и объявить их
// находкой значило бы приписать дереву чужое состояние. Полосу выбирает
// classifyRefusal, и правило у неё одно: получен ли вердикт О ПРЕДМЕТЕ.
//
// # Всякий отказ называет СЛЕДУЮЩИЙ ШАГ
//
// Связывающее требование продукта: отказ, не восстанавливающий следующий шаг
// клиента, — находка. Поэтому у каждого отказа здесь есть строка «что сделать»,
// и она называет команду либо место починки, а не «обратитесь к администратору».
package iamctl

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifestcheckrun"
)

// Коды возврата. Смысл каждого — в комментарии пакета.
const (
	ExitOK      = 0
	ExitFinding = 1
	ExitVoid    = 2
	ExitNotRun  = 3
)

// actionNames — пять действий в порядке, в котором их называет отказ разбора.
// Перечень ОДИН: второй, выписанный в тексте отказа, разошёлся бы с ветвлением.
var actionNames = []string{"validate", "plan", "apply", "export", "doctor"}

// ModuleService — порт службы применения. Ровно четыре её глагола и ни одного
// своего: инструмент вправе звать службу, но не вправе решать за неё.
//
// Реализация — сгенерированный gRPC-клиент (её вносит композиционный корень);
// в пробах — дублёр, отдающий те же коды и те же сообщения контракта.
type ModuleService interface {
	Plan(ctx context.Context, in *iamv1.PlanModuleRequest) (*iamv1.PlanModuleResponse, error)
	Apply(ctx context.Context, in *iamv1.ApplyModuleRequest) (*operationv1.Operation, error)
	Get(ctx context.Context, in *iamv1.GetModuleRequest) (*iamv1.ModuleCatalog, error)
	List(ctx context.Context, in *iamv1.ListModulesRequest) (*iamv1.ListModulesResponse, error)
}

// Deps — что вносит композиционный корень.
type Deps struct {
	// Connect — соединение со службой. Зовётся ТОЛЬКО теми действиями, которым
	// служба нужна: validate обязан работать там, где сети нет вовсе.
	Connect func(ctx context.Context) (ModuleService, func() error, error)

	// Validate — локальная проверка дерева. Порт, а не прямой вызов: проба
	// инструмента не должна обходить дерево, чтобы судить разбор аргументов.
	// Единственный производитель — manifestcheckrun.Run.
	Validate func(root string, stdout, stderr io.Writer) int

	// Endpoint — адрес службы. Называется в отказах соединения: «сосед не
	// ответил» без адреса не восстанавливает следующий шаг.
	Endpoint string
}

// Run — точка входа инструмента.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, deps Deps) int {
	if len(args) == 0 {
		return refuseCall(stderr, "действие не названо")
	}
	action, rest := args[0], args[1:]
	switch action {
	case "validate":
		return runValidate(rest, stdout, stderr, deps)
	case "plan":
		return runPlan(ctx, rest, stdout, stderr, deps)
	case "apply":
		return runApply(ctx, rest, stdout, stderr, deps)
	case "export":
		return runExport(ctx, rest, stdout, stderr, deps)
	case "doctor":
		return runDoctor(ctx, rest, stdout, stderr, deps)
	default:
		return refuseCall(stderr, fmt.Sprintf("действие %q неизвестно", action))
	}
}

// refuseCall — отказ разбора вызова: вердикта не получено, поэтому ExitNotRun,
// а не находка. Перечень действий печатается из единственного источника.
func refuseCall(stderr io.Writer, reason string) int {
	_, _ = fmt.Fprintf(stderr, "вызов НЕ ИСПОЛНЕН: %s\n", reason)
	_, _ = fmt.Fprintf(stderr, "что сделать: назовите одно из пяти действий — %s\n",
		strings.Join(actionNames, " · "))
	_, _ = fmt.Fprintln(stderr, "  iamctl validate [-root=КАТАЛОГ]")
	_, _ = fmt.Fprintln(stderr, "  iamctl plan МОДУЛЬ")
	_, _ = fmt.Fprintln(stderr, "  iamctl apply МОДУЛЬ -expected-state=ОТПЕЧАТОК")
	_, _ = fmt.Fprintln(stderr, "  iamctl export {МОДУЛЬ | -all}")
	_, _ = fmt.Fprintln(stderr, "  iamctl doctor")
	return ExitNotRun
}

// withService соединяется со службой и закрывает соединение за собой.
//
// Зовётся ПОСЛЕ разбора вызова, и это не стиль. Опечатка оператора, пришедшая к
// нему отказом посадки («сертификат не задан» вместо «имя модуля не названо»),
// уводит его чинить не то место: оба утверждения верны, а чинятся в разных.
// Тот же порядок, что у чтения списка: форма запроса судится до всего, что
// зависит от состояния снаружи.
//
// Отказ соединения — «не выполнилось», а не находка: вердикта о каталоге
// получено не было. Адрес называется в самом отказе — без него читателю некуда
// идти, а оболочка конвейера снимает поток ошибок отдельной строкой.
func withService(ctx context.Context, stderr io.Writer, deps Deps, fn func(ModuleService) int) int {
	if deps.Connect == nil {
		_, _ = fmt.Fprintln(stderr, "вызов НЕ ИСПОЛНЕН: соединение со службой не внесено")
		return ExitNotRun
	}
	svc, closeFn, err := deps.Connect(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: соединение со службой iam %s не установлено: %v\n",
			addressPhrase(deps.Endpoint), err)
		if deps.Endpoint == "" {
			_, _ = fmt.Fprintln(stderr, "что сделать: назовите адрес внутреннего слушателя iam флагом "+
				"-endpoint (либо переменной KACHO_IAMCTL_ENDPOINT) и удостоверение к нему; "+
				"вердикта о каталоге НЕ получено")
		} else {
			_, _ = fmt.Fprintf(stderr, "что сделать: проверьте, что служба поднята и адрес %s достижим "+
				"отсюда; вердикта о каталоге НЕ получено — повтор осмыслен\n", deps.Endpoint)
		}
		return ExitNotRun
	}
	if closeFn != nil {
		defer func() { _ = closeFn() }()
	}
	return fn(svc)
}

// addressPhrase — координата в тексте отказа либо СЛОВА о её отсутствии.
//
// Пустая строка, подставленная в «по адресу %s», даёт пропуск там, где читатель
// ждёт координату: он видит опечатку вывода вместо факта «адрес не задан». Тот
// же класс, что пустое значение, выдающее себя за факт о ресурсе.
func addressPhrase(endpoint string) string {
	if endpoint == "" {
		return "(адрес не задан: -endpoint / KACHO_IAMCTL_ENDPOINT)"
	}
	return "по адресу " + endpoint
}

// --- разбор аргументов ------------------------------------------------------

// parsePositional разбирает набор флагов, СОБИРАЯ позиционные аргументы в любом
// их порядке относительно флагов.
//
// Своими руками, а не одним fs.Parse: разбор стандартной библиотеки
// останавливается на первом непомеченном аргументе, поэтому `apply vpc
// -expected-state=…` отдал бы флаг позиционным. Порядок «модуль до флагов» —
// самый естественный для оператора, и требовать обратного значило бы завести
// правило, о котором он узнаёт только из отказа.
func parsePositional(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
}

// newFlagSet — набор флагов, чей отказ разбора НЕ выходит кодом VOID.
//
// У flag.ExitOnError код выхода 2, то есть он совпал бы с VOID и объявил бы
// «выгружать нечего» опечатку в вызове. Поэтому ContinueOnError и свой код.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// wantModule достаёт единственный позиционный аргумент — имя модуля.
func wantModule(positional []string, action string, stderr io.Writer) (string, bool) {
	switch len(positional) {
	case 1:
		if positional[0] != "" {
			return positional[0], true
		}
	case 0:
		_, _ = fmt.Fprintf(stderr, "вызов НЕ ИСПОЛНЕН: module: обязательное поле — имя модуля не названо\n")
		_, _ = fmt.Fprintf(stderr, "что сделать: iamctl %s МОДУЛЬ; имена действующих модулей показывает "+
			"iamctl export --all\n", action)
		return "", false
	default:
		_, _ = fmt.Fprintf(stderr, "вызов НЕ ИСПОЛНЕН: module: названо имён %d, а действие судит ОДИН модуль: %v\n",
			len(positional), positional)
		_, _ = fmt.Fprintf(stderr, "что сделать: iamctl %s МОДУЛЬ — по одному вызову на модуль; "+
			"имена показывает iamctl export --all\n", action)
		return "", false
	}
	_, _ = fmt.Fprintln(stderr, "вызов НЕ ИСПОЛНЕН: module: обязательное поле — имя модуля пусто")
	_, _ = fmt.Fprintf(stderr, "что сделать: iamctl %s МОДУЛЬ; имена показывает iamctl export --all\n", action)
	return "", false
}

// --- классификация чужого отказа -------------------------------------------

// classifyRefusal разводит отказ службы по ПОЛОСЕ и печатает следующий шаг.
//
// Правило одно: получен ли вердикт О ПРЕДМЕТЕ. Негодное поле, невыполнимое
// предусловие и отсутствие строки — вердикты, и это находки. Недоступность,
// невыданное право, истёкший срок и устаревший образ вердиктами не являются:
// служба о модуле не высказалась вовсе, и записать это находкой значило бы
// приписать дереву чужое состояние.
func classifyRefusal(stderr io.Writer, endpoint, what string, err error) int {
	st, _ := status.FromError(err)
	msg := st.Message()
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound,
		codes.AlreadyExists, codes.OutOfRange, codes.Aborted:
		_, _ = fmt.Fprintf(stderr, "НАХОДКА: %s: служба отвергла запрос (%s): %s\n", what, st.Code(), msg)
		return ExitFinding
	case codes.PermissionDenied:
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: %s: доступ не разрешён (%s): %s\n", what, st.Code(), msg)
		_, _ = fmt.Fprintf(stderr, "что сделать: глаголы каталога модуля требуют отношения system_admin "+
			"на объекте cluster; выдайте его вызывающему — повтор без выдачи не поможет\n")
		return ExitNotRun
	case codes.Unauthenticated:
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: %s: личность не принята (%s): %s\n", what, st.Code(), msg)
		_, _ = fmt.Fprintf(stderr, "что сделать: предъявите годное удостоверение службе %s; "+
			"вердикта о каталоге НЕ получено\n", addressPhrase(endpoint))
		return ExitNotRun
	case codes.Unimplemented:
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: %s: служба не несёт этого глагола (%s): %s\n", what, st.Code(), msg)
		_, _ = fmt.Fprintf(stderr, "что сделать: образ службы %s старше инструмента — "+
			"обновите развёртывание; повтор не поможет\n", addressPhrase(endpoint))
		return ExitNotRun
	default:
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: %s: вердикта не получено (%s): %s\n", what, st.Code(), msg)
		_, _ = fmt.Fprintf(stderr, "что сделать: служба %s ответа не дала; "+
			"проверьте её состояние и повторите — вердикта о каталоге НЕ получено\n", addressPhrase(endpoint))
		return ExitNotRun
	}
}

// --- validate ---------------------------------------------------------------

// runValidate — форма манифестов дерева. Ни базы, ни сети.
//
// Разбор аргументов и сама проверка берутся у ЕДИНСТВЕННОГО производителя:
// вторая композиция тех же стадий разошлась бы с сборочной целью молча.
func runValidate(args []string, stdout, stderr io.Writer, deps Deps) int {
	root, err := manifestcheckrun.ParseRoot("iamctl validate", args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitNotRun
		}
		_, _ = fmt.Fprintf(stderr, "вызов НЕ ИСПОЛНЕН: %v\n", err)
		_, _ = fmt.Fprintln(stderr, "что сделать: iamctl validate [-root=КАТАЛОГ] — корень задаётся "+
			"флагом -root, позиционных аргументов действие не принимает")
		return ExitNotRun
	}
	if deps.Validate == nil {
		_, _ = fmt.Fprintln(stderr, "вызов НЕ ИСПОЛНЕН: локальная проверка дерева не внесена")
		return ExitNotRun
	}
	return deps.Validate(root, stdout, stderr)
}

// --- plan -------------------------------------------------------------------

func runPlan(ctx context.Context, args []string, stdout, stderr io.Writer, deps Deps) int {
	fs := newFlagSet("iamctl plan", stderr)
	positional, err := parsePositional(fs, args)
	if err != nil {
		return refuseCall(stderr, fmt.Sprintf("разбор аргументов plan: %v", err))
	}
	module, ok := wantModule(positional, "plan", stderr)
	if !ok {
		return ExitNotRun
	}
	return withService(ctx, stderr, deps, func(svc ModuleService) int {
		return planWithService(ctx, stdout, stderr, svc, deps, module)
	})
}

func planWithService(ctx context.Context, stdout, stderr io.Writer, svc ModuleService, deps Deps, module string) int {
	resp, err := svc.Plan(ctx, &iamv1.PlanModuleRequest{Module: module})
	if err != nil {
		return classifyRefusal(stderr, deps.Endpoint, "план модуля "+module, err)
	}
	printPlan(stdout, resp)

	if resp.GetVerdict() == iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_BEYOND_ANCHOR {
		printBeyondAnchor(stderr, resp)
		return ExitFinding
	}
	_, _ = fmt.Fprintf(stdout, "вердикт: применение сойдётся с якорем\n")
	_, _ = fmt.Fprintf(stdout, "следующий шаг: iamctl apply %s -expected-state=%s\n",
		module, resp.GetExpectedState())
	return ExitOK
}

// printPlan печатает последствия ЧИСЛОМ и рядом — списки поимённо.
//
// Числа плана и числа применения названы врозь намеренно: переселение и
// вычистка — оценки НА МОМЕНТ ПЛАНА, и отпечаток их не стережёт. Прочитать одно
// за другое — ровно та ошибка, которую разделение и предотвращает.
func printPlan(stdout io.Writer, resp *iamv1.PlanModuleResponse) {
	_, _ = fmt.Fprintf(stdout, "модуль: %s\n", resp.GetModule())
	_, _ = fmt.Fprintf(stdout, "план: записать ресурсов %d · глаголов %d\n",
		resp.GetWrittenResourceCount(), resp.GetWrittenVerbCount())
	_, _ = fmt.Fprintf(stdout, "план: снять ресурсов %d · глаголов %d\n",
		resp.GetWithdrawnResourceCount(), resp.GetWithdrawnVerbCount())
	printNamed(stdout, "  снимается ресурс", resp.GetWithdrawnResources())
	printNamed(stdout, "  снимается глагол", resp.GetWithdrawnVerbs())
	if resp.GetWithdrawnListTruncated() {
		_, _ = fmt.Fprintln(stdout, "  перечень снимаемого УСЕЧЁН службой — числа выше полны, имена нет")
	}
	_, _ = fmt.Fprintf(stdout, "на момент плана: переселить правил-ссылок %d · глаголов ролей %d\n",
		resp.GetResettledRuleRefsAtPlanTime(), resp.GetResettledRoleVerbsAtPlanTime())
	_, _ = fmt.Fprintf(stdout, "на момент плана: вычистить строк отбора %d (отбросить %d) · типов %d\n",
		resp.GetPrunedSelectorRowsAtPlanTime(), resp.GetPrunedSelectorRowsDroppedAtPlanTime(),
		resp.GetPrunedSelectorTypesAtPlanTime())
	_, _ = fmt.Fprintf(stdout, "отпечаток состояния: %s\n", resp.GetExpectedState())
}

func printBeyondAnchor(stderr io.Writer, resp *iamv1.PlanModuleResponse) {
	_, _ = fmt.Fprintf(stderr, "НАХОДКА: модуль %s: применение вышло бы ЗА ЯКОРЬ и было бы отвергнуто "+
		"внутри транзакции, до фиксации\n", resp.GetModule())
	printNamed(stderr, "  лишняя строка (якорь её не объявляет)", resp.GetBeyondAnchorExtra())
	printNamed(stderr, "  недостающая строка (якорь объявляет, каталог не несёт)", resp.GetBeyondAnchorMissing())
	_, _ = fmt.Fprintln(stderr, "что сделать: править ИСТОЧНИК манифеста — повтор применения не поможет "+
		"ни при каком числе попыток")
}

func printNamed(w io.Writer, label string, items []string) {
	for _, it := range items {
		_, _ = fmt.Fprintf(w, "%s: %s\n", label, it)
	}
}

// --- apply ------------------------------------------------------------------

func runApply(ctx context.Context, args []string, stdout, stderr io.Writer, deps Deps) int {
	fs := newFlagSet("iamctl apply", stderr)
	expected := fs.String("expected-state", "",
		"отпечаток состояния, полученный от iamctl plan: применение идёт, только если состояние не сдвинулось")
	maxRuleRefs := fs.Int("max-resettled-rule-refs", 0,
		"потолок переселяемых правил-ссылок; НЕ задан и задан нулём — разное")
	maxRoleVerbs := fs.Int("max-resettled-role-verbs", 0,
		"потолок переселяемых глаголов ролей; НЕ задан и задан нулём — разное")
	positional, err := parsePositional(fs, args)
	if err != nil {
		return refuseCall(stderr, fmt.Sprintf("разбор аргументов apply: %v", err))
	}
	module, ok := wantModule(positional, "apply", stderr)
	if !ok {
		return ExitNotRun
	}
	if *expected == "" {
		_, _ = fmt.Fprintln(stderr, "вызов НЕ ИСПОЛНЕН: -expected-state: обязательное поле — "+
			"отпечаток состояния не назван")
		_, _ = fmt.Fprintf(stderr, "что сделать: возьмите отпечаток у плана — iamctl plan %s — и передайте "+
			"его сюда: применение сверяет им, что состояние модуля не сдвинулось с момента плана\n", module)
		return ExitNotRun
	}

	// Потолки передаются ПРИСУТСТВИЕМ: ноль здесь — законное и самое частое
	// подтверждение («ни одного права не отбирать»), поэтому «не задан» и
	// «задан нулём» обязаны доехать до службы разными значениями.
	req := &iamv1.ApplyModuleRequest{Module: module, ExpectedState: *expected}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "max-resettled-rule-refs":
			v := safeconv.IntToInt32(*maxRuleRefs)
			req.MaxResettledRuleRefs = &v
		case "max-resettled-role-verbs":
			v := safeconv.IntToInt32(*maxRoleVerbs)
			req.MaxResettledRoleVerbs = &v
		}
	})

	return withService(ctx, stderr, deps, func(svc ModuleService) int {
		return applyWithService(ctx, stdout, stderr, svc, deps, module, req)
	})
}

func applyWithService(ctx context.Context, stdout, stderr io.Writer, svc ModuleService, deps Deps,
	module string, req *iamv1.ApplyModuleRequest,
) int {
	op, err := svc.Apply(ctx, req)
	if err != nil {
		code := classifyRefusal(stderr, deps.Endpoint, "применение модуля "+module, err)
		if code == ExitFinding {
			_, _ = fmt.Fprintf(stderr, "что сделать: перечитайте план — iamctl plan %s — и повторите "+
				"применение с его отпечатком\n", module)
		}
		return code
	}
	return reportApply(stdout, stderr, module, op)
}

// reportApply читает ТЕРМИНАЛЬНЫЙ конверт операции.
//
// Отказ внутри конверта — находка: вердикт о предмете получен, он отрицательный.
// Незавершённая операция — «не выполнилось»: контракт объявляет конверт
// терминальным, поэтому незавершённость означает, что ответ пришёл не тот, а не
// что применение идёт.
func reportApply(stdout, stderr io.Writer, module string, op *operationv1.Operation) int {
	if op == nil {
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: применение модуля %s: служба вернула пустой конверт операции\n", module)
		_, _ = fmt.Fprintf(stderr, "что сделать: повторите — вердикта о применении НЕ получено\n")
		return ExitNotRun
	}
	if !op.GetDone() {
		_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: применение модуля %s: конверт операции %s объявлен "+
			"терминальным контрактом, а пришёл незавершённым\n", module, op.GetId())
		_, _ = fmt.Fprintf(stderr, "что сделать: перечитайте план — iamctl plan %s — и сверьте состояние; "+
			"вердикта о применении НЕ получено\n", module)
		return ExitNotRun
	}
	if e := op.GetError(); e != nil {
		_, _ = fmt.Fprintf(stderr, "НАХОДКА: применение модуля %s отвергнуто (%s): %s\n",
			module, codes.Code(safeconv.IntToUint32(int(e.GetCode()))), e.GetMessage())
		_, _ = fmt.Fprintf(stderr, "что сделать: перечитайте план — iamctl plan %s — и повторите "+
			"применение с его отпечатком\n", module)
		return ExitFinding
	}

	var res iamv1.ApplyModuleResponse
	if any := op.GetResponse(); any != nil {
		if err := any.UnmarshalTo(&res); err != nil {
			_, _ = fmt.Fprintf(stderr, "НЕ ИСПОЛНЕНО: применение модуля %s: тело ответа не разобрано: %v\n", module, err)
			_, _ = fmt.Fprintln(stderr, "что сделать: образ службы и инструмент собраны от разных деревьев — "+
				"сверьте версии развёртывания")
			return ExitNotRun
		}
	}
	_, _ = fmt.Fprintf(stdout, "модуль: %s\n", module)
	_, _ = fmt.Fprintf(stdout, "применение: состояние изменено=%t · строка модуля записана=%t\n",
		res.GetChanged(), res.GetModuleWritten())
	_, _ = fmt.Fprintf(stdout, "записано: ресурсов %d · глаголов %d\n",
		res.GetWrittenResources(), res.GetWrittenVerbs())
	_, _ = fmt.Fprintf(stdout, "снято: ресурсов %d · глаголов %d\n",
		res.GetRetiredResources(), res.GetRetiredVerbs())
	_, _ = fmt.Fprintf(stdout, "переселено: правил-ссылок %d · глаголов ролей %d (на момент плана было %d и %d)\n",
		res.GetResettledRuleRefs(), res.GetResettledRoleVerbs(),
		res.GetPlannedResettledRuleRefs(), res.GetPlannedResettledRoleVerbs())
	_, _ = fmt.Fprintf(stdout, "вычищено: строк отбора %d (отброшено %d) · типов %d\n",
		res.GetPrunedSelectorRows(), res.GetPrunedSelectorRowsDropped(), res.GetPrunedSelectorTypes())
	return ExitOK
}

// --- export -----------------------------------------------------------------

// sourceLine — источник выгрузки, названный словами.
//
// Выгрузка без названного источника читается как то, что читателю удобнее:
// строки каталога и манифест дерева — РАЗНЫЕ предметы, и расходятся они ровно
// тогда, когда выгрузку и смотрят.
const sourceLine = "источник: строки каталога прав, прочитанные службой " +
	"(iam InternalModuleService), а НЕ манифест дерева"

func runExport(ctx context.Context, args []string, stdout, stderr io.Writer, deps Deps) int {
	fs := newFlagSet("iamctl export", stderr)
	all := fs.Bool("all", false, "выгрузить каталог целиком: перечень модулей и живые строки каждого")
	positional, err := parsePositional(fs, args)
	if err != nil {
		return refuseCall(stderr, fmt.Sprintf("разбор аргументов export: %v", err))
	}
	switch {
	case *all && len(positional) > 0:
		_, _ = fmt.Fprintf(stderr, "вызов НЕ ИСПОЛНЕН: названы обе формы сразу — -all и модуль %v\n", positional)
		_, _ = fmt.Fprintln(stderr, "что сделать: выберите одну — iamctl export МОДУЛЬ либо iamctl export -all")
		return ExitNotRun
	case !*all && len(positional) == 0:
		_, _ = fmt.Fprintln(stderr, "вызов НЕ ИСПОЛНЕН: не названо ни модуля, ни -all — выгружать нечего")
		_, _ = fmt.Fprintln(stderr, "что сделать: выберите форму — iamctl export МОДУЛЬ либо iamctl export -all")
		return ExitNotRun
	case *all:
		return withService(ctx, stderr, deps, func(svc ModuleService) int {
			return exportAll(ctx, stdout, stderr, svc, deps)
		})
	default:
		module, ok := wantModule(positional, "export", stderr)
		if !ok {
			return ExitNotRun
		}
		return withService(ctx, stderr, deps, func(svc ModuleService) int {
			return exportOne(ctx, stdout, stderr, svc, deps, module)
		})
	}
}

func exportOne(ctx context.Context, stdout, stderr io.Writer, svc ModuleService, deps Deps, module string) int {
	cat, err := svc.Get(ctx, &iamv1.GetModuleRequest{Module: module})
	if err != nil {
		return classifyRefusal(stderr, deps.Endpoint, "выгрузка модуля "+module, err)
	}
	_, _ = fmt.Fprintln(stdout, sourceLine)
	printCatalog(stdout, cat)
	_, _ = fmt.Fprintf(stdout, "перепись: модулей выгружено 1 · строк ресурсов %d · строк глаголов %d\n",
		len(cat.GetResources()), len(cat.GetVerbs()))
	return ExitOK
}

// exportAll выгружает каталог целиком и СВЕРЯЕТ полноту.
//
// Перечень называет числа живых строк, чтение отдаёт сами строки. Расхождение
// между ними — НАХОДКА, а не тихо усечённая выгрузка: без сверки «выгружено»
// означало бы «выгружено столько, сколько дошло», и потеря строки была бы
// неотличима от её отсутствия.
func exportAll(ctx context.Context, stdout, stderr io.Writer, svc ModuleService, deps Deps) int {
	list, err := svc.List(ctx, &iamv1.ListModulesRequest{})
	if err != nil {
		return classifyRefusal(stderr, deps.Endpoint, "перечень модулей", err)
	}
	summaries := list.GetModules()
	if len(summaries) == 0 {
		_, _ = fmt.Fprintln(stderr, "ВЫГРУЖАТЬ НЕЧЕГО: перечень не назвал НИ ОДНОГО живого модуля — "+
			"это НЕ успех, а отсутствие предмета")
		_, _ = fmt.Fprintln(stderr, "что сделать: примените манифест хотя бы одного модуля — "+
			"iamctl plan МОДУЛЬ, затем iamctl apply")
		return ExitVoid
	}

	_, _ = fmt.Fprintln(stdout, sourceLine)
	code := ExitOK
	modules, resources, verbs := 0, 0, 0
	for _, s := range summaries {
		cat, err := svc.Get(ctx, &iamv1.GetModuleRequest{Module: s.GetModule()})
		if err != nil {
			code = worse(code, classifyRefusal(stderr, deps.Endpoint, "выгрузка модуля "+s.GetModule(), err))
			continue
		}
		printCatalog(stdout, cat)
		modules++
		resources += len(cat.GetResources())
		verbs += len(cat.GetVerbs())

		gotRes, gotVerbs := safeconv.IntToInt32(len(cat.GetResources())), safeconv.IntToInt32(len(cat.GetVerbs()))
		if gotRes != s.GetLiveResourceCount() || gotVerbs != s.GetLiveVerbCount() {
			_, _ = fmt.Fprintf(stderr, "НАХОДКА: модуль %s: перечень назвал живыми ресурсов %d · глаголов %d, "+
				"а выгружено %d и %d — выгрузка НЕПОЛНА\n",
				s.GetModule(), s.GetLiveResourceCount(), s.GetLiveVerbCount(), gotRes, gotVerbs)
			_, _ = fmt.Fprintln(stderr, "что сделать: повторите выгрузку; если расхождение держится — "+
				"каталог менялся между перечнем и чтением либо чтение усечено")
			code = worse(code, ExitFinding)
		}
	}
	_, _ = fmt.Fprintf(stdout, "перепись: модулей названо %d · выгружено %d · строк ресурсов %d · строк глаголов %d\n",
		len(summaries), modules, resources, verbs)
	return code
}

func printCatalog(stdout io.Writer, cat *iamv1.ModuleCatalog) {
	_, _ = fmt.Fprintf(stdout, "модуль: %s\n", cat.GetModule())
	_, _ = fmt.Fprintf(stdout, "  строк ресурсов %d · строк глаголов %d\n",
		len(cat.GetResources()), len(cat.GetVerbs()))
	for _, r := range cat.GetResources() {
		_, _ = fmt.Fprintf(stdout, "  ресурс: %s\n", strings.TrimSpace(r.String()))
	}
	for _, v := range cat.GetVerbs() {
		_, _ = fmt.Fprintf(stdout, "  глагол: %s\n", strings.TrimSpace(v.String()))
	}
}

// worse — исход, который НЕ вправе быть перекрыт более мягким.
//
// Находка объявляется первой: прогон, где есть и находка, и беспредметная
// проверка, обязан остановить оператора, а не сообщить об отсутствии предмета.
func worse(a, b int) int {
	rank := map[int]int{ExitOK: 0, ExitVoid: 1, ExitNotRun: 2, ExitFinding: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// --- doctor -----------------------------------------------------------------

// finding — одна запись разбора: ТРИ части, и ни одна не факультативна.
//
// «Похоже, есть проблема» ответом не является. Что именно неверно · чем это
// проверено · что сделать — вот форма, и держится она структурой записи, а не
// добросовестностью пишущего.
type finding struct {
	Wrong   string // что именно неверно
	Checked string // чем это проверено — предикат, а не впечатление
	Fix     string // что сделать
}

func (f finding) print(stderr io.Writer) {
	_, _ = fmt.Fprintf(stderr, "неверно: %s\n", f.Wrong)
	_, _ = fmt.Fprintf(stderr, "  проверено: %s\n", f.Checked)
	_, _ = fmt.Fprintf(stderr, "  сделать: %s\n", f.Fix)
}

// runDoctor — разбор состояния каталога. Своей проверки не заводит: спрашивает
// перечень и план по каждому модулю, то есть теми же глаголами, которыми ими
// пользуется оператор.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer, deps Deps) int {
	fs := newFlagSet("iamctl doctor", stderr)
	positional, err := parsePositional(fs, args)
	if err != nil {
		return refuseCall(stderr, fmt.Sprintf("разбор аргументов doctor: %v", err))
	}
	if len(positional) > 0 {
		_, _ = fmt.Fprintf(stderr, "вызов НЕ ИСПОЛНЕН: doctor судит каталог целиком и имён не принимает: %v\n", positional)
		_, _ = fmt.Fprintln(stderr, "что сделать: iamctl doctor — без аргументов; один модуль смотрит iamctl plan МОДУЛЬ")
		return ExitNotRun
	}

	return withService(ctx, stderr, deps, func(svc ModuleService) int {
		return doctorWithService(ctx, stdout, stderr, svc, deps)
	})
}

func doctorWithService(ctx context.Context, stdout, stderr io.Writer, svc ModuleService, deps Deps) int {
	checks, findings := 0, 0

	// Проверка 1 — служба отвечает. Без неё остальные не имеют предмета.
	checks++
	list, err := svc.List(ctx, &iamv1.ListModulesRequest{})
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "перепись: проверок %d · модулей 0 · находок 0 · НЕ ИСПОЛНЕНО 1\n", checks)
		return classifyRefusal(stderr, deps.Endpoint, "перечень модулей", err)
	}

	// Проверка 2 — каталог непуст. Пустой каталог — отсутствие предмета, а не
	// его исправность: разбирать в нём нечего.
	checks++
	summaries := list.GetModules()
	if len(summaries) == 0 {
		_, _ = fmt.Fprintf(stdout, "перепись: проверок %d · модулей 0 · находок 0\n", checks)
		_, _ = fmt.Fprintln(stderr, "РАЗБИРАТЬ НЕЧЕГО: перечень не назвал НИ ОДНОГО живого модуля — "+
			"это НЕ «всё в порядке», а отсутствие предмета")
		_, _ = fmt.Fprintln(stderr, "что сделать: примените манифест хотя бы одного модуля — "+
			"iamctl plan МОДУЛЬ, затем iamctl apply")
		return ExitVoid
	}

	// Проверка 3..N — по модулю: сходится ли доставленный манифест с каталогом.
	code := ExitOK
	for _, s := range summaries {
		checks++
		module := s.GetModule()
		resp, planErr := svc.Plan(ctx, &iamv1.PlanModuleRequest{Module: module})
		if planErr != nil {
			st, _ := status.FromError(planErr)
			switch st.Code() {
			case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound:
				findings++
				finding{
					Wrong: fmt.Sprintf("модуль %s: план не строится — %s", module, st.Message()),
					Checked: fmt.Sprintf("вызов iam InternalModuleService/Plan по адресу %s "+
						"вернул %s", deps.Endpoint, st.Code()),
					Fix: "почините ДОСТАВКУ манифеста этого модуля: объявлена ли она посадкой, " +
						"читается ли источник, есть ли в нём манифест именно этого модуля — " +
						"три разных места починки",
				}.print(stderr)
				code = worse(code, ExitFinding)
			default:
				code = worse(code, classifyRefusal(stderr, deps.Endpoint, "план модуля "+module, planErr))
			}
			continue
		}
		if resp.GetVerdict() == iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_BEYOND_ANCHOR {
			findings++
			finding{
				Wrong: fmt.Sprintf("модуль %s: каталог вышел за якорь сверки — лишние строки %v, "+
					"недостающие %v", module, resp.GetBeyondAnchorExtra(), resp.GetBeyondAnchorMissing()),
				Checked: fmt.Sprintf("вызов iam InternalModuleService/Plan по адресу %s вернул вердикт %s",
					deps.Endpoint, resp.GetVerdict()),
				Fix: "править ИСТОЧНИК манифеста: следующий подъём службы будет отвергнут этой же " +
					"сверкой, и повтор применения не поможет",
			}.print(stderr)
			code = worse(code, ExitFinding)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "модуль %s: каталог сходится с доставленным манифестом "+
			"(живых ресурсов %d · глаголов %d; записать %d и %d, снять %d и %d)\n",
			module, s.GetLiveResourceCount(), s.GetLiveVerbCount(),
			resp.GetWrittenResourceCount(), resp.GetWrittenVerbCount(),
			resp.GetWithdrawnResourceCount(), resp.GetWithdrawnVerbCount())
	}

	// Перепись печатается ВСЕГДА: без неё «ноль находок» неотличимо от
	// «ноль проверенного».
	_, _ = fmt.Fprintf(stdout, "перепись: проверок %d · модулей %d · находок %d\n",
		checks, len(summaries), findings)
	return code
}
