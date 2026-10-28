// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// form_before_door_class_test.go — IAM-PNE-1-21 полоса А приёмки
// `docs/engineering/acceptance/non-empty-project-is-not-deleted.md` (§11,
// задача kaname#168): неверная форма идентификатора отвергается ступенью формы
// публичного слушателя ДО вопроса о праве — у КАЖДОГО глагола с пообъектной
// областью, а не у одного показательного.
//
// # Что утверждается
//
// По каждому глаголу класса и каждому из трёх входов (приставки нет; приставка
// ожидаемого вида при неверной длине; правильная форма ДРУГОГО вида) цепочка
// публичного слушателя отвечает `INVALID_ARGUMENT` с текстом обработчика
// дословно, решатель модели не спрошен, обработчик не позван, причины рубежа
// прав `AUTHZ_DENIED` в деталях нет.
//
// # Порядок проверок несущий
//
// Сначала по глаголу гоняется ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ — та же цепочка, тот же
// субъект, правильная форма ожидаемого вида. Он обязан дойти до двери: первый
// вопрос решателю — об объекте `<вид>:<значение>` с отношением записи карты и
// от субъекта `service_account:<sva-…>`, отчеканенного удостоверением (условие
// ревью K7-N2). Близнец, не дошедший до двери, — «запрос не построен»: вердикта
// у глагола НЕТ, и это отдельная категория, а не находка. Только после близнеца
// гоняются три входа неверной формы. Обратный порядок дал бы сломанной фикстуре
// (субъект не назвался, порог доверия остановил запрос раньше формы) выдать
// себя за отсутствующую ступень формы.
//
// # Перечень глаголов ВЫВОДИТСЯ
//
// Класс — аннотации тех же дескрипторов, из которых дверь строит карту
// (`catalogderive.RangeAnnotated` по `authzguard.OwnDoorProtoPackages()`):
// конкретное поле области (не пустое и не `*`), без поля вида области, не
// `scope_filtered`, — пересечённые с методами, которые корень МОНТИРУЕТ на
// публичный сервер (`registerPublicServices`), а не с приставкой имени службы.
// Условие KE-1 разбора требует, чтобы ступень и проба звали ОДНУ функцию
// класса прод-кода; её в дереве ещё нет, и до неё класс выводится здесь, из
// того же источника, — полоса реализации переводит пробу на ту функцию.
//
// # Одна цепочка на корень и пробу (условие ревью K6-N2)
//
// Цепочку, которую судит проба, строит `publicChainUnderProbe`. Пока общего
// сборщика публичной цепочки в прод-коде нет, это сборка по месту в тестовом
// файле, повторяющая порядок `serve.go` (её звенья — ниже), — то есть вторая
// проводка. Поэтому проба утверждает и это: функция, собравшая её цепочку,
// объявлена вне тестовых файлов и её зовёт корень. Сегодня утверждение
// красное по предмету — сборщика нет; полоса реализации заводит его в
// `serve.go`, переводит на него корень и `publicChainUnderProbe`, и тем самым
// снимает эту копию.
//
// # Чем проба НЕ является
//
// Не проверкой двери (её держит `TestOwnDoor_EveryObjectScopedRPCRefusesAStranger`)
// и не сквозной пробой фронта (полосы 1-08 и Б — набор newman). Контроли вне
// класса стоят ради одной стороны: ступень формы не отвечает там, где отвечать
// ей не положено (§11.4 и условия KE-2, KE-3, KE-9 разбора).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// formProbeSA — служебная учётка без прав, от имени которой идут все вызовы
// класса. Вид выбран приёмкой (§11.5): у всех глаголов класса каталог объявляет
// порог доверия, человек без уровня остановился бы на политике вызывающего до
// формы, а машинный принципал от порога освобождён.
const formProbeSA = "sva-formprobe0000001"

// formProbeSubject — субъект модели, которым дверь обязана спросить о близнеце.
const formProbeSubject = "service_account:" + formProbeSA

// formProbeSeededRole — посеянный идентификатор роли (длина 21, закрытый
// перечень посеянного): форма его не отвергает.
const formProbeSeededRole = "rol000000000sysviewer"

// formProbeNoPrefix — вход (1): приставки нет ни у одного вида.
const formProbeNoPrefix = "qqq-not-a-project"

// formProbeKinds — таблица §11.3 приёмки: вид объекта двери → приставка и имя
// вида в тексте отказа. Имена — литералами из приёмки: утверждение «равно тому,
// что вернул производитель» зеленело бы при любом его значении.
var formProbeKinds = map[string]struct{ prefix, name string }{
	"project":             {domain.PrefixProject, "project"},
	"account":             {domain.PrefixAccount, "account"},
	"iam_user":            {domain.PrefixUser, "user"},
	"iam_service_account": {domain.PrefixServiceAccount, "service account"},
	"iam_group":           {domain.PrefixGroup, "group"},
	"iam_role":            {domain.PrefixRole, "role"},
	"iam_access_binding":  {domain.PrefixAccessBinding, "access binding"},
}

// formProbeWellFormed — правильная форма вида: приставка и 17 знаков до длины
// 20; хвост `notfnd` в чеканке не встречается, объекта такого нет.
func formProbeWellFormed(prefix string) string { return prefix + "00000000000notfnd" }

// formProbeQuestion — один вопрос решателю модели.
type formProbeQuestion struct{ subject, relation, object string }

// formProbeDecider — подделка решателя: считает вопросы и не разрешает ничего.
type formProbeDecider struct{ asked []formProbeQuestion }

func (d *formProbeDecider) Check(_ context.Context, subject, relation, object string) (bool, error) {
	d.asked = append(d.asked, formProbeQuestion{subject: subject, relation: relation, object: object})
	return false, nil
}

// formProbeChainInputs — то, что цепочке приносит мир пробы: читатель
// предъявленного, каталог прав (порог доверия и действие отказа), решатель и
// режим посадки политики вызывающего.
type formProbeChainInputs struct {
	reader   *presentedcred.Reader
	catalog  *seed.PermissionRegistry
	decider  authzguard.RelationChecker
	prodMode bool
}

// publicChainUnderProbe — сборщик цепочки, которую судит проба. Утверждение
// K6-N2 ниже читает, ГДЕ объявлена эта функция и зовёт ли её корень.
var publicChainUnderProbe = handAssembledPublicChain

// handAssembledPublicChain — сборка по месту в порядке `serve.go`: обогатитель
// отказа → личность (пара извлечения и читатель предъявленного) → политика
// вызывающего → ворота адреса → анти-аноним → дверь. Измеритель задержки и
// перехват паники опущены: решения о доступе они не несут. Это вторая
// проводка, и проба красная на ней по условию K6-N2, пока её не сменит
// общий сборщик прод-кода.
func handAssembledPublicChain(t *testing.T, in formProbeChainInputs) grpc.UnaryServerInterceptor {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := authzguard.NewPublicCallerPolicy(in.prodMode, authzguard.PublicPeerCallableRPCs(), in.catalog,
		presentedcred.Presented).WithModuleRoster(testModuleRoster())
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: in.decider, Logger: quiet})
	if err != nil {
		t.Fatalf("дверь не собрана — условие пробы не создано: %v", err)
	}
	links := append([]grpc.UnaryServerInterceptor{authzguard.DenyDetailUnary(in.catalog)},
		publicIdentityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN), in.reader)...)
	links = append(links, policy.Unary(), authzguard.NewAddressGate(chainRevocations{}).Unary(),
		authzguard.AntiAnonymousUnary(quiet), door.Unary())
	return chainUnaryServer(links...)
}

// formProbeRegistrar запоминает имена служб, которые корень монтирует.
type formProbeRegistrar struct{ services []string }

func (r *formProbeRegistrar) RegisterService(sd *grpc.ServiceDesc, _ any) {
	r.services = append(r.services, sd.ServiceName)
}

// formProbePublicMethods — методы, которые корень монтирует на ПУБЛИЧНЫЙ
// сервер. Обработчики заполняются нулевыми значениями отражением по ВСЕМ
// полям-указателям набора служб: новое поле попадает в перепись само, а не
// через выписанный здесь перечень.
func formProbePublicMethods(t *testing.T) map[string]struct{} {
	t.Helper()
	var svcs services
	v := reflect.ValueOf(&svcs).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Ptr {
			continue
		}
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.New(f.Type().Elem()))
	}
	rec := &formProbeRegistrar{}
	registerPublicServices(rec, &svcs, nil)
	out := map[string]struct{}{}
	for _, name := range rec.services {
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
		if err != nil {
			t.Fatalf("служба публичного сервера %s без дескриптора: %v", name, err)
		}
		sd, ok := desc.(protoreflect.ServiceDescriptor)
		if !ok {
			t.Fatalf("%s — не служба", name)
		}
		for j := 0; j < sd.Methods().Len(); j++ {
			out["/"+name+"/"+string(sd.Methods().Get(j).Name())] = struct{}{}
		}
	}
	return out
}

// formProbeVerb — глагол класса и то, что о нём сказали аннотации.
type formProbeVerb struct {
	method string
	field  string
	kind   string
}

// formProbeClass выводит класс и контроли вне класса из аннотаций дескрипторов
// двери, пересечённых с публичным сервером корня.
func formProbeClass(t *testing.T) (class, typedScope []formProbeVerb) {
	t.Helper()
	public := formProbePublicMethods(t)
	if len(public) == 0 {
		t.Fatal("корень не смонтировал на публичный сервер ни одного метода — перепись беспредметна")
	}
	catalogderive.RangeAnnotated(authzguard.OwnDoorProtoPackages(),
		func(full string, _ protoreflect.MethodDescriptor, a catalogderive.Annotations) {
			if _, mounted := public[full]; !mounted || a.ScopeFiltered {
				return
			}
			field := a.ScopeFromRequestField
			if field == "" || field == catalogderive.WildcardField {
				return
			}
			v := formProbeVerb{method: full, field: field, kind: a.ScopeObjectType}
			if a.ScopeObjectTypeFromRequest != "" {
				typedScope = append(typedScope, v)
				return
			}
			class = append(class, v)
		})
	sort.Slice(class, func(i, j int) bool { return class[i].method < class[j].method })
	sort.Slice(typedScope, func(i, j int) bool { return typedScope[i].method < typedScope[j].method })
	return class, typedScope
}

// formProbeRequest строит запрос глагола: поле области — value, поле вида
// области (если аннотация его называет) — объявленный аннотацией вид. false —
// «не построен»: поля нет либо оно не строковое.
func formProbeRequest(method, field, value string) (any, bool) {
	trimmed := strings.TrimPrefix(method, "/")
	slash := strings.LastIndex(trimmed, "/")
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(trimmed[:slash]))
	if err != nil {
		return nil, false
	}
	sd, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, false
	}
	md := sd.Methods().ByName(protoreflect.Name(trimmed[slash+1:]))
	if md == nil {
		return nil, false
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(md.Input().FullName())
	if err != nil {
		return nil, false
	}
	msg := mt.New()
	fd := msg.Descriptor().Fields().ByName(protoreflect.Name(field))
	if fd == nil || fd.Kind() != protoreflect.StringKind || fd.IsList() {
		return nil, false
	}
	msg.Set(fd, protoreflect.ValueOfString(value))
	a := catalogderive.AnnotationsOf(md)
	if a.ScopeObjectTypeFromRequest != "" {
		tf := msg.Descriptor().Fields().ByName(protoreflect.Name(a.ScopeObjectTypeFromRequest))
		if tf == nil || tf.Kind() != protoreflect.StringKind || tf.IsList() {
			return nil, false
		}
		msg.Set(tf, protoreflect.ValueOfString(a.ScopeObjectType))
	}
	return msg.Interface(), true
}

// formProbeOutcome — исход одного вызова цепочки.
type formProbeOutcome struct {
	err     error
	reached bool
	asked   []formProbeQuestion
}

func (o formProbeOutcome) code() codes.Code { return status.Code(o.err) }
func (o formProbeOutcome) message() string  { return status.Convert(o.err).Message() }

// authzDenied — несёт ли отказ причину рубежа прав.
func (o formProbeOutcome) authzDenied() bool {
	for _, d := range status.Convert(o.err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == "AUTHZ_DENIED" {
			return true
		}
	}
	return false
}

func (o formProbeOutcome) String() string {
	return o.code().String() + " " + strconv.Quote(o.message()) +
		", вопросов решателю " + strconv.Itoa(len(o.asked)) +
		", обработчик " + map[bool]string{true: "позван", false: "не позван"}[o.reached]
}

// formProbeCall — один вызов цепочки свежим решателем.
type formProbeCall func(ctx context.Context, method string, req any) formProbeOutcome

func formProbeCaller(t *testing.T, in formProbeChainInputs) formProbeCall {
	t.Helper()
	decider := &formProbeDecider{}
	in.decider = decider
	chain := publicChainUnderProbe(t, in)
	return func(ctx context.Context, method string, req any) formProbeOutcome {
		decider.asked = nil
		reached := false
		_, err := chain(ctx, req, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) { reached = true; return nil, nil })
		return formProbeOutcome{err: err, reached: reached, asked: append([]formProbeQuestion(nil), decider.asked...)}
	}
}

// formProbeTwinFailure — почему положительный близнец не дошёл до двери; пусто —
// дошёл. Этим отличается «запрос не построен» от отказа (K7-N2).
func formProbeTwinFailure(o formProbeOutcome, relation, object string) string {
	switch {
	case o.code() == codes.Unauthenticated:
		return "остановлен до формы подлинностью либо порогом доверия: " + o.String()
	case len(o.asked) == 0:
		return "решатель не спрошен: " + o.String()
	case o.asked[0].subject != formProbeSubject:
		return "первый вопрос задан от " + strconv.Quote(o.asked[0].subject) + ", а не от " + strconv.Quote(formProbeSubject)
	case o.asked[0].relation != relation || o.asked[0].object != object:
		return "первый вопрос " + o.asked[0].relation + "@" + o.asked[0].object + ", ожидался " + relation + "@" + object
	case o.code() == codes.InvalidArgument:
		return "правильная форма отвергнута как неверная: " + o.String()
	}
	return ""
}

func TestIAM_PNE_1_21_A_FormIsAnsweredBeforeTheDoorOnEveryObjectScopedRPC(t *testing.T) {
	catalog, err := seed.LoadPermissionRegistry(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("каталог прав не загружен — условие пробы не создано: %v", err)
	}
	doorMap, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	if err != nil {
		t.Fatalf("карта двери не выведена — условие пробы не создано: %v", err)
	}
	reader, mint := chainMint(t)
	saCtx := presenting(mint(jwt.MapClaims{
		"sub": formProbeSA, "acr": "1",
		domain.ClaimPrincipalType: "service_account",
		domain.ClaimPrincipalID:   formProbeSA,
	}))
	call := formProbeCaller(t, formProbeChainInputs{reader: reader, catalog: catalog, prodMode: true})

	class, typedScope := formProbeClass(t)
	if len(class) == 0 {
		t.Fatal("в классе ноль глаголов — обход беспредметен, это не зелёное")
	}

	var (
		byKind       = map[string]int{}
		built        int
		unbuildable  []string
		findings     []string
		formAnswered int
	)
	for _, v := range class {
		byKind[v.kind]++
		kind, known := formProbeKinds[v.kind]
		entry, mapped := doorMap[v.method]
		switch {
		case !known:
			unbuildable = append(unbuildable, v.method+": вид "+strconv.Quote(v.kind)+" вне таблицы §11.3")
			continue
		case !mapped || entry.Relation == "":
			unbuildable = append(unbuildable, v.method+": в карте двери нет отношения")
			continue
		}

		// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ — первым: фикстура проверяется до вопроса о
		// ступени формы.
		good := formProbeWellFormed(kind.prefix)
		req, ok := formProbeRequest(v.method, v.field, good)
		if !ok {
			unbuildable = append(unbuildable, v.method+": поле "+v.field+" не строится")
			continue
		}
		if why := formProbeTwinFailure(call(saCtx, v.method, req), entry.Relation, v.kind+":"+good); why != "" {
			unbuildable = append(unbuildable, v.method+" (близнец "+good+"): "+why)
			continue
		}
		// ВТОРОЙ БЛИЗНЕЦ — посеянное: у глаголов с полем роли.
		if v.kind == "iam_role" {
			sreq, _ := formProbeRequest(v.method, v.field, formProbeSeededRole)
			if why := formProbeTwinFailure(call(saCtx, v.method, sreq), entry.Relation, v.kind+":"+formProbeSeededRole); why != "" {
				findings = append(findings, v.method+" (посеянное "+formProbeSeededRole+"): "+why)
			}
		}
		built++

		other := domain.PrefixProject
		if v.kind == "project" {
			other = domain.PrefixAccount
		}
		for _, bad := range []string{formProbeNoPrefix, kind.prefix + "123", formProbeWellFormed(other)} {
			breq, _ := formProbeRequest(v.method, v.field, bad)
			o := call(saCtx, v.method, breq)
			want := "invalid " + kind.name + " id '" + bad + "'"
			var why []string
			if o.code() != codes.InvalidArgument || o.message() != want {
				why = append(why, "ответ "+o.code().String()+" "+strconv.Quote(o.message())+", ожидался InvalidArgument "+strconv.Quote(want))
			}
			if len(o.asked) != 0 {
				why = append(why, "решатель спрошен "+strconv.Itoa(len(o.asked))+" раз, первый — "+o.asked[0].relation+"@"+o.asked[0].object)
			}
			if o.reached {
				why = append(why, "обработчик позван")
			}
			if o.authzDenied() {
				why = append(why, "в деталях ErrorInfo AUTHZ_DENIED")
			}
			if len(why) > 0 {
				findings = append(findings, v.method+" ["+bad+"]: "+strings.Join(why, "; "))
				continue
			}
			formAnswered++
		}
	}

	// КОНТРОЛИ ВНЕ КЛАССА — ступень формы обязана МОЛЧАТЬ.
	var controls []string
	// (а) поле вида области (§11.4, KE-2): неверная форма доходит до двери.
	for _, v := range typedScope {
		req, ok := formProbeRequest(v.method, v.field, formProbeNoPrefix)
		if !ok {
			controls = append(controls, v.method+" (вне класса): запрос не построен")
			continue
		}
		if o := call(saCtx, v.method, req); len(o.asked) == 0 || o.code() == codes.InvalidArgument {
			controls = append(controls, v.method+" (вне класса, поле вида области): ступень ответила вместо двери: "+o.String())
		}
	}
	// (б) безымянный вызывающий (KE-3): в непроизводственной посадке политика
	// его пропускает, и ступень формы ему не отвечает.
	anonCall := formProbeCaller(t, formProbeChainInputs{reader: reader, catalog: catalog, prodMode: false})
	// (в) пустое поле (KE-9): отсутствие — не неверная форма.
	for _, v := range class {
		kind, known := formProbeKinds[v.kind]
		if !known {
			continue
		}
		if req, ok := formProbeRequest(v.method, v.field, formProbeNoPrefix); ok {
			if o := anonCall(context.Background(), v.method, req); o.code() == codes.InvalidArgument &&
				o.message() == "invalid "+kind.name+" id '"+formProbeNoPrefix+"'" {
				controls = append(controls, v.method+" (безымянный): ступень формы ответила анониму: "+o.String())
			}
		}
		if req, ok := formProbeRequest(v.method, v.field, ""); ok {
			if o := call(saCtx, v.method, req); o.code() == codes.InvalidArgument &&
				o.message() == "invalid "+kind.name+" id ''" {
				controls = append(controls, v.method+" (пустое поле): ступень формы ответила на отсутствие: "+o.String())
			}
		}
	}

	// K6-N2 — цепочку пробы собирает функция прод-кода, и её зовёт корень.
	structural := formProbeOneWiring(t)

	kinds := make([]string, 0, len(byKind))
	for k, n := range byKind {
		kinds = append(kinds, k+" "+strconv.Itoa(n))
	}
	sort.Strings(kinds)
	t.Logf("перепись IAM-PNE-1-21 А: глаголов класса %d (%s) · вне класса с полем вида области %d · "+
		"построено %d · не построено %d · входов неверной формы отвечено ступенью %d из %d · находок %d · "+
		"контролей вне класса нарушено %d · проводка K6-N2 нарушений %d",
		len(class), strings.Join(kinds, ", "), len(typedScope), built, len(unbuildable),
		formAnswered, 3*built, len(findings), len(controls), len(structural))

	sort.Strings(unbuildable)
	if len(unbuildable) > 0 {
		t.Errorf("вердикта НЕТ (запрос не построен) у %d глаголов из %d — это не отказ ступени:\n  %s",
			len(unbuildable), len(class), strings.Join(unbuildable, "\n  "))
	}
	if built == 0 {
		t.Fatal("ни один глагол класса не построен — проба не утверждает ничего")
	}
	if len(controls) > 0 {
		t.Errorf("контроли вне класса нарушены (%d):\n  %s", len(controls), strings.Join(controls, "\n  "))
	}
	if len(structural) > 0 {
		t.Errorf("одна цепочка на корень и пробу (K6-N2) не держится:\n  %s", strings.Join(structural, "\n  "))
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("ступень формы не отвечает до двери: находок %d на %d построенных глаголах:\n  %s",
			len(findings), built, strings.Join(findings, "\n  "))
	}
}

// formProbeOneWiring — функция, собравшая цепочку пробы, объявлена вне тестовых
// файлов пакета, и её зовёт не-тестовый код корня. Нарушения — строками.
func formProbeOneWiring(t *testing.T) []string {
	t.Helper()
	fn := runtime.FuncForPC(reflect.ValueOf(publicChainUnderProbe).Pointer())
	if fn == nil {
		return []string{"сборщик цепочки пробы не опознан средой исполнения"}
	}
	file, _ := fn.FileLine(fn.Entry())
	name := fn.Name()[strings.LastIndex(fn.Name(), ".")+1:]
	var out []string
	if strings.HasSuffix(file, "_test.go") {
		out = append(out, "цепочку пробы собирает "+name+" из тестового файла "+filepath.Base(file)+
			" — вторая проводка, корень её не исполняет")
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("каталог корня не прочитан: %v", err)
	}
	fset := token.NewFileSet()
	var read, calls int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("исходник корня %s не разобран: %v", e.Name(), err)
		}
		read++
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == name {
					calls++
				}
			}
			return true
		})
	}
	if read == 0 {
		t.Fatal("не-тестовых исходников корня ноль — проверка проводки беспредметна")
	}
	if calls == 0 {
		out = append(out, "корень (не-тестовых файлов "+strconv.Itoa(read)+") не зовёт "+name+
			" — цепочка, которую судит проба, не та, что уезжает в публичный слушатель")
	}
	return out
}
