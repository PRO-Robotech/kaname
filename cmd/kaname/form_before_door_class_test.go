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
// Класс берётся у функции прод-кода `authzguard.ObjectScopedRPCs` — той же,
// по которой звено формы решает, что оно судит (условие KE-1 разбора): она
// выводит его из аннотаций тех же дескрипторов, из которых дверь строит карту
// (конкретное поле области, не пустое и не `*`, без поля вида области, не
// `scope_filtered`, не исключение). Проба пересекает класс с методами, которые
// корень МОНТИРУЕТ на публичный сервер (`registerPublicServices`), а не с
// приставкой имени службы.
//
// # Перечень выводится ДВАЖДЫ, и выводы сверяются
//
// Один вывод у пробы и у ступени слеп к сужению: глагол, выпавший из функции
// класса, выпал бы из обоих разом, и проба зеленела бы на 57 глаголах так же,
// как на 58. Поэтому второй вывод — встроенный каталог прав службы
// (`internal/apps/kaname/seed/embedded/permission_catalog.json`, предикат «по
// предмету» §11.2 приёмки), прочитанный своим разбором, без `catalogderive` и
// без функции класса. Проба обходит ОБЪЕДИНЕНИЕ двух выводов: выпавший из
// функции глагол всё равно гоняется и даёт находку там, где ступень молчит.
// Сверх объединения утверждаются равенство выводов поглаголово (метод, поле,
// вид) и точная перепись класса по видам — таблицей §11.2, а не потолком.
//
// # Одна цепочка на корень и пробу (условие ревью K6-N2)
//
// Цепочку, которую судит проба, строит `publicChainUnderProbe` — сборщик
// корня `publicListenerChain` (`serve.go`), от измерителя задержки до двери.
// Свои у пробы лишь звенья с зависимостями мира (политика, ворота адреса,
// дверь с решателем-подделкой). Проба утверждает и это: функция, собравшая
// её цепочку, объявлена вне тестовых файлов и её зовёт корень, — иначе она
// судила бы вторую проводку.
//
// # Чем проба НЕ является
//
// Не проверкой двери (её держит `TestOwnDoor_EveryObjectScopedRPCRefusesAStranger`)
// и не сквозной пробой фронта (полосы 1-08 и Б — набор newman). Контроли вне
// класса стоят ради одной стороны: ступень формы не отвечает там, где отвечать
// ей не положено (§11.4 и условия KE-2, KE-3, KE-9 разбора).

import (
	"context"
	"encoding/json"
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
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"
	"github.com/PRO-Robotech/corelib/grpcsrv"

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

// testPublicChainInputs — то, что цепочке приносит мир пробы: читатель
// предъявленного, каталог прав (порог доверия и действие отказа), решатель и
// режим посадки политики вызывающего.
type testPublicChainInputs struct {
	reader   *presentedcred.Reader
	catalog  *seed.PermissionRegistry
	decider  authzguard.RelationChecker
	prodMode bool
}

// publicChainUnderProbe — сборщик цепочки, которую судит проба: ТОТ ЖЕ, что
// зовёт корень. Утверждение K6-N2 ниже читает, где объявлена эта функция и
// зовёт ли её корень, — сборка по месту в тестовом файле его бы не прошла.
var publicChainUnderProbe = publicListenerChain

// testPublicChain собирает публичную цепочку сборщиком корня. Свои у пробы —
// только звенья, несущие зависимости мира: политика вызывающего (режим
// посадки, каталог), ворота адреса (читатель отметок без строк людей) и дверь
// (решатель-подделка); измеритель задержки — на своём реестре серий.
func testPublicChain(t testing.TB, in testPublicChainInputs) grpc.UnaryServerInterceptor {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	latency, err := grpcsrv.NewServerLatency(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("измеритель задержки не собран — условие пробы не создано: %v", err)
	}
	policy := authzguard.NewPublicCallerPolicy(in.prodMode, authzguard.PublicPeerCallableRPCs(), in.catalog,
		presentedcred.Presented).WithModuleRoster(testModuleRoster())
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: in.decider, Logger: quiet})
	if err != nil {
		t.Fatalf("дверь не собрана — условие пробы не создано: %v", err)
	}
	unary, _, err := publicChainUnderProbe(fwdCfg(fwdGatewaySAN, fwdVPCSAN), quiet, latency, in.catalog, in.reader,
		policy, authzguard.NewAddressGate(chainRevocations{}), door)
	if err != nil {
		t.Fatalf("публичная цепочка не собрана сборщиком корня: %v", err)
	}
	return chainUnaryServer(unary...)
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
		if f.Kind() != reflect.Pointer {
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

// formProbeClass — класс и контроли вне класса, пересечённые с публичным
// сервером корня.
//
// Класс берётся у ТОЙ функции прод-кода, по которой звено формы решает, какие
// глаголы оно судит (`authzguard.ObjectScopedRPCs`, условие KE-1): проба,
// выписавшая свой отбор, судила бы звено по чужому перечню. Контроль вне
// класса — глаголы с полем вида области — выводится из тех же аннотаций
// отдельно: в класс они не входят, и функция класса их не возвращает.
func formProbeClass(t *testing.T) (class, typedScope []formProbeVerb) {
	t.Helper()
	public := formProbePublicMethods(t)
	if len(public) == 0 {
		t.Fatal("корень не смонтировал на публичный сервер ни одного метода — перепись беспредметна")
	}
	for _, rpc := range authzguard.ObjectScopedRPCs() {
		if _, mounted := public[rpc.Method]; mounted {
			class = append(class, formProbeVerb{method: rpc.Method, field: rpc.Field, kind: rpc.ObjectType})
		}
	}
	catalogderive.RangeAnnotated(authzguard.OwnDoorProtoPackages(),
		func(full string, _ protoreflect.MethodDescriptor, a catalogderive.Annotations) {
			if _, mounted := public[full]; !mounted || a.ScopeFiltered || a.ScopeObjectTypeFromRequest == "" {
				return
			}
			if field := a.ScopeFromRequestField; field != "" && field != catalogderive.WildcardField {
				typedScope = append(typedScope, formProbeVerb{method: full, field: field, kind: a.ScopeObjectType})
			}
		})
	sort.Slice(typedScope, func(i, j int) bool { return typedScope[i].method < typedScope[j].method })
	return class, typedScope
}

// formProbeCatalogPath — встроенный каталог прав службы, источник второго
// вывода класса. Путь — от каталога пакета корня, в котором исполняется проба.
const formProbeCatalogPath = "../../internal/apps/kaname/seed/embedded/permission_catalog.json"

// formProbeExempt — литерал изъятия в поле права строки каталога. Литералом, а
// не константой `catalogderive`: второй вывод не делит кода с первым.
const formProbeExempt = "<exempt>"

// formProbeClassCensus — перепись класса по видам объекта, §11.2 приёмки:
// 16 · 15 · 9 · 7 · 5 · 3 · 3, сумма 58. Число ТОЧНОЕ, а не потолок: новый
// глагол класса меняет эту таблицу вместе с приёмкой, а выпавший краснит пробу.
var formProbeClassCensus = map[string]int{
	"account":             16,
	"iam_user":            15,
	"iam_service_account": 9,
	"iam_group":           7,
	"project":             5,
	"iam_role":            3,
	"iam_access_binding":  3,
}

// formProbeCatalogRow — строка каталога прав, разобранная своим типом.
type formProbeCatalogRow struct {
	FQN              string `json:"fqn"`
	Permission       string `json:"permission"`
	RequiredRelation string `json:"required_relation"`
	ScopeFiltered    bool   `json:"scope_filtered"`
	ScopeExtractor   struct {
		ObjectType                 string `json:"object_type"`
		FromRequestField           string `json:"from_request_field"`
		ObjectTypeFromRequestField string `json:"object_type_from_request_field"`
	} `json:"scope_extractor"`
}

// formProbeCatalogClass — второй вывод класса: строки каталога с конкретным
// полем области (не пустым и не `*`), без поля вида области, не `scope_filtered`,
// не изъятые и с отношением, — пересечённые с публичным сервером корня. Строк
// каталога ноль — условие пробы не создано.
func formProbeCatalogClass(t *testing.T) []formProbeVerb {
	t.Helper()
	raw, err := os.ReadFile(formProbeCatalogPath)
	if err != nil {
		t.Fatalf("каталог прав не прочитан — второго вывода класса нет: %v", err)
	}
	var rows []formProbeCatalogRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("каталог прав не разобран: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("в каталоге прав ноль строк — второй вывод класса беспредметен")
	}
	public := formProbePublicMethods(t)
	var out []formProbeVerb
	for _, r := range rows {
		se := r.ScopeExtractor
		method := "/" + r.FQN
		if _, mounted := public[method]; !mounted ||
			se.FromRequestField == "" || se.FromRequestField == "*" || se.ObjectTypeFromRequestField != "" ||
			r.ScopeFiltered || r.Permission == formProbeExempt || r.RequiredRelation == "" {
			continue
		}
		out = append(out, formProbeVerb{method: method, field: se.FromRequestField, kind: se.ObjectType})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].method < out[j].method })
	return out
}

// formProbeDisagreement — расхождения двух выводов класса поглаголово: глагол
// одного вывода без другого либо с другим полем или видом. Пусто — сошлись.
func formProbeDisagreement(stage, catalog []formProbeVerb) []string {
	byMethod := func(vs []formProbeVerb) map[string]formProbeVerb {
		m := make(map[string]formProbeVerb, len(vs))
		for _, v := range vs {
			m[v.method] = v
		}
		return m
	}
	s, c := byMethod(stage), byMethod(catalog)
	var out []string
	for m, cv := range c {
		sv, ok := s[m]
		switch {
		case !ok:
			out = append(out, m+": в каталоге прав глагол класса, функция класса ступени его не выводит")
		case sv.field != cv.field || sv.kind != cv.kind:
			out = append(out, m+": ступень судит "+sv.kind+"@"+sv.field+", каталог объявляет "+cv.kind+"@"+cv.field)
		}
	}
	for m := range s {
		if _, ok := c[m]; !ok {
			out = append(out, m+": функция класса выводит глагол, которого в классе каталога прав нет")
		}
	}
	sort.Strings(out)
	return out
}

// formProbeCensusMismatch — расхождения переписи класса по видам с таблицей
// §11.2: по каждому виду таблицы и по каждому виду вне её.
func formProbeCensusMismatch(class []formProbeVerb) []string {
	got := map[string]int{}
	for _, v := range class {
		got[v.kind]++
	}
	var out []string
	for kind, want := range formProbeClassCensus {
		if got[kind] != want {
			out = append(out, "вид "+kind+": глаголов "+strconv.Itoa(got[kind])+", перепись §11.2 — "+strconv.Itoa(want))
		}
	}
	for kind, n := range got {
		if _, ok := formProbeClassCensus[kind]; !ok {
			out = append(out, "вид "+kind+": глаголов "+strconv.Itoa(n)+", в переписи §11.2 его нет")
		}
	}
	sort.Strings(out)
	return out
}

// formProbeUnion — объединение двух выводов по методу; поле и вид — каталога,
// если глагол в нём есть (расхождение называет `formProbeDisagreement`).
func formProbeUnion(stage, catalog []formProbeVerb) []formProbeVerb {
	seen := map[string]bool{}
	var out []formProbeVerb
	for _, vs := range [][]formProbeVerb{catalog, stage} {
		for _, v := range vs {
			if !seen[v.method] {
				seen[v.method] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].method < out[j].method })
	return out
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

func formProbeCaller(t *testing.T, in testPublicChainInputs) formProbeCall {
	t.Helper()
	decider := &formProbeDecider{}
	in.decider = decider
	chain := testPublicChain(t, in)
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
	call := formProbeCaller(t, testPublicChainInputs{reader: reader, catalog: catalog, prodMode: true})

	class, typedScope := formProbeClass(t)
	if len(class) == 0 {
		t.Fatal("в классе ноль глаголов — обход беспредметен, это не зелёное")
	}
	// Второй вывод — каталог прав: сужение функции класса видно сверкой, а
	// выпавший глагол всё равно гоняется — обход идёт по объединению.
	catalogClass := formProbeCatalogClass(t)
	if len(catalogClass) == 0 {
		t.Fatal("второй вывод класса (каталог прав) пуст — сверять не с чем, это не зелёное")
	}
	disagreement := formProbeDisagreement(class, catalogClass)
	var census []string
	for _, side := range []struct {
		name string
		vs   []formProbeVerb
	}{{"функция класса ступени", class}, {"каталог прав", catalogClass}} {
		for _, m := range formProbeCensusMismatch(side.vs) {
			census = append(census, side.name+": "+m)
		}
	}
	verbs := formProbeUnion(class, catalogClass)

	var (
		byKind       = map[string]int{}
		built        int
		unbuildable  []string
		findings     []string
		formAnswered int
	)
	for _, v := range verbs {
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
	anonCall := formProbeCaller(t, testPublicChainInputs{reader: reader, catalog: catalog, prodMode: false})
	// (в) пустое поле (KE-9): отсутствие — не неверная форма.
	for _, v := range verbs {
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
	t.Logf("перепись IAM-PNE-1-21 А: глаголов обойдено %d (%s) · функция класса ступени %d · каталог прав %d · "+
		"расхождений выводов %d · расхождений переписи по видам %d · вне класса с полем вида области %d · "+
		"построено %d · не построено %d · входов неверной формы отвечено ступенью %d из %d · находок %d · "+
		"контролей вне класса нарушено %d · проводка K6-N2 нарушений %d",
		len(verbs), strings.Join(kinds, ", "), len(class), len(catalogClass), len(disagreement), len(census),
		len(typedScope), built, len(unbuildable),
		formAnswered, 3*built, len(findings), len(controls), len(structural))

	if len(disagreement) > 0 {
		t.Errorf("два вывода класса расходятся (%d) — ступень судит не тот перечень, что объявлен каталогом:\n  %s",
			len(disagreement), strings.Join(disagreement, "\n  "))
	}
	if len(census) > 0 {
		t.Errorf("перепись класса по видам расходится с §11.2 (%d):\n  %s", len(census), strings.Join(census, "\n  "))
	}
	sort.Strings(unbuildable)
	if len(unbuildable) > 0 {
		t.Errorf("вердикта НЕТ (запрос не построен) у %d глаголов из %d — это не отказ ступени:\n  %s",
			len(unbuildable), len(verbs), strings.Join(unbuildable, "\n  "))
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
	var (
		read, calls int
		files       []*ast.File
	)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("исходник корня %s не разобран: %v", e.Name(), err)
		}
		read++
		files = append(files, f)
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
		return out
	}
	return append(out, formProbeChainReachesListener(files, name)...)
}

// formProbeChainInterceptors — куда обязан уехать каждый результат сборщика
// цепочки, по позиции: однократная полоса, затем потоковая.
var formProbeChainInterceptors = []string{"ChainUnaryInterceptor", "ChainStreamInterceptor"}

// formProbeChainReachesListener — собранная корнем цепочка доходит до
// слушателя: каждое присваивание результата сборщика name в не-тестовом коде
// раскрывается (`…`) в `grpc.ChainUnaryInterceptor` и `grpc.ChainStreamInterceptor`
// той же функции. Звено, собранное и выброшенное (`_`) либо подменённое другим
// перечнем, — нарушение: проба судила бы цепочку, которой слушатель не несёт.
// Перечень, раскрытый под тем же именем, но переписанный после сборки
// (`formProbeReassigned`), — то же нарушение. Присваиваний ноль — тоже
// нарушение: зов без результата не провязка.
func formProbeChainReachesListener(files []*ast.File, name string) []string {
	var (
		out      []string
		assigned int
	)
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Rhs) != 1 {
					return true
				}
				c, ok := as.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != name {
					return true
				}
				assigned++
				for i, interceptor := range formProbeChainInterceptors {
					var links string
					if i < len(as.Lhs) {
						if id, ok := as.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
							links = id.Name
						}
					}
					if links == "" || !formProbeSpreadInto(fn.Body, interceptor, links) {
						out = append(out, fn.Name.Name+": результат "+strconv.Itoa(i+1)+" сборщика "+name+
							" не раскрыт в grpc."+interceptor+" — цепочка собрана, но в слушатель не уезжает")
						continue
					}
					if where := formProbeReassigned(fn.Body, as, name, links); where != "" {
						out = append(out, fn.Name.Name+": результат "+strconv.Itoa(i+1)+" сборщика "+name+
							" ("+links+") переприсвоен после сборки ("+where+") — раскрывается уже не собранная цепочка")
					}
				}
				return true
			})
		}
	}
	if assigned == 0 {
		out = append(out, "результат "+name+" не присвоен ни в одной функции корня — до слушателя ему не дойти")
	}
	return out
}

// formProbeReassigned — пишется ли перечень links после его сборки assembly
// внутри body: первая такая запись строкой формы, либо пусто.
//
// Отказ — на ЛЮБУЮ запись после сборки, а не только «между сборкой и
// раскрытием»: в цикле либо замыкании запись, стоящая текстом после
// раскрытия, исполняется до следующего, и лексический порядок о порядке
// исполнения не говорит. Записью считаются: присваивание самому перечню
// (`=` и `:=` с ним в левой части, `+=`), его элементу (`links[i] =`), ключ и
// значение перебора (`for _, links = range`) и объявление того же имени
// (`var links = …`) — затенённое имя раскрывает уже не собранный перечень.
// Повторный вызов самого сборщика записью не считается: это сборка, а не
// подмена. Граница: запись через указатель (`p := &links; *p = …`) и
// передачу перечня функции, пишущей в его элементы, страж не видит — в корне
// таких форм нет, и цена их распознавания — разбор потока данных.
func formProbeReassigned(body *ast.BlockStmt, assembly *ast.AssignStmt, assembler, links string) string {
	root := func(e ast.Expr) string {
		for {
			switch x := e.(type) {
			case *ast.Ident:
				return x.Name
			case *ast.IndexExpr:
				e = x.X
			case *ast.ParenExpr:
				e = x.X
			default:
				return ""
			}
		}
	}
	isAssembly := func(rhs []ast.Expr) bool {
		if len(rhs) != 1 {
			return false
		}
		c, ok := rhs[0].(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := c.Fun.(*ast.Ident)
		return ok && id.Name == assembler
	}
	var where string
	ast.Inspect(body, func(n ast.Node) bool {
		if where != "" || n == nil || n.Pos() <= assembly.End() {
			return where == ""
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			if isAssembly(x.Rhs) {
				return true
			}
			for _, l := range x.Lhs {
				if root(l) == links {
					where = "присваивание " + x.Tok.String()
				}
			}
		case *ast.RangeStmt:
			if (x.Key != nil && root(x.Key) == links) || (x.Value != nil && root(x.Value) == links) {
				where = "перебор range"
			}
		case *ast.ValueSpec:
			for _, id := range x.Names {
				if id.Name == links {
					where = "объявление var"
				}
			}
		}
		return where == ""
	})
	return where
}

// formProbeSpreadInto — раскрывается ли перечень links в вызов interceptor
// внутри body: `<пакет>.<interceptor>(links...)`.
func formProbeSpreadInto(body *ast.BlockStmt, interceptor, links string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || c.Ellipsis == token.NoPos || len(c.Args) != 1 {
			return true
		}
		if sel, ok := c.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != interceptor {
			return true
		}
		if id, ok := c.Args[0].(*ast.Ident); ok && id.Name == links {
			found = true
		}
		return true
	})
	return found
}

// formProbeStreams — потоковый ли метод: по дескриптору контракта.
func formProbeStreams(method string) bool {
	trimmed := strings.TrimPrefix(method, "/")
	slash := strings.LastIndex(trimmed, "/")
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(trimmed[:slash]))
	if err != nil {
		return false
	}
	sd, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return false
	}
	md := sd.Methods().ByName(protoreflect.Name(trimmed[slash+1:]))
	return md != nil && (md.IsStreamingClient() || md.IsStreamingServer())
}

// formProbeStreamingVerbs — глаголы класса, идущие потоковой полосой.
func formProbeStreamingVerbs(class []formProbeVerb, streams func(string) bool) []string {
	var out []string
	for _, v := range class {
		if streams(v.method) {
			out = append(out, v.method)
		}
	}
	return out
}

// TestIAM_PNE_1_21_A_FormStageHasNoStreamLane — звено формы стоит только на
// однократной полосе публичного слушателя (условие KE-8 разбора, исход «Б»).
// Это верно, пока в классе нет потоковых глаголов; первый такой глагол обязан
// покраснить пробу, а не пройти мимо звена молча. Вторая половина — инъекция:
// тот же распознаватель на подставленном «потоковом» глаголе называет его.
func TestIAM_PNE_1_21_A_FormStageHasNoStreamLane(t *testing.T) {
	class, _ := formProbeClass(t)
	if len(class) == 0 {
		t.Fatal("в классе ноль глаголов — обход беспредметен, это не зелёное")
	}
	streaming := formProbeStreamingVerbs(class, formProbeStreams)
	t.Logf("перепись полосы потока: глаголов класса %d · потоковых среди них %d", len(class), len(streaming))
	if len(streaming) > 0 {
		t.Errorf("глаголы класса формы идут потоковой полосой, где звена формы нет (%d): %s — "+
			"провяжите звено формы на publicStream той же семантикой, что дверь",
			len(streaming), strings.Join(streaming, ", "))
	}
	t.Run("инъекция: потоковый глагол класса назван", func(t *testing.T) {
		victim := class[0].method
		got := formProbeStreamingVerbs(class, func(m string) bool { return m == victim })
		if len(got) != 1 || got[0] != victim {
			t.Fatalf("распознаватель не назвал подставленный потоковый глагол %s: %v", victim, got)
		}
	})
}

// TestIAM_PNE_1_21_A_ClassCrossCheckNamesANarrowedVerb — распознаватели сверки
// двух выводов и переписи по видам на синтетике: выпавший из функции класса
// глагол назван обоими, законный близнец (выводы равны, перепись по таблице)
// молчит. Сам класс сюда не читается — только форма, которую сверка судит.
func TestIAM_PNE_1_21_A_ClassCrossCheckNamesANarrowedVerb(t *testing.T) {
	var full []formProbeVerb
	for kind, n := range formProbeClassCensus {
		for i := 0; i < n; i++ {
			full = append(full, formProbeVerb{method: "/x." + kind + "/V" + strconv.Itoa(i), field: kind + "_id", kind: kind})
		}
	}
	if got := formProbeDisagreement(full, full); len(got) != 0 {
		t.Fatalf("близнец: равные выводы названы расходящимися: %v", got)
	}
	if got := formProbeCensusMismatch(full); len(got) != 0 {
		t.Fatalf("близнец: перепись по таблице названа расходящейся: %v", got)
	}
	victim := full[0]
	narrowed := full[1:]
	if got := formProbeDisagreement(narrowed, full); len(got) != 1 || !strings.HasPrefix(got[0], victim.method+":") {
		t.Fatalf("сверка не назвала глагол %s, выпавший из функции класса: %v", victim.method, got)
	}
	if got := formProbeCensusMismatch(narrowed); len(got) != 1 || !strings.Contains(got[0], "вид "+victim.kind+":") {
		t.Fatalf("перепись не назвала вид %s выпавшего глагола: %v", victim.kind, got)
	}
	if got := formProbeUnion(narrowed, full); len(got) != len(full) {
		t.Fatalf("объединение потеряло выпавший глагол: обойдено бы %d из %d", len(got), len(full))
	}
	moved := append([]formProbeVerb{{method: victim.method, field: "other_id", kind: victim.kind}}, narrowed...)
	if got := formProbeDisagreement(moved, full); len(got) != 1 || !strings.Contains(got[0], "@other_id") {
		t.Fatalf("сверка не назвала глагол с другим полем области: %v", got)
	}
}

// TestIAM_PNE_1_21_A_ChainReachesTheListenerInjection — страж «собранная
// цепочка доходит до слушателя» на синтетическом корне: законная проводка
// молчит, выброшенный, подменённый и переписанный после сборки результат
// названы; запись в соседнюю переменную той же сборки — молчит.
func TestIAM_PNE_1_21_A_ChainReachesTheListenerInjection(t *testing.T) {
	const (
		head         = "package main\nfunc serve() {\n"
		lawfulSpread = "srv(grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...))\n"
	)
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"законная проводка":     {"u, s, err := chain()\n_ = err\nsrv(grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...))\n", 0},
		"однократная выброшена": {"_, s, err := chain()\n_ = err\nsrv(grpc.ChainUnaryInterceptor(other...), grpc.ChainStreamInterceptor(s...))\n", 1},
		"обе подменены":         {"u, s, err := chain()\n_, _, _ = u, s, err\nsrv(grpc.ChainUnaryInterceptor(other...), grpc.ChainStreamInterceptor(other...))\n", 2},
		"результат не присвоен": {"chain()\n", 1},
		// Переприсваивание перечня после сборки — один факт против законной
		// проводки: раскрыт тот же идентификатор, но уже не собранный сборщиком.
		"однократная переприсвоена": {"u, s, err := chain()\n_ = err\nu = other\n" + lawfulSpread, 1},
		"потоковая дописана":        {"u, s, err := chain()\n_ = err\ns = append(s, extra)\n" + lawfulSpread, 1},
		"элемент подменён":          {"u, s, err := chain()\n_ = err\nu[0] = extra\n" + lawfulSpread, 1},
		"многозначное присваивание": {"u, s, err := chain()\n_ = err\nx, s := 1, other\n_ = x\n" + lawfulSpread, 1},
		"перебором по перечню":      {"u, s, err := chain()\n_ = err\nfor _, u = range lists {\n}\n" + lawfulSpread, 1},
		"затенена во вложенном блоке": {"u, s, err := chain()\n_ = err\nif ok {\nvar u = other\n" +
			lawfulSpread + "}\n", 1},
		"обе переприсвоены":           {"u, s, err := chain()\n_ = err\nu, s = other, other\n" + lawfulSpread, 2},
		"соседняя переменная — молчит": {"u, s, err := chain()\nerr = nil\n_ = err\n" + lawfulSpread, 0},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "root.go", head+tc.body+"}\n", 0)
			if err != nil {
				t.Fatalf("синтетический корень не разобран: %v", err)
			}
			if got := formProbeChainReachesListener([]*ast.File{f}, "chain"); len(got) != tc.want {
				t.Fatalf("нарушений %d, ожидалось %d: %v", len(got), tc.want, got)
			}
		})
	}
}
