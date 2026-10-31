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
// её цепочку, объявлена вне тестовых файлов, её зовёт корень, и собранная
// цепочка доходит именно до ПУБЛИЧНОГО слушателя — сервера, на котором корень
// монтирует публичные службы и который обслуживает слушатель публичного адреса
// (`formProbeChainReachesListener`), — иначе она судила бы вторую проводку
// либо цепочку, уехавшую во внутренний слушатель.
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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
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

// formProbeSeededRole — действующий посеянный идентификатор системной роли:
// положительный близнец берётся из домена и проходит общую проверку формы.
const formProbeSeededRole = domain.SystemViewerRoleID

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

// formProbeFuncName — короткое имя функции прод-кода, как его пишет вызов в
// исходнике корня: по указателю на саму функцию, а не литералом, — переименование
// ломает сборку пробы, а не оставляет стража искать прежнее имя.
func formProbeFuncName(f any) string {
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer())
	if fn == nil {
		return ""
	}
	return fn.Name()[strings.LastIndex(fn.Name(), ".")+1:]
}

// formProbeRootAnchors — якоря стража провязки у настоящего корня, выведенные
// из функций и типов, которые корень зовёт: конструктор сервера, монтирование
// публичных служб (по нему же проба выводит класс — `formProbePublicMethods`),
// поле раздела API-сервера в конфигурации и его метод публичного адреса.
func formProbeRootAnchors(t *testing.T, assembler string) formProbeAnchors {
	t.Helper()
	an := formProbeAnchors{
		assembler:      assembler,
		newServer:      formProbeFuncName(grpcsrv.NewServer),
		registerPublic: formProbeFuncName(registerPublicServices),
		addrMethod:     formProbeFuncName(config.APIServerConfig.ListenAddress),
	}
	var fields []string
	root := reflect.TypeOf(config.Config{})
	for i := 0; i < root.NumField(); i++ {
		if root.Field(i).Type == reflect.TypeOf(config.APIServerConfig{}) {
			fields = append(fields, root.Field(i).Name)
		}
	}
	if len(fields) != 1 {
		t.Fatalf("раздел API-сервера в конфигурации корня — полей %d (%v), ожидалось одно: публичный адрес не опознать", len(fields), fields)
	}
	an.addrField = fields[0]
	if an.newServer == "" || an.registerPublic == "" || an.addrMethod == "" {
		t.Fatalf("якоря стража провязки не опознаны средой исполнения: %+v", an)
	}
	return an
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
	name := formProbeFuncName(publicChainUnderProbe)
	anchors := formProbeRootAnchors(t, name)
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
	return append(out, formProbeChainReachesListener(fset, files, anchors)...)
}

// formProbeChainInterceptors — куда обязан уехать каждый результат сборщика
// цепочки, по позиции: однократная полоса, затем потоковая.
var formProbeChainInterceptors = []string{"ChainUnaryInterceptor", "ChainStreamInterceptor"}

// formProbeInterceptorOptions — параметры gRPC-сервера, добавляющие звенья
// цепочки: сверх собранной корнем на публичном сервере их быть не должно.
var formProbeInterceptorOptions = map[string]bool{
	"UnaryInterceptor": true, "StreamInterceptor": true,
	"ChainUnaryInterceptor": true, "ChainStreamInterceptor": true,
}

// formProbeAnchors — имена для разрешения сборщика в области пакета корня и
// конструктора в пакете formProbeServerPackage; прочие якоря узнаются по имени. У
// настоящего корня они ВЫВОДЯТСЯ (`formProbeRootAnchors`), у синтетического —
// литералами таблицы инъекций.
type formProbeAnchors struct {
	assembler      string // сборщик цепочки публичного слушателя
	newServer      string // конструктор gRPC-сервера
	registerPublic string // монтирует публичные службы — по нему проба выводит класс
	addrField      string // поле раздела API-сервера в конфигурации корня
	addrMethod     string // метод раздела, отдающий публичный адрес
}

const formProbeServerPackage = "github.com/PRO-Robotech/corelib/grpcsrv"

// formProbeAnchorImports не читает зависимости. Пустой пакет конструктора
// сохраняет объект PkgName и путь импорта, включая алиасы; объектов его членов
// и их типов он не предоставляет. Остальные импорты остаются неразрешёнными.
type formProbeAnchorImports struct{}

func (formProbeAnchorImports) Import(path string) (*types.Package, error) {
	if path == formProbeServerPackage {
		pkg := types.NewPackage(path, "grpcsrv")
		pkg.MarkComplete()
		return pkg, nil
	}
	return nil, errors.New("страж провязки зависимостей не читает: " + path)
}

// formProbeChainReachesListener — собранная корнем цепочка доходит до
// ПУБЛИЧНОГО слушателя (K6-N2), а не просто раскрыта где-то в той же функции.
// По каждому результату сборщика `an.assembler` в не-тестовом коде страж
// связывает сборщик с объектом *types.Func области пакета корня, а перечни,
// сервер и слушатель — по тождеству локальных объектов (`go/types`). Конструктор
// узнаётся по объекту *types.PkgName квалификатора с путём formProbeServerPackage
// и имени члена: это происхождение импорта, не полная типизация внешнего API.
// Селекторы перехватчиков, Serve, Listen и публичного адреса, а также вызов
// регистрации служб по-прежнему узнаются по имени. Шаги проверки:
//
//  1. результат присвоен имени, и имя РОЖДЕНО этой сборкой (`:=`): перечень,
//     объявленный раньше, мог быть раскрыт или записан до неё (O01);
//  2. помимо сборки перечень употреблён РОВНО ОДИН раз — раскрытием (`…`) в
//     `grpc.ChainUnaryInterceptor` либо `grpc.ChainStreamInterceptor`; любое
//     другое употребление — запись (`=`, `+=`, элемент, перебор), второе имя
//     того же среза (O04), взятие адреса, передача функции — нарушение: через
//     него раскрывается уже не собранная цепочка. Одноимённый перечень другого
//     объекта — параметр (O02) или именованный результат (O05) замыкания,
//     затенение в блоке — не раскрытие собранного; имя, которое разбор типов
//     не связал ни с каким объектом, считается употреблением (`formProbeWiring`);
//  3. раскрытие — прямой довод конструктора сервера `an.newServer`;
//  4. сервер присвоен имени этой функции, и имя после этого не переписано и
//     адрес его не взят;
//  5. на этом сервере корень монтирует публичные службы (`an.registerPublic` —
//     та же функция, по которой проба выводит класс глаголов);
//  6. этот сервер обслуживает (`Serve`) слушатель, рождённый `net.Listen` на
//     адресе `<…>.<an.addrField>.<an.addrMethod>()`, и ни слушатель, ни адрес
//     после рождения не переписаны;
//  7. других звеньев (`grpc.UnaryInterceptor`, ещё одной `Chain…`) сервер не
//     несёт — ни вызовом доводом, ни именем, рождённым таким вызовом; довод-имя,
//     рождённое не в этой функции, — нарушение: что он несёт, не видно.
//
// Перестановка цепочек публичного и внутреннего серверов (O03), монтирования
// служб либо слушателей ломает шаги 5–6. Присваиваний сборщика ноль — тоже
// нарушение: зов без результата не провязка. На результат — одно нарушение,
// первое по пути: следующие шаги от предыдущего зависят.
//
// Граница — чего страж не видит, и чем это держится:
//   - что делает со своим результатом сам сборщик после возврата (хранит ссылку
//     на срез и пишет в неё позже) — страж судит употребления в корне, а не
//     тело сборщика; тело `publicListenerChain` сегодня — сборка срезов из
//     доводов и возврат, без горутин и сохранённых ссылок, и цепочку, которую
//     оно вернуло, исполняет сама проба;
//   - довод конструктора, рождённый в этой функции значением, которое лишь
//     возвращает параметр (`opt := wrap(grpc.UnaryInterceptor(x))`), шаг 7 не
//     раскрывает: судится вызов, рождающий имя, а не его доводы; в корне доводы
//     конструктора — раскрытия сборки и учётные данные слушателя;
//   - что `an.newServer` делает с переданными ему параметрами (фундамент
//     `corelib/grpcsrv`, его пробы) и какие службы монтирует `an.registerPublic`
//     (их судит проба: класс выводится из того же вызова);
//   - запись в переменную через отражение либо `unsafe` — в корне таких форм
//     нет, и разбор исходника их не различает в принципе;
//   - провязку вне функции, где стоит сборка: перечень, сервер, слушатель и
//     адрес обязаны жить в одной функции, иначе — нарушение «не раскрыт»,
//     «объявленный вне этой функции» либо «не обслуживает», а не молчание.
func formProbeChainReachesListener(fset *token.FileSet, files []*ast.File, an formProbeAnchors) []string {
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: formProbeAnchorImports{}, Error: func(error) {}}
	// Ошибки типов ожидаемы (зависимостей разбор не читает) и вердиктом не
	// являются: тождество объектов корня от них не зависит.
	pkg, _ := conf.Check("main", fset, files, info)
	if pkg == nil {
		return []string{"пакет корня не разобран — якорь сборщика не разрешён"}
	}
	assembler, ok := pkg.Scope().Lookup(an.assembler).(*types.Func)
	if !ok || assembler.Parent() != pkg.Scope() {
		return []string{"сборщик " + an.assembler + " не объявлен функцией пакета корня"}
	}
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
			w := newFormProbeWiring(fset, info, fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Rhs) != 1 {
					return true
				}
				call, ok := as.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				callee, ok := call.Fun.(*ast.Ident)
				if !ok || info.Uses[callee] != assembler {
					return true
				}
				assigned++
				for i, interceptor := range formProbeChainInterceptors {
					if why := w.linkProblem(as, i, interceptor, an); why != "" {
						out = append(out, fn.Name.Name+": результат "+strconv.Itoa(i+1)+" сборщика "+an.assembler+" "+why)
					}
				}
				return true
			})
		}
	}
	if assigned == 0 {
		out = append(out, "результат "+an.assembler+" не присвоен ни в одной функции корня — до слушателя ему не дойти")
	}
	return out
}

// formProbeCallee — написание имени вызываемого для диагностики и проверок
// формы остальных селекторов. Идентичность сборщика и конструктора им не судится.
func formProbeCallee(e ast.Expr) string {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// formProbeWiring — одна функция корня: родитель каждого узла и объявление и
// употребления каждого объекта внутри неё.
//
// unresolved — имена, которые разбор типов не связал ни с каким объектом. Это
// не редкость, а следствие импортёра без зависимостей: при неверном типе
// выражения перебора `go/types` не связывает переменные перебора
// (`for _, links = range <вызов чужого пакета>`). Такое имя того же написания,
// стоящее после рождения объекта, страж считает его употреблением — отказ по
// умолчанию, а не слепота. Имена полей и методов (`x.links`), ключи составных
// литералов и метки сюда не входят: переменной они не называют.
type formProbeWiring struct {
	fset       *token.FileSet
	info       *types.Info
	body       *ast.BlockStmt
	parent     map[ast.Node]ast.Node
	def        map[types.Object]*ast.Ident
	uses       map[types.Object][]*ast.Ident
	unresolved map[string][]*ast.Ident
}

func newFormProbeWiring(fset *token.FileSet, info *types.Info, body *ast.BlockStmt) *formProbeWiring {
	w := &formProbeWiring{fset: fset, info: info, body: body, parent: map[ast.Node]ast.Node{},
		def: map[types.Object]*ast.Ident{}, uses: map[types.Object][]*ast.Ident{},
		unresolved: map[string][]*ast.Ident{}}
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
			w.parent[n] = parent
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj, defined := info.Defs[id]
		if obj != nil {
			w.def[obj] = id
		}
		used, isUse := info.Uses[id]
		if used != nil {
			w.uses[used] = append(w.uses[used], id)
		}
		if !defined && !isUse && id.Name != "_" && !formProbeNamesNoVariable(parent, id) {
			w.unresolved[id.Name] = append(w.unresolved[id.Name], id)
		}
		return true
	})
	return w
}

// formProbeNamesNoVariable — имя стоит там, где переменной не называет: поле
// или метод селектора, ключ составного литерала, метка.
func formProbeNamesNoVariable(parent ast.Node, id *ast.Ident) bool {
	switch p := parent.(type) {
	case *ast.SelectorExpr:
		return p.Sel == id
	case *ast.KeyValueExpr:
		return p.Key == id
	case *ast.LabeledStmt, *ast.BranchStmt:
		return true
	}
	return false
}

// occurrences — употребления объекта в функции после позиции after: связанные
// разбором типов и несвязанные того же написания, в порядке исходника.
func (w *formProbeWiring) occurrences(obj types.Object, after token.Pos) []*ast.Ident {
	var out []*ast.Ident
	for _, id := range w.uses[obj] {
		if id.Pos() > after {
			out = append(out, id)
		}
	}
	for _, id := range w.unresolved[obj.Name()] {
		if id.Pos() > after {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pos() < out[j].Pos() })
	return out
}

// born — позиция, с которой объект живёт в функции; не объявлен в ней — ноль.
func (w *formProbeWiring) born(obj types.Object) token.Pos {
	if id := w.def[obj]; id != nil {
		return id.Pos()
	}
	return token.NoPos
}

func (w *formProbeWiring) line(n ast.Node) string {
	return "строка " + strconv.Itoa(w.fset.Position(n.Pos()).Line)
}

func (w *formProbeWiring) object(e ast.Expr) types.Object {
	id, ok := e.(*ast.Ident)
	if !ok {
		return nil
	}
	if obj := w.info.Defs[id]; obj != nil {
		return obj
	}
	return w.info.Uses[id]
}

// serverConstructor связывает квалификатор с импортом, а не с одноимённой
// местной переменной. Сам член пакета проверяется по имени: импортёр его API
// не загружает и объект *types.Func для этого члена не строит.
func (w *formProbeWiring) serverConstructor(c *ast.CallExpr, name string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	qualifier, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	pkg, ok := w.info.Uses[qualifier].(*types.PkgName)
	return ok && pkg.Imported().Path() == formProbeServerPackage
}

// spreadOf — раскрытие `<пакет>.<interceptor>(id...)` с ровно этим доводом.
func (w *formProbeWiring) spreadOf(id *ast.Ident, interceptor string) *ast.CallExpr {
	c, ok := w.parent[id].(*ast.CallExpr)
	if !ok || c.Ellipsis == token.NoPos || len(c.Args) != 1 || c.Args[0] != id {
		return nil
	}
	if sel, ok := c.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != interceptor {
		return nil
	}
	return c
}

// touch — как употреблён перечень помимо раскрытия: строкой для отказа.
func (w *formProbeWiring) touch(id *ast.Ident) string {
	how := "употребление"
	switch p := w.parent[id].(type) {
	case *ast.AssignStmt:
		how = "значение присваивания — второе имя того же среза"
		for _, l := range p.Lhs {
			if l == id {
				how = "присваивание " + p.Tok.String()
			}
		}
	case *ast.IndexExpr:
		how = "элемент"
		if as, ok := w.parent[p].(*ast.AssignStmt); ok {
			for _, l := range as.Lhs {
				if l == p {
					how = "запись элемента"
				}
			}
		}
	case *ast.UnaryExpr:
		if p.Op == token.AND {
			how = "взят адрес"
		}
	case *ast.CallExpr:
		how = "довод вызова " + formProbeCallee(p)
		if p.Ellipsis != token.NoPos {
			how = "раскрыт ещё раз в " + formProbeCallee(p)
		}
	case *ast.RangeStmt:
		how = "перебор range"
	case *ast.ValueSpec:
		how = "значение объявления var — второе имя того же среза"
	}
	return w.line(id) + ": " + how
}

// written — запись в объект после его рождения: присваивание (кроме except),
// взятие адреса, ключ или значение перебора. Пусто — не записан.
func (w *formProbeWiring) written(obj types.Object, except ast.Node) string {
	for _, u := range w.occurrences(obj, w.born(obj)) {
		switch p := w.parent[u].(type) {
		case *ast.AssignStmt:
			if ast.Node(p) == except {
				continue
			}
			for _, l := range p.Lhs {
				if l == u {
					return w.line(u) + ": присваивание " + p.Tok.String()
				}
			}
		case *ast.UnaryExpr:
			if p.Op == token.AND {
				return w.line(u) + ": взят адрес"
			}
		case *ast.RangeStmt:
			if p.Key == u || p.Value == u {
				return w.line(u) + ": перебор range"
			}
		}
	}
	return ""
}

// definition — выражение, которым объект рождён в этой функции (`:=` либо
// `var … = …`); nil — рождён не здесь либо без значения.
func (w *formProbeWiring) definition(obj types.Object) ast.Expr {
	id := w.def[obj]
	if id == nil {
		return nil
	}
	pick := func(names []ast.Expr, values []ast.Expr) ast.Expr {
		for i, n := range names {
			if n != id {
				continue
			}
			switch {
			case len(values) == len(names):
				return values[i]
			case len(values) == 1:
				return values[0]
			}
		}
		return nil
	}
	switch p := w.parent[id].(type) {
	case *ast.AssignStmt:
		if p.Tok == token.DEFINE {
			return pick(p.Lhs, p.Rhs)
		}
	case *ast.ValueSpec:
		names := make([]ast.Expr, len(p.Names))
		for i, n := range p.Names {
			names[i] = n
		}
		return pick(names, p.Values)
	}
	return nil
}

// linkProblem — путь результата i сборки as до публичного слушателя (шаги 1–6
// шапки `formProbeChainReachesListener`); первое нарушение строкой, либо пусто.
func (w *formProbeWiring) linkProblem(as *ast.AssignStmt, i int, interceptor string, an formProbeAnchors) string {
	var id *ast.Ident
	if i < len(as.Lhs) {
		id, _ = as.Lhs[i].(*ast.Ident)
	}
	if id == nil || id.Name == "_" {
		return "выброшен — цепочка собрана, но в слушатель не уезжает"
	}
	links := w.info.Defs[id]
	if links == nil {
		return "(" + id.Name + ") объявлен не этой сборкой (" + w.line(as) + ") — перечень, живший до неё, " +
			"мог быть раскрыт или записан раньше сборки"
	}
	// Шаг 2: одно употребление — раскрытие; всё прочее — нарушение.
	var (
		spread  *ast.CallExpr
		touched []string
	)
	for _, u := range w.occurrences(links, id.Pos()) {
		if c := w.spreadOf(u, interceptor); c != nil && spread == nil {
			spread = c
			continue
		}
		touched = append(touched, w.touch(u))
	}
	if len(touched) > 0 {
		return "(" + id.Name + ") после сборки употреблён не раскрытием (" + strings.Join(touched, "; ") +
			") — раскрывается уже не собранная цепочка"
	}
	if spread == nil {
		why := "(" + id.Name + ") не раскрыт в grpc." + interceptor + " — цепочка собрана, но в слушатель не уезжает"
		if shadow := w.shadowSpread(id.Name, interceptor); shadow != "" {
			why += "; раскрыт одноимённый, но другой перечень (" + shadow + ") — затенение имени"
		}
		return why
	}
	// Шаг 3: прямой довод конструктора сервера.
	srvCall, ok := w.parent[spread].(*ast.CallExpr)
	if !ok || !w.serverConstructor(srvCall, an.newServer) || !formProbeIsArg(srvCall, spread) {
		return "(" + id.Name + ") раскрыт не прямым доводом " + an.newServer + " (" + w.line(spread) +
			") — до какого слушателя он доходит, не доказать"
	}
	// Шаг 4: сервер присвоен имени этой функции и не переписан.
	var (
		srv       types.Object
		srvAssign ast.Node
	)
	switch p := w.parent[srvCall].(type) {
	case *ast.AssignStmt:
		if len(p.Lhs) == 1 && len(p.Rhs) == 1 {
			srv, srvAssign = w.object(p.Lhs[0]), p
		}
	case *ast.ValueSpec:
		if len(p.Names) == 1 && len(p.Values) == 1 {
			srv = w.info.Defs[p.Names[0]]
		}
	}
	if srv == nil || srv.Name() == "_" {
		return "попадает в сервер (" + w.line(srvCall) + "), не присвоенный имени, — до слушателя не проследить"
	}
	if w.def[srv] == nil {
		return "попадает в сервер " + srv.Name() + ", объявленный вне этой функции, — записи в него вне её страж не видит"
	}
	if where := w.written(srv, srvAssign); where != "" {
		return "попадает в сервер " + srv.Name() + ", переписанный после сборки (" + where +
			") — слушатель обслуживает уже другой сервер"
	}
	// Шаг 5: на нём монтируются публичные службы.
	if !w.registersOn(srv, an.registerPublic) {
		return "попадает в сервер " + srv.Name() + ", на котором корень НЕ монтирует публичные службы (" +
			an.registerPublic + ") — цепочка уезжает не в публичный сервер"
	}
	// Шаг 6: он обслуживает слушатель публичного адреса.
	if why := w.servesPublic(srv, an); why != "" {
		return "попадает в сервер " + srv.Name() + ", который " + why
	}
	// Шаг 7: других звеньев сервер не несёт — ни вызовом параметра доводом, ни
	// именем, рождённым таким вызовом в этой функции.
	assembled := map[types.Object]bool{}
	for _, l := range as.Lhs {
		if obj := w.object(l); obj != nil {
			assembled[obj] = true
		}
	}
	for _, a := range srvCall.Args {
		opt := a
		if _, isName := a.(*ast.Ident); isName {
			obj := w.object(a)
			if obj == nil || w.definition(obj) == nil {
				return "попадает в сервер " + srv.Name() + ", чей довод (" + w.line(a) + ") — имя, рождённое не в этой " +
					"функции: несёт ли он звенья цепочки, не видно"
			}
			opt = w.definition(obj)
		}
		c, ok := opt.(*ast.CallExpr)
		if !ok || !formProbeInterceptorOptions[formProbeCallee(c)] {
			continue
		}
		// Своё раскрытие и раскрытие другой полосы той же сборки — не лишние.
		if c == spread || (len(c.Args) == 1 && c.Ellipsis != token.NoPos && assembled[w.object(c.Args[0])]) {
			continue
		}
		return "попадает в сервер " + srv.Name() + ", который несёт сверх неё звенья (" + w.line(c) + ": grpc." +
			formProbeCallee(c) + ") — слушатель исполняет не ту цепочку, что судит проба"
	}
	return ""
}

// shadowSpread — раскрытие в interceptor одноимённого перечня ДРУГОГО объекта:
// где раскрыт и где объявлен; пусто — такого нет.
func (w *formProbeWiring) shadowSpread(name, interceptor string) string {
	var where string
	ast.Inspect(w.body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || where != "" || id.Name != name || w.spreadOf(id, interceptor) == nil {
			return where == ""
		}
		where = "раскрыт в " + w.line(id)
		if obj := w.object(id); obj != nil {
			if d := w.def[obj]; d != nil {
				where += ", объявлен в " + w.line(d)
				// Параметр и результат: имя → поле → перечень полей → тип функции.
				if _, ok := w.parent[w.parent[w.parent[d]]].(*ast.FuncType); ok {
					where += " параметром либо результатом замыкания"
				}
			}
		}
		return false
	})
	return where
}

// registersOn — монтирует ли вызов name службы на сервер srv: srv употреблён в
// первом доводе `name(…)` (прямо либо через обёртку допуска).
func (w *formProbeWiring) registersOn(srv types.Object, name string) bool {
	found := false
	ast.Inspect(w.body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if fn, ok := c.Fun.(*ast.Ident); !ok || fn.Name != name || len(c.Args) == 0 {
			return true
		}
		ast.Inspect(c.Args[0], func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok && w.object(id) == srv {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

// servesPublic — каждый `srv.Serve(l)` обслуживает слушатель публичного адреса,
// и такой вызов есть; иначе — почему нет.
func (w *formProbeWiring) servesPublic(srv types.Object, an formProbeAnchors) string {
	served := 0
	for _, u := range w.occurrences(srv, w.born(srv)) {
		sel, ok := w.parent[u].(*ast.SelectorExpr)
		if !ok || sel.X != u || sel.Sel.Name != "Serve" {
			continue
		}
		call, ok := w.parent[sel].(*ast.CallExpr)
		if !ok || call.Fun != sel || len(call.Args) != 1 {
			continue
		}
		served++
		if why := w.publicListener(call.Args[0], an); why != "" {
			return "обслуживает (" + w.line(call) + ") слушатель " + why
		}
	}
	if served == 0 {
		return "ни одним вызовом Serve не обслуживает слушатель — до публичного слушателя цепочка не доходит"
	}
	return ""
}

// publicListener — слушатель рождён `net.Listen` на публичном адресе и не
// переписан; иначе — почему нет.
func (w *formProbeWiring) publicListener(e ast.Expr, an formProbeAnchors) string {
	lis := w.object(e)
	if lis == nil {
		return "не именем — его адрес не проследить"
	}
	birth, ok := w.definition(lis).(*ast.CallExpr)
	if !ok || !formProbeIsNetListen(birth) {
		return lis.Name() + ", не рождённый net.Listen в этой функции, — его адрес не проследить"
	}
	if where := w.written(lis, nil); where != "" {
		return lis.Name() + ", переписанный после рождения (" + where + ")"
	}
	addr := birth.Args[1]
	if obj := w.object(addr); obj != nil {
		if where := w.written(obj, nil); where != "" {
			return lis.Name() + " на адресе " + obj.Name() + ", переписанном после рождения (" + where + ")"
		}
		addr = w.definition(obj)
	}
	if !formProbePublicAddr(addr, an) {
		return lis.Name() + " НЕ на публичном адресе (<…>." + an.addrField + "." + an.addrMethod +
			"()) — цепочка уезжает не в публичный слушатель"
	}
	return ""
}

// formProbeIsArg — e стоит доводом вызова c.
func formProbeIsArg(c *ast.CallExpr, e ast.Expr) bool {
	for _, a := range c.Args {
		if a == e {
			return true
		}
	}
	return false
}

// formProbeIsNetListen — вызов есть `net.Listen(<сеть>, <адрес>)`.
func formProbeIsNetListen(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Listen" || len(c.Args) != 2 {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "net"
}

// formProbePublicAddr — выражение есть `<…>.<addrField>.<addrMethod>()`.
func formProbePublicAddr(e ast.Expr, an formProbeAnchors) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok || len(c.Args) != 0 {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != an.addrMethod {
		return false
	}
	field, ok := sel.X.(*ast.SelectorExpr)
	return ok && field.Sel.Name == an.addrField
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

// formProbeLawfulRoot — синтетический корень с ДВУМЯ серверами, как у
// `runServe`: публичный (сборщик `chain`, публичные службы, публичный адрес) и
// внутренний (свой перечень `iu`/`is`, внутренние службы и адрес). Без второго
// сервера перестановку цепочек слушателей (O03) таблица различить не могла бы.
const formProbeLawfulRoot = `package main
import "github.com/PRO-Robotech/corelib/grpcsrv"
func chain() ([]X, []X, error) { return nil, nil, nil }
func serve() {
	pubCreds, inCreds := creds()
	u, s, err := chain()
	_ = err
	pub := grpcsrv.NewServer(pubCreds, grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...))
	in := grpcsrv.NewServer(inCreds, grpc.ChainUnaryInterceptor(iu...), grpc.ChainStreamInterceptor(is...))
	registerPublicServices(adm.Registrar(pub), svcs)
	registerInternalServices(adm.Registrar(in), svcs)
	addr := cfg.APIServer.ListenAddress()
	lis, err := net.Listen("tcp", addr)
	ilis, err := net.Listen("tcp", cfg.APIServer.InternalListenAddress())
	run(func() error { return pub.Serve(lis) })
	run(func() error { return in.Serve(ilis) })
}
`

// formProbeSyntheticAnchors — якоря синтетического корня.
var formProbeSyntheticAnchors = formProbeAnchors{
	assembler: "chain", newServer: "NewServer", registerPublic: "registerPublicServices",
	addrField: "APIServer", addrMethod: "ListenAddress",
}

// TestIAM_PNE_1_21_A_ChainReachesTheListenerInjection — страж «собранная
// цепочка доходит до ПУБЛИЧНОГО слушателя» на синтетическом корне. Каждая
// строка меняет законный корень ОДНОЙ правкой (замена фрагмента, который в
// корне встречается ровно один раз — иначе инъекция не применена и строка
// падает сама). Законные близнецы молчат; формы O01–O05 возврата
// check-verifier и прежние формы переприсваивания названы с причиной.
func TestIAM_PNE_1_21_A_ChainReachesTheListenerInjection(t *testing.T) {
	t.Run("настоящий корень", formProbeRootAnchorInjections)
	const (
		pubLine = "pub := grpcsrv.NewServer(pubCreds, grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...))"
		inLine  = "in := grpcsrv.NewServer(inCreds, grpc.ChainUnaryInterceptor(iu...), grpc.ChainStreamInterceptor(is...))"
		pubArgs = "grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...))"
		pubVar  = "var pub *grpc.Server\n\t"
		pubSet  = "pub = grpcsrv.NewServer(pubCreds, " + pubArgs
		after   = "_ = err\n"
	)
	type edit struct{ old, new string }
	for name, tc := range map[string]struct {
		edits []edit
		want  int
		// texts — причины: каждое нарушение называет одну из них, и каждая
		// названа хотя бы одним нарушением.
		texts []string
	}{
		"законная проводка — молчит": {nil, 0, nil},
		"законная: сервер объявлен var и присвоен = — молчит": {
			[]edit{{pubLine, pubVar + pubSet}}, 0, nil},
		"законная: сервер объявлен var со значением — молчит": {
			[]edit{{"pub := grpcsrv.NewServer(", "var pub = grpcsrv.NewServer("}}, 0, nil},
		"сервер объявлен вне функции": {
			[]edit{{"func serve() {", "var pub *grpc.Server\nfunc serve() {"}, {pubLine, pubSet}},
			2, []string{"объявленный вне этой функции"}},
		"законная: адрес прямым доводом Listen — молчит": {
			[]edit{{`net.Listen("tcp", addr)`, `net.Listen("tcp", cfg.APIServer.ListenAddress())`}}, 0, nil},
		"законная: соседняя переменная сборки записана — молчит": {
			[]edit{{after, "err = nil\n\t" + after}}, 0, nil},

		// O03 — слушатель не различался: перестановки внутри одной функции.
		"O03 цепочки публичного и внутреннего серверов переставлены": {
			[]edit{{pubLine, "pub := grpcsrv.NewServer(pubCreds, grpc.ChainUnaryInterceptor(iu...), grpc.ChainStreamInterceptor(is...))"},
				{inLine, "in := grpcsrv.NewServer(inCreds, " + pubArgs}},
			2, []string{"попадает в сервер in, на котором корень НЕ монтирует публичные службы"}},
		"O03 переставлена одна однократная полоса": {
			[]edit{{"(u...), grpc.ChainStreamInterceptor(s...))", "(iu...), grpc.ChainStreamInterceptor(s...))"},
				{"(iu...), grpc.ChainStreamInterceptor(is...))", "(u...), grpc.ChainStreamInterceptor(is...))"}},
			2, []string{"попадает в сервер in, на котором корень НЕ монтирует публичные службы", "несёт сверх неё звенья"}},
		"O03 публичные службы смонтированы на внутренний сервер": {
			[]edit{{"registerPublicServices(adm.Registrar(pub)", "registerPublicServices(adm.Registrar(in)"}},
			2, []string{"НЕ монтирует публичные службы (registerPublicServices)"}},
		"O03 слушатели серверов переставлены": {
			[]edit{{"pub.Serve(lis)", "pub.Serve(ilis)"}, {"in.Serve(ilis)", "in.Serve(lis)"}},
			2, []string{"слушатель ilis НЕ на публичном адресе"}},
		"O03 публичный слушатель открыт на внутреннем адресе": {
			[]edit{{"addr := cfg.APIServer.ListenAddress()", "addr := cfg.APIServer.InternalListenAddress()"}},
			2, []string{"НЕ на публичном адресе"}},
		"O03 публичный сервер не обслуживает ни одного слушателя": {
			[]edit{{"run(func() error { return pub.Serve(lis) })\n", ""}},
			2, []string{"ни одним вызовом Serve"}},
		"O03 звено доводом-именем, рождённым grpc.UnaryInterceptor": {
			[]edit{{"pub := grpcsrv.NewServer(", "bypass := grpc.UnaryInterceptor(x)\n\tpub := grpcsrv.NewServer("},
				{pubArgs, "grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...), bypass)"}},
			2, []string{"несёт сверх неё звенья"}},
		"довод конструктора — имя, рождённое вне функции": {
			[]edit{{"func serve() {", "var extra grpc.ServerOption\nfunc serve() {"},
				{pubArgs, "grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...), extra)"}},
			2, []string{"имя, рождённое не в этой функции"}},
		"O03 публичный сервер несёт сверх цепочки звено": {
			[]edit{{pubArgs, "grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(s...), grpc.UnaryInterceptor(bypass))"}},
			2, []string{"несёт сверх неё звенья"}},
		"O03 сервер переписан после сборки": {
			[]edit{{"registerInternalServices", "pub = in\n\tregisterInternalServices"}},
			2, []string{"переписанный после сборки"}},
		"O03 слушатель переписан после рождения": {
			[]edit{{"run(func() error { return pub.Serve(lis) })", "lis = ilis\n\trun(func() error { return pub.Serve(lis) })"}},
			2, []string{"переписанный после рождения"}},
		"раскрыт не прямым доводом конструктора сервера": {
			[]edit{{"pub := grpcsrv.NewServer(pubCreds, grpc.ChainUnaryInterceptor(u...),",
				"opt := grpc.ChainUnaryInterceptor(u...)\n\tpub := grpcsrv.NewServer(pubCreds, opt,"}},
			1, []string{"раскрыт не прямым доводом NewServer"}},

		// O01 — раскрытие до сборки: перечень объявлен раньше и раскрыт до неё.
		"O01 раскрытие до сборки": {
			[]edit{{"u, s, err := chain()\n\t_ = err\n\t" + pubLine,
				"var u, s []X\n\tvar err error\n\t" + pubLine + "\n\tu, s, err = chain()\n\t_ = err"}},
			2, []string{"объявлен не этой сборкой"}},
		// O02, O05 — одноимённый перечень замыкания (тот же класс, что var в блоке).
		"O02 параметр замыкания затеняет перечень": {
			[]edit{{pubLine, pubVar + "func(u []X) {\n\t\t" + pubSet + "\n\t}(other)"}},
			2, []string{"раскрыт одноимённый, но другой перечень", "несёт сверх неё звенья"}},
		"O05 именованный результат замыкания затеняет перечень": {
			[]edit{{pubLine, pubVar + "func() (u []X) {\n\t\t" + pubSet + "\n\t\treturn\n\t}()"}},
			2, []string{"параметром либо результатом замыкания", "несёт сверх неё звенья"}},
		"затенение объявлением var во вложенном блоке": {
			[]edit{{pubLine, pubVar + "if ok {\n\t\tvar u = other\n\t\t" + pubSet + "\n\t}"}},
			2, []string{"раскрыт одноимённый, но другой перечень", "несёт сверх неё звенья"}},
		// O04 — второе имя того же среза и родственные формы утечки.
		"O04 второе имя того же среза": {
			[]edit{{after, after + "\tv := u\n\tv[0] = extra\n"}},
			1, []string{"второе имя того же среза"}},
		"взят адрес перечня": {
			[]edit{{after, after + "\tp := &u\n\t(*p)[0] = extra\n"}},
			1, []string{"взят адрес"}},
		"перечень передан функции": {
			[]edit{{after, after + "\tmutate(s)\n"}},
			1, []string{"довод вызова mutate"}},
		"раскрыт ещё раз в другом сервере": {
			[]edit{{inLine, "in := grpcsrv.NewServer(inCreds, grpc.ChainUnaryInterceptor(u...), grpc.ChainStreamInterceptor(is...))"}},
			1, []string{"раскрыт ещё раз в ChainUnaryInterceptor"}},

		// Прежние формы: результат выброшен, подменён, переприсвоен.
		"однократная выброшена": {
			[]edit{{"u, s, err := chain()", "_, s, err := chain()"}}, 2, []string{"выброшен", "несёт сверх неё звенья"}},
		"обе подменены": {
			[]edit{{pubArgs, "grpc.ChainUnaryInterceptor(other...), grpc.ChainStreamInterceptor(other...))"}},
			2, []string{"не раскрыт в grpc."}},
		"результат не присвоен": {
			[]edit{{"u, s, err := chain()", "chain()"}}, 1, []string{"не присвоен ни в одной функции"}},
		"однократная переприсвоена": {
			[]edit{{after, after + "\tu = other\n"}}, 1, []string{"присваивание ="}},
		"потоковая дописана": {
			[]edit{{after, after + "\ts = append(s, extra)\n"}}, 1, []string{"присваивание ="}},
		"элемент подменён": {
			[]edit{{after, after + "\tu[0] = extra\n"}}, 1, []string{"запись элемента"}},
		"многозначное присваивание": {
			[]edit{{after, after + "\tx, s := 1, other\n\t_ = x\n"}}, 1, []string{"присваивание :="}},
		"перебором по перечню": {
			[]edit{{after, after + "\tfor _, u = range lists {\n\t}\n"}}, 1, []string{"перебор range"}},
		"обе переприсвоены": {
			[]edit{{after, after + "\tu, s = other, other\n"}}, 2, []string{"присваивание ="}},
	} {
		t.Run(name, func(t *testing.T) {
			src := formProbeLawfulRoot
			for _, e := range tc.edits {
				if n := strings.Count(src, e.old); n != 1 {
					t.Fatalf("инъекция не применена: фрагмент %q в корне встречается %d раз, ожидался 1", e.old, n)
				}
				src = strings.Replace(src, e.old, e.new, 1)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "root.go", src, 0)
			if err != nil {
				t.Fatalf("синтетический корень не разобран: %v\n%s", err, src)
			}
			got := formProbeChainReachesListener(fset, []*ast.File{f}, formProbeSyntheticAnchors)
			if len(got) != tc.want {
				t.Fatalf("нарушений %d, ожидалось %d: %v", len(got), tc.want, got)
			}
			named := map[string]bool{}
			for _, g := range got {
				matched := false
				for _, text := range tc.texts {
					if strings.Contains(g, text) {
						matched, named[text] = true, true
					}
				}
				if !matched {
					t.Errorf("нарушение не называет ни одной из причин %q: %s", tc.texts, g)
				}
			}
			for _, text := range tc.texts {
				if !named[text] {
					t.Errorf("причину %q не назвало ни одно нарушение: %v", text, got)
				}
			}
			if tc.want > 0 {
				t.Logf("%s", strings.Join(got, "\n"))
			}
		})
	}
}
