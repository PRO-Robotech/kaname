// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_every_gated_rpc_test.go — парная проба «край снят → отказ» НА КАЖДЫЙ
// пообъектный RPC, а не на один показательный.
//
// # Зачем перебор, если соседняя проба уже показала механизм
//
// Соседний файл доказывает, что дверь УМЕЕТ отказать и умеет пропустить, — на
// одном RPC. Этого достаточно для механизма и недостаточно для поверхности:
// вынесенный iam отдаёт арендатору десятки глаголов, и вопрос «а этот тоже за
// дверью?» задаётся по каждому. Перепись публичной поверхности отвечает на него
// СТАТИЧЕСКИ (запись в карте есть), здесь — ПОВЕДЕНЧЕСКИ: дверь позвана, модель
// спрошена, посторонний не дошёл до обработчика.
//
// # Перечень ВЫВОДИТСЯ из карты, а не выписывается
//
// Выписанный перечень был бы вторым объявлением того же предмета: новый
// пообъектный RPC в него не попал бы, и проба осталась бы зелёной ровно там,
// где появилась непроверенная дверь.
//
// # Положительный близнец — НА КАЖДЫЙ RPC, и он выводится из отказа
//
// Отрицание без положительного зеленело бы на двери, отвергающей всех: она
// прошла бы этот перебор целиком, сломав продукт. Поэтому по каждому RPC
// берётся тройка, которую дверь СПРОСИЛА на отказе, она разрешается — и тот же
// вызов обязан пройти. Тройка не сочиняется: сочинённая разошлась бы с
// извлечением области и дала бы ложное «дверь не пропускает выданному».
//
// # Третья категория названа отдельно
//
// RPC, чей запрос не удалось построить так, чтобы извлечение области
// разрешилось, вердикта НЕ имеет — ни отказа, ни пропуска. Такие считаются
// отдельно и печатаются поимённо: «ноль находок» обязано быть отличимо от «ноль
// проверенного».

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	authzv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/iam/authz/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/pkg/authz/catalogderive"
)

// probeID — правдоподобный идентификатор области, подставляемый в запрос.
//
// Форма взята у настоящих идентификаторов платформы: извлечение области у части
// RPC проверяет форму, и «x» отвергалось бы разбором, а не дверью, — тогда
// вердикт относился бы к валидатору, а не к двери.
const probeID = "prj00000000000000042"

func TestOwnDoor_EveryObjectScopedRPCRefusesAStranger(t *testing.T) {
	m, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	if err != nil {
		t.Fatalf("карта прав не выведена: %v", err)
	}
	if len(m) == 0 {
		t.Fatal("карта пуста — вердикт беспредметен")
	}

	// delegated — RPC, у которых дверь снимается ЦЕЛИКОМ: вопрос о правах решает
	// обработчик (`api/authorize/caller_authority.go`), единственный полный
	// решатель «кто вправе спрашивать». Перебор их не судит — не как послабление,
	// а потому что предмет у него другой: он спрашивает «держит ли ДВЕРЬ этот
	// пообъектный RPC», а дверь этих RPC не держит по решению.
	//
	// Множество берётся у САМОЙ двери, а не выписывается здесь: выписанное было
	// бы вторым объявлением того же предмета и разошлось бы с поправкой звена
	// молча — ровно там, где расхождение невидимо. Отсюда же самоистечение:
	// снимут запись из поправки — RPC вернётся в перебор сам.
	delegated := make(map[string]struct{})
	for _, full := range authzguard.CallerAuthorityGatedMethods() {
		delegated[full] = struct{}{}
	}

	var (
		objectScoped  int
		refused       int
		admitted      int
		delegatedSeen int
		unbuildable   []string
		findings      []string
	)

	methods := make([]string, 0, len(m))
	for full := range m {
		methods = append(methods, full)
	}
	sort.Strings(methods)

	for _, full := range methods {
		entry := m[full]
		if entry.Public || entry.ScopeFiltered || entry.Relation == "" || entry.Extract == nil {
			continue
		}
		if _, handlerDecides := delegated[full]; handlerDecides {
			// Считается ОТДЕЛЬНО и печатается в переписи: «не судили» обязано быть
			// отличимо от «судили и прошло», иначе знаменатель молча уменьшался бы.
			delegatedSeen++
			continue
		}
		objectScoped++

		req, built := buildScopedRequest(t, full)
		if !built {
			unbuildable = append(unbuildable, full)
			continue
		}
		objType, objID, xerr := entry.Extract(req)
		switch {
		case xerr != nil:
			unbuildable = append(unbuildable, full+" (извлечение области: "+xerr.Error()+")")
			continue
		case objType == "" || objID == "":
			// Область не назвалась: вид или идентификатор пусты. Вердикта нет —
			// дверь спросила бы модель о пустом объекте, и её ответ относился бы
			// к фикстуре, а не к двери.
			unbuildable = append(unbuildable, full+" (область не назвалась: вид "+
				quoted(objType)+", идентификатор "+quoted(objID)+")")
			continue
		}

		// ОТРИЦАНИЕ: постороннему не выдано ничего.
		denyStore := &grantStore{allow: map[string]bool{}}
		hit := false
		_, derr := doorUnder(t, denyStore)(
			tenantCtx(strangerUser), req,
			&grpc.UnaryServerInfo{FullMethod: full}, reached(&hit),
		)
		switch {
		case hit:
			findings = append(findings, full+": обработчик достигнут посторонним")
			continue
		case derr == nil:
			findings = append(findings, full+": отказа нет")
			continue
		case len(denyStore.asked) == 0:
			findings = append(findings, full+": модель не спрошена — отказ вынесен не по объекту")
			continue
		}
		refused++

		// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: разрешаем ровно ту тройку, которую дверь
		// спросила, — и тот же вызов обязан пройти.
		grantStoreForRPC := &grantStore{allow: map[string]bool{denyStore.asked[0]: true}}
		passed := false
		_, aerr := doorUnder(t, grantStoreForRPC)(
			tenantCtx(strangerUser), req,
			&grpc.UnaryServerInfo{FullMethod: full}, reached(&passed),
		)
		if aerr != nil || !passed {
			findings = append(findings,
				full+": выданному отказано ("+errText(aerr)+"), спрошено "+denyStore.asked[0])
			continue
		}
		admitted++
	}

	sort.Strings(unbuildable)
	t.Logf("перепись: записей карты %d · пообъектных %d · отказано постороннему %d · "+
		"пропущено выданному %d · запрос не построен %d · решает обработчик %d · находок %d",
		len(m), objectScoped, refused, admitted, len(unbuildable), delegatedSeen, len(findings))

	if objectScoped == 0 {
		t.Fatal("пообъектных RPC в карте ноль — перебор беспредметен")
	}
	if len(unbuildable) > 0 {
		t.Logf("вердикта НЕТ (запрос не построен) у %d:\n  %s",
			len(unbuildable), strings.Join(unbuildable, "\n  "))
	}
	if refused == 0 || admitted == 0 {
		t.Fatalf("одна из сторон пары пуста (отказано %d, пропущено %d): "+
			"перебор утверждал бы лишь половину", refused, admitted)
	}
	// Категории обязаны покрывать пообъектные RPC ЦЕЛИКОМ. Без этого RPC,
	// выпавший из перебора по недосмотру, не попал бы ни в находки, ни в третью
	// категорию — и знаменатель рос бы, а числитель нет, что со стороны
	// выглядит как улучшение.
	if refused+len(unbuildable)+len(findings) != objectScoped {
		t.Fatalf("категории не покрывают пообъектные RPC: отказано %d + без вердикта %d + "+
			"находок %d != %d — часть RPC не посчитана нигде",
			refused, len(unbuildable), len(findings), objectScoped)
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Errorf("дверь не держит %d пообъектных RPC из %d:\n  %s",
			len(findings), objectScoped, strings.Join(findings, "\n  "))
	}
}

func quoted(s string) string { return "«" + s + "»" }

func errText(err error) string {
	if err == nil {
		return "<без ошибки>"
	}
	return err.Error()
}

// buildScopedRequest строит запрос RPC так, чтобы извлечение области
// разрешилось: поле, названное аннотацией, заполняется идентификатором, а поле
// вида области — объявленным статическим значением.
//
// Второй результат false означает «не построен»: у RPC нет аннотации области,
// названного поля не существует либо оно не строковое. Это третья категория, а
// не находка.
func buildScopedRequest(t *testing.T, fullMethod string) (any, bool) {
	t.Helper()
	md, ok := methodDescriptor(fullMethod)
	if !ok {
		return nil, false
	}
	opts, ok := md.Options().(*descriptorpb.MethodOptions)
	if !ok {
		return nil, false
	}
	scope, ok := proto.GetExtension(opts, authzv1.E_ScopeExtractor).(*authzv1.ScopeExtractor)
	if !ok || scope == nil {
		return nil, false
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(md.Input().FullName())
	if err != nil {
		return nil, false
	}
	msg := mt.New()
	fields := msg.Descriptor().Fields()

	// Поля области может не быть вовсе: у RPC с ЯКОРЕМ-КОНСТАНТОЙ (кластер)
	// извлечение статично и работает на пустом запросе. Требовать поле здесь
	// значило бы вывести из-под перебора всю кластерную полосу — 27 RPC, — и
	// перепись назвала бы это «не построен», хотя строить нечего.
	// «*» — объявленное «запрос области не несёт»: либо кластерный синглтон,
	// либо объект, которого вызывающий не называет. Поля с таким именем не
	// существует by construction, и искать его значило бы вывести из-под
	// перебора всю эту полосу.
	if name := scope.GetFromRequestField(); name != "" && name != catalogderive.WildcardField {
		idField := fields.ByName(protoreflect.Name(name))
		if idField == nil || idField.Kind() != protoreflect.StringKind || idField.IsList() {
			return nil, false
		}
		msg.Set(idField, protoreflect.ValueOfString(probeID))
	}

	if name := scope.GetObjectTypeFromRequestField(); name != "" {
		typeField := fields.ByName(protoreflect.Name(name))
		if typeField == nil || typeField.Kind() != protoreflect.StringKind || typeField.IsList() {
			return nil, false
		}
		// Статическое значение аннотации — объявленное умолчание того же поля,
		// поэтому подстановка не выдумывает вид области, а повторяет её.
		msg.Set(typeField, protoreflect.ValueOfString(scope.GetObjectType()))
	}
	return msg.Interface(), true
}

// methodDescriptor находит дескриптор метода по полному имени вида
// «/пакет.Служба/Метод».
func methodDescriptor(fullMethod string) (protoreflect.MethodDescriptor, bool) {
	trimmed := strings.TrimPrefix(fullMethod, "/")
	slash := strings.LastIndex(trimmed, "/")
	if slash < 0 {
		return nil, false
	}
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
	return md, true
}
