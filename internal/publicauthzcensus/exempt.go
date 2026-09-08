// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus

// exempt.go — освобождение от пообъектного вопроса как ДОКАЗУЕМОЕ, а не
// объявленное.
//
// # Почему освобождение нельзя зачесть по слову
//
// Пока iam стоит за нашим краем, `<exempt>` означает «край не задаёт единичного
// вопроса», а не «вопроса не задаёт никто»: за краем остаётся аутентификация, а
// решение о доступе принимает либо обработчик, либо сама природа RPC (ответ ЕСТЬ
// вызывающий). Вынесенный в чужое облако iam края не имеет BY CONSTRUCTION —
// тогда освобождённый RPC, у которого на пути обслуживания решателя нет,
// отдаёт объект ЛЮБОМУ аутентифицированному вызывающему, а запись `<exempt>`
// в контракте выглядит принятым решением.
//
// Поэтому здесь спрашивается не «освобождён ли», а «кто решает вместо двери» —
// и ответ обязан быть найден НА ПУТИ ОБСЛУЖИВАНИЯ, а не в комментарии.
//
// # Причина освобождения ЧИТАЕТСЯ ИЗ ДЕСКРИПТОРОВ, а не из текста контракта
//
// Тот же источник, что у карты прав двери: аннотация `exempt_reason` метода,
// влинкованная в бинарь. Своё чтение `.proto` было бы вторым объявлением одного
// предмета — оно разошлось бы с дверью молча.
//
// # Каждой причине — СВОЯ форма решателя, и это не педантизм
//
// Общий перечень «любой из этих вызовов сойдёт» превратил бы гейт в форму без
// содержания: чтение личности вызывающего стоит на пути почти каждой мутации
// (аудит), и, будучи зачтённым за решателя, оно объявило бы доказанным
// освобождение, при котором решения не принимает никто.
//
//	HANDLER_DECIDES    — контракт заявил, что решает ОБРАБОТЧИК, потому что
//	                     объект вопроса вычисляется из запроса и статической
//	                     записи каталога для него не существует. Значит на пути
//	                     обязан быть ВОПРОС К МОДЕЛИ;
//	SELF_SERVICE       — объект ответа ЕСТЬ вызывающий (создаёт свой аккаунт,
//	                     читает себя). Спрашивать модель не о чем: другого
//	                     объекта нет. Значит на пути обязано быть СВЯЗЫВАНИЕ с
//	                     личностью вызывающего — иначе объект берётся из
//	                     запроса, и «self» перестаёт быть правдой;
//	INTERNAL_LISTENER  — контракт заявил, что RPC живёт на ВНУТРЕННЕМ слушателе.
//	                     На публичном такого не бывает: это либо ban #6
//	                     (внутренний метод на внешнем порту), либо неверная
//	                     причина. Находка by construction, никакой решатель её
//	                     не снимает.
//
// Вопрос к модели засчитывается и за SELF_SERVICE — он строго сильнее.
//
// # Что в перечень решателей НЕ входит, и почему
//
// `authzguard.RequireAuthenticated` / `IsAnonymous` — это аутентификация. Путь,
// который только их и задаёт, отдаёт объект любому вошедшему; зачесть их за
// решателя значило бы объявить доказанным ровно то состояние, ради которого
// гейт написан.
//
// Надзор администратора кластера (`IsClusterAdmin`, `IsClusterAdminE`) — РАННЕЕ
// РАЗРЕШЕНИЕ, а не решение: он отвечает «ты ли администратор всего», и путь,
// задающий только его, отдаёт объект постороннему. Соседняя перепись уже
// заплатила за этот урок — засчитав надзор, она перевела два RPC из находок в
// норму, ничего не изменив в коде.

import (
	"fmt"
	"go/ast"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	authzv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/iam/authz/v1"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// Причины освобождения, которые перепись умеет судить. Перечень ЗАКРЫТ:
// причина вне него уходит в «не разрешилось» — третью категорию, — а не в норму
// и не в находку.
const (
	reasonHandlerDecides   = "HANDLER_DECIDES"
	reasonSelfService      = "SELF_SERVICE"
	reasonInternalListener = "INTERNAL_LISTENER"
)

// modelQuestionCalls — вызовы, ЗАДАЮЩИЕ МОДЕЛИ вопрос о названном объекте.
//
// Перечень выведен из помощников собственной двери; четвёртая форма — прямой
// вопрос к порту отношений — распознаётся не именем, а формой вызова
// (см. isRelationPortQuestion).
var modelQuestionCalls = map[string]string{
	"authzguard.AllowsVGet":           "вопрос к модели",
	"authzguard.AllowsVerb":           "вопрос к модели",
	"authzguard.RequireScopeRelation": "вопрос к модели",
	"authzfilter.Visible":             "сужение выдачи по данным",
	"authzfilter.VisibleSet":          "сужение выдачи по данным",
}

// callerBindingCalls — вызовы, СВЯЗЫВАЮЩИЕ объект с личностью вызывающего.
//
// Это и есть решатель самообслуживания: другого объекта у такого RPC нет, и
// доступ решается тем, что объект берётся у вызывающего, а не из запроса.
var callerBindingCalls = map[string]string{
	"authzguard.IsSelf":                       "связывание с личностью вызывающего",
	"authzguard.RequireOwnerMatchesPrincipal": "связывание с личностью вызывающего",
	"authzguard.PrincipalUserID":              "связывание с личностью вызывающего",
	"operations.PrincipalFromContext":         "связывание с личностью вызывающего",
}

// modelQuestionMatcher — распознаватель вопроса к модели.
func modelQuestionMatcher(call *ast.CallExpr) string {
	if name, isQualified := qualifiedCallName(call.Fun); isQualified {
		if form, hit := modelQuestionCalls[name]; hit {
			return "решатель: " + name + " (" + form + ")"
		}
	}
	if isRelationPortQuestion(call) {
		return "решатель: порт отношений Check(ctx, субъект, отношение, объект)"
	}
	return ""
}

// ownershipScopedReadArity — (ctx, идентификатор, владелец): предикат владения
// стоит доводом ЗАПРОСА, а не проверкой после чтения.
const ownershipScopedReadArity = 3

// handlerDecidesMatcher — распознаватель решателя, требуемого причиной
// `HANDLER_DECIDES`.
//
// # Форм решателя ДВЕ, и вторая сильнее первой
//
// Первая — вопрос к модели: обработчик спрашивает «можно ли этому субъекту».
//
// Вторая — ЧТЕНИЕ, СУЖЕННОЕ ВЛАДЕЛЬЦЕМ: предикат владения уходит доводом в сам
// запрос к хранилищу (`GetOwned(ctx, id, owner)`), поэтому чужая строка не
// читается вовсе. Это строго сильнее вопроса после чтения: нет окна между
// «прочитал» и «проверил», и «есть, но не твоя» неотличимо от «нет такой» —
// то есть ответ не служит оракулом существования.
//
// Распознаватель, знающий только первую, МОЛЧИТ на второй: он не даёт ни
// красного, ни зелёного, а освобождённый RPC уезжает в «без двери», хотя его
// решатель на пути обслуживания есть и он крепче требуемого. Так и было со
// службой операций.
func handlerDecidesMatcher(call *ast.CallExpr) string {
	if ev := modelQuestionMatcher(call); ev != "" {
		return ev
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel || !strings.HasSuffix(sel.Sel.Name, "Owned") {
		return ""
	}
	if len(call.Args) < ownershipScopedReadArity {
		return ""
	}
	return "решатель: " + sel.Sel.Name + " (чтение, суженное владельцем: предикат " +
		"владения — довод запроса, а не проверка после чтения)"
}

// callerBindingMatcher — распознаватель связывания с личностью вызывающего.
//
// Вопрос к модели засчитывается и здесь: он строго сильнее связывания.
func callerBindingMatcher(call *ast.CallExpr) string {
	if ev := modelQuestionMatcher(call); ev != "" {
		return ev
	}
	if name, isQualified := qualifiedCallName(call.Fun); isQualified {
		if form, hit := callerBindingCalls[name]; hit {
			return "решатель: " + name + " (" + form + ")"
		}
	}
	return ""
}

// matcherForReason возвращает распознаватель решателя, требуемый причиной
// освобождения. Второй результат false означает, что причина перечню неизвестна
// и вердикта по ней нет.
func matcherForReason(reason string) (callMatcher, bool) {
	switch reason {
	case reasonHandlerDecides:
		return handlerDecidesMatcher, true
	case reasonSelfService:
		return callerBindingMatcher, true
	default:
		return nil, false
	}
}

// exemptReasons читает аннотацию `exempt_reason` у каждого метода тех же
// пакетов контракта, что поднимает собственная дверь.
//
// Пустая карта — ошибка, а не пустой обход: пакеты те же, что у карты прав, и
// если по ним не прочитано ни одного метода, значит дескрипторы не влинкованы,
// а перепись судила бы о дереве, которого нет.
func exemptReasons() (map[RPC]string, error) {
	out := map[RPC]string{}
	methods := 0
	for _, pkg := range authzguard.OwnDoorProtoPackages() {
		protoregistry.GlobalFiles.RangeFilesByPackage(protoreflect.FullName(pkg),
			func(fd protoreflect.FileDescriptor) bool {
				for i := 0; i < fd.Services().Len(); i++ {
					sd := fd.Services().Get(i)
					for j := 0; j < sd.Methods().Len(); j++ {
						md := sd.Methods().Get(j)
						methods++
						opts, ok := md.Options().(*descriptorpb.MethodOptions)
						if !ok {
							continue
						}
						reason, has := proto.GetExtension(opts, authzv1.E_ExemptReason).(string)
						if !has || reason == "" {
							continue
						}
						out[RPC{Service: string(sd.Name()), Method: string(md.Name())}] = reason
					}
				}
				return true
			})
	}
	if methods == 0 {
		return nil, fmt.Errorf("причины освобождения: по пакетам двери не прочитано ни одного метода — " +
			"дескрипторы не влинкованы")
	}
	return out, nil
}
