// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// address_gate.go — РУБЕЖ ПОЛОЖЕНИЯ ПОДТВЕРЖДЕНИЯ на обоих слушателях службы
// (задача PRO-Robotech/kaname#456; приёмка
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// решения Р3, Р4б, Р4в).
//
// # Предмет
//
// Метод, чей действующий принципал — человек с неподтверждённым адресом,
// отвечает отказом положения (Р3) ДО разбора аргументов и до решения по
// методу. Порядок как у аутентификации: «может ли принципал действовать
// вообще» решается раньше «верен ли вход» и раньше «чего недостаёт» (пола
// системного читателя, пола ступени подтверждения личности, анти-анонима,
// двери решения и обработчика). Место в цепочке — сразу после политики
// вызывающего, на обоих слушателях и на обеих полосах (однократный вызов и
// поток); его держит проба композиционного корня.
//
// # Кто человек — строка людей, а не утверждение
//
// Действующий принципал — тот, кого назвала цепочка личности слушателя. Вид
// его рубеж НЕ берёт ни из утверждения токена, ни из переданного заголовка:
// идентификатор судится предикатом допуска по строкам людей (`admission.ID`).
// Модуль, служебная учётная запись, системный принципал строки человека не
// имеют — рубеж молчит, и их вопросы о праве человека судит дверь решения.
//
// # Исходов три
//
// Допущен · не допущен (отказ Р3) · спросить не смогли — отказ операции
// `UNAVAILABLE`, а не проход: «не прочли отметку» не значит «подтверждён».
//
// # Внутренний слушатель — таблица ЗАКРЫТА (Р4в)
//
// На внутреннем слушателе рубеж стоит на методах КРУГА КРАЯ
// (`GatewayFrontedInternalRPCs`), которые край зовёт от лица человека; снятие
// собственного удостоверения (`Revoke` о себе) доступно — это выход. Прочие
// методы внутренних служб объявлены таблицей вне круга, каждый с доводом.
// Метод круга без строки и строка без метода — находка гейта
// (`TestInternalAddressGateTablesAreClosed`).

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/admission"
)

// TextAddressGateUnavailable — отказ операции, когда отметку прочесть не
// смогли: фиксированный текст, без эха причины.
const TextAddressGateUnavailable = "request not performed; try again later"

// InternalGateRow — строка таблицы Р4в: что рубеж делает на методе внутреннего
// слушателя.
type InternalGateRow int

const (
	// GateRefuses — метод круга края: отказ Р3 неподтверждённому человеку.
	GateRefuses InternalGateRow = iota + 1
	// GateAllowsSelfRevoke — снятие собственного удостоверения доступно
	// (`user_id` — сам принципал); о другом человеке — отказ Р3.
	GateAllowsSelfRevoke
	// GateOutsideCircle — метод вне круга края: рубежа нет, довод — у строки.
	GateOutsideCircle
)

// InternalAddressGateRow — строка таблицы с доводом.
type InternalAddressGateRow struct {
	Row    InternalGateRow
	Reason string
}

const (
	svcCluster     = "/kaname.cloud.iam.v1.InternalClusterService/"
	svcInteractive = "/kaname.cloud.iam.v1.InternalInteractiveClientService/"
	svcModule      = "/kaname.cloud.iam.v1.InternalModuleService/"
	svcIAM         = "/kaname.cloud.iam.v1.InternalIAMService/"
	svcOperations  = "/kaname.cloud.iam.v1.InternalOperationsService/"
	svcRevocations = "/kaname.cloud.iam.v1.InternalSessionRevocationsService/"
	svcUser        = "/kaname.cloud.iam.v1.InternalUserService/"
	svcHumanSess   = "/kaname.cloud.iam.v1.InternalHumanSessionService/"
	svcBootstrap   = "/kaname.cloud.iam.v1.InternalBootstrapTokenService/"
	svcNotifyGrant = "/kaname.cloud.iam.v1.InternalNotificationGrantService/"
	svcRecipients  = "/kaname.cloud.iam.v1.InternalNotificationRecipientService/"
)

// internalAddressGateTable — таблицы Р4в: 18 строк круга и 18 вне круга.
var internalAddressGateTable = map[string]InternalAddressGateRow{
	// ── круг края (18) ──
	svcRevocations + "Revoke": {GateAllowsSelfRevoke,
		"снятие собственного удостоверения есть выход (Р2) и доступа не прибавляет; о другом человеке — не выход"},
	svcRevocations + "ListByUser": {GateRefuses,
		"чтение о себе решается без вопроса к модели, и дверь решения его не видит; видит рубеж"},
	svcCluster + "GrantAdmin":           {GateRefuses, "действие распорядителя облака"},
	svcCluster + "RevokeAdmin":          {GateRefuses, "действие распорядителя облака"},
	svcCluster + "ListAdmins":           {GateRefuses, "чтение распорядителя облака"},
	svcCluster + "Get":                  {GateRefuses, "чтение распорядителя облака"},
	svcInteractive + "Get":              {GateRefuses, "клиенты церемонии — действие распорядителя"},
	svcInteractive + "List":             {GateRefuses, "клиенты церемонии — действие распорядителя"},
	svcInteractive + "Create":           {GateRefuses, "клиенты церемонии — действие распорядителя"},
	svcInteractive + "Update":           {GateRefuses, "клиенты церемонии — действие распорядителя"},
	svcInteractive + "Delete":           {GateRefuses, "клиенты церемонии — действие распорядителя"},
	svcModule + "Plan":                  {GateRefuses, "модули платформы — действие распорядителя"},
	svcModule + "Apply":                 {GateRefuses, "модули платформы — действие распорядителя"},
	svcModule + "Get":                   {GateRefuses, "модули платформы — чтение распорядителя"},
	svcModule + "List":                  {GateRefuses, "модули платформы — чтение распорядителя"},
	svcIAM + "ForceLogout":              {GateRefuses, "принудительный выход другого человека — действие распорядителя"},
	svcOperations + "ListIamOperations": {GateRefuses, "операции службы — чтение распорядителя"},
	svcUser + "UpsertFromIdentity": {GateRefuses,
		"от лица человека — отказ; без принципала-человека (обратный вызов поставщика от имени системы) рубеж молчит, исход судит правило приглашения"},

	// ── вне круга (18) ──
	svcIAM + "Check": {GateOutsideCircle,
		"вопрос о праве субъекта, названного в запросе: ответ судит допуск под дверью решения — неподтверждённому «нет»"},
	svcIAM + "LookupSubject": {GateOutsideCircle,
		"поиск субъекта: ответ — идентичность, а не право; право найденного судит дверь решения"},
	svcHumanSess + "Resolve": {GateOutsideCircle,
		"разбор сессии краем: отдаёт отметку, на нём стоит экран «подтвердите почту»"},
	svcRevocations + "IsRevoked": {GateOutsideCircle,
		"вопрос об отзыве: доступа он не прибавляет"},
	svcRevocations + "SessionCutoffOf": {GateOutsideCircle,
		"вопрос об отсечке: доступа он не прибавляет"},
	svcIAM + "ResolveBasicCredential": {GateOutsideCircle,
		"дверь базового секрета: её судит правило выдачи, причина owner-unverified"},
	svcIAM + "CheckBasicCredentialLive": {GateOutsideCircle,
		"дверь базового секрета: её судит правило выдачи, причина owner-unverified"},
	svcBootstrap + "MintBootstrapToken": {GateOutsideCircle,
		"выпуск удостоверения первого администратора: принципал выпуска — служебная учётная запись"},
	svcIAM + "GetRoleCompiled": {GateOutsideCircle,
		"справочник модели: о человеке не говорит"},
	svcIAM + "PollSubjectChanges": {GateOutsideCircle,
		"поток изменений субъектов: доставляет изменения, о доступе не решает"},
	svcIAM + "RegisterResource": {GateOutsideCircle,
		"запись материализации модуля: ресурс, заведённый человеком, прошёл вопрос о праве у модуля; записанное отношение неподтверждённому права не даёт; рубеж остановил бы очередь модуля"},
	svcIAM + "UnregisterResource": {GateOutsideCircle,
		"запись материализации модуля: тот же довод, что у записи"},
	svcIAM + "CurrentAuthzRevision": {GateOutsideCircle,
		"токен версии прав для модуля-владельца вида (NTF-3 Р30): снимок транзакций, а не право; круг судит дверь регистрации обработчика"},
	svcUser + "Get": {GateOutsideCircle,
		"чтение строки человека краем: ответ — строка, а не право"},
	// Служба выдачи права на письма (NTF-1, kaname#484): контракт без REST-привязки, края-маршрута нет,
	// поэтому в круг края методы не входят. Попадёт метод в круг — строка переходит туда же.
	svcNotifyGrant + "ResolveSend": {GateOutsideCircle,
		"решение о письме для службы notify: вызывающий — служебный принципал по сертификату, человека на пути нет; право решает обработчик вопросом reader к модели"},
	svcNotifyGrant + "Revoke": {GateOutsideCircle,
		"рычаг оператора над выдачей: маршрута края нет, человек-принципал до метода не доходит; право system_admin судит путь обслуживания, который заводит K3"},
	svcNotifyGrant + "Restore": {GateOutsideCircle,
		"рычаг оператора над выдачей: тот же довод, что у Revoke"},
	svcRecipients + "Resolve": {GateOutsideCircle,
		"справочник адресов для службы notify (NTF-3 Р7): вызывающий — служебный принципал по сертификату, маршрута края нет; право решает обработчик вопросом reader на справочник к модели"},
	svcRecipients + "ListProjectAudience": {GateOutsideCircle,
		"справочник адресов: тот же довод, что у Resolve"},
}

// InternalAddressGateTable — таблицы Р4в копией: метод → строка.
func InternalAddressGateTable() map[string]InternalAddressGateRow {
	out := make(map[string]InternalAddressGateRow, len(internalAddressGateTable))
	for k, v := range internalAddressGateTable {
		out[k] = v
	}
	return out
}

// AddressGate — рубеж; ОДНО значение на оба слушателя. Метод, объявленный
// таблицей Р4в (методы внутренних служб контракта), судится её строкой; всякий
// прочий смонтированный метод — публичных служб и служб фундамента — судится
// как на публичном слушателе: отказ Р3 неподтверждённому человеку (Р4б).
type AddressGate struct {
	marks admission.Marks
	// onRefusal — клетка отказа положения на диагностической поверхности; nil —
	// не считается.
	onRefusal func()
}

// WithRefusalObserver — приёмник отказа положения (клетка счётчика): отказ,
// невидимый снаружи иначе чем ответом вызывающему, считается.
func (g *AddressGate) WithRefusalObserver(on func()) *AddressGate {
	g.onRefusal = on
	return g
}

// NewAddressGate — рубеж над читателем отметок; домен отказа — у объявления
// (`refusaldomain`).
func NewAddressGate(marks admission.Marks) *AddressGate {
	return &AddressGate{marks: marks}
}

// selfTarget — запрос, называющий человека, о котором действие (`user_id`).
type selfTarget interface{ GetUserId() string }

// judge — исход рубежа для метода и запроса. req — nil у потока: действие о
// себе потоком не выражается, и на потоке строка «о себе» судится как отказ.
func (g *AddressGate) judge(ctx context.Context, fullMethod string, req any) error {
	if g == nil {
		return nil
	}
	p, ok := operations.PrincipalFromContextOK(ctx)
	if !ok || p.ID == "" {
		// Принципала нет: судить нечего; анонима отсекает анти-аноним.
		return nil
	}
	if row, declared := internalAddressGateTable[fullMethod]; declared {
		switch row.Row {
		case GateOutsideCircle:
			// Вне круга рубежа нет (Р4в): довод — у строки таблицы.
			return nil
		case GateAllowsSelfRevoke:
			if t, isTarget := req.(selfTarget); isTarget && t.GetUserId() == p.ID {
				return nil
			}
		}
	}
	admitted, err := admission.ID(ctx, g.marks, p.ID)
	if err != nil {
		return status.Error(codes.Unavailable, TextAddressGateUnavailable)
	}
	if !admitted {
		if g.onRefusal != nil {
			g.onRefusal()
		}
		return admission.RefusalStatus()
	}
	return nil
}

// Unary — однократная полоса.
func (g *AddressGate) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := g.judge(ctx, info.FullMethod, req); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream — потоковая полоса.
func (g *AddressGate) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := g.judge(ss.Context(), info.FullMethod, nil); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// InternalAddressGateFindings — сверка таблиц Р4в с двумя производителями
// (§9 п. 5 приёмки): кругом края (`GatewayFrontedInternalRPCs`) и перечнем
// методов внутренних служб контракта. Находки — строками с координатой:
// метод круга без строки круга, метод внутренней службы без строки ни в одной
// таблице, строка без метода. Пустой перечень любого производителя — находка:
// пустой обход не вердикт.
func InternalAddressGateFindings(circle, internalMethods []string, table map[string]InternalAddressGateRow) []string {
	var out []string
	if len(circle) == 0 {
		out = append(out, "круг края пуст — сверять таблицу круга не с чем")
	}
	if len(internalMethods) == 0 {
		out = append(out, "перечень методов внутренних служб пуст — сверять таблицу вне круга не с чем")
	}
	inCircle := make(map[string]bool, len(circle))
	for _, m := range circle {
		inCircle[m] = true
		row, ok := table[m]
		switch {
		case !ok:
			out = append(out, m+": метод круга края без строки таблицы Р4в")
		case row.Row == GateOutsideCircle:
			out = append(out, m+": метод круга края объявлен строкой вне круга")
		}
	}
	known := make(map[string]bool, len(internalMethods))
	for _, m := range internalMethods {
		known[m] = true
		if inCircle[m] {
			continue
		}
		row, ok := table[m]
		switch {
		case !ok:
			out = append(out, m+": метод внутренней службы без строки ни в одной таблице Р4в")
		case row.Row != GateOutsideCircle:
			out = append(out, m+": метод вне круга края объявлен строкой круга")
		}
	}
	for m, row := range table {
		if !known[m] && !inCircle[m] {
			out = append(out, m+": строка таблицы Р4в без метода")
		}
		if row.Reason == "" {
			out = append(out, m+": строка таблицы Р4в без довода")
		}
	}
	return out
}
