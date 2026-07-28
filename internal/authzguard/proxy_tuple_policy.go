// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// proxy_tuple_policy.go — least-privilege guard for the FGA-proxy write-path.
//
// RegisterResource / UnregisterResource / WriteCreatorTuple let a resource-owning
// module (vpc/compute/nlb) write an owner-hierarchy FGA tuple THROUGH iam. The
// cert-bound gate (RelationWriteGate) authorizes WHO may use the proxy; this
// policy constrains WHAT they may write, so a single over-broad (or compromised)
// module SA cannot mint a privilege tuple (relation=system_admin object=cluster:…)
// and escalate to cluster-admin everywhere.
package authzguard

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// allowedProxyRelations — owner-hierarchy relations, которые модуль вправе писать
// через proxy. ТОЛЬКО ownership/parent-связи: `project`/`account`/`parent` (ресурс
// принадлежит scope) и `owner` (creator-tuple). Privilege relations
// (`system_admin`/`admin`/`editor`/`viewer`/`v_*`/`fga_writer`/`use`) намеренно
// отсутствуют — их выписывает только AccessBinding-флоу, не модульный proxy.
// Исключение — публикация ресурса для анонимного чтения, см.
// publicReadRelation/publicReadSubject ниже: там сужение идёт по СУБЪЕКТУ.
var allowedProxyRelations = map[string]struct{}{
	"project": {},
	"account": {},
	"parent":  {},
	"owner":   {},
}

// publicReadRelation / publicReadSubject — единственная НЕ-иерархическая пара,
// которую proxy принимает: «этот ресурс модуля читает кто угодно».
//
// Публичность ресурса выражается именно tuple'ом: у kacho-registry
// `user:* #v_get @registry_repository:<reg>/<repo>` — это НЕ отдельный флаг, а
// сам факт видимости для анонимного pull. Без этой пары намерение эмитируется,
// но принимающей стороной отвергается целиком, и публичного репозитория не
// существует ни при каком раскладе (эмиссия ≠ применение — контракт принимающей
// стороны, `data-integrity.md`).
//
// Сужение идёт по субъекту, а не по relation: подстановочный `user:*` не называет
// НИ ОДНОГО конкретного получателя, поэтому модуль по-прежнему не может выдать
// чтение конкретному пользователю/SA — такая выдача остаётся за AccessBinding,
// где она перечислима, ограничена scope'ом и отзываема. Все прочие ограничения
// (домен объекта, forbidden-типы) действуют без изменений.
const (
	publicReadRelation = "v_get"
	publicReadSubject  = "user:*"
)

// forbiddenProxyObjectTypes — типы объектов, которые НИКОГДА не являются ресурсом
// модуля и поэтому не могут быть объектом proxy-tuple: платформенный `cluster` и
// сущности домена iam. Запрещены даже в dev-mode (где домен caller неизвестен),
// чтобы выписать tuple на `cluster`/iam-объект было нельзя ни при каком раскладе.
var forbiddenProxyObjectTypes = map[string]struct{}{
	"cluster":         {},
	"account":         {},
	"project":         {},
	"user":            {},
	"service_account": {},
	"group":           {},
	"role":            {},
}

// moduleObjectDomain маппит service-short-name модуля (из mTLS SAN, напр. "nlb")
// на префикс FGA-object-домена, которым реально владеют его ресурсы, КОГДА он
// расходится с service-именем. По умолчанию (пустая карта) домен = service-имя:
// vpc→`vpc_*`, compute→`compute_*`, nlb→`nlb_*` (после NLB-1a hard-rename FGA
// object-типы kacho-nlb — `nlb_network_load_balancer` / `nlb_listener` /
// `nlb_target_group` — совпадают с SAN-именем "nlb", поэтому исключение больше не
// нужно). Карта сохранена как extension-point для будущего модуля, чей FGA-домен
// разойдётся с его SAN short-name.
var moduleObjectDomain = map[string]string{}

// proxyRelationAllowed — вправе ли модуль писать пару (subject, relation).
// Иерархические relation'ы — с любым субъектом; публикация для анонимного чтения
// (`v_get`) — ТОЛЬКО с подстановочным субъектом `user:*`, чтобы модуль не мог
// выдать чтение названному пользователю в обход AccessBinding.
func proxyRelationAllowed(subject, relation string) bool {
	if _, ok := allowedProxyRelations[relation]; ok {
		return true
	}
	return IsPublicReadGrant(subject, relation)
}

// IsPublicReadGrant — это пара «ресурс читает кто угодно» (`user:* #v_get`)?
//
// Отличается от иерархических intent'ов принципиально: она НЕ описывает состояние
// ресурса (нет ни родительского scope'а, ни labels) — она только открывает чтение.
// Поэтому приёмная сторона обязана применить её как ЧИСТЫЙ tuple и не трогать
// проекцию ресурса: register иначе затрёт родительский scope пустым, а unregister
// удалит строку проекции живого ресурса (см. RegisterResourceUseCase).
// Экспортируется, чтобы у политики и у пути применения был ОДИН предикат.
func IsPublicReadGrant(subject, relation string) bool {
	return strings.TrimSpace(relation) == publicReadRelation &&
		strings.TrimSpace(subject) == publicReadSubject
}

// objectDomainForCaller — object-домен, которым модуль вправе владеть. По умолчанию
// совпадает с service-именем; исключения — в moduleObjectDomain.
func objectDomainForCaller(callerDomain string) string {
	if d, ok := moduleObjectDomain[callerDomain]; ok {
		return d
	}
	return callerDomain
}

// ValidateProxyTuple ограничивает FGA-proxy write-path до least-privilege: модуль
// пишет owner-hierarchy tuple (плюс публикацию для анонимного чтения — см.
// publicReadRelation) ТОЛЬКО на объект своего домена. callerDomain — svc
// из verified mTLS SAN (vpc/compute/nlb/registry); пустой (dev-mode, домен
// неизвестен) отключает domain-binding, но relation-allowlist, subject-сужение
// публикации и forbidden-object-type действуют всегда. Любое нарушение →
// PermissionDenied (fail-closed, без leak).
func ValidateProxyTuple(callerDomain, subject, relation, object string) error {
	subject = strings.TrimSpace(subject)
	relation = strings.TrimSpace(relation)
	object = strings.TrimSpace(object)
	if relation == "" || object == "" {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if !proxyRelationAllowed(subject, relation) {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	colon := strings.IndexByte(object, ':')
	if colon <= 0 || colon == len(object)-1 {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	objType := object[:colon]
	if _, bad := forbiddenProxyObjectTypes[objType]; bad {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// Domain-binding: объект обязан принадлежать домену caller (vpc→`vpc_*`,
	// compute→`compute_*`, nlb→`nlb_*`). Пустой callerDomain (dev-mode) пропускает
	// эту проверку, но forbidden-set + relation-allowlist выше все равно держат
	// границу против cluster/iam/privilege.
	if callerDomain != "" && !strings.HasPrefix(objType, objectDomainForCaller(callerDomain)+"_") {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}
