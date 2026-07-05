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
var allowedProxyRelations = map[string]struct{}{
	"project": {},
	"account": {},
	"parent":  {},
	"owner":   {},
}

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
// на префикс FGA-object-домена, которым реально владеют его ресурсы. Большинство
// модулей совпадают с собственным именем (vpc→`vpc_*`, compute→`compute_*`), но
// kacho-nlb владеет доменом loadbalancer, чьи FGA-object-типы префиксуются `lb_`
// (lb_network_load_balancer / lb_listener / lb_target_group), НЕ `nlb_`. Без этого
// маппинга verified-SAN domain-binding отвергал бы все owner-tuple nlb → LB-ресурсы
// становились невидимы в authz-filtered List.
var moduleObjectDomain = map[string]string{
	"nlb": "lb",
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
// пишет owner-hierarchy tuple ТОЛЬКО на объект своего домена. callerDomain — svc
// из verified mTLS SAN (vpc/compute/nlb); пустой (dev-mode, домен неизвестен)
// отключает domain-binding, но relation-allowlist и forbidden-object-type
// действуют всегда. Любое нарушение → PermissionDenied (fail-closed, без leak).
func ValidateProxyTuple(callerDomain, subject, relation, object string) error {
	relation = strings.TrimSpace(relation)
	object = strings.TrimSpace(object)
	if relation == "" || object == "" {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if _, ok := allowedProxyRelations[relation]; !ok {
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
	// compute→`compute_*`, nlb→`lb_*`). Пустой callerDomain (dev-mode) пропускает
	// эту проверку, но forbidden-set + relation-allowlist выше все равно держат
	// границу против cluster/iam/privilege.
	if callerDomain != "" && !strings.HasPrefix(objType, objectDomainForCaller(callerDomain)+"_") {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}
