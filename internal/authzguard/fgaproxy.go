// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fgaproxy.go — the FGA-proxy authz gate.
//
// RegisterResource / UnregisterResource carry `permission = "<exempt>"` in the
// proto catalog (like every Internal IAM RPC), so least-privilege is NOT
// expressed as a flat permission-string. It is enforced HERE as ReBAC:
//
//  1. The mTLS client-cert SAN (SPIRE format
//     spiffe://<trust-domain>/ns/<ns>/sa/kacho-<svc>, extracted by SEC-B's
//     grpcsrv.CertIdentityFromContext under the domain the installation
//     declared) is recognized against the installation's module roster
//     (moduleidentity.Roster, kaname#984 — only a DECLARED namespace/account
//     pair is a module) and mapped to a deterministic
//     ServiceAccount id (`'sva' || substr(md5('kacho-<svc>'),1,17)`).
//  2. A ReBAC Check `service_account:<sva>#fga_writer@cluster:cluster_root`
//     is issued. ALLOW → the RPC proceeds; DENY → PermissionDenied. Право
//     выдаётся системной выдачей на кластере (kacho#914) — оно видно перечислением
//     выдач и закрывается отзывом.
//
// Fail-closed: an unverified peer, a malformed / foreign-trust-domain SAN, an
// unknown SA, or a denied relation all collapse to PermissionDenied. The
// service→service (mTLS-SA) path never consults `required_acr_min` — ACR-floor
// is a user-token concern only; the gate decides purely on the
// ReBAC relation.
package authzguard

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

const (
	// RelationWriteRelation — отношение, которое обязана держать служебная учётка
	// модуля, чтобы писать кортежи через iam. Экспортировано намеренно: пробы и
	// перепись обязаны спрашивать ТО ЖЕ имя, которое спрашивает гейт, — имя,
	// выписанное на стороне пробы, остаётся зелёным, когда гейт спрашивает другое.
	RelationWriteRelation = "fga_writer"
	// relationWriteObject — объект, на котором спрашивается право писать
	// кортежи. Это ПЛАТФОРМЕННЫЙ СИНГЛТОН кластера — тот же, на котором стоят
	// кластерные выдачи (`clusterRootObject`, system_viewer_floor.go).
	//
	// Прежде здесь стоял якорь вне иерархии `cluster → account → project`.
	// У такого якоря нет ни яруса, ни владельца: право не выражалось выдачей,
	// не было видно перечислением выдач и не отзывалось (kacho#914, решение 1 в
	// `docs/engineering/architecture/grant-surface-boundaries.md`).
	// Фактический доступ переезд не расширяет: модуль и прежде писал кортежи по
	// всему кластеру — честнее стало ОБЪЯВЛЕНИЕ этого права.
	relationWriteObject = clusterRootObject

	// svcNamePrefix — приставка учётки модуля (`kacho-<svc>`). Объявлена у
	// разбора личности (`moduleidentity.AccountPrefix`): выводом имени службы из
	// учётки и формулой идентификатора служебной учётки правит одна величина.
	svcNamePrefix = moduleidentity.AccountPrefix
	// saPrefix — приставка идентификатора служебной учётки.
	//
	// Объявлена именем, а не вписана в формулу литералом: круговая сверка с
	// посевом (module_identity_seed_test.go) читает её ОТСЮДА, и вписанный
	// литерал был бы вторым местом об одном предмете — с тем же исходом, ради
	// которого сверка и заведена.
	saPrefix = "sva"
)

// RelationWriteGate authorizes RegisterResource / UnregisterResource via ReBAC.
// It reuses the package RelationChecker port (scope.go) — the same FGA
// `Check(subject, relation, object)` surface used by the scope guard, satisfied
// directly by clients.RelationStore (no extra adapter at the composition root).
type RelationWriteGate struct {
	checker RelationChecker
	// prodMode = production AuthN mode. In dev-mode (false) an insecure peer
	// with no verified client-cert is allowed (backward-compat);
	// in production-mode (true) the gate is strictly fail-closed.
	prodMode bool
	// modules — личности модулей установки (kaname#984). Нулевое значение не
	// признаёт никого.
	modules moduleidentity.Roster
}

// WithModuleRoster подставляет перечень личностей модулей установки: писать
// отношения вправе только объявленная пара, и домен записи — имя службы её
// учётки.
func (g *RelationWriteGate) WithModuleRoster(r moduleidentity.Roster) *RelationWriteGate {
	g.modules = r
	return g
}

// NewRelationWriteGate — constructor. Defaults to dev-mode (backward-compat); use
// WithProductionMode to enable strict fail-closed enforcement.
func NewRelationWriteGate(checker RelationChecker) *RelationWriteGate {
	return &RelationWriteGate{checker: checker}
}

// WithProductionMode toggles strict fail-closed enforcement (production AuthN).
func (g *RelationWriteGate) WithProductionMode(prod bool) *RelationWriteGate {
	g.prodMode = prod
	return g
}

// Authorize returns nil iff the verified mTLS client-cert resolves to a module
// ServiceAccount holding `fga_writer` on `cluster:cluster_root`. Every other
// outcome is PermissionDenied (fail-closed). Message text is the fixed,
// non-leaking `"permission denied"`.
// Authorize проверяет, что caller — модульная SA с `fga_writer@cluster:cluster_root`,
// и возвращает ее домен (vpc/compute/nlb) для object-type binding на write-path.
// Dev-mode без cert → ("", nil): домен неизвестен, domain-binding в ValidateProxyTuple
// отключается, но relation-allowlist и forbidden-object-type там действуют всегда.
func (g *RelationWriteGate) Authorize(ctx context.Context) (string, error) {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		if !g.prodMode {
			// Dev-mode backward-compat: insecure listener, no mTLS cert,
			// anonymous → allow. Production-mode is strictly fail-closed.
			return "", nil
		}
		// Production-mode: unverified peer or no module identity → never trusted.
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	// Признание — объявленная пара перечня (kaname#984): лист нашего домена с
	// учёткой модуля из необъявленного пространства модулем не является.
	module, ok := g.modules.FromContext(ctx)
	if !ok {
		// Malformed / foreign-trust-domain / undeclared SAN → not a module identity.
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	domain := module.Service
	if g.checker == nil {
		// ReBAC backend not wired → fail-closed (never silently allow).
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	allowed, err := g.checker.Check(ctx, "service_account:"+ServiceAccountIDForService(domain), RelationWriteRelation, relationWriteObject)
	if err != nil {
		// Backend failure (FGA 5xx / network drop / ErrNotConfigured) is NOT an
		// authorization decision — it is a transient outage. Surfacing it as
		// Unavailable (retryable, fail-closed) lets the caller retry; collapsing
		// it to PermissionDenied would make the drainer poison a legitimate
		// owner-tuple intent. The raw backend error is logged-not-leaked.
		return "", AuthzBackendUnavailable()
	}
	if !allowed {
		// Explicit deny: Check succeeded and returned allowed==false (the SA holds
		// no fga_writer relation). Genuine authorization decision → fail-closed.
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return domain, nil
}

// ServiceAccountIDForService derives the deterministic module SA id from a
// service short-name (`'sva' || substr(md5('kacho-<svc>'),1,17)`). Single
// source of truth shared by the gate and the seed migration helper.
//
// Формула ОДНА на дерево и живёт в `domain.DerivedIDSuffix`: своя копия здесь
// разошлась бы с постгресовой молча — полученный идентификатор остался бы
// синтаксически верным и перестал бы находить строку.
func ServiceAccountIDForService(svc string) string {
	return saPrefix + domain.DerivedIDSuffix(svcNamePrefix+svc)
}
