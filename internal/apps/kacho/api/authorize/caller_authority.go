// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// caller_authority.go — the authority gate for
// AuthorizeService.{Check,BatchCheck,ListObjects,ListSubjects,ExpandRelations}.
//
// It is NOT an inner second opinion behind a narrower outer one. The proto
// comment on these RPCs says the gateway admits only callers holding
// `iam.subjects.checkAuthorization` on the subject/resource; there is no such
// permission in the catalog and no such relation in the model. What the catalog
// actually asks for all four public RPCs is `viewer` on the cluster singleton —
// and the cluster bootstrap deliberately grants that relation to `user:*`, so
// the global reference catalog (regions, zones, disk types) is readable by
// anyone authenticated. Every authenticated subject therefore answers the
// gateway's question, and this file is the ONLY thing deciding who may ask the
// service "may subject X do Y to object Z", enumerate the objects a subject can
// reach, or enumerate the subjects that can reach an object. Without it these
// RPCs are an authorization oracle over every tenant (CWE-863 / CWE-862).
//
// Scope of the gate — only TENANT-facing principals (user / service_account)
// are gated. Anonymous / system principals are the cluster-internal
// verified-mTLS module PDP peer calls (kacho-vpc / kacho-compute / kacho-nlb
// on :9091): their authz contract is "a verified module MAY query authz
// decisions" (NOT "the module has access to the objects"), gated by the
// internal listener's CallerPolicy verified-cert floor — see
// cmd/kacho-iam/grpc_register.go. Gating them here would break every peer PDP
// query, so they pass through and the outer cert floor governs them.

package authorize

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
)

// callerAuthorityRelations — FGA relations on the queried resource that grant a
// tenant caller the authority to ask authz questions about OTHER subjects on
// that resource (delegated administration). `admin` is the canonical resource
// authority and, today, the only one the model defines for this purpose.
//
// It used to also carry `checkAuthorization`, "mirroring the gateway's documented
// relation". No such relation exists in the canonical model, so that arm could
// only ever Check-error and be skipped: a branch documenting a contract the
// system never produces, paid for with a second FGA round-trip on every denial.
// If delegated "may ask about others" is wanted as its own grantable authority
// (rather than riding on `admin`), it has to be declared in
// proto/kacho/cloud/iam/v1/fga_model.fga first — then added here.
var callerAuthorityRelations = []string{"admin"}

// authorizeCaller is the inner defense-in-depth gate. It returns nil (allow) when:
//
//   - the ctx principal is anonymous / system (module PDP peer call — outer
//     cert floor governs); OR
//   - the ctx principal (a user / service_account) IS the queried `subject`
//     (self-query); OR
//   - the ctx principal is a cluster-admin (flat super-gate); OR
//   - the ctx principal holds a resource-authority relation on `res`.
//
// Otherwise it returns PermissionDenied with a fixed, redacted message. `subject`
// may be "" (ListSubjects / ExpandRelations carry no subject arg — then only the
// cluster-admin / resource-authority arms apply). `res` may be nil (ListObjects
// has no single resource — then only self-query / cluster-admin apply).
//
// Fail-closed on every degraded mode (nil checker, Check transport error): a
// tenant principal that cannot prove authority is denied, never allowed.
//
// ОТКАЗЫ РАЗНЫЕ, И РАЗЛИЧИЕ НАЗЫВАЕТСЯ КОДОМ (#665). Отказ в правах говорит
// вызывающему «повтор бессмыслен»: решение зависит от тройки (субъект,
// отношение, объект), и одинаковый повтор не меняет ни одного из трёх. Если же
// хотя бы один заданный вопрос остался БЕЗ ОТВЕТА (хранилище отношений не
// отвечает), о правах не сказано ничего, и ответом идёт `Unavailable` — тот же
// код, которым этот же обработчик отвечает на недоступность движка вердиктов
// ниже по телу. Fail-closed не ослабляется: вызов отвергнут в обоих случаях.
func (h *Handler) authorizeCaller(ctx context.Context, subject string, res *iamv1.ResourceRef) error {
	callerSubject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		// Anonymous / system / unknown-type principal. This is EITHER a genuine
		// cluster-internal module PDP peer call (verified mTLS module cert on the
		// :9091 internal listener — its CallerPolicy verified-cert floor governs)
		// OR an unauthenticated caller that reached the PUBLIC :9090 listener,
		// which has NO module-cert floor. Do NOT blanket-allow: that fails open
		// and turns Check/ListObjects/ListSubjects into an anonymous
		// authorization oracle over every tenant (CWE-863 / CWE-200). Distinguish
		// the two by the verified mTLS client-cert identity, not by principal
		// absence.
		return h.authorizeAnonymousPeer(ctx)
	}
	// Self-query: a tenant may always ask authz questions about itself.
	if subject != "" && callerSubject == subject {
		return nil
	}
	// unanswered — неполадка на ЛЮБОМ из заданных ниже вопросов. Копится, а не
	// возвращается сразу: разрешению второе мнение не нужно, поэтому «да» любого
	// последующего вопроса сильнее неполадки на предыдущем.
	var unanswered error

	// Cluster-admin flat super-gate. Ответ берётся ВМЕСТЕ с причиной
	// (`…PlainE`), а не булевым сокращением: у запроса с подстановочным
	// идентификатором объекта полоса «право на этот объект» не исполняется вовсе,
	// и тогда неполадка сверх-гейта — единственный вопрос, оставшийся без
	// ответа. Проглотив её, обработчик отвечал бы терминальным отказом на
	// мигание хранилища.
	admin, adminErr := authzguard.SubjectIsClusterAdminPlainE(ctx, h.authority, callerSubject)
	if admin {
		return nil
	}
	if adminErr != nil {
		unanswered = adminErr
	}
	// Delegated authority on the specific queried resource.
	if h.authority != nil && res != nil {
		rType, rID := strings.ToLower(res.GetType()), res.GetId()
		if rType != "" && rID != "" && rID != "*" {
			object := rType + ":" + rID
			for _, rel := range callerAuthorityRelations {
				allowed, err := h.authority.Check(ctx, callerSubject, rel, object)
				switch {
				case err != nil:
					unanswered = err
				case allowed:
					return nil
				}
			}
		}
	}
	// Отказ — решение ТОЛЬКО когда каждый заданный вопрос получил ответ.
	// Сырая ошибка наружу не идёт (`security.md` §Hardening #1): текст хранилища
	// отношений может нести адрес и диагностику движка.
	if unanswered != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	return status.Error(codes.PermissionDenied, "permission denied")
}

// authorizeAnonymousPeer decides the fate of an anonymous / system principal
// (PrincipalSubject !ok) reaching the inner gate. The only legitimate
// no-tenant-principal caller of AuthorizeService is a cluster-internal module
// PDP peer, which is identified by a VERIFIED mTLS module SAN
// (spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>) on the :9091 internal listener —
// NOT by the mere absence of a principal. It returns nil (allow) only when:
//
//   - a verified module SAN is present (genuine internal PDP peer — the internal
//     listener's CallerPolicy verified-cert floor is the governing outer gate); OR
//   - the deployment explicitly opted into the insecure-listener posture
//     (WithInsecureAnonymousPeer), where there is no mTLS at all so the
//     public/internal listeners are indistinguishable — mirroring
//     authzguard.CallerPolicy / RelationWriteGate.
//
// Otherwise the caller reached the PUBLIC :9090 listener with no credentials and
// is DENIED — fail-closed, closing the public-listener authorization-oracle
// bypass. Denial is the DEFAULT: an omitted setter lands here, because that is
// what a wiring mistake must produce.
func (h *Handler) authorizeAnonymousPeer(ctx context.Context) error {
	if san, verified := grpcsrv.CertIdentityFromContext(ctx); verified && san != "" {
		if _, ok := authzguard.SANToServiceDomain(san); ok {
			return nil
		}
	}
	if h.insecureAnonymousPeer {
		// Explicitly opted-in insecure listener: no mTLS to distinguish listeners
		// → allow. Every other configuration is strictly fail-closed above.
		return nil
	}
	return status.Error(codes.PermissionDenied, "permission denied")
}
