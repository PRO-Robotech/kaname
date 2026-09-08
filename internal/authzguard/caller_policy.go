// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// caller_policy.go — the per-RPC CALLER policy for the cluster-internal listener
// (:9091). It does NOT re-ReBAC the end user — that is the api-gateway's job (the
// platform's single authZ front door validates the JWT and runs per-user ReBAC
// via iam.Check). iam's :9091 enforces only WHO MAY CALL each RPC:
//
//  1. Floor — every internal RPC requires a VERIFIED mTLS module cert (SPIRE SAN
//     spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>) in production. dev (no verified
//     cert) → no-op (insecure back-compat, mirror RelationWriteGate).
//  2. Gateway-only — the gateway-fronted privileged admin RPCs
//     (GatewayFrontedInternalRPCs) may ONLY be called by the api-gateway SA. A
//     direct call from any other module (e.g. a compromised kacho-vpc) → DENY in
//     prod (a data-plane module cannot escalate via :9091).
//     dev → no-op.
//  3. SAN-restricted — a small set of RPCs whose caller must appear on an
//     EXPLICIT, operator-supplied allow-list of client-certificate SPIFFE SANs
//     (WithSANAllowlist). Unlike arms 1-2 this arm is enforced in EVERY mode and
//     an empty/absent allow-list denies EVERYONE (fail-closed: these RPCs have no
//     default caller). Today: InternalBootstrapTokenService/MintBootstrapToken,
//     which hands out a cluster `system_admin` Bearer and therefore cannot be
//     gated by "any verified module cert" — a compromised data-plane module must
//     not be able to mint cluster-admin — nor by a ReBAC relation (it exists to
//     obtain the FIRST token, when no relation exists yet). The credential is the
//     caller's verified certificate identity; network position is NOT a
//     credential (security.md — "internal = trusted" is forbidden).
//
// WHY this replaces the former cert-bound ReBAC interceptor: the api-gateway
// re-dials :9091 with ITS OWN client cert (SAN .../sa/kacho-api-gateway) and
// forwards the end-user principal in x-kacho-principal-* metadata. A cert-bound
// ReBAC Check on the gateway SA would DENY legitimate admin calls (system_admin@
// cluster is held by the user, not the gateway SA); ReBAC-ing the forwarded user
// would couple iam to the gateway's relation map. So iam does NO ReBAC and trusts
// NO metadata here — it only verifies the caller IS the gateway for admin RPCs.
//
// The fga-proxy write RPCs (RegisterResource / UnregisterResource) are NOT
// gateway-only — their callers are vpc/compute/nlb MODULE SAs — and stay gated
// IN-HANDLER by RelationWriteGate (fga_writer), unchanged. They satisfy the
// floor like any other module RPC.
package authzguard

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// gatewayServiceName — the module service short-name of the api-gateway SA
// (SPIRE SAN .../sa/kacho-api-gateway → "api-gateway"). The single legitimate
// caller of the gateway-fronted privileged admin RPCs.
const gatewayServiceName = "api-gateway"

// GatewayFrontedInternalRPCs returns the full-method set of internal RPCs that
// the api-gateway fronts on behalf of an end user (admin UI / admin tooling).
// These privileged RPCs may ONLY be called by the api-gateway SA — a direct call
// from any other module is a privilege-escalation attempt.
//
// NOT in this set (any verified module — floor only):
//   - InternalIAMService/{Check,LookupSubject,PollSubjectChanges} — hot-path
//     service→service RPCs.
//   - InternalSessionRevocationsService/IsRevoked — заведено под собственный
//     запрос края, идущий до того, как может пойти пер-пользовательская
//     проверка (курица и яйцо). ПРЕДМЕТ У ПОСЛАБЛЕНИЯ ЕСТЬ: клиент края
//     экспонирует `IsSessionRevoked`, и он провязан в слой аутентификации
//     (`middleware.NewLocalThenProviderRevocation`, #1122) — то есть край
//     спрашивает эту полосу на каждом предъявлении удостоверения. Здесь стояло
//     «этого вызывающего в дереве СЕГОДНЯ НЕТ (#797)»: утверждение пережило
//     свой предмет (#1156). Исчезнет метод у края — снимать и эту строку.
//   - InternalUserService/Get — service→service lookup.
//   - Hydra hook callbacks are not in this set and cannot be: they are served
//     over HTTP by internal/handler/iamhooks, not as gRPC methods. The gRPC
//     declaration that once mirrored them (InternalIamHooksService) had no
//     implementation and was retired — see retiredRPCSurface in
//     internal/repohygiene.
//   - the fga-proxy writes InternalIAMService/{RegisterResource,
//     UnregisterResource} — gated in-handler by RelationWriteGate (module SAs).
//     The third one, WriteCreatorTuple, was retired with zero callers (#788).
func GatewayFrontedInternalRPCs() []string {
	return []string{
		// InternalClusterService — cluster admin RBAC (admin UI).
		"/kaname.cloud.iam.v1.InternalClusterService/GrantAdmin",
		"/kaname.cloud.iam.v1.InternalClusterService/RevokeAdmin",
		"/kaname.cloud.iam.v1.InternalClusterService/ListAdmins",
		"/kaname.cloud.iam.v1.InternalClusterService/Get",
		// InternalInteractiveClientService — lifecycle of the OAuth2 client a
		// HUMAN signs in through (admin UI / admin tooling). All five are
		// gateway-fronted: the operator acts through the edge, and no module has
		// business dialling them directly. The three mutations additionally carry
		// the catalog step-up floor acr=2 (a redirect target is where an
		// authorization code is delivered); the acr-floor interceptor reads that
		// from the catalog, so it is not restated here.
		"/kaname.cloud.iam.v1.InternalInteractiveClientService/Get",
		"/kaname.cloud.iam.v1.InternalInteractiveClientService/List",
		"/kaname.cloud.iam.v1.InternalInteractiveClientService/Create",
		"/kaname.cloud.iam.v1.InternalInteractiveClientService/Update",
		"/kaname.cloud.iam.v1.InternalInteractiveClientService/Delete",
		// InternalLimitService — administration of resource-count ceilings
		// (issue #291). The five CRUD verbs are gateway-fronted: an operator acts
		// through the edge, and no module has business dialling them.
		//
		// Resolve / ListChangedSince are deliberately ABSENT: they are
		// service→service reads made by the OWNER of the counted resource type
		// (vpc today, the other owners next), so restricting them to the
		// api-gateway SA would make the capability unreachable by its only
		// intended caller. They are gated instead by the narrow `quota_reader`
		// relation — at the edge catalog and again in-handler.
		"/kaname.cloud.iam.v1.InternalLimitService/Get",
		"/kaname.cloud.iam.v1.InternalLimitService/List",
		"/kaname.cloud.iam.v1.InternalLimitService/Create",
		"/kaname.cloud.iam.v1.InternalLimitService/Update",
		"/kaname.cloud.iam.v1.InternalLimitService/Delete",
		// InternalModuleService — план и применение каталога прав модуля
		// (kacho#1991). Все четыре фронтируются краем: оператор действует через
		// него, а НИ ОДИН модуль эти глаголы не зовёт — замер, а не допущение:
		// `NewInternalModuleServiceClient` вне `pkg/api` встречается только в
		// пробах самого iam, прод-вызывающих ноль.
		//
		// ЗАПИСЬ ОЖИВЛЯЕТ СТУПЕНЬ ПОДТВЕРЖДЕНИЯ ЛИЧНОСТИ У `Apply`, и это её
		// главное следствие. Ступень объявлена контрактом (`required_acr_min =
		// "2"`: применение ОТЗЫВАЕТ права арендатора, то есть меняет посадку
		// безопасности, а не правит рутину), но `ACRFloor` применяет её ТОЛЬКО
		// к методам этого круга — значит до сих пор она была инертна.
		//
		// Инертность была РЕШЕНИЕМ, а не недосмотром, и у него был назван
		// предикат снятия: запись круга заодно объявляет, что звать метод
		// вправе только край, — а REST-маршрута у края не было, и запись
		// завела бы поверхность, недостижимую ни для кого. Маршрут заведён
		// (`/iam/v1/internal/modules`), предикат сработал, инертность снята
		// тем же изменением. Понижать объявление до "1" было бы ложью о
		// требовании: инертность есть свойство ПУТИ, а не цены применения.
		//
		// Величина ступени здесь НЕ повторяется — `ACRFloor` читает её из
		// каталога прав; второе объявление разошлось бы с первым молча.
		"/kaname.cloud.iam.v1.InternalModuleService/Plan",
		"/kaname.cloud.iam.v1.InternalModuleService/Apply",
		"/kaname.cloud.iam.v1.InternalModuleService/Get",
		"/kaname.cloud.iam.v1.InternalModuleService/List",
		// Четырёх методов администрирования хранилища отношений здесь больше нет:
		// служба снята вместе с внешним движком (стадия S6 эпика #747). Запись
		// круга, называющая метод, которого не существует, — не безобидный
		// остаток: она переживает свой предмет и делает вид, что круг шире, чем
		// он есть.
		// InternalIAMService — cluster admin mutation (admin tooling). The
		// fga-proxy writes are NOT here (module SAs, in-handler gate).
		"/kaname.cloud.iam.v1.InternalIAMService/ForceLogout",
		// InternalOperationsService — cluster-wide admin operations feed
		// (admin UI). Gateway-fronted: only the api-gateway SA may
		// dial it, AND the acr-floor enforces the catalog acr_min for it. The
		// in-handler system_admin@cluster ReBAC Check is the additional per-user
		// gate (AuthN+AuthZ on every RPC — internal not exempt).
		"/kaname.cloud.iam.v1.InternalOperationsService/ListIamOperations",
		// InternalSessionRevocationsService — Revoke is driven by the
		// api-gateway logout handler on behalf of a user; ListByUser is the
		// admin-UI revocation history. Both are gateway-fronted. IsRevoked is
		// the hot-path lookup the gateway makes BEFORE authz can run
		// (chicken-and-egg) → floor-only, deliberately NOT in this set.
		"/kaname.cloud.iam.v1.InternalSessionRevocationsService/Revoke",
		"/kaname.cloud.iam.v1.InternalSessionRevocationsService/ListByUser",
		// InternalUserService — identity provisioning fronted by the gateway
		// lazy-mirror / recovery flow.
		"/kaname.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
		"/kaname.cloud.iam.v1.InternalUserService/OnRecoveryCompleted",
		// NOT here: InternalBootstrapTokenService/MintBootstrapToken. It has no
		// REST route on the gateway at all (the mint would be credential-free
		// there — see the proto / restmux comments), so the api-gateway SA is not
		// one of its callers, and "is the gateway" must never be a licence to mint
		// cluster-admin. It is SAN-restricted instead — see BootstrapMintFullMethod.
	}
}

// BootstrapMintFullMethod — InternalBootstrapTokenService/MintBootstrapToken,
// the SAN-restricted cluster-admin token mint (arm 3). Exported so the
// composition root can key its allow-list without re-spelling the FQN.
const BootstrapMintFullMethod = "/kaname.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken"

// SANRestrictedInternalRPCs returns the full-method set gated by arm 3 — an
// explicit client-certificate SPIFFE SAN allow-list.
//
// The SET IS STATIC, deliberately independent of configuration: membership is a
// property of the RPC, not of what an operator happened to configure. A
// deployment that never supplies an allow-list must end up with the mint DENIED
// to everyone, not silently downgraded to the "any verified module cert" floor —
// a config omission must never open a cluster-admin mint.
func SANRestrictedInternalRPCs() []string {
	return []string{BootstrapMintFullMethod}
}

// CallerPolicy enforces the per-RPC caller policy on the internal listener.
// Construct via NewCallerPolicy.
type CallerPolicy struct {
	// prodMode = production AuthN mode (cfg.AuthN.Mode.IsProduction()). dev-mode
	// (false) is a no-op for the floor / gateway-only arms (insecure
	// back-compat); production is fail-closed. It does NOT relax the
	// SAN-restricted arm.
	prodMode bool
	// gatewayOnly — full-method set restricted to the api-gateway SA.
	gatewayOnly map[string]struct{}
	// sanRestricted — full-method set gated by arm 3. STATIC
	// (SANRestrictedInternalRPCs), so an unconfigured allow-list denies rather
	// than silently falling back to the floor.
	sanRestricted map[string]struct{}
	// sanAllow — full-method → the EXACT client-certificate SPIFFE SANs allowed
	// to call it. Only consulted for sanRestricted methods; a missing/empty entry
	// denies everyone.
	sanAllow map[string]map[string]struct{}
}

// NewCallerPolicy builds the caller policy. gatewayOnlyRPCs is the set of
// full-method names restricted to the api-gateway SA (see
// GatewayFrontedInternalRPCs). prodMode comes from cfg.AuthN.Mode.IsProduction().
//
// The arm-3 METHOD set is static (SANRestrictedInternalRPCs); WithSANAllowlist
// only supplies WHICH certificate identities may call them. A policy built
// without WithSANAllowlist therefore denies every caller of those methods.
func NewCallerPolicy(prodMode bool, gatewayOnlyRPCs []string) *CallerPolicy {
	m := make(map[string]struct{}, len(gatewayOnlyRPCs))
	for _, rpc := range gatewayOnlyRPCs {
		m[rpc] = struct{}{}
	}
	restricted := make(map[string]struct{})
	for _, rpc := range SANRestrictedInternalRPCs() {
		restricted[rpc] = struct{}{}
	}
	return &CallerPolicy{prodMode: prodMode, gatewayOnly: m, sanRestricted: restricted}
}

// WithSANAllowlist supplies the arm-3 allow-list: fullMethod → the exact
// client-certificate SPIFFE SAN URIs permitted to call it. Callers whose verified
// SAN is not listed are denied — in EVERY mode; a restricted method with no
// entry (or an empty one) is denied to everyone (fail-closed: the mint has no
// default caller). Exact URI match, not a service short-name — the ns AND the sa
// are part of the identity.
//
// Blank entries are dropped so an accidentally empty config value
// (`KANAME_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS=""` → [""]) can never
// match a caller whose SAN failed to parse.
func (p *CallerPolicy) WithSANAllowlist(perRPC map[string][]string) *CallerPolicy {
	if len(perRPC) == 0 {
		p.sanAllow = nil
		return p
	}
	out := make(map[string]map[string]struct{}, len(perRPC))
	for method, sans := range perRPC {
		set := make(map[string]struct{}, len(sans))
		for _, san := range sans {
			if s := strings.TrimSpace(san); s != "" {
				set[s] = struct{}{}
			}
		}
		out[method] = set
	}
	p.sanAllow = out
	return p
}

// allow returns nil iff the call may proceed past the policy for fullMethod:
//   - SAN-restricted RPC (arm 3): the caller must present a VERIFIED client cert
//     whose exact SPIFFE SAN is allow-listed → otherwise PermissionDenied, in
//     EVERY mode. An empty/absent allow-list denies everyone. Evaluated FIRST and
//     terminally: this arm never falls through to the mode-relaxed arms below.
//   - no verified module cert: prod → PermissionDenied (floor fail-closed);
//     dev → nil (insecure back-compat).
//   - gateway-only RPC called by a non-gateway module: prod → PermissionDenied;
//     dev → nil.
//   - otherwise (any verified module for a non-gateway RPC, or the gateway for a
//     gateway-only RPC) → nil.
//
// Message text is the verbatim, non-leaking "permission denied".
func (p *CallerPolicy) allow(ctx context.Context, fullMethod string) error {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)

	// Arm 3 — explicit per-RPC certificate-identity allow-list. Checked before
	// everything else and terminal in both directions, so neither dev-mode nor
	// the gateway-fronted set can widen it. An unconfigured allow-list leaves
	// p.sanAllow[fullMethod] empty → deny.
	if _, restricted := p.sanRestricted[fullMethod]; restricted {
		if !verified || san == "" {
			return status.Error(codes.PermissionDenied, "permission denied")
		}
		if _, listed := p.sanAllow[fullMethod][san]; !listed {
			return status.Error(codes.PermissionDenied, "permission denied")
		}
		return nil
	}

	svc, ok := "", false
	if verified && san != "" {
		svc, ok = ServiceNameFromSAN(grpcsrv.CertIdentityDomainFromContext(ctx), san)
	}
	if !ok {
		// No verified module cert. Dev → no-op; prod → fail-closed.
		if !p.prodMode {
			return nil
		}
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if _, gw := p.gatewayOnly[fullMethod]; gw && svc != gatewayServiceName {
		// Gateway-only RPC from a non-gateway module. Dev → no-op; prod →
		// fail-closed (a data-plane module cannot escalate via :9091).
		if !p.prodMode {
			return nil
		}
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// Any verified module for a non-gateway RPC, or the gateway for a
	// gateway-only RPC → allow.
	return nil
}

// Unary returns the unary interceptor enforcing the caller policy.
func (p *CallerPolicy) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := p.allow(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the stream interceptor enforcing the caller policy.
func (p *CallerPolicy) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := p.allow(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
