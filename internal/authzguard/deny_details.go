// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// deny_details.go — the machine-readable reason on a refusal iam decides itself.
//
// WHY THIS LIVES HERE AND NOT AT EACH REFUSAL SITE
// ------------------------------------------------
// Some RPCs are authorized over the DATA: their catalog row carries no
// required_relation, an empty scope extractor and the scope-filtered marker, so
// the edge runs no per-RPC check and passes the call through. That is correct —
// a method whose answer concerns many individually-owned objects has no single
// object to ask one question about. But the edge was also the only layer that
// attached the detail naming the action, and it still attaches it for the
// neighbouring rows it does check. On the data-filtered band the refusal
// therefore arrived bare: `{"code":7,"message":"permission denied","details":[]}`.
//
// A bare refusal is worse than terse. It is INDISTINGUISHABLE from a catalog
// miss — a method the catalog cannot map to any permission at all, which
// fail-closes to the same code with the same prose. A client (and a test) could
// not tell "you may not read this" from "this method is not in the catalog".
//
// The convention requires the reason to be machine-readable and forbids parsing
// the prose, so the fix belongs on the transport edge of the service, where the
// method name is known, rather than duplicated at each of the refusal sites.
// One place, and every method on the band is covered — including the ones added
// to it later.

import (
	"context"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	"github.com/PRO-Robotech/kaname/internal/contractnaming"
)

const (
	// denyReason — the token a client keys on. Deliberately the SAME token the
	// edge stamps when IT refuses: a caller must not have to know which layer
	// said no in order to recognise a refusal.
	denyReason = "AUTHZ_DENIED"

	// grantRequiredViolation — the violation type naming the missing grant.
	// Deliberately shaped like the step-up one ("authz.step_up") so a client
	// reads both next-step signals through one lookup.
	grantRequiredViolation = "authz.grant_required"
)

// denyDomain — the domain a client keys on, identical to the edge's for the same
// reason as denyReason above.
//
// Берётся у ОБЪЯВЛЕННОГО источника имён, а не выписывается: разойдись он с
// пакетом контракта — ключ клиента перестал бы совпадать молча (#2168).
// Не константа лишь потому, что источник — ведомость, а не литерал.
var denyDomain = contractnaming.OwnContractPackage()

// DenyActionLookup — port: full method name (no leading slash) → what the
// catalog says about that method.
//
// ActionForMethod — the permission name, or "" when the catalog has no row for
// it or the row is exempt.
//
// ScopeForMethod — the OBJECT TYPE on which that permission is granted
// (project / account / cluster), or "" when the row names none. It is the other
// half of the answer a refusal owes its caller: the action says WHAT is
// missing, the scope says WHERE it is granted — and therefore whom to ask.
//
// Both are functions of the METHOD alone. That is not an implementation detail
// but the property that keeps the enriched refusal free of an existence oracle:
// nothing from the request, the object id or the subject enters the answer, so
// a refusal on an existing object stays byte-identical to a refusal on one that
// does not exist. Asserted by TestDenyNextStep_IsAFunctionOfTheMethodOnly.
//
// Implemented by *seed.PermissionRegistry.
type DenyActionLookup interface {
	ActionForMethod(fqn string) string
	ScopeForMethod(fqn string) string
}

// DenyDetailUnary returns an interceptor that attaches the machine-readable
// reason to a refusal that does not already carry one.
//
// What it does NOT attach, and why:
//
//   - the subject — the caller already knows who it is, and echoing it adds
//     nothing a client can act on;
//   - the resource — on a data-filtered method there is no single resource by
//     construction; naming one would be a claim the service cannot make. The
//     edge fills that field only where it resolved a scope object.
//
// WHAT IT ALSO ATTACHES, AND WHY THAT IS NOT AN ORACLE
// ----------------------------------------------------
// A refusal exists so the caller can build the NEXT STEP. A bare one does not
// restore it: the administrator learns neither which permission to request nor
// from whom. So the refusal carries the step — in the DETAILS, never in the
// prose. The message stays the verbatim "permission denied" on every refusal,
// byte for byte, because a distinguishable text is exactly the existence oracle
// the fixed wording exists to close.
//
// The form is not invented here: it is the one the step-up refusal already
// uses (acr_floor.go — a PreconditionFailure violation the edge turns into an
// RFC 9470 challenge). Type "authz.grant_required", Subject = the scope object
// type, Description = the permission to ask for and where it is granted.
//
// A refusal that ALREADY names its own next step (the step-up one) gets no
// second advice: the caller there may hold the grant in full, and "ask for the
// permission" would send them the wrong way.
//
// A method with no catalog row gets NOTHING attached. That is the whole point:
// an absent action is how a caller recognises a catalog miss, so inventing an
// empty one would erase the distinction this exists to create.
func DenyDetailUnary(catalog DenyActionLookup) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		if err == nil {
			return resp, nil
		}
		return resp, withDenyReason(catalog, info.FullMethod, err)
	}
}

// withDenyReason enriches a PermissionDenied status; everything else is
// returned untouched (a reason token on a NotFound would mislabel the failure).
func withDenyReason(catalog DenyActionLookup, fullMethod string, err error) error {
	if catalog == nil {
		return err
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		return err
	}
	if hasErrorInfo(st) {
		// Already named — a second, possibly disagreeing, reason would be worse
		// than none. The step-up refusal builds its own details, and so may a
		// future site.
		return err
	}
	fqn := strings.TrimPrefix(fullMethod, "/")
	action := catalog.ActionForMethod(fqn)
	if action == "" {
		return err
	}
	tier := scopeTier(catalog.ScopeForMethod(fqn))

	meta := map[string]string{
		"action": action,
		"fqn":    fqn,
	}
	if tier != "" {
		// Named only when the catalog names a scope. An invented one would be a
		// claim the service cannot make — the same reason an absent action is
		// left absent rather than filled with a blank.
		meta["scope"] = tier
	}

	details := []protoadapt.MessageV1{&errdetails.ErrorInfo{
		Reason:   denyReason,
		Domain:   denyDomain,
		Metadata: meta,
	}}
	// The next step in human words — but only where there IS a next step to
	// name, and only where the refusal does not already name one of its own.
	if tier != "" && !hasPreconditionFailure(st) {
		details = append(details, &errdetails.PreconditionFailure{
			Violations: []*errdetails.PreconditionFailure_Violation{{
				Type:        grantRequiredViolation,
				Subject:     tier,
				Description: grantAdvice(action, tier),
			}},
		})
	}

	// WithDetails APPENDS, so any detail already on the status survives.
	enriched, derr := st.WithDetails(details...)
	if derr != nil {
		// Marshalling a fixed, tiny message cannot realistically fail; if it
		// somehow does, the refusal itself must still reach the caller intact.
		return err
	}
	return enriched.Err()
}

// scopeTier переводит тип объекта модели прав в ЯРУС, названный словами
// продукта.
//
// ПОЧЕМУ НЕ ОТДАВАТЬ ТИП КАК ЕСТЬ — и это не вкус, а перемеренная ошибка первой
// редакции этого кода. Тип объекта в записи каталога — это ЦЕЛЬ проверки
// (`iam_access_binding`, `compute_instance`, `vpc_cidr_group`), а не область, у
// администратора которой просят выдачу. Отдав его дословно, отказ (а) назвал бы
// арендатору словарь модели прав — того, чего в клиентских текстах сегодня ноль
// и заводить обратно нельзя, — и (б) советовал бы «попросите у администратора
// этого iam_access_binding», что попросту неверно: выдача делается на самом
// ресурсе либо на содержащем его проекте или аккаунте.
//
// Ярусов четыре, и все четыре — слова продукта:
//
//	cluster / account / project — область названа каталогом прямо;
//	resource                    — проверка идёт по КОНКРЕТНОМУ объекту, и выдача
//	                              делается на нём либо на содержащем его проекте
//	                              или аккаунте;
//	""                          — область не названа: сказать нечего, и молчание
//	                              здесь честнее выдуманного совета.
func scopeTier(objectType string) string {
	switch objectType {
	case "":
		return ""
	case "cluster", "account", "project":
		return objectType
	default:
		return "resource"
	}
}

// grantAdvice — следующий шаг словами, по ярусу. Текст английский и стабильный:
// он часть контракта, а русскую редакцию производит клиентская поверхность из
// машинного признака (решение о языке клиентских отказов —
// services/iam/internal/errors/client_refusal_reason_coverage_test.go).
func grantAdvice(action, tier string) string {
	const lead = "the '"
	switch tier {
	case "cluster":
		return lead + action + "' permission is granted cluster-wide; ask a cluster administrator for it"
	case "account":
		return lead + action + "' permission is granted by an AccessBinding on the account; " +
			"ask an administrator of that account for it"
	case "project":
		return lead + action + "' permission is granted by an AccessBinding on the project; " +
			"ask an administrator of that project or of its account for it"
	default:
		return lead + action + "' permission is granted by an AccessBinding on this resource, " +
			"or on the project or account that contains it; " +
			"ask an administrator of that project or account for it"
	}
}

// hasPreconditionFailure — у отказа уже назван его собственный следующий шаг.
func hasPreconditionFailure(st *status.Status) bool {
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.PreconditionFailure); ok {
			return true
		}
	}
	return false
}

func hasErrorInfo(st *status.Status) bool {
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.ErrorInfo); ok {
			return true
		}
	}
	return false
}
