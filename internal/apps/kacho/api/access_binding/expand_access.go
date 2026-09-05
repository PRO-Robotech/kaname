// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// expand_access.go — ExpandAccessUseCase. Sync read "who can perform <relation> on <object>": resolves the
// FGA userset into CONCRETE principals (USER / SERVICE_ACCOUNT), closing the
// effective-principal audit gap — a binding on a GROUP subject (or a rules-model
// scope_grant grant) otherwise only shows "group G" / nothing, not its members.
//
// Mechanism — a graph-traversing `ListUsers` over the rights model. Earlier this
// use-case did a flat filtered-Read of (object, relation) plus a hand-rolled
// group#member walk.
// A flat Read sees ONLY literal tuples on the EXACT (object, relation) node — it
// does NOT traverse the authorization graph, so every rules-model grant that
// reaches the queried relation through INDIRECTION resolved to EMPTY:
//   - computed-userset cascade (admin⇒editor⇒viewer): a `compute.instance.*` role
//     emits `account#admin@subject`; ExpandAccess(account, viewer) saw nothing.
//   - scope_grant indirection (`g_admin_<type> from <anchor>`): the subject sits
//     on the `scope_grant:…` object, never on the queried object's relation.
//   - group#member usersets (incl. nested groups).
// `ListUsers` natively traverses all three and returns the concrete grantees with
// groups already expanded (the decision door walks the form's pages to exhaustion
// under an explicit page bound, so no cycle-guard or depth counter is needed here).
// We restrict `user_filters` to the concrete principal types so usersets and
// wildcards never appear in the result.

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// defaultExpandResults / maxExpandResults — the CLIENT-side trim of the
// principal fan-out (proto: max_results, default 1000, ceiling 10000).
//
// It only ever narrows: the grant store bounds its own enumeration at
// clients.ListUsersServerCap and offers no continuation, so asking for more than
// that cannot widen the answer. Whether the answer was cut is therefore NOT
// decidable from these numbers — it is reported by the store and carried through
// PrincipalLister.
const (
	defaultExpandResults = 1000
	maxExpandResults     = 10000
)

// expandUserTypes — the closed set of concrete principal types ExpandAccess
// resolves (FGA `user_filters`). A GROUP is never a concrete principal — it is
// expanded by FGA into its (user / service_account) members, so it is NOT a
// filter type. Keeping the filter to these two means ListUsers returns only
// `object`-form entries (no userset / wildcard leaves to drop).
var expandUserTypes = []string{"user", "service_account"}

// PrincipalLister — narrow port: resolve the CONCRETE principals (FGA-prefixed
// "user:…" / "service_account:…") that hold object+relation, traversing the full
// authorization graph (computed usersets + scope_grant indirection + group
// memberships). Implemented by the decision door over the relational form.
//
// The second result is the SOURCE's truncation signal — whether the answer is a
// prefix is a fact only the source's reply can carry, because measuring the
// returned length against anything the use-case itself chose cannot detect a cut
// made upstream. It USED TO BE produced: the external engine bounded its own answer
// and offered no continuation. The form does not produce it — its enumeration is
// paged and continuable, so an incomplete answer that cannot be asked further does
// not arise — and it reads false. That false is HONEST, not a stub, and the field
// stays because the caller reads it and because the next source may truncate again.
type PrincipalLister interface {
	ListUsers(ctx context.Context, objectType, objectID, relation string, userTypes []string) (principals []string, storeTruncated bool, err error)
}

// Principal — a concrete grantee resolved by ExpandAccess (USER or
// SERVICE_ACCOUNT; never a GROUP).
type Principal struct {
	Type domain.SubjectType
	ID   domain.SubjectID
}

type ExpandAccessUseCase struct {
	lister PrincipalLister
	// repo + relations back the per-object grant-authority gate. Execute ALWAYS
	// requires the caller to hold grant-authority/admin on the target object's
	// scope BEFORE the principals are resolved — the SAME requireGrantAuthority
	// predicate ListByScope/ListByRole enforce (read==enforce: a caller may expand
	// "who can do X" only on objects they are themselves authorized to administer).
	// repo is nil-safe: for leaf FGA objects (compute.instance, …) authority
	// resolves purely through the FGA admin path, so only relations is strictly
	// required. Both nil is not a bypass — it is an unresolvable authority, and the
	// gate denies.
	repo      Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewExpandAccessUseCase(l PrincipalLister) *ExpandAccessUseCase {
	return &ExpandAccessUseCase{lister: l}
}

// WithGrantAuthority wires the per-object authority gate. repo resolves the
// owner-path for hierarchy scopes (account/project); relations resolves the
// delegated-admin FGA path for every scope. Mirrors the WithRelationStore wiring
// on Create/Delete/ListByScope. Logger is used for failure diagnostics.
func (u *ExpandAccessUseCase) WithGrantAuthority(repo Repo, relations clients.RelationStore, logger *slog.Logger) *ExpandAccessUseCase {
	u.repo = repo
	u.relations = relations
	u.logger = logger
	return u
}

// Execute resolves <relation> on <objectType>:<objectID> into concrete
// principals. maxResults<=0 → default (1000); capped at 10000.
//
// truncated=true means the answer is a LOWER BOUND, for either reason: the grant
// store cut its own enumeration at its server-side ceiling (no continuation
// token exists, so the rest is unreachable — narrow the query), or the resolved
// set exceeded maxResults and was trimmed here.
func (u *ExpandAccessUseCase) Execute(ctx context.Context, objectType, objectID, relation string, maxResults int) ([]Principal, bool, error) {
	// Anti-anonymous floor — a precondition for, not a substitute for, the
	// per-object authority gate below.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, false, err
	}
	if objectType == "" {
		return nil, false, status.Error(codes.InvalidArgument, "Illegal argument object_type (must be non-empty)")
	}
	if objectID == "" {
		return nil, false, status.Error(codes.InvalidArgument, "Illegal argument object_id (must be non-empty)")
	}
	if relation == "" {
		return nil, false, status.Error(codes.InvalidArgument, "Illegal argument relation (must be non-empty)")
	}
	// Пара (тип объекта, отношение) судится ДО любого обращения к источнику — и
	// судится ТЕМ ЖЕ набором, которым её потом разбирает компиляция плана
	// (`authzmap.AcceptExpand` → `authzmodel.Declares`).
	//
	// Прежде здесь стоял только вопрос о ПОВЕРХНОСТИ: отношение принималось, если
	// его объявлял ХОТЬ ОДИН тип, — то есть по ОБЪЕДИНЕНИЮ наборов. План же
	// собирается по набору КОНКРЕТНОГО типа, и пара из зазора между ними доезжала
	// до формы и возвращалась INTERNAL на КОРРЕКТНОМ запросе (#1290): «мы
	// сломались» там, где сломались не мы — запрос назвал пару, которой не бывает.
	// Зазор был не краевым случаем: на день заведения 80 пар из 189 принимаемых по
	// глагольной оси и 158 из 352 по всей поверхности. Числа названы как замер, а
	// не как инвариант: текущие печатает перепись
	// (authzmap/expand_acceptance_test.go), и она же роняет прогон, если приём и
	// компиляция снова разойдутся.
	//
	// Отказ ТЕРМИНАЛЬНЫЙ (`INVALID_ARGUMENT`): повтор того же запроса не пройдёт
	// никогда. И он называет ВИНОВНОЕ поле — у необъявленного типа не объявлено ни
	// одно отношение, поэтому жалоба на отношение увела бы править не ту
	// координату.
	//
	// Проверка стоит ДО пообъектного стража прав (`api-conventions` §порядок:
	// format-validate → authz → источник): иначе ответ на один и тот же негодный
	// ввод зависел бы от того, что вызывающему выдано. Оракула здесь нет —
	// каноническая модель прав лежит в репозитории и тенантских данных не несёт.
	verdict, verr := authzmap.AcceptExpand(objectType, relation)
	if verr != nil {
		// Модель не разобралась — это НАША поломка, а не негодный ввод.
		if u.logger != nil {
			u.logger.ErrorContext(ctx, "ExpandAccess: модель прав не разобрана", slog.Any("error", verr))
		}
		return nil, false, status.Error(codes.Internal, "failed to expand access")
	}
	switch verdict {
	case authzmap.ExpandTypeNotDeclared:
		return nil, false, status.Errorf(codes.InvalidArgument, "Illegal argument object_type %q", objectType)
	case authzmap.ExpandRelationOffSurface:
		// Тон сохранён дословно: машинерия модели отвергалась этим текстом и
		// раньше, и он часть контракта (сквозной кейс RBACSUBJ-EXPAND-VAL-RELATION).
		return nil, false, status.Errorf(codes.InvalidArgument, "Illegal argument relation %q", relation)
	case authzmap.ExpandRelationNotOnType:
		return nil, false, status.Errorf(codes.InvalidArgument,
			"Illegal argument relation %q (not declared on object type %q)", relation, objectType)
	case authzmap.ExpandAccepted:
		// пара разбирается — идём дальше, к стражу прав
	}

	// Per-object authority gate (read==enforce). The caller may expand "who
	// can do <relation> on <object>" ONLY if they hold grant-authority/admin on the
	// object's scope — the SAME predicate ListByScope/ListByRole enforce. This
	// runs BEFORE the principal resolution, so an unauthorized caller never observes
	// the effective principals (no authz-topology / membership leak).
	//
	// UNCONDITIONAL. It used to run only `if u.repo != nil || u.relations != nil`,
	// which made the single narrowing this RPC has depend on a composition-root
	// setter: a build that forgot WithGrantAuthority answered "who can act on this
	// object" — people and machine accounts, groups already expanded — to any
	// authenticated caller, on any object, with nothing failing anywhere. The
	// catalog entry cannot catch that either: it asks `viewer` on the cluster
	// singleton, a relation the bootstrap grants to `user:*` so the global
	// reference catalog stays readable, so every authenticated subject is already
	// through the front door by the time execution reaches here.
	//
	// Unwired now means unresolvable authority, and unresolvable authority is a
	// denial: requireGrantAuthority's own paths are fail-closed on nil ports, so
	// calling it always yields PermissionDenied rather than an accidental pass.
	if err := requireGrantAuthority(ctx, u.repo, u.relations, objectType, objectID); err != nil {
		return nil, false, hideObjectExistence(err)
	}
	limit := maxResults
	if limit <= 0 {
		limit = defaultExpandResults
	}
	if limit > maxExpandResults {
		limit = maxExpandResults
	}

	// Resolve concrete principals via the graph-traversing ListUsers (groups,
	// computed usersets and scope_grant indirection all expanded server-side).
	//
	// storeTruncated is the store's OWN report that it cut the answer at its
	// server-side ceiling (clients.ListUsersServerCap). There is no continuation
	// token to follow, so a cut set can only be DECLARED incomplete, never
	// continued. It has to come from the store: the enumeration is bounded
	// upstream, and no comparison against our own trim can observe a cut made
	// before the answer reached us.
	principals, storeTruncated, err := u.lister.ListUsers(ctx, objectType, objectID, relation, expandUserTypes)
	if err != nil {
		if u.logger != nil {
			u.logger.WarnContext(ctx, "ExpandAccess ListUsers failed",
				slog.String("object_type", objectType), slog.String("object_id", objectID),
				slog.String("relation", relation), slog.Any("error", err))
		}
		// Fail-closed: never leak the FGA/transport error text; no partial result.
		return nil, false, status.Error(codes.Internal, "failed to expand access")
	}

	seen := make(map[Principal]struct{}, len(principals))
	out := make([]Principal, 0, len(principals))
	// Two independent reasons the answer is a lower bound, and BOTH must set the
	// flag: the store cut its own enumeration, or we trimmed to the caller's
	// max_results below. Reporting only the second is what made the flag always
	// false — our trim is never smaller than what the store returns.
	truncated := storeTruncated
	for _, s := range principals {
		p, ok := parseFGAPrincipal(s)
		if !ok {
			continue // unparseable / non-principal (group userset / wildcard)
		}
		if _, dup := seen[p]; dup {
			continue // granted directly AND via a group → counted once
		}
		seen[p] = struct{}{}
		if len(out) >= limit {
			truncated = true
			break
		}
		out = append(out, p)
	}
	return out, truncated, nil
}

// hideObjectExistence collapses the authority gate's NOT_FOUND into the denial,
// so a caller with no authority over an object cannot use this RPC to learn
// whether the object is there.
//
// The gate resolves an account/project scope through the database, so an absent
// id answered `NOT_FOUND "Account <id> not found"` while a real id belonging to
// someone else answered `PERMISSION_DENIED` — two different answers to "is this
// id real?", available to any authenticated subject, because the front door's
// catalog question is one every authenticated subject passes.
//
// Only NOT_FOUND is collapsed. A backend failure keeps its own code: an outage
// reported as a denial would send the caller to fix permissions that are fine.
func hideObjectExistence(err error) error {
	if status.Code(err) == codes.NotFound {
		return authzguard.PermissionDenied()
	}
	return err
}

// parseFGAPrincipal parses an FGA user string into a concrete Principal. Returns
// ok=false for a GROUP userset ("group:grp_x#member") or any non-user/SA form —
// those are not concrete principals (FGA already expanded groups to members).
func parseFGAPrincipal(s string) (Principal, bool) {
	typ, id, found := strings.Cut(s, ":")
	if !found || id == "" {
		return Principal{}, false
	}
	// Drop any FGA relation sigil (e.g. "group:grp_x#member") — only a bare
	// user/service_account id is a concrete principal.
	if i := strings.IndexByte(id, '#'); i >= 0 {
		return Principal{}, false
	}
	switch typ {
	case "user":
		return Principal{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}, true
	case "service_account":
		return Principal{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(id)}, true
	default:
		return Principal{}, false
	}
}
