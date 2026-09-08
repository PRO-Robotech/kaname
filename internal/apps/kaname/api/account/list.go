// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// list.go — ListAccountsUseCase. Sync read с pagination.
//
// # A page of this list is a page of the VISIBLE (task #645)
//
// It used to be a window over the whole `accounts` table, from which the visible
// was subtracted afterwards. That order loses every account with more than
// `page_size` invisible predecessors by creation time: the row never reaches the
// narrowing at all, so the caller receives `200` with an empty array while a Get
// on that same account answers `200`. The threshold depends on the population of
// the cloud and on nothing else, so it arrives silently and reads, to the tenant,
// as "you have nothing".
//
// The page is therefore SELECTED narrowed, in three parts that do not work apart
// — CANDIDATES from iam's own database, VERDICT from the authorization model,
// REFILL until the page is full. The shape, the reasoning behind each part and
// the invariants of the loop are stated once, in the project sibling
// (api/project/list.go); this file states only what is different here.
//
// # What is different on this surface
//
//   - An account IS its own account, so both halves of the candidate narrowing
//     compare the same column. `Scope.Candidates("account")` carries the accounts
//     the caller reaches in AccountIDs and a by-name grant in ObjectIDs; the
//     repository ORs them over `id`.
//   - There is NO ownership floor here, and that is not an omission. On the
//     project surface owning the parent account makes its contents visible
//     without a verdict; here the object IS the account, and the model decides
//     whether its owner may read it. Owning an account still makes it a
//     CANDIDATE — the narrowing must not be narrower than the model — but a
//     candidate is not a verdict, and the predicate this list serves is
//     unchanged from before the repair.
//
// The visibility filter is FGA-relation-driven. Instead of the legacy
// owner-only Go post-filter (`OwnerUserID == principal.ID`), the use-case asks the
// rights model, per candidate id, whether the principal may see that account, and
// returns only those rows.
//
// On the flat explicit model `account` is a verb-bearing
// resource with NO `from account` access-cascade. Visibility is the UNION of
// two direct-tuple sets:
//
//	visible(id) = Check(subject, "viewer", "account:"+id)
//	            ∨ Check(subject, "v_list", "account:"+id)
//
// asked for the CANDIDATES read from the iam database (§ above: they are
// selected narrowed, and the verdict is put per candidate). The predicate is
// unchanged; what changed is which rows reach it.
//
// It was never right to ask the MODEL which accounts are visible and then narrow
// the query to that set — that enumeration is truncated server-side with no
// continuation token, and past the cap a tenant's own account fell outside the
// returned prefix. That remains forbidden: the candidate set above comes from
// iam's OWN tables, has no cap, and decides nothing. See the internal/authzfilter
// package doc.
//
//   - The `viewer` branch surfaces accounts the principal holds the viewer tier
//     on (owner-binding admin/editor/viewer write-authz anchor). A viewer grant
//     implies broader access.
//   - The `v_list` branch surfaces accounts granted ONLY `iam.account.{get,list}`
//     via a names/labels selector — an OBJECT-ONLY `account:<id> # v_list @ subj`
//     tuple with NO cascade into the account's contents (D-2). This is the
//     owner's original goal: "see the account in the selector WITHOUT access to
//     its contents" — the account is listed while a Check on a project/network
//     inside it still DENIES.
//   - The two sets are deduplicated; an account in both appears once.
//   - There is NO cluster-wide reader floor on this page, and this line used to
//     say the opposite. It claimed the kacho-vpc-operator SA "resolves viewer on
//     EVERY account → sees ALL accounts (floor intact)". That floor was the SEC-L
//     read-cascade `viewer … or system_viewer from cluster`, and Contract-A
//     REMOVED it — fga_model.fga says so on both `account` and `project`. What
//     replaced it was per-object materialisation from the operator's role rules,
//     and those rules resolve to nothing: every one of the four names its role
//     authors (`vpc.subnetses`, `vpc.networks`, `vpc.network_interfaces`,
//     `iam.projectses`) is absent from the closed object-type table, so the
//     reconciler emits no tuple for any of them. Measured, with a control, and
//     pinned by TestSeededRoleRulesResolveOrArePinned.
//     The retirement then happened at the seed, where it belonged: 0076 took the
//     role and its binding, 0081 the identity itself and the cluster tuple it
//     still held. Do NOT widen the predicate here to restore the sentence — a
//     cluster-wide reader floor is a grant, and grants are made at the seed, not
//     conceded by a list filter.
//   - Anonymous short-circuits to empty BEFORE any FGA call.
//   - FGA outage on EITHER relation → fail-closed `Unavailable`: never a
//     full-list leak, never a degraded/partial list.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// ListAccountsUseCase.
type ListAccountsUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects port resolving the principal's viewer-set.
	// When nil the use-case fails closed (no unfiltered list ever leaves the
	// service); production wiring always injects it via WithRelationStore.
	relationQueries clients.RelationQueries

	// listScan — узкий порт наблюдаемости стоимости страницы (#653).
	// Не провязан ⇒ наблюдение выключено, а не сломано.
	listScan shared.ListScanRecorder
}

// NewListAccountsUseCase.
func NewListAccountsUseCase(r Repo) *ListAccountsUseCase {
	return &ListAccountsUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client used to resolve the principal's
// `viewer`-relation account-id set. Mirrors ListProjectsUseCase.
// WithListScanRecorder провязывает съём стоимости страницы (#653).
func (u *ListAccountsUseCase) WithListScanRecorder(rec shared.ListScanRecorder) *ListAccountsUseCase {
	u.listScan = rec
	return u
}

func (u *ListAccountsUseCase) WithRelationStore(relations clients.RelationQueries) *ListAccountsUseCase {
	u.relationQueries = relations
	return u
}

// fgaAccountType — the object type this list asks the model about.
const fgaAccountType = "account"

// Execute — sync read + cursor pagination, filtered to the principal's FGA
// `viewer`-set.
func (u *ListAccountsUseCase) Execute(ctx context.Context, f account.ListFilter) ([]domain.Account, string, error) {
	// C7 — формат ПЕРВЫМ стейтментом, до решения о том, кто спрашивает. Ниже
	// стоит замыкание по личности: анонимный вызывающий до репозитория не
	// доходит, поэтому проверка, живущая только там, для него не исполняется, и
	// один и тот же мусорный курсор получал бы разный ответ в зависимости от
	// того, что вызывающему выдано.
	if err := shared.ValidateVisiblePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}
	after, err := shared.DecodeVisiblePageToken("page_token", f.PageToken)
	if err != nil {
		return nil, "", err
	}

	// Anonymous / non-principal → empty (default-deny). Short-circuits BEFORE
	// any FGA call so an FGA outage never turns an anonymous request into
	// Unavailable (INV-3).
	if authzguard.IsAnonymous(ctx) {
		return []domain.Account{}, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)
	subject := principalSubject(principal)
	if subject == "" {
		// Тип принципала, который не резолвится в субъект модели, видит пусто.
		return []domain.Account{}, "", nil
	}
	if u.relationQueries == nil {
		return nil, "", shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	// ВОПРОС О СУБЪЕКТЕ — один на запрос, вне цикла набора страницы. Его отказ —
	// отказ запроса, а не «этот вызывающий не администратор».
	clusterAdmin, err := authzguard.SubjectIsClusterAdminE(ctx, u.relationQueries, subject)
	if err != nil {
		return nil, "", shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	scope, err := u.subjectScope(ctx, rd, principal, clusterAdmin)
	if err != nil {
		return nil, "", err
	}
	return u.collectVisiblePage(ctx, rd, subject, scope, f, after)
}

// subjectScope resolves the structural facts of the caller once per request.
//
// A reader that cannot answer them is a REFUSAL, not a licence to list
// un-narrowed: "I have nothing to narrow with" and "you may see nothing" are
// different facts, and the second must never be produced by the first.
func (u *ListAccountsUseCase) subjectScope(
	ctx context.Context, rd kanamerepo.Reader, principal operations.Principal, clusterAdmin bool,
) (visibility.Scope, error) {
	vr := rd.Visibility()
	if vr == nil {
		return visibility.Scope{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	scope, err := vr.ScopeOf(ctx, visibility.Subject{Type: principal.Type, ID: principal.ID})
	if err != nil {
		return visibility.Scope{}, shared.MapRepoErr(err)
	}
	// A cloud administrator's candidates are not narrowed: he holds no per-object
	// row anywhere, so any narrowing by iam's tables would be narrower than the
	// model.
	if clusterAdmin {
		scope.Unrestricted = true
	}
	return scope, nil
}

// collectVisiblePage fills one page with visible rows, reading candidates until
// the page is full or the caller's own candidates are exhausted.
func (u *ListAccountsUseCase) collectVisiblePage(
	ctx context.Context, rd kanamerepo.Reader, subject string,
	scope visibility.Scope, f account.ListFilter, after *shared.VisibleCursor,
) ([]domain.Account, string, error) {
	want := shared.EffectiveListPageSize(f.PageSize)
	// One row beyond the page: a non-empty token is issued only when a visible row
	// past this page has ALREADY been read and judged (C2).
	need := want + 1
	// Насыщающее сужение, а не голое int32(need): величина здесь заведомо мала
	// (want ≤ MaxListPageSize), но «заведомо» — рассуждение автора, а не свойство
	// типа, и проверяющий переполнение анализатор его не знает. Общий helper
	// делает границу свойством кода.
	chunk := safeconv.IntToInt32(need)
	if chunk > shared.MaxListPageSize {
		chunk = shared.MaxListPageSize
	}
	candidates := scope.Candidates(fgaAccountType)

	var cursor *account.Cursor
	if after != nil {
		cursor = &account.Cursor{CreatedAt: after.CreatedAt, ID: after.ID}
	}

	// Собственный аккумулятор, а не массив репозитория: `rows[:0]` затирает и
	// отобранное, и опережающую строку, до которой вердикт ещё не дошёл.
	visible := make([]domain.Account, 0, need)

	scan := shared.ListScan{}
	for len(visible) < need {
		rows, _, err := rd.Accounts().List(ctx, account.ListFilter{
			Filter:     f.Filter,
			PageSize:   chunk,
			After:      cursor,
			Candidates: candidates,
		})
		if err != nil {
			return nil, "", shared.MapRepoErr(err)
		}
		if len(rows) == 0 {
			break
		}
		scan.AddBatch(len(rows))
		last := rows[len(rows)-1]
		cursor = &account.Cursor{CreatedAt: last.CreatedAt, ID: string(last.ID)}

		judged, err := u.judge(ctx, subject, rows)
		if err != nil {
			return nil, "", err
		}
		visible = append(visible, judged...)

		if len(rows) < int(chunk) {
			break // кандидаты исчерпаны
		}
	}

	// Токен считается от последней ОТДАННОЙ видимой строки в keyset-порядке —
	// том самом, в котором их вернул обход.
	scan.Report(ctx, u.listScan, "account")

	if len(visible) > want {
		boundary := visible[want-1]
		return visible[:want], shared.EncodeVisiblePageToken(shared.VisibleCursor{
			CreatedAt: boundary.CreatedAt,
			ID:        string(boundary.ID),
		}), nil
	}
	return visible, "", nil
}

// judge keeps the rows this caller may see, in the order they were read.
//
// Every candidate is put to the model — this surface has no floor. Fail-closed:
// a verdict that could not be obtained aborts the request (UNAVAILABLE), because
// a page filtered by an incomplete answer under-reports, and an under-report
// reads to a reconciliation loop as "these are gone".
func (u *ListAccountsUseCase) judge(
	ctx context.Context, subject string, rows []domain.Account,
) ([]domain.Account, error) {
	granted, err := authzfilter.VisibleSet(ctx, u.relationQueries, subject, fgaAccountType, accountIDsOf(rows))
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	out := make([]domain.Account, 0, len(rows))
	for _, a := range rows {
		if granted[string(a.ID)] {
			out = append(out, a)
		}
	}
	return out, nil
}

// accountIDsOf projects an account page to its bare ids.
func accountIDsOf(rows []domain.Account) []string {
	out := make([]string, 0, len(rows))
	for _, a := range rows {
		out = append(out, string(a.ID))
	}
	return out
}

// principalSubject builds the FGA subject string from the principal type:
// `user:<id>` for users, `service_account:<id>` for SAs.
// Any other type yields "" (no resolvable subject → deny).
func principalSubject(p operations.Principal) string {
	switch p.Type {
	case "user":
		return "user:" + p.ID
	case "service_account":
		return "service_account:" + p.ID
	default:
		return ""
	}
}
