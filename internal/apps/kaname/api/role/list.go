// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// list.go — ListRolesUseCase: per-object scope-filtered RoleService.List.
//
// The Role catalog has TWO visibility layers:
//   - System roles (is_system) are the tenant-wide reference floor — every
//     authenticated principal sees them. Both reads are declared
//     `scope_filtered` in the contract, so the gateway asks nothing per-object
//     and this use-case decides; system roles are NOT subject to the per-object
//     filter.
//   - CUSTOM roles are filtered per-object via the UNION of the FGA `viewer` and
//     `v_list` relations on iam_role, asked DIRECTLY for the roles ON THE PAGE —
//     parity with account/project List. The `viewer` tier on
//     iam_role cascades from the ACCOUNT tier (account.admin→editor→viewer), so a
//     role's creator / account-admin resolves visibility on every role
//     hierarchy-linked to their account; the `v_list` branch surfaces an
//     OBJECT-ONLY selector grant (`iam_role:<id> # v_list @ subj`, no viewer
//     cascade) — the see-in-selector-without-content path. A foreign account
//     resolves neither (no existence leak). The SAME resolver backs
//     RoleService.Get so List == Get for custom roles (read==enforce).
//
//     Design-B (flat-authz verb-bearing complete): v_* are DECOUPLED from the tier
//     relations (no viewer ⊇ v_list union in the FGA model), so a v_list-only
//     selector grant does NOT resolve `viewer`. A viewer-only filter therefore hid
//     such a grant from its grantee; the viewer ∪ v_list union surfaces it.
//     Content follows the SAME union rather than a second relation: Get asks the
//     very question this page asks (read==enforce), so `iam_role` carries no
//     separate content predicate — `v_get` in particular gates nothing here, no
//     catalog entry names it for this type. The predicate is declared in ONE
//     place (`pageRelations`, internal/authzfilter) and held against the
//     permission catalog type by type by a repo-wide gate; whether this type
//     ought to carry a content relation at all is an open decision, tracked as
//     #1922. The owner sees their own role via the viewer branch (account-tier
//     cascade).
//
// # A page of this list is a page of the VISIBLE (task #645)
//
// The page used to be a raw window over `roles`, from which the visible was
// subtracted afterwards — and on THIS surface that defect arrived on day one,
// with no population at all: the migrations seed a system-role catalog that by
// itself fills a default page, so a tenant's own custom role sat past the window
// from the moment it was created.
//
// The page is therefore SELECTED narrowed — CANDIDATES from iam's own database,
// VERDICT from the model, REFILL until the page is full. The shape and the
// invariants of the loop are stated once, in the project sibling
// (api/project/list.go). What is peculiar here is the catalog FLOOR: `is_system`
// is a condition of the candidate SELECT (see the repository's predicate), not a
// filter applied to rows already taken. A floor applied after the fact is the
// original defect wearing a floor's name.
//
// Still forbidden: asking the MODEL which roles are visible and narrowing the SQL
// to that id-set. The external engine truncated that enumeration server-side
// (default 1000, no continuation token) and made a tenant's own custom roles vanish
// past the cap; the engine is gone, and the ban survives it because "enumerate
// everything visible" is unbounded by construction. The candidate
// set above is a different thing — it comes from iam's own tables, has no cap,
// and decides nothing. See the internal/authzfilter package doc.
//
// Two consequences of the old order are GONE: a page no longer comes back SHORT
// merely because rows were filtered out of it, and `next_page_token` is no longer
// derived from the last row EXAMINED — it is the last row RETURNED, which is
// visible by construction.
//
// f.AccountID (set by the handler from req.account_id) scopes the catalog
// to system + that Account's custom roles at the SQL layer.
//
// Fail-closed: a nil FGA port or an FGA error → Unavailable (never an unfiltered
// catalog leak, never an owner-only fallback).

import (
	"context"
	"sort"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

type ListRolesUseCase struct {
	repo Repo
	// cat — ЖИВЫЕ строки каталога: набор глаголов типа для превью роли (#1994).
	// Приходит ОБЯЗАТЕЛЬНЫМ параметром, а не опцией: непровязанный источник даёт
	// роль без набора, а проекция такую роль отвергает — то есть чтение отказало
	// бы целиком и в рантайме. Компилятор ловит это раньше.
	cat catalog.Source

	// relationQueries — FGA port resolving the principal's `viewer ∪ v_list`
	// visibility on the iam_role objects of a page. When nil the use-case fails
	// closed.
	relationQueries clients.RelationQueries

	// listScan — узкий порт наблюдаемости стоимости страницы (#653).
	// Не провязан ⇒ наблюдение выключено, а не сломано.
	listScan shared.ListScanRecorder
}

func NewListRolesUseCase(r Repo, cat catalog.Source) *ListRolesUseCase {
	return &ListRolesUseCase{repo: r, cat: cat}
}

// WithRelationStore wires the FGA client used to resolve the principal's
// readable-role visibility on iam_role. Mirrors ListAccountsUseCase /
// ListProjectsUseCase.
// WithListScanRecorder провязывает съём стоимости страницы (#653).
func (u *ListRolesUseCase) WithListScanRecorder(rec shared.ListScanRecorder) *ListRolesUseCase {
	u.listScan = rec
	return u
}

func (u *ListRolesUseCase) WithRelationStore(relations clients.RelationQueries) *ListRolesUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListRolesUseCase) Execute(ctx context.Context, f reporole.ListFilter) ([]domain.Role, string, error) {
	// C7 — формат ПЕРВЫМ стейтментом, до решения о том, кто спрашивает. Ниже
	// стоит замыкание по личности: анонимный вызывающий до репозитория не
	// доходит, поэтому проверка, живущая только там, для него не исполняется, и
	// один и тот же мусорный курсор получал бы разный ответ в зависимости от
	// того, что вызывающему выдано.
	//
	// На этой поверхности формат судит use-case, а не хендлер (у остальных шести
	// — хендлер): хендлер проверяет только СЫРОЙ page_size, потому что сужение
	// int64→int32 насыщающее. Токен судится здесь, и это по-прежнему первый
	// стейтмент — порядок «формат до замыкания» держится у всех семи.
	if err := shared.ValidateVisiblePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}
	after, err := shared.DecodeVisiblePageToken("page_token", f.PageToken)
	if err != nil {
		return nil, "", err
	}
	// Anonymous → empty (default-deny) BEFORE any FGA call so an FGA outage never
	// turns an anonymous request into Unavailable.
	if authzguard.IsAnonymous(ctx) {
		return []domain.Role{}, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	// Unwired FGA port → fail closed BEFORE touching the database: no visibility
	// is resolvable at all, so the page could only be served unfiltered (a catalog
	// leak) or discarded.
	if u.relationQueries == nil {
		return nil, "", shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)

	// ВОПРОС О СУБЪЕКТЕ — один на запрос, вне цикла набора страницы. Его отказ —
	// отказ запроса, а не «этот вызывающий не администратор».
	//
	// Нерезолвимый субъект вопроса не задаёт и ошибкой не является: такому
	// вызывающему причитается пол каталога и ничего сверх него.
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
	return u.collectVisiblePage(ctx, rd, principal, scope, f, after)
}

// subjectScope resolves the structural facts of the caller once per request.
//
// A reader that cannot answer them is a REFUSAL, not a licence to list
// un-narrowed: "I have nothing to narrow with" and "you may see nothing" are
// different facts, and the second must never be produced by the first.
func (u *ListRolesUseCase) subjectScope(
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
//
// The catalog floor travels INSIDE the candidate narrowing (see the repository's
// predicate), so a caller with no grants at all still selects the whole system
// catalog rather than whatever fraction of it fell inside a raw window.
func (u *ListRolesUseCase) collectVisiblePage(
	ctx context.Context, rd kanamerepo.Reader, principal operations.Principal,
	scope visibility.Scope, f reporole.ListFilter, after *shared.VisibleCursor,
) ([]domain.Role, string, error) {
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
	candidates := scope.Candidates(fgaRoleObjectType)

	var cursor *reporole.Cursor
	if after != nil {
		cursor = &reporole.Cursor{CreatedAt: after.CreatedAt, ID: after.ID}
	}

	// Собственный аккумулятор, а не массив репозитория: `rows[:0]` затирает и
	// отобранное, и опережающую строку, до которой вердикт ещё не дошёл.
	visible := make([]domain.Role, 0, need)

	scan := shared.ListScan{}
	for len(visible) < need {
		rows, _, err := rd.Roles().List(ctx, reporole.ListFilter{
			AccountID:  f.AccountID,
			IsSystem:   f.IsSystem,
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
		cursor = &reporole.Cursor{CreatedAt: last.CreatedAt, ID: string(last.ID)}

		judged, err := u.judge(ctx, principal, rows)
		if err != nil {
			return nil, "", err
		}
		visible = append(visible, judged...)

		if len(rows) < int(chunk) {
			break // кандидаты исчерпаны
		}
	}

	// Токен считается от последней ОТДАННОЙ видимой строки В KEYSET-ПОРЯДКЕ, и
	// только ПОТОМ страница пересортировывается для показа. Обратный порядок дал
	// бы токеном границу презентационной сортировки — величину, к обходу
	// отношения не имеющую, и обход поехал бы не оттуда.
	page, next := visible, ""
	scan.Report(ctx, u.listScan, "role")

	if len(visible) > want {
		boundary := visible[want-1]
		page = visible[:want]
		next = shared.EncodeVisiblePageToken(shared.VisibleCursor{
			CreatedAt: boundary.CreatedAt,
			ID:        string(boundary.ID),
		})
	}
	// redesign-2026 F6: present the canonical system-role catalog first — system
	// roles ahead of custom, and among system the canonical four in
	// viewer→editor→admin→owner order (domain.CanonicalRank). Stable, so the
	// (created_at,id) keyset order is preserved within each rank group; this is a
	// presentation refinement over the authoritative keyset page.
	sortCatalogFirst(page)

	// Целость — ОДИН вопрос на СТРАНИЦУ, и задаётся он после её сужения: на
	// накопителе `visible` он стоил бы на `want+1` строк больше, а внутри цикла
	// добора — по вопросу на итерацию. Стоимость ответа обязана принадлежать
	// ответу, а не тому, сколько строк пришлось прочитать, чтобы его собрать.
	//
	// Тот же производитель, что у `Get`: расхождение поверхностей непредставимо.
	if ierr := attachIntegrity(ctx, rd, u.cat, page); ierr != nil {
		return nil, "", ierr
	}
	return page, next, nil
}

// judge keeps the rows this caller may see, in the order they were read.
//
// System roles are the tenant-wide catalog FLOOR and ask the model nothing; a
// page carrying only system roles costs no relation call at all. Everything else
// goes through resolveVisibleRoleIDs — the SAME function GetRoleUseCase calls, so
// the two read surfaces keep drawing from one question and Get can never serve a
// custom role absent from List. Asking the model here directly would be a second
// spelling of that question, free to drift from the one Get uses.
//
// Fail-closed: a verdict that could not be obtained aborts the request
// (UNAVAILABLE).
func (u *ListRolesUseCase) judge(
	ctx context.Context, principal operations.Principal, rows []domain.Role,
) ([]domain.Role, error) {
	ask := customRoleIDs(rows)
	granted := map[string]bool{}
	if len(ask) > 0 {
		var err error
		granted, err = resolveVisibleRoleIDs(ctx, u.relationQueries, principal, ask)
		if err != nil {
			return nil, err
		}
	}
	out := make([]domain.Role, 0, len(rows))
	for _, r := range rows {
		if r.IsSystem || granted[string(r.ID)] {
			out = append(out, r)
		}
	}
	return out, nil
}

// customRoleIDs projects a role page to the ids of its CUSTOM roles — the only
// ones subject to the per-object visibility filter (system roles are the catalog
// floor).
func customRoleIDs(roles []domain.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if !r.IsSystem {
			out = append(out, string(r.ID))
		}
	}
	return out
}

// sortCatalogFirst stably orders a role page: system roles first, then by canonical
// rank (viewer<editor<admin<owner<other), preserving the incoming (created_at,id)
// order within equal keys.
func sortCatalogFirst(roles []domain.Role) {
	sort.SliceStable(roles, func(i, j int) bool {
		si, sj := roles[i].IsSystemDerived(), roles[j].IsSystemDerived()
		if si != sj {
			return si // system roles first
		}
		return roles[i].CanonicalRank() < roles[j].CanonicalRank()
	})
}

// resolveVisibleRoleIDs returns which of the given CUSTOM-role ids the principal
// can read — the UNION of the FGA `viewer` and `v_list` relations on iam_role,
// asked DIRECTLY per object:
//
//		visible(id) = Check(subject, "viewer", "iam_role:"+id)
//		            ∨ Check(subject, "v_list", "iam_role:"+id)
//
//	  - The `viewer` branch surfaces roles the principal resolves the viewer tier on
//	    (the account-admin's own roles via the account-tier cascade; viewer implies
//	    content access). On the decoupled Design-B model v_* are NOT union-ed into
//	    tier, so viewer alone never surfaces an object-only v_list grant.
//	  - The `v_list` branch surfaces roles granted ONLY `iam.roles.{get,list}` via a
//	    names/labels selector — an OBJECT-ONLY `iam_role:<id> # v_list @ subj` tuple
//	    with NO viewer-tier cascade (see-in-selector-without-content).
//
// The predicate is unchanged from the ListObjects enumeration this replaces
// (ListObjects returns, by definition, what Check would allow). What changed is
// the SHAPE: the external relations engine capped that enumeration server-side at
// 1000 objects of the type in its store with no continuation token, so past that
// population a role's own grantee fell outside the returned prefix — List dropped
// the role and Get answered NOT_FOUND, permanently. The engine is gone; the shape
// is what mattered and it stays (internal/authzfilter package doc).
//
// Fail-closed: a nil FGA port or an FGA error on ANY object → Unavailable; an
// unresolvable subject → empty set (system roles still served).
//
// Shared by ListRolesUseCase (filter the custom roles on a page) AND
// GetRoleUseCase (enforce a single custom role) so the two read surfaces draw
// from the IDENTICAL FGA question — Get can never serve a custom role absent
// from List (no existence leak).
func resolveVisibleRoleIDs(ctx context.Context, relationQueries clients.RelationQueries, principal operations.Principal, ids []string) (map[string]bool, error) {
	if relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil // unknown principal → only system catalog floor
	}
	visible, err := authzfilter.VisibleSet(ctx, relationQueries, subject, fgaRoleObjectType, ids)
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, nil
}

// fgaRoleObjectType — the rights-model object type of a Role.
const fgaRoleObjectType = "iam_role"

// principalSubject builds the FGA subject string from the principal type:
// `user:<id>` for users, `service_account:<id>` for SAs. Any other type → ""
// (no resolvable subject → only the system catalog floor).
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
