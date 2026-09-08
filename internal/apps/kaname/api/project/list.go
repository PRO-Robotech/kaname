// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// list.go — ListProjectsUseCase.
//
// # A page of this list is a page of the VISIBLE (task #645)
//
// It used to be a window over the whole `projects` table, from which the visible
// was subtracted afterwards. That order loses every project with more than
// `page_size` invisible predecessors by creation time: the row never reaches the
// narrowing at all, so the caller receives `200` with an empty array while a Get
// on that same project answers `200`. The threshold depends on the population of
// the cloud and on nothing else — not on rights, not on load — so it arrives
// silently and reads, to the tenant, as "you have nothing".
//
// The page is therefore SELECTED narrowed, in three parts that do not work apart:
//
//  1. CANDIDATES — a superset of the visible, read from iam's OWN database:
//     accounts the caller owns, accounts he reaches through a grant (his own or
//     one made to a group he belongs to), and projects a grant names by name
//     (internal/repo/kaname/visibility). Foreign objects are not in it at all,
//     which is why the price of a request does not follow the population.
//  2. VERDICT — pronounced by the authorization MODEL, per candidate, with the
//     same predicate as before (internal/authzfilter). The SQL selects; it never
//     decides. Making it decide would put a second, home-grown rights system
//     beside the model, which is what `security.md` §«Авторизация живёт в МОДЕЛИ»
//     forbids. The one exception is the ownership FLOOR — see below.
//  3. REFILL — if the verdict leaves fewer than `page_size` visible rows and the
//     candidates are not exhausted, more candidates are read. Bounded by the page
//     asked for and by the caller's own candidates; never by the population.
//
// # The ownership floor asks no verdict, and that is not an oversight
//
// Ownership is a column of iam's own table, not a tuple. An account owner sees
// the contents of his account on a stand whose materialization has never run —
// which is exactly the state a drainer outage produces, and exactly when the
// owner most needs his own listing. Reading the model text and concluding this
// code path is redundant has already misled one round of review; the probe that
// settles it seeds NO tuple at all (645-05).
//
// # What the loop must not do, and why it is written this way
//
//   - it runs inside ONE reader. N refills across N readers would be N snapshots,
//     and a keyset walk across shifting snapshots skips rows;
//   - it accumulates into its OWN slice. Reusing the repository's array
//     (`filtered := rows[:0]`) would overwrite rows that have not been judged yet
//     — including the look-ahead row the token depends on;
//   - the structural facts about the caller are resolved ONCE, before it starts.
//     Expressed as subqueries of the page read they would be re-derived on every
//     refill: the same facts, recomputed, N times;
//   - the ONE question about the caller (is he a cluster administrator) is asked
//     once per request, OUTSIDE the loop, and its FAILURE is a refusal. Folding it
//     into "not an admin" would answer a well-formed, silently narrowed `200`,
//     which the caller cannot tell from a revocation.
//
// # Token semantics changed, and the change is breaking on purpose
//
// A non-empty `next_page_token` is now issued ONLY when a visible row BEYOND the
// returned page has already been read and judged. That is the only way "the token
// is empty exactly when nothing visible remains" can hold: a token issued just in
// case IS the old behaviour — a promise of a next page that arrives empty. The
// token therefore carries its own form marker, and a token minted by the previous
// build is refused (INVALID_ARGUMENT) rather than continued approximately; an
// approximate continuation skips rows silently, which is the outcome this whole
// change exists to remove. See shared.EncodeVisiblePageToken.
//
// # Unchanged
//
//   - format before rights: page_size / page_token are judged as the FIRST
//     statement, before the short-circuit on identity, so the same malformed input
//     gets the same answer from an anonymous caller, a caller with no grants and
//     an owner;
//   - existence is never disclosed: a caller with nothing visible gets an empty
//     page, never PERMISSION_DENIED;
//   - anonymous never reaches the relation store, so an outage of that store
//     cannot turn an unauthenticated request into UNAVAILABLE;
//   - fail-closed: a nil relation port, an unresolvable rights question or a
//     candidate scope that cannot be read is UNAVAILABLE, never a narrowed page.

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
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// fgaProjectType — the object type this list asks the model about.
const fgaProjectType = "project"

type ListProjectsUseCase struct {
	repo Repo
	// relationQueries — the relation-store port. It carries BOTH questions this
	// use-case asks: the one about the caller (cluster administrator) and the
	// per-object verdicts. When nil the whole read fails closed.
	relationQueries clients.RelationQueries

	// listScan — узкий порт наблюдаемости стоимости страницы (#653).
	// Не провязан ⇒ наблюдение выключено, а не сломано.
	listScan shared.ListScanRecorder
}

func NewListProjectsUseCase(r Repo) *ListProjectsUseCase {
	return &ListProjectsUseCase{repo: r}
}

// WithRelationStore wires the relation-store port.
// WithListScanRecorder провязывает съём стоимости страницы (#653).
func (u *ListProjectsUseCase) WithListScanRecorder(rec shared.ListScanRecorder) *ListProjectsUseCase {
	u.listScan = rec
	return u
}

func (u *ListProjectsUseCase) WithRelationStore(relations clients.RelationQueries) *ListProjectsUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListProjectsUseCase) Execute(ctx context.Context, f project.ListFilter) ([]domain.Project, string, error) {
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

	// Анонимный — пустая страница и НИ ОДНОГО обращения к стору отношений.
	if authzguard.IsAnonymous(ctx) {
		return []domain.Project{}, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)
	subject := principalSubject(principal)
	if subject == "" {
		// Тип принципала, который не резолвится в субъект модели, видит пусто.
		return []domain.Project{}, "", nil
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
func (u *ListProjectsUseCase) subjectScope(
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
func (u *ListProjectsUseCase) collectVisiblePage(
	ctx context.Context, rd kanamerepo.Reader, subject string,
	scope visibility.Scope, f project.ListFilter, after *shared.VisibleCursor,
) ([]domain.Project, string, error) {
	want := shared.EffectiveListPageSize(f.PageSize)
	// One row beyond the page: a non-empty token is issued only when a visible row
	// past this page has ALREADY been read and judged (C2). Read as an ordinary
	// candidate, so it costs no more than it is.
	need := want + 1
	// Один чтение-запрос спрашивает страницу кандидатов. Потолок — контрактный
	// максимум, а не `need`: при `page_size` = 1000 опережающая строка не влезает
	// в один запрос, и её приносит второе чтение.
	// Насыщающее сужение, а не голое int32(need): величина здесь заведомо мала
	// (want ≤ MaxListPageSize), но «заведомо» — рассуждение автора, а не свойство
	// типа, и проверяющий переполнение анализатор его не знает. Общий helper
	// делает границу свойством кода.
	chunk := safeconv.IntToInt32(need)
	if chunk > shared.MaxListPageSize {
		chunk = shared.MaxListPageSize
	}
	candidates := scope.Candidates(fgaProjectType)

	var cursor *project.Cursor
	if after != nil {
		cursor = &project.Cursor{CreatedAt: after.CreatedAt, ID: after.ID}
	}

	// Собственный аккумулятор, а не массив репозитория: `rows[:0]` затирает и
	// отобранное, и опережающую строку, до которой вердикт ещё не дошёл.
	visible := make([]domain.Project, 0, need)

	scan := shared.ListScan{}
	for len(visible) < need {
		rows, _, err := rd.Projects().List(ctx, project.ListFilter{
			AccountID:  f.AccountID,
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
		cursor = &project.Cursor{CreatedAt: last.CreatedAt, ID: string(last.ID)}

		judged, err := u.judge(ctx, subject, scope, rows)
		if err != nil {
			return nil, "", err
		}
		visible = append(visible, judged...)

		if len(rows) < int(chunk) {
			break // кандидаты исчерпаны
		}
	}

	// Токен считается от последней ОТДАННОЙ видимой строки в keyset-порядке —
	// том самом, в котором их вернул обход. Никакой пересортировки между этими
	// двумя строками нет и быть не должно.
	scan.Report(ctx, u.listScan, "project")

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
// The ownership floor answers first and asks the model nothing; everything else
// is decided by the model, in one batched round per relation. Fail-closed: a
// verdict that could not be obtained aborts the request (UNAVAILABLE) — a page
// filtered by an incomplete answer under-reports, and an under-report reads to a
// reconciliation loop as "these are gone".
func (u *ListProjectsUseCase) judge(
	ctx context.Context, subject string, scope visibility.Scope, rows []domain.Project,
) ([]domain.Project, error) {
	ask := make([]string, 0, len(rows))
	for _, p := range rows {
		if !scope.Owns(string(p.AccountID)) {
			ask = append(ask, string(p.ID))
		}
	}
	granted := map[string]bool{}
	if len(ask) > 0 {
		var err error
		granted, err = authzfilter.VisibleSet(ctx, u.relationQueries, subject, fgaProjectType, ask)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
	}
	out := make([]domain.Project, 0, len(rows))
	for _, p := range rows {
		if scope.Owns(string(p.AccountID)) || granted[string(p.ID)] {
			out = append(out, p)
		}
	}
	return out, nil
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
