// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// list.go — ListUsersUseCase. Единая модель видимости (паритет с
// account/serviceAccount/role List): результат фильтруется через UNION
// FGA-отношений
//
//	visible(id) = Check(subj,"viewer","iam_user:"+id)
//	            ∨ Check(subj,"v_list","iam_user:"+id)
//
// спрашиваемых для КАНДИДАТОВ, отобранных сужённо (задача #645, см. ниже).
// Перечисление у МОДЕЛИ («перечислить всё видимое и пересечь») остаётся
// запрещённым. У прежнего движка оно молча резалось серверным пределом без
// продолжения; движка нет, а запрет остаётся по существу — вопрос «перечисли
// всё видимое» неограничен по построению, и ответ на него страницей не является
// (см. internal/authzfilter).
//
// # Страница этого списка — страница ВИДИМОГО (задача #645)
//
// Прежде страница бралась окном по всей таблице, и видимое вычиталось после.
// Такой порядок теряет всякую строку, перед которой по времени создания лежит
// больше `page_size` невидимых: до сужения она не доезжает вовсе, и арендатор
// получает 200 с пустым массивом, тогда как чтение того же объекта по
// идентификатору отвечает 200.
//
// Теперь страница ОТБИРАЕТСЯ сужённой: КАНДИДАТЫ — из собственной БД iam
// (`internal/repo/kaname/visibility`, надмножество видимого), ВЕРДИКТ — у модели
// прав по каждому кандидату, ДОГРУЗКА — пока страница не полна. Форма цикла и
// его инварианты изложены один раз, у соседа-проекта (api/project/list.go).
//
// Токен теперь обозначает границу ВИДИМОЙ последовательности — последнюю
// ОТДАННУЮ строку, видимую по построению, — и выдаётся только когда за отданной
// страницей уже прочитана и осуждена видимая строка. Форма токена сменилась и
// несёт признак: обход, начатый прежней сборкой, отвергается, а не продолжается
// приблизительно.
//
//   - ветка `viewer` — user'ы, на которые принципал держит viewer-tier
//     (account-admin/owner резолвит viewer на каждого user'а своего аккаунта через
//     account-tier cascade; self-tuple iam_user:<U>#subject@user:<U> резолвится в
//     viewer-ветку — self-floor);
//   - ветка `v_list` — user'ы, выданные ТОЛЬКО `iam.user.{get,list}` через
//     names/labels-селектор (object-only `iam_user:<id> # v_list @ subj`, БЕЗ
//     viewer-каскада — see-in-selector-without-content).
//
// Устраняет прежнюю membership-over-show модель (любой член аккаунта видел ВСЕХ
// user'ов аккаунта без per-object грантов, T3.3 D-5). Инварианты сохранены:
//   - anonymous → empty ДО любого FGA-вызова (fail-closed, не Unavailable);
//     не-forwarded principal (включая system/bootstrap fallback) — тоже anonymous;
//   - FGA-ошибка на любой relation → Unavailable (никогда partial/owner-only);
//   - cluster-admin/operator/owner покрыты той же веткой `viewer` (tier-cascade).

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
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

type ListUsersUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects-порт, резолвящий visible-set принципала на
	// iam_user. При nil use-case fail-closed (никогда unfiltered).
	relationQueries clients.RelationQueries

	// listScan — узкий порт наблюдаемости стоимости страницы (#653).
	// Не провязан ⇒ наблюдение выключено, а не сломано.
	listScan shared.ListScanRecorder
}

func NewListUsersUseCase(r Repo) *ListUsersUseCase {
	return &ListUsersUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client (паритет с account/SA/role List).
// WithListScanRecorder провязывает съём стоимости страницы (#653).
func (uc *ListUsersUseCase) WithListScanRecorder(rec shared.ListScanRecorder) *ListUsersUseCase {
	uc.listScan = rec
	return uc
}

func (uc *ListUsersUseCase) WithRelationStore(relations clients.RelationQueries) *ListUsersUseCase {
	uc.relationQueries = relations
	return uc
}

// fgaUserType — the object type this list asks the model about.
const fgaUserType = "iam_user"

func (uc *ListUsersUseCase) Execute(ctx context.Context, f user.ListFilter) ([]domain.User, string, error) {
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
	// Anonymous → empty (default-deny) ДО любого FGA-вызова. authzguard.IsAnonymous
	// относит сюда и не-forwarded principal (api-gateway не передал заголовки →
	// system/bootstrap fallback) — fail-closed, без unfiltered-обхода.
	if authzguard.IsAnonymous(ctx) {
		return []domain.User{}, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	subject := userPrincipalSubject(principal)
	if subject == "" {
		// Тип принципала, который не резолвится в субъект модели, видит пусто.
		return []domain.User{}, "", nil
	}
	if uc.relationQueries == nil {
		return nil, "", shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	// ВОПРОС О СУБЪЕКТЕ — один на запрос, вне цикла набора страницы. Его отказ —
	// отказ запроса, а не «этот вызывающий не администратор».
	clusterAdmin, err := authzguard.SubjectIsClusterAdminE(ctx, uc.relationQueries, subject)
	if err != nil {
		return nil, "", shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	scope, err := uc.subjectScope(ctx, rd, principal, clusterAdmin)
	if err != nil {
		return nil, "", err
	}
	// Self-floor: юзер всегда видит собственную запись, независимо от
	// FGA-материализации (паритет с GetUser.IsSelf). Защищает от отсутствующего/
	// протухшего subject self-tuple.
	//
	// Собственный id держится ОТДЕЛЬНОЙ величиной, а не только внутри набора
	// кандидатов: набор отвечает «эту строку стоит прочитать», пол — «эту строку
	// вызывающий видит», и это разные утверждения. Слить их значило бы сделать
	// всякого кандидата видимым.
	self := ""
	if principal.Type == domain.PrincipalTypeUser && principal.ID != "" {
		self = principal.ID
	}
	return uc.collectVisiblePage(ctx, rd, subject, self, scope, f, after)
}

// subjectScope resolves the structural facts of the caller once per request.
//
// A reader that cannot answer them is a REFUSAL, not a licence to list
// un-narrowed: "I have nothing to narrow with" and "you may see nothing" are
// different facts, and the second must never be produced by the first.
func (uc *ListUsersUseCase) subjectScope(
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
// `self` is the caller's own user id — the floor of this surface. It enters the
// CANDIDATE set as well as the verdict, because the caller's own row may sit
// arbitrarily far past a raw window: a floor applied to an already-taken page is
// the original defect wearing a floor's name.
//
// Каждый кандидат ставится модели: полосы «без вердикта» здесь нет ни у кого.
// Прежде она была — параметром `unfiltered` под системный бутстрап, — и не
// исполнялась НИ ПРИ КАКОМ входе: замыкание по личности выше по Execute относит
// бутстрап к анонимным (authzguard.IsAnonymous). Ветка снята вместе с параметром
// (#648); несужённая страница администратору облака остаётся достижимой, но по
// структурному пути — scope.Unrestricted из subjectScope.
func (uc *ListUsersUseCase) collectVisiblePage(
	ctx context.Context, rd kanamerepo.Reader, subject, self string,
	scope visibility.Scope, f user.ListFilter, after *shared.VisibleCursor,
) ([]domain.User, string, error) {
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
	candidates := scope.Candidates(fgaUserType)
	if candidates != nil && self != "" {
		// A copy: Scope.Candidates hands back a fresh PageScope, but the slice it
		// carries is the Scope's own. Appending in place would grow a memo shared
		// with every other projection of this scope.
		objects := make([]string, 0, len(candidates.ObjectIDs)+1)
		objects = append(objects, candidates.ObjectIDs...)
		candidates = &visibility.PageScope{
			AccountIDs: candidates.AccountIDs,
			ObjectIDs:  append(objects, self),
		}
	}

	var cursor *user.Cursor
	if after != nil {
		cursor = &user.Cursor{CreatedAt: after.CreatedAt, ID: after.ID}
	}

	// Собственный аккумулятор, а не массив репозитория: `rows[:0]` затирает и
	// отобранное, и опережающую строку, до которой вердикт ещё не дошёл.
	visible := make([]domain.User, 0, need)

	scan := shared.ListScan{}
	for len(visible) < need {
		rows, _, err := rd.Users().List(ctx, user.ListFilter{
			AccountID:  f.AccountID,
			AccountIDs: f.AccountIDs,
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
		cursor = &user.Cursor{CreatedAt: last.CreatedAt, ID: string(last.ID)}

		judged, err := uc.judge(ctx, subject, self, rows)
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
	scan.Report(ctx, uc.listScan, "user")

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
// The self floor answers first and asks the model nothing; everything else is
// decided by the model. Fail-closed: a verdict that could not be obtained aborts
// the request (UNAVAILABLE).
func (uc *ListUsersUseCase) judge(
	ctx context.Context, subject, self string, rows []domain.User,
) ([]domain.User, error) {
	ask := make([]string, 0, len(rows))
	for _, u := range rows {
		if string(u.ID) != self {
			ask = append(ask, string(u.ID))
		}
	}
	granted := map[string]bool{}
	if len(ask) > 0 {
		var err error
		granted, err = authzfilter.VisibleSet(ctx, uc.relationQueries, subject, fgaUserType, ask)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
	}
	out := make([]domain.User, 0, len(rows))
	for _, u := range rows {
		if string(u.ID) == self || granted[string(u.ID)] {
			out = append(out, u)
		}
	}
	return out, nil
}

// userPrincipalSubject builds the FGA subject string: `user:<id>` / `service_account:<id>`.
func userPrincipalSubject(p operations.Principal) string {
	switch p.Type {
	case "user":
		return "user:" + p.ID
	case "service_account":
		return "service_account:" + p.ID
	default:
		return ""
	}
}
