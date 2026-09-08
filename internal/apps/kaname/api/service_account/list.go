// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// list.go — ListServiceAccountsUseCase. Единая модель видимости (паритет с
// account/project/role List): результат фильтруется через UNION FGA-отношений
//
//	visible(id) = Check(subj,"viewer","iam_service_account:"+id)
//	            ∨ Check(subj,"v_list","iam_service_account:"+id)
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
//   - ветка `viewer` — SA, на которые принципал держит viewer-tier (account-admin
//     резолвит viewer на каждый SA своего аккаунта через account-tier cascade;
//     viewer подразумевает доступ к содержимому);
//   - ветка `v_list` — SA, выданные ТОЛЬКО `iam.serviceAccount.{get,list}` через
//     names/labels-селектор (object-only `iam_service_account:<id> # v_list @ subj`,
//     БЕЗ viewer-каскада — see-in-selector-without-content).
//
// Устраняет прежнюю membership-over-show модель (любой член аккаунта видел ВСЕ SA
// аккаунта без per-object грантов). Инварианты сохранены:
//   - anonymous → empty ДО любого FGA-вызова (fail-closed, не Unavailable);
//     не-forwarded principal (включая system/bootstrap fallback) — тоже anonymous;
//   - FGA-ошибка на любой relation → Unavailable (никогда partial/owner-only);
//   - cluster-admin/operator покрыты той же веткой `viewer` (system_viewer floor).

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
	reposa "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

type ListServiceAccountsUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects-порт, резолвящий visible-set принципала на
	// iam_service_account. При nil use-case fail-closed (никогда unfiltered).
	relationQueries clients.RelationQueries

	// listScan — узкий порт наблюдаемости стоимости страницы (#653).
	// Не провязан ⇒ наблюдение выключено, а не сломано.
	listScan shared.ListScanRecorder
}

func NewListServiceAccountsUseCase(r Repo) *ListServiceAccountsUseCase {
	return &ListServiceAccountsUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client (паритет с account/role List).
// WithListScanRecorder провязывает съём стоимости страницы (#653).
func (u *ListServiceAccountsUseCase) WithListScanRecorder(rec shared.ListScanRecorder) *ListServiceAccountsUseCase {
	u.listScan = rec
	return u
}

func (u *ListServiceAccountsUseCase) WithRelationStore(relations clients.RelationQueries) *ListServiceAccountsUseCase {
	u.relationQueries = relations
	return u
}

// fgaServiceAccountType — the object type this list asks the model about.
const fgaServiceAccountType = "iam_service_account"

func (u *ListServiceAccountsUseCase) Execute(ctx context.Context, f reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
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
		return []domain.ServiceAccount{}, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	subject := principalSubject(principal)
	if subject == "" {
		// Тип принципала, который не резолвится в субъект модели, видит пусто.
		return []domain.ServiceAccount{}, "", nil
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
func (u *ListServiceAccountsUseCase) subjectScope(
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
// Каждый кандидат ставится модели: полосы «без вердикта» здесь нет ни у кого.
// Прежде она была — параметром `unfiltered` под системный бутстрап, — и не
// исполнялась НИ ПРИ КАКОМ входе: замыкание по личности выше по Execute относит
// бутстрап к анонимным (authzguard.IsAnonymous). Ветка снята вместе с параметром
// (#648); несужённая страница администратору облака остаётся достижимой, но по
// структурному пути — scope.Unrestricted из subjectScope.
func (u *ListServiceAccountsUseCase) collectVisiblePage(
	ctx context.Context, rd kanamerepo.Reader, subject string,
	scope visibility.Scope, f reposa.ListFilter, after *shared.VisibleCursor,
) ([]domain.ServiceAccount, string, error) {
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
	candidates := scope.Candidates(fgaServiceAccountType)

	var cursor *reposa.Cursor
	if after != nil {
		cursor = &reposa.Cursor{CreatedAt: after.CreatedAt, ID: after.ID}
	}

	// Собственный аккумулятор, а не массив репозитория: `rows[:0]` затирает и
	// отобранное, и опережающую строку, до которой вердикт ещё не дошёл.
	visible := make([]domain.ServiceAccount, 0, need)

	scan := shared.ListScan{}
	for len(visible) < need {
		rows, _, err := rd.ServiceAccounts().List(ctx, reposa.ListFilter{
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
		cursor = &reposa.Cursor{CreatedAt: last.CreatedAt, ID: string(last.ID)}

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
	scan.Report(ctx, u.listScan, "service_account")

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
// a verdict that could not be obtained aborts the request (UNAVAILABLE).
func (u *ListServiceAccountsUseCase) judge(
	ctx context.Context, subject string, rows []domain.ServiceAccount,
) ([]domain.ServiceAccount, error) {
	granted, err := authzfilter.VisibleSet(ctx, u.relationQueries, subject,
		fgaServiceAccountType, serviceAccountIDsOf(rows))
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	out := make([]domain.ServiceAccount, 0, len(rows))
	for _, sa := range rows {
		if granted[string(sa.ID)] {
			out = append(out, sa)
		}
	}
	return out, nil
}

// serviceAccountIDsOf проецирует страницу SA в голые id.
func serviceAccountIDsOf(rows []domain.ServiceAccount) []string {
	out := make([]string, 0, len(rows))
	for _, sa := range rows {
		out = append(out, string(sa.ID))
	}
	return out
}

// principalSubject builds the FGA subject string: `user:<id>` / `service_account:<id>`.
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
