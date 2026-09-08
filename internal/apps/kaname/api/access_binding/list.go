// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list.go — ListUseCase (redesign-2026 F11). The single, plain List that
// supersedes the legacy ListByScope/ListBySubject/ListByRole/ListByAccount family.
// Visibility is the caller's `viewer ∪ v_list` set on iam_access_binding, resolved
// PER-OBJECT for the rows on the page.
//
// # A page of this list is a page of the VISIBLE (task #645)
//
// It used to be a window over the whole `access_bindings` table, from which the
// visible was subtracted afterwards. That order loses every binding with more
// than `page_size` invisible predecessors by creation time: the row never
// reaches the narrowing at all, so the caller receives `200` with an empty array
// while a Get on that same binding answers `200`.
//
// The page is therefore SELECTED narrowed — CANDIDATES from iam's own database,
// VERDICT from the authorization model, REFILL until the page is full. The
// shape and the invariants of the loop are stated once, in the project sibling
// (api/project/list.go); what is peculiar to a binding is that it carries no
// account column — its account is DERIVED from its scope — and that derivation
// lives in the repository, next to the identical one ListByAccount already uses.
//
// The candidate set is a superset of the visible by the MODEL's own text
// (`fga_model.fga`, type `iam_access_binding`): reading a binding comes either
// from a direct tuple on it, or from `super_admin`, which derives through the
// binding's parent pointer — `admin from account` / `super_admin from project`
// (both reduce to the account of the scope) or `any_admin from cluster` (a cloud
// administrator, for whom there is no narrowing at all). The type admits no
// fourth path.
//
// Two consequences of the old order are GONE and must not be restored from the
// paragraphs that used to describe them: a page no longer comes back SHORT
// merely because rows were filtered out of it, and `next_page_token` no longer
// encodes a row the caller may not read — it is the last row RETURNED, which is
// visible by construction. The token-leak trade documented here previously was
// the price of subtracting after the fact; it is not the price of anything now.
//
// Contract (IAM-1-32):
//   - cluster-admin (D-9 super-gate) → the UNFILTERED page (they hold no per-object
//     tuple after the access-cascade contraction; parity with every sibling read).
//     The question is asked ONCE per request, outside the refill loop, and its
//     FAILURE is now a refusal — see below;
//   - anonymous / no visible bindings → empty page (never a leak, never an error);
//   - FGA error → UNAVAILABLE (fail-closed — never an unfiltered result);
//   - page format (page_token/page_size) is validated in the handler BEFORE this
//     use-case runs, so a garbage token / page_size>1000 is INVALID_ARGUMENT
//     independent of grant state.
//
// # TWO answers changed here, and both are contract changes on purpose
//
//  1. An UNWIRED relation port (`queries == nil`) now REFUSES with UNAVAILABLE.
//     It used to return an empty page, which a tenant cannot tell from "nobody
//     has been granted anything" — so a deployment that forgot to configure the
//     relation store looked, to every tenant, exactly like a correctly
//     locked-down one. This surface was the last of the seven still answering
//     that way (645-23b).
//  2. A FAILURE of the cluster-admin question is now a refusal instead of "not
//     an admin". Swallowed, it produces a well-formed, silently narrowed `200`
//     that the caller cannot tell from a revocation (645-16b, acceptance §3.6).
//     A nil `relations` port is NOT that case and keeps its old meaning: the
//     gate is simply not wired and does not fire.
//
// Both are recorded in docs/engineering/architecture/known-divergences.md §13.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// clusterAdminReader — перечисление ДЕЙСТВУЮЩИХ кластерных администраторов.
//
// Своя поверхность у них остаётся (выдать / отозвать / перечислить своим
// глаголом), но ЧТЕНИЕ сводится сюда: две поверхности об одном предмете
// расходятся молча — спрашивающий «кто имеет доступ» получает ответ с одной из
// них и считает его полным (#914, решение 2).
type clusterAdminReader interface {
	ListActive(ctx context.Context) ([]domain.ClusterAdminEntry, error)
}

// ListPage — одна страница ПОЛНОГО перечисления поверхности выдач.
//
// Три вида, три поля, и это не «список разнородного»: у членства нет ни роли,
// ни области, ни срока, у кластерного администратора — свой порядок выдачи, и
// втискивание их в форму выдачи потребовало бы пустых полей, которые читатель
// принимает за «не задано», а не за «неприменимо».
type ListPage struct {
	// Bindings — выдачи этой страницы, уже суженные вердиктом.
	Bindings []domain.AccessBinding
	// NextPageToken — продолжение обхода ВЫДАЧ. Соседние виды сопровождают
	// страницу и по страницам не режутся: их объём ограничен её содержимым
	// (членство) либо мал по построению (кластерные администраторы).
	NextPageToken string
	// Memberships — состав ТЕХ групп, что названы субъектами выдач на этой
	// странице. Членство в группе без выдачи доступа не даёт и к вопросу «кто
	// имеет доступ» не относится; видимость наследуется от выдачи, которую
	// вызывающий и так видит.
	Memberships []domain.GroupMember
	// ClusterAdmins — все действующие кластерные администраторы, и ТОЛЬКО тому,
	// кто сам кластерный администратор. Верхний ярус супер-доступа обязан быть
	// виден целиком тому, кто им распоряжается, и не обязан — арендатору:
	// перечисление имён администраторов облака арендатору не адресовано.
	ClusterAdmins []domain.ClusterAdminEntry
	// IncompleteMembershipGroups — группы, чей состав в этом ответе НЕПОЛОН.
	//
	// Состав ограничен сверху (членство неограниченно by construction — у него
	// для того и есть свой пагинированный глагол), и упереться в предел законно.
	// Незаконно — промолчать об этом: усечённое членство читается вызывающим как
	// факт о доступе, а «в группе больше никого» и «дальше мы не читали» — разные
	// утверждения.
	IncompleteMembershipGroups []domain.GroupID
}

type ListUseCase struct {
	repo Repo
	// queries — FGA port resolving the caller's visible bindings on the page.
	// nil → the use-case REFUSES (UNAVAILABLE), never an unfiltered leak and no
	// longer an empty page: see the file doc, change (1).
	queries clients.RelationQueries
	// relations — FGA Check port backing the D-9 cluster-admin super-gate. nil-safe
	// (unwired → the gate is never taken and only the per-object floor runs); a
	// wired port whose ANSWER fails is a different fact and refuses.
	relations clients.RelationStore

	// listScan — узкий порт наблюдаемости стоимости страницы (#653).
	// Не провязан ⇒ наблюдение выключено, а не сломано.
	listScan shared.ListScanRecorder

	// clusterAdmins — соседняя поверхность верхнего яруса супер-доступа.
	// Не провязана ⇒ перечисление её вида не несёт, и это ОТЛИЧИМО: вид не
	// объявляется пустым, он просто отсутствует. Провязанный порт, чей ОТВЕТ
	// не получен, — другой факт, и он отказывает (см. neighbours).
	clusterAdmins clusterAdminReader
}

func NewListUseCase(r Repo) *ListUseCase {
	return &ListUseCase{repo: r}
}

// WithRelationQueries wires the FGA ListObjects port (viewer ∪ v_list floor).
// WithListScanRecorder провязывает съём стоимости страницы (#653).
func (u *ListUseCase) WithListScanRecorder(rec shared.ListScanRecorder) *ListUseCase {
	u.listScan = rec
	return u
}

func (u *ListUseCase) WithRelationQueries(q clients.RelationQueries) *ListUseCase {
	u.queries = q
	return u
}

// WithClusterAdmins провязывает чтение соседней поверхности кластерных
// администраторов (#914, решение 2). nil-safe: непровязанный порт вида не даёт.
func (u *ListUseCase) WithClusterAdmins(r clusterAdminReader) *ListUseCase {
	u.clusterAdmins = r
	return u
}

// WithRelationStore wires the FGA Check port for the D-9 cluster-admin super-gate.
// After the access-cascade contraction a cluster super-admin holds NO per-object
// viewer/v_list tuple on iam_access_binding (helpers.go requireGrantAuthority Path 0),
// so the per-object push-down alone would hand them an empty page — diverging from
// Get / ListByScope / ListByAccount / ListByRole, which all run requireGrantAuthority.
// nil-safe: an unwired gate does not fire.
//
// No logger parameter (unlike the sibling builders). This used to be justified by
// "IsClusterAdmin swallows the FGA error, so there is nothing to diagnose" — that
// is no longer true: the failure of this question now refuses the request
// (UNAVAILABLE), so it is reported to the caller rather than buried, which is a
// stronger outcome than a log line and still needs no field here.
func (u *ListUseCase) WithRelationStore(relations clients.RelationStore) *ListUseCase {
	u.relations = relations
	return u
}

// Execute reads the page from the iam database by cursor and returns the subset
// of it visible to the caller. The predicate fields on f (subject/role/scope/
// scopeId) narrow the page at the SQL layer; visibility is applied to the rows
// that page yields.
func (u *ListUseCase) Execute(ctx context.Context, f repoab.ListFilter) (ListPage, error) {
	// C7 — формат ПЕРВЫМ стейтментом, до решения о том, кто спрашивает. Хендлер
	// судит СЫРОЙ запрос (насыщающее сужение int64→int32), здесь судится уже
	// суженное значение и форма токена.
	if err := shared.ValidateVisiblePagination(f.PageToken, f.PageSize); err != nil {
		return ListPage{}, err
	}
	after, err := shared.DecodeVisiblePageToken("page_token", f.PageToken)
	if err != nil {
		return ListPage{}, err
	}
	// account_id — ФОРМАТ здесь же, до решения о том, кто спрашивает (#1737,
	// IAM-AB-SIA-14). Проверка стоит в ТОЙ ЖЕ функции, которая замыкается на
	// неопознанном вызывающем: guard этажом выше не защищает второго
	// вызывающего этой функции, а до репозитория замыкание не доходит by
	// construction — то есть репозиторный backstop на этой полосе не
	// исполняется. Иначе ответ на один и тот же негодный ввод зависел бы от
	// того, что вызывающему выдано: `400` при живом гранте и `200 []` при пустом.
	//
	// Пустая строка ПРОПУСКАЕТСЯ намеренно: она означает «не сужать», а не
	// «аккаунт с пустым id». Required-проверка — отдельная ответственность, и
	// здесь её предмета нет: поле необязательное.
	//
	// Производитель — тот же, что у ListByAccount на этом же поле, поэтому оба
	// глагола отвечают на один вход побайтово одинаково (IAM-AB-SIA-12/16).
	if f.AccountID != "" {
		if err := shared.ValidateResourceID(f.AccountID, domain.PrefixAccount, "account"); err != nil {
			return ListPage{}, err
		}
	}

	subject, _ := authzguard.PrincipalSubject(ctx) // fail-closed: anon / unknown → ""
	if subject == "" {
		return ListPage{Bindings: []domain.AccessBinding{}}, nil
	}
	if u.queries == nil {
		// No visibility is resolvable at all. An empty page here cannot be told
		// apart from "you have no grants" — see the file doc, change (1).
		return ListPage{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	// D-9 flat super-gate (parity with Get / ListByScope / ListByAccount /
	// ListByRole): a cluster-admin enumerates the UNFILTERED page. After the
	// access-cascade contraction they hold no per-object tuple on
	// iam_access_binding, so the per-object filter alone would answer "no grants
	// exist" on the read that supersedes the whole legacy family.
	//
	// ВОПРОС О СУБЪЕКТЕ — один на запрос, вне цикла набора страницы, и через тот
	// же порт, которым эта поверхность его уже задавала (`RelationStore`, простой
	// Check). Его ОТКАЗ — отказ запроса; nil-порт отказом не является и означает
	// ровно то же, что раньше: гейт не провязан и не срабатывает.
	clusterAdmin, err := authzguard.SubjectIsClusterAdminPlainE(ctx, u.relations, subject)
	if err != nil {
		return ListPage{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return ListPage{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	scope, err := u.subjectScope(ctx, rd, clusterAdmin)
	if err != nil {
		return ListPage{}, err
	}
	page, next, err := u.collectVisiblePage(ctx, rd, scope, f, after, clusterAdmin)
	if err != nil {
		return ListPage{}, err
	}
	// Subjects and the materialization stamp are projected onto the RETURNED page
	// only — the rows a verdict discarded never needed either.
	if err := projectSubjectsBatch(ctx, rd, page); err != nil {
		return ListPage{}, err
	}
	if err := projectMaterializedAtBatch(ctx, rd, page); err != nil {
		return ListPage{}, err
	}
	out := ListPage{Bindings: page, NextPageToken: next}
	if err := u.neighbours(ctx, rd, &out, clusterAdmin); err != nil {
		return ListPage{}, err
	}
	return out, nil
}

// neighbours дочитывает две соседние поверхности для УЖЕ ОТОБРАННОЙ страницы.
//
// СОСТАВ ГРУПП читается на ТОЙ ЖЕ транзакции, что и страница: иначе членство и
// выдача, его давшая, приехали бы из разных снимков, и ответ описывал бы
// состояние, которого не было ни в один момент.
//
// ВЕРХНИЙ ЯРУС читается СВОИМ портом и, в боевой провязке, вне этой транзакции —
// у него собственный пул. Здесь это безвредно и потому оставлено: его записи ни
// с чем на странице не сверяются (у выдач нет ссылки на кластерного
// администратора), поэтому «другой снимок» не даёт несогласованной пары. Сказано
// прямо, потому что прежняя редакция утверждала «обе на той же транзакции» — а
// это было верно ровно наполовину.
//
// Отказ чтения — ОТКАЗ ЗАПРОСА, а не тихо усечённое перечисление: полнота и
// есть предмет этого поля, и «соседей нет» обязано означать «их нет», а не «их
// не удалось прочитать».
func (u *ListUseCase) neighbours(
	ctx context.Context, rd Reader, page *ListPage, clusterAdmin bool,
) error {
	if groups := groupSubjectsOf(page.Bindings); len(groups) > 0 {
		gr := rd.Groups()
		if gr == nil {
			return shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		members, incomplete, err := gr.MembersOfGroups(ctx, groups)
		if err != nil {
			// Одна полоса отказа на всех трёх соседей — `UNAVAILABLE`, и это
			// выбор, а не следствие общего маппера. Вход этого чтения не
			// приходит от вызывающего: идентификаторы групп взяты со страницы,
			// которую мы только что прочитали сами, — значит «неверный
			// аргумент» и «не найдено» здесь непредставимы by construction, а
			// единственный возможный исход отказа — недоступность соседа.
			// Вызывающему это говорит «повтори», тогда как INTERNAL сказал бы
			// «сломано у нас» на временном событии, и три полосы одного предмета
			// отвечали бы по-разному.
			return shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		page.Memberships = members
		page.IncompleteMembershipGroups = incomplete
	}

	// Верхний ярус супер-доступа перечисляется ТОМУ, КТО ИМ РАСПОРЯЖАЕТСЯ.
	// Арендатору он не адресован: список администраторов облака — не ответ на
	// вопрос «кто имеет доступ к МОЕМУ».
	if !clusterAdmin || u.clusterAdmins == nil {
		return nil
	}
	admins, err := u.clusterAdmins.ListActive(ctx)
	if err != nil {
		return shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	page.ClusterAdmins = admins
	return nil
}

// groupSubjectsOf — идентификаторы групп, названных субъектами выдач страницы.
//
// Читаются ОБЕ формы субъекта: плоская пара (легаси-проекция строки) и
// многосубъектный набор. Одна из двух дала бы неполный ответ ровно там, где
// выдача заведена другой формой, — и неполнота выглядела бы как «в группе никого».
func groupSubjectsOf(rows []domain.AccessBinding) []domain.GroupID {
	seen := make(map[domain.GroupID]struct{}, len(rows))
	var out []domain.GroupID
	add := func(t domain.SubjectType, id domain.SubjectID) {
		if t != domain.SubjectTypeGroup || id == "" {
			return
		}
		gid := domain.GroupID(id)
		if _, dup := seen[gid]; dup {
			return
		}
		seen[gid] = struct{}{}
		out = append(out, gid)
	}
	for _, b := range rows {
		add(b.SubjectType, b.SubjectID)
		for _, s := range b.Subjects {
			add(s.Type, s.ID)
		}
	}
	return out
}

// subjectScope resolves the structural facts of the caller once per request.
//
// A reader that cannot answer them is a REFUSAL, not a licence to list
// un-narrowed: "I have nothing to narrow with" and "you may see nothing" are
// different facts, and the second must never be produced by the first.
func (u *ListUseCase) subjectScope(
	ctx context.Context, rd Reader, clusterAdmin bool,
) (visibility.Scope, error) {
	vr := rd.Visibility()
	if vr == nil {
		return visibility.Scope{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	principal := operations.PrincipalFromContext(ctx)
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
// `unfiltered` is the cluster administrator's path: no narrowing, no verdict. It
// is a parameter rather than a separate traversal so that both callers produce
// and consume the SAME token form.
func (u *ListUseCase) collectVisiblePage(
	ctx context.Context, rd Reader,
	scope visibility.Scope, f repoab.ListFilter, after *shared.VisibleCursor, unfiltered bool,
) ([]domain.AccessBinding, string, error) {
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
	candidates := scope.Candidates(fgaBindingObjectType)

	var cursor *repoab.Cursor
	if after != nil {
		cursor = &repoab.Cursor{CreatedAt: after.CreatedAt, ID: after.ID}
	}

	// Собственный аккумулятор, а не массив репозитория: `rows[:0]` затирает и
	// отобранное, и опережающую строку, до которой вердикт ещё не дошёл.
	visible := make([]domain.AccessBinding, 0, need)

	scan := shared.ListScan{}
	for len(visible) < need {
		rows, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{
			SubjectID: f.SubjectID,
			RoleID:    f.RoleID,
			ScopeType: f.ScopeType,
			ScopeID:   f.ScopeID,
			// Фильтр пересобирается по полю, а не копируется целиком, поэтому
			// новый предикат обязан быть перечислен ЗДЕСЬ. Пропуск не ломает
			// сборку и не виден в диффе: поле приняли бы и молча выбросили —
			// ровно тот запрет, который держит IAM-AB-SIA-06.
			AccountID:      f.AccountID,
			IncludeRevoked: f.IncludeRevoked,
			PageSize:       chunk,
			After:          cursor,
			Candidates:     candidates,
		})
		if err != nil {
			return nil, "", shared.MapRepoErr(err)
		}
		if len(rows) == 0 {
			break
		}
		scan.AddBatch(len(rows))
		last := rows[len(rows)-1]
		cursor = &repoab.Cursor{CreatedAt: last.CreatedAt, ID: string(last.ID)}

		if unfiltered {
			visible = append(visible, rows...)
		} else {
			judged, err := u.judge(ctx, rows)
			if err != nil {
				return nil, "", err
			}
			visible = append(visible, judged...)
		}

		if len(rows) < int(chunk) {
			break // кандидаты исчерпаны
		}
	}

	// Токен считается от последней ОТДАННОЙ видимой строки в keyset-порядке —
	// том самом, в котором их вернул обход.
	scan.Report(ctx, u.listScan, "access_binding")

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
// Every candidate is put to the model — this surface has no floor. The question
// goes through visibleBindingIDsOnPage, the SAME function ListByScope and
// ListByAccount call, so the three reads of this type keep drawing from one
// question. Asking the model here directly would be a second spelling of it,
// free to drift from the one the siblings use.
//
// The `ok` return is the "port unwired" signal; Execute has already refused on
// that, so it cannot be false here — asserted rather than assumed, because a
// silent false would filter the page to nothing.
//
// Fail-closed: a verdict that could not be obtained aborts the request
// (UNAVAILABLE).
func (u *ListUseCase) judge(
	ctx context.Context, rows []domain.AccessBinding,
) ([]domain.AccessBinding, error) {
	visible, ok, err := visibleBindingIDsOnPage(ctx, u.queries, bindingIDs(rows))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return filterVisibleBindings(rows, visible), nil
}
