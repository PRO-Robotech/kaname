// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_role.go — ListByRoleUseCase for the RBAC rules-model 2026.
//
// Audit read "who holds role R": returns the AccessBindings carrying a given
// role, each filled with the dual subjects[]/legacy projection. Sync read
// (not an Operation).
//
// Authorisation: authenticated floor + per-row scope-filter — a binding row is
// returned only if the caller holds grant-authority on that binding's scope
// (owner of the owning Account/Project OR FGA admin on the scope object), the
// same predicate as Create/Delete/ListByScope. A caller therefore sees only
// the bindings-of-the-role they would be allowed to read individually; no
// existence-leak of bindings on scopes they cannot administer.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

type ListByRoleUseCase struct {
	repo      Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewListByRoleUseCase(r Repo) *ListByRoleUseCase {
	return &ListByRoleUseCase{repo: r}
}

// WithRelationStore wires the FGA client for the per-row delegated-admin scope
// filter. When unset (unit tests / degraded mode) only owner-based access passes.
func (u *ListByRoleUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListByRoleUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *ListByRoleUseCase) Execute(ctx context.Context, roleID string, f repoab.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	if err := shared.ValidateResourceID(roleID, domain.PrefixRole, "role"); err != nil {
		return nil, "", err
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}

	// Read + fill the dual subjects[]/legacy projection via the shared read
	// skeleton; the reader-tx is released before the per-row authority filter
	// (requireGrantAuthority opens its own reader).
	out, next, err := readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().ListByRole(ctx, domain.RoleID(roleID), f)
	})
	if err != nil {
		return nil, "", err
	}

	// Per-row scope-filter: keep only the bindings whose scope the caller may
	// administer (grant-authority holder / admin). requireGrantAuthority opens its
	// own reader, so the list reader is released first. Self-grants (the caller is
	// the subject) are also visible.
	authority := &pageAuthority{repo: u.repo, relations: u.relations}
	filtered := out[:0:0]
	for _, b := range out {
		if callerIsSubjectOf(ctx, b) {
			filtered = append(filtered, b)
			continue
		}
		if err := authority.grantAuthorityVerdict(ctx, string(b.ResourceType), b.ResourceID); err == nil {
			filtered = append(filtered, b)
		}
	}
	// NB: the next_page_token reflects the pre-filter page boundary (the repo
	// keyset cursor). A page may return fewer rows than page_size after the
	// scope-filter; the client paginates until next_page_token is empty (parity
	// with the per-object filtered List RPCs).
	//
	// Дофильтровый курсор — РЕШЕНИЕ, а не умолчание, и оно записано:
	// docs/engineering/architecture/page-cost-belongs-to-the-request.md
	// (паритет с пообъектно-фильтрованными списочными RPC подфазы D — полосы
	// меняются вместе либо не меняются).
	return filtered, next, nil
}

// ─── СТОИМОСТЬ СТРАНИЦЫ ПРИНАДЛЕЖИТ ЗАПРОСУ ─────────────────────────────────

// pageAuthority — вердикты о праве администрировать область, СОБРАННЫЕ ЗА ОДИН
// ЗАПРОС. Отвечает ровно то же, что requireGrantAuthority на той же строке, и
// отличается только тем, СКОЛЬКО РАЗ об этом спрашивают.
//
// # Что именно перестало умножаться на число строк
//
// Прежде каждая строка страницы стоила двух вопросов к хранилищу прав: супер-гейт
// (про ЛИЧНОСТЬ вызывающего — одинаков для всей страницы) и админ-кортеж области
// (про ОБЛАСТЬ — одинаков для всех строк одной области). `page_size` — часть
// контракта и доходит до 1000 (`api-conventions.md` §Pagination), поэтому тысяча
// строк разворачивалась в две тысячи последовательных вопросов; под нагрузкой
// это не укладывается в срок и даёт `UNAVAILABLE` на ПОЛОЖИТЕЛЬНОМ пути, а
// сужать `page_size` ради бюджета запрещено (`security.md` §«Фильтрация —
// страница → проверка страницы»).
//
// Теперь супер-гейт спрашивается ОДНАЖДЫ за запрос, а область — однажды на
// РАЗЛИЧНУЮ область. Число вопросов перестало быть функцией числа строк.
//
// # Почему это не ослабление
//
// Оба вопроса детерминированы в пределах запроса: субъект берётся из одного и
// того же контекста, объект — из типа и идентификатора области. Повторный вопрос
// об одном и том же дал бы тот же ответ, поэтому памятка не меняет ни одного
// вердикта — она снимает повтор. Кэша МЕЖДУ запросами здесь нет намеренно: отзыв
// права обязан действовать на следующем же чтении.
//
// # Три исхода супер-гейта, а не два
//
// «Спросить не удалось» — не «не положено»: неполадка хранилища прав возвращается
// как `AuthzBackendUnavailable`, ровно как в requireGrantAuthority, и запоминается
// вместе с остальными, чтобы страница не переспрашивала сорванный источник по
// разу на строку.
//
// Вопрос задаётся ЛЕНИВО: страница без строк не оплачивается вовсе.
type pageAuthority struct {
	repo      Repo
	relations clients.RelationStore

	clusterAsked bool
	clusterAdmin bool
	clusterErr   error

	byScope map[string]error
}

// grantAuthorityVerdict — тот же исход, что у requireGrantAuthority для этой строки.
//
// # Почему имя такое длинное, а не `verdict`
//
// Имя метода здесь — ТОКЕН, по которому гейт списочных поверхностей
// (`tools/auditlistfilter`) узнаёт пообъектный вопрос: он идёт по графу вызовов
// и записывает имена, а через локальную переменную (`authority`) внутрь метода
// не проходит — значит `grantAuthorityBeyondClusterAdmin` ниже ему не виден by
// construction. Голое `verdict` в перечень сужателей ставить нельзя: этим именем
// в iam уже назван ДРУГОЙ предмет (`internal/service/authorize_service.go` —
// вычисление одного разрешения), и профиль, назвавший сужателем `verdict`,
// проверял бы написание, а не предмет.
//
// Поэтому имя названо по существу и ничьего другого предмета не называет
// (предикат: `git grep -l grantAuthorityVerdict -- services/iam` — этот файл,
// профиль гейта и его инъекция, больше ничего). Правя имя, правь и
// `Profile.Filters`: гейт скажет
// об этом сам, но координатой назовёт ОБЪЯВЛЕНИЕ листинга — `handler.go`,
// `ListByRole`, — а не эту строку. Он сообщает о поверхности, отдавшей страницу,
// и вызов может лежать в нескольких шагах от неё.
func (p *pageAuthority) grantAuthorityVerdict(ctx context.Context, resourceType, resourceID string) error {
	// Путь 0 — супер-гейт, ОДИН на запрос.
	if !p.clusterAsked {
		p.clusterAdmin, p.clusterErr = authzguard.IsClusterAdminE(ctx, p.relations)
		p.clusterAsked = true
	}
	if p.clusterErr != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if p.clusterAdmin {
		return nil
	}

	// Пути 1-2 — один на РАЗЛИЧНУЮ область. Ключ несёт разделитель, которого нет
	// ни в типе, ни в идентификаторе: склейка без него дала бы одну память двум
	// разным областям.
	key := resourceType + "\x00" + resourceID
	if err, seen := p.byScope[key]; seen {
		return err
	}
	err := grantAuthorityBeyondClusterAdmin(ctx, p.repo, p.relations, resourceType, resourceID)
	if p.byScope == nil {
		p.byScope = make(map[string]error, 4)
	}
	p.byScope[key] = err
	return err
}
