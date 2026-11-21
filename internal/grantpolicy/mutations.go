// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

func roleScope(r domain.Role) domain.ScopeAnchor {
	if r.ProjectID != "" {
		return domain.ScopeAnchor{Type: "project", ID: string(r.ProjectID)}
	}
	return domain.ScopeAnchor{Type: "account", ID: string(r.AccountID)}
}

// RequireRoleMethod — обычный method gate, отдельно от полного содержимого.
// Он никогда не читает предлагаемые правила как источник прав actor.
func RequireRoleMethod(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, r domain.Role, create bool) error {
	p, err := CollectWitnessedLowerBound(ctx, w, actor)
	if err != nil {
		return err
	}
	return requireRoleMethod(ctx, w, p, r, create)
}
func requireRoleMethod(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, r domain.Role, create bool) error {
	scope := roleScope(r)
	admin, err := administrative(ctx, w, p, scope)
	if err != nil {
		return err
	}
	if admin {
		return nil
	}
	relation, object := "v_update", "iam_role:"+string(r.ID)
	if create {
		relation = "editor"
		object = scope.Type + ":" + scope.ID
	}
	ok, err := check(ctx, w, p.census.Actor, relation, object)
	if err != nil {
		return err
	}
	if !ok {
		return p.insufficient()
	}
	return nil
}

// RequireRole запрещает оправдывать предлагаемый результат собственной записью.
// Для Update проверяется всё содержимое и все PENDING/ACTIVE носители, в том
// числе последняя страница, пока исходные правила ещё не изменены.
func RequireRole(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, r domain.Role, create bool) error {
	p, err := CollectWitnessedLowerBound(ctx, w, actor)
	if err != nil {
		return err
	}
	if err = requireRoleMethod(ctx, w, p, r, create); err != nil {
		return err
	}
	// D4: собственный definitionTier — запасная область только для новой роли
	// или роли без действующих носителей. Роль аккаунта, выданная лишь в P/Q,
	// не требует лишнего покрытия всего аккаунта поверх этих настоящих выдач.
	fallback := func() error {
		proposed := granteffect.Binding{SourceID: "proposed-role:" + string(r.ID), Role: r, Scope: roleScope(r), Target: domain.AccessTarget{AllInScope: true}, Recipient: actor, Subjects: []domain.Subject{actor}, CapabilityVersion: 1}
		return requireRoleContent(ctx, w, p, proposed)
	}
	if create {
		return fallback()
	}
	used := false
	if err = population(ctx, w, func(token string) ([]domain.AccessBinding, string, error) {
		return w.AccessBindings().ListByRole(ctx, r.ID, ab.ListByRoleFilter{PageSize: 256, PageToken: token})
	}, func(b domain.AccessBinding) error {
		// population уже проверил статус, срок и непустой полный набор Subjects.
		// PENDING тоже создаёт будущий эффект и не включает fallback аккаунта.
		used = true
		for _, recipient := range b.Subjects {
			proposed := granteffect.Binding{SourceID: string(b.ID), Role: r, Scope: domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}, Target: b.Target, Recipient: recipient, Subjects: b.Subjects, CapabilityVersion: 1}
			if err := requireRoleContent(ctx, w, p, proposed); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// Отсутствие носителей доказано лишь после всех страниц. Ошибка чтения,
	// неполный census или превышение лимита не превращаются в пустой список.
	if used {
		return nil
	}
	return fallback()
}
func requireRoleContent(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, b granteffect.Binding) error {
	if err := validateProposed(b); err != nil {
		return err
	}
	admin, err := administrative(ctx, w, p, b.Scope)
	if err != nil {
		return err
	}
	if admin {
		return nil
	}
	// Bind конкретной роли здесь намеренно не вызывается: оно не escalate.
	return requireCoverage(p, b)
}

func RequireGroupAddition(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, m domain.GroupMember) error {
	p, err := CollectWitnessedLowerBound(ctx, w, actor)
	if err != nil {
		return err
	}
	if err := chargePopulationRead(w, 0, 1); err != nil {
		return err
	}
	g, err := w.Groups().Get(ctx, m.GroupID)
	if err != nil {
		return err
	}
	if err := chargePopulationRead(w, 1, 0); err != nil {
		return err
	}
	ok, err := check(ctx, w, actor, "v_update", "iam_group:"+string(g.ID))
	if err != nil {
		return err
	}
	if !ok {
		ok, err = administrative(ctx, w, p, domain.ScopeAnchor{Type: "account", ID: string(g.AccountID)})
		if err != nil {
			return err
		}
		if !ok {
			return p.insufficient()
		}
	}
	recipient := domain.Subject{Type: m.MemberType, ID: m.MemberID}
	if recipient.Validate() != nil || (recipient.Type != domain.SubjectTypeUser && recipient.Type != domain.SubjectTypeServiceAccount) {
		return denied()
	}
	return population(ctx, w, func(token string) ([]domain.AccessBinding, string, error) {
		return w.AccessBindings().ListBySubject(ctx, domain.SubjectTypeGroup, domain.SubjectID(m.GroupID), ab.PageFilter{PageSize: 256, PageToken: token})
	}, func(b domain.AccessBinding) error {
		if b.RoleID == "" {
			return denied()
		}
		if err := chargePopulationRead(w, 0, 1); err != nil {
			return err
		}
		r, err := w.Roles().Get(ctx, b.RoleID)
		if err != nil {
			return err
		}
		if err := chargePopulationRead(w, 1, 0); err != nil {
			return err
		}
		// Эффект нового получателя вычисляется отдельно от исходной group userset.
		// Никакого INSERT членства до этого решения не происходит.
		proposed := granteffect.Binding{SourceID: string(b.ID), Role: r, Scope: domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}, Target: b.Target, Recipient: recipient, Subjects: []domain.Subject{recipient}, CapabilityVersion: 1}
		return requireBinding(ctx, w, p, proposed)
	})
}

// Population сохраняет PENDING; истёкшая необратимо выдача не создаёт будущего
// эффекта. Бюджет и повтор курсора — ошибка, а не усечённый успешный census.
func population(ctx context.Context, w kaname.SemanticAuthorityWriter, page func(string) ([]domain.AccessBinding, string, error), visit func(domain.AccessBinding) error) error {
	token := ""
	tokens := map[string]bool{"": true}
	seen := map[domain.AccessBindingID]bool{}
	total := 0
	for n := 0; n < 4096; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := chargePopulationRead(w, 0, 1); err != nil {
			return err
		}
		rows, next, err := page(token)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		// PG ListByRole/ListBySubject читают page_size+1: sentinel тоже
		// физическая строка, хотя не попадает в возвращённый page.
		physical := len(rows)
		if next != "" {
			physical++
		}
		if err := chargePopulationRead(w, physical, 0); err != nil {
			return err
		}
		total += len(rows)
		if total > 100000 {
			return kaname.ErrSourceReadLimit
		}
		ids := make([]domain.AccessBindingID, 0, len(rows))
		for _, b := range rows {
			if b.ID == "" || seen[b.ID] {
				return kaname.ErrCanonicalSourceInvalid
			}
			seen[b.ID] = true
			ids = append(ids, b.ID)
		}
		// Пустой список не исполняет SQL в PG reader.
		if len(ids) > 0 {
			if err := chargePopulationRead(w, 0, 1); err != nil {
				return err
			}
		}
		ss, err := w.AccessBindings().ListSubjectsForBindings(ctx, ids)
		if err != nil {
			return err
		}
		// Начисляем все физически прочитанные subjects ДО фильтрации по
		// сроку/status и до нормализации. Истёкший carrier уменьшает эффект,
		// но не отменяет уже выполненное чтение его строк.
		for _, subjects := range ss {
			if err := chargePopulationRead(w, len(subjects), 0); err != nil {
				return err
			}
			if len(subjects) > 100000-total {
				return kaname.ErrSourceReadLimit
			}
			total += len(subjects)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		for _, b := range rows {
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = b.Status.Validate(); err != nil {
				return err
			}
			if b.Status == domain.AccessBindingStatusRevoked || b.RevokedAt != nil || (b.ExpiresAt != nil && !b.ExpiresAt.After(w.AuthorityFence().DecisionAt())) {
				continue
			}
			subjects, ok := ss[b.ID]
			if !ok || len(subjects) == 0 {
				return kaname.ErrCanonicalSourceInvalid
			}
			b.Subjects, err = domain.NormalizeSubjects(subjects, "", "")
			if err != nil {
				return err
			}
			if err = visit(b); err != nil {
				return err
			}
		}
		if next == "" {
			return ctx.Err()
		}
		if tokens[next] {
			return kaname.ErrCanonicalSourceInvalid
		}
		tokens[next] = true
		token = next
	}
	return kaname.ErrSourceReadLimit
}

// Optional общий attempt counter: прежние writers/doubles без интерфейса
// сохраняют локальный contract. PG writer передаёт тот же pointer, что RR
// discovery, CollectSemanticActor и native checker, без reset/двойного charge.
func chargePopulationRead(w kaname.SemanticAuthorityWriter, rows, reads int) error {
	if shared, ok := w.(interface {
		ChargeSourceRead(kaname.SourceReadCost) error
	}); ok {
		return shared.ChargeSourceRead(kaname.SourceReadCost{Rows: rows, Reads: reads})
	}
	return nil
}
