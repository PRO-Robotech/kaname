// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// RolePolicyWriters открывает только role-порты отдельного app LOGIN.
// Не встраиваем GrantPolicyWriters: group/binding-порты не должны попасть
// в общий wiring вместе с этой зависимостью. Это выбор соединения, не allow.
type RolePolicyWriters struct {
	shared *Repository
	policy *GrantPolicyWriters
}

// NewRolePolicyWriters принимает два заранее подготовленных FULL repository.
// Для role нужен собственный NewFullWriterContract на его pool: контракт
// общего repository нельзя переносить на другой pool даже при том же bundle.
// Проверки здесь не заменяют owner SQL trust pin и не включают protected admission.
// Ни pool, ни repository не закрываются: ими владеет startup.
func NewRolePolicyWriters(ctx context.Context, shared, role *Repository, bundle *granteffect.Bundle) (*RolePolicyWriters, error) {
	if shared == nil || role == nil || shared.master == nil || role.master == nil ||
		shared.master == role.master || role.slave != nil ||
		!shared.fullContractMatches(bundle) || !role.fullContractMatches(bundle) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	// Отдельная identity не означает отдельную БД. Здесь намеренно требуем
	// одинаковый endpoint; разрешение разных aliases требует отдельной проверки.
	sharedConfig, roleConfig := shared.master.Config().ConnConfig, role.master.Config().ConnConfig
	if sharedConfig.Host != roleConfig.Host || sharedConfig.Port != roleConfig.Port ||
		sharedConfig.Database != roleConfig.Database || len(sharedConfig.Fallbacks) != len(roleConfig.Fallbacks) {
		return nil, fmt.Errorf("role policy requires the primary database endpoint")
	}
	for i, fallback := range sharedConfig.Fallbacks {
		other := roleConfig.Fallbacks[i]
		if fallback == nil || other == nil || fallback.Host != other.Host || fallback.Port != other.Port {
			return nil, fmt.Errorf("role policy requires the primary database endpoint")
		}
	}
	if err := shared.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	policy, err := NewGrantPolicyWriters(ctx, role, bundle)
	if err != nil {
		return nil, err
	}
	// Два pool не доказывают разные identities: сверяем реальные LOGIN.
	// Имена используются только для сравнения и не попадают в ошибки.
	var sharedLogin, roleLogin string
	if err := shared.master.QueryRow(ctx, `SELECT session_user::text`).Scan(&sharedLogin); err != nil {
		return nil, err
	}
	if err := role.master.QueryRow(ctx, `SELECT session_user::text`).Scan(&roleLogin); err != nil {
		return nil, err
	}
	if sharedLogin == "" || roleLogin == "" || sharedLogin == roleLogin {
		return nil, fmt.Errorf("role policy requires a separate application LOGIN")
	}
	var enrolled bool
	if err := role.master.QueryRow(ctx, `SELECT kaname.authority_role_actor_login_ready_v1()`).Scan(&enrolled); err != nil {
		return nil, fmt.Errorf("verify role writer enrollment: %w", err)
	}
	if !enrolled {
		return nil, fmt.Errorf("role policy requires an enrolled application LOGIN")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &RolePolicyWriters{shared: shared, policy: policy}, nil
}

// ValidateFor не читает БД повторно: проверяет принадлежность уже проверенной
// зависимости именно этой composition и установленной semantic identity.
func (p *RolePolicyWriters) ValidateFor(shared *Repository, bundle *granteffect.Bundle) error {
	if p == nil || p.shared == nil || p.policy == nil || p.policy.repo == nil ||
		shared == nil || shared.master != p.shared.master ||
		p.policy.repo.master == shared.master || !shared.fullContractMatches(bundle) ||
		!p.policy.repo.fullContractMatches(bundle) || p.policy.bundle.Identity() != bundle.Identity() {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return nil
}

func (p *RolePolicyWriters) RoleMutationWriter(ctx context.Context, request kaname.RoleMutationRequest, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.policy == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	// Штатный writer сохраняет одно соединение для RR spool и RC mutation.
	return p.policy.RoleMutationWriter(ctx, request, actor)
}

func (p *RolePolicyWriters) RoleAuthorityWriter(ctx context.Context, role domain.Role, create bool, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.policy == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	return p.policy.RoleAuthorityWriter(ctx, role, create, actor)
}

var _ kaname.RoleMutationWriterFactory = (*RolePolicyWriters)(nil)
var _ kaname.RoleAuthorityWriterFactory = (*RolePolicyWriters)(nil)
