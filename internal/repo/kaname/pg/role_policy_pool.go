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

// RolePolicyWriters открывает role-порты назначенного app LOGIN.
// Порт User.Update требует отдельной установки владельцем БД.
// Не встраиваем GrantPolicyWriters: group/binding-порты не должны попасть
// в общий wiring вместе с этой зависимостью. Это выбор соединения, не allow.
type RolePolicyWriters struct {
	shared      *Repository
	policy      *GrantPolicyWriters
	runtimeOID  uint32
	runtimeName string
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
	// Получаем координаты с ordinary соединения. Владелец БД подтверждает
	// эту пару на соединении назначенного LOGIN в той же проверке.
	var runtimeOID uint32
	var runtimeName string
	if err := shared.master.QueryRow(ctx, `SELECT r.oid, r.rolname::text
		FROM pg_catalog.pg_roles r WHERE r.rolname=session_user AND current_user=session_user`).Scan(&runtimeOID, &runtimeName); err != nil {
		return nil, fmt.Errorf("verify primary application LOGIN: %w", err)
	}
	var enrolled bool
	if err := role.master.QueryRow(ctx, `SELECT current_user=session_user
		AND kaname.authority_role_actor_pair_ready_v1($1::oid,$2::text)`, runtimeOID, runtimeName).Scan(&enrolled); err != nil {
		return nil, fmt.Errorf("verify role writer enrollment: %w", err)
	}
	if !enrolled {
		return nil, fmt.Errorf("role policy requires the enrolled pair of application LOGINs")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &RolePolicyWriters{shared: shared, policy: policy, runtimeOID: runtimeOID, runtimeName: runtimeName}, nil
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
