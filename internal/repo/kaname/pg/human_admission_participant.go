// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// HumanAdmissionParticipant — транзакции регистрации/admission и жизненного цикла личности.
// Глобальная личность заранее требует GLOBAL Identity; это не fallback для
// account writers и не право на новый grant. Bootstrap policy остаётся в UC.
type HumanAdmissionParticipant struct {
	repo   *Repository
	bundle *granteffect.Bundle
}

func NewHumanAdmissionParticipant(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*HumanAdmissionParticipant, error) {
	if repo == nil || repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	return &HumanAdmissionParticipant{repo: repo, bundle: bundle}, nil
}

// Настройка копии сохраняет исходное хранилище и явно помнит даже выбор nil.
func (s *RegistrationStore) WithHumanAdmissionParticipant(p *HumanAdmissionParticipant) *RegistrationStore {
	copy := *s
	copy.participantConfigured = true
	copy.participant = p
	return &copy
}

func (s *RegistrationStore) beginAdmissionSession(ctx context.Context) (*humanSessionWriter, error) {
	if s == nil || s.pool == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if s.participantConfigured {
		return s.participant.begin(ctx, s.pool)
	}
	return beginHumanSessionWriter(ctx, s.pool)
}

// Параметры церемонии названы явно: координатор передаёт RC и начинает
// authority entry до person/row/advisory locks. Никакого повторного pool slot.
func (p *HumanAdmissionParticipant) beginCeremonyTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if options != ceremonyWriterTx() {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	return p.repo.master.BeginTx(ctx, ceremonyWriterTx())
}

func (p *HumanAdmissionParticipant) begin(ctx context.Context, pool *pgxpool.Pool) (*humanSessionWriter, error) {
	if p == nil || p.repo == nil || p.repo.master == nil || p.repo.master != pool {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: p.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	w, err := p.repo.coordinatedAuthorityWriterWithBegin(ctx, intent, "participant", p.beginCeremonyTx)
	if err != nil {
		return nil, err
	}
	// Одна аттестованная TX передаётся session/mirror/owner-intent/outbox.
	// Закрытое свидетельство остаётся в TX; обычный writer не получает semantic checker.
	return &humanSessionWriter{tx: w.tx}, nil
}
