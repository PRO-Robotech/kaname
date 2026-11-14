// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"strings"
	"time"
)

// IdentityLifecycleWriter использует уже загруженный неизменяемый bundle.
// Личность и её метки общие для всех членств: GLOBAL берётся до тела UC,
// любых person/row/cutoff locks. Этот participant не принимает grant-решение.
func (p *HumanAdmissionParticipant) IdentityLifecycleWriter(ctx context.Context, kind kaname.IdentityMutation, id domain.UserID) (kaname.Writer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || p.repo == nil || p.repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	switch kind {
	case kaname.IdentityUpdate, kaname.IdentityDelete, kaname.IdentityBlock, kaname.IdentityUnblock, kaname.IdentityRemoveFromAccount:
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if !strings.HasPrefix(string(id), domain.PrefixUser) || len(id) != domain.ShortIDLen || strings.ContainsAny(string(id), ":#* \t\r\n") {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: p.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	w, err := p.repo.coordinatedAuthorityWriter(ctx, intent, "participant")
	if err != nil {
		return nil, err
	}
	return &identityLifecycleWriteTx{authorityWriteTx: w}, nil
}

type identityLifecycleWriteTx struct{ *authorityWriteTx }

// Общий helper сохраняет свой контракт; отменённый worker всё равно освобождает TX.
func (w *identityLifecycleWriteTx) Rollback(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return w.authorityWriteTx.Rollback(cleanup)
}

var _ kaname.IdentityLifecycleWriterFactory = (*HumanAdmissionParticipant)(nil)
