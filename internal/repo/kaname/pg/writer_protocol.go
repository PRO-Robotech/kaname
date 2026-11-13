// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const authorityEntryAttempts = 3

func validateAuthorityIntent(in kaname.AuthorityWriteIntent) error {
	if err := in.Bundle.Validate(); err != nil {
		return err
	}
	if _, err := canonicalAuthorityAccounts(in.Plan); err != nil {
		return err
	}
	switch in.Kind {
	case kaname.AuthorityBinding, kaname.AuthorityRole, kaname.AuthorityGroup, kaname.AuthorityMembership, kaname.AuthorityDelegation, kaname.AuthorityResource:
	case kaname.AuthorityIdentity, kaname.AuthorityCatalog, kaname.AuthorityCluster:
		if in.Plan.Mode != kaname.AuthorityFenceGlobal {
			return kaname.ErrInvalidAuthorityFencePlan
		}
	default:
		return kaname.ErrInvalidAuthorityFencePlan
	}
	if len(in.Owners) > kaname.MaxAuthorityOwnershipRefs || (in.Plan.Mode == kaname.AuthorityFenceAccounts && len(in.Owners) == 0) {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	for _, ref := range in.Owners {
		switch ref.Kind {
		case "account", "project", "role", "group", "service_account", "binding":
		default:
			return kaname.ErrInvalidAuthorityFencePlan
		}
		if ref.ID == "" || strings.TrimSpace(ref.ID) != ref.ID || strings.ContainsRune(ref.ID, '\x00') {
			return kaname.ErrInvalidAuthorityFencePlan
		}
	}
	return nil
}

// kaname#1034: каждая попытка — новая физическая TX. До entry доступны только
// readonly ownership discovery и immutable bundle; callback/старых locks нет.
func (r *Repository) coordinatedAuthorityWriter(ctx context.Context, in kaname.AuthorityWriteIntent, purpose string) (*authorityWriteTx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateAuthorityIntent(in); err != nil {
		return nil, err
	}
	in.Owners = append([]kaname.AuthorityOwnerRef{}, in.Owners...)
	accounts, err := canonicalAuthorityAccounts(in.Plan)
	if err != nil {
		return nil, err
	}
	owners, err := json.Marshal(in.Owners)
	if err != nil {
		return nil, err
	}
	mode := in.Plan.Mode
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		tx, e := r.master.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if e != nil {
			return nil, e
		}
		opened, e := r.enterAuthority(ctx, tx, in, owners, mode, accounts, attempt > 0, purpose)
		if e == nil {
			return opened, nil
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollbackErr := tx.Rollback(cleanup)
		cancel()
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return nil, errors.Join(e, rollbackErr)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var pgerr *pgconn.PgError
		if !errors.As(e, &pgerr) || pgerr.Code != "P1034" {
			return nil, e
		}
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}

func (r *Repository) enterAuthority(ctx context.Context, tx pgx.Tx, in kaname.AuthorityWriteIntent, owners []byte, mode kaname.AuthorityFenceMode, accounts []domain.AccountID, rediscover bool, purpose string) (*authorityWriteTx, error) {
	if rediscover && mode == kaname.AuthorityFenceAccounts {
		var actual []string
		var global bool
		if err := tx.QueryRow(ctx, `SELECT accounts, global_scope FROM kaname.authority_protocol_discover($1::jsonb)`, owners).Scan(&actual, &global); err != nil {
			return nil, err
		}
		if global || len(actual) > kaname.MaxAuthorityFenceAccounts {
			mode = kaname.AuthorityFenceGlobal
			accounts = nil
		} else {
			accounts = make([]domain.AccountID, len(actual))
			for i, id := range actual {
				accounts[i] = domain.AccountID(id)
			}
		}
	}
	ids := make([]string, len(accounts))
	for i, id := range accounts {
		ids[i] = string(id)
	}
	label := "accounts"
	if mode == kaname.AuthorityFenceGlobal {
		label = "global"
	}
	identity := in.Bundle.Identity()
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_protocol_enter($1,$2::text[],$3::jsonb,$4,$5,$6,$7,1,$8)`, label, ids, owners, string(in.Kind), identity.ModelID, identity.CatalogID, identity.ProjectorVersion, purpose).Scan(&at); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: mode, accounts: slices.Clone(accounts), decisionAt: at.UTC()}}
	return w, nil
}

var _ kaname.CoordinatedAuthorityWriterFactory = (*Repository)(nil)

func (r *Repository) CoordinatedAuthorityWriter(ctx context.Context, in kaname.AuthorityWriteIntent) (kaname.SemanticAuthorityWriter, error) {
	w, err := r.coordinatedAuthorityWriter(ctx, in, "decision")
	if err != nil {
		return nil, err
	}
	return newSemanticAuthorityWriter(w, in.Bundle), nil
}
func (r *Repository) TransitionalAuthorityWriter(ctx context.Context, in kaname.AuthorityWriteIntent) (kaname.AuthorityWriter, error) {
	w, err := r.coordinatedAuthorityWriter(ctx, in, "transition")
	if err != nil {
		return nil, err
	}
	return w, nil
}

// PrepareAuthorityBundle доступен только доверенному migration owner в БД.
// Подготовка целой identity не переводит protocol в strict и не включает gates.
func (r *Repository) PrepareAuthorityBundle(ctx context.Context, bundle *granteffect.Bundle) error {
	return r.StageAuthorityBundle(ctx, bundle)
}

// kaname#1034: обычный participant сохраняет тот же entry/fences и в strict,
// но не получает SemanticBundle/checker для принятия policy decision.
func (r *Repository) ParticipantAuthorityWriter(ctx context.Context, in kaname.AuthorityWriteIntent) (kaname.AuthorityWriter, error) {
	w, err := r.coordinatedAuthorityWriter(ctx, in, "participant")
	if err != nil {
		return nil, err
	}
	return w, nil
}

var _ kaname.ParticipantAuthorityWriterFactory = (*Repository)(nil)

var _ kaname.TransitionalAuthorityWriterFactory = (*Repository)(nil)
