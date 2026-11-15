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
func (r *Repository) coordinatedAuthorityWriter(ctx context.Context, in kaname.AuthorityWriteIntent, purpose string, policy ...*policyPlan) (*authorityWriteTx, error) {
	return r.coordinatedAuthorityWriterWithBegin(ctx, in, purpose, r.master.BeginTx, policy...)
}

// kaname#1034: завершённый RR stage передаёт idle connection в тот же coordinator.
// Это всегда НОВАЯ RC TX; один проход не ждёт второй slot удерживая первый.
// Обычные callers сохраняют pool.BeginTx и его прежний release lifecycle.
func (r *Repository) coordinatedAuthorityWriterWithBegin(ctx context.Context, in kaname.AuthorityWriteIntent, purpose string, begin func(context.Context, pgx.TxOptions) (pgx.Tx, error), policy ...*policyPlan) (*authorityWriteTx, error) {
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
		tx, e := begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if e != nil {
			return nil, e
		}
		opened, e := r.enterAuthority(ctx, tx, in, owners, mode, accounts, attempt > 0, purpose, policy...)
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

func (r *Repository) enterAuthority(ctx context.Context, tx pgx.Tx, in kaname.AuthorityWriteIntent, owners []byte, mode kaname.AuthorityFenceMode, accounts []domain.AccountID, rediscover bool, purpose string, policy ...*policyPlan) (*authorityWriteTx, error) {
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
	if r.fullContract != nil && !r.fullContractMatches(in.Bundle) {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	identity := in.Bundle.Identity()
	var at time.Time
	var population *policyPopulationToken
	if len(policy) > 1 || (len(policy) == 1 && policy[0] == nil) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if len(policy) == 1 {
		plan := policy[0]
		if plan.population == nil || !plan.population.valid() || plan.nativeBudget == nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		copy := *plan.population
		population = &copy
		encoded, err := population.json()
		if err != nil {
			return nil, err
		}
		query := `SELECT kaname.authority_protocol_enter_full_v2($1,$2::text[],$3::jsonb,$4,$5,$6,$7,$8,$9::jsonb)`
		if r.fullContract != nil {
			query = `SELECT kaname.authority_protocol_enter_full_v3($1,$2::text[],$3::jsonb,$4,$5,$6,$7,$8,$9::jsonb)`
		}
		if err = tx.QueryRow(ctx, query, label, ids, owners, string(in.Kind), identity.ModelID, identity.CatalogID, identity.ProjectorVersion, purpose, encoded).Scan(&at); err != nil {
			return nil, err
		}
	} else {
		query := `SELECT kaname.authority_protocol_enter_typed_v2($1,$2::text[],$3::jsonb,$4,$5,$6,$7,$8)`
		if r.fullContract != nil {
			query = `SELECT kaname.authority_protocol_enter_typed_v3($1,$2::text[],$3::jsonb,$4,$5,$6,$7,$8)`
		}
		if err := tx.QueryRow(ctx, query, label, ids, owners, string(in.Kind), identity.ModelID, identity.CatalogID, identity.ProjectorVersion, purpose).Scan(&at); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w := &authorityWriteTx{population: population, writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: mode, accounts: slices.Clone(accounts), decisionAt: at.UTC()}}
	return w, nil
}

var _ kaname.CoordinatedAuthorityWriterFactory = (*Repository)(nil)

// Старый широкий порт не содержал actor/source intent. После ABI2 его нельзя
// выдавать за protected full reader; вызывающий выбирает explicit read plan
// либо entry-only участие. Отказ происходит до acquire и до любого SQL.
func (r *Repository) CoordinatedAuthorityWriter(ctx context.Context, in kaname.AuthorityWriteIntent) (kaname.SemanticAuthorityWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateAuthorityIntent(in); err != nil {
		return nil, err
	}
	return nil, kaname.ErrSemanticReadPlanRequired
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
