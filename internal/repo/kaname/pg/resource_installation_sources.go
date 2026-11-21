// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Эти свидетельства описывают только источник installation gate, не весь
// авторитет module SA. В частности, receipts чужих аккаунтов сюда не входят.
// Сам захват не удостоверяет удержание замков; их проверяет общий preflight
// перед привязкой checker к окончательному решению.
type resourceInstallationWitness struct {
	assignment string
	binding    string
	state      string
}
type resourceInstallationCapture struct {
	lifetime    *resourceAttemptLifetime
	bundle      *granteffect.Bundle
	serviceName string
	actor       string
	accounts    []domain.AccountID
	sources     map[domain.AccountID][]resourceInstallationWitness
	budget      *relverdict.AdministrativeReadBudget
}

func captureResourceInstallation(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime, identity resourceModuleIdentity, accounts []domain.AccountID, budget *relverdict.AdministrativeReadBudget) (*resourceInstallationCapture, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !identity.valid() || tx == nil || budget == nil || lifetime == nil || lifetime.ended || lifetime.writer != nil || lifetime.conn == nil || tx.Conn() != lifetime.conn {
		return nil, kaname.ErrSourceUnconfirmed
	}
	bundle := lifetime.bundle
	if err := validateResourceRegistrationModel(bundle); err != nil {
		return nil, err
	}
	if _, err := resourceRegistrationQuestions(identity.serviceName, accounts); err != nil {
		return nil, err
	}
	if err := chargeNativePolicyBudget(budget, 1, 1); err != nil {
		return nil, err
	}
	var isolation, readonly string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')`).Scan(&isolation, &readonly); err != nil {
		return nil, err
	}
	if isolation != "repeatable read" || readonly != "on" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	c := &resourceInstallationCapture{lifetime: lifetime, bundle: bundle, serviceName: identity.serviceName,
		actor: identity.actor, accounts: slices.Clone(accounts),
		sources: make(map[domain.AccountID][]resourceInstallationWitness), budget: budget}
	slices.Sort(c.accounts)
	c.accounts = slices.Compact(c.accounts)
	for _, account := range c.accounts {
		c.sources[account] = nil
		cursor := ""
		for {
			left := budget.RemainingRows()
			if left == 0 {
				return nil, kaname.ErrSourceReadLimit
			}
			pageLimit := min(kaname.MaxCanonicalSourcePage, left+1)
			if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
				return nil, err
			}
			rows, err := tx.Query(ctx, `SELECT assignment_id FROM kaname.registration_account_writer_assignment
WHERE account_id=$1 AND module=$2 AND assignment_id COLLATE "C">$3::text COLLATE "C"
ORDER BY assignment_id COLLATE "C" LIMIT $4`, string(account), identity.serviceName, cursor, pageLimit)
			if err != nil {
				return nil, err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return nil, err
			}
			if err = chargeNativePolicyBudget(budget, len(ids), 0); err != nil {
				return nil, err
			}
			for _, id := range ids {
				if id == "" || id <= cursor {
					return nil, kaname.ErrSourceUnconfirmed
				}
				if err = resourceInstallationReadBudget(budget); err != nil {
					return nil, err
				}
				var witness resourceInstallationWitness
				var eligible bool
				var childRows int
				var unsupported bool
				witness.assignment = id
				err = tx.QueryRow(ctx, resourceInstallationWitnessSQL, identity.serviceName, string(account), id, c.actor, time.Time{}).
					Scan(&witness.binding, &witness.state, &eligible, &childRows, &unsupported)
				if err != nil {
					return nil, err
				}
				if err = chargeNativePolicyBudget(budget, childRows+4, 0); err != nil {
					return nil, err
				}
				if unsupported {
					return nil, kaname.ErrSourceUnconfirmed
				}
				c.sources[account] = append(c.sources[account], witness)
				cursor = id
			}
			if len(ids) < pageLimit {
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// Повторное чтение не открывает новые назначения. Изменение любого захваченного
// состояния, в том числе ABA, требует новой попытки. Только неизменённый текущий
// источник может доказать точное account#fga_writer на окончательных часах.
func (c *resourceInstallationCapture) current(ctx context.Context, w *authorityWriteTx, account domain.AccountID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if c == nil || !c.lifetime.valid(w, c.bundle) || c.budget == nil {
		return false, kaname.ErrSourceUnconfirmed
	}
	witnesses, exists := c.sources[account]
	if !exists {
		return false, kaname.ErrSourceUnconfirmed
	}
	allowed := false
	for _, witness := range witnesses {
		if err := resourceInstallationReadBudget(c.budget); err != nil {
			return false, err
		}
		var binding, state string
		var eligible bool
		var childRows int
		var unsupported bool
		err := w.tx.QueryRow(ctx, resourceInstallationWitnessSQL, c.serviceName, string(account), witness.assignment, c.actor, w.fence.decisionAt).
			Scan(&binding, &state, &eligible, &childRows, &unsupported)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, kaname.ErrAuthorityClassificationChanged
		}
		if err != nil {
			return false, err
		}
		if err = chargeNativePolicyBudget(c.budget, childRows+4, 0); err != nil {
			return false, err
		}
		if unsupported {
			return false, kaname.ErrSourceUnconfirmed
		}
		if binding != witness.binding || state != witness.state {
			return false, kaname.ErrAuthorityClassificationChanged
		}
		allowed = allowed || eligible
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return allowed, nil
}

// Один witness читает максимум четыре корневые строки, 33 субъекта и четыре
// ledger-строки. До SQL требуется остаток на весь sentinel; списывается actual
// число после чтения. Это bound логических строк, не физических MVCC tuples.
func resourceInstallationReadBudget(budget *relverdict.AdministrativeReadBudget) error {
	if budget == nil {
		return kaname.ErrSourceUnconfirmed
	}
	if budget.RemainingRows() < 41 {
		return kaname.ErrSourceReadLimit
	}
	return chargeNativePolicyBudget(budget, 0, 1)
}

// Конструктор остаётся внутри PG: будущий runner передаёт capture лишь после
// общего preflight и final clock. Наружу не выходит ни перечень источников, ни
// возможность использовать checker для другого субъекта/отношения/аккаунта.
type resourceRegistrationChecker struct {
	capture *resourceInstallationCapture
	writer  *authorityWriteTx
	native  kaname.RelationChecker
	at      time.Time
}

func (c *resourceRegistrationChecker) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if c == nil || c.capture == nil || c.writer == nil || c.writer.closed || c.native == nil || c.at.IsZero() || !c.at.Equal(c.writer.fence.decisionAt) ||
		subject != "service_account:"+c.capture.actor || relation != authzguard.RelationWriteRelation || !strings.HasPrefix(object, "account:") {
		return false, kaname.ErrSourceUnconfirmed
	}
	account := domain.AccountID(strings.TrimPrefix(object, "account:"))
	if _, exists := c.capture.sources[account]; !exists {
		return false, kaname.ErrSourceUnconfirmed
	}
	live, err := c.capture.current(ctx, c.writer, account)
	if err != nil || !live {
		return false, err
	}
	return c.native.Check(ctx, subject, relation, object)
}

// LIMIT здесь — предохранитель повреждённой installation формы. Четвёртая
// ledger-строка или 33-й субъект возвращают Unknown, а не объявляют
// усечённый набор полным. Нормальное назначение содержит одного субъекта и два
// ledger tuple: прямое отношение и структурного родителя.
const resourceInstallationWitnessSQL = `
WITH source AS (
 SELECT a, b, sa, acc,
   coalesce((SELECT jsonb_agg(jsonb_build_array(s.xmin::text,s.ctid::text,to_jsonb(s)) ORDER BY s.subject_type,s.subject_id,s.ordinal)
     FROM (SELECT s.* , s.xmin, s.ctid FROM kaname.access_binding_subjects s
       WHERE s.binding_id=a.binding_id LIMIT 33) s),'[]'::jsonb) subjects,
   coalesce((SELECT jsonb_agg(jsonb_build_array(e.xmin::text,e.ctid::text,to_jsonb(e)) ORDER BY e.fga_user,e.relation,e.object,e.source)
     FROM (SELECT e.* , e.xmin, e.ctid FROM kaname.access_binding_emitted_tuples e
       WHERE e.binding_id=a.binding_id LIMIT 4) e),'[]'::jsonb) ledger,
   jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a),b.xmin::text,b.ctid::text,to_jsonb(b),
    sa.xmin::text,sa.ctid::text,to_jsonb(sa),acc.xmin::text,acc.ctid::text,to_jsonb(acc)) roots
 FROM kaname.registration_account_writer_assignment a
 LEFT JOIN kaname.access_bindings b ON b.id=a.binding_id
 LEFT JOIN kaname.service_accounts sa ON sa.id=$4
 LEFT JOIN kaname.accounts acc ON acc.id=$2
 WHERE a.module=$1 AND a.account_id=$2 AND a.assignment_id=$3
)
SELECT (a).binding_id, jsonb_build_array(roots,subjects,ledger)::text,
 coalesce((a).removed_at IS NULL AND (acc).id=$2 AND (sa).id=$4 AND (sa).enabled
  AND (b).id=(a).binding_id AND (b).is_system AND (b).status='ACTIVE' AND (b).revoked_at IS NULL
  AND ((b).expires_at IS NULL OR (b).expires_at>$5::timestamptz)
  AND (b).resource_type='account' AND (b).resource_id=$2 AND (b).role_id IS NULL
  AND (b).subject_type='service_account' AND (b).subject_id=$4 AND (b).granted_relation='fga_writer'
  AND coalesce(jsonb_array_length((b).target->'resources'),0)=0
  AND jsonb_array_length(subjects)=1
  AND subjects->0->2->>'subject_type'='service_account' AND subjects->0->2->>'subject_id'=$4
  AND subjects->0->2->>'resource_type'='account' AND subjects->0->2->>'resource_id'=$2
  AND jsonb_array_length(ledger)<4
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(ledger) e
    WHERE e->2->>'fga_user'='service_account:'||$4 AND e->2->>'relation'='fga_writer'
      AND e->2->>'object'='account:'||$2 AND e->2->>'source'='binding'),false),
 jsonb_array_length(subjects)+jsonb_array_length(ledger),
 jsonb_array_length(subjects)>=33 OR jsonb_array_length(ledger)>=4
FROM source`
