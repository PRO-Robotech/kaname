// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Каталог захватывается чтением. Ни RR witness, ни его protected RC recheck
// не выполняют UPDATE/INSERT постоянной строки каталога или общего fence.
// Защиту shared catalog admission обязан получить runner до этого recheck.
type resourceCatalogRow struct {
	identity domain.CatalogTypeIdentity
	live     bool
	policy   domain.WritePolicy
	state    string
}
type resourceCatalogCapture struct {
	input string
	rows  []resourceCatalogRow
}

// Две версии одного model type ограничены действующим UNIQUE(object_type,live).
// Третья строка — sentinel повреждённой/неподдержанной dictionary формы, не
// разрешение выбрать произвольную первую строку. OR соответствует штатному reader.
const resourceCatalogCaptureSQL = `SELECT c.dotted,c.module,c.object_type,c.live,
 c.parent_names,c.parent_types,c.writes,c.permanent_project,
 jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c))::text
 FROM kaname.catalog_resource c WHERE c.object_type=$1 OR c.dotted=$1
 ORDER BY c.live DESC,c.dotted COLLATE "C" LIMIT $2`

func readResourceCatalog(ctx context.Context, tx pgx.Tx, input string, budget *relverdict.AdministrativeReadBudget) (*resourceCatalogCapture, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tx == nil || budget == nil || input == "" || strings.TrimSpace(input) != input || strings.ContainsAny(input, ":\x00") {
		return nil, kaname.ErrSourceUnconfirmed
	}
	remaining := budget.RemainingRows()
	if remaining == 0 {
		return nil, kaname.ErrSourceReadLimit
	}
	limit := 3
	if remaining < limit {
		limit = remaining + 1
	}
	if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, resourceCatalogCaptureSQL, input, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	capture := &resourceCatalogCapture{input: input}
	for rows.Next() {
		var row resourceCatalogRow
		var names, types, writes []string
		if err = rows.Scan(&row.identity.Dotted, &row.identity.Module, &row.identity.ObjectType, &row.live, &names, &types, &writes, &row.policy.PermanentProject, &row.state); err != nil {
			return nil, err
		}
		if err = chargeNativePolicyBudget(budget, 1, 0); err != nil {
			return nil, err
		}
		if len(capture.rows) == 2 || len(names) != len(types) || row.state == "" || row.identity.Dotted == "" || row.identity.Module == "" || row.identity.ObjectType == "" {
			return nil, kaname.ErrSourceUnconfirmed
		}
		row.policy.Module = row.identity.Module
		row.policy.ObjectType = row.identity.ObjectType
		for i, name := range names {
			row.policy.Pointers = append(row.policy.Pointers, domain.ParentPointer{Name: name, Type: types[i]})
		}
		for _, raw := range writes {
			grant, ok := domain.ParseWriteGrant(raw)
			if !ok {
				return nil, kaname.ErrSourceUnconfirmed
			}
			row.policy.Writes = append(row.policy.Writes, grant)
		}
		capture.rows = append(capture.rows, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return capture, ctx.Err()
}

func (c *resourceCatalogCapture) selected() (resourceCatalogRow, bool) {
	if c == nil || len(c.rows) == 0 {
		return resourceCatalogRow{}, false
	}
	return c.rows[0], true
}

// Даже отсутствие каталога — точный RR witness. Новая/удалённая/заменённая
// строка, ABA или смена live после ожидания требуют новой полной попытки.
func (c *resourceCatalogCapture) recheck(ctx context.Context, tx pgx.Tx, budget *relverdict.AdministrativeReadBudget) error {
	if c == nil {
		return kaname.ErrSourceUnconfirmed
	}
	current, err := readResourceCatalog(ctx, tx, c.input, budget)
	if err != nil {
		return err
	}
	if len(c.rows) != len(current.rows) {
		return kaname.ErrAuthorityClassificationChanged
	}
	for i, row := range c.rows {
		if row.state != current.rows[i].state || row.identity != current.rows[i].identity || row.live != current.rows[i].live {
			return kaname.ErrAuthorityClassificationChanged
		}
	}
	return nil
}
