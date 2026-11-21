// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// BindingCapabilityVersions не выводит версию из правил роли или её проекции:
// старый carrier остаётся версией 0 после изменения роли. Источник — только
// колонка самой выдачи, прочитанная на удерживаемом writer.
func (w *authorityWriteTx) BindingCapabilityVersions(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]int, error) {
	if len(ids) > kaname.MaxAuthorityBindingVersionBatch {
		return nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument binding version batch")
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		if id == "" {
			return nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument binding id")
		}
		keys[i] = string(id)
	}
	out := make(map[domain.AccessBindingID]int, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := w.tx.Query(ctx, `SELECT id, grant_capability_version FROM kaname.access_bindings WHERE id = ANY($1::text[])`, keys)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var id domain.AccessBindingID
		var version int
		if err := rows.Scan(&id, &version); err != nil {
			return nil, mapErr(err, "", "")
		}
		if version != 0 && version != 1 {
			return nil, fmt.Errorf("unsupported authority binding capability version: %d", version)
		}
		out[id] = version
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}
