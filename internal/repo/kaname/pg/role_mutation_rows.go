// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

var roleProjectionRowKinds = []string{"selectors", "verbs", "refs", "create_capability", "bind_capability", "pending"}

// Имена таблиц замкнуты здесь; пользовательских identifiers нет. Физический
// locator применим только с тем же source epoch и повторной проверкой xmin.
// Перемещение/замена строки требует restage, не молчаливого пропуска lock.
func roleStageRowSource(kind string) (table, predicate string, err error) {
	switch kind {
	case "selectors":
		table = "role_rule_selectors"
	case "verbs":
		table = "role_verb"
	case "refs":
		table = "role_rule_ref"
	case "create_capability":
		table = "role_create_binding_rule"
	case "bind_capability":
		table = "role_bind_role_rule"
	case "pending":
		table = "role_selector_verbs_pending"
	case "ledger":
		return "access_binding_emitted_tuples", "binding_id=$1 AND (source='binding' OR (member_object_type='' AND member_object_id=''))", nil
	default:
		return "", "", kaname.ErrInvalidAuthorityFencePlan
	}
	return table, "role_id=$1", nil
}
func (s *roleMutationStage) stageRows(ctx context.Context, tx pgx.Tx, kind, owner string) error {
	table, predicate, err := roleStageRowSource(kind)
	if err != nil {
		return err
	}
	after := "(0,0)"
	for {
		if err := s.read(0); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT ctid::text,xmin::text FROM kaname.%s WHERE (%s) AND ctid>$2::tid ORDER BY ctid LIMIT $3`, table, predicate), owner, after, policyDiscoveryPage)
		if err != nil {
			return err
		}
		type rowKey struct{ tid, xmin string }
		var page []rowKey
		for rows.Next() {
			var key rowKey
			if err = rows.Scan(&key.tid, &key.xmin); err != nil {
				rows.Close()
				return err
			}
			page = append(page, key)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if err = s.charge(len(page)); err != nil {
			return err
		}
		for _, key := range page {
			if _, err = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_role_stage_rows(kind,owner_id,row_tid,row_xmin) VALUES($1,$2,$3,$4)`, kind, owner, key.tid, key.xmin); err != nil {
				return err
			}
		}
		if len(page) < policyDiscoveryPage {
			return nil
		}
		after = page[len(page)-1].tid
	}
}
func (s *roleMutationStage) lockStagedRows(ctx context.Context, w *authorityWriteTx) error {
	var after int64
	for {
		rows, err := w.tx.Query(ctx, `SELECT seq,kind,owner_id,row_tid,row_xmin FROM pg_temp.kaname_role_stage_rows WHERE seq>$1 ORDER BY seq LIMIT $2`, after, policyDiscoveryPage)
		if err != nil {
			return err
		}
		type stagedRow struct {
			seq                    int64
			kind, owner, tid, xmin string
		}
		var page []stagedRow
		for rows.Next() {
			var row stagedRow
			if err = rows.Scan(&row.seq, &row.kind, &row.owner, &row.tid, &row.xmin); err != nil {
				rows.Close()
				return err
			}
			page = append(page, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, row := range page {
			table, predicate, err := roleStageRowSource(row.kind)
			if err != nil {
				return err
			}
			var xmin string
			err = w.tx.QueryRow(ctx, fmt.Sprintf(`SELECT xmin::text FROM kaname.%s WHERE (%s) AND ctid=$2::tid FOR UPDATE`, table, predicate), row.owner, row.tid).Scan(&xmin)
			if errors.Is(err, pgx.ErrNoRows) {
				return kaname.ErrAuthorityClassificationChanged
			}
			if err != nil {
				return err
			}
			if xmin != row.xmin {
				return kaname.ErrAuthorityClassificationChanged
			}
		}
		if len(page) < policyDiscoveryPage {
			return ctx.Err()
		}
		after = page[len(page)-1].seq
	}
}
