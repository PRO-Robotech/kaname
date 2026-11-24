// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package fga_outbox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// Один порядок table locks совпадает с Down. Receipt не хранит named ownership
// и не выводится из прежних фактов: его создаёт только текущий combined план.
func lockRetirementTables(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `LOCK TABLE kaname.resource_registration_pointer IN ACCESS SHARE MODE`)
	return err
}

func prepareRetirementTx(ctx context.Context, tx pgx.Tx, rows []outboxtypes.VersionedRelationTuple) error {
	if err := lockRetirementTables(ctx, tx); err != nil {
		return fmt.Errorf("retirement lock: %w", err)
	}
	for _, row := range rows {
		t := row.Tuple
		if t.Relation != "project" && t.Relation != "parent" && t.Relation != "owner" {
			continue
		}
		typ, id, ok := strings.Cut(t.Object, ":")
		if !ok || typ == "" || id == "" {
			return fmt.Errorf("retirement: invalid object")
		}
		cutoff := row.SourceVersion
		if row.CurrentRemoval {
			// Только actual zero removal разрешает этот nonlocking snapshot. Writer
			// fence уже взят use-case; AB может поднять aggregate, но не сам cutoff.
			err := tx.QueryRow(ctx, `SELECT source_version FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 AND isfinite(source_version)`, typ, id, t.Relation, t.User).Scan(&cutoff)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("retirement snapshot: %w", err)
			}
		} else if cutoff.IsZero() {
			continue
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.resource_registration_retirement(object_type,object_id,relation,subject,delete_through) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE SET delete_through=greatest(resource_registration_retirement.delete_through,EXCLUDED.delete_through)`, typ, id, t.Relation, t.User, cutoff)
		if err != nil {
			return fmt.Errorf("retirement save: %w", err)
		}
	}
	return nil
}

func invalidateRetirementTx(ctx context.Context, tx pgx.Tx, users, relations, objects []string) error {
	if err := lockRetirementTables(ctx, tx); err != nil {
		return fmt.Errorf("retirement lock: %w", err)
	}
	_, err := tx.Exec(ctx, `DELETE FROM kaname.resource_registration_retirement p USING unnest($1::text[],$2::text[],$3::text[]) AS t(u,r,o)
 WHERE p.object_type=split_part(t.o,':',1) AND p.object_id=substr(t.o,strpos(t.o,':')+1) AND p.relation=t.r AND p.subject=t.u AND t.r IN ('project','parent','owner')`, users, relations, objects)
	if err != nil {
		return fmt.Errorf("retirement invalidate: %w", err)
	}
	return nil
}
