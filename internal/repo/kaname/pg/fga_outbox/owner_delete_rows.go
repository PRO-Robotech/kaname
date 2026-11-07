// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package fga_outbox

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// EmitVersionedDeleteTx кладёт объединённый набор ОДНИМ оператором: свёртка
// берёт полный набор fact locks в прежнем общем порядке, независимо от версии
// каждой строки. Разбивать версии на отдельные вызовы нельзя.
// protect_holders — внутренний literal этого оператора: даже legacy строка
// смешанного набора не снимает факт, который ещё держит независимая выдача.
func EmitVersionedDeleteTx(ctx context.Context, tx pgx.Tx, rows []outboxtypes.VersionedRelationTuple) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(rows) == 0 {
		return nil
	}
	users := make([]string, 0, len(rows))
	relations := make([]string, 0, len(rows))
	objects := make([]string, 0, len(rows))
	versions := make([]pgtype.Timestamptz, 0, len(rows))
	seen := map[outboxtypes.RelationTuple]outboxtypes.VersionedRelationTuple{}
	unique := make([]outboxtypes.VersionedRelationTuple, 0, len(rows))
	for _, row := range rows {
		t := row.Tuple
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("fga_outbox: withdrawal tuple without user/relation/object")
		}
		if domain.IsStoredPublication(t.User, t.Relation) || strings.HasPrefix(t.Relation, "v_") {
			return fmt.Errorf("fga_outbox: publication or verb in registration withdrawal")
		}
		if prior, ok := seen[t]; ok {
			if !prior.SourceVersion.Equal(row.SourceVersion) || prior.CurrentRemoval != row.CurrentRemoval {
				return fmt.Errorf("fga_outbox: conflicting versions of withdrawal tuple")
			}
			continue
		}
		seen[t] = row
		unique = append(unique, row)
		users = append(users, t.User)
		relations = append(relations, t.Relation)
		objects = append(objects, t.Object)
		versions = append(versions, pgtype.Timestamptz{Time: row.SourceVersion, Valid: !row.SourceVersion.IsZero()})
	}
	// Все receipt mutations завершаются до первого fact lock всего набора.
	if err := prepareRetirementTx(ctx, tx, unique); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at)
 SELECT $1,jsonb_build_object('user',u,'relation',r,'object',o,'protect_holders',true) || CASE WHEN v IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('source_version',v) END,clock_timestamp()
 FROM unnest($2::text[],$3::text[],$4::text[],$5::timestamptz[]) AS t(u,r,o,v)
 ORDER BY o COLLATE "C",u COLLATE "C",r COLLATE "C"`, EventTypeDelete, users, relations, objects, versions)
	if err != nil {
		return fmt.Errorf("fga_outbox: insert versioned withdrawal: %w", err)
	}
	return nil
}
