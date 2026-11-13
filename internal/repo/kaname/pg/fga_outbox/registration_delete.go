// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package fga_outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// EmitRegistrationDeleteTx — только отзыв регистрации. Общий EmitDeleteTx
// обслуживает и AB, поэтому не вправе отзывать provenance регистрации.
func EmitRegistrationDeleteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple, version time.Time) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(tuples) == 0 {
		return nil
	}
	users, relations, objects := []string{}, []string{}, []string{}
	versions := []pgtype.Timestamptz{}
	seen := map[clients.RelationTuple]bool{}
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" || domain.IsStoredPublication(t.User, t.Relation) || strings.HasPrefix(t.Relation, "v_") {
			return fmt.Errorf("fga_outbox: invalid registration withdrawal tuple")
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		users = append(users, t.User)
		relations = append(relations, t.Relation)
		objects = append(objects, t.Object)
		versions = append(versions, pgtype.Timestamptz{Time: version, Valid: !version.IsZero()})
	}
	actionAt, err := retireProducerOwnersTx(ctx, tx, users, relations, objects, versions)
	if err != nil {
		return err
	}
	if !version.IsZero() {
		_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at)
 SELECT $1,jsonb_build_object('user',u,'relation',r,'object',o,'source_version',$5::timestamptz),$6::timestamptz
 FROM unnest($2::text[],$3::text[],$4::text[]) AS t(u,r,o)
 ORDER BY o,u,r`, EventTypeDelete, users, relations, objects, version, actionAt)
	} else {
		// Сохраняем прежнюю группировку/порядок legacy payload. Clock НЕ попадает
		// в source_version: иначе изменится ветка свёртки и защита других holders.
		groups := groupByGrant(tuples)
		payloads := make([]string, 0, len(groups))
		for _, g := range groups {
			fields := map[string]any{"user": g.user, "object": g.object}
			if len(g.relations) == 1 {
				fields["relation"] = g.relations[0]
			} else {
				fields["relations"] = g.relations
			}
			payload, e := json.Marshal(fields)
			if e != nil {
				return e
			}
			payloads = append(payloads, string(payload))
		}
		_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at)
 SELECT $1,p::jsonb,$3::timestamptz FROM unnest($2::text[]) AS p`, EventTypeDelete, payloads, actionAt)
	}
	if err != nil {
		return fmt.Errorf("fga_outbox: registration withdrawal: %w", err)
	}
	return nil
}

// Две фазы одной TX: сначала фиксируем единственную границу действия и
// завершаем ВСЕ receipt UPDATE, затем вызывающий вставляет весь journal набор.
// INSERT/его trigger не может захватить fact locks до завершения этой функции.
// Ordered строки сравниваются с SourceVersion; legacy — с той же actionAt,
// которая передаётся как created_at, даже если UPDATE пришлось ждать.
func retireProducerOwnersTx(ctx context.Context, tx pgx.Tx, users, relations, objects []string, versions []pgtype.Timestamptz) (time.Time, error) {
	var actionAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&actionAt); err != nil {
		return actionAt, err
	}
	_, err := tx.Exec(ctx, `UPDATE kaname.producer_source_receipt p
 SET active=false,invalidation='owner_withdrawn',model_identity=NULL,catalog_identity=NULL,projector_version=NULL
 FROM unnest($1::text[],$2::text[],$3::text[],$4::timestamptz[]) AS t(u,r,o,v)
 WHERE p.kind='registration_owner' AND t.r='owner' AND p.relation=t.r
 AND p.object_type=split_part(t.o,':',1) AND p.object_id=substr(t.o,strpos(t.o,':')+1)
 AND p.subject_type=split_part(t.u,':',1) AND p.subject_id=substr(t.u,strpos(t.u,':')+1)
 AND p.source_version<=coalesce(t.v,$5::timestamptz)`, users, relations, objects, versions, actionAt)
	if err != nil {
		return actionAt, fmt.Errorf("fga_outbox: retire producer receipt: %w", err)
	}
	return actionAt, nil
}
