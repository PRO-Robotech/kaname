// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Только наблюдение после FALSE: исходный assertion остаётся обязательным.
// Нет новых сроков, исправляющих записей, allow tuples или изменения verdict.
func mirrorLogPublicVGet(t *testing.T, ctx context.Context, r protocolRig, binding domain.AccessBindingID, uid, object string, admitted bool) {
	t.Helper()
	plan, planErr := r.bundle.Plan("vpc_network", "v_get")
	encoded, encodeErr := json.Marshal(plan)
	t.Logf("v_get diagnostic original_admitted=%t plan=%s plan_error=%v encode_error=%v", admitted, encoded, planErr, encodeErr)
	tx, err := r.runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Logf("v_get diagnostic begin_error=%v", err)
		return
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Logf("v_get diagnostic clock_error=%v", err)
		return
	}
	verdict, grounds, verdictErr := relverdict.Ask(ctx, tx, relverdict.Query{PreparedPlans: r.bundle, DecisionAt: at, Subject: "user:" + uid, ObjectType: "vpc_network", ObjectID: object, Relation: "v_get"})
	t.Logf("v_get diagnostic raw_verdict=%v grounds=%+v error=%v", verdict, grounds, verdictErr)
	var state []byte
	err = tx.QueryRow(ctx, `SELECT jsonb_build_object(
 'binding',(SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE b.id=$1),
 'user_marks',(SELECT jsonb_build_object('invite_status',u.invite_status,'email_verified',u.email_verified_at IS NOT NULL,'disabled_at',to_jsonb(u)->'disabled_at','deleted_at',to_jsonb(u)->'deleted_at','login_kind',to_jsonb(u)->'login_kind') FROM kaname.users u WHERE u.id=$2),
 'role',(SELECT to_jsonb(r) FROM kaname.roles r JOIN kaname.access_bindings b ON b.role_id=r.id WHERE b.id=$1),
 'selectors',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT s.* FROM kaname.role_rule_selectors s JOIN kaname.access_bindings b ON b.role_id=s.role_id WHERE b.id=$1 LIMIT 16) q),
 'verbs',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT v.* FROM kaname.role_verb v JOIN kaname.access_bindings b ON b.role_id=v.role_id WHERE b.id=$1 AND v.object_type='vpc.network' LIMIT 16) q),
 'subjects',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT s.* FROM kaname.access_binding_subjects s WHERE s.binding_id=$1 LIMIT 16) q),
 'members',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT m.* FROM kaname.access_binding_target_members m WHERE m.binding_id=$1 AND m.object_id=$3 LIMIT 16) q),
 'ledger',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT l.* FROM kaname.access_binding_emitted_tuples l WHERE l.binding_id=$1 AND l.object='vpc_network:'||$3 LIMIT 16) q),
 'facts',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT f.* FROM kaname.relation_fact f WHERE f.object_type='vpc_network' AND f.object_id=$3 LIMIT 16) q),
 'mirror',(SELECT to_jsonb(m) FROM kaname.resource_mirror m WHERE m.object_type='vpc.network' AND m.object_id=$3),
 'parents',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT e.* FROM kaname.resource_parent_edge e WHERE to_jsonb(e)->>'object_id'=$3 LIMIT 16) q),
 'catalog',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT c.* FROM kaname.catalog_resource c WHERE to_jsonb(c)->>'object_type'='vpc_network' OR to_jsonb(c)->>'resource'='network' LIMIT 16) q),
 'outbox',(SELECT jsonb_agg(to_jsonb(q)) FROM (SELECT o.event_type,o.payload,o.created_at FROM kaname.fga_outbox o WHERE o.payload::text LIKE '%'||$3||'%' LIMIT 16) q)
 )`, string(binding), uid, object).Scan(&state)
	t.Logf("v_get diagnostic committed_state=%s error=%v", state, err)
}
