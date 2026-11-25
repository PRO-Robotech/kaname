// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto/toproto"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/anypb"
)

// Только для PG integration: в тестовой базе три SQL входа вызывают приватные
// функции владельца. RR discovery, две policy protection и evaluator штатные.
func ProbeUserMetadataNoop(ctx context.Context, factory *MetadataMutationWriters, op operations.Operation,
	uid, account string, patch json.RawMessage, afterReserve func(pgx.Tx, string) error, finish string,
) (*anypb.Any, error) {
	policy := factory.policy
	repo := policy.repo
	conn, err := repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer policyRollback(ctx, rr)
	var physical, members json.RawMessage
	err = rr.QueryRow(ctx, `SELECT jsonb_build_array(u.xmin::text,u.ctid::text,to_jsonb(u)),
		(SELECT coalesce(jsonb_agg(s.image ORDER BY s.image::text COLLATE "C"),'[]'::jsonb)
		 FROM (SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) image FROM ONLY kaname.memberships m WHERE m.user_id=u.id LIMIT 257) s)
		FROM ONLY kaname.users u WHERE u.id=$1`, uid).Scan(&physical, &members)
	if err != nil {
		return nil, err
	}
	var memberRows []json.RawMessage
	if err = json.Unmarshal(members, &memberRows); err != nil {
		return nil, err
	}
	if len(memberRows) > 256 {
		return nil, kaname.ErrSourceReadLimit
	}
	actor := domain.Subject{Type: domain.SubjectType(op.Principal.Type), ID: domain.SubjectID(op.Principal.ID)}
	questions := newNativePolicyQuestions()
	if err = questions.add(actor, "record_writer", "iam_user", uid); err != nil {
		return nil, err
	}
	request := policyWriteRequest{actor: actor, kind: kaname.AuthorityResource, global: true, nativeQuestions: questions, consumedReads: 2}
	plan, err := policy.discoverPolicyPlanWithRows(ctx, rr, request, 1+len(memberRows))
	if err != nil {
		return nil, err
	}
	if err = rr.Rollback(ctx); err != nil {
		return nil, err
	}
	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer policyRollback(ctx, rc)
	intent := plan.intent(policy.bundle)
	if intent.Plan.Mode != kaname.AuthorityFenceGlobal || len(intent.Owners) != 0 {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	writer, err := repo.enterAuthority(ctx, rc, intent, []byte("[]"), intent.Plan.Mode, intent.Plan.Accounts, false, "decision", plan)
	if err != nil {
		return nil, err
	}
	_, err = rc.Exec(ctx, `SELECT kaname.test_user_noop_prepare($1,$2,$3,$4,$5,$6)`, uid, physical, members, patch, actor.Type, actor.ID)
	if err != nil {
		return nil, err
	}
	if err = policy.protectPolicyPlanAt(ctx, writer, plan, policyPlanBeforeMetadataFreeze); err != nil {
		return nil, err
	}
	var retained domain.User
	var nonce string
	var rows, reads int
	// Пополняем штатный scanUser непосредственно json-строкой закрытого reserve.
	reserve := "kaname.test_user_noop_reserve($1,$2,$3,$4,$5,$6,$7,$8,$9)"
	args := []any{op.ID, op.CreatedAt, op.Metadata.Value, account, actor.Type, actor.ID, op.Principal.DisplayName,
		plan.nativeBudget.RemainingRows(), plan.nativeBudget.RemainingReads()}
	err = scanUserInto(rc.QueryRow(ctx, `WITH receipt AS MATERIALIZED (
		SELECT `+reserve+` packet
	) SELECT `+userCols+`,packet->>'nonce',(packet->>'rows')::int,(packet->>'reads')::int FROM receipt
	CROSS JOIN LATERAL jsonb_populate_record(NULL::kaname.users,packet->'user') AS retained`,
		args...), &retained, &nonce, &rows, &reads)
	if err != nil {
		return nil, err
	}
	if string(retained.ID) != uid {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(plan.nativeBudget, rows, reads); err != nil {
		return nil, err
	}
	if afterReserve != nil {
		if err = afterReserve(rc, nonce); err != nil {
			return nil, err
		}
	}
	if err = policy.protectPolicyPlanAt(ctx, writer, plan, policyPlanBeforeMetadataWrite); err != nil {
		return nil, err
	}
	if _, err = rc.Exec(ctx, `SELECT kaname.authority_scalar_sequence_finalize_v3()`); err != nil {
		return nil, err
	}
	semantic := newSemanticAuthorityWriter(writer, policy.bundle)
	allowed, err := semantic.SemanticRelationChecker().Check(ctx, subjectPolicyKey(actor), "record_writer", "iam_user:"+uid)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, iamerr.ErrPermissionDenied
	}
	if finish == "omit" {
		return nil, rc.Commit(ctx)
	}
	response, err := toproto.MarshalUserOperationResponse(retained)
	if err != nil {
		return nil, err
	}
	const complete = `SELECT o.id FROM kaname.test_user_noop_complete($1,$2,$3,$4) o
	WHERE o.id=$1 AND o.done AND o.response_data=$4 AND o.response_type=$5 AND o.metadata_data=$6`
	var id string
	opID, attempt, decision := op.ID, nonce, writer.AuthorityFence().DecisionAt()
	switch finish {
	case "wrong nonce":
		attempt = "00000000-0000-0000-0000-000000000000"
	case "wrong operation":
		opID = "other"
	case "wrong clock":
		decision = decision.Add(-time.Microsecond)
	}
	doComplete := func() error {
		return rc.QueryRow(ctx, complete, opID, attempt, decision, response.Value, response.TypeUrl, op.Metadata.Value).Scan(&id)
	}
	if err = doComplete(); err != nil {
		return nil, err
	}
	switch finish {
	case "replay":
		return nil, doComplete()
	case "rollback":
		return response, rc.Rollback(ctx)
	case "commit":
		return response, rc.Commit(ctx)
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
}
