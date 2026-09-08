// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// group_member_fga_outbox_integration_test.go — integration proof of the in-tx
// fga_outbox co-commit for GROUP MEMBERSHIP (the E-31 / group-based-authz bug).
//
// The bug: AddMember persisted ONLY the kaname.group_members row and emitted
// NO `group:<gid>#member` userset intent, so a binding on a GROUP subject resolved
// to no concrete members at all. These tests pin the atomic emit
// contract the AddMember/RemoveMember use-cases now rely on:
//
//   GM-O1  AddMember's group_members DML + the FGA member-tuple INTENT
//          (event_type='fga.tuple.write', payload {user:user:<id>, member,
//          object:group:<gid>}) co-commit in the SAME writer-tx. The object type
//          is `group`, NOT `iam_group`.
//
//          Здесь стояло ещё одно утверждение — «строка ПОКА НЕ ДОСТАВЛЕНА»
//          (`sent_at IS NULL`). Оно снято вместе со своим предметом: дренажа у
//          этого журнала больше нет (стадия S6 эпика #747, `a4b6cfba9`), а
//          колонки доставки сняла миграция 20260822160000 (kacho#917). Строка
//          журнала действует С КОММИТА, поэтому «доставлена или нет» — вопрос,
//          которого не существует; проверять его было нечем и незачем.
//   GM-O2  Rollback discards BOTH the group_members row AND the fga_outbox intent
//          — atomic all-or-nothing (запрет #10).
//   GM-O3  RemoveMember co-commits the SYMMETRIC delete intent
//          (event_type='fga.tuple.delete') with the exact same payload.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// groupMemberFGATuple is the member-tuple shape AddMember/RemoveMember co-commit:
// user|service_account:<member_id> → member → group:<group_id>.
func groupMemberFGATuple(memberType, memberID, groupID string) service.RelationTuple {
	return service.RelationTuple{
		User:     memberType + ":" + memberID,
		Relation: "member",
		Object:   "group:" + groupID,
	}
}

func TestGroupMember_FGAOutbox_GM_O1_AddEmitsMemberTupleInTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gmo1")
	acc := seedAccount(t, ctx, repo, "acc-gmo1", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-gmo1")
	tup := groupMemberFGATuple("user", string(uid), string(g.ID))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(string(uid)),
	}))
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{tup}))
	require.NoError(t, w.Commit(ctx))

	var et, payloadRaw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload::text
		   FROM kaname.fga_outbox
		  WHERE payload->>'object' = $1
		  ORDER BY id DESC LIMIT 1`,
		"group:"+string(g.ID)).Scan(&et, &payloadRaw))
	require.Equal(t, "fga.tuple.write", et)
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, "user:"+string(uid), payload["user"])
	require.Equal(t, "member", payload["relation"])
	require.Equal(t, "group:"+string(g.ID), payload["object"],
		"member-tuple object must be FGA type `group`, NOT iam_group")
}

func TestGroupMember_FGAOutbox_GM_O2_RollbackDiscardsBoth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gmo2")
	acc := seedAccount(t, ctx, repo, "acc-gmo2", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-gmo2")
	tup := groupMemberFGATuple("user", string(uid), string(g.ID))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(string(uid)),
	}))
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{tup}))
	require.NoError(t, w.Rollback(ctx))

	var memCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.group_members WHERE group_id = $1 AND member_id = $2`,
		string(g.ID), string(uid)).Scan(&memCount))
	require.Equal(t, 0, memCount, "group_members row must be rolled back")

	var intentCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object' = $1`,
		"group:"+string(g.ID)).Scan(&intentCount))
	require.Equal(t, 0, intentCount,
		"fga_outbox member-tuple intent must roll back atomically with the membership row (запрет #10)")
}

func TestGroupMember_FGAOutbox_GM_O3_RemoveEmitsSymmetricDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gmo3")
	acc := seedAccount(t, ctx, repo, "acc-gmo3", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-gmo3")
	tup := groupMemberFGATuple("user", string(uid), string(g.ID))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().RemoveMember(ctx, g.ID, domain.SubjectTypeUser, domain.SubjectID(string(uid))))
	require.NoError(t, w.EmitFGARelationDelete(ctx, []service.RelationTuple{tup}))
	require.NoError(t, w.Commit(ctx))

	var et, payloadRaw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload::text
		   FROM kaname.fga_outbox
		  WHERE payload->>'object' = $1
		  ORDER BY id DESC LIMIT 1`,
		"group:"+string(g.ID)).Scan(&et, &payloadRaw))
	require.Equal(t, "fga.tuple.delete", et, "RemoveMember co-commits a symmetric delete intent")
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, "user:"+string(uid), payload["user"])
	require.Equal(t, "member", payload["relation"])
	require.Equal(t, "group:"+string(g.ID), payload["object"])
}
