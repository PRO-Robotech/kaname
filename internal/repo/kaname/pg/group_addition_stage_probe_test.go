// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"fmt"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Конечный TEST-only probe использует ту же ordinary LOGIN TX фабрики.
// Обход Go-декоратора нужен для проверки независимого отказа БД, включая COMMIT.
// Произвольный SQL, owner connection и готовая подпись сюда не передаются.
func GroupAdditionProbeForTest(ctx context.Context, writer kaname.SemanticAuthorityWriter, probe string) error {
	w, ok := writer.(*preparedGroupAdditionWriter)
	if !ok || w.stage == nil {
		return fmt.Errorf("ожидался фактический prepared Add writer")
	}
	m := w.stage.member
	gid, typ, mid, stamp := string(m.GroupID), string(m.MemberType), string(m.MemberID), w.stage.stamp
	var query string
	var args []any
	switch probe {
	case "commit":
		return w.tx.Commit(ctx)
	case "member-replay", "member-group", "member-type", "member-id", "member-stamp":
		switch probe {
		case "member-group":
			gid += "_foreign"
		case "member-type":
			typ = "service_account"
		case "member-id":
			mid += "_foreign"
		case "member-stamp":
			stamp = stamp.Add(time.Microsecond)
		}
		query = `INSERT INTO kaname.group_members(group_id,member_type,member_id,added_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`
		args = []any{gid, typ, mid, stamp}
	case "group-empty-delete":
		query = `DELETE FROM kaname.group_members WHERE false`
	case "fact-empty-delete":
		query = `DELETE FROM kaname.relation_fact WHERE false`
	case "subject-empty-delete":
		query = `DELETE FROM kaname.subject_change_outbox WHERE false`
	case "direct-fact":
		query = `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version) VALUES('group',$1,'member',$2,now())`
		args = []any{gid, typ + ":" + mid}
	case "direct-journal":
		query = `INSERT INTO kaname.resource_journal(sequence_no,resource_kind,resource_id,project_id,scope,event_type,payload) VALUES(9223372036854775806,'iam_group',$1,NULL,'[]'::jsonb,'UPDATED',jsonb_build_object('id',$1::text))`
		args = []any{gid}
	case "wrong-origin":
		query = `SELECT kaname.authority_prepared_journal_value_v3('{"table":"group_members","operation":"INSERT","when":"AFTER","old":null,"new":null}'::jsonb,'{}'::jsonb)`
	case "fga-foreign", "fga-explicit-id", "fga-replay":
		query = `INSERT INTO kaname.fga_outbox(event_type,payload) VALUES('fga.tuple.write',jsonb_build_object('user',$1::text,'relation','member','object',$2::text))`
		if probe == "fga-foreign" {
			mid += "_foreign"
		}
		if probe == "fga-explicit-id" {
			query = `INSERT INTO kaname.fga_outbox(id,event_type,payload) VALUES(9223372036854775806,'fga.tuple.write',jsonb_build_object('user',$1::text,'relation','member','object',$2::text))`
		}
		args = []any{typ + ":" + mid, "group:" + gid}
	case "subject-foreign", "subject-explicit-id", "subject-replay":
		if probe == "subject-foreign" {
			mid += "_foreign"
		}
		query = `INSERT INTO kaname.subject_change_outbox(subject_id,op,event_type,payload) VALUES($1,'group_member_change','group_member_change',jsonb_build_object('subject_id',$1::text,'subject_type',$2::text,'op','group_member_change','event_type','group_member_change'))`
		if probe == "subject-explicit-id" {
			query = `INSERT INTO kaname.subject_change_outbox(id,subject_id,op,event_type,payload) VALUES(9223372036854775806,$1,'group_member_change','group_member_change',jsonb_build_object('subject_id',$1::text,'subject_type',$2::text,'op','group_member_change','event_type','group_member_change'))`
		}
		args = []any{mid, typ}
	case "prepare-reentry":
		query = `SELECT kaname.authority_group_add_prepare_v3($1::jsonb,100000,4096)`
		args = []any{w.stage.request}
	case "finalize-reentry":
		query = `SELECT * FROM kaname.authority_group_add_finalize_v3($1::jsonb,100000,4096)`
		args = []any{w.stage.request}
	case "finalize-mismatch":
		query = `SELECT * FROM kaname.authority_group_add_finalize_v3($1::jsonb||'{"member_id":"usr_foreign"}'::jsonb,100000,4096)`
		args = []any{w.stage.request}
	case "private-state-write":
		query = `UPDATE pg_temp.kaname_group_add_command SET member_attempted=true,fold_done=true,subject_done=true`
	case "private-program-write":
		query = `UPDATE pg_temp.kaname_authority_sequence_program SET selected='[]'::jsonb`
	case "private-effects-write":
		query = `UPDATE pg_temp.kaname_authority_sequence_effects SET claimed=true,consumed=true`
	case "private-completion":
		query = `SELECT kaname._authority_group_add_complete_v3()`
	case "public-fold":
		query = `SELECT kaname.authority_group_add_fold_v3('fga.tuple.write',jsonb_build_object('user',$1::text,'relation','member','object',$2::text),now())`
		args = []any{typ + ":" + mid, "group:" + gid}
	case "corrupt-command-nonce", "corrupt-command-empty", "corrupt-command-missing":
		query = `SELECT kaname.test_group_add_corrupt_state_v3($1)`
		args = []any{probe}
	default:
		return fmt.Errorf("неизвестный конечный Add probe %q", probe)
	}
	_, err := w.tx.Exec(ctx, query, args...)
	return err
}
