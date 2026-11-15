// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"fmt"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Probe не получает owner connection, не читает private store и не создаёт
// подпись. Предмет — обычная фабрика и её фактический SQL transaction.
func MetadataSequenceProbeForTest(ctx context.Context, writer kaname.SemanticAuthorityWriter, probe string) error {
	w, ok := writer.(*metadataWriteTx)
	if !ok {
		return fmt.Errorf("expected actual metadata writer")
	}
	switch probe {
	case "private-program-write":
		_, err := w.tx.Exec(ctx, `UPDATE pg_temp.kaname_authority_sequence_program SET frozen_mode='authorize'`)
		return err
	case "private-effects-write":
		_, err := w.tx.Exec(ctx, `UPDATE pg_temp.kaname_authority_sequence_effects SET consumed=true`)
		return err
	case "commit":
		return w.tx.Commit(ctx)
	case "wrong-origin":
		_, err := w.tx.Exec(ctx, `SELECT kaname.authority_prepared_journal_value_v3(
   '{"table":"projects","operation":"UPDATE","when":"AFTER","old":null,"new":null}'::jsonb,'{}'::jsonb)`)
		return err
	case "foreign-id":
		_, err := w.tx.Exec(ctx, `INSERT INTO kaname.resource_journal(sequence_no,resource_kind,resource_id,project_id,scope,event_type,payload)
   VALUES(9223372036854775806,'project','prj_sequence_foreign','prj_sequence_foreign','[]'::jsonb,'UPDATED','{"id":"prj_sequence_foreign"}'::jsonb)`)
		return err
	case "unplanned-fga":
		_, err := w.tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at) VALUES('fga.tuple.write','{"object":"project:prj_sequence_foreign","user":"user:usr_sequence_foreign","relations":["viewer"]}'::jsonb,now())`)
		return err
	default:
		return fmt.Errorf("unknown finite sequence probe %q", probe)
	}
}

// Только test-файл: конечный owner fault injector создаётся самим native-тестом.
// Ни публичный production API, ни подписывание/расширение manifest не добавляются.
func MetadataSequenceCorruptForTest(ctx context.Context, writer kaname.SemanticAuthorityWriter, mode string) error {
	w, ok := writer.(*metadataWriteTx)
	if !ok {
		return fmt.Errorf("expected actual metadata writer")
	}
	switch mode {
	case "header-nonce", "header-backend", "header-xid", "header-invoker", "pair-oid", "effects-nonce", "digest-only", "duplicate-exact", "unselected", "consumed":
		_, err := w.tx.Exec(ctx, `SELECT kaname.test_sequence_effect_corrupt_v3($1)`, mode)
		return err
	default:
		return fmt.Errorf("unknown finite sequence corruption %q", mode)
	}
}
