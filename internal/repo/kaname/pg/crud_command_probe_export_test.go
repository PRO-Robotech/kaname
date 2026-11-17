// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"fmt"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// CRUDCommandProbeForTest доступен только native test binary. Он использует
// реальный factory TX ordinary LOGIN, не создаёт proof и не читает private
// программу. Raw commit сохраняет SQLSTATE deferred guard до mapErr.
func CRUDCommandProbeForTest(ctx context.Context, writer kaname.SemanticAuthorityWriter, probe string) error {
	w, ok := writer.(*preparedCRUDWriter)
	if !ok {
		return fmt.Errorf("expected actual prepared CRUD writer")
	}
	switch probe {
	case "commit":
		w.lifetime.close()
		return w.tx.Commit(ctx)
	case "claim-again":
		_, err := w.tx.Exec(ctx, `SELECT kaname.authority_resource_crud_body_values_v3()`)
		return err
	case "wrong-origin":
		_, err := w.tx.Exec(ctx, `SELECT kaname.authority_resource_crud_journal_value_v3('{"table":"projects","operation":"DELETE","when":"AFTER","old":null,"new":null}'::jsonb,'{}'::jsonb)`)
		return err
	case "unplanned-journal":
		_, err := w.tx.Exec(ctx, `INSERT INTO kaname.resource_journal(resource_kind,resource_id,project_id,scope,event_type,payload)
   VALUES('project','prj_crud_unplanned','prj_crud_unplanned','[]'::jsonb,'CREATED','{"id":"prj_crud_unplanned"}'::jsonb)`)
		return err
	default:
		return fmt.Errorf("unknown finite CRUD probe %q", probe)
	}
}
