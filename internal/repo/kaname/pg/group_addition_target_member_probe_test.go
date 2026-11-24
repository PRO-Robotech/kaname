// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"fmt"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Конечный TEST-only probe использует actual TX prepared writer обычного LOGIN.
// Он не принимает произвольный SQL, owner connection, подпись или private state.
// Строка уже создана исходным reconciler; INSERT сохраняет её точный образ.
func GroupAdditionTargetMemberProbeForTest(ctx context.Context, writer kaname.SemanticAuthorityWriter, operation, bindingID, objectID string) error {
	w, ok := writer.(*preparedGroupAdditionWriter)
	if !ok || w.stage == nil {
		return fmt.Errorf("ожидался фактический prepared Add writer")
	}
	var query string
	switch operation {
	case "INSERT":
		query = `INSERT INTO kaname.access_binding_target_members SELECT m.* FROM kaname.access_binding_target_members m WHERE binding_id=$1 AND object_id=$2`
	case "UPDATE":
		query = `UPDATE kaname.access_binding_target_members SET verification_status=verification_status WHERE binding_id=$1 AND object_id=$2`
	case "DELETE":
		query = `DELETE FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_id=$2`
	default:
		return fmt.Errorf("неизвестный конечный target-member probe %q", operation)
	}
	_, err := w.tx.Exec(ctx, query, bindingID, objectID)
	return err
}
