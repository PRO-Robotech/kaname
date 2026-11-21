// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// EmitSubjectChangeEventForTest вызывает только настоящий emitter на переданной
// PG TX. Адаптер существует лишь в test binary: он не открывает authority writer,
// не создаёт proof и не меняет SQL guards или границы транзакции.
func EmitSubjectChangeEventForTest(ctx context.Context, tx pgx.Tx, event access_binding.SubjectChangeEvent) error {
	w := &abWriter{abReader: abReader{tx: tx}}
	return w.EmitSubjectChangeEvent(ctx, event)
}
