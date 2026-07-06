// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// maperr.go — единая точка SQLSTATE → service.Err* трансляции
// (within-service refs enforced at DB level).
//
// Тонкая обертка над `wrapPgErr` (pgmaperr.go, эта же adapter-пакет); конкретный
// маппинг 23502/23503/23505/23514/23P01/40001/08000 + constraint_name-aware
// канонический Kachō error-text живет в wrapPgErr. Мапперы держат pgconn в
// adapter-слое — pure sentinel-пакет `internal/errors` остается pgx-free.

// mapErr — repo-side хелпер: завернуть pgconn.PgError в sentinel-семейство.
// kindHint:
//   - "" — generic (берется constraint_name из pgErr)
//   - "Account.Delete" — переключает FK-сообщения projects_account_fk и т.п.
//     в "Account <id> contains projects and cannot be deleted" (обратная сторона FK).
//
// idHint — для канонического Kachō error-текста ("Account with name <X>...", "User <id> not found",
// "Account <id> contains projects..."). Caller знает, что подставить.
func mapErr(err error, kindHint, idHint string) error {
	return wrapPgErr(err, kindHint, idHint)
}
