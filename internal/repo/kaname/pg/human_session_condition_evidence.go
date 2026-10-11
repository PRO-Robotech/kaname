// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// liveSessionOfSQL — запись сессии, годная доводом условия `mfa_fresh`
// (kaname#133, исход (а)): живая на моменте вопроса и принадлежащая названной
// личности. Оба условия — в ОДНОМ операторе: запись, прочитанная отдельно от
// суждения о ней, судилась бы по состоянию, которого уже нет.
//
// Живость — та же, что у `sessionLiveSQL`: не окончена и срок позже момента.
const liveSessionOfSQL = `
	SELECT authenticated_at, presented_methods
	  FROM human_sessions
	 WHERE id = $1 AND user_id = $2 AND ended_at IS NULL AND expires_at > $3`

// LiveSessionOf — запись `id`, если она жива в момент `at` и принадлежит
// личности `person` (порт `service.SessionRecords`). Иначе found=false: чужая,
// оконченная, истёкшая и несуществующая запись неразличимы для вызывающего —
// для условия каждая из них значит «доводов нет».
func (r *HumanSessionRepo) LiveSessionOf(ctx context.Context, id domain.HumanSessionID, person domain.UserID,
	at time.Time) (domain.HumanSession, bool, error) {
	if id == "" || person == "" {
		return domain.HumanSession{}, false, nil
	}
	rec := domain.HumanSession{ID: id, UserID: person}
	err := r.pool.QueryRow(ctx, liveSessionOfSQL, string(id), string(person), at).
		Scan(&rec.AuthenticatedAt, &rec.PresentedMethods)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.HumanSession{}, false, nil
	}
	if err != nil {
		return domain.HumanSession{}, false, mapErr(err, "HumanSession.LiveSessionOf", string(id))
	}
	return rec, true, nil
}
