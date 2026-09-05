// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_cutoff.go — InternalSessionRevocationsService.SessionCutoffOf.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Отсечка субъекта (`user_token_revocations.revoke_before`) — то, что пишет наш
// выход и административный принудительный выход. До этого RPC её читали ТОЛЬКО
// хуки выдачи, то есть отзыв действовал на выдаче и не действовал на
// предъявлении браузерной сессии: человек, которого администратор вывел, работал
// в консоли дальше.
//
// Рядом стоит `IsRevoked`, и он про ДРУГОЕ. Тот спрашивает про одно
// удостоверение по его идентификатору; у браузерной сессии удостоверения нет
// вовсе — ни `jti`, ни подписи, которую край мог бы прочитать. Спросить про неё
// можно только по паре (субъект, момент аутентификации), и эта пара — ровно то,
// чем оперирует отсечка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОТВЕТ НЕСЁТ `found` ОТДЕЛЬНЫМ ПОЛЕМ
//
// «Отсечки нет» и «отсечка на нулевой отметке» — разные утверждения, и слитые в
// одно они читаются вызывающим одинаково. Читатель, принявший нулевой момент за
// «отозвано всё», закрылся бы на каждом человеке, которого никто не отзывал;
// принявший его за «отзыва нет» — пропустил бы отозванного. Пустое обязано
// означать пусто, поэтому его несёт своё поле.
package session_revocations

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
)

// cutoffReader — узкий порт чтения отсечки субъекта.
//
// ОТДЕЛЬНЫЙ от `reader` намеренно: тот читает `session_revocations` (строка на
// удостоверение), этот — `user_token_revocations` (строка на человека). Две
// таблицы, два репозитория, и объединение портов заставило бы каждого
// реализующего знать обе.
//
// Реализуется `*pg.UserTokenRevocationRepo` — ТЕМ ЖЕ читателем, которым
// пользуются хуки выдачи. Один читатель на один предмет: два ответа об одной
// отсечке разошлись бы молча, и разошлись бы именно там, где расхождение
// означает «выведен по одной полосе и работает по другой».
type cutoffReader interface {
	RevokedBefore(ctx context.Context, userID string) (time.Time, bool, error)
}

// WithCutoffReader — провязывает читателя отсечки. Composition-root only.
//
// nil оставляет `SessionCutoffOf` fail-closed (`Unavailable`): ответ «отсечки
// нет» от непровязанного читателя неотличим для края от настоящего «человека не
// отзывали», то есть непровязка молча снимала бы контроль.
func (h *Handler) WithCutoffReader(r cutoffReader) *Handler {
	h.cutoffs = r
	return h
}

// SessionCutoffOf — момент, раньше которого сессии человека недействительны.
//
// Полоса прямого чтения своей БД: well-formed идентификатор без строки — это НЕ
// `NOT_FOUND`, а законный ответ «отсечки нет». Отсутствие отзыва — обычное
// состояние человека, а не отсутствие ресурса, и отвечать на него тоном промаха
// значило бы утверждать, что человека не существует.
func (h *Handler) SessionCutoffOf(
	ctx context.Context, req *iamv1.SessionCutoffOfRequest,
) (*iamv1.SessionCutoffOfResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	if h.cutoffs == nil {
		return nil, status.Error(codes.Unavailable, "session revocation reader not configured")
	}
	before, found, err := h.cutoffs.RevokedBefore(ctx, userID)
	if err != nil {
		// Фиксированный текст: сюда приходит ошибка хранилища, и её текст несёт
		// координаты соединения. Причина уходит в журнал вызывающего репозитория,
		// наружу — только то, что спросить не удалось.
		return nil, status.Error(codes.Internal, "session revocation lookup failed")
	}
	resp := &iamv1.SessionCutoffOfResponse{Found: found}
	if found {
		resp.RevokeBefore = shared.TimestampProto(before)
	}
	return resp, nil
}
