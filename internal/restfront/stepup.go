// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// stepup.go — указание повысить уровень на публичном REST-фронте (решение Р11
// приёмки уровня уверенности, сценарий Ф11-49; PRO-Robotech/kaname#511).
//
// # Предмет
//
// Публичный слушатель отвечает на недостаток уровня указанием:
// `UNAUTHENTICATED` с текстом, называющим шаг, и вызовом RFC 9470 в хвосте
// ответа. Статус параметров вызова не несёт, а умолчание библиотеки поставило
// бы в `WWW-Authenticate` ТЕКСТ отказа, после чего обёртка подсказки заменила
// бы его голым `Bearer` — и клиент не узнал бы, какой уровень нужен.
//
// # Почему тело пишется здесь, а не кодировщиком
//
// Р11 требует тела, побайтово равного телу края (Ф11-51):
// `{"code":16,"message":"<текст>","details":[]}`. Кодировщик библиотеки ставит
// пробелы после запятых по решению, выведенному из хэша двоичного файла, —
// побайтовое равенство с краем держалось бы по совпадению сборки. Указание —
// один фиксированный ответ, и пишется оно тем же литералом, что у края.
//
// # Что НЕ меняется
//
// Всё, что не указание, уходит умолчанию библиотеки дословно: множество
// статусов и тела прежние. Признак указания — ДВА факта сразу: код с текстом
// Р11 и вызов в хвосте ответа собственного слушателя; одного недостаточно.

// stepUpBody — тело указания, побайтово тело края (KA1-15, Р11).
var stepUpBody = []byte(`{"code":16,"message":"` + iamerr.TextStepUpRequired + `","details":[]}`)

// stepUpErrorHandler — обработчик ошибок вызова обоих фронтов. Указание
// рендерится только там, где обёртка подсказки завела место для вызова
// (публичный фронт); внутренний фронт места не заводит и отвечает умолчанием.
func stepUpErrorHandler(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler,
	w http.ResponseWriter, r *http.Request, err error,
) {
	slot, public := stepUpSlotFrom(ctx)
	challenge, indication := stepUpChallengeOf(ctx, err)
	if !public || !indication {
		runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, r, err)
		return
	}
	slot.challenge = challenge
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(stepUpBody)
}

// stepUpChallengeOf — вызов указания, если ошибка — указание слушателя.
func stepUpChallengeOf(ctx context.Context, err error) (string, bool) {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated || st.Message() != iamerr.TextStepUpRequired {
		return "", false
	}
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.TrailerMD.Get(iamerr.StepUpChallengeTrailer)
	if len(vals) != 1 || vals[0] == "" {
		return "", false
	}
	return vals[0], true
}
