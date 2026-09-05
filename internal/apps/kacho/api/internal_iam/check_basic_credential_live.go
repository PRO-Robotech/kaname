// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// CheckBasicCredentialLive — живо ли удостоверение, названное ИДЕНТИФИКАТОРОМ
// (задача #1450).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ВТОРОЙ ВОПРОС РЯДОМ С `ResolveBasicCredential`
//
// Тот отвечает ПРЕДЪЯВИТЕЛЮ и потому требует предъявленной строки. Открытое
// длинное соединение предъявителем не является: секрет оно видело однажды, при
// открытии. Держать его живым весь срок соединения значило бы завести
// поверхность хранения ради контроля — то есть платить за отзыв тем самым, что
// отзыв защищает.
//
// Без этого вопроса граница отзыва базового удостоверения на открытом
// соединении равна СРОКУ ЖИЗНИ СОЕДИНЕНИЯ: контроль стоит на выдаче и не стоит
// на предъявлении, а такое состояние само не сходится — сходиться нечему.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОТВЕТ — ОТКАЗ, А НЕ ПОЛЕ
//
// Живое даёт `OK` с ПУСТЫМ ответом. Поле-признак означало бы, что вызывающий
// вправе его не прочитать, и тогда контроль присутствует, провязан и не
// отказывает ни разу. Тот же довод записан у `ResolveBasicCredentialResponse`, и
// второго решения об одном предмете здесь не заводится.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ ИСХОДА, А НЕ ДВА
//
//	OK             — живо;
//	UNAUTHENTICATED — не живо, ЕДИНЫМ отказом полосы;
//	UNAVAILABLE    — состояние установить не удалось.
//
// Третий не сливается со вторым: спрашивающий с открытого соединения на
// «не удалось» обязан держать соединение и переспросить по своему сроку, а на
// «не живо» — закрыть. Слив их, мы закрывали бы соединения арендаторов каждый
// раз, когда моргнула наша база.
func (h *Handler) CheckBasicCredentialLive(
	ctx context.Context, req *iamv1.CheckBasicCredentialLiveRequest,
) (*iamv1.CheckBasicCredentialLiveResponse, error) {
	if h.basicCredentials == nil {
		// Непровязанный контроль не есть «живо»: fail-closed по тому же
		// разделителю, что у резолва.
		return nil, status.Error(codes.Unavailable, credentialStateUnknownText)
	}

	id := req.GetCredentialId()
	if id == "" {
		// Пустое отвергается тем же единым отказом: «поле не заполнено» и
		// «удостоверение не действует» различимы только тем, что первое
		// подсказывает форму, — а подсказывать нечему.
		return nil, status.Error(codes.Unauthenticated, refusalText)
	}
	if _, err := credsecret.Parse(id); err == nil {
		// Сюда прислали ПРЕДЪЯВЛЕННУЮ СТРОКУ целиком. Поле идентификатора не
		// помечено носителем секрета — и это утверждение о ЗНАЧЕНИИ, а не о
		// форме: приняв такую строку молча, глагол сделал бы его ложным, и
		// секрет поехал бы дальше в поле, которое никто не обязан беречь.
		//
		// Отказ — ТОТ ЖЕ единый, и значение НЕ логируется: различимый исход
		// здесь сообщал бы предъявителю, что его строка разобралась.
		if h.logger != nil {
			h.logger.WarnContext(ctx, "basic credential liveness asked with a presented string "+
				"instead of an identifier; the value is not logged")
		}
		return nil, status.Error(codes.Unauthenticated, refusalText)
	}

	switch err := h.basicCredentials.CheckBasicLive(ctx, id); {
	case err == nil:
		return &iamv1.CheckBasicCredentialLiveResponse{}, nil
	case errors.Is(err, domain.ErrBasicCredentialRefused):
		return nil, status.Error(codes.Unauthenticated, refusalText)
	default:
		// Сырой текст драйвера наружу не течёт: он ЛОГИРУЕТСЯ, а на провод
		// уходит фиксированный.
		if h.logger != nil {
			h.logger.ErrorContext(ctx, "basic credential liveness could not be established",
				slog.Any("error", err))
		}
		return nil, status.Error(codes.Unavailable, credentialStateUnknownText)
	}
}

// credentialStateUnknownText — ЕДИНСТВЕННЫЙ текст исхода «состояние не
// установлено». Объявлен одним местом по той же причине, что и отказ полосы:
// два написания разошлись бы, и по различию узнавали бы, каким путём спрашивали.
// #nosec G101 -- это ТЕКСТ ОТКАЗА, который видит вызывающий, а не удостоверение:
// слово `credential` называет предмет отказа. Значение уходит на провод именно
// затем, чтобы наружу не ушло ничего другого.
const credentialStateUnknownText = "credential state could not be established"
