// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identityquota — арендаторское чтение квот, носителем которых является
// личность.
//
// Сегодня такой вид ровно один — число аккаунтов, — и он единственный, чей
// носитель не проект и не аккаунт: аккаунт есть корень аренды, и потолок над ним
// обязан лежать на том, что существует ДО него.
package identityquota

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quotav1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/quota/quotapb"
	"github.com/PRO-Robotech/kacho/pkg/quota/quotaread"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Reader — то, что нужно чтению от хранилища.
//
// Порт объявлен ЗДЕСЬ, у вызывающего: use-case не импортирует pgx и не знает про
// схему. Два глагола, и они разные по существу — «кто спрашивает» и «что ему
// причитается»; свести их в один значило бы позволить вызывающему назвать чужую
// личность параметром.
type Reader interface {
	// IdentityOfUser — внешний идентификатор входа по строке пользователя.
	IdentityOfUser(ctx context.Context, userID domain.UserID) (string, error)
	// States — квоты личности полным набором, никогда пустым.
	States(ctx context.Context, identity string) ([]quotaread.State, error)
}

// Handler — реализация quotav1.IdentityQuotaServiceServer.
//
// ТОЛЬКО ЧТЕНИЕ, и это граница прав, а не объём работы: величину назначает
// администратор облака через `InternalLimitService` на внутреннем слушателе.
// Арендатор, способный поднять свой потолок, потолка не имеет.
type Handler struct {
	quotav1.UnimplementedIdentityQuotaServiceServer

	reader Reader
}

// NewHandler собирает обработчик поверх чтения.
func NewHandler(reader Reader) *Handler { return &Handler{reader: reader} }

// List отдаёт квоты ВЫЗЫВАЮЩЕГО — предел, потребление и источник величины.
//
// Личность берётся из проверенного принципала и ниоткуда больше. Поля запроса,
// которым её можно было бы назвать, не существует: вопрос о чужом потреблении
// здесь невыразим, а это сильнее проверки, которая обязана срабатывать каждый раз.
func (h *Handler) List(
	ctx context.Context, _ *quotav1.ListIdentityQuotasRequest,
) (*quotav1.ListIdentityQuotasResponse, error) {
	// Анонимный вызывающий личности не имеет, и отвечать ему нечем. Отказ стоит
	// ПЕРВЫМ стейтментом: без него пустой принципал уехал бы в чтение и вернулся
	// бы пустым набором — то есть утверждением «у вас нет пределов», которого
	// платформа не делает.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if h == nil || h.reader == nil {
		return nil, status.Error(codes.Internal, "identity quota reader is not wired")
	}

	identity, err := h.identityOfAuthenticatedCaller(ctx)
	if err != nil {
		return nil, err
	}
	states, err := h.reader.States(ctx, identity)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Перевод — ОБЩИЙ (`pkg/quota/quotapb`). Он несёт решение, а не механику:
	// неопознанная область отображается в `SCOPE_UNSPECIFIED`, а не в `DEFAULT`.
	return &quotav1.ListIdentityQuotasResponse{Quotas: quotapb.Quotas(states)}, nil
}

// identityOfAuthenticatedCaller — личность ВЫЗЫВАЮЩЕГО, и ничья больше.
//
// Шаг назван и вынесен не ради читаемости: он и есть доказательство сужения,
// которое читает страж списочных методов (`services/iam/tools/auditlistfilter`,
// форма `SubjectScoped`). Сужение здесь держится ПОДПИСЬЮ — на входе только
// `ctx`, — поэтому назвать чужую личность нечем, и расширить это, не тронув
// подписи, которую страж и читает, нельзя.
//
// Проверяется РОД принципала, а не только непустота его идентификатора.
// `authzguard.PrincipalUserID` — accessor АУДИТНЫЙ: его godoc прямо перечисляет
// «user / service-account / system», потому что он отвечает на вопрос «кто
// совершил действие», а не «кто является личностью». Машинной учётке он отдаёт
// `sva…`, и проверка на пустоту её пропускает — строка пользователя с таким
// идентификатором не найдётся, и вызывающий получил бы `NotFound` про
// несуществующего человека вместо ответа по существу.
//
// Тот же самый accessor уже использовался для вывода ВЛАДЕЛЬЦА аккаунта и там
// стоил принятого запроса, предвыделенного идентификатора и отказа на фиксации.
// Здесь он стоил бы меньше — и всё же неверного ответа.
func (h *Handler) identityOfAuthenticatedCaller(ctx context.Context) (string, error) {
	principal := operations.PrincipalFromContext(ctx)
	if principal.Type != "user" {
		// Машинная учётка личностью не является: аккаунтом владеет человек, и
		// счёт ведётся по тому, кто способен войти. Отказ называет предмет, а не
		// отдаёт пустой набор.
		return "", status.Error(codes.FailedPrecondition,
			"quotas of an identity are readable by a user principal only")
	}
	userID := authzguard.PrincipalUserID(ctx)
	if userID == "" {
		return "", status.Error(codes.FailedPrecondition,
			"quotas of an identity are readable by a user principal only")
	}

	identity, err := h.reader.IdentityOfUser(ctx, domain.UserID(userID))
	if err != nil {
		return "", shared.MapRepoErr(err)
	}
	return identity, nil
}

// Гарантия соответствия контракту на этапе сборки.
var _ quotav1.IdentityQuotaServiceServer = (*Handler)(nil)
