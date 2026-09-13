// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

// usecase_unavailable_cause_logged_test.go — у подробности отказа
// недоступности есть ЧИТАТЕЛЬ на полосе хранилища (задача #2507).
//
// Близнец пробы того же имени в `sa_keys`, и это НЕ дубль: переводчики у двух
// доменов свои (различаются текстом INTERNAL, который есть часть контракта),
// поэтому свойство у каждого своё и проверяется у каждого. Расхождение двух
// переводчиков между собой — ровно тот класс, из-за которого эта задача и
// заведена.
//
// `refusal_text_never_carries_the_cause_test.go` рядом зовёт переводчик
// НАПРЯМУЮ и про читателя не говорит ничего; здесь полоса исполняется через
// use-case, то есть утверждается, что глагол ЗОВУТ, а не что он существует.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// utStoreOutageCause — подробность, которую вызывающему знать не положено.
const utStoreOutageCause = "dial tcp 10.42.7.3:5432: connect: connection refused"

func TestIssue_StoreUnavailable_CauseReachesTheLogAndNotTheCaller(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	repo := &stubUserClientRepo{
		accountErr: iamerr.Wrapf(iamerr.ErrUnavailable, "account lookup: %s", utStoreOutageCause),
	}
	u := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubOpsRepo{}).WithLogger(logger)

	_, err := u.Execute(context.Background(), IssueInput{
		UserID:          domain.UserID("usr_owner00000000000"),
		CreatedByUserID: "usr_owner00000000000",
	})

	require.Error(t, err, "неотвеченное хранилище обязано прервать выдачу")
	st := status.Convert(err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"признак недоступности обязан доехать кодом: на 500 клиент не повторяет")
	require.Equal(t, shared.UnavailableMessage, st.Message(),
		"текст на проводе обязан остаться ФИКСИРОВАННЫМ: цепочка ведёт к драйверу "+
			"и может нести адрес узла, имя базы и учётную запись")

	require.Contains(t, buf.String(), utStoreOutageCause,
		"подробность обязана иметь ЧИТАТЕЛЯ: без записи в журнале отказ на подъёме "+
			"разбирают без единой строки о причине")
}

// Законный близнец: отказ, АДРЕСОВАННЫЙ вызывающему, в журнал не дублируется.
func TestIssue_AddressedRefusal_IsNotRepeatedIntoTheLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const addressed = "User usr_owner00000000000 not found"
	repo := &stubUserClientRepo{accountErr: iamerr.Wrapf(iamerr.ErrNotFound, "%s", addressed)}
	u := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubOpsRepo{}).WithLogger(logger)

	_, err := u.Execute(context.Background(), IssueInput{
		UserID:          domain.UserID("usr_owner00000000000"),
		CreatedByUserID: "usr_owner00000000000",
	})

	require.Error(t, err)
	st := status.Convert(err)
	require.Equal(t, codes.NotFound, st.Code(), "полоса отсутствия не меняется")
	require.Equal(t, addressed, st.Message(),
		"отказ, адресованный вызывающему, называет причину САМ и доезжает дословно")
	require.NotContains(t, buf.String(), addressed,
		"адресованный отказ в журнал не дублируется: строка на каждое обычное "+
			"обращение арендатора топит ту единственную, ради которой журнал читают")
}

// Контроль предпосылки: подробность действительно ЕСТЬ в цепочке.
func TestIssue_StoreOutageChain_ActuallyCarriesTheCause(t *testing.T) {
	chain := iamerr.Wrapf(iamerr.ErrUnavailable, "account lookup: %s", utStoreOutageCause)
	require.True(t, errors.Is(chain, iamerr.ErrUnavailable))
	require.Contains(t, chain.Error(), utStoreOutageCause,
		"предпосылка пробы: подробность лежит в цепочке — иначе читать нечего")
}
