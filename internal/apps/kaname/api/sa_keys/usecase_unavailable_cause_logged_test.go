// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// usecase_unavailable_cause_logged_test.go — у подробности отказа
// недоступности есть ЧИТАТЕЛЬ на полосе хранилища (задача #2507).
//
// # Что здесь другое против соседних проб
//
// `refusal_text_never_carries_the_cause_test.go` зовёт переводчик НАПРЯМУЮ:
// он утверждает, что подробность не уезжает вызывающему, и про читателя не
// говорит ничего. `usecase_hydra_unavailable_test.go` обе половины утверждает,
// но на полосе ПИРА — там свой производитель записи, поэтому на этот предмет
// он зелен by construction.
//
// Здесь полоса ХРАНИЛИЩА: отказ приходит от репозитория, переводит его
// `mapPGErr`, и до этой задачи читателя у подробности на ней не было — она
// оставалась в цепочке, а цепочку никто не читал.
//
// # Обе половины в ОДНОМ утверждении
//
// Порознь каждая половина зеленеет на неверной реализации: «текст фиксирован»
// проходит и тогда, когда подробность потеряна целиком, а «причина в журнале»
// проходит и тогда, когда та же причина уехала вызывающему. Утверждать надо
// разделение, а не каждую сторону по отдельности.

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
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// saStoreOutageCause — подробность, которую вызывающему знать не положено:
// цепочка ведёт к драйверу и несёт адрес узла, имя базы и учётную запись.
const saStoreOutageCause = "dial tcp 10.42.7.3:5432: connect: connection refused"

func TestIssue_StoreUnavailable_CauseReachesTheLogAndNotTheCaller(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	repo := &stubSAClientRepo{
		accountErr: iamerr.Wrapf(iamerr.ErrUnavailable, "account lookup: %s", saStoreOutageCause),
	}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, &stubOpsRepo{})
	u.WithLogger(logger)

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_test000000000000",
		CreatedByUserID:  "usr_admin00000000000",
	})

	require.Error(t, err, "неотвеченное хранилище обязано прервать выдачу")
	st := status.Convert(err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"признак недоступности обязан доехать кодом: на 500 клиент не повторяет")
	require.Equal(t, shared.UnavailableMessage, st.Message(),
		"текст на проводе обязан остаться ФИКСИРОВАННЫМ: цепочка ведёт к драйверу "+
			"и может нести адрес узла, имя базы и учётную запись")

	require.Contains(t, buf.String(), saStoreOutageCause,
		"подробность обязана иметь ЧИТАТЕЛЯ: без записи в журнале отказ на подъёме "+
			"разбирают без единой строки о причине — соседний файл обещает «деталь "+
			"остаётся в цепочке для журнала», и обещание держится только если цепочку "+
			"кто-то читает")
}

// Законный близнец: отказ, АДРЕСОВАННЫЙ вызывающему, в журнал не пишется.
//
// Без него «причина в журнале» зеленело бы на реализации, пишущей строку на
// каждое обычное обращение арендатора, — и та единственная запись, ради которой
// журнал читают, утонула бы среди них. Заметность, введённая таким способом,
// уничтожается тем же средством, которым вводится.
func TestIssue_AddressedRefusal_IsNotRepeatedIntoTheLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const addressed = "ServiceAccount sva_test000000000000 not found"
	repo := &stubSAClientRepo{accountErr: iamerr.Wrapf(iamerr.ErrNotFound, "%s", addressed)}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, &stubOpsRepo{})
	u.WithLogger(logger)

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_test000000000000",
		CreatedByUserID:  "usr_admin00000000000",
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

// Контроль предпосылки: подробность недоступности действительно ЕСТЬ в цепочке.
// Без него проба выше могла бы зеленеть оттого, что писать было нечего.
func TestIssue_StoreOutageChain_ActuallyCarriesTheCause(t *testing.T) {
	chain := iamerr.Wrapf(iamerr.ErrUnavailable, "account lookup: %s", saStoreOutageCause)
	require.True(t, errors.Is(chain, iamerr.ErrUnavailable))
	require.Contains(t, chain.Error(), saStoreOutageCause,
		"предпосылка пробы: подробность лежит в цепочке — иначе читать нечего")
}
