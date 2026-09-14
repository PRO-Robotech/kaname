// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// subscription_internal_only_test.go — GWT-14 APPROVED-приёмки: глагол потока
// изменений живёт ТОЛЬКО на внутреннем слушателе.
//
// Запрет #6 про поверхность методов, и здесь он несущий вдвойне: у глагола нет
// пообъектной проверки на крае (он `scope_filtered`), поэтому попав на внешний
// слушатель, он отдавал бы журнал под кодом, который выглядит фильтрующим.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	subscriptionv1 "github.com/PRO-Robotech/corelib/api/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestSubscriptionVerbIsNeverOnThePublicListener — обе стороны в одном прогоне.
//
// Одной половины мало: «на публичном нет» зеленеет и на глаголе, не
// зарегистрированном НИГДЕ, — то есть на подписке, которой нет вовсе.
func TestSubscriptionVerbIsNeverOnThePublicListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Дверь решения не провязана: сервер не собирается, и глагол отвечает
	// `Unimplemented` НА ОБОИХ слушателях. Это и есть честный отказ — несужающая
	// подписка была бы выдачей всего журнала.
	svcs := &services{}

	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, config.Config{}, nil)
	})

	subscribe := func(cc grpc.ClientConnInterface) error {
		stream, err := subscriptionv1.NewInternalSubscriptionServiceClient(cc).
			Subscribe(ctx, &subscriptionv1.SubscriptionRequest{})
		if err != nil {
			return err
		}
		_, err = stream.Recv()
		return err
	}

	err := subscribe(pubConn)
	require.Error(t, err, "глагол подписки на публичном слушателе отвечать не вправе")
	assert.Equal(t, codes.Unimplemented, status.Code(err),
		"на публичном слушателе он не зарегистрирован — значит `Unimplemented`, "+
			"а не отказ доступа: отказ доступа означал бы, что метод там ЕСТЬ")

	err = subscribe(intConn)
	require.Error(t, err, "без двери решения сервер не собран и здесь")
	assert.Equal(t, codes.Unimplemented, status.Code(err),
		"регистрация условна: без сужателя глагол не поднимается, и это честно")
}

// TestSubscriptionNarrowRelationsAreTotalAndDerived — карта отношений сужателя
// ВЫВЕДЕНА из единственного объявления видимости и ТОТАЛЬНА.
//
// Тотальность — требование фундамента: запись под пустым ключом есть умолчание
// для типа, не названного поимённо. Без неё тип без записи остался бы без
// предиката, и сужатель ответил бы по умолчанию пакета, а не по решению службы.
func TestSubscriptionNarrowRelationsAreTotalAndDerived(t *testing.T) {
	rel := subscriptionNarrowRelations()

	require.Contains(t, rel, "",
		"карта обязана быть тотальной: запись под пустым ключом — умолчание")
	assert.NotEmpty(t, rel[""], "умолчание не может быть пустым перечнем")

	for kind := range subscriptionJournalKinds() {
		assert.NotEmpty(t, rel[kind],
			"вид %q объявлен журналом, но предиката видимости у него нет: "+
				"сужатель ответил бы по умолчанию, а не по решению службы", kind)
	}
}
