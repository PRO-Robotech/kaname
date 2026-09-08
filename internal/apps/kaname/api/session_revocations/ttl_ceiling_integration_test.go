// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations_test

// ttl_ceiling_integration_test.go — срок строки отзыва ОГРАНИЧЕН СВЕРХУ и не
// подставляется молча (приёмка `retention-sweep-has-a-caller.md` §2.5,
// сценарии RET-SWP-21 и RET-SWP-22).
//
// # Почему это часть работы об уборке
//
// Уборка НЕ ограничивает рост, пока срок строки называет вызывающий и потолка у
// него нет: строка с далёким горизонтом не удовлетворяет порогу
// `ttl_expires_at <= now()` НИКОГДА и переживает всякий проход при любом выборе
// интервала. Без потолка утверждение «рост ограничен» ложно, то есть предмет
// задачи не закрыт.
//
// # И зеркальный класс: момент в ПРОШЛОМ принимался молча
//
// Условие `t.After(now)` было ложно — присланное значение ВЫБРАСЫВАЛОСЬ,
// подставлялось умолчание, вызывающий получал успех и был уверен, что его
// величина применена. Особенность в том, что проверка на этот случай УЖЕ
// существовала и была недостижима: `domain.SessionRevocation.Validate`
// отвергает `ttl_expires_at <= revoked_at` каноничным текстом — но до неё
// присланное значение уже заменялось.
//
// # Тип изменения назван честно
//
// Это ЛОМАЮЩЕЕ изменение контракта на поверхности Internal: вызывающий,
// сегодня присылающий момент в прошлом или далеко в будущем, получает
// `INVALID_ARGUMENT` там, где получал успех. Вызывающий в дереве ОДИН — выход с
// края, — и он присылает ровно умолчание, но ЧАСАМИ КРАЯ; поэтому потолок несёт
// слагаемое `ClockSkew`, и положительная половина RET-SWP-21 стоит именно за
// этим: без запаса потолок отверг бы выход всякий раз, когда часы края идут
// вперёд хоть на миллисекунду, и отверг бы его ТИХО — край логирует отказ
// предупреждением, отвечает 200 и кладёт текст в поле, у которого во всём
// дереве один писатель и ни одного читателя.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	sessionrev "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestRevoke_TTLCeiling — RET-SWP-21.
func TestRevoke_TTLCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	h, pool := newRevokeHandler(t)
	ctx := principalCtx()
	uid := seedRevokeUser(t, ctx, pool)

	t.Run("умолчание единственного вызывающего дерева ПРОХОДИТ и применяется", func(t *testing.T) {
		// Ровно то, что присылает выход с края: `now() + defaultRevocationTTL`,
		// но часами КРАЯ. Слагаемое запаса в потолке существует ради этого
		// запроса — без него он отвергался бы при малейшем расхождении часов.
		jti := "ttl-ok-" + ids.NewID(domain.PrefixUser)
		want := time.Now().UTC().Add(sessionrev.DefaultRevocationTTL)
		_, err := h.Revoke(ctx, &iamv1.RevokeRequest{
			UserId:       string(uid),
			TokenJti:     jti,
			TtlExpiresAt: timestamppb.New(want),
		})
		require.NoError(t, err, "запрос выхода с края обязан проходить")

		// Утверждается ПРИМЕНЁННАЯ величина, а не только код: по успеху не
		// видно, что значение выброшено.
		var got time.Time
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT ttl_expires_at FROM kaname.session_revocations WHERE token_jti = $1`, jti).Scan(&got))
		require.WithinDuration(t, want, got, time.Second,
			"присланная величина не применена — подставлено умолчание")
	})

	t.Run("часы вызывающего, ушедшие вперёд в пределах запаса, ПРОХОДЯТ", func(t *testing.T) {
		jti := "ttl-skew-" + ids.NewID(domain.PrefixUser)
		want := time.Now().UTC().Add(sessionrev.DefaultRevocationTTL + tokenpolicy.ClockSkew/2)
		_, err := h.Revoke(ctx, &iamv1.RevokeRequest{
			UserId: string(uid), TokenJti: jti, TtlExpiresAt: timestamppb.New(want),
		})
		require.NoError(t, err,
			"потолок без слагаемого ClockSkew отверг бы выход всякий раз, когда часы края идут вперёд")
	})

	t.Run("срок сверх потолка ОТВЕРГАЕТСЯ с именем поля", func(t *testing.T) {
		jti := "ttl-over-" + ids.NewID(domain.PrefixUser)
		_, err := h.Revoke(ctx, &iamv1.RevokeRequest{
			UserId:   string(uid),
			TokenJti: jti,
			// Далёкий горизонт: такая строка не удовлетворяет порогу уборки
			// НИКОГДА и переживает всякий проход.
			TtlExpiresAt: timestamppb.New(time.Now().UTC().Add(10 * 365 * 24 * time.Hour)),
		})
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		require.Contains(t, status.Convert(err).Message(), "ttl_expires_at",
			"отказ обязан называть поле, иначе вызывающему нечего чинить")

		// Строки не появилось: отказ синхронный, до записи.
		var n int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.session_revocations WHERE token_jti = $1`, jti).Scan(&n))
		require.EqualValues(t, 0, n, "отвергнутый запрос оставил строку")
	})
}

// TestRevoke_TTLInThePastIsRefusedNotSubstituted — RET-SWP-22.
//
// Утверждается ответ И применённая величина: сегодня вызывающий получает успех,
// и по ответу не видно, что его значение выброшено. Утверждать надо то, что
// различает эти два состояния.
func TestRevoke_TTLInThePastIsRefusedNotSubstituted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	h, pool := newRevokeHandler(t)
	ctx := principalCtx()
	uid := seedRevokeUser(t, ctx, pool)

	jti := "ttl-past-" + ids.NewID(domain.PrefixUser)
	_, err := h.Revoke(ctx, &iamv1.RevokeRequest{
		UserId:       string(uid),
		TokenJti:     jti,
		TtlExpiresAt: timestamppb.New(time.Now().UTC().Add(-time.Hour)),
	})
	require.Error(t, err, "момент в прошлом принят молча: подставлено умолчание, вызывающий уверен, что его величина применена")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "ttl_expires_at")

	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.session_revocations WHERE token_jti = $1`, jti).Scan(&n))
	require.EqualValues(t, 0, n,
		"строка появилась: значит присланный момент был выброшен и заменён умолчанием")
}
