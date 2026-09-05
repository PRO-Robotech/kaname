// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// grant_authority_outage_test.go — «хранилище прав не ответило» ≠ «не положено»
// на путях выдачи и на списочном пути видимого (#665, повторная развёртка).
//
// # Предмет
//
// `fgaHoldsScopeAdmin` заканчивалась `return err == nil && allowed`: у обоих
// ответов хранилища исход был один — `false`. Это Path 2 `requireGrantAuthority`,
// а его питают шесть списочных путей. Наблюдаемое следствие разное на разных
// полосах, и обе проверяются здесь:
//
//   - путь ВЫДАЧИ отдавал `PERMISSION_DENIED` — вызывающий читает «повтор
//     бессмыслен», а дренаж очередей травит строку навсегда;
//   - СПИСОЧНЫЙ путь отдавал well-formed `200` с молча суженной страницей,
//     неотличимой от настоящего отзыва прав.
//
// # Почему утверждается КОД, а не факт вызова
//
// Проба вида «страж позвал хранилище» остаётся зелёной на дефекте: он звал.
// Различие целиком в том, ЧТО вызывающий получает, поэтому утверждается ответ.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// outageStore — хранилище прав, которое НЕ ОТВЕЧАЕТ. Отличается от отказа
// ровно тем, чем отличается предмет: `(false, err)` против `(false, nil)`.
type outageStore struct{ calls int }

func (o *outageStore) Check(context.Context, string, string, string) (bool, error) {
	o.calls++
	return false, errors.New("relation store unreachable")
}

var _ clients.RelationStore = (*outageStore)(nil)

// denyStore — хранилище, которое ОТВЕТИЛО «нет». Положительный контроль: без
// него «недоступность» зеленела бы и на полосе, отвечающей недоступностью на
// всякий отрицательный ответ, — то есть отказ в правах перестал бы существовать.
type denyStore struct{ calls int }

func (d *denyStore) Check(context.Context, string, string, string) (bool, error) {
	d.calls++
	return false, nil
}

var _ clients.RelationStore = (*denyStore)(nil)

// principalCtx — контекст с опознанным вызывающим: без него стражи выходят
// раньше вопроса, и проба судила бы вырожденный путь.
func principalCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr_probe"})
}

// TestScopeAdminOutageIsNotADenial — сам предикат: три исхода, а не два.
func TestScopeAdminOutageIsNotADenial(t *testing.T) {
	t.Run("хранилище не ответило", func(t *testing.T) {
		store := &outageStore{}
		held, err := fgaHoldsScopeAdminE(principalCtx(), store, "account", "acc-1")
		require.Error(t, err, "неполадка обязана доехать до вызывающего")
		require.False(t, held)
		require.Equal(t, 1, store.calls, "вопрос обязан быть задан — иначе проба судит вырожденный путь")
	})

	t.Run("хранилище ответило нет", func(t *testing.T) {
		store := &denyStore{}
		held, err := fgaHoldsScopeAdminE(principalCtx(), store, "account", "acc-1")
		require.NoError(t, err, "отказ в правах ошибкой не является")
		require.False(t, held)
		require.Equal(t, 1, store.calls)
	})
}

// TestGrantAuthorityOutageIsUnavailableNotDenied — полоса ВЫДАЧИ: код ответа
// разный у двух отказов.
func TestGrantAuthorityOutageIsUnavailableNotDenied(t *testing.T) {
	t.Run("хранилище не ответило", func(t *testing.T) {
		err := requireGrantAuthority(principalCtx(), nil, &outageStore{}, "cluster", "cluster_kacho_root")
		require.Error(t, err)
		require.Equal(t, codes.Unavailable, grpcstatus.Code(err),
			"«спросить не удалось» обязано быть отличимо от «не положено»: дренаж очередей "+
				"классифицирует отказ в правах как ТЕРМИНАЛЬНЫЙ и травит строку навсегда")
	})

	t.Run("хранилище ответило нет", func(t *testing.T) {
		err := requireGrantAuthority(principalCtx(), nil, &denyStore{}, "cluster", "cluster_kacho_root")
		require.Error(t, err)
		require.Equal(t, codes.PermissionDenied, grpcstatus.Code(err),
			"отказ в правах остаётся отказом — иначе недоступность поглотила бы его")
	})
}

// TestVisiblePageOutageIsNotAnEmptyPage — СПИСОЧНАЯ полоса: неполадка не
// превращается в тихо суженную страницу.
//
// Это то самое, о чём предупреждает godoc `SubjectIsClusterAdminPlainE`
// дословно: «A list whose page is a page of the visible must use an E-variant:
// swallowing this failure there produces a well-formed, silently narrowed 200
// that the caller cannot tell from a revocation».
func TestVisiblePageOutageIsNotAnEmptyPage(t *testing.T) {
	t.Run("хранилище не ответило", func(t *testing.T) {
		held, err := fgaHoldsAdminE(principalCtx(), &outageStore{}, "account", "acc-1")
		require.Error(t, err, "иначе страница строится по «нет» и выглядит отзывом прав")
		require.False(t, held)
	})

	t.Run("хранилище ответило нет", func(t *testing.T) {
		held, err := fgaHoldsAdminE(principalCtx(), &denyStore{}, "account", "acc-1")
		require.NoError(t, err)
		require.False(t, held)
	})
}
