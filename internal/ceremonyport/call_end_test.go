// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport_test

// call_end_test.go — отказ хранилища без собственной причины на кончившемся
// сроке вызова порта уезжает мосту церемонии концом срока, а не отказом
// сервера (задача PRO-Robotech/kaname#423, столкновение с правилом kaname#383).
// Близнец — тот же отказ на живом вызове остаётся отказом хранилища.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestPortsCarryTheEndOfTheCallOnAStoreFailure(t *testing.T) {
	storeFailure := iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 57014")
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	grants, err := ceremonyport.NewGrants(&recordingFamilies{err: storeFailure})
	require.NoError(t, err)
	secrets, err := ceremonyport.NewClientSecrets(&secretStore{fail: storeFailure},
		stubChecker{outcome: "unused"})
	require.NoError(t, err)

	for _, call := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"отзыв семейства", func(c context.Context) error {
			_, e := grants.RevokeGrantRefreshTokens(c, "tfm-1", oauthceremony.RevocationCodeReplay)
			return e
		}},
		{"сверка секрета клиента", func(c context.Context) error {
			_, e := secrets.VerifyClientSecret(c, "ic-1", oauthceremony.NewPresentedSecret("s"))
			return e
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			err := call.run(expired)
			require.ErrorIs(t, err, context.DeadlineExceeded, "конец срока вызова не в цепочке: %v", err)
			require.ErrorIs(t, err, iamerr.ErrInternal)

			live := call.run(context.Background())
			require.ErrorIs(t, live, iamerr.ErrInternal)
			require.False(t, errors.Is(live, context.DeadlineExceeded), "живому вызову приписан конец срока: %v", live)
		})
	}
}
