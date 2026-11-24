// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const ridKeyResponseGrace = 8 * time.Second

// Ждём результат штатной очистки в PRIMARY. Ключ уже получен через API и
// сохранён в закрытом файле. Проверка не пишет в БД и не печатает ответ.
func (f *installationNativeWorld) awaitIssuedKeyResponseRedaction(t *testing.T, key *installruntime.StandingCreator) {
	t.Helper()
	require.NotEmpty(t, key.KeyOperation.ID)
	typed, err := anypb.New(&iamv1.IssueSAKeyResponse{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var done bool
		var kind string
		var raw []byte
		err := f.given.pool.QueryRow(ctx, `SELECT done,response_type,response_data
 FROM kaname.operations WHERE id=$1 AND NOT pg_is_in_recovery()`, key.KeyOperation.ID).Scan(&done, &kind, &raw)
		require.True(t, err == nil && done && kind == typed.TypeUrl, "нужна та же завершённая операция выдачи на PRIMARY")
		var response iamv1.IssueSAKeyResponse
		err = proto.Unmarshal(raw, &response)
		require.True(t, err == nil && response.GetClientId() == key.ClientID && response.GetKeyId() == key.KeyID && response.GetAlgorithm() == "ES256",
			"после выдачи сохраняются реквизиты того же ключа")
		if response.GetPrivateKeyPem() == "" && response.GetClientSecret() == "" && response.GetSecret() == "" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("штатная очистка ответа выданного ключа не подтверждена до начала сценария")
		case <-ticker.C:
		}
	}
}
