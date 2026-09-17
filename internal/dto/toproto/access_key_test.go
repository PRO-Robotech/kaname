// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestAccessKeyToPb_PublicProjectionOnly — ОДНА проекция ключа на все дороги
// (перечень, ответ операции, резолвер осиротевших): наружу выходят
// идентификатор, человек, имя, описание и две отметки, усечённые до секунды;
// идентификатор удостоверения, открытый ключ, счётчик и рукоятка — нет (Ф7 Р10).
func TestAccessKeyToPb_PublicProjectionOnly(t *testing.T) {
	created := time.Date(2026, 9, 17, 10, 0, 0, 123456000, time.UTC)
	used := created.Add(time.Hour)
	k := domain.AccessKey{
		ID: "ak-0000000000000key1", UserID: "usr00000000000000001",
		CredentialID: []byte("cred"), PublicKey: []byte("pub"), Algorithm: -7, SignCount: 9, UserHandle: []byte("h"),
		Name: "laptop", Description: "рабочий", CreatedAt: created, LastUsedAt: &used,
	}
	var pb *iamv1.AccessKey
	require.NoError(t, dto.Transfer(dto.FromTo(k, &pb)))
	require.Equal(t, "ak-0000000000000key1", pb.GetId())
	require.Equal(t, "usr00000000000000001", pb.GetUserId())
	require.Equal(t, "laptop", pb.GetName())
	require.Equal(t, "рабочий", pb.GetDescription())
	require.Equal(t, created.Truncate(time.Second), pb.GetCreatedAt().AsTime())
	require.Equal(t, used.Truncate(time.Second), pb.GetLastUsedAt().AsTime())

	k.LastUsedAt = nil
	require.NoError(t, dto.Transfer(dto.FromTo(k, &pb)))
	require.Nil(t, pb.GetLastUsedAt(), "ключ без предъявлений — отметки нет, а не эпоха")
}
