// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/service"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// handler_consistency_test.go — переброс поля `CheckRequest.consistency` с провода в
// `CheckRelationRequest.HigherConsistency`, и РОВНО это.
//
// Что здесь утверждается: транспортный переход. Заданное на проводе значение доезжает
// до запроса решателя, незаданное — не подменяется сильным чтением.
//
// Чего здесь НЕ утверждается, и это надо знать читателю: что дальше с этим полем
// что-нибудь происходит. Прежде его читала необязательная способность решателя,
// вынуждавшая движок к сильному чтению мимо кэша и реплики. Способность снята вместе с
// движком, и на сегодняшнем дереве `CheckRelation` поле НЕ ЧИТАЕТ — то есть значение
// принимается и не меняет поведения. Это дефект контракта, а не свойство, и он заведён
// отдельно; проба оставлена честной по своему предмету, чтобы переход не сломали молча
// заодно.

func TestInternalIAM_Check_ForwardsHigherConsistency(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{Allowed: true}}
	h := newCheckHandler(authz)

	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId:   "user:usr_owner",
		Relation:    "v_update",
		Object:      "vpc_network:enp_new",
		Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY,
	})
	require.NoError(t, err)
	assert.True(t, authz.gotReq.HigherConsistency,
		"HIGHER_CONSISTENCY on the wire must set CheckRelationRequest.HigherConsistency")
}

func TestInternalIAM_Check_DefaultConsistency_NotForced(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{Allowed: true}}
	h := newCheckHandler(authz)

	// Enforcement gate: consistency unset → default (cache-eligible) read.
	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_reader",
		Relation:  "viewer",
		Object:    "vpc_network:enp_x",
	})
	require.NoError(t, err)
	assert.False(t, authz.gotReq.HigherConsistency,
		"unset consistency must NOT force HIGHER_CONSISTENCY (enforcement gate stays low-latency)")

	// Explicit MINIMIZE_LATENCY behaves identically to unset.
	_, err = h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId:   "user:usr_reader",
		Relation:    "viewer",
		Object:      "vpc_network:enp_x",
		Consistency: iamv1.CheckRequest_MINIMIZE_LATENCY,
	})
	require.NoError(t, err)
	assert.False(t, authz.gotReq.HigherConsistency)
}
