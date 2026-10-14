// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// roster_findings_test.go — находки Н1 и Н2 приёмки ADM-CA
// (`docs/engineering/acceptance/cluster-admins-on-the-public-surface.md` §8).
//
// Обе живут на ОБЩЕМ пути, который исполняют оба близнеца — внутренний и
// публичный (Р3): транспорт перечня и строка аудита мутаций. Поэтому пробы
// судят общий путь, а не одного из близнецов.
//
//   - Н1: перечень читает `display_name` субъекта, а транспорт не переносил его в
//     `subject_display_name` — поле было пустым всегда. Проба подаёт НЕПУСТОЕ
//     имя: на пустом обе стороны равенства пусты и проба зелена без правки.
//   - Н2: строка аудита назначения и снятия писала `subject_type = "user"` для
//     любого рода субъекта, в том числе для служебной учётки.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// fixedRosterReader — перечень из заданных строк.
type fixedRosterReader struct{ entries []domain.ClusterAdminEntry }

func (f fixedRosterReader) ListActive(context.Context) ([]domain.ClusterAdminEntry, error) {
	return f.entries, nil
}

// recordingAudit — запоминает строки аудита, отданные в транзакцию записи.
type recordingAudit struct{ events []service.AuditEvent }

func (r *recordingAudit) EmitTx(_ context.Context, _ service.Tx, ev service.AuditEvent) error {
	r.events = append(r.events, ev)
	return nil
}

// TestClusterAdmins_H1_ListAdminsCarriesSubjectDisplayName — Н1.
func TestClusterAdmins_H1_ListAdminsCarriesSubjectDisplayName(t *testing.T) {
	const name = "CAP target h1"
	reader := fixedRosterReader{entries: []domain.ClusterAdminEntry{{
		ClusterAdminGrantID: "cag_0000000000000000a",
		SubjectType:         string(domain.GrantSubjectTypeUser),
		SubjectID:           validUserB,
		SubjectEmail:        "target@example.com",
		SubjectDisplayName:  name,
		GrantedByUserID:     validUserA,
		GrantedAt:           time.Unix(1_700_000_000, 0).UTC(),
	}}}
	h := clusterapp.NewHandler(nil, nil, nil, clusterapp.NewListAdminsUseCase(reader))

	resp, err := h.ListAdmins(context.Background(), &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetAdmins(), 1)
	got := resp.GetAdmins()[0].GetSubjectDisplayName()
	require.NotEmpty(t, got, "subject_display_name is read from the store and must reach the wire")
	require.Equal(t, name, got)
}

// TestClusterAudit_H2_GrantNamesTheMachineSubjectType — Н2, назначение.
func TestClusterAudit_H2_GrantNamesTheMachineSubjectType(t *testing.T) {
	audit := &recordingAudit{}
	uc := clusterapp.NewGrantAdminUseCase(&recordingGrantWriter{}, nil, &recordingRelationEmitter{},
		&fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(&fakeAdminChecker{allow: true}).
		WithSubjectStateReader(&fakeSubjectState{saEnabled: true}).
		WithAuditEmitter(audit)

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, validServiceAccount)
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, "service_account", audit.events[0].Payload["subject_type"],
		"the audit row must name the machine subject as a service account, not a user")
}

// TestClusterAudit_H2_RevokeNamesTheMachineSubjectType — Н2, снятие.
func TestClusterAudit_H2_RevokeNamesTheMachineSubjectType(t *testing.T) {
	audit := &recordingAudit{}
	uc := clusterapp.NewRevokeAdminUseCase(&recordingGrantWriter{}, &recordingRelationEmitter{},
		&fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(&fakeAdminChecker{allow: true}).
		WithAuditEmitter(audit)

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, validServiceAccount)
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, "service_account", audit.events[0].Payload["subject_type"])
}

// TestClusterAudit_H2_UserSubjectStaysUser — положительный близнец Н2: человек
// по-прежнему называется человеком.
func TestClusterAudit_H2_UserSubjectStaysUser(t *testing.T) {
	audit := &recordingAudit{}
	uc := clusterapp.NewGrantAdminUseCase(&recordingGrantWriter{}, nil, &recordingRelationEmitter{},
		&fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(&fakeAdminChecker{allow: true}).
		WithSubjectStateReader(&fakeSubjectState{userStatus: domain.InviteStatusActive}).
		WithAuditEmitter(audit)

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, "user", audit.events[0].Payload["subject_type"])
}
