// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// cluster_admin_outage_lane_test.go — ListAllOperations: «хранилище прав не
// ответило» на вопрос надзора обязано прервать выдачу отказом о недоступности,
// а не сообщить аудитору, что ему не положено (задача #1045).
//
// Неполадка наводится ТОЛЬКО на вопрос надзора: следующий вопрос (`admin` на
// аккаунте) свой исход уже разводит, и полная недоступность зеленила бы пробу на
// починке соседа. Рядом — положительный контроль: доступное хранилище,
// ответившее «нет», по-прежнему даёт отказ в правах.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// acctSuperGateOutageStub — не отвечает ровно на `system_admin @ cluster:<синглтон>`.
type acctSuperGateOutageStub struct {
	clients.RelationStore
	superGateCalls int
}

func (s *acctSuperGateOutageStub) Check(_ context.Context, _, relation, object string) (bool, error) {
	if relation == "system_admin" && object == "cluster:"+domain.ClusterSingletonID {
		s.superGateCalls++
		return false, errors.New("relation store unreachable")
	}
	return false, nil
}

// TestListAllOperations_SuperGateOutage_IsUnavailableNotDenied — неполадка
// обязана дать UNAVAILABLE и НЕ отдать страницу.
func TestListAllOperations_SuperGateOutage_IsUnavailableNotDenied(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc0000000000000acct", "usr-owner")
	fga := &acctSuperGateOutageStub{}
	ops := &acctAllOpsRepo{}

	uc := NewListAllOperationsUseCase(repo, ops).WithRelationStore(fga, nil)
	got, next, err := uc.Execute(ctxUser("usr-auditor"), "acc0000000000000acct", 50, "")

	if err == nil {
		t.Fatal("неотвеченный вопрос надзора не прервал выдачу: отказа нет вовсе")
	}
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("код ответа %s, ожидался Unavailable: «спросить не удалось» сообщено аудитору "+
			"как «не положено», и повтор выглядит бессмысленным (ошибка: %v)", code, err)
	}
	if got != nil || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q", len(got), next)
	}
	if fga.superGateCalls == 0 {
		t.Fatal("вопрос надзора не задан вовсе — проба утверждала бы о пути, который не исполнялся")
	}
}

// TestListAllOperations_StoreDenies_StaysPermissionDenied — положительный
// контроль: доступное хранилище, ответившее «нет», по-прежнему отказ в правах.
func TestListAllOperations_StoreDenies_StaysPermissionDenied(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc0000000000000acct", "usr-owner")
	fga := &acctAdminCheckStub{allow: map[string]bool{}} // доступно, не даёт ничего
	ops := &acctAllOpsRepo{}

	uc := NewListAllOperationsUseCase(repo, ops).WithRelationStore(fga, nil)
	_, _, err := uc.Execute(ctxUser("usr-auditor"), "acc0000000000000acct", 50, "")

	if err == nil {
		t.Fatal("посторонний получил выдачу: отказа нет")
	}
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Fatalf("код ответа %s, ожидался PermissionDenied (ошибка: %v)", code, err)
	}
}
