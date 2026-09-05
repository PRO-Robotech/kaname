// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// cluster_admin_outage_lane_test.go — надзор администратора облака: «хранилище
// прав не ответило» обязано доехать до вызывающего ОТКАЗОМ О НЕДОСТУПНОСТИ, а не
// стать отказом в правах (задача #1045).
//
// # Почему неполадка наводится ТОЛЬКО на вопрос надзора
//
// Полностью недоступное хранилище роняет и следующий вопрос — про отношение
// `admin` на области, — а у того исход уже разведён. Тогда проба зеленела бы на
// починке соседа и о ЭТОЙ площадке не утверждала бы ничего. Поэтому дублёр
// отказывает ровно на `system_admin @ cluster:<синглтон>` и честно отвечает
// «нет» на всё остальное: наблюдаемая разница принадлежит одному вызову.
//
// # Отрицание — в паре с положительным
//
// Рядом с каждой пробой недоступности стоит проба настоящего отказа: хранилище
// доступно и отвечает «нет». Без неё «отказ в правах не приходит» зеленело бы на
// коде, который не отказывает никому.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

// errSuperGateDown — отказ ТРАНСПОРТА, а не вердикт о правах.
var errSuperGateDown = errors.New("relation store unreachable")

// outageOnSuperGateFGA — хранилище, не отвечающее ровно на вопрос надзора и
// честно отвечающее «нет» на все прочие.
type outageOnSuperGateFGA struct {
	clients.RelationStore
	superGateCalls int
}

func (s *outageOnSuperGateFGA) Check(_ context.Context, _, relation, object string) (bool, error) {
	if relation == "system_admin" && object == "cluster:"+domain.ClusterSingletonID {
		s.superGateCalls++
		return false, errSuperGateDown
	}
	return false, nil
}

// Положительный контроль пользуется уже существующим в пакете `denyingFGA`
// (delete_anti_leak_test.go): хранилище ДОСТУПНО и отвечает «нет» на всё.

// wantCode — единственное, что утверждают пробы ниже: КОД ОТВЕТА. Не факт
// вызова, не текст — код, потому что именно по нему вызывающий решает, осмыслен
// ли повтор.
func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: отказа нет вовсе, ожидался %s", what, want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("%s: код ответа %s, ожидался %s (ошибка: %v)", what, got, want, err)
	}
}

// ── requireGrantAuthority ───────────────────────────────────────────────────

// TestRequireGrantAuthority_SuperGateOutage_IsUnavailable — неполадка на надзоре
// обязана дать UNAVAILABLE. Прежде она давала PERMISSION_DENIED: вызывающий
// читал «не положено» и повтор считал бессмысленным.
func TestRequireGrantAuthority_SuperGateOutage_IsUnavailable(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	fga := &outageOnSuperGateFGA{}

	err := requireGrantAuthority(clusterAdminCtx("usr_caller"), repo, clients.RelationStore(fga), "account", "acc_foreign")

	wantCode(t, err, codes.Unavailable, "requireGrantAuthority при неотвечающем надзоре")
	if fga.superGateCalls == 0 {
		t.Fatal("вопрос надзора не задан вовсе — проба утверждала бы о пути, который не исполнялся")
	}
}

// TestRequireGrantAuthority_StoreDenies_StaysPermissionDenied — положительный
// контроль: доступное хранилище, ответившее «нет», по-прежнему даёт отказ в правах.
func TestRequireGrantAuthority_StoreDenies_StaysPermissionDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})

	err := requireGrantAuthority(clusterAdminCtx("usr_caller"), repo, clients.RelationStore(&denyingFGA{}), "account", "acc_foreign")

	wantCode(t, err, codes.PermissionDenied, "requireGrantAuthority при доступном хранилище, ответившем «нет»")
}

// ── ListSubjectPrivileges: субъект не разрешается ───────────────────────────
//
// Ветвь «идентификатор не принадлежит никому» — единственная, где надзор решает
// в одиночку: домашнего аккаунта у такого субъекта нет, администрировать нечего.

// TestListSubjectPrivileges_SuperGateOutage_IsUnavailableNotDenied — неполадка
// обязана ПРЕРВАТЬ выдачу отказом о недоступности, а не отдать отказ в правах.
func TestListSubjectPrivileges_SuperGateOutage_IsUnavailableNotDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_x", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	fga := &outageOnSuperGateFGA{}
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(fga, nil)

	out, next, err := uc.Execute(clusterAdminCtx("usr_caller"),
		domain.SubjectTypeUser, domain.SubjectID("usr00000000000000404"), repoab.PageFilter{})

	wantCode(t, err, codes.Unavailable, "ListSubjectPrivileges при неотвечающем надзоре")
	if out != nil || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q — страница при неотвеченном вопросе "+
			"неотличима от отзыва прав", len(out), next)
	}
	if fga.superGateCalls == 0 {
		t.Fatal("вопрос надзора не задан вовсе — проба утверждала бы о пути, который не исполнялся")
	}
}

// TestListSubjectPrivileges_StoreDenies_StaysPermissionDenied — положительный
// контроль.
func TestListSubjectPrivileges_StoreDenies_StaysPermissionDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_x", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	_, _, err := uc.Execute(clusterAdminCtx("usr_caller"),
		domain.SubjectTypeUser, domain.SubjectID("usr00000000000000404"), repoab.PageFilter{})

	wantCode(t, err, codes.PermissionDenied, "ListSubjectPrivileges при доступном хранилище, ответившем «нет»")
}
