// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notification_grant_edge_leg_integration_test.go — рычаг оператора над
// выдачей права на письма ЧЕРЕЗ ВНУТРЕННИЙ КРАЙ (решение владельца 2026-10-08,
// п. 1: `Revoke`/`Restore` зовёт администратор кластера своей личностью через
// внутренний край; новой машинной учётки нет).
//
// # Как проба зовёт рычаг — так, как зовёт край
//
// По проводу: тот же слушатель, что у соседних проб записи выдачи (mTLS, лист
// точного SAN, цепочка `internalUnaryChain` корня в боевом режиме, регистрация
// `registerInternalServices`, настоящий обработчик над своей базой). Край
// пересылает личность и ступень подтверждения метаданными
// (`x-kacho-principal-*`, `x-kacho-token-acr`); слушатель принимает их только
// от отправителя из круга доверенных (`authn.trusted-forwarder-sans`), и право
// `system_admin` на `cluster:cluster_root` судится по пересланному принципалу.
//
// # Исходы и близнецы — каждый меняет ровно один факт против положительного
//
//   - край · человек-администратор кластера · ступень «2» → переход проходит, выдача
//     отозвана (решение о письме — `REVOKED`), затем возвращена;
//   - та же пересылка со ступенью «1» → `PERMISSION_DENIED` с нарушением
//     `authz.step_up` «2», запись выдачи побайтово та же: ступень каталога
//     («2») на внутреннем слушателе не понижается;
//   - тот же вызов с листом модуля (не края) → отказ политики вызывающего:
//     рычаг зовёт только край, пересланную соседом личность слушатель не
//     принимает;
//   - край · человек БЕЗ роли администратора · ступень «2» →
//     `PERMISSION_DENIED` обработчика: право судится по пересланному, а не по
//     учётке края.
//
// Run: `go test ./cmd/kaname/ -run TestNTF1EdgeLeg -count=1` (Docker). Skipped under -short.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// edgeLegCall — вызов рычага по проводу от лица пира san с пересылкой личности
// (тип, идентификатор) и ступени acr. Принятый вызов дочитывается до done.
type edgeLegCall struct {
	san, principalType, principalID, acr string
}

func (w *ntfGrantWorld) edgeLeg(t *testing.T, c edgeLegCall, restore bool, req *iamv1.NotificationGrantRequest) error {
	t.Helper()
	md := metadata.Pairs(
		grpcsrv.MDKeyPrincipalType, c.principalType,
		grpcsrv.MDKeyPrincipalID, c.principalID,
		grpcsrv.MDKeyTokenACR, c.acr,
	)
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 10*time.Second)
	defer cancel()
	client := iamv1.NewInternalNotificationGrantServiceClient(w.lis.dial(t, c.san))
	call := client.Revoke
	if restore {
		call = client.Restore
	}
	op, err := call(ctx, req)
	if err != nil {
		require.Nil(t, op, "отказ с операцией: при синхронном отказе Operation не создаётся")
		return err
	}
	done := ntfAwaitOperation(t, w.db, op.GetId())
	require.Nil(t, done.Error, "переход %v: операция завершилась ошибкой", req)
	return nil
}

// requireStepUp — отказ пола ступени: код, текст и нарушение «нужна ступень 2».
func requireStepUp(t *testing.T, err error) {
	t.Helper()
	st := status.Convert(err)
	require.Equal(t, codes.PermissionDenied, st.Code(), "ступень «1» на рычаге со ступенью «2» пропущена: %v", err)
	require.Equal(t, "permission denied", st.Message())
	var stepUp *errdetails.PreconditionFailure_Violation
	for _, d := range st.Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				if v.GetType() == "authz.step_up" {
					stepUp = v
				}
			}
		}
	}
	require.NotNil(t, stepUp, "отказ без нарушения authz.step_up — это не пол ступени: детали %v", st.Details())
	require.Equal(t, "acr_values:2", stepUp.GetSubject(), "пол требует ступень каталога «2»")
}

// edgeLegHumanAdmin — человек-администратор кластера: факт `system_admin` на
// `cluster:cluster_root` у `user:<id>`. Фикстура сама спрашивает дверь, что он
// администратор, прежде чем проба опереться на это. Строки человека у него нет
// — рубеж положения его не судит (`admission.ID`: не человек по строке людей).
func edgeLegHumanAdmin(t *testing.T, w *ntfGrantWorld) string {
	t.Helper()
	id := ids.NewID(domain.PrefixUser)
	_, err := w.db.fixture.Exec(context.Background(), `
		INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		VALUES ('cluster', 'cluster_root', 'system_admin', $1)`, "user:"+id)
	require.NoError(t, err, "фикстура: факт администратора кластера не посеян")
	requireClusterAdmin(t, w, "user:"+id, true)
	return id
}

func requireClusterAdmin(t *testing.T, w *ntfGrantWorld, subject string, want bool) {
	t.Helper()
	res, err := w.door.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: subject, Relation: "system_admin", Object: "cluster:cluster_root",
	})
	require.NoError(t, err)
	require.Equal(t, want, res.Allowed, "фикстура: дверь о %s — system_admin=%v, ожидалось %v", subject, res.Allowed, want)
}

func TestNTF1EdgeLeg_RevokeAndRestoreByTheForwardedClusterAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	byEdge := edgeLegCall{san: acrTestGatewaySAN, principalType: "user", principalID: edgeLegHumanAdmin(t, w), acr: "2"}

	before, err := w.grantRow(t, "probe")
	require.NoError(t, err)
	requireUntouched := func(why string) {
		t.Helper()
		after, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		require.Equal(t, before, after, "надгробие появилось: %s", why)
	}

	// Ступень «1» — отказ пола до обработчика; запись та же.
	stepOne := byEdge
	stepOne.acr = "1"
	requireStepUp(t, w.edgeLeg(t, stepOne, false, ntfGrantReq("probe")))
	requireUntouched("вызов со ступенью «1»")

	// Лист модуля вместо края — отказ политики вызывающего; запись та же.
	byModule := byEdge
	byModule.san = ntfVPCSAN
	err = w.edgeLeg(t, byModule, false, ntfGrantReq("probe"))
	require.Equal(t, codes.PermissionDenied, status.Code(err), "рычаг позвал модуль мимо края: %v", err)
	requireUntouched("вызов модуля мимо края")

	// Пересланный человек без роли администратора, ступень «2» — пол пройден,
	// отказ обработчика: право судится по пересланному, а не по учётке края.
	notAdmin := byEdge
	notAdmin.principalID = ids.NewID(domain.PrefixUser)
	requireClusterAdmin(t, w, "user:"+notAdmin.principalID, false)
	requireRefusal(t, w.edgeLeg(t, notAdmin, false, ntfGrantReq("probe")), codes.PermissionDenied, "permission denied", "")
	requireUntouched("пересланный не-администратор")
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", time.Now()))

	// Положительный: край · администратор · ступень «2» — отзыв, затем возврат.
	require.NoError(t, w.edgeLeg(t, byEdge, false, ntfGrantReq("probe")), "Revoke администратора через край")
	require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", time.Now()),
		"отзыв через край не дошёл до решения о письме")
	require.NoError(t, w.edgeLeg(t, byEdge, true, ntfGrantReq("probe")), "Restore администратора через край")
	require.False(t, w.cutoff(t, "probe").IsZero(), "возврат через край не поставил отсечку")
}
