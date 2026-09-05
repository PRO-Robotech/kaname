// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_sa_lane_no_silent_drop_test.go — поле запроса, на которое сервис не
// смотрит, не может быть принято молча (api-conventions.md, «Принято-и-
// проигнорировано — ЗАПРЕЩЕНО»: законных исхода три — реализовать, отвергнуть
// явно, снять с контракта; принять и выбросить исходом не является).
//
// Правило против подлога на `created_by_user_id` целиком сидело в ветке
// вызывающего-ЧЕЛОВЕКА. На полосе служебной учётки поле поэтому не читал никто:
// значение приезжало, ответственным записывался целевой пользователь, а
// вызывающий получал успех и был уверен, что его параметр применён. Это хуже
// отказа: отказ виден сразу, а выброшенное поле всплывает месяцами позже в
// чужом разборе — как ответственный, которого никто не назначал.
//
// Полоса-близнец (ключи служебных учёток) отвергала такой вход с самого начала;
// расхождение между полосами не решал никто, и его предмет — этот файл.
//
// Положительные контроли здесь не для полноты: правило, которое только
// отказывает, неотличимо от мёртвой полосы. Посев (вызывающая машина БЕЗ
// `created_by`) обязан продолжать работать, и значение, совпадающее с тем, что
// сервис запишет, — тоже: на этой полосе край его ЗНАЕТ, потому что это
// `user_id` из того же запроса.
package user_tokens

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// saCallerCtx — вызывающая служебная учётка (bootstrap-admin SA).
func saCallerCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva00000000000000009"})
}

// TestHandlerIssue_SAPrincipal_UnrecordableCreatedBy_IsRejectedNotDropped —
// отрицательная половина. Вызывающая машина, назвавшая ответственного, которого
// сервис не запишет, обязана узнать об этом синхронно и с именем поля.
func TestHandlerIssue_SAPrincipal_UnrecordableCreatedBy_IsRejectedNotDropped(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(NewIssueUserTokenUseCase(repo, &stubTx{}, ops), nil, nil)

	_, err := h.Issue(saCallerCtx(), &iamv1.IssueUserTokenRequest{
		UserId: "usr00000000000000001",
		// Ни целевой пользователь, ни сама вызывающая учётка — третье лицо.
		CreatedByUserId: "usr00000000000000099",
	})
	require.Error(t, err,
		"ответственного, которого сервис не запишет, надо отвергнуть, а не принять и выбросить")
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"неисполнимое поле запроса — INVALID_ARGUMENT")
	require.Contains(t, grpcstatus.Convert(err).Message(), "created_by_user_id",
		"отказ обязан назвать поле, иначе вызывающему нечего править")
	// `inserted` — значение, а не указатель: оно никогда не nil, поэтому проверка
	// на nil была бы вакуумной. Пустой идентификатор — тот наблюдаемый, который
	// отличает «ничего не записано» от «что-то записано».
	require.Empty(t, string(repo.inserted.CreatedByUserID),
		"отвергнутый Issue не имеет права ничего записать")
}

// TestHandlerIssue_SAPrincipal_OwnSvaIdAsCreatedBy_IsRejected — та же полоса,
// вход, который прежде уезжал молча и, будь он применён, уронил бы внешний ключ
// `created_by` (идентификатор служебной учётки строкой users(id) не является).
func TestHandlerIssue_SAPrincipal_OwnSvaIdAsCreatedBy_IsRejected(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(NewIssueUserTokenUseCase(repo, &stubTx{}, ops), nil, nil)

	_, err := h.Issue(saCallerCtx(), &iamv1.IssueUserTokenRequest{
		UserId:          "usr00000000000000001",
		CreatedByUserId: "sva00000000000000009",
	})
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
	require.Contains(t, grpcstatus.Convert(err).Message(), "created_by_user_id")
	require.Empty(t, string(repo.inserted.CreatedByUserID))
}

// TestHandlerIssue_SAPrincipal_OmittedCreatedBy_StillSeeds — положительный
// контроль №1. Посев производственной посадки не шлёт `created_by` вовсе, и эта
// полоса обязана остаться открытой, иначе отказ выше неотличим от сломанной
// полосы.
func TestHandlerIssue_SAPrincipal_OmittedCreatedBy_StillSeeds(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(NewIssueUserTokenUseCase(repo, &stubTx{}, ops), nil, nil)

	_, err := h.Issue(saCallerCtx(), &iamv1.IssueUserTokenRequest{
		UserId: "usr00000000000000001",
	})
	require.NoError(t, err, "посев не шлёт created_by и обязан продолжать работать")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000001", string(repo.inserted.CreatedByUserID),
		"ответственным остаётся целевой пользователь")
}

// TestHandlerIssue_SAPrincipal_MatchingCreatedBy_IsHonoured — положительный
// контроль №2 и ОДНО НАЗВАННОЕ ОТЛИЧИЕ от полосы-близнеца.
//
// У ключей служебных учёток ответственный резолвится ВНУТРИ use-case из
// владельца аккаунта целевой учётки — край этого значения не знает, поэтому
// сверить присланное там нечем и любое непустое отвергается. Здесь край
// записываемое значение ЗНАЕТ: это `user_id` того же запроса. Совпавшее
// значение поэтому не выбрасывается, а применяется дословно — и это остаётся
// исходом «реализовать», а не «принять и выбросить».
func TestHandlerIssue_SAPrincipal_MatchingCreatedBy_IsHonoured(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(NewIssueUserTokenUseCase(repo, &stubTx{}, ops), nil, nil)

	_, err := h.Issue(saCallerCtx(), &iamv1.IssueUserTokenRequest{
		UserId:          "usr00000000000000001",
		CreatedByUserId: "usr00000000000000001",
	})
	require.NoError(t, err,
		"значение, совпадающее с записываемым, применяется — отвергать его было бы отказом без предмета")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000001", string(repo.inserted.CreatedByUserID))
}

// TestHandlerIssue_UserPrincipal_OwnCreatedBy_StillAccepted — положительный
// контроль №3, на ДРУГОЙ полосе. Отказ выше намеренно узок: он про вызывающую
// машину. Человек, назвавший собственный принципал, законен, и эта проба
// закрепляет, что новая ветка не расползлась в полосу, о которой она не была.
func TestHandlerIssue_UserPrincipal_OwnCreatedBy_StillAccepted(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(NewIssueUserTokenUseCase(repo, &stubTx{}, ops), nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{
		UserId:          "usr00000000000000001",
		CreatedByUserId: "usr00000000000000007",
	})
	require.NoError(t, err,
		"человек, назвавший свой принципал, не подлог и обязан остаться принятым")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000007", string(repo.inserted.CreatedByUserID))
}
