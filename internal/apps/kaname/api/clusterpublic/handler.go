// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clusterpublic — тонкий транспорт публичного близнеца `ClusterService`
// (приёмка ADM-CA, `docs/engineering/acceptance/cluster-admins-on-the-public-surface.md`,
// решения Р1, Р3, Р8).
//
// Близнец не собирает своих сценариев: он стоит над ТЕМ ЖЕ обработчиком
// внутреннего близнеца (`internal/apps/kaname/api/cluster`), а значит над теми
// же четырьмя экземплярами сценариев применения (Р3). Путь записи у таблицы
// выдач один; вторая копия проверок, второе умолчание рода субъекта или второй
// перевод в провод невозможны по построению — их здесь нет.
//
// Свой пакет, а не второй тип в пакете внутреннего близнеца: гейт списков
// (`tools/auditlistfilter`) судит каждый списочный метод по пакету-ресурсу и
// требует объявления против СВОЕГО контракта. Публичный `ListAdmins` судится
// аннотацией `cluster_service.proto`, внутренний — `internal_cluster_service.proto`;
// второй тип в одном пакете слил бы их в одно объявление.
//
// Регистрация: публичный слушатель и публичный REST-фронт службы; на
// внутренних его нет (Р8).
package clusterpublic

import (
	"context"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
)

// Handler implements iamv1.ClusterServiceServer над обработчиком внутреннего
// близнеца.
type Handler struct {
	iamv1.UnimplementedClusterServiceServer

	core *clusterapp.Handler
}

// NewHandler — публичный близнец над УЖЕ собранным внутренним обработчиком.
// Composition root: cmd/kaname/wiring.go.
func NewHandler(core *clusterapp.Handler) *Handler {
	return &Handler{core: core}
}

// Get — синглтон кластера.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetClusterRequest) (*iamv1.Cluster, error) {
	return h.core.Get(ctx, req)
}

// GrantAdmin — назначение администратора кластера.
func (h *Handler) GrantAdmin(ctx context.Context, req *iamv1.GrantClusterAdminRequest) (*operationpb.Operation, error) {
	return h.core.GrantAdmin(ctx, req)
}

// RevokeAdmin — снятие администратора кластера.
func (h *Handler) RevokeAdmin(ctx context.Context, req *iamv1.RevokeClusterAdminRequest) (*operationpb.Operation, error) {
	return h.core.RevokeAdmin(ctx, req)
}

// ListAdmins — перечень активных администраторов кластера.
func (h *Handler) ListAdmins(ctx context.Context, req *iamv1.ListClusterAdminsRequest) (*iamv1.ListClusterAdminsResponse, error) {
	return h.core.ListAdmins(ctx, req)
}
