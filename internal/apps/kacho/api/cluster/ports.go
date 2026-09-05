// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

// ports.go — narrow port-interfaces for InternalClusterService use-cases.
//
// Clean Architecture: use-cases depend on these interfaces; concrete adapters
// live in internal/repo/kacho/pg and are wired via cmd/kacho-iam/wiring.go.
// No pgx / grpc imports here.

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// operationRepo — Operation-порт cluster-мутаций. Шире operations.Repo ровно на
// MetadataFinalizer, и это не удобство, а требование контракта:
// `{Grant,Revoke}ClusterAdminMetadata.cluster_admin_grant_id` обязано назвать
// строку cluster_admin_grants, чей id известен ТОЛЬКО после мутации (на
// идемпотентном повторе это вообще id уже существующей строки), тогда как саму
// op-строку обязано создавать ДО мутации. `MarkDone` третьим параметром берёт
// RESPONSE и metadata не трогает — то есть заполнить обещанное поле ею нельзя.
//
// Порт объявлен здесь, а не подменён type-assert'ом в рантайме, чтобы
// composition root не мог собраться с репозиторием, который эту запись не
// умеет: operations.NewRepo возвращает FullRepo, и несоответствие поймает
// компилятор.
type operationRepo interface {
	operations.Repo
	operations.MetadataFinalizer
}

// clusterReader — port for reading the singleton cluster row.
// Implemented by *kachopg.ClusterReader.
type clusterReader interface {
	Get(ctx context.Context) (domain.Cluster, error)
}

// grantWriter — port for the atomic CAS-based Grant/Revoke/Reactivate
// operations on cluster_admin_grants.
// Implemented by *kachopg.ClusterAdminGrantWriter.
//
// Every method carries the subject TYPE alongside the id. cluster_admin_grants
// is polymorphic (`subject_type ∈ {user, service_account}`) and the platform
// seeds a machine grant in migration 0058; a writer that assumes `user` matches
// no row for a machine subject, so the revoke would report success and take
// nothing away.
type grantWriter interface {
	Grant(ctx context.Context, txh service.Tx, subjectType domain.GrantSubjectType, subject domain.SubjectID, grantedBy string) (domain.ClusterAdminGrant, bool, error)
	Revoke(ctx context.Context, txh service.Tx, subjectType domain.GrantSubjectType, subject domain.SubjectID, principalID string) (domain.ClusterAdminGrant, error)
	Reactivate(ctx context.Context, txh service.Tx, subjectType domain.GrantSubjectType, subject domain.SubjectID, grantedBy string) (domain.ClusterAdminGrant, error)
}

// grantReader — port for read-only access to cluster_admin_grants.
// Implemented by *kachopg.ClusterAdminGrantReader.
type grantReader interface {
	ListActive(ctx context.Context) ([]domain.ClusterAdminEntry, error)
}

// relationOutboxEmitter — port for emitting relation tuple rows into
// fga_outbox within a TX. Implemented by *kachopg.FGAOutboxEmitter.
type relationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
}

// auditEmitter — port for emitting one durable audit_outbox compliance row
// inside the grant/revoke writer-tx. Atomic with the
// cluster_admin_grants mutation + fga_outbox row (запрет #10). Implemented by
// *kachopg.AuditOutboxEmitter. nil → emit is skipped (degraded/legacy wiring);
// the mutation contract is unchanged either way (purely-additive audit).
type auditEmitter interface {
	EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error
}

// subjectStateReader — состояние субъекта, которому выдают право. Реализуется
// *kachopg.SubjectStateReader.
//
// Порт отдаёт СОСТОЯНИЕ, а не «нашлось / не нашлось»: решение о выдаче права
// принимает use-case, и принимать его по факту наличия строки нельзя —
// заблокированный пользователь и отключённая служебная учётка существуют оба.
// Прежняя форма (`ExistsUser(...) error`) сделать этого не позволяла by
// construction: сквозь неё не проходило ничего, кроме факта наличия.
//
// cluster_admin_grants.subject_id полиморфен, поэтому чтение — по типу:
// UserInviteStatus читает kacho_iam.users, ServiceAccountEnabled —
// kacho_iam.service_accounts. (Условного FK на полиморфную колонку в PostgreSQL
// нет, поэтому проверка остаётся на request-path.)
type subjectStateReader interface {
	UserInviteStatus(ctx context.Context, userID string) (domain.InviteStatus, error)
	ServiceAccountEnabled(ctx context.Context, svaID string) (bool, error)
}
