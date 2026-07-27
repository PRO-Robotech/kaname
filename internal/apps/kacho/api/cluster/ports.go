// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// ports.go — narrow port-interfaces for InternalClusterService use-cases.
//
// Clean Architecture: use-cases depend on these interfaces; concrete adapters
// live in internal/repo/kacho/pg and are wired via cmd/kacho-iam/wiring.go.
// No pgx / grpc imports here.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

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

// userChecker — guard: checks the grant subject exists in this DB.
// Implemented by *kachopg.UserExistenceChecker.
//
// cluster_admin_grants.subject_id is polymorphic, so the guard is per-type:
// ExistsUser reads kacho_iam.users, ExistsServiceAccount reads
// kacho_iam.service_accounts. (No FK is possible for a polymorphic column —
// PostgreSQL has no conditional FK — so this stays a request-path check.)
type userChecker interface {
	ExistsUser(ctx context.Context, userID string) error
	ExistsServiceAccount(ctx context.Context, svaID string) error
}
