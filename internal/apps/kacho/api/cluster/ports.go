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
type grantWriter interface {
	Grant(ctx context.Context, txh service.Tx, subject domain.SubjectID, grantedBy string) (domain.ClusterAdminGrant, bool, error)
	Revoke(ctx context.Context, txh service.Tx, subject domain.SubjectID, principalID string) (domain.ClusterAdminGrant, error)
	Reactivate(ctx context.Context, txh service.Tx, subject domain.SubjectID, grantedBy string) (domain.ClusterAdminGrant, error)
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

// userChecker — guard: checks user exists in kacho_iam.users.
// Implemented by *kachopg.UserExistenceChecker.
type userChecker interface {
	ExistsUser(ctx context.Context, userID string) error
}
