// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hook_pool_adapters.go — pool-scoped adapters для handler/internal port-iface.
//
// Hook handlers (token / refresh) are stateless HTTP endpoints that need
// lightweight pool-scoped writes without the CQRS Writer-TX overhead.
// These adapters wrap the existing AuditOutboxRepo / SessionRevocationRepo
// in single-statement TX (autocommit-style), serving the
// kacho_iam.audit_outbox and kacho_iam.session_revocations tables.
package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Session/force-logout audit_outbox taxonomy. Values satisfy
// audit_outbox_event_type_check (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`),
// including the all_revoked / force_logout underscore segments.
const (
	// sessionAuditEventRevoked — single-jti session revoke (Revoke with token_jti).
	sessionAuditEventRevoked = "iam.session.revoked"
	// SessionAuditEventAllRevoked — Revoke(revoke_all_user_tokens=true).
	SessionAuditEventAllRevoked = "iam.session.all_revoked"
	// SessionAuditEventForceLogout — InternalIAMService.ForceLogout.
	SessionAuditEventForceLogout = "iam.session.force_logout"
)

// AuditEmitterAdapter — pool-scoped wrapper. Каждый Emit открывает мини-TX,
// INSERT audit row, commit. Это не идеально для atomic-coupling с domain
// mutation, но hook handlers — асинхронный side-channel, atomicity не критична
// (loss tolerable; drainer-side dedupe handles duplicates).
type AuditEmitterAdapter struct {
	pool *pgxpool.Pool
	repo *AuditOutboxRepo
	now  func() time.Time
}

// NewAuditEmitterAdapter — constructor.
func NewAuditEmitterAdapter(pool *pgxpool.Pool) *AuditEmitterAdapter {
	return &AuditEmitterAdapter{
		pool: pool,
		repo: NewAuditOutboxRepo(pool),
		now:  time.Now,
	}
}

// Emit append-only пишет audit event.
func (a *AuditEmitterAdapter) Emit(ctx context.Context, eventType string, tenantAccountID string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	entry := domain.AuditOutboxEntry{
		// newAuditEventID yields an `evt_<22-char>` id; the previous
		// NewKac127ID("evt") produced a 17-char body that FAILS the
		// audit_outbox_id_check ({20,30}) → every hook audit Emit was silently
		// rejected (23514) at INSERT. Same generator the grant/revoke + bootstrap
		// audit paths use.
		ID:           domain.AuditEventID(newAuditEventID()),
		EventType:    domain.EventTypeName(eventType),
		EventPayload: payloadJSON,
		Status:       domain.AuditOutboxStatusPending,
		CreatedAt:    a.now(),
	}
	if tenantAccountID != "" {
		aid := domain.AccountID(tenantAccountID)
		entry.TenantAccountID = &aid
	}

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := a.repo.InsertTx(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SessionRevocationsAdapter — pool-scoped wrapper над SessionRevocationRepo +
// UserTokenRevocationRepo. Backs the per-jti revocation path (Revoke / IsRevoked)
// AND the user-level "revoke-all-before" path (RevokeAllUserTokens /
// UserRevokedBefore) — one adapter shared by ForceLogout, the
// InternalSessionRevocationsService Revoke path, and the refresh-hook reader.
type SessionRevocationsAdapter struct {
	pool      *pgxpool.Pool
	repo      *SessionRevocationRepo
	userRepo  *UserTokenRevocationRepo
	auditRepo *AuditOutboxRepo
}

// NewSessionRevocationsAdapter — constructor.
func NewSessionRevocationsAdapter(pool *pgxpool.Pool) *SessionRevocationsAdapter {
	return &SessionRevocationsAdapter{
		pool:      pool,
		repo:      NewSessionRevocationRepo(pool),
		userRepo:  NewUserTokenRevocationRepo(pool),
		auditRepo: NewAuditOutboxRepo(pool),
	}
}

// Revoke append-only INSERT (с поддержкой revoked_by — миграция 0015).
func (s *SessionRevocationsAdapter) Revoke(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error {
	_, err := s.repo.RevokeWithAdmin(ctx, rev, revokedBy)
	return err
}

// RevokeTx — atomic single-jti revocation + durable audit_outbox emit in ONE tx
// (запрет #10). The pool-scoped Revoke path has no caller-tx, so
// to make the iam.session.revoked compliance row commit-together-or-rollback-
// together with the revocation we open one tx here, run the SAME ON CONFLICT
// upsert (revocation behaviour unchanged), insert the audit row, and commit.
//
// The audit payload carries only non-secret identifiers (actor / subject /
// reason / token_jti — the jti is the id of the revoked token, NOT the token).
func (s *SessionRevocationsAdapter) RevokeTx(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if _, err := s.repo.RevokeWithAdminTx(ctx, tx, rev, revokedBy); err != nil {
		return err
	}
	payload := map[string]any{
		"actor":        string(revokedBy),
		"subject_type": "user",
		"subject_id":   string(rev.UserID),
		"reason":       rev.Reason,
		"token_jti":    rev.TokenJTI,
	}
	if err := s.emitAuditTx(ctx, tx, sessionAuditEventRevoked, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RevokeAllUserTokens — записать per-user revoke-all cutoff (monotonic upsert).
// Это шлюз, который refresh-hook реально энфорсит против session auth_time;
// используется admin ForceLogout и Revoke(revoke_all_user_tokens=true).
func (s *SessionRevocationsAdapter) RevokeAllUserTokens(ctx context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID) error {
	return s.userRepo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID:       userID,
		RevokeBefore: revokeBefore,
		Reason:       reason,
		RevokedBy:    revokedBy,
	}, revokedBy)
}

// RevokeAllUserTokensTx — atomic per-user revoke-all cutoff + durable
// audit_outbox emit in ONE tx (запрет #10). Shared by the
// Revoke(revoke_all_user_tokens=true) path (eventType iam.session.all_revoked)
// and admin ForceLogout (eventType iam.session.force_logout). The cutoff upsert
// is identical to RevokeAllUserTokens (monotonic GREATEST); only the tx
// ownership + audit row differ. eventType MUST be one of the session taxonomy
// values that satisfy the audit_outbox_event_type CHECK.
func (s *SessionRevocationsAdapter) RevokeAllUserTokensTx(
	ctx context.Context,
	userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID,
	eventType string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if err := s.userRepo.UpsertRevokeAllTx(ctx, tx, domain.UserTokenRevocation{
		UserID:       userID,
		RevokeBefore: revokeBefore,
		Reason:       reason,
		RevokedBy:    revokedBy,
	}, revokedBy); err != nil {
		return err
	}
	payload := map[string]any{
		"actor":        string(revokedBy),
		"subject_type": "user",
		"subject_id":   string(userID),
		"reason":       reason,
	}
	if err := s.emitAuditTx(ctx, tx, eventType, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IsRevoked делегирует.
func (s *SessionRevocationsAdapter) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return s.repo.IsRevoked(ctx, jti)
}

// UserRevokedBefore делегирует — per-user revoke-all cutoff lookup для
// refresh-hook user-level gate.
func (s *SessionRevocationsAdapter) UserRevokedBefore(ctx context.Context, userID string) (time.Time, bool, error) {
	return s.userRepo.RevokedBefore(ctx, userID)
}

// GetByJTI делегирует (used by IsRevoked enrichment in the gRPC service).
func (s *SessionRevocationsAdapter) GetByJTI(ctx context.Context, jti string) (domain.SessionRevocation, error) {
	return s.repo.GetByJTI(ctx, jti)
}

// ListByUser делегирует (admin/audit enumeration via the gRPC service).
func (s *SessionRevocationsAdapter) ListByUser(ctx context.Context, userID string, limit int32) ([]domain.SessionRevocation, error) {
	return s.repo.ListByUser(ctx, userID, limit)
}

// emitAuditTx — INSERT one audit_outbox row on the supplied tx.
// id = newAuditEventID() (evt_<22-char> regression-guard, NOT the
// 17-char NewKac127ID which fails audit_outbox_id_check). status='pending'.
func (s *SessionRevocationsAdapter) emitAuditTx(ctx context.Context, tx pgx.Tx, eventType string, payload map[string]any) error {
	if eventType == "" {
		return fmt.Errorf("emit session audit_outbox: event_type required")
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("emit session audit_outbox: marshal payload: %w", err)
	}
	entry := domain.AuditOutboxEntry{
		ID:           domain.AuditEventID(newAuditEventID()),
		EventType:    domain.EventTypeName(eventType),
		EventPayload: payloadJSON,
		Status:       domain.AuditOutboxStatusPending,
	}
	if _, err := s.auditRepo.InsertTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("emit session audit_outbox %s: %w", eventType, err)
	}
	return nil
}
