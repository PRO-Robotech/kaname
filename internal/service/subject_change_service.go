// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_service.go — read-side of subject_change_outbox.
// Exposes the outbox by ascending-id cursor for api-gateway authz-cache
// invalidation. Read-only; no mutation.
package service

import "context"

// SubjectChange — a row of kacho_iam.subject_change_outbox, plain Go (no proto).
type SubjectChange struct {
	ID        int64
	SubjectID string
	Op        string
}

// SubjectChangeReader — port: read side of subject_change_outbox.
type SubjectChangeReader interface {
	// PollSubjectChanges returns rows with id > sinceID ordered ascending,
	// at most limit rows, plus headID = current MAX(id) (0 when empty).
	PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) (changes []SubjectChange, headID int64, err error)
}

// SubjectChangeService — read-only use-case that drains subject_change_outbox
// by ascending-id cursor. Used by InternalIAMService.PollSubjectChanges.
type SubjectChangeService struct{ reader SubjectChangeReader }

// NewSubjectChangeService constructs a SubjectChangeService backed by the
// given SubjectChangeReader port.
func NewSubjectChangeService(reader SubjectChangeReader) *SubjectChangeService {
	return &SubjectChangeService{reader: reader}
}

// PollSubjectChanges returns up to `limit` rows from subject_change_outbox
// where id > sinceID, ordered ascending. limit is clamped to [1, 1000];
// zero or negative defaults to 256. Also returns headID = MAX(id) in the
// table (0 when empty) so a freshly started caller can seed its cursor
// without replaying history.
func (s *SubjectChangeService) PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) ([]SubjectChange, int64, error) {
	if limit <= 0 {
		limit = 256
	}
	if limit > 1000 {
		limit = 1000
	}
	return s.reader.PollSubjectChanges(ctx, sinceID, limit)
}
