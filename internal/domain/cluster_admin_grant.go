// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"regexp"
	"time"

	"go.uber.org/multierr"
)

// ClusterAdminGrant — permanent root grant. Один источник истины для
// FGA-tuple `cluster_admin`.
//
// Partial UNIQUE (subject_type, subject_id) WHERE granted_until IS NULL
// гарантирует на DB-уровне, что **permanent** grant у одного subject — один.
// Temporary grants не входят в модель — есть только permanent.
type ClusterAdminGrant struct {
	ID           ClusterAdminGrantID
	ClusterID    ClusterID
	SubjectType  GrantSubjectType
	SubjectID    SubjectID
	GrantedBy    string // 'bootstrap' либо user_id (verbatim text)
	GrantedAt    time.Time
	GrantedUntil *time.Time // NULL = permanent
}

// IsActive — true если grant — permanent active (`granted_until IS NULL`).
// False — для revoked / expired / time-bombed grants (granted_until set).
// Используется handler'ом и use-case'ами для diagnostic-веток.
func (g ClusterAdminGrant) IsActive() bool { return g.GrantedUntil == nil }

func (g ClusterAdminGrant) Validate() error {
	var errs error
	errs = multierr.Append(errs, g.ID.Validate())
	errs = multierr.Append(errs, g.ClusterID.Validate())
	errs = multierr.Append(errs, g.SubjectType.Validate())
	if g.SubjectID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument subject_id: required"))
	}
	if g.GrantedBy == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument granted_by: required"))
	}
	if len(g.GrantedBy) > 64 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument granted_by: length must be <=64"))
	}
	return errs
}

// ClusterAdminGrantID — self-validating newtype, format `cag_<17-crockford>`.
type ClusterAdminGrantID string

var cagIDRe = regexp.MustCompile(`^cag_[0-9a-hjkmnp-tv-z]{17}$`)

func (id ClusterAdminGrantID) Validate() error {
	if !cagIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument id: must match ^cag_[0-9a-hjkmnp-tv-z]{17}$")
	}
	return nil
}

// GrantSubjectType — enum: user|service_account (NOT group: cluster-admin grant —
// strictly individual identity for audit). Backed by migration 0011 CHECK.
type GrantSubjectType string

const (
	GrantSubjectTypeUser           GrantSubjectType = "user"
	GrantSubjectTypeServiceAccount GrantSubjectType = "service_account"
)

func (t GrantSubjectType) Validate() error {
	switch t {
	case GrantSubjectTypeUser, GrantSubjectTypeServiceAccount:
		return nil
	default:
		return fmt.Errorf("Illegal argument subject_type %q (allowed: user|service_account)", string(t))
	}
}
