// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

// helpers.go — shared constants and helpers for cluster use-cases.

import (
	"fmt"
	"regexp"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// subjectIDRe — format validation for user-type subject IDs.
// Matches kacho-iam User ID format: `usr` (3-char prefix, NO underscore) +
// 17-char Crockford base32 body = 20 chars total.
var subjectIDRe = regexp.MustCompile(`^usr[0-9a-hjkmnp-tv-z]{17}$`)

// saSubjectIDRe — format validation for service-account-type subject IDs.
// Same shape with the ServiceAccount prefix (`sva`), which is what migration
// 0058 seeds for the bootstrap-admin ServiceAccount.
var saSubjectIDRe = regexp.MustCompile(`^sva[0-9a-hjkmnp-tv-z]{17}$`)

// resolveSubject validates the (subject_type, subject_id) pair and returns the
// domain subject type + id.
//
// Both USER and SERVICE_ACCOUNT are accepted: the relation model permits
// `cluster:…#system_admin@service_account:<id>` and the platform SEEDS exactly
// such a grant for the bootstrap-admin ServiceAccount (migration 0058).
// Refusing the machine type here made that seeded grant impossible to take back
// through the interface — granted authority that cannot be revoked (security.md
// "Авторизация живёт в МОДЕЛИ": a machine is a first-class principal, not an
// exception, and "exempt from step-up" must mean "protected differently", never
// "unprotected").
//
// The id format is checked PER TYPE — widening the accepted type set must not
// turn the id check into a rubber stamp, so a `usr…` id under SERVICE_ACCOUNT
// (and the mirror) is still InvalidArgument.
func resolveSubject(
	subjectType iamv1.ClusterGrantSubjectType, subjectID string,
) (domain.GrantSubjectType, domain.SubjectID, error) {
	var (
		typ domain.GrantSubjectType
		re  *regexp.Regexp
	)
	switch subjectType {
	case iamv1.ClusterGrantSubjectType_USER:
		typ, re = domain.GrantSubjectTypeUser, subjectIDRe
	case iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT:
		typ, re = domain.GrantSubjectTypeServiceAccount, saSubjectIDRe
	default:
		return "", "", shared.InvalidArg("subject_type",
			"must be 'user' or 'service_account'")
	}
	if subjectID == "" {
		return "", "", shared.InvalidArg("subject_id", "required")
	}
	if !re.MatchString(subjectID) {
		return "", "", shared.InvalidArg("subject_id",
			fmt.Sprintf("must match %s (got %q)", re.String(), subjectID))
	}
	return typ, domain.SubjectID(subjectID), nil
}

// systemAdminTuples — FGA tuple shape for a cluster system_admin grant.
//
// The subject prefix MUST follow the subject type: emitting `user:<sva…>` for a
// machine subject would write (and delete) a tuple that no enforcement path
// ever consults — a grant that grants nothing, or worse, a revoke that reports
// success and takes nothing away. `domain.GrantSubjectType` is exactly the FGA
// object-type token (`user` / `service_account`), so it doubles as the prefix.
func systemAdminTuples(subjectType domain.GrantSubjectType, subjectID string) []service.RelationTuple {
	return []service.RelationTuple{
		{
			User:     string(subjectType) + ":" + subjectID,
			Relation: "system_admin",
			Object:   "cluster:" + domain.ClusterSingletonID,
		},
	}
}
