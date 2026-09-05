// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// subject_question.go — THE question about the caller, asked once per list
// request, with its failure kept (task #645, acceptance §3.6).
//
// # Why the existing form does not serve a list
//
// IsClusterAdmin / SubjectIsClusterAdmin fold a transport failure into `false`,
// and at their decision sites that is right: a super-gate that cannot be
// evaluated simply does not fire, and the ordinary per-object path runs behind
// it and reports its own outage.
//
// A list that SELECTS its candidates narrowed has no such path behind it. The
// answer to this question decides how wide the candidate set is, so swallowing
// its failure produces a perfectly well-formed, perfectly wrong `200` with fewer
// rows — an answer the caller cannot tell from "you were granted less than you
// think". That is the failure mode C6 of the acceptance forbids, and it is the
// quieter of the two: an outage that refuses is visible, an outage that narrows
// is not.
//
// # Why the port is the context-carrying Check
//
// A list use-case holds clients.RelationQueries — the batched, context-carrying
// door — and not clients.RelationStore. Declaring the narrow port here (rather
// than importing the client) keeps this package a leaf, the same discipline as
// RelationChecker and authzfilter.ObjectChecker.

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// ContextRelationChecker — narrow port: ONE relation question, carrying a
// condition context. Satisfied by clients.RelationQueries.
type ContextRelationChecker interface {
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (allowed bool, err error)
}

// SubjectIsClusterAdminE answers "is this caller a cluster administrator" and
// keeps the reason.
//
// (false, nil) is an ANSWER — the store said no. (false, err) means the question
// was not answered, and the caller must refuse (UNAVAILABLE) rather than narrow.
//
// A nil checker or an unresolvable subject yields (false, nil): those are not
// outages, they are callers this gate does not apply to, and the list decides
// what to do about them before it gets here.
func SubjectIsClusterAdminE(ctx context.Context, chk ContextRelationChecker, subject string) (bool, error) {
	if chk == nil || subject == "" {
		return false, nil
	}
	return chk.CheckWithContext(ctx, subject, "system_admin", ClusterObject(), nil)
}

// ClusterObject — the singleton every cluster-tier tuple hangs off. Named once
// so a caller composing the question by hand cannot spell it differently.
func ClusterObject() string { return "cluster:" + domain.ClusterSingletonID }
