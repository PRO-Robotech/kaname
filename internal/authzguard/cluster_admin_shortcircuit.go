// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// cluster_admin_shortcircuit.go — RBAC explicit-model 2026 P5 (D-9 / КФ-2).
//
// IsClusterAdmin is the FLAT cluster-admin super-gate shared by EVERY authz
// decision site (authorize_service.Check + InternalIAMService.Check + all
// write-authz gates: requireGrantAuthority / fgaHoldsAdmin). It answers ONE
// question with ONE relation Check:
//
//	cluster:cluster_kacho_root # system_admin @ <subject>
//
// This is a plain super-gate ("is the subject cluster-admin?"), NOT a hierarchical
// `<rel> from cluster` cascade — exactly one tuple = one fact = one audit row. The
// derivation cascade (`system_admin from cluster`) is removed in the contract
// phase, so after contraction this short-circuit is the SOLE carrier of
// cluster-admin authority; applying it additively in the expand phase keeps the
// cascade and the short-circuit in lockstep (no access-loss window).
//
// Fail-closed on every degraded mode: nil checker (unwired gate), anonymous /
// empty principal, or a Check transport error → false (never fail-open).

import "context"

// IsClusterAdmin reports whether the ctx principal holds the flat cluster
// super-admin relation. fail-closed: nil checker / anonymous / empty id / Check
// error → false.
func IsClusterAdmin(ctx context.Context, checker RelationChecker) bool {
	if checker == nil {
		return false
	}
	subject, ok := PrincipalSubject(ctx) // fail-closed: anon / empty / unknown type → ""
	if !ok {
		return false
	}
	return SubjectIsClusterAdmin(ctx, checker, subject)
}

// IsClusterAdminE is IsClusterAdmin with the reason kept: it separates "the
// store answered: not an admin" (false, nil) from "the store could not be asked"
// (false, err).
//
// # Когда обязателен именно он
//
// Всюду, где несработавший супер-гейт МЕНЯЕТ наблюдаемый ответ, а не просто
// «не срабатывает». Списочный путь — главный такой случай: проглоченная
// неполадка отдаёт well-formed `200` с молча суженной страницей, которую
// вызывающий не отличит от отзыва прав. Ровно это и требует godoc
// SubjectIsClusterAdminPlainE ниже; булева обёртка остаётся для мест, где
// обычная пообъектная полоса всё равно отработает и сама сообщит о неполадке.
func IsClusterAdminE(ctx context.Context, checker RelationChecker) (bool, error) {
	if checker == nil {
		return false, nil
	}
	subject, ok := PrincipalSubject(ctx) // fail-closed: anon / empty / unknown type → ""
	if !ok {
		return false, nil
	}
	return SubjectIsClusterAdminPlainE(ctx, checker, subject)
}

// SubjectIsClusterAdmin is the subject-string variant of IsClusterAdmin — used by
// authorize_service.Check, whose request already carries a pre-formatted FGA
// subject ("user:usr_xxx" / "service_account:sva_xxx") rather than a ctx
// principal. fail-closed: nil checker / empty subject / Check error → false.
func SubjectIsClusterAdmin(ctx context.Context, checker RelationChecker, subject string) bool {
	admin, _ := SubjectIsClusterAdminPlainE(ctx, checker, subject)
	return admin
}

// SubjectIsClusterAdminPlainE is SubjectIsClusterAdmin with the reason kept: it
// separates "the store answered: not an admin" (false, nil) from "the store
// could not be asked" (false, err). Gates that turn a non-allow into a 404 need
// that distinction — see AllowsVerb. The bool-only wrappers above stay for the
// decision sites that are ALREADY fail-closed by construction (a super-gate that
// cannot be evaluated simply does not fire, and the ordinary per-object path
// still runs and still reports its own outage).
//
// # Which of the two E-variants to call
//
// This one and SubjectIsClusterAdminE (subject_question.go) ask the SAME question
// — same relation, same singleton — and differ only in the port they ask it
// through: this one over RelationChecker (plain `Check`), that one over the
// context-carrying `CheckWithContext`. Call the one matching the port the
// use-case already holds; do not wire a second port to reach the other.
//
// A list whose page is a page of the visible must use an E-variant: swallowing
// this failure there produces a well-formed, silently narrowed `200` that the
// caller cannot tell from a revocation (task #645, acceptance §3.6).
func SubjectIsClusterAdminPlainE(ctx context.Context, checker RelationChecker, subject string) (bool, error) {
	if checker == nil || subject == "" {
		return false, nil
	}
	// ClusterObject() rather than the literal: the singleton is named ONCE so two
	// call sites cannot spell it differently (this function used to compose it by
	// hand, beside a sibling that already had the helper).
	allowed, err := checker.Check(ctx, subject, "system_admin", ClusterObject())
	if err != nil {
		return false, err
	}
	return allowed, nil
}
