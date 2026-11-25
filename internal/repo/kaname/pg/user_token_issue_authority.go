// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Описание двух вопросов для RR discovery. Само описание не даёт права записи.
type userTokenIssueAuthority struct {
	bundle *granteffect.Bundle
	actor  domain.Subject
	owner  domain.UserID
}

func prepareUserTokenIssueAuthority(ctx context.Context, bundle *granteffect.Bundle, actor domain.Subject, owner domain.UserID, questions *nativePolicyQuestions) (*userTokenIssueAuthority, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok || subject != string(actor.Type)+":"+string(actor.ID) {
		return nil, iamerr.ErrPermissionDenied
	}
	if err := shared.ValidateResourceID(string(owner), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	if bundle.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	model, err := authzplan.ParseModel(bundle.ModelSource())
	if err != nil {
		return nil, err
	}
	if err = validateUserTokenIssueModel(model); err != nil {
		return nil, err
	}
	if err = questions.add(actor, "token_issuer", "iam_user", string(owner)); err != nil {
		return nil, err
	}
	if err = questions.add(actor, "system_admin", "cluster", domain.ClusterSingletonID); err != nil {
		return nil, err
	}
	return &userTokenIssueAuthority{bundle, actor, owner}, nil
}

func validateUserTokenIssueModel(model *authzplan.Model) error {
	user := model.Type("iam_user")
	if user == nil {
		return kaname.ErrSourceUnconfirmed
	}
	issuer, subject := user.Rel("token_issuer"), user.Rel("subject")
	if issuer == nil || len(issuer.Terms) != 1 || issuer.Terms[0].Kind != authzplan.TermComputed || issuer.Terms[0].Computed != "subject" ||
		subject == nil || len(subject.Terms) != 1 || subject.Terms[0].Kind != authzplan.TermDirect || len(subject.Terms[0].Direct) != 1 ||
		subject.Terms[0].Direct[0] != (authzplan.DirectSubject{Type: "user"}) {
		return kaname.ErrSourceUnconfirmed
	}
	return validateSystemAdminDecisionModel(model)
}

// Вычисляет решение на часах и в бюджете защищённой попытки. Будущий writer
// должен до protectPolicyPlan дождаться блокировок credential, quota и audit,
// затем выполнить запись и аудит на той же TX. Здесь нет открытия/commit TX.
func (a *userTokenIssueAuthority) evaluate(ctx context.Context, w *authorityWriteTx) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || w == nil || w.closed || w.writeTx == nil || w.tx == nil || w.fence.decisionAt.IsZero() ||
		w.fence.mode != kaname.AuthorityFenceGlobal || w.nativeRead == nil || !w.nativeRead.global ||
		w.nativeRead.budget == nil || w.producerBudget != w.nativeRead.budget {
		return kaname.ErrSourceUnconfirmed
	}
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok || subject != string(a.actor.Type)+":"+string(a.actor.ID) {
		return iamerr.ErrPermissionDenied
	}
	object := "iam_user:" + string(a.owner)
	if err := w.nativeRead.boundary.requireQuestion(a.bundle, subject, "token_issuer", object); err != nil {
		return err
	}
	if err := w.nativeRead.boundary.requireQuestion(a.bundle, subject, "system_admin", authzguard.ClusterObject()); err != nil {
		return err
	}

	if err := chargeNativePolicyBudget(w.nativeRead.budget, 2, 1); err != nil {
		return err
	}
	var state domain.InviteStatus
	var eligible bool
	err := w.tx.QueryRow(ctx, `SELECT u.invite_status, CASE $2::text
 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$3 AND invite_status=$4)
 WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$3 AND enabled)
 ELSE false END FROM kaname.users u WHERE u.id=$1`, string(a.owner), string(a.actor.Type), string(a.actor.ID), string(domain.InviteStatusActive)).Scan(&state, &eligible)
	if errors.Is(err, pgx.ErrNoRows) {
		return iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", a.owner)
	}
	if err != nil {
		return err
	}
	if !state.MayAuthenticate() {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "User %s is not active and cannot be issued a token", a.owner)
	}
	if !eligible {
		return iamerr.ErrPermissionDenied
	}

	checker := newAdministrativeSourceChecker(w, a.bundle, a.verify)
	allowed, err := checker.Check(ctx, subject, "token_issuer", object)
	if err != nil {
		return err
	}
	if !allowed {
		allowed, err = authzguard.SubjectIsClusterAdminPlainE(ctx, checker, subject)
		if err != nil {
			return err
		}
	}
	if !allowed {
		return iamerr.ErrPermissionDenied
	}
	return ctx.Err()
}

// Строка owner производит один tuple subject для самого человека. Обе
// декларации плоские: group/userset, wildcard или класс не заменяют точного
// субъекта. Для надзора происхождение оставшегося tuple проверяется общим
// читателем (включая system binding и допустимые role-backed источники).
func (a *userTokenIssueAuthority) verify(sources *nativeAdministrativeSources, ctx context.Context, f relverdict.AdministrativeFact, budget *relverdict.AdministrativeReadBudget) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	actor := string(a.actor.Type) + ":" + string(a.actor.ID)
	if f.QuestionSubject != actor || f.QuestionObjectType != f.ObjectType || f.QuestionObjectID != f.ObjectID || f.ConditionName != "" || len(f.ConditionParameters) != 0 {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	switch {
	case f.QuestionRelation == "token_issuer" && f.ObjectType == "iam_user" && f.ObjectID == string(a.owner) && f.Relation == "subject":
		return f.Subject == actor && f.Subject == "user:"+string(a.owner), nil
	case f.QuestionRelation == "system_admin" && f.ObjectType == "cluster" && f.ObjectID == domain.ClusterSingletonID && f.Relation == "system_admin":
		if f.Subject != actor {
			return false, nil
		}
		return sources.verify(ctx, f, budget)
	default:
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
}
