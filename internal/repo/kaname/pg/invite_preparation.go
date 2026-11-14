// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type invitePhase struct {
	Phase, Enforcement string
	Protocol           int
	Identity           grantcoverage.Identity
}

func readInvitePhase(ctx context.Context, tx pgx.Tx, protected bool) (invitePhase, error) {
	var p invitePhase
	query := `SELECT phase,enforcement,protocol_version,model_id,catalog_id,projector_version FROM kaname.authority_invite_phase_snapshot()`
	if protected {
		query = `SELECT phase,enforcement,protocol_version,model_id,catalog_id,projector_version FROM kaname.authority_invite_phase_held()`
	}
	err := tx.QueryRow(ctx, query).Scan(&p.Phase, &p.Enforcement, &p.Protocol, &p.Identity.ModelID, &p.Identity.CatalogID, &p.Identity.ProjectorVersion)
	if err != nil {
		return p, err
	}
	if p.Protocol != 1 || !((p.Phase == "prepared" && p.Enforcement == "compatibility") || (p.Phase == "active" && p.Enforcement == "strict")) {
		return p, kaname.ErrSemanticIdentityUnavailable
	}
	return p, nil
}

// Полный exact snapshot identity/membership. Future identity не попадает в Reader
// и никогда не становится actor/source; отсутствие защищается GLOBAL+preflight.
type inviteIdentityPlan struct {
	recipient domain.UserID
	existing  bool
	state     string
}

const inviteIdentitySnapshotSQL = `WITH person AS (SELECT * FROM kaname.users WHERE lower(email)=lower($1::text)), selected AS (SELECT coalesce((SELECT id FROM person),$2::text) id)
 SELECT selected.id,EXISTS(SELECT 1 FROM person),jsonb_build_object(
 'person',(SELECT to_jsonb(p) FROM person p),
 'candidate',(SELECT to_jsonb(u) FROM kaname.users u WHERE id=$2),
 'issued',EXISTS(SELECT 1 FROM kaname.issued_user_ids WHERE id=$2),
 'membership',(SELECT to_jsonb(m) FROM kaname.memberships m WHERE m.user_id=selected.id AND m.account_id=$3))::text FROM selected`

func readInviteIdentity(ctx context.Context, tx pgx.Tx, in kaname.InviteDecisionIntent) (inviteIdentityPlan, error) {
	var out inviteIdentityPlan
	err := tx.QueryRow(ctx, inviteIdentitySnapshotSQL, string(in.Email), string(in.CandidateUserID), string(in.AccountID)).Scan(&out.recipient, &out.existing, &out.state)
	if err != nil {
		return out, err
	}
	var facts struct {
		Candidate json.RawMessage `json:"candidate"`
		Issued    bool            `json:"issued"`
	}
	if err = json.Unmarshal([]byte(out.state), &facts); err != nil {
		return out, err
	}
	if !out.existing && string(facts.Candidate) != "null" {
		return out, iamerr.ErrAlreadyExists
	}
	if !out.existing && facts.Issued {
		return out, iamerr.Wrapf(iamerr.ErrFailedPrecondition, "User %s not found", in.CandidateUserID)
	}
	return out, nil
}

// Только private результат той же попытки. Наружу возвращаются копии subjects.
type preparedInvite struct {
	recipient domain.UserID
	binding   domain.AccessBinding
	at        time.Time
}

func (p *preparedInvite) RecipientID() domain.UserID { return p.recipient }
func (p *preparedInvite) DecisionAt() time.Time      { return p.at }
func (p *preparedInvite) Binding() domain.AccessBinding {
	b := p.binding
	b.Subjects = append([]domain.Subject(nil), b.Subjects...)
	return b
}
func inviteBinding(in kaname.InviteDecisionIntent, id domain.UserID) domain.AccessBinding {
	if in.ProjectID == "" {
		return domain.AccessBinding{}
	}
	sub := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}
	return domain.AccessBinding{ID: in.BindingID, SubjectType: sub.Type, SubjectID: sub.ID, Subjects: []domain.Subject{sub}, RoleID: in.RoleID, ResourceType: "project", ResourceID: string(in.ProjectID), GrantedByUserID: in.GrantedBy, Target: domain.AccessTarget{AllInScope: true}}
}
func inviteRole(ctx context.Context, tx pgx.Tx, in kaname.InviteDecisionIntent) (domain.Role, error) {
	if in.ProjectID == "" {
		return domain.Role{}, nil
	}
	rd := &readTx{tx: tx}
	project, err := rd.Projects().Get(ctx, in.ProjectID)
	if err != nil {
		return domain.Role{}, err
	}
	if project.AccountID != in.AccountID {
		return domain.Role{}, iamerr.ErrFailedPrecondition
	}
	role, err := rd.Roles().Get(ctx, in.RoleID)
	if err != nil {
		return domain.Role{}, err
	}
	if !domain.IsRoleAssignableInAccount(role, "project", string(in.ProjectID), string(in.AccountID)) {
		return domain.Role{}, iamerr.ErrFailedPrecondition
	}
	return role, nil
}

// Ошибка rollback прекращает retry: состояние leased connection не предполагается.
func inviteRollback(ctx context.Context, tx pgx.Tx, err *error) {
	if cleanup := policyRollback(ctx, tx); cleanup != nil {
		*err = &inviteCleanupError{errors.Join(*err, cleanup)}
	}
}

type inviteCleanupError struct{ error }

func (e *inviteCleanupError) Unwrap() error { return e.error }
