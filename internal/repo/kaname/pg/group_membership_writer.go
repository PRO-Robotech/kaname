// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// GroupMembershipParticipant владеет immutable handoff; наружу не возвращает
// decision checker. kaname#1034: это настоящий adapter двух mutation workers.
type GroupMembershipParticipant struct {
	repo   *Repository
	bundle *granteffect.Bundle
}

func NewGroupMembershipParticipant(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*GroupMembershipParticipant, error) {
	if repo == nil || repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	return &GroupMembershipParticipant{repo: repo, bundle: bundle}, nil
}

// ValidateAuthorityRuntime проверяет реальный LOGIN до startup-записей.
// SET ROLE поверх owner, membership и DDL authority не заменяют разделение DSN.
func (r *Repository) ValidateAuthorityRuntime(ctx context.Context) error {
	if r == nil || r.master == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	var ordinary bool
	err := r.master.QueryRow(ctx, `SELECT current_user=session_user
 AND NOT (u.rolsuper OR u.rolcreatedb OR u.rolcreaterole OR u.rolreplication OR u.rolbypassrls OR u.rolinherit)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=u.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database() AND datdba=u.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='kaname' AND (nspowner=u.oid OR pg_catalog.has_schema_privilege(u.oid,oid,'CREATE')))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND (pg_catalog.pg_has_role(u.oid,c.relowner,'MEMBER') OR (c.relkind IN ('r','p') AND pg_catalog.has_table_privilege(u.oid,c.oid,'TRIGGER'))))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='kaname' AND pg_catalog.pg_has_role(u.oid,f.proowner,'MEMBER'))
 AND NOT pg_catalog.has_table_privilege(u.oid,'kaname.authority_writer_protocol','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT pg_catalog.has_table_privilege(u.oid,'kaname.authority_semantic_identity','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT pg_catalog.has_table_privilege(u.oid,'kaname.authority_bundle_handoff','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 FROM pg_catalog.pg_roles u WHERE u.rolname=session_user`).Scan(&ordinary)
	if err != nil {
		return err
	}
	if !ordinary {
		return errors.New("authority participation requires a separate ordinary runtime LOGIN")
	}
	return ctx.Err()
}

type groupMembershipScope struct {
	accounts []string
	global   bool
}

func readGroupMembershipScope(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, m domain.GroupMember) (groupMembershipScope, error) {
	var s groupMembershipScope
	err := q.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_group_member_scopes($1,$2,$3)`, string(m.GroupID), string(m.MemberType), string(m.MemberID)).Scan(&s.accounts, &s.global)
	return s, err
}
func (s groupMembershipScope) intent(m domain.GroupMember, b *granteffect.Bundle) kaname.AuthorityWriteIntent {
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityGroup, Bundle: b, Owners: []kaname.AuthorityOwnerRef{{Kind: "group", ID: string(m.GroupID)}}, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	if !s.global {
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for _, a := range s.accounts {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
			in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
		}
	}
	return in
}
func (p *GroupMembershipParticipant) GroupMembershipWriter(ctx context.Context, m domain.GroupMember) (kaname.Writer, error) {
	if p == nil || p.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if m.GroupID == "" || m.MemberID == "" || strings.ContainsAny(string(m.GroupID)+string(m.MemberID), ":#* \t\r\n") || (m.MemberType != domain.SubjectTypeUser && m.MemberType != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Только primary discovery, никаких row/advisory locks и mutable cache.
		initial, err := readGroupMembershipScope(ctx, p.repo.master, m)
		if err != nil {
			return nil, err
		}
		w, err := p.repo.coordinatedAuthorityWriter(ctx, initial.intent(m, p.bundle), "participant")
		if err != nil {
			return nil, err
		}
		actual, err := readGroupMembershipScope(ctx, w.tx, m)
		// Полный OLD/NEW scope нельзя расширить в уже открытой TX. Любое изменение
		// классификации означает rollback и новый entry до первого старого lock.
		same := err == nil && actual.global == initial.global && (actual.global || slices.Equal(actual.accounts, initial.accounts))
		if same {
			// Coordinator мог повторно обнаружить ownership; сверяем фактически
			// полученный план, а не только первоначальную заявку.
			fence := w.AuthorityFence()
			same = (actual.global && fence.Mode() == kaname.AuthorityFenceGlobal) || (!actual.global && fence.Mode() == kaname.AuthorityFenceAccounts && slices.EqualFunc(actual.accounts, fence.Accounts(), func(a string, b domain.AccountID) bool { return a == string(b) }))
		}
		if same && ctx.Err() == nil {
			return w, nil
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollbackErr := w.Rollback(cleanup)
		cancel()
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return nil, errors.Join(err, rollbackErr)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}

var _ kaname.GroupMembershipWriterFactory = (*GroupMembershipParticipant)(nil)
