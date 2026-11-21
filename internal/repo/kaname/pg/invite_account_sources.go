// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Только Invite расширяет закрытый source checker точным editor leaf. Ordinary
// verifier остальных семейств не меняется. Actor взят из authenticated intent.
type inviteAccountSources struct {
	nativeAdministrativeSources
	actor domain.Subject
}

func newInviteAccountChecker(w *authorityWriteTx, bundle *granteffect.Bundle, actor domain.Subject) kaname.RelationChecker {
	if w == nil || w.tx == nil || w.nativeRead == nil || bundle.Validate() != nil {
		return &liveAdministrativeChecker{}
	}
	sources := &inviteAccountSources{nativeAdministrativeSources: nativeAdministrativeSources{w: w, bundle: bundle}, actor: actor}
	form := relverdict.NewAdministrativeAsker(w.tx, bundle, func() time.Time { return w.fence.decisionAt }, sources.verify)
	form.BindReadBoundary(w.nativeRead, w.nativeRead.budget)
	return &liveAdministrativeChecker{w: w, inner: authzcascade.WrapAdmitted(form, personmarks.NewTransaction(w.tx))}
}
func (s *inviteAccountSources) verify(ctx context.Context, f relverdict.AdministrativeFact, budget *relverdict.AdministrativeReadBudget) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if administrativeRelation(f.Relation) {
		return s.nativeAdministrativeSources.verify(ctx, f, budget)
	}
	// Empty grant-arm provenance, неизвестный тип и иные non-admin leaves не
	// становятся editor proof. Поддержан точный производственный account tier.
	if f.ObjectType != "account" || f.Relation != "editor" || f.ConditionName != "" || len(f.ConditionParameters) != 0 {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	typ, id, ok := strings.Cut(strings.TrimSuffix(f.Subject, "#member"), ":")
	if !ok {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	subject := domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}
	if subject.Validate() != nil || domain.FGASubjectRef(typ, id) != f.Subject {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	if err := budget.Charge(1, 1); err != nil {
		return false, err
	}
	var exists bool
	err := s.w.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.accounts WHERE id=$1) AND CASE $2
 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$3) AND $2=$4 AND $3=$5
 WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$3) AND $2=$4 AND $3=$5
 WHEN 'group' THEN EXISTS(SELECT 1 FROM kaname.groups g JOIN kaname.group_members m ON m.group_id=g.id WHERE g.id=$3 AND m.member_type=$4 AND m.member_id=$5)
 ELSE false END`, f.ObjectID, typ, id, string(s.actor.Type), string(s.actor.ID)).Scan(&exists)
	if err != nil || !exists {
		return false, err
	}
	if err = s.w.canonicalCoverage(domain.AccountID(f.ObjectID)); err != nil {
		return false, err
	}
	// Ledger — индекс, не разрешение. Дочитываем последнюю страницу даже при
	// живом первом holder; ошибку/отмену хвоста нельзя превратить в partial allow.
	var cursor [3]string
	known, allowed, unknown := false, false, false
	for {
		if err = ctx.Err(); err != nil {
			return false, err
		}
		if err = budget.Charge(0, 1); err != nil {
			return false, err
		}
		rows, e := s.w.tx.Query(ctx, `SELECT binding_id,member_object_type,member_object_id FROM kaname.access_binding_emitted_tuples WHERE fga_user=$1 AND relation=$2 AND object=$3 AND (binding_id COLLATE "C",member_object_type COLLATE "C",member_object_id COLLATE "C")>($4::text COLLATE "C",$5::text COLLATE "C",$6::text COLLATE "C") ORDER BY binding_id COLLATE "C",member_object_type COLLATE "C",member_object_id COLLATE "C" LIMIT 256`, f.Subject, f.Relation, f.ObjectType+":"+f.ObjectID, cursor[0], cursor[1], cursor[2])
		if e != nil {
			return false, e
		}
		page := make([][3]string, 0, 256)
		for rows.Next() {
			var key [3]string
			if e = rows.Scan(&key[0], &key[1], &key[2]); e != nil {
				break
			}
			page = append(page, key)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return false, e
		}
		if err = budget.Charge(len(page), 0); err != nil {
			return false, err
		}
		for _, key := range page {
			known = true
			live, e := s.bindingProduces(ctx, domain.AccessBindingID(key[0]), f, budget)
			if errors.Is(e, relverdict.ErrAdministrativeSourceUnconfirmed) {
				unknown = true
				continue
			}
			if e != nil {
				return false, e
			}
			allowed = allowed || live
		}
		if len(page) < 256 {
			break
		}
		cursor = page[len(page)-1]
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if allowed {
		return true, nil
	}
	if !known || unknown {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	return false, nil
}
