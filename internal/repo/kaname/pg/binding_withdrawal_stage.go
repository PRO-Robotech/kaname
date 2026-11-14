// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5"
)

// kaname#1034: закрытые predicates, а не произвольный SQL/список ID caller.
// Delegation включает все неотозванные ACTIVE/PENDING строки, включая tail и phantom
// нового carrier; её источник читается до первой страницы в том же RR snapshot.
type bindingWithdrawalSelection struct {
	BindingID     domain.AccessBindingID
	DelegationID  domain.GrantDelegationID
	requirePolicy bool
	global        bool // DELETE parent cascade требует global до locks.
}
type bindingWithdrawalStage struct {
	*bindingStage
	delegation  domain.GrantDelegation
	policy      *policyPlan
	policyOwner *GrantPolicyWriters
}

func (p *BindingStageParticipant) stageWithdrawal(ctx context.Context, selection bindingWithdrawalSelection) (out *bindingWithdrawalStage, err error) {
	if p == nil || p.owner == nil || (selection.BindingID == "") == (selection.DelegationID == "") {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	conn, err := p.owner.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	out = &bindingWithdrawalStage{bindingStage: &bindingStage{conn: conn, accounts: map[string]bool{}, global: selection.global || selection.DelegationID != ""}}
	defer func() {
		if err != nil {
			out.close()
		}
	}()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return out, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `CREATE TEMP TABLE kaname_binding_withdrawal_headers(binding_id text PRIMARY KEY,body jsonb NOT NULL) ON COMMIT PRESERVE ROWS;
 CREATE TEMP TABLE kaname_binding_withdrawal_tuples(seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,body jsonb NOT NULL) ON COMMIT PRESERVE ROWS`); err != nil {
		return out, err
	}
	if err = createGrantChildSpool(ctx, tx); err != nil {
		return out, err
	}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read(ARRAY[]::text[])`).Scan(&raw); err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out.epochs); err != nil {
		return out, err
	}
	if _, ok := out.epochs["$generation"]; !ok {
		return out, errors.New("binding epochs are uninitialized")
	}
	if selection.DelegationID != "" {
		out.delegation, err = (&gdReader{tx: tx}).Get(ctx, selection.DelegationID)
		if err != nil {
			return out, err
		}
		principal, ok := authzguard.PrincipalSubject(ctx)
		if !ok {
			return out, kaname.ErrInvalidAuthorityFencePlan
		}
		typ, id, ok := strings.Cut(principal, ":")
		if !ok {
			return out, kaname.ErrInvalidAuthorityFencePlan
		}
		out.policyOwner = &GrantPolicyWriters{repo: p.owner.repo, bundle: p.owner.bundle}
		out.policy, err = out.policyOwner.discoverPolicyPlan(ctx, tx, policyWriteRequest{actor: domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}, kind: kaname.AuthorityDelegation, global: true})
		if err != nil {
			return out, err
		}
	}
	after := ""
	for {
		var ids []domain.AccessBindingID
		if selection.BindingID != "" {
			ids = []domain.AccessBindingID{selection.BindingID}
		} else {
			rows, e := tx.Query(ctx, `SELECT id FROM kaname.access_bindings WHERE delegation_id=$1 AND revoked_at IS NULL AND id>$2 ORDER BY id LIMIT $3`, string(selection.DelegationID), after, bindingStagePage)
			if e != nil {
				return out, e
			}
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return out, e
				}
				ids = append(ids, domain.AccessBindingID(id))
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return out, e
			}
		}
		for _, id := range ids {
			reader := &abReader{tx: tx}
			b, e := reader.Get(ctx, id)
			if e != nil {
				return out, e
			}
			b.Subjects, e = reader.ListSubjects(ctx, id)
			if e != nil {
				return out, e
			}
			b.Subjects, e = domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
			if e != nil {
				return out, e
			}
			if selection.BindingID != "" {
				out.binding = b
			}
			data, e := json.Marshal(b)
			if e != nil {
				return out, e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_binding_withdrawal_headers VALUES($1,$2::jsonb)`, string(id), data); e != nil {
				return out, e
			}
			// Только Delete/expiry физически снимают children. Soft revoke сохраняет историю.
			if selection.BindingID != "" && (selection.global || !selection.requirePolicy) {
				if e = captureGrantChildren(ctx, tx, id); e != nil {
					return out, e
				}
			}
			if !out.global {
				var scopes groupMembershipScope
				if e = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_binding_mutation_scopes($1)`, string(id)).Scan(&scopes.accounts, &scopes.global); e != nil {
					return out, e
				}
				out.include(scopes)
			}
			// Строка member без ledger тоже будет удалена expiry/delete. Её OLD owner
			// входит в census независимо от наличия выпущенного tuple, включая tail page.
			memberType, memberID, memberFP := "", "", ""
			firstMember := true
			for !out.global {
				rows, e := tx.Query(ctx, `SELECT object_type,object_id,rule_fp,pg_catalog.to_jsonb(m) FROM kaname.access_binding_target_members m
     WHERE binding_id=$1 AND ($2 OR (object_type,object_id,rule_fp)>($3,$4,$5)) ORDER BY object_type,object_id,rule_fp LIMIT $6`, string(id), firstMember, memberType, memberID, memberFP, bindingStagePage)
				if e != nil {
					return out, e
				}
				var members [][]byte
				for rows.Next() {
					var raw []byte
					if e = rows.Scan(&memberType, &memberID, &memberFP, &raw); e != nil {
						rows.Close()
						return out, e
					}
					members = append(members, raw)
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					return out, e
				}
				for _, raw := range members {
					var scopes groupMembershipScope
					if e = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_protocol_row_scopes('access_binding_target_members',$1::jsonb)`, raw).Scan(&scopes.accounts, &scopes.global); e != nil {
						return out, e
					}
					out.include(scopes)
				}
				if len(members) < bindingStagePage {
					break
				}
				firstMember = false
			}
			// DISTINCT сохраняет настоящий SelectEmittedTuples контракт: один tuple
			// от нескольких member coordinates снимается один раз для данной выдачи.
			cursor := ab.RelationTuple{}
			first := true
			for {
				rows, e := tx.Query(ctx, `SELECT DISTINCT relation,object,fga_user FROM kaname.access_binding_emitted_tuples
     WHERE binding_id=$1 AND ($2 OR (relation,object,fga_user)>($3,$4,$5))
     ORDER BY relation,object,fga_user LIMIT $6`, string(id), first, cursor.Relation, cursor.Object, cursor.User, bindingStagePage)
				if e != nil {
					return out, e
				}
				var tuples []ab.RelationTuple
				for rows.Next() {
					var tuple ab.RelationTuple
					if e = rows.Scan(&tuple.Relation, &tuple.Object, &tuple.User); e != nil {
						rows.Close()
						return out, e
					}
					tuples = append(tuples, tuple)
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					return out, e
				}
				if len(tuples) == 0 {
					break
				}
				if !out.global {
					for _, tuple := range tuples {
						var scopes groupMembershipScope
						payload, e := json.Marshal(map[string]any{"event_type": "fga.tuple.delete", "payload": map[string]string{"user": tuple.User, "relation": tuple.Relation, "object": tuple.Object}})
						if e != nil {
							return out, e
						}
						if e = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_protocol_row_scopes('fga_outbox',$1::jsonb)`, payload).Scan(&scopes.accounts, &scopes.global); e != nil {
							return out, e
						}
						out.include(scopes)
					}
				}
				data, e = json.Marshal(tuples)
				if e != nil {
					return out, e
				}
				if _, e = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_binding_withdrawal_tuples(body) VALUES($1::jsonb)`, data); e != nil {
					return out, e
				}
				if len(tuples) < bindingStagePage {
					break
				}
				cursor = tuples[len(tuples)-1]
				first = false
			}
		}
		if selection.BindingID != "" || len(ids) < bindingStagePage {
			break
		}
		after = string(ids[len(ids)-1])
	}

	if selection.requirePolicy && out.policy == nil {
		principal, ok := authzguard.PrincipalSubject(ctx)
		if !ok {
			return out, kaname.ErrInvalidAuthorityFencePlan
		}
		typ, id, ok := strings.Cut(principal, ":")
		if !ok {
			return out, kaname.ErrInvalidAuthorityFencePlan
		}
		accounts := make([]domain.AccountID, 0, len(out.accounts))
		for a := range out.accounts {
			accounts = append(accounts, domain.AccountID(a))
		}
		out.policyOwner = &GrantPolicyWriters{repo: p.owner.repo, bundle: p.owner.bundle}
		out.policy, err = out.policyOwner.discoverPolicyPlan(ctx, tx, policyWriteRequest{actor: domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}, kind: kaname.AuthorityBinding, owners: []kaname.AuthorityOwnerRef{{Kind: "binding", ID: string(selection.BindingID)}}, mutationSubjects: out.binding.Subjects, additionalAccounts: accounts, global: out.global})
		if err != nil {
			return out, err
		}
		out.global = out.policy.global
		out.accounts = out.policy.accounts
	}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, out.scopeAccounts()).Scan(&raw); err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out.epochs); err != nil {
		return out, err
	}
	if _, ok := out.epochs["$generation"]; !ok {
		return out, errors.New("binding epochs are uninitialized")
	}
	return out, tx.Commit(ctx)
}
func (s *bindingWithdrawalStage) include(scopes groupMembershipScope) {
	s.global = s.global || scopes.global
	for _, a := range scopes.accounts {
		s.accounts[a] = true
	}
	if len(s.accounts) > kaname.MaxAuthorityFenceAccounts {
		s.global = true
	}
}
func (s *bindingWithdrawalStage) scopeAccounts() []string {
	if s.global {
		return nil
	}
	accounts := make([]string, 0, len(s.accounts))
	for a := range s.accounts {
		accounts = append(accounts, a)
	}
	slices.Sort(accounts)
	return accounts
}
func (s *bindingWithdrawalStage) open(ctx context.Context, owner *GroupMembershipParticipant, purpose string) (*authorityWriteTx, error) {
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: owner.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	if !s.global {
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for _, a := range s.scopeAccounts() {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
			in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
		}
	}
	if s.policy != nil {
		in = s.policy.intent(owner.bundle)
	}
	w, err := owner.repo.coordinatedAuthorityWriterWithBegin(ctx, in, purpose, s.conn.BeginTx)
	if err != nil {
		return nil, err
	}
	if err = s.recheck(ctx, w); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
		return nil, err
	}
	return w, nil
}
func (s *bindingWithdrawalStage) recheck(ctx context.Context, w *authorityWriteTx) error {
	if err := grantMutationPreflight(ctx, w.tx, "withdrawal"); err != nil {
		return err
	}
	if s.policy != nil {
		if err := s.policyOwner.protectPolicyPlan(ctx, w, s.policy); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(s.epochs)
	if err != nil {
		return err
	}
	var at time.Time
	if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, s.scopeAccounts(), encoded).Scan(&at); err != nil {
		return err
	}
	w.fence.decisionAt = at.UTC()
	return ctx.Err()
}
func (s *bindingWithdrawalStage) visitBindings(ctx context.Context, w *authorityWriteTx, visit func(context.Context, domain.AccessBinding) error) error {
	if visit == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	after := ""
	for {
		rows, err := w.tx.Query(ctx, `SELECT binding_id,body FROM pg_temp.kaname_binding_withdrawal_headers WHERE binding_id>$1 ORDER BY binding_id LIMIT $2`, after, bindingStagePage)
		if err != nil {
			return err
		}
		var bindings []domain.AccessBinding
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&after, &raw); err != nil {
				rows.Close()
				return err
			}
			var b domain.AccessBinding
			if err = json.Unmarshal(raw, &b); err != nil {
				rows.Close()
				return err
			}
			bindings = append(bindings, b)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, b := range bindings {
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = visit(ctx, b); err != nil {
				return err
			}
		}
		if len(bindings) < bindingStagePage {
			return nil
		}
	}
}
func (s *bindingWithdrawalStage) lockBindings(ctx context.Context, w *authorityWriteTx) error {
	// kaname#1034: порядок GD → binding совпадает с cascade revoke. Inactive
	// delegation не запрещает владельцу удалить carrier; authority проверит callback.
	if s.binding.DelegationID != "" {
		if _, _, err := w.AccessBindingsW().GrantDelegationsW().HoldActive(ctx, s.binding.DelegationID); err != nil {
			return err
		}
	}
	store := &reconcileStore{tx: w.tx}
	// Все advisory сначала, затем все deactivation rows. Сортировка ID одинакова
	// для всех проходов; под fence обходим только заранее построенный spool.
	if err := s.visitBindings(ctx, w, func(ctx context.Context, b domain.AccessBinding) error { return store.AcquireBindingLock(ctx, b.ID) }); err != nil {
		return err
	}
	if err := s.visitBindings(ctx, w, func(ctx context.Context, b domain.AccessBinding) error {
		_, err := w.AccessBindingsW().GetForDeactivation(ctx, b.ID)
		return err
	}); err != nil {
		return err
	}
	if err := lockGrantChildren(ctx, w.tx); err != nil {
		return err
	}
	// kaname#1034: настоящий fold DELETE ждёт эти строки. Ожидание переносим
	// перед окончательным decision_at; затем emitter повторно берёт те же locks.
	// Читается только готовый spool, не inventory фактов/держателей.
	return s.visitTuplePages(ctx, w, func(ctx context.Context, tuples []ab.RelationTuple) error {
		for _, tuple := range tuples {
			typ, id, ok := strings.Cut(tuple.Object, ":")
			if !ok || typ == "" || id == "" {
				return errors.New("invalid withdrawal object")
			}
			subject := tuple.User
			if subject == "user:*" {
				subject = "system_class:authenticated"
				if tuple.Relation == "v_get" {
					subject = "system_class:anonymous"
				}
			}
			_, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 FOR UPDATE`, typ, id, tuple.Relation, subject)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *bindingWithdrawalStage) emitDeletes(ctx context.Context, w *authorityWriteTx) error {
	return s.visitTuplePages(ctx, w, func(ctx context.Context, tuples []ab.RelationTuple) error {
		return w.AccessBindingsW().EmitRelationDelete(ctx, tuples)
	})
}
func (s *bindingWithdrawalStage) visitTuplePages(ctx context.Context, w *authorityWriteTx, visit func(context.Context, []ab.RelationTuple) error) error {
	var after int64
	for {
		// Одна запись spool уже содержит не более bindingStagePage tuples.
		var raw []byte
		err := w.tx.QueryRow(ctx, `SELECT seq,body FROM pg_temp.kaname_binding_withdrawal_tuples WHERE seq>$1 ORDER BY seq LIMIT 1`, after).Scan(&after, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var tuples []ab.RelationTuple
		if err = json.Unmarshal(raw, &tuples); err != nil {
			return err
		}
		if len(tuples) > bindingStagePage {
			return errors.New("oversized withdrawal spool page")
		}
		if err = visit(ctx, tuples); err != nil {
			return err
		}
	}
}
