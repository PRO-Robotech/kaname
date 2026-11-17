// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"slices"
)

// Runtime proposal не является доказательством: RR owner verifier проверяет
// фактический census и каждую исходную строку, затем сохраняет свою копию.
// RC принимает её только после защищённого повторного сравнения epochs.
type bindingSequenceCoordinate struct {
	Type     string                     `json:"type"`
	ID       string                     `json:"id"`
	Desired  []reconcile.DesiredMember  `json:"desired"`
	Commands []reconcile.BindingCommand `json:"commands"`
}
type bindingSequenceCapture struct {
	parents     *resourceParentCapture
	binding     domain.AccessBindingID
	converge    bool
	coordinates []bindingSequenceCoordinate
}

func (s *bindingSequenceCapture) captureCarrier(ctx context.Context) error {
	for _, kind := range []resourceSourceKind{resourceSourceBinding, resourceSourceBindingSubjects, resourceSourceBindingMembers, resourceSourceBindingLedger} {
		if _, err := s.parents.source.read(ctx, s.parents.tx, resourceSourceKey{kind: kind, typ: "binding", id: string(s.binding)}); err != nil {
			return err
		}
	}
	out := &resourceOutputCapture{bindings: map[string]domain.AccessBinding{}, roles: map[string]domain.Role{}}
	return out.captureBindings(ctx, s.parents, map[string]bool{string(s.binding): true})
}
func (s *bindingSequenceCapture) captureCoordinate(ctx context.Context, typ, id string, input reconcile.CapturedObjectDiff, commands []reconcile.BindingCommand, group *bindingCapturedGroupStore) error {
	object, present, err := s.parents.captureObjectProjection(ctx, typ, id)
	if err != nil {
		return err
	}
	_ = object
	if _, err = s.parents.captureObjectAncestors(ctx, typ, id, present); err != nil {
		return err
	}
	for _, kind := range []resourceSourceKind{resourceSourceObjectMembers, resourceSourceObjectLedger} {
		if _, err = s.parents.source.read(ctx, s.parents.tx, resourceSourceKey{kind: kind, typ: typ, id: id}); err != nil {
			return err
		}
	}
	// Only the closed same-stage adapter can account for the three SELECTs
	// it actually replaced. The independent SQL verifier still rereads all sources.
	reads := 4
	if group != nil {
		if err = group.check(ctx, s, typ, id); err != nil {
			return err
		}
		if !group.membersRead || !group.ledgerRead {
			return kaname.ErrSourceUnconfirmed
		}
		reads = 1 // The unchanged AncestorObjects SELECT still ran.
	}
	if err = s.parents.source.budget.Charge(len(input.Current)+len(input.Ledger)+len(input.Desired)+len(commands)+1, reads); err != nil {
		return err
	}
	desired := slices.Clone(input.Desired)
	if desired == nil {
		desired = []reconcile.DesiredMember{}
	}
	if commands == nil {
		commands = []reconcile.BindingCommand{}
	}
	s.coordinates = append(s.coordinates, bindingSequenceCoordinate{typ, id, desired, commands})
	return nil
}
func (s *bindingSequenceCapture) verifySnapshot(ctx context.Context, accounts []string, epochs map[string]json.RawMessage) error {
	sources := make([]resourceProposalSource, 0, len(s.parents.source.entries))
	for key, rows := range s.parents.source.entries {
		item := resourceProposalSource{Kind: key.kind, Type: key.typ, ID: key.id, Projection: key.projection, States: make([]string, 0, len(rows))}
		for _, row := range rows {
			item.States = append(item.States, row.state)
		}
		slices.Sort(item.States)
		sources = append(sources, item)
	}
	// Пустой внутренний census является массивом; SQL null guard остаётся строгим.
	coordinates := s.coordinates
	if coordinates == nil {
		coordinates = []bindingSequenceCoordinate{}
	}
	payload, err := json.Marshal(struct {
		Binding     string                      `json:"binding"`
		Converge    bool                        `json:"converge"`
		Sources     []resourceProposalSource    `json:"sources"`
		Coordinates []bindingSequenceCoordinate `json:"coordinates"`
	}{string(s.binding), s.converge, sources, coordinates})
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(epochs)
	if err != nil {
		return err
	}
	var rows, reads int
	if err = s.parents.tx.QueryRow(ctx, `SELECT logical_rows,logical_reads FROM kaname.authority_binding_stage_sequence_capture_v3($1::jsonb,$2::text[],$3::jsonb,$4,$5)`, payload, accounts, encoded, s.parents.source.budget.RemainingRows(), s.parents.source.budget.RemainingReads()).Scan(&rows, &reads); err != nil {
		return err
	}
	return chargeNativePolicyBudget(s.parents.source.budget, rows, reads)
}
func (s *bindingSequenceCapture) prepare(ctx context.Context, tx pgx.Tx, id domain.AccessBindingID, accounts []string, epochs []byte) error {
	if s == nil || s.binding != id || s.parents == nil || s.parents.source.conn != tx.Conn() {
		return kaname.ErrSourceUnconfirmed
	}
	var rows, reads int
	if err := tx.QueryRow(ctx, `SELECT logical_rows,logical_reads FROM kaname.authority_binding_stage_sequence_prepare_v3($1,$2::text[],$3::jsonb,$4,$5)`, string(id), accounts, epochs, s.parents.source.budget.RemainingRows(), s.parents.source.budget.RemainingReads()).Scan(&rows, &reads); err != nil {
		return err
	}
	return chargeNativePolicyBudget(s.parents.source.budget, rows, reads)
}
