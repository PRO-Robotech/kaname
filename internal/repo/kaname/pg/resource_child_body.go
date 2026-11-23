// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type resourceChildBodyValues struct {
	Outcome       string            `json:"outcome"`
	SourceVersion time.Time         `json:"source_version"`
	TransactionAt time.Time         `json:"transaction_at"`
	DecisionAt    time.Time         `json:"decision_at"`
	Commands      []json.RawMessage `json:"commands"`
	Certificate   struct {
		Action     int                   `json:"action"`
		ModelType  string                `json:"model_type"`
		ObjectType string                `json:"object_type"`
		ObjectID   string                `json:"object_id"`
		Tuple      service.RelationTuple `json:"tuple"`
		Command    struct {
			DottedType      string            `json:"dotted_type"`
			ObjectID        string            `json:"object_id"`
			ParentProjectID string            `json:"parent_project_id"`
			ParentAccountID string            `json:"parent_account_id"`
			ParentChain     []string          `json:"parent_chain"`
			Labels          map[string]string `json:"labels"`
			SourceVersion   time.Time         `json:"source_version"`
		} `json:"command"`
	} `json:"certificate"`
}

// Тело принадлежит одной закрытой попытке. Последний пользовательский допуск
// предшествует открытию SQL body; callback и модульной личности здесь нет.
func (s *resourceChildStage) applyChildBody(ctx context.Context, tx *resourceDecisionTx, proposal *resourceDecisionProposal) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if s == nil || s.source == nil || !s.source.sealed || s.authorization == nil ||
		s.source.lifetime == nil || s.source.lifetime != s.authorization.native.lifetime ||
		tx == nil || tx.Tx == nil || tx.lifetime != s.source.lifetime || tx.registrationBody != nil ||
		!tx.lifetime.valid(tx.owner, tx.lifetime.bundle) || tx.Tx != tx.owner.tx ||
		proposal == nil || proposal.lifetime != tx.lifetime || proposal.prepared != tx.owner {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	var intent resourceChildRegistrationIntent
	if err := json.Unmarshal(proposal.intent, &intent); err != nil {
		return time.Time{}, err
	}
	authorization := s.authorization
	target := authorization.target
	if intent.Kind != "child_registration" || intent.ResourceType != s.catalog.identity.Dotted ||
		intent.Actor != authorization.principal.ID || intent.AuditID == "" ||
		s.catalog.identity.ObjectType+":"+intent.ResourceID != target.ChildObject {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	allowed, err := authorization.checkFinal(ctx, tx.owner, authorization.subject, target.ParentAction, target.ParentObject)
	if err != nil {
		return time.Time{}, err
	}
	if !allowed {
		return time.Time{}, childFinalDenied
	}
	var encoded []byte
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_child_registration_begin_body_v1($1::jsonb)`, proposal.intent).Scan(&encoded); err != nil {
		return time.Time{}, err
	}
	var values resourceChildBodyValues
	if err := json.Unmarshal(encoded, &values); err != nil {
		return time.Time{}, err
	}
	switch values.Outcome {
	case "create", "replay":
	case "parent_missing":
		return time.Time{}, childParentMissing
	case "parent_closed":
		return time.Time{}, childParentClosed
	case "child_occupied":
		return time.Time{}, childOccupied
	case "capacity":
		return time.Time{}, childCapacity
	case "rate":
		return time.Time{}, childRate
	default:
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	if values.SourceVersion.IsZero() || values.TransactionAt.IsZero() || !values.DecisionAt.Equal(tx.lifetime.at) ||
		values.Commands == nil || len(values.Commands) > 100000 {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	if values.Outcome == "replay" {
		if len(values.Commands) != 0 {
			return time.Time{}, kaname.ErrSourceUnconfirmed
		}
	} else {
		certificate, row := values.Certificate, values.Certificate.Command
		if certificate.Action != int(kaname.ResourceDecisionRegister) || certificate.ModelType != s.catalog.identity.ObjectType ||
			certificate.ObjectType != intent.ResourceType || certificate.ObjectID != intent.ResourceID ||
			certificate.Tuple.User != target.ParentObject || certificate.Tuple.Relation != "parent" || certificate.Tuple.Object != target.ChildObject ||
			row.DottedType != intent.ResourceType || row.ObjectID != intent.ResourceID || !row.SourceVersion.Equal(values.SourceVersion) ||
			len(row.ParentChain) == 0 || row.ParentChain[0] != target.ParentObject || len(row.Labels) != 0 || len(values.Commands) == 0 {
			return time.Time{}, kaname.ErrSourceUnconfirmed
		}
		// Register обозначает только набор существующих direct-адаптеров.
		// SQL intent остаётся child_registration с удостоверенным человеком.
		prepared := &resourceRegistrationPreparation{catalog: s.catalog, parents: s.parents,
			input: kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRegister, Tuple: certificate.Tuple},
			row: service.ResourceMirrorRow{ObjectType: row.DottedType, ObjectID: row.ObjectID, ParentProjectID: row.ParentProjectID,
				ParentAccountID: row.ParentAccountID, ParentChain: row.ParentChain, Labels: row.Labels, SourceVersion: row.SourceVersion}}
		tx.registrationBody = prepared
		for i, expected := range values.Commands {
			if err := ctx.Err(); err != nil {
				return time.Time{}, err
			}
			if err := tx.QueryRow(ctx, `SELECT kaname.authority_child_registration_step_v1($1)`, i+1).Scan(&encoded); err != nil {
				return time.Time{}, err
			}
			// Оба образа приходят из PostgreSQL jsonb. Сравниваем весь JSON,
			// сохраняя точные числа; одного совпадения kind недостаточно.
			var want, got bytes.Buffer
			if json.Compact(&want, expected) != nil || json.Compact(&got, encoded) != nil || !bytes.Equal(want.Bytes(), got.Bytes()) {
				return time.Time{}, kaname.ErrSourceUnconfirmed
			}
			var command resourceRegistrationCommand
			if err := json.Unmarshal(encoded, &command); err != nil {
				return time.Time{}, err
			}
			command.Encoded = encoded
			switch command.Kind {
			case "mirror", "scope_clear", "scope_insert", "receipt_invalidate", "registration_journal", "registration_reconcile", "registration_audit":
			default:
				return time.Time{}, kaname.ErrSourceUnconfirmed
			}
			if err := prepared.applyDirectCommand(ctx, tx, command, values.TransactionAt); err != nil {
				return time.Time{}, err
			}
		}
	}
	var complete bool
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_child_registration_complete_v1()`).Scan(&complete); err != nil {
		return time.Time{}, err
	}
	if !complete {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return values.SourceVersion.UTC(), nil
}
