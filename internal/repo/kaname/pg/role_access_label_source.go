// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
)

// Узкий runtime-вход вызывает закрытую проверку источника в программе роли.
// Вызов private checker напрямую не является допустимым runtime fallback.
const roleAccessLabelSourceSQL = `SELECT kaname.authority_role_access_label_source_read_v1(
 $1::text,$2::text,$3::text,$4::timestamptz,
 $5::text,$6::text,$7::text,$8::text,$9::text,$10::text,
 $11::text,$12::text,$13::text,$14::text,$15::uuid,$16::text,
 $17::jsonb,$18::integer,$19::integer)`

func accessLabelSourceDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}
func accessLabelSourceStamp(xmin, ctid string) bool {
	xid, err := strconv.ParseUint(xmin, 10, 32)
	if err != nil || xid == 0 || strconv.FormatUint(xid, 10) != xmin || len(ctid) < 5 || ctid[0] != '(' || ctid[len(ctid)-1] != ')' {
		return false
	}
	parts := strings.Split(ctid[1:len(ctid)-1], ",")
	if len(parts) != 2 {
		return false
	}
	block, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return false
	}
	offset, err := strconv.ParseUint(parts[1], 10, 16)
	return err == nil && offset > 0 && fmt.Sprintf("(%d,%d)", block, offset) == ctid
}

// Реализация есть только у подготовленной role mutation. Общий semantic writer
// и preplanned публичный порт не получают новую SQL-возможность.
// Стоимость возвращается caller: ChargeSourceRead здесь повторно НЕ вызывается.
func (w *preparedRoleWriteTx) CheckAccessLabelSource(ctx context.Context, actor domain.Subject, at time.Time, candidate kaname.AccessLabelSourceCandidate) (bool, kaname.SourceReadCost, error) {
	zero := kaname.SourceReadCost{}
	if err := ctx.Err(); err != nil {
		return false, zero, err
	}
	if !w.canReadAccessLabelSource() || !w.AccessLabelBindingSourcesEnabled() {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	plan := w.stage.plan
	if (!w.stage.request.Create && !w.stage.request.Rules) || plan.request.kind != kaname.AuthorityRole || actor != plan.request.actor || actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) || at.IsZero() || !at.Equal(w.fence.decisionAt) || !nativeQuestionToken(string(actor.ID)) || !nativeQuestionToken(string(w.stage.request.Role.ID)) {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	budget := plan.nativeBudget
	if budget == nil || w.producerBudget != budget || w.nativeRead.budget != budget || w.nativeRead.boundary != plan.native {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityApplyAccessLabel, Anchor: candidate.Scope, DefinitionID: candidate.DefinitionID})
	if err != nil {
		return false, zero, err
	}
	if err = w.nativeRead.boundary.requireQuestion(w.bundle, string(actor.Type)+":"+string(actor.ID), ref.Relation, ref.Object()); err != nil {
		return false, zero, err
	}
	recipient := candidate.Recipient
	if recipient.Validate() != nil || !nativeQuestionToken(string(recipient.ID)) || (recipient.Type != domain.SubjectTypeGroup && recipient != actor) || (recipient.Type == domain.SubjectTypeGroup && !w.policyGuards["group:"+string(recipient.ID)]) || !w.policyGuards[subjectPolicyKey(actor)] || !nativeQuestionToken(string(candidate.BindingID)) || !nativeQuestionToken(string(candidate.RoleID)) || !w.policyGuards["role:"+string(candidate.RoleID)] {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	origin, checkpoint := candidate.Provenance, candidate.Checkpoint
	if origin.SourceID != string(candidate.BindingID) || origin.RoleID != candidate.RoleID || origin.Primitive != "explicit_meta" || origin.AuthoredRuleFP != origin.ProjectedRuleFP || !accessLabelSourceDigest(origin.AuthoredRuleFP) || checkpoint.ModelID != w.bundle.Identity().ModelID || checkpoint.ProjectorVersion != granteffect.ProjectorVersion || !accessLabelSourceDigest(checkpoint.AuthoredID) || !accessLabelSourceDigest(checkpoint.RelevantCatalogID) || !accessLabelSourceDigest(checkpoint.ProjectionID) {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	// Поколения не принимаются как свободные строки от caller: binding receipt
	// обязан принадлежать этой попытке и тому же полному исходному образу.
	receipt, captured := candidate.BindingSnapshot.(*capturedAccessLabelBindingSource)
	if !captured || receipt == nil || candidate.Binding.ID != candidate.BindingID ||
		candidate.Binding.RoleID != candidate.RoleID || candidate.RoleSnapshot.RoleID != candidate.RoleID ||
		candidate.RoleSnapshot.Checkpoint != checkpoint ||
		candidate.Binding.ResourceID != candidate.Scope.ID || string(candidate.Binding.ResourceType) != candidate.Scope.Type ||
		!slices.Contains(candidate.Binding.Subjects, recipient) ||
		candidate.Binding.Status != domain.AccessBindingStatusActive || candidate.Binding.RevokedAt != nil ||
		(candidate.Binding.ExpiresAt != nil && !candidate.Binding.ExpiresAt.After(at)) || len(candidate.Binding.Target.Resources) != 0 {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	if err = receipt.Validate(w, actor, at, candidate.Binding, 1); err != nil {
		return false, zero, err
	}
	bindingSnapshot := receipt.Snapshot()
	roleSnapshot := candidate.RoleSnapshot
	if bindingSnapshot.BindingID != candidate.BindingID || bindingSnapshot.RoleID != candidate.RoleID || bindingSnapshot.CapabilityVersion != 1 ||
		!accessLabelSourceStamp(bindingSnapshot.RowXmin, bindingSnapshot.RowCTID) || !accessLabelSourceStamp(roleSnapshot.RowXmin, roleSnapshot.RowCTID) {
		return false, zero, kaname.ErrSourceUnconfirmed
	}
	rawCheckpoint, err := json.Marshal(checkpoint)
	if err != nil {
		return false, zero, err
	}
	rowsLeft, readsLeft := budget.RemainingRows(), budget.RemainingReads()
	if rowsLeft < kaname.AccessLabelSourceMinimumRows || readsLeft < kaname.AccessLabelSourceReads {
		return false, zero, kaname.ErrSourceReadLimit
	}
	// На SQL-ошибке неизвестные фактические расходы не превращаются в ноль.
	cost := kaname.SourceReadCost{Rows: rowsLeft, Reads: readsLeft}
	var raw []byte
	err = w.tx.QueryRow(ctx, roleAccessLabelSourceSQL,
		string(w.stage.request.Role.ID), string(actor.Type), string(actor.ID), at,
		string(candidate.BindingID), bindingSnapshot.RowXmin, bindingSnapshot.RowCTID,
		string(candidate.RoleID), roleSnapshot.RowXmin, roleSnapshot.RowCTID,
		string(recipient.Type), string(recipient.ID), candidate.Scope.Type, candidate.Scope.ID,
		string(candidate.DefinitionID), origin.AuthoredRuleFP, rawCheckpoint, rowsLeft, readsLeft).Scan(&raw)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "54000" {
			cost.Rows = rowsLeft + 1
			return false, cost, errors.Join(kaname.ErrSourceReadLimit, err)
		}
		return false, cost, errors.Join(kaname.ErrSourceUnconfirmed, err)
	}
	if len(raw) == 0 || len(raw) > 4096 {
		return false, cost, kaname.ErrCanonicalSourceInvalid
	}
	var result struct {
		Allowed *bool `json:"allowed"`
		Rows    *int  `json:"rows"`
		Reads   *int  `json:"reads"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return false, cost, kaname.ErrCanonicalSourceInvalid
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || result.Allowed == nil || result.Rows == nil || result.Reads == nil || *result.Rows < kaname.AccessLabelSourceMinimumRows || *result.Reads != kaname.AccessLabelSourceReads || *result.Rows > rowsLeft || *result.Reads > readsLeft {
		return false, cost, kaname.ErrCanonicalSourceInvalid
	}
	cost = kaname.SourceReadCost{Rows: *result.Rows, Reads: *result.Reads}
	if err = ctx.Err(); err != nil {
		return false, cost, err
	}
	return *result.Allowed, cost, nil
}

var _ kaname.AccessLabelSourceReader = (*preparedRoleWriteTx)(nil)
