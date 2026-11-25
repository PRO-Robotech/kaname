// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Обёртка считает настоящий SQL на прежнем pgx.Tx: Conn, signed proof и locks
// сохраняются. Никакие результаты чтения или allow ответы не подменяются.
type accessSnapshotCountingTx struct {
	pgx.Tx
	bindingReads, nativeSourceReads, applyScanWidth, ordinaryScanWidth int
}
type accessSnapshotCountingRow struct {
	pgx.Row
	width *int
}

func (r accessSnapshotCountingRow) Scan(dest ...any) error {
	*r.width = len(dest)
	return r.Row.Scan(dest...)
}
func (c *accessSnapshotCountingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if sql == roleAccessLabelSourceSQL {
		c.nativeSourceReads++
	}
	if sql == accessLabelBindingSnapshotSQL {
		c.bindingReads++
	}
	row := c.Tx.QueryRow(ctx, sql, args...)
	if sql == roleProjectionWithAccessLabelsSQL {
		return accessSnapshotCountingRow{Row: row, width: &c.applyScanWidth}
	}
	if sql == roleProjectionSnapshotSQL {
		return accessSnapshotCountingRow{Row: row, width: &c.ordinaryScanWidth}
	}
	return row
}

// Произвольная реализация публичного интерфейса намеренно лжёт об attestation.
// Настоящий adapter обязан отвергнуть её по private dynamic type до SQL.
type forgedAccessLabelSourceReceipt struct {
	snapshot kaname.AccessLabelBindingSourceSnapshot
}

func (r forgedAccessLabelSourceReceipt) Snapshot() kaname.AccessLabelBindingSourceSnapshot {
	return r.snapshot
}
func (r forgedAccessLabelSourceReceipt) Validate(kaname.SemanticAuthorityWriter, domain.Subject, time.Time, domain.AccessBinding, int) error {
	return nil
}

func PreparedRoleSourceSnapshotConformanceForTest(t *testing.T, ctx context.Context, writer kaname.SemanticAuthorityWriter, actor domain.Subject, applyRole, ordinaryRole domain.RoleID, bindingID domain.AccessBindingID, wantCapture, negatives bool) {
	t.Helper()
	w, ok := writer.(*preparedRoleWriteTx)
	require.True(t, ok, "обычный RoleMutationWriter возвращает настоящий prepared writer")
	require.False(t, w.closed)
	require.Equal(t, actor, w.stage.plan.request.actor)
	require.True(t, w.policyGuards[subjectPolicyKey(actor)])
	require.True(t, w.policyGuards["role:"+string(applyRole)])
	require.Same(t, w.stage.plan.nativeBudget, w.producerBudget)
	require.Same(t, w.stage.plan.nativeBudget, w.nativeRead.budget)
	// Runtime получает финальное время через штатный fence. Точный stamp
	// подтверждает, что подписанная программа уже выбрала эффекты.
	signedAt := w.fence.decisionAt
	require.False(t, signedAt.IsZero())
	input, err := roleSequenceInput(w.stage.request)
	require.NoError(t, err)
	var stamp time.Time
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`, input).Scan(&stamp))
	require.False(t, stamp.IsZero(), "signed role program действительно finalized")

	original := w.tx
	counted := &accessSnapshotCountingTx{Tx: original}
	w.tx = counted
	defer func() { w.tx = original }()
	budget := w.stage.plan.nativeBudget
	// Реальный snapshot с сохранёнными stamps всё ещё отдаёт восемь колонок.
	beforeRows, beforeReads := budget.RemainingRows(), budget.RemainingReads()
	roleSnapshot, cost, err := w.RoleProjectionCheckpointSource(ctx, applyRole)
	require.NoError(t, err)
	require.Equal(t, 8, counted.applyScanWidth)
	require.Equal(t, 5, cost.Reads)
	require.NoError(t, w.ChargeSourceRead(cost))
	require.Equal(t, beforeRows-cost.Rows, budget.RemainingRows())
	require.Equal(t, beforeReads-cost.Reads, budget.RemainingReads())
	var roleXmin, roleCTID string
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT xmin::text,ctid::text FROM kaname.roles WHERE id=$1`, applyRole).Scan(&roleXmin, &roleCTID))
	require.Equal(t, roleXmin, roleSnapshot.RowXmin)
	require.Equal(t, roleCTID, roleSnapshot.RowCTID)
	_, absentCost, absentErr := w.RoleProjectionCheckpointSource(ctx, "rol_snapshot_unheld")
	require.ErrorIs(t, absentErr, kaname.ErrSourceUnconfirmed)
	require.Equal(t, kaname.SourceReadCost{}, absentCost, "нет held role guard — нет SQL")
	_, ordinaryCost, err := w.RoleProjectionCheckpoint(ctx, ordinaryRole)
	require.NoError(t, err)
	require.Equal(t, 2, ordinaryCost.Reads, "обычный checkpoint не получил дополнительных чтений")
	require.Equal(t, 7, counted.ordinaryScanWidth)
	require.NoError(t, w.ChargeSourceRead(ordinaryCost))

	beforeBindingReads := counted.bindingReads
	proof, err := grantpolicy.CollectWitnessedLowerBound(ctx, w, actor)
	require.NoError(t, err)
	var source *grantsource.BindingSource
	for _, binding := range proof.Census().Bindings {
		if binding.Source.Binding.ID == bindingID {
			copy := binding.Source
			source = &copy
			break
		}
	}
	require.NotNil(t, source, "actor действительно имеет исходную apply роль даже при ordinary proposal")
	require.NotNil(t, source.RoleSnapshot)
	require.Equal(t, roleSnapshot, *source.RoleSnapshot)
	require.Len(t, source.Binding.Subjects, 2, "полный набор не сокращён до actor")
	require.Equal(t, wantCapture, w.AccessLabelBindingSourcesEnabled())
	if !wantCapture {
		require.Nil(t, source.BindingSnapshot)
		require.Equal(t, beforeBindingReads, counted.bindingReads, "apply источник actor не включает чтения для ordinary/metadata mutation")
		receipt, disabledCost, err := w.CaptureAccessLabelBindingSource(ctx, actor, signedAt, source.Binding, 1)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.Nil(t, receipt)
		require.Equal(t, kaname.SourceReadCost{}, disabledCost)
		require.Equal(t, beforeBindingReads, counted.bindingReads)
		// Наличие apply источника не включает native reader для ordinary proposal.
		allowed, nativeCost, nativeErr := w.CheckAccessLabelSource(ctx, actor, signedAt, kaname.AccessLabelSourceCandidate{})
		require.ErrorIs(t, nativeErr, kaname.ErrSourceUnconfirmed)
		require.False(t, allowed)
		require.Equal(t, kaname.SourceReadCost{}, nativeCost)
		require.Zero(t, counted.nativeSourceReads)
		return
	}
	require.Equal(t, beforeBindingReads+1, counted.bindingReads)
	require.NotNil(t, source.BindingSnapshot)
	require.NoError(t, source.BindingSnapshot.Validate(w, actor, signedAt, source.Binding, 1))
	observed := source.BindingSnapshot.Snapshot()
	var bindingXmin, bindingCTID string
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT xmin::text,ctid::text FROM kaname.access_bindings WHERE id=$1`, bindingID).Scan(&bindingXmin, &bindingCTID))
	require.Equal(t, bindingID, observed.BindingID)
	require.Equal(t, applyRole, observed.RoleID)
	require.Equal(t, bindingXmin, observed.RowXmin)
	require.Equal(t, bindingCTID, observed.RowCTID)
	require.Equal(t, 1, observed.CapabilityVersion)
	receipt, exactCost, err := w.CaptureAccessLabelBindingSource(ctx, actor, signedAt, source.Binding, 1)
	require.NoError(t, err)
	require.Equal(t, kaname.SourceReadCost{Rows: 3, Reads: 1}, exactCost)
	beforeRows, beforeReads = budget.RemainingRows(), budget.RemainingReads()
	require.NoError(t, w.ChargeSourceRead(exactCost))
	require.Equal(t, beforeRows-3, budget.RemainingRows())
	require.Equal(t, beforeReads-1, budget.RemainingReads())
	// Другая dynamic writer identity не может предъявить receipt того же TX.
	wrapped := &struct{ kaname.SemanticAuthorityWriter }{w}
	require.ErrorIs(t, receipt.Validate(wrapped, actor, signedAt, source.Binding, 1), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, receipt.Validate(w, actor, signedAt.Add(time.Microsecond), source.Binding, 1), kaname.ErrSourceUnconfirmed)
	// Кандидат берётся из реального сохранённого census, а не собирается из
	// свободного rule fingerprint. Предлагаемая роль задаёт только exact вопрос.
	var candidate kaname.AccessLabelSourceCandidate
	foundCandidate := false
	for _, compiled := range proof.Census().Bindings {
		if compiled.Source.Binding.ID != bindingID || compiled.Source.Recipient != actor {
			continue
		}
		for _, effect := range compiled.Effects.Effects() {
			if effect.Kind != granteffect.ApplyAccessLabel || effect.Condition != (granteffect.Condition{}) {
				continue
			}
			declared := false
			for _, capability := range w.stage.projection.Capabilities {
				if capability.Kind == domain.GrantCapabilityApplyAccessLabel && capability.DefinitionID == effect.DefinitionID {
					declared = true
					break
				}
			}
			if !declared {
				continue
			}
			require.NotNil(t, compiled.Source.RoleSnapshot)
			require.NotNil(t, compiled.Source.BindingSnapshot)
			candidate = kaname.AccessLabelSourceCandidate{
				Binding: compiled.Source.Binding, BindingSnapshot: compiled.Source.BindingSnapshot,
				RoleSnapshot: *compiled.Source.RoleSnapshot, BindingID: bindingID,
				Recipient: actor, RoleID: applyRole, Checkpoint: compiled.Source.RoleSnapshot.Checkpoint,
				Provenance: effect.Provenance, Scope: effect.Anchor, DefinitionID: effect.DefinitionID,
			}
			foundCandidate = true
			break
		}
		if foundCandidate {
			break
		}
	}
	require.True(t, foundCandidate, "реальная compiled apply source совпадает с объявленным вопросом")
	beforeRows, beforeReads = budget.RemainingRows(), budget.RemainingReads()
	beforeNativeReads := counted.nativeSourceReads
	beforeBindingReads = counted.bindingReads
	allowed, nativeCost, nativeErr := w.CheckAccessLabelSource(ctx, actor, signedAt, candidate)
	require.NoError(t, nativeErr)
	require.True(t, allowed, "Go adapter получает exact allow от runtime SECURITY DEFINER bridge")
	require.Equal(t, beforeNativeReads+1, counted.nativeSourceReads)
	require.Equal(t, beforeBindingReads, counted.bindingReads, "проверка не перечитывает captured binding snapshot")
	require.GreaterOrEqual(t, nativeCost.Rows, kaname.AccessLabelSourceMinimumRows)
	require.Equal(t, kaname.AccessLabelSourceReads, nativeCost.Reads)
	require.Equal(t, beforeRows, budget.RemainingRows(), "reader возвращает расход; начисляет caller")
	require.Equal(t, beforeReads, budget.RemainingReads())
	require.NoError(t, w.ChargeSourceRead(nativeCost))
	require.Equal(t, beforeRows-nativeCost.Rows, budget.RemainingRows())
	require.Equal(t, beforeReads-nativeCost.Reads, budget.RemainingReads())

	// Отказы проверяются без SQL: PostgreSQL transaction остаётся пригодной
	// для прежних snapshot/budget проверок ниже.
	for _, mismatch := range []string{"forged-receipt", "wrong-clock", "wrong-writer", "post-role-DML"} {
		bad := candidate
		checkWriter, checkAt := w, signedAt
		savedRoleWriteStarted := w.roleWriteStarted
		switch mismatch {
		case "forged-receipt":
			bad.BindingSnapshot = forgedAccessLabelSourceReceipt{snapshot: candidate.BindingSnapshot.Snapshot()}
		case "wrong-clock":
			checkAt = signedAt.Add(time.Microsecond)
		case "wrong-writer":
			copy := *w
			checkWriter = &copy
		case "post-role-DML":
			w.roleWriteStarted = true
		}
		beforeRows, beforeReads = budget.RemainingRows(), budget.RemainingReads()
		beforeNativeReads = counted.nativeSourceReads
		badAllowed, badCost, badErr := checkWriter.CheckAccessLabelSource(ctx, actor, checkAt, bad)
		w.roleWriteStarted = savedRoleWriteStarted
		require.ErrorIs(t, badErr, kaname.ErrSourceUnconfirmed, mismatch)
		require.False(t, badAllowed, mismatch)
		require.Equal(t, kaname.SourceReadCost{}, badCost, mismatch)
		require.Equal(t, beforeNativeReads, counted.nativeSourceReads, mismatch)
		require.Equal(t, beforeRows, budget.RemainingRows(), mismatch)
		require.Equal(t, beforeReads, budget.RemainingReads(), mismatch)
	}
	// Политика роли должна использовать тот же exact source path, включая
	// actor, заявленный вопрос, текущий binding и общий budget.
	beforeNativeReads = counted.nativeSourceReads
	require.NoError(t, grantpolicy.RequireRole(ctx, w, actor, w.stage.request.Role, w.stage.request.Create))
	require.Equal(t, beforeNativeReads+1, counted.nativeSourceReads)
	if !negatives {
		return
	}
	for _, change := range []string{"header", "subjects"} {
		altered := source.Binding
		if change == "header" {
			altered.Labels = domain.Labels{"changed": "yes"}
		} else {
			altered.Subjects = altered.Subjects[:1]
		}
		bad, badCost, err := w.CaptureAccessLabelBindingSource(ctx, actor, signedAt, altered, 1)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, change)
		require.Nil(t, bad)
		require.Equal(t, kaname.SourceReadCost{Rows: 3, Reads: 1}, badCost)
		require.NoError(t, w.ChargeSourceRead(badCost), "mismatch тоже расходует общий бюджет")
	}
	// Две оставшиеся строки не вмещают header+двух получателей. Sentinel
	// запрещает частичный receipt и сохраняет стоимость уже выполненного SQL.
	require.NoError(t, w.ChargeSourceRead(kaname.SourceReadCost{Rows: budget.RemainingRows() - 2}))
	bad, limitedCost, err := w.CaptureAccessLabelBindingSource(ctx, actor, signedAt, source.Binding, 1)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Nil(t, bad)
	require.Equal(t, kaname.SourceReadCost{Rows: 3, Reads: 1}, limitedCost)
	require.ErrorIs(t, w.ChargeSourceRead(limitedCost), kaname.ErrSourceReadLimit)
}
