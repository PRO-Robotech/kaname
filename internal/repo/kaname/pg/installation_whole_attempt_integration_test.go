// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestCatalogWholeAttemptCommitRetryReportReset(t *testing.T) {
	r := writerProtocolRig(t)
	_, contract := fullContractActivate(t, r)
	store, err := kanamepg.NewCatalogWriteRepo(r.runtime).WithFullWriterContract(contract)
	require.NoError(t, err)
	m := catalogAtomicManifest(t)
	declared, err := modulecatalog.RowsOf(m)
	require.NoError(t, err)
	check := wholeAttemptCommitFault(t, r, "audit_outbox", modulecatalog.AppliedEventType)
	report, err := modulecatalog.NewApplier(store).Apply(r.ctx, m)
	require.NoError(t, err)
	check()
	require.True(t, report.ModuleWritten)
	require.Equal(t, len(declared.Resources), report.WrittenResources, "откаченная попытка не удваивает Report")
	require.Equal(t, len(declared.Verbs), report.WrittenVerbs)
	require.Zero(t, report.UnchangedResources)
	require.Zero(t, report.UnchangedVerbs)
	var events int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1`, modulecatalog.AppliedEventType).Scan(&events))
	require.Equal(t, 1, events)
	require.Equal(t, "transition", catalogIdentityPhase(t, r))
}
