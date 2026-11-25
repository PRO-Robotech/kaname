// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package account

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/stretchr/testify/require"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
)

// Конкурентная смена labels происходит между синхронным Get и открытием
// writer. Дублёр применяет пустую маску как настоящий SQL full-PATCH.
type labelRoutingRepo struct {
	*lcaRepo
	mask   []string
	writes int
}

func (r *labelRoutingRepo) Writer(ctx context.Context) (kaname.Writer, error) {
	r.acct.Labels = domain.Labels{"concurrent": "retained"}
	base, err := r.lcaRepo.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &labelRoutingWriter{Writer: base, repo: r}, nil
}

type labelRoutingWriter struct {
	kaname.Writer
	repo *labelRoutingRepo
}

func (w *labelRoutingWriter) AccountsW() repoaccount.WriterIface {
	return &labelRoutingRow{WriterIface: w.Writer.AccountsW(), repo: w.repo}
}

type labelRoutingRow struct {
	repoaccount.WriterIface
	repo *labelRoutingRepo
}

func (w *labelRoutingRow) Update(_ context.Context, value domain.Account, mask []string) (domain.Account, error) {
	w.repo.mask = append([]string(nil), mask...)
	w.repo.writes++
	if shared.MaskAllows(mask, "labels") {
		w.repo.acct.Labels = value.Labels
	}
	if shared.MaskAllows(mask, "name") {
		w.repo.acct.Name = value.Name
	}
	if shared.MaskAllows(mask, "description") {
		w.repo.acct.Description = value.Description
	}
	return w.repo.acct, nil
}

type labelRoutingOps struct {
	*lcaOps
	done    bool
	failure *gstatus.Status
}

func (o *labelRoutingOps) MarkDone(context.Context, string, *anypb.Any) error {
	o.done = true
	return nil
}
func (o *labelRoutingOps) MarkError(_ context.Context, _ string, failure *gstatus.Status) error {
	o.failure = failure
	return nil
}

func TestUpdateAccountLabelAuthorityRoutingAndOmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mask   []string
		body   domain.Labels
		mode   string
		denied bool
	}{
		{name: "omitted_implicit", mode: "labels"},
		{name: "explicit_description_ignores_labels", mode: "labels", mask: []string{"description"}, body: domain.Labels{"ignored": "value"}},
		{name: "explicit_clear", mode: "labels", mask: []string{"labels"}, denied: true},
		{name: "implicit_non_nil_empty", mode: "labels", body: domain.Labels{}, denied: true},
		{name: "implicit_labels", mode: "labels", body: domain.Labels{"new": "value"}, denied: true},
		{name: "unchanged_labels_still_protected", mode: "labels", body: domain.Labels{"old": "snapshot"}, denied: true},
		{name: "all_metadata_still_protects_description", mode: "metadata", mask: []string{"description"}, denied: true},
		{name: "metadata_overrides_label_mode", mode: "metadata_after_labels", denied: true},
		{name: "ordinary_omission_preserves_concurrent_labels", mode: "ordinary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &labelRoutingRepo{lcaRepo: newLcaRepo(domain.Labels{"old": "snapshot"})}
			ops := &labelRoutingOps{lcaOps: newLcaOps()}
			uc := NewUpdateAccountUseCase(repo, ops)
			switch tc.mode {
			case "labels":
				uc.WithAccountLabelAuthorityWriter(nil)
			case "metadata":
				uc.WithAccountMetadataWriter(nil)
			case "metadata_after_labels":
				uc.WithAccountLabelAuthorityWriter(nil).WithAccountMetadataWriter(nil)
			}
			ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: lcaOwnerID})
			description := domain.Description("updated description")
			inputMask := append([]string(nil), tc.mask...)
			op, err := uc.Execute(ctx, UpdateAccountInput{ID: lcaAcctID, Description: &description, Labels: tc.body, UpdateMask: inputMask})
			require.NoError(t, err)
			require.NotNil(t, op)
			wait, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			require.NoError(t, operations.Wait(wait))
			require.Equal(t, tc.mask, inputMask, "маска вызывающего не изменяется")
			if tc.denied {
				require.False(t, ops.done)
				require.NotNil(t, ops.failure)
				require.Equal(t, int32(codes.Unavailable), ops.failure.Code)
				require.Zero(t, repo.writes, "защищённый отказ не переходит к обычному writer")
				require.Equal(t, domain.Labels{"old": "snapshot"}, repo.acct.Labels)
			} else {
				require.True(t, ops.done)
				require.Nil(t, ops.failure)
				require.Equal(t, 1, repo.writes)
				require.Equal(t, description, repo.acct.Description)
				require.Equal(t, domain.Labels{"concurrent": "retained"}, repo.acct.Labels)
				wantMask := tc.mask
				if len(wantMask) == 0 {
					wantMask = []string{"name", "description"}
				}
				require.Equal(t, wantMask, repo.mask)
			}
			require.Empty(t, repo.reconciled(), "description или отказ не создаёт label reconcile")
		})
	}
}
