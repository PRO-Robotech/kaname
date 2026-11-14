// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type optionalReferenceProbeTx struct {
	pgx.Tx
	exists bool
	err    error
	reads  int
}

func (tx *optionalReferenceProbeTx) QueryRow(context.Context, string, ...any) pgx.Row {
	tx.reads++
	return optionalReferenceProbeRow{exists: tx.exists, err: tx.err}
}

type optionalReferenceProbeRow struct {
	exists bool
	err    error
}

func (row optionalReferenceProbeRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	*dest[0].(*bool) = row.exists
	return nil
}
func optionalReferenceProbeRequest() policyWriteRequest {
	m := domain.GroupMember{GroupID: domain.GroupID(ids.NewID(domain.PrefixGroup)), MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(ids.NewID(domain.PrefixServiceAccount))}
	return policyWriteRequest{
		actor: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(ids.NewID(domain.PrefixUser))},
		kind:  kaname.AuthorityGroup, groupID: m.GroupID,
		mutationSubjects: []domain.Subject{{Type: m.MemberType, ID: m.MemberID}},
		owners:           []kaname.AuthorityOwnerRef{{Kind: "group", ID: string(m.GroupID)}, {Kind: "service_account", ID: string(m.MemberID)}},
		groupNative:      &groupAdditionNativeRequest{member: m},
	}
}

// Ошибка чтения, исчерпанный бюджет и отсутствующий actor не дают права
// ослабить обязательный owner lookup. Только точный отрицательный ответ
// для новой ссылки порождает отдельный witness.
func TestGroupAdditionOptionalReferenceQualification(t *testing.T) {
	in := optionalReferenceProbeRequest()
	for _, present := range []bool{false, true} {
		tx := &optionalReferenceProbeTx{exists: present}
		out, witness, rows, err := discoverGroupAdditionReference(context.Background(), tx, in, &relverdict.AdministrativeReadBudget{})
		require.NoError(t, err)
		require.Equal(t, 1, rows)
		require.Len(t, in.owners, 2)
		require.Equal(t, in.mutationSubjects, out.mutationSubjects)
		if present {
			require.Nil(t, witness)
			require.Equal(t, in.owners, out.owners)
			require.False(t, out.global)
		} else {
			require.NotNil(t, witness)
			require.True(t, out.global)
			require.Equal(t, in.owners[:1], out.owners)
			require.True(t, witness.excludes(subjectPolicyKey(in.mutationSubjects[0])))
			require.False(t, witness.excludes(subjectPolicyKey(in.actor)))
			require.False(t, witness.excludes("*"))
		}
	}
	readErr := errors.New("optional reference read failed")
	tx := &optionalReferenceProbeTx{err: readErr}
	out, witness, _, err := discoverGroupAdditionReference(context.Background(), tx, in, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, readErr)
	require.Nil(t, witness)
	require.Equal(t, in.owners, out.owners)
	budget := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(100000, 0))
	tx = &optionalReferenceProbeTx{}
	_, witness, _, err = discoverGroupAdditionReference(context.Background(), tx, in, budget)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Nil(t, witness)
	require.Zero(t, tx.reads)
	in.actor = in.mutationSubjects[0]
	out, witness, _, err = discoverGroupAdditionReference(context.Background(), tx, in, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Nil(t, witness)
	require.Equal(t, in.owners, out.owners)
	require.Zero(t, tx.reads)
}

// Появившаяся после RR ссылка требует restage, а ошибка повторного чтения
// остаётся ошибкой. Ни один исход не превращается в reference refusal здесь.
func TestGroupAdditionOptionalReferenceRecheckRequiresUnchangedAbsence(t *testing.T) {
	witness := &groupAdditionReferenceWitness{serviceAccountID: ids.NewID(domain.PrefixServiceAccount)}
	tx := &optionalReferenceProbeTx{}
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: kaname.AuthorityFenceGlobal}}
	require.NoError(t, witness.recheck(context.Background(), writer, &relverdict.AdministrativeReadBudget{}))
	tx.exists = true
	require.ErrorIs(t, witness.recheck(context.Background(), writer, &relverdict.AdministrativeReadBudget{}), kaname.ErrAuthorityClassificationChanged)
	tx.err = errors.New("presence recheck failed")
	require.ErrorIs(t, witness.recheck(context.Background(), writer, &relverdict.AdministrativeReadBudget{}), tx.err)
	writer.fence.mode = kaname.AuthorityFenceAccounts
	reads := tx.reads
	require.ErrorIs(t, witness.recheck(context.Background(), writer, &relverdict.AdministrativeReadBudget{}), kaname.ErrSourceUnconfirmed)
	require.Equal(t, reads, tx.reads)
}
