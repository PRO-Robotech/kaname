// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func childQuotaRuntimeFixture(t *testing.T, rule catalog.ChildRegistrationRule) (protocolRig, *kanamepg.ResourceDecisionRunner, context.Context, operations.Principal) {
	t.Helper()
	r, owner, _, principal := childStageFixtureWithPolicy(t, rule, "container-one", "container-two")
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	ctx := operations.WithPrincipal(r.ctx, principal)
	runner, err := kanamepg.NewResourceDecisionRunner(ctx, full, r.bundle, authzguard.NewRelationWriteGate(delegationNativeDoor{r}))
	require.NoError(t, err)
	return r, runner, ctx, principal
}

func childQuotaInput(id string) kaname.UserChildRegistrationInput {
	return kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: id}
}

func childQuotaRequireReason(t *testing.T, r protocolRig, principal operations.Principal, reason string, want int) {
	t.Helper()
	var count int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox
 WHERE event_type='iam.child_registration.refused' AND event_payload->>'actor'=$1
 AND event_payload->>'reason'=$2 AND event_payload->>'outcome'='permission_denied'`, "user:"+principal.ID, reason).Scan(&count))
	require.Equal(t, want, count, "durable отказ сохраняет точную внутреннюю причину")
}

func childQuotaReceiptSnapshot(t *testing.T, r protocolRig) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY child_type,child_id,source_version),'[]')
 FROM kaname.authority_child_creation c`).Scan(&raw))
	return raw
}

func TestUserChildRuntimeCapacityLastSlotSerializesAndIsolatesParents(t *testing.T) {
	rule := catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 2, MaxCreates: 100, WindowSeconds: 1}
	r, runner, ctx, principal := childQuotaRuntimeFixture(t, rule)
	seed := childQuotaInput("container-one/seed")
	seedVersion, err := runner.RunUserChildRegistration(ctx, seed, principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, seedVersion.IsZero())
	inputs := [2]kaname.UserChildRegistrationInput{childQuotaInput("container-one/contender-a"), childQuotaInput("container-one/contender-b")}
	type outcome struct {
		index   int
		version time.Time
		err     error
	}
	start := make(chan struct{})
	done := make(chan outcome, 2)
	raceCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for i, input := range inputs {
		go func(index int, in kaname.UserChildRegistrationInput) {
			<-start
			version, callErr := runner.RunUserChildRegistration(raceCtx, in, principal)
			done <- outcome{index, version, callErr}
		}(i, input)
	}
	close(start)
	winner, loser := -1, -1
	var winnerVersion time.Time
	for range inputs {
		var got outcome
		select {
		case got = <-done:
		case <-raceCtx.Done():
			t.Fatal("capacity race did not finish")
		}
		if got.err == nil {
			require.Equal(t, -1, winner, "только последний свободный слот может быть принят")
			winner, winnerVersion = got.index, got.version
			require.False(t, got.version.IsZero())
		} else {
			require.ErrorIs(t, got.err, domain.ErrUserChildRegistrationRefused)
			require.Equal(t, domain.ErrUserChildRegistrationRefused.Error(), got.err.Error())
			require.True(t, got.version.IsZero())
			require.Equal(t, -1, loser)
			loser = got.index
		}
	}
	require.NotEqual(t, -1, winner)
	require.NotEqual(t, -1, loser)
	childQuotaRequireReason(t, r, principal, "capacity", 1)
	var children, receipts, loserMirror, loserReceipt, loserFGA int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type='childstage.child' AND object_id LIKE 'container-one/%'),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='childstage.child' AND child_id LIKE 'container-one/%'),
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type='childstage.child' AND object_id=$1),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='childstage.child' AND child_id=$1),
 (SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='childstage_child:'||$1)`, inputs[loser].ResourceID).Scan(&children, &receipts, &loserMirror, &loserReceipt, &loserFGA))
	require.Equal(t, 2, children)
	require.Equal(t, 2, receipts)
	require.Zero(t, loserMirror)
	require.Zero(t, loserReceipt)
	require.Zero(t, loserFGA)
	beforeReplay := childQuotaReceiptSnapshot(t, r)
	replay, err := runner.RunUserChildRegistration(ctx, inputs[winner], principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.True(t, winnerVersion.Equal(replay), "replay разрешён даже при заполненной capacity")
	require.JSONEq(t, string(beforeReplay), string(childQuotaReceiptSnapshot(t, r)))
	independent, err := runner.RunUserChildRegistration(ctx, childQuotaInput("container-two/independent"), principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, independent.IsZero())
	var incarnations int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(DISTINCT parent_incarnation) FROM kaname.authority_child_creation
 WHERE child_type='childstage.child'`).Scan(&incarnations))
	require.Equal(t, 2, incarnations, "квоты привязаны к разным инкарнациям родителей")
	childQuotaRequireReason(t, r, principal, "capacity", 1)
	authorityWaitReleased(t, r.runtime)
}

func TestUserChildRuntimeRateUsesPostgresRollingWindowAndIsolatesParents(t *testing.T) {
	// Короткое окно является настоящей подписанной политикой этого fixture.
	// Производственные часы/квитанции не подменяются и не переписываются.
	rule := catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 10, MaxCreates: 1, WindowSeconds: 5}
	r, runner, ctx, principal := childQuotaRuntimeFixture(t, rule)
	first := childQuotaInput("container-one/rate-first")
	version, err := runner.RunUserChildRegistration(ctx, first, principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	var firstReceipt json.RawMessage
	var createdAt, expiresAt time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(c),created_at,created_at+make_interval(secs=>$4)
 FROM kaname.authority_child_creation c WHERE child_type=$1 AND child_id=$2 AND source_version=$3`, first.ResourceType, first.ResourceID, version, rule.WindowSeconds).Scan(&firstReceipt, &createdAt, &expiresAt))
	candidate := childQuotaInput("container-one/rate-retry")
	rejected, err := runner.RunUserChildRegistration(ctx, candidate, principal)
	require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
	require.Equal(t, domain.ErrUserChildRegistrationRefused.Error(), err.Error())
	require.True(t, rejected.IsZero())
	childQuotaRequireReason(t, r, principal, "rate", 1)
	var absent bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 NOT EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2)
 AND NOT EXISTS(SELECT 1 FROM kaname.authority_child_creation WHERE child_type=$1 AND child_id=$2)
 AND NOT EXISTS(SELECT 1 FROM kaname.fga_outbox WHERE payload->>'object'='childstage_child:'||$2)`, candidate.ResourceType, candidate.ResourceID).Scan(&absent))
	require.True(t, absent, "rate refusal не создаёт регистрацию, квитанцию или FGA effect")
	independent, err := runner.RunUserChildRegistration(ctx, childQuotaInput("container-two/rate-independent"), principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, independent.IsZero(), "расход parent-one не затрагивает parent-two")
	beforeWait := childQuotaReceiptSnapshot(t, r)
	var secondsRemaining float64
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT greatest(extract(epoch FROM ($1::timestamptz-clock_timestamp())),0)::double precision`, expiresAt).Scan(&secondsRemaining))
	// Deadline выведен из серверного остатка окна. Ожидает только observer;
	// production runner не получает fake clock и не выполняет sleep.
	waitCtx, cancel := context.WithTimeout(r.ctx, time.Duration(secondsRemaining*float64(time.Second))+5*time.Second)
	defer cancel()
	_, err = r.admin.Exec(waitCtx, `SELECT pg_sleep_until($1::timestamptz)`, expiresAt)
	require.NoError(t, err)
	require.JSONEq(t, string(beforeWait), string(childQuotaReceiptSnapshot(t, r)), "течение окна не меняет immutable quota receipts")
	admitted, err := runner.RunUserChildRegistration(ctx, candidate, principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, admitted.IsZero())
	var admittedAt time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT created_at FROM kaname.authority_child_creation
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3`, candidate.ResourceType, candidate.ResourceID, admitted).Scan(&admittedAt))
	require.False(t, admittedAt.Before(expiresAt), "новое решение принято после PostgreSQL-time rolling boundary")
	require.True(t, expiresAt.Equal(createdAt.Add(time.Duration(rule.WindowSeconds)*time.Second)))
	var retained json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(c) FROM kaname.authority_child_creation c
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3`, first.ResourceType, first.ResourceID, version).Scan(&retained))
	require.JSONEq(t, string(firstReceipt), string(retained), "первая квитанция не переписывается для освобождения rate")
	childQuotaRequireReason(t, r, principal, "rate", 1)
	authorityWaitReleased(t, r.runtime)
}
