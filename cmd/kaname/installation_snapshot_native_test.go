// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

type rid08FutureProof struct {
	Initial, Full, Expired, AfterD         rid08Admission
	AccountsN3                             []string
	System, TenantNamedSystem, D, Operator string
	Snapshot                               rid08SnapshotObservation
	RepeatSnapshot                         rid08SnapshotObservation
	DCommitted, Released                   time.Time
	First, Repeat                          rid08PublicProof
	FirstRaw, RepeatRaw                    map[string]string
}
type rid08FaultProof struct {
	Accounts                        []string
	FailedOpsBefore, FailedOpsAfter []string
	FaultGDHistory                  string
	Twin, Retry                     rid08PublicProof
	TwinSnapshot, RetrySnapshot     rid08SnapshotObservation
}
type rid08EmptyProof struct {
	Snapshot                                              rid08SnapshotObservation
	Public, PublicAfterGracefulStop                       rid08PublicProof
	SavedCanonical, AfterPublicRenewal, AfterGracefulStop []rid08AccountRow
	Deleted, Operator                                     string
}

func rid08World(t *testing.T) *installationNativeWorld {
	t.Helper()
	return newInstallationNativeWorldAccountCapacity(t, 7200, "", false, true, 4)
}
func rid08IDs(ids []domain.AccountID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}
func rid08RawRows(t *testing.T, f *installationNativeWorld) map[string]string {
	t.Helper()
	var rows []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(rid08PrimaryGD(t, f)), &rows))
	out := map[string]string{}
	for _, row := range rows {
		var id string
		require.NoError(t, json.Unmarshal(row["id"], &id))
		raw, err := json.Marshal(row)
		require.NoError(t, err)
		require.NotContains(t, out, id)
		out[id] = string(raw)
	}
	return out
}
func rid08SetupN3(t *testing.T, f *installationNativeWorld) ([]string, string, rid08Admission, rid08Admission) {
	t.Helper()
	initial := rid08AdmissionRead(t, f)
	require.True(t, initial.Present)
	require.EqualValues(t, 1, initial.Admitted)
	primary := rid08PrimaryAccounts(t, f)
	require.Equal(t, []string{f.tenantID}, rid08NonSystemIDs(t, primary, f.baseline.SystemID))
	b := rid08CreateAccount(t, f, "rid-b")
	mid := rid08AdmissionRead(t, f)
	require.EqualValues(t, 2, mid.Admitted)
	require.Equal(t, initial.Started, mid.Started)
	require.Equal(t, initial.CarrierDigest, mid.CarrierDigest)
	namedSystem := rid08CreateAccount(t, f, "system-tenant")
	full := rid08AdmissionRead(t, f)
	require.EqualValues(t, 3, full.Admitted)
	require.Equal(t, initial.Started, full.Started)
	require.Equal(t, initial.CarrierDigest, full.CarrierDigest)
	require.NotEqual(t, f.baseline.SystemID, namedSystem)
	ids := []string{f.tenantID, b, namedSystem}
	sort.Strings(ids)
	require.Equal(t, ids, rid08NonSystemIDs(t, rid08PrimaryAccounts(t, f), f.baseline.SystemID))
	rid08Write(t, f.session.Root, "admission-one-two-three", []rid08Admission{initial, mid, full})
	return ids, namedSystem, initial, full
}
func rid08FutureWorld(t *testing.T) *rid08FutureProof {
	t.Helper()
	deadline, ok := t.Deadline()
	require.True(t, ok)
	require.GreaterOrEqual(t, time.Until(deadline), 70*time.Minute, "real hour plus bounded native completion must fit BEFORE creating PG")
	f := rid08World(t)
	ids, namedSystem, initial, full := rid08SetupN3(t, f)
	proof := &rid08FutureProof{Initial: initial, Full: full, AccountsN3: ids, TenantNamedSystem: namedSystem, System: f.baseline.SystemID, Operator: string(f.given.user)}
	rid08RequireAccountCapacity(t, f, 3)
	// Во время этого ожидания по штатным часам нет потомка, транзакции переписи или записи.
	proof.Expired = rid08WaitRealWindow(t, f, full)
	rid08Stage(t, f)
	require.Equal(t, ids, rid08NonSystemIDs(t, rid08PrimaryAccounts(t, f), f.baseline.SystemID))
	before := rid08GDOperations(t, f)
	require.Empty(t, before)
	wire := rid08Wire(t, f)
	child := rid08Start(t, f, "rid08-future", true, false)
	rid08AwaitEvent(t, f, child, "snapshot-complete")
	proof.Snapshot = rid08ReadSnapshot(t, child)
	require.Equal(t, ids, rid08IDs(proof.Snapshot.Accounts))
	require.Equal(t, domain.AccountID(f.baseline.SystemID), proof.Snapshot.System)
	require.Equal(t, 3, proof.Snapshot.Pages)
	require.False(t, proof.Snapshot.CompletedAt.Before(proof.Expired.DBNow))
	require.JSONEq(t, "[]", rid08PrimaryGD(t, f))
	require.Equal(t, before, rid08GDOperations(t, f))
	// Состав учётных записей теперь зафиксирован НАСТОЯЩИМ возвращённым каноническим снимком.
	// D создаётся через ТОГО ЖЕ заново проверенного O до первого освобождения GD.
	proof.D = rid08CreateAccount(t, f, "rid-d")
	proof.DCommitted = time.Now().UTC()
	rid08RequireAccountCapacity(t, f, 4)
	proof.AfterD = rid08AdmissionRead(t, f)
	require.Equal(t, initial.User, proof.AfterD.User)
	require.Equal(t, initial.CarrierDigest, proof.AfterD.CarrierDigest)
	require.EqualValues(t, 1, proof.AfterD.Admitted)
	require.True(t, proof.AfterD.Present)
	require.False(t, proof.AfterD.Started.Before(full.Started.Add(time.Hour)))
	require.NotContains(t, ids, proof.D)
	require.JSONEq(t, "[]", rid08PrimaryGD(t, f))
	require.Equal(t, before, rid08GDOperations(t, f))
	all := append(append([]string{}, ids...), proof.D)
	sort.Strings(all)
	require.Equal(t, all, rid08NonSystemIDs(t, rid08PrimaryAccounts(t, f), f.baseline.SystemID))
	proof.Released = time.Now().UTC()
	child.release(t, "continue")
	rid08Ready(t, f, child, wire, 6)
	proof.First = rid08PublicCensus(t, f, ids)
	proof.FirstRaw = rid08RawRows(t, f)
	firstNewman := rid08NewmanPhase(t, f, "first-n3", ids, nil, namedSystem, proof.D, "")
	rid08NewOperations(t, f, before, 6)
	rid06GracefulStop(t, child)
	repeatBefore := rid08GDOperations(t, f)
	repeat := rid08Start(t, f, "rid08-future-repeat", false, false)
	rid08AwaitEvent(t, f, repeat, "snapshot-complete")
	proof.RepeatSnapshot = rid08ReadSnapshot(t, repeat)
	require.Equal(t, all, rid08IDs(proof.RepeatSnapshot.Accounts))
	require.Equal(t, 3, proof.RepeatSnapshot.Pages)
	rid08Ready(t, f, repeat, wire, 8)
	proof.Repeat = rid08PublicCensus(t, f, all)
	proof.RepeatRaw = rid08RawRows(t, f)
	rid08NewmanPhase(t, f, "repeat-n4", all, firstNewman, namedSystem, proof.D, "")
	rid08NewOperations(t, f, repeatBefore, 8)
	rid06GracefulStop(t, repeat)
	require.Equal(t, proof.First.ServiceAccounts, proof.Repeat.ServiceAccounts)
	for id, raw := range proof.First.Delegations {
		require.Equal(t, raw, proof.Repeat.Delegations[id])
		require.Equal(t, proof.First.Created[id], proof.Repeat.Created[id])
		require.Equal(t, proof.FirstRaw[id], proof.RepeatRaw[id])
	}
	f.requireSameCredential(t)
	rid08Write(t, f.session.Root, "future-account-proof", proof)
	return proof
}
func rid08EmptyWorld(t *testing.T) *rid08EmptyProof {
	t.Helper()
	f := rid08World(t)
	before := rid08PrimaryAccounts(t, f)
	require.Equal(t, []string{f.tenantID}, rid08NonSystemIDs(t, before, f.baseline.SystemID))
	requireNativeNoDelivery(t, f.given)
	// Account.Delete — штатная операция владельца. Она не удаляет человека и должна
	// оставить независимого O живым, без домашней записи и всё ещё текущим кластерным администратором.
	var projects, sas, groups, roles int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.projects WHERE account_id=$1),
 (SELECT count(*) FROM kaname.service_accounts WHERE account_id=$1),
 (SELECT count(*) FROM kaname.groups WHERE account_id=$1),
 (SELECT count(*) FROM kaname.roles WHERE account_id=$1)`, f.tenantID).Scan(&projects, &sas, &groups, &roles))
	require.Zero(t, projects)
	require.Zero(t, sas)
	require.Zero(t, groups)
	require.Zero(t, roles)
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	var op installruntime.Operation
	code, err := f.wire.JSON(ctx, http.MethodDelete, "/iam/v1/accounts/"+f.tenantID, f.operator.Bearer(), nil, &op)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	op, err = f.wire.AwaitOperation(ctx, f.operator.Bearer(), op)
	require.NoError(t, err)
	require.True(t, op.Done)
	require.Nil(t, op.Error)
	var response anypb.Any
	require.NoError(t, protojson.Unmarshal(op.Response, &response))
	require.NoError(t, response.UnmarshalTo(&emptypb.Empty{}))
	f.renewOperator(t, ctx)
	require.Equal(t, string(f.given.user), f.operator.UserID())
	var notFound json.RawMessage
	code, err = f.wire.JSON(ctx, http.MethodGet, "/iam/v1/accounts/"+f.tenantID, f.operator.Bearer(), nil, &notFound)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, code)
	var user, home string
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT id,COALESCE(account_id,'') FROM kaname.users WHERE id=$1`, string(f.given.user)).Scan(&user, &home))
	require.Equal(t, string(f.given.user), user)
	require.Empty(t, home)
	deletedCanonical := rid08PrimaryAccounts(t, f)
	require.Empty(t, rid08NonSystemIDs(t, deletedCanonical, f.baseline.SystemID))
	require.Len(t, deletedCanonical, 1)
	requireNativeAuthority(t, f.given, "user", user, 1)
	requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 1)
	rid08Stage(t, f)
	savedCanonical := rid08PrimaryAccounts(t, f)
	require.Equal(t, deletedCanonical, savedCanonical, "normal staging cannot recreate an account")
	require.Empty(t, rid08NonSystemIDs(t, savedCanonical, f.baseline.SystemID))
	ops := rid08GDOperations(t, f)
	require.Empty(t, ops)
	wire := rid08Wire(t, f)
	child := rid08Start(t, f, "rid08-empty", false, false)
	rid08AwaitEvent(t, f, child, "snapshot-complete")
	snapshot := rid08ReadSnapshot(t, child)
	require.Empty(t, snapshot.Accounts)
	require.Equal(t, domain.AccountID(f.baseline.SystemID), snapshot.System)
	require.Equal(t, 1, snapshot.Pages)
	rid08Ready(t, f, child, wire, 0)
	public := rid08PublicCensus(t, f, nil)
	require.Equal(t, savedCanonical, public.Accounts, "tested startup and public renewal preserve the full SYS-only census")
	afterPublic := rid08RequireEmptyBoundary(t, f, savedCanonical)
	rid08NewmanPhase(t, f, "empty-n0", nil, nil, "", "", f.tenantID)
	require.Empty(t, public.Delegations)
	require.Equal(t, ops, rid08GDOperations(t, f))
	require.JSONEq(t, "[]", rid08PrimaryGD(t, f))
	rid06GracefulStop(t, child)
	afterStop := rid08RequireEmptyBoundary(t, f, savedCanonical)
	publicAfterStop := rid08PublicCensus(t, f, nil)
	require.Equal(t, savedCanonical, publicAfterStop.Accounts, "public census after graceful stop preserves the full SYS-only baseline")
	require.Empty(t, publicAfterStop.Delegations)
	proof := &rid08EmptyProof{Snapshot: snapshot, Public: public, PublicAfterGracefulStop: publicAfterStop, SavedCanonical: savedCanonical, AfterPublicRenewal: afterPublic, AfterGracefulStop: afterStop, Deleted: f.tenantID, Operator: user}
	rid08Write(t, f.session.Root, "empty-census-proof", proof)
	return proof
}

// Обе границы заново проверяют ТОГО ЖЕ штатного O и независимо читают
// полное первичное множество учётных записей. Запись, пересозданная при запуске/обновлении или
// завершении, не может скрыться за пустым списком GD или прежним снимком.
func rid08RequireEmptyBoundary(t *testing.T, f *installationNativeWorld, saved []rid08AccountRow) []rid08AccountRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 15*time.Second)
	defer cancel()
	f.renewOperator(t, ctx)
	require.Equal(t, string(f.given.user), f.operator.UserID())
	var user string
	var homeIsNull bool
	var deletedCount int
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT id,account_id IS NULL,
 (SELECT count(*) FROM kaname.accounts WHERE id=$2)
 FROM kaname.users WHERE id=$1`, string(f.given.user), f.tenantID).Scan(&user, &homeIsNull, &deletedCount))
	require.Equal(t, string(f.given.user), user)
	require.True(t, homeIsNull, "same O remains alive without a home")
	require.Zero(t, deletedCount, "deleted A cannot return")
	current := rid08PrimaryAccounts(t, f)
	require.Equal(t, saved, current, "full SYS-only canonical baseline stays exact")
	require.Empty(t, rid08NonSystemIDs(t, current, f.baseline.SystemID))
	require.NoError(t, ctx.Err())
	return current
}

func rid08FaultWorld(t *testing.T) *rid08FaultProof {
	t.Helper()
	f := rid08World(t)
	ids, namedSystem, _, _ := rid08SetupN3(t, f)
	rid08Stage(t, f)
	canonical := rid08PrimaryAccounts(t, f)
	before := rid08GDOperations(t, f)
	history := rid08PrimaryGD(t, f)
	require.Empty(t, before)
	require.JSONEq(t, "[]", history)
	wire := rid08Wire(t, f)
	watch := wire.StartReadinessWatch(f.given.ctx)
	defer watch.Stop()
	spawned := time.Now().UTC()
	failed := rid08Start(t, f, "rid08-late-page-fault", false, true)
	rid08AwaitEvent(t, f, failed, "second-page-fault")
	rid08FaultExit(t, f, failed, watch, spawned)
	after := rid08GDOperations(t, f)
	require.Equal(t, before, after)
	require.Equal(t, canonical, rid08PrimaryAccounts(t, f))
	require.Equal(t, history, rid08PrimaryGD(t, f))
	proof := &rid08FaultProof{Accounts: ids, FailedOpsBefore: before, FailedOpsAfter: after, FaultGDHistory: history}
	rid08NewmanPhase(t, f, "late-fault-n0", nil, nil, namedSystem, "", "")
	// Тот же мир, манифесты, C/O, множество учётных записей, размер страницы и настоящий запуск. Убран только
	// флаг сбоя второй страницы; без починки состояния или записи разрешений.
	twin := rid08Start(t, f, "rid08-late-page-twin", false, false)
	rid08AwaitEvent(t, f, twin, "snapshot-complete")
	proof.TwinSnapshot = rid08ReadSnapshot(t, twin)
	require.Equal(t, ids, rid08IDs(proof.TwinSnapshot.Accounts))
	require.Equal(t, 3, proof.TwinSnapshot.Pages)
	rid08Ready(t, f, twin, wire, 6)
	proof.Twin = rid08PublicCensus(t, f, ids)
	twinNewman := rid08NewmanPhase(t, f, "fault-twin-n3", ids, nil, namedSystem, "", "")
	rid08NewOperations(t, f, after, 6)
	rid06GracefulStop(t, twin)
	stable := rid08PrimaryGD(t, f)
	retryOps := rid08GDOperations(t, f)
	retry := rid08Start(t, f, "rid08-late-page-retry", false, false)
	rid08AwaitEvent(t, f, retry, "snapshot-complete")
	proof.RetrySnapshot = rid08ReadSnapshot(t, retry)
	require.Equal(t, ids, rid08IDs(proof.RetrySnapshot.Accounts))
	require.Equal(t, 3, proof.RetrySnapshot.Pages)
	rid08Ready(t, f, retry, wire, 6)
	proof.Retry = rid08PublicCensus(t, f, ids)
	rid08NewmanPhase(t, f, "retry-n3", ids, twinNewman, namedSystem, "", "")
	rid08NewOperations(t, f, retryOps, 6)
	require.Equal(t, stable, rid08PrimaryGD(t, f))
	require.Equal(t, proof.Twin, proof.Retry)
	require.Equal(t, canonical, rid08PrimaryAccounts(t, f))
	rid06GracefulStop(t, retry)
	f.requireSameCredential(t)
	rid08Write(t, f.session.Root, "late-page-proof", proof)
	return proof
}

// Квитанции вместимости и допуска называют независимые существующие производственные
// политики. Четвёртая учётная запись разрешена только заявленным пределом количества;
// её штатный Create всё равно ждёт неизменного окна трёх допусков в час.
func rid08RequireAccountCapacity(t *testing.T, f *installationNativeWorld, owned int64) {
	t.Helper()
	var ceiling, count int64
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, "SELECT limit_value FROM kaname.own_ceilings WHERE kind='iam.account'").Scan(&ceiling))
	require.EqualValues(t, 4, ceiling)
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, "SELECT count(*) FROM kaname.accounts WHERE owner_user_id=$1", string(f.given.user)).Scan(&count))
	require.Equal(t, owned, count)
	a := rid08AdmissionRead(t, f)
	require.EqualValues(t, 3, a.Limit)
	require.EqualValues(t, 3600, a.WindowSeconds)
	rid08Write(t, f.session.Root, fmt.Sprintf("account-capacity-%d", owned), map[string]any{"declaredCountCeiling": ceiling, "actualOwnedAccounts": count, "admissionMax": a.Limit, "admissionWindowSeconds": a.WindowSeconds})
}
