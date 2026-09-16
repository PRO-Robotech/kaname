// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed_test

// apply_test.go — применитель посева через подставной порт хранилища: ПОРЯДОК
// и ПЕРЕПИСЬ, которые исходом применения не утверждаются (приёмка MRW-1, Р3).
//
// Порядок доказывается записью вызовов, а не состоянием базы: на базе, где
// группа жива из свода, вступление ложится при любом порядке (§2.13 приёмки),
// и только журнал вызовов различает «своё раньше доставленного» от обратного.
// Против живой базы тот же порядок держит интеграционная проба MRW-04 на
// снятой строке группы; здесь — её дешёвый близнец без Postgres.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// ownProbeManifest — форма Р1: одна группа и одна выдача, ни личностей, ни
// вступлений. Аккаунт назван живым написанием `system`.
const ownProbeManifest = `
apiVersion: iam/v1
module: iam
resources: []
seed:
  groups:
    - name: module-relation-writers
      account: system
      description: "Module service accounts allowed to write relation tuples through iam (issue #914)"
  accessBindings:
    - subjects:
        - {type: group, name: module-relation-writers}
      grantedRelation: fga_writer
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
`

// deliveredProbeManifest — доставленный манифест модуля со вступлением в группу,
// которую объявляет манифест службы.
const deliveredProbeManifest = `
apiVersion: iam/v1
module: compute
resources: []
seed:
  serviceAccounts:
    - name: kacho-compute
      account: system
      description: "Module SA: kacho-compute (probe)"
  joins:
    - serviceAccount: {account: system, name: kacho-compute}
      group: {account: system, name: module-relation-writers}
      why: "проба порядка применения посева"
`

// recordingWriter — порт, который ЗАПИСЫВАЕТ глаголы в порядке вызова.
type recordingWriter struct {
	calls   []string
	refuse  map[string]error
	changed bool
}

func (w *recordingWriter) record(call string) (bool, error) {
	w.calls = append(w.calls, call)
	if err, ok := w.refuse[call]; ok {
		return false, err
	}
	return w.changed, nil
}

func (w *recordingWriter) UpsertServiceAccount(_ context.Context, account, name, _ string) (bool, error) {
	return w.record("sa " + account + "/" + name)
}
func (w *recordingWriter) UpsertGroup(_ context.Context, account, name, _ string) (bool, error) {
	return w.record("group " + account + "/" + name)
}
func (w *recordingWriter) JoinGroup(_ context.Context, saAccount, saName, groupAccount, groupName string) (bool, error) {
	return w.record("join " + saAccount + "/" + saName + " → " + groupAccount + "/" + groupName)
}
func (w *recordingWriter) GrantRelation(_ context.Context, subject moduleseed.Subject, relation, scopeKind, scopeID string) (bool, error) {
	return w.record("relation " + subject.String() + " " + relation + " @" + scopeKind + ":" + scopeID)
}
func (w *recordingWriter) GrantRole(_ context.Context, subject moduleseed.Subject, roleID, scopeKind, scopeID string) (bool, error) {
	return w.record("role " + subject.String() + " " + roleID + " @" + scopeKind + ":" + scopeID)
}

// recordingTx — исполнитель транзакций над одним записывающим портом. Считает
// транзакции: их обязано быть по одной на манифест.
type recordingTx struct {
	w   *recordingWriter
	txs int
}

func (t *recordingTx) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleseed.Writer) error) error {
	t.txs++
	return fn(ctx, t.w)
}

func load(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	require.NoError(t, err, "проба подаёт манифест, который разбор не принимает — вердикт беспредметен")
	return m
}

func indexOf(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// TestMRW04_OwnManifestIsAppliedBeforeTheDeliveredOnes — своё раньше
// доставленного независимо от имени модуля: `compute` < `iam` лексически, и
// обход каталога поставил бы его первым.
func TestMRW04_OwnManifestIsAppliedBeforeTheDeliveredOnes(t *testing.T) {
	w := &recordingWriter{changed: true}
	applier := moduleseed.NewApplier(&recordingTx{w: w})

	census, err := applier.Apply(context.Background(),
		load(t, ownProbeManifest), []*manifest.Manifest{load(t, deliveredProbeManifest)})
	require.NoError(t, err)
	t.Logf("перепись: %s\nвызовы: %s", census, strings.Join(w.calls, " · "))

	group := indexOf(w.calls, "group system/module-relation-writers")
	join := indexOf(w.calls, "join system/kacho-compute → system/module-relation-writers")
	require.NotEqual(t, -1, group, "группа службы не заведена вовсе")
	require.NotEqual(t, -1, join, "вступление модуля не записано вовсе")
	require.Less(t, group, join,
		"вступление модуля (%d) записано РАНЬШЕ группы службы (%d): порядок получен обходом "+
			"каталога, а не объявлен — на базе без строки свода вступление отказало бы "+
			"«группа не резолвится»", join, group)
}

// TestMRW05_OwnManifestIsAppliedWithoutAnyDelivery — самостоятельная установка:
// доставки нет, свой манифест применён, перепись говорит это числом.
func TestMRW05_OwnManifestIsAppliedWithoutAnyDelivery(t *testing.T) {
	w := &recordingWriter{changed: true}
	tx := &recordingTx{w: w}
	census, err := moduleseed.NewApplier(tx).Apply(context.Background(), load(t, ownProbeManifest), nil)
	require.NoError(t, err)
	t.Logf("перепись: %s", census)

	require.Equal(t, 1, tx.txs, "своя транзакция — ровно одна на манифест")
	require.NotNil(t, census.Own, "перепись не называет свой манифест применённым")
	require.Equal(t, 1, census.Own.WrittenGroups)
	require.Equal(t, 1, census.Own.WrittenGrants)
	require.Zero(t, census.Manifests, "доставленных манифестов ноль, а перепись считает иначе")
	require.Contains(t, census.String(), "доставлено 0")
	require.Contains(t, census.String(), "свой манифест применён")
}

// TestMRW04_CensusTellsOwnAndDeliveredApart — перепись различает два разряда
// ЧИСЛОМ, а не складывает их: одно число скрыло бы ровно тот случай, ради
// которого разделение и делается.
func TestMRW04_CensusTellsOwnAndDeliveredApart(t *testing.T) {
	w := &recordingWriter{changed: true}
	census, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(),
		load(t, ownProbeManifest), []*manifest.Manifest{load(t, deliveredProbeManifest)})
	require.NoError(t, err)

	require.NotNil(t, census.Own)
	require.Equal(t, "iam", census.Own.Module)
	require.Equal(t, 1, census.Manifests, "доставлен один манифест")
	require.Equal(t, 1, census.Seeding)
	require.Len(t, census.Reports, 1, "перечень отчётов — по ДОСТАВЛЕННЫМ; свой стоит отдельно")
	declared, written := census.Totals()
	// свой: группа + выдача; доставленный: личность + вступление.
	require.Equal(t, 4, declared)
	require.Equal(t, 4, written)
	require.Contains(t, census.String(), "доставлено 1")
}

// TestMRW02_OwnReportPrintsWrittenOverDeclared — перепись своего манифеста
// печатает «групп 0/1 · выдач 0/1» на повторном старте (записано/объявлено).
func TestMRW02_OwnReportPrintsWrittenOverDeclared(t *testing.T) {
	w := &recordingWriter{changed: false}
	census, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), load(t, ownProbeManifest), nil)
	require.NoError(t, err)
	require.NotNil(t, census.Own)
	require.Contains(t, census.Own.String(), "групп 0/1")
	require.Contains(t, census.Own.String(), "выдач 0/1")
}

// TestApply_OwnRefusalStopsBeforeTheDelivery — отказ на своём манифесте
// прекращает применение и называет свой разряд: доставленное не применяется.
func TestApply_OwnRefusalStopsBeforeTheDelivery(t *testing.T) {
	refusal := errors.New("проба: отказ хранилища")
	w := &recordingWriter{changed: true, refuse: map[string]error{"group system/module-relation-writers": refusal}}
	_, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(),
		load(t, ownProbeManifest), []*manifest.Manifest{load(t, deliveredProbeManifest)})
	require.ErrorIs(t, err, refusal)
	require.Contains(t, err.Error(), "свой манифест")
	require.Equal(t, -1, indexOf(w.calls, "sa system/kacho-compute"),
		"доставленный манифест применялся после отказа на своём")
}

// TestApply_NilOwnIsNotSupplied — «свой не подан» и «свой подан без посева»
// различаются переписью: указатель и пустой отчёт.
func TestApply_NilOwnIsNotSupplied(t *testing.T) {
	w := &recordingWriter{changed: true}
	census, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil,
		[]*manifest.Manifest{load(t, deliveredProbeManifest)})
	require.NoError(t, err)
	require.Nil(t, census.Own)
	require.Contains(t, census.String(), "свой манифест не подан")
}
