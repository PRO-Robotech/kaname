// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type rid03NewmanSnapshot struct {
	BusinessAudit []rid09PrimaryRow            `json:"-"`
	Facts         *catalog.Facts               `json:"-"`
	Projection    rid09NewmanProjection        `json:"projection"`
	Whole         ridWholeDeliverySnapshot     `json:"-"`
	Raw           map[string][]rid09PrimaryRow `json:"-"`
}
type rid03NewmanExpectation struct {
	CaseID            string                 `json:"caseId"`
	Mode              string                 `json:"mode"`
	Scenario          string                 `json:"scenario"`
	Phase             string                 `json:"phase"`
	Actor             string                 `json:"actor"`
	Operator          string                 `json:"operatorId"`
	Issuer            string                 `json:"issuerId"`
	Creator           string                 `json:"creatorId"`
	System            string                 `json:"systemId"`
	Tenant            string                 `json:"tenantId"`
	InstallationGD    string                 `json:"installationDelegationId"`
	Request           map[string]any         `json:"request"`
	Path              string                 `json:"path"`
	Denied            bool                   `json:"denied"`
	Snapshot          rid03NewmanSnapshot    `json:"snapshot"`
	TechnicalEvidence *rid03TechnicalReceipt `json:"-"`
	Operation         map[string]any         `json:"operation"`
	Resource          map[string]any         `json:"resource"`
}

// Произвольный суффикс случая или переменные не могут добавить токен предъявителя в эту замкнутую перепись.
func rid03NewmanActor(caseID string) (string, bool) {
	return rid03NewmanActors[caseID], rid03NewmanActors[caseID] != ""
}

// Полный необработанный снимок RR только чтения с проверенной проекцией RID09 с обеих
// сторон. Вызывающий владеет ОДНИМ общим бюджетом SQL, готовности и возврата.
func rid03CaptureNewmanSnapshot(t *testing.T, ctx context.Context, f *installationNativeWorld) (rid03NewmanSnapshot, bool) {
	return rid03CaptureNewmanSnapshotWithCensus(t, ctx, f, nil)
}
func rid03CaptureNewmanSnapshotWithCensus(t *testing.T, ctx context.Context, f *installationNativeWorld, census func(context.Context, pgx.Tx)) (rid03NewmanSnapshot, bool) {
	t.Helper()
	require.NoError(t, ctx.Err())
	s := rid03NewmanSnapshot{Projection: rid09ReadNewmanProjectionContext(t, ctx, f), Raw: map[string][]rid09PrimaryRow{}}
	view, given := *f, *f.given
	given.ctx = ctx
	view.given = &given
	s.Whole = ridReadWholeDelivery(t, &view)
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cctx)
	}()
	var recovery bool
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery))
	require.False(t, recovery)
	var catalogProjection rid09NewmanProjection
	s.Facts = rid09PrimaryCatalog(t, ctx, tx, &catalogProjection)
	for table := range s.Whole.Delivery {
		s.Raw[table] = rid09PrimaryRows(t, ctx, tx, table)
	}
	s.Raw["operations"] = rid09PrimaryRows(t, ctx, tx, "operations")
	s.BusinessAudit = rid03ReadBusinessAudit(t, ctx, tx)
	if census != nil {
		census(ctx, tx)
	}
	require.NoError(t, tx.Commit(ctx))
	after := rid09ReadNewmanProjectionContext(t, ctx, f)
	require.NoError(t, ctx.Err(), "RID03 aggregate capture deadline before return")
	return s, reflect.DeepEqual(s.Projection, after)
}
func rid03SnapshotEqual(a, b rid03NewmanSnapshot) bool {
	return reflect.DeepEqual(a.BusinessAudit, b.BusinessAudit) && reflect.DeepEqual(a.Projection, b.Projection) && reflect.DeepEqual(a.Whole.Delivery, b.Whole.Delivery) && reflect.DeepEqual(a.Whole.OwnCeilings, b.Whole.OwnCeilings) && reflect.DeepEqual(a.Whole.Bookkeeping["operations"], b.Whole.Bookkeeping["operations"]) && reflect.DeepEqual(a.Raw, b.Raw)
}
func rid03StableNewmanSnapshot(t *testing.T, w *ridLifecycleWorld) rid03NewmanSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	var previous *rid03NewmanSnapshot
	for {
		require.NoError(t, ctx.Err(), "RID03 aggregate primary readiness deadline")
		s, composed := rid03CaptureNewmanSnapshot(t, ctx, w.f)
		materialized := true
		for _, g := range s.Projection.Bindings {
			if g["delegationId"] != nil && g["delegationId"] != "" && g["status"] == "ACTIVE" && g["materializedAt"] == nil {
				materialized = false
			}
		}
		// Завершаем штатную подготовку/прямое сведение до принятия
		// базы; без записей и повторного запуска настоящего действия Newman.
		for _, r := range s.Raw["resource_reconcile_outbox"] {
			if string(r["sent_at"]) == "null" {
				materialized = false
			}
		}
		for _, r := range s.Raw["access_binding_target_members"] {
			if rid03S(r, "verification_status") == "PENDING_VERIFICATION" {
				materialized = false
			}
		}
		if composed && materialized && previous != nil && rid03SnapshotEqual(*previous, s) {
			require.NoError(t, ctx.Err())
			return s
		}
		previous = nil
		if composed && materialized {
			previous = &s
		}
		select {
		case <-ctx.Done():
			t.Fatal("RID03 primary full ledger/materialization not stable before admission")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func rid03PhaseSnapshot(t *testing.T, w *ridLifecycleWorld) rid03NewmanSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	s, stable := rid03CaptureNewmanSnapshot(t, ctx, w.f)
	require.True(t, stable, "primary moved during single phase capture; no actual-phase retry")
	require.NoError(t, ctx.Err())
	return s
}
func rid03RequireReadOnly(t *testing.T, a, b rid03NewmanSnapshot) {
	t.Helper()
	require.True(t, rid03SnapshotEqual(a, b), "full public/raw/history/Operation/own-ceilings ledger changed during read-only phase")
}
func rid03Mode(t *testing.T, w *ridLifecycleWorld) string {
	t.Helper()
	require.Contains(t, []int{1, 3}, len(w.accounts))
	if len(w.accounts) == 3 {
		return "S2"
	}
	return "S1"
}
func rid03PublicEnabled(t *testing.T, w *ridLifecycleWorld, scenarios ...string) bool {
	t.Helper()
	if os.Getenv("KANAME_RID_NEWMAN") == "1" {
		return true
	}
	for _, scenario := range scenarios {
		for _, phase := range []string{"ACT", "VERIFY"} {
			id := "registry-installation-rid03-" + rid03Mode(t, w) + "-" + scenario + "-" + phase
			_, ok := rid03NewmanActor(id)
			require.True(t, ok)
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "actualNewmanExecuted": false, "wholeDoDAccepted": false})
		}
	}
	return false
}
func rid03PublicDelegatedGrant(t *testing.T, w *ridLifecycleWorld) {
	if !rid03PublicEnabled(t, w, "GRANT") {
		return
	}
	u := w.f.ridSA(t, w.f.tenantID, "rid03-newman-grantee")
	rid03PublicActionPair(t, w, "GRANT", w.bindingInput("service_account", u, w.pull, "registry.registries", w.object), false)
}
func rid03PublicDelegatedAxes(t *testing.T, w *ridLifecycleWorld) {
	if !rid03PublicEnabled(t, w, "ROLE-DENIED", "ROLE-TWIN", "TARGET-DENIED", "TARGET-TWIN", "SUBJECT-DENIED", "SUBJECT-TWIN") {
		return
	}
	for _, axis := range []string{"ROLE", "TARGET", "SUBJECT"} {
		u := w.f.ridSA(t, w.f.tenantID, "rid03-newman-"+strings.ToLower(axis))
		body := w.bindingInput("service_account", u, w.pull, "registry.registries", w.object)
		switch axis {
		case "ROLE":
			body["roleId"] = w.push
		case "TARGET":
			body["target"] = w.bindingInput("service_account", u, w.pull, "registry.repositories", w.repository)["target"]
		case "SUBJECT":
			body["subjectType"] = "user"
			body["subjectId"] = w.f.operator.UserID()
		}
		rid03PublicActionPair(t, w, axis+"-DENIED", body, true)
		switch axis {
		case "ROLE":
			body["roleId"] = w.pull
		case "TARGET":
			body["target"] = w.bindingInput("service_account", u, w.pull, "registry.registries", w.object)["target"]
		case "SUBJECT":
			body["subjectType"] = "service_account"
			body["subjectId"] = u
		}
		rid03PublicActionPair(t, w, axis+"-TWIN", body, false)
	}
}
func rid03PublicIssuerCannotDelegate(t *testing.T, w *ridLifecycleWorld, other string) {
	if !rid03PublicEnabled(t, w, "ISSUER-GD-DENIED", "CREATOR-GD-TWIN") {
		return
	}
	require.NotEqual(t, w.f.tenantID, other)
	delegate := w.f.ridSA(t, other, "rid03-newman-explicit-delegate")
	body := w.gdCreateBody(other, delegate)
	rid03PublicActionPair(t, w, "ISSUER-GD-DENIED", body, true)
	rid03PublicActionPair(t, w, "CREATOR-GD-TWIN", body, false)
}
func rid03PublicAnonymousClass(t *testing.T, w *ridLifecycleWorld) {
	if !rid03PublicEnabled(t, w, "AUTHENTICATED-DENIED", "ANONYMOUS-TWIN") {
		return
	}
	// Штатная отдельная цель избегает столкновения с сохранённым нативным анонимным G.
	// Оба публичных запроса используют ЭТИХ ЖЕ участника/цель/учётную запись/проект/роль/область.
	target := "rid03-newman-registry"
	conn, err := w.f.wire.ModuleWriter(filepath.Join(w.f.session.Root, "pki"))
	require.NoError(t, err)
	defer conn.Close()
	module := iamv1.NewInternalIAMServiceClient(conn)
	for _, tuple := range []struct{ subject, relation string }{{"project:" + w.project, "project"}, {"user:" + w.f.operator.UserID(), "owner"}} {
		_, err = module.RegisterResource(w.f.given.ctx, &iamv1.RegisterResourceRequest{SubjectId: tuple.subject, Relation: tuple.relation, Object: "registry_registry:" + target, ParentProjectId: w.project, ParentAccountId: w.f.tenantID, ParentChain: []string{"project:" + w.project, "account:" + w.f.tenantID}, SourceVersion: timestamppb.Now()})
		require.NoError(t, err)
		check, e := module.Check(w.f.given.ctx, &iamv1.CheckRequest{SubjectId: tuple.subject, Relation: tuple.relation, Object: "registry_registry:" + target, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, e)
		require.True(t, check.Allowed)
	}
	body := w.bindingInput("system_class", "authenticated", w.pull, "registry.registries", target)
	rid03PublicActionPair(t, w, "AUTHENTICATED-DENIED", body, true)
	body["subjectId"] = "anonymous"
	rid03PublicActionPair(t, w, "ANONYMOUS-TWIN", body, false)
}

// ACT и VERIFY — настоящие фазы Newman в том же владеющем мире. ID, возвращённые
// в очищенных отчётах Node, НИКОГДА не используются первичным оракулом.
func rid03PublicActionPair(t *testing.T, w *ridLifecycleWorld, scenario string, body map[string]any, denied bool) {
	t.Helper()
	f := w.f
	mode := rid03Mode(t, w)
	prefix := "registry-installation-rid03-" + mode + "-" + scenario
	// Выдача токена и штатная подготовка субъекта предшествуют независимой базе.
	token := f.ridToken(t, w.issuer)
	secretName := "jwtRIDIssuer"
	actor := w.issuer.ID
	path := "/iam/v1/accessBindings"
	if strings.Contains(scenario, "-GD-") {
		path = "/iam/v1/grantDelegations"
	}
	if scenario == "CREATOR-GD-TWIN" {
		token = f.ridToken(t, f.creator)
		secretName = "jwtRIDCreator"
		actor = f.creator.ID
	}
	// Сохраняем закрытую глубокую копию: далее нативные вызывающие меняют единственный допустимый факт.
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	request := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &request))
	before := rid03StableNewmanSnapshot(t, w)
	rid03RequirePremise(t, w, before, scenario)
	require.NotEmpty(t, before.BusinessAudit, "FIXTURE_NOT_ACCEPTED: normal business audit producer has no baseline history")
	e := rid03NewmanExpectation{CaseID: prefix + "-ACT", Mode: mode, Scenario: scenario, Phase: "ACT", Actor: actor, Operator: string(f.given.user), Issuer: w.issuer.ID, Creator: f.creator.ID, System: f.baseline.SystemID, Tenant: f.tenantID, InstallationGD: w.gd.Id, Request: request, Path: path, Denied: denied, Snapshot: before}
	var after rid03NewmanSnapshot
	var actionReceipt ridNewmanReceipt
	// Даже фатальный исход/Goexit захватывает полное первичное доказательство после ACT ровно один раз.
	func() {
		defer func() {
			after = rid03StableNewmanSnapshot(t, w)
			rid03RequireActionDelta(t, w, &e, before, after)
			rid03RequireActObservation(t, &e, actionReceipt.RID03ActGetObservation, before, after)
			require.NotNil(t, e.TechnicalEvidence)
			require.True(t, actionReceipt.OK, "actual ACT receipt required before primary proof publication")
			e.TechnicalEvidence.PhaseRuntimeChecksPassed = true
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-technical-audit-receipt", e.TechnicalEvidence)
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-delta", map[string]any{"caseId": e.CaseID, "denied": denied, "operation": e.Operation, "resource": e.Resource, "wholeDoDAccepted": false})
		}()
		actionReceipt = ridRunNewmanPhase(t, f, "registry-installation-rid03", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid03Expected": e, secretName: token})
		require.True(t, actionReceipt.OK)
	}()
	e.CaseID = prefix + "-VERIFY"
	e.Phase = "VERIFY"
	e.Snapshot = after
	var verifyReceipt ridNewmanReceipt
	func() {
		defer func() {
			end := rid03PhaseSnapshot(t, w)
			rid03RequireReadOnly(t, after, end)
			proof, proofOK := rid03BuildTechnicalReceipt(&e, after, end, nil)
			require.True(t, proofOK, "closed VERIFY zero technical/business delta receipt required")
			require.True(t, verifyReceipt.OK, "actual VERIFY receipt required before primary proof publication")
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-technical-audit-receipt", proof)
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-bracket", map[string]any{"caseId": e.CaseID, "fullPrimarySnapshotUnchangedDuringPhase": rid03SnapshotEqual(after, end), "wholeDoDAccepted": false})
		}()
		verifyReceipt = ridRunNewmanPhase(t, f, "registry-installation-rid03", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid03Expected": e})
		require.True(t, verifyReceipt.OK)
	}()
}
func rid03RequirePremise(t *testing.T, w *ridLifecycleWorld, s rid03NewmanSnapshot, scenario string) {
	t.Helper()
	require.Len(t, w.accounts, map[string]int{"S1": 1, "S2": 3}[rid03Mode(t, w)])
	accountCount := len(w.accounts) + 1
	if strings.Contains(scenario, "-GD-") && len(w.accounts) == 1 {
		accountCount++
	}
	require.Len(t, s.Projection.Accounts, accountCount)
	expectedSAs := map[string]int{"GRANT": 7, "ROLE-DENIED": 9, "ROLE-TWIN": 9, "TARGET-DENIED": 10, "TARGET-TWIN": 10, "SUBJECT-DENIED": 11, "SUBJECT-TWIN": 11, "ISSUER-GD-DENIED": 7, "CREATOR-GD-TWIN": 7, "AUTHENTICATED-DENIED": 5, "ANONYMOUS-TWIN": 5}
	require.Contains(t, expectedSAs, scenario)
	require.Len(t, s.Projection.ServiceAccounts, expectedSAs[scenario])
	for id := range w.f.baseline.ServiceAccounts {
		found := false
		for _, sa := range s.Projection.ServiceAccounts {
			if sa["id"] == id {
				found = true
			}
		}
		require.True(t, found, "all declared stock identities retained")
	}
	expectedGD := len(w.accounts)
	if strings.Contains(scenario, "-GD-") {
		expectedGD++
	}
	require.Len(t, s.Projection.Delegations, expectedGD)
	issuer, creator := false, false
	for _, sa := range s.Projection.ServiceAccounts {
		if sa["id"] == w.issuer.ID {
			issuer = true
			require.Equal(t, "rid-public-issuer", sa["name"])
			require.Equal(t, w.f.baseline.SystemID, sa["accountId"])
			require.Equal(t, true, sa["enabled"])
		}
		if sa["id"] == w.f.creator.ID {
			creator = true
		}
	}
	require.True(t, issuer)
	require.True(t, creator)
	require.NotEqual(t, w.issuer.ID, w.f.creator.ID)
	installed := 0
	for _, gd := range s.Projection.Delegations {
		delegate := gd["delegate"].(map[string]any)
		if delegate["id"] != w.issuer.ID {
			continue
		}
		installed++
		require.Equal(t, "ACTIVE", gd["status"])
		require.Equal(t, "registry", gd["module"])
		require.Equal(t, map[string]any{"type": "service_account", "id": w.f.creator.ID}, gd["delegatedBy"])
		require.ElementsMatch(t, []string{w.pull}, gd["roleIds"])
		require.ElementsMatch(t, []string{"registry.registries"}, gd["targetTypes"])
		subjects := []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}
		if scenario == "AUTHENTICATED-DENIED" || scenario == "ANONYMOUS-TWIN" {
			subjects = append(subjects, "SUBJECT_TYPE_SYSTEM_CLASS")
		}
		require.ElementsMatch(t, subjects, gd["subjectTypes"])
		require.NotEmpty(t, gd["createdAt"])
		require.Nil(t, gd["revokedAt"])
		require.Nil(t, gd["revokedBy"])
	}
	require.Equal(t, len(w.accounts), installed)
	require.NotEmpty(t, s.Projection.Groups)
	stock := 0
	for _, g := range s.Projection.Groups {
		if g["accountId"] == w.f.baseline.SystemID && g["name"] == "module-relation-writers" {
			stock++
		}
	}
	require.Equal(t, 1, stock)
}

func rid03ProjectionRows(t *testing.T, rows []map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, r := range rows {
		id := r["id"].(string)
		require.NotContains(t, out, id)
		out[id] = r
	}
	return out
}
func rid03OnlyAdded(t *testing.T, before, after []map[string]any, want int) []map[string]any {
	t.Helper()
	old := rid03ProjectionRows(t, before)
	now := rid03ProjectionRows(t, after)
	require.Len(t, now, len(old)+want)
	for id, row := range old {
		require.Equal(t, row, now[id], "every old full object including history/timestamps survives")
	}
	added := []map[string]any{}
	for id, row := range now {
		if old[id] == nil {
			added = append(added, row)
		}
	}
	require.Len(t, added, want)
	return added
}
func rid03RawID(t *testing.T, r rid09PrimaryRow, key string) string {
	t.Helper()
	return rid09PrimaryValue[string](t, r, key)
}
func rid03RowsByID(t *testing.T, rows []rid09PrimaryRow) map[string]rid09PrimaryRow {
	t.Helper()
	out := map[string]rid09PrimaryRow{}
	for _, r := range rows {
		id := rid03RawID(t, r, "id")
		_, duplicate := out[id]
		require.False(t, duplicate, "duplicate primary row identity")
		out[id] = r
	}
	return out
}
func rid03RawDigest(t *testing.T, r rid09PrimaryRow) string { t.Helper(); return ridWholeDigest(t, r) }

// У ACT одно заявленное изменение; все таблицы/столбцы/история остаются захваченными.
// Неизменённые физические строки должны сохраниться побайтно. Аддитивные строки прямой материализации
// привязаны к новому G как объекту либо запрошенным субъекту/цели; неизвестные
// таблицы, удаления, посторонние обновления и вторая Operation отклоняются.
func rid03RequireActionDelta(t *testing.T, w *ridLifecycleWorld, e *rid03NewmanExpectation, a, b rid03NewmanSnapshot) {
	t.Helper()
	rid03RequireActionDeltaWithReceipt(t, w, e, a, b, rid03BuildTechnicalReceipt)
}
func rid03RequireActionDeltaWithReceipt(t *testing.T, w *ridLifecycleWorld, e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, build func(*rid03NewmanExpectation, rid03NewmanSnapshot, rid03NewmanSnapshot, *rid03DeltaPolicy) (rid03TechnicalReceipt, bool)) {
	t.Helper()
	f := w.f
	rid03WriteRawDeltaCensus(t, f, e.CaseID, a, b)
	require.Equal(t, a.Whole.OwnCeilings, b.Whole.OwnCeilings)
	if e.Denied {
		rid03RequireReadOnly(t, a, b)
		proof, ok := build(e, a, b, nil)
		require.True(t, ok, "closed denied zero technical/business delta receipt required")
		e.TechnicalEvidence = &proof
		return
	}
	require.Equal(t, a.Projection.Accounts, b.Projection.Accounts)
	require.Equal(t, a.Projection.ServiceAccounts, b.Projection.ServiceAccounts)
	require.Equal(t, a.Projection.Groups, b.Projection.Groups)
	require.Equal(t, a.Projection.Members, b.Projection.Members)
	require.Equal(t, a.Projection.Roles, b.Projection.Roles)
	require.Equal(t, a.Projection.Catalog, b.Projection.Catalog)
	require.Equal(t, a.Whole.Bookkeeping["operations"].Columns, b.Whole.Bookkeeping["operations"].Columns)
	for table, old := range a.Whole.Delivery {
		now, ok := b.Whole.Delivery[table]
		require.True(t, ok)
		require.Equal(t, old.Columns, now.Columns, "full physical schema preserved")
	}
	oldOps, newOps := rid03RowsByID(t, a.Raw["operations"]), rid03RowsByID(t, b.Raw["operations"])
	require.Equal(t, len(oldOps)+1, len(newOps), "exactly one new Operation")
	for id, row := range oldOps {
		require.True(t, reflect.DeepEqual(row, newOps[id]), "complete old Operation including Any/index/principal/times unchanged; safe per-column census retained")
	}
	opID := ""
	for id := range newOps {
		if oldOps[id] == nil {
			require.Empty(t, opID)
			opID = id
		}
	}
	require.NotEmpty(t, opID)
	var resourceID string
	if e.Path == "/iam/v1/grantDelegations" {
		added := rid03OnlyAdded(t, a.Projection.Delegations, b.Projection.Delegations, 1)
		e.Resource = added[0]
		resourceID = e.Resource["id"].(string)
		require.Equal(t, e.Request["accountId"], e.Resource["accountId"])
		require.Equal(t, e.Request["delegate"], e.Resource["delegate"])
		require.Equal(t, e.Request["roleIds"], e.Resource["roleIds"])
		require.Equal(t, e.Request["targetTypes"], e.Resource["targetTypes"])
		require.Equal(t, e.Request["subjectTypes"], e.Resource["subjectTypes"])
		require.Equal(t, map[string]any{"type": "service_account", "id": f.creator.ID}, e.Resource["delegatedBy"])
		require.Equal(t, "ACTIVE", e.Resource["status"])
		require.Equal(t, a.Projection.Bindings, b.Projection.Bindings)
	} else {
		require.Equal(t, a.Projection.Delegations, b.Projection.Delegations)
		old := rid03ProjectionRows(t, a.Projection.Bindings)
		now := rid03ProjectionRows(t, b.Projection.Bindings)
		require.Len(t, now, len(old)+1)
		for id, row := range now {
			if old[id] == nil {
				require.Empty(t, resourceID)
				resourceID = id
				e.Resource = row
			}
		}
		require.NotEmpty(t, resourceID)
		encoded, err := json.Marshal(e.Request)
		require.NoError(t, err)
		var request iamv1.CreateAccessBindingRequest
		require.NoError(t, protojson.Unmarshal(encoded, &request))
		encoded, err = json.Marshal(e.Resource)
		require.NoError(t, err)
		var got iamv1.AccessBinding
		require.NoError(t, protojson.Unmarshal(encoded, &got))
		w.requireGrantRequest(t, &request, &got)
		require.Equal(t, iamv1.AccessBinding_ACTIVE, got.Status)
		require.Equal(t, w.gd.Id, got.DelegationId)
		require.NotNil(t, got.MaterializedAt)
		for id, row := range old {
			actual := now[id]
			require.NotNil(t, actual)
			for key, value := range row {
				if key != "materializedAt" {
					require.Equal(t, value, actual[key], "old binding field %s remains full and exact", key)
				}
			}
			if !reflect.DeepEqual(row["materializedAt"], actual["materializedAt"]) {
				// Прямое сведение может обогатить существующий G владельца для этого нового G как объекта.
				// Его необработанные основная строка/история остаются точными; требуем настоящего нового члена ACTIVE
				// ровно для этого нового выделенного ресурса, без произвольного обогащения.
				member := false
				for _, r := range b.Raw["access_binding_target_members"] {
					if rid03ExactOwnerMember(t, e, a, r, id, resourceID) {
						member = true
					}
				}
				require.True(t, member, "changed old materializedAt needs actual new G-as-object membership")
				require.NotNil(t, actual["materializedAt"])
			}
		}
	}
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	op, err := operations.NewRepo(f.given.pool, "kaname").Get(ctx, opID)
	require.NoError(t, err)
	require.True(t, op.Done)
	require.Nil(t, op.Error)
	require.Equal(t, operations.Principal{Type: "service_account", ID: e.Actor, DisplayName: e.Actor}, op.Principal)
	require.NotNil(t, op.Metadata)
	require.NotNil(t, op.Response)
	row := newOps[opID]
	require.Equal(t, resourceID, rid03RawID(t, row, "resource_id"))
	if e.Path == "/iam/v1/grantDelegations" {
		var meta iamv1.CreateGrantDelegationMetadata
		var response iamv1.GrantDelegation
		require.NoError(t, op.Metadata.UnmarshalTo(&meta))
		require.NoError(t, op.Response.UnmarshalTo(&response))
		require.Equal(t, resourceID, meta.GrantDelegationId)
		require.Equal(t, e.Request["accountId"], meta.AccountId)
		require.Equal(t, meta.AccountId, rid03RawID(t, row, "account_id"))
		require.Equal(t, e.Resource, rid09PrimaryJSON(t, &response))
	} else {
		var meta iamv1.CreateAccessBindingMetadata
		var response iamv1.AccessBinding
		require.NoError(t, op.Metadata.UnmarshalTo(&meta))
		require.NoError(t, op.Response.UnmarshalTo(&response))
		require.Equal(t, resourceID, meta.AccessBindingId)
		require.Equal(t, f.tenantID, meta.AccountId)
		require.Equal(t, meta.AccountId, rid03RawID(t, row, "account_id"))
		w.requireGrantRequest(t, rid03BindingRequest(t, e.Request), &response)
		// Operation хранит исходный ответ; сохраняем его настоящее обогащение. Последующий
		// Get использует отдельно захваченный materializedAt первичного журнала.
		full := proto.Clone(&response).(*iamv1.AccessBinding)
		encoded, err := json.Marshal(e.Resource)
		require.NoError(t, err)
		var primary iamv1.AccessBinding
		require.NoError(t, protojson.Unmarshal(encoded, &primary))
		full.MaterializedAt = primary.MaterializedAt
		require.True(t, proto.Equal(full, &primary))
		if response.MaterializedAt != nil {
			require.False(t, response.MaterializedAt.AsTime().After(primary.MaterializedAt.AsTime()))
			require.False(t, response.MaterializedAt.AsTime().Before(response.CreatedAt.AsTime()))
		}
	}
	e.Operation = rid09PrimaryJSON(t, operationspb.ToProto(op))
	require.NoError(t, ctx.Err())
	require.Equal(t, a.Whole.Separation, b.Whole.Separation)
	policy := rid03BuildDeltaPolicy(t, e, a, b, resourceID)
	rid03RequireClosedDelta(t, a, b, policy)
	proof, ok := build(e, a, b, &policy)
	require.True(t, ok, "closed independent technical/business primary proof required")
	e.TechnicalEvidence = &proof
}
func rid03BindingRequest(t *testing.T, body map[string]any) *iamv1.CreateAccessBindingRequest {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	out := &iamv1.CreateAccessBindingRequest{}
	require.NoError(t, protojson.Unmarshal(raw, out))
	return out
}
func rid03WriteRawDeltaCensus(t *testing.T, f *installationNativeWorld, id string, a, b rid03NewmanSnapshot) {
	t.Helper()
	tables := map[string]any{}
	for table, before := range a.Raw {
		after := b.Raw[table]
		old := map[string]bool{}
		now := map[string]bool{}
		for _, r := range before {
			old[rid03RawDigest(t, r)] = true
		}
		for _, r := range after {
			now[rid03RawDigest(t, r)] = true
		}
		changes := []any{}
		for _, side := range []struct {
			name  string
			rows  []rid09PrimaryRow
			other map[string]bool
		}{{"removed-or-changed", before, now}, {"added-or-changed", after, old}} {
			for _, r := range side.rows {
				if side.other[rid03RawDigest(t, r)] {
					continue
				}
				cols := map[string]any{}
				for key, value := range r {
					cols[key] = map[string]any{"present": true, "sha256": ridWholeDigest(t, value)}
				}
				changes = append(changes, map[string]any{"kind": side.name, "columns": cols})
			}
		}
		tables[table] = map[string]any{"beforeCount": len(before), "afterCount": len(after), "changes": changes}
	}
	rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id)+"-raw-delta-census", map[string]any{"caseId": id, "tables": tables, "state": "DIAGNOSTIC_NOT_ACCEPTANCE", "wholeDoDAccepted": false})
}

var rid03NewmanActors = map[string]string{
	"registry-installation-rid03-S1-GRANT-ACT":                   "I",
	"registry-installation-rid03-S1-GRANT-VERIFY":                "O",
	"registry-installation-rid03-S1-ROLE-DENIED-ACT":             "I",
	"registry-installation-rid03-S1-ROLE-DENIED-VERIFY":          "O",
	"registry-installation-rid03-S1-ROLE-TWIN-ACT":               "I",
	"registry-installation-rid03-S1-ROLE-TWIN-VERIFY":            "O",
	"registry-installation-rid03-S1-TARGET-DENIED-ACT":           "I",
	"registry-installation-rid03-S1-TARGET-DENIED-VERIFY":        "O",
	"registry-installation-rid03-S1-TARGET-TWIN-ACT":             "I",
	"registry-installation-rid03-S1-TARGET-TWIN-VERIFY":          "O",
	"registry-installation-rid03-S1-SUBJECT-DENIED-ACT":          "I",
	"registry-installation-rid03-S1-SUBJECT-DENIED-VERIFY":       "O",
	"registry-installation-rid03-S1-SUBJECT-TWIN-ACT":            "I",
	"registry-installation-rid03-S1-SUBJECT-TWIN-VERIFY":         "O",
	"registry-installation-rid03-S1-ISSUER-GD-DENIED-ACT":        "I",
	"registry-installation-rid03-S1-ISSUER-GD-DENIED-VERIFY":     "O",
	"registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT":         "C",
	"registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY":      "O",
	"registry-installation-rid03-S1-AUTHENTICATED-DENIED-ACT":    "I",
	"registry-installation-rid03-S1-AUTHENTICATED-DENIED-VERIFY": "O",
	"registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT":          "I",
	"registry-installation-rid03-S1-ANONYMOUS-TWIN-VERIFY":       "O",
	"registry-installation-rid03-S2-GRANT-ACT":                   "I",
	"registry-installation-rid03-S2-GRANT-VERIFY":                "O",
	"registry-installation-rid03-S2-ROLE-DENIED-ACT":             "I",
	"registry-installation-rid03-S2-ROLE-DENIED-VERIFY":          "O",
	"registry-installation-rid03-S2-ROLE-TWIN-ACT":               "I",
	"registry-installation-rid03-S2-ROLE-TWIN-VERIFY":            "O",
	"registry-installation-rid03-S2-TARGET-DENIED-ACT":           "I",
	"registry-installation-rid03-S2-TARGET-DENIED-VERIFY":        "O",
	"registry-installation-rid03-S2-TARGET-TWIN-ACT":             "I",
	"registry-installation-rid03-S2-TARGET-TWIN-VERIFY":          "O",
	"registry-installation-rid03-S2-SUBJECT-DENIED-ACT":          "I",
	"registry-installation-rid03-S2-SUBJECT-DENIED-VERIFY":       "O",
	"registry-installation-rid03-S2-SUBJECT-TWIN-ACT":            "I",
	"registry-installation-rid03-S2-SUBJECT-TWIN-VERIFY":         "O",
	"registry-installation-rid03-S2-ISSUER-GD-DENIED-ACT":        "I",
	"registry-installation-rid03-S2-ISSUER-GD-DENIED-VERIFY":     "O",
	"registry-installation-rid03-S2-CREATOR-GD-TWIN-ACT":         "C",
	"registry-installation-rid03-S2-CREATOR-GD-TWIN-VERIFY":      "O",
	"registry-installation-rid03-S2-AUTHENTICATED-DENIED-ACT":    "I",
	"registry-installation-rid03-S2-AUTHENTICATED-DENIED-VERIFY": "O",
	"registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT":          "I",
	"registry-installation-rid03-S2-ANONYMOUS-TWIN-VERIFY":       "O",
}
