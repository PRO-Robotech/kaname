// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestChildRegistrationCaptureBoundsCurrentIncarnation(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	rule := &catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 2, MaxCreates: 2, WindowSeconds: 60}
	require.NoError(t, kanamepg.NewCatalogWriteRepo(r.admin).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		if _, err := w.UpsertModule(ctx, "probe"); err != nil {
			return err
		}
		if _, err := w.UpsertResource(ctx, catalog.ResourceRow{Module: "probe", Resource: "boxes", ObjectType: "odd_box"}); err != nil {
			return err
		}
		if _, err := w.UpsertResource(ctx, catalog.ResourceRow{Module: "probe", Resource: "items", ObjectType: "odd_item", ParentNames: []string{"parent"}, ParentTypes: []string{"odd_box"}, ChildRegistration: rule}); err != nil {
			return err
		}
		_, err := w.UpsertVerb(ctx, catalog.VerbRow{Module: "probe", Resource: "items", Verb: "registerchild", ContainerParent: "odd_box", ContainerRelation: "child_registrar"})
		return err
	}))

	const parent = "capture-box"
	const candidate = parent + "/candidate"
	version := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := r.admin.Exec(r.ctx, sql, args...)
		require.NoError(t, err)
	}
	mirror := func(typ, id string, at time.Time) {
		t.Helper()
		exec(`INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,source_version) VALUES($1,$2,$3,$4)`, typ, id, r.a, at)
	}
	edge := func(typ, id string, depth int) {
		t.Helper()
		exec(`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version) VALUES($1,$2,'odd_box',$3,$4,$5)`, typ, id, parent, depth, version)
	}
	type capture struct {
		ParentType        string          `json:"parent_type"`
		ParentModel       string          `json:"parent_model"`
		ParentID          string          `json:"parent_id"`
		ParentAction      string          `json:"parent_action"`
		ParentVersion     *time.Time      `json:"parent_version"`
		ParentIncarnation *string         `json:"parent_incarnation"`
		ClosedAt          *time.Time      `json:"closed_at"`
		ChildVersion      *time.Time      `json:"child_version"`
		ReplayVersion     *time.Time      `json:"replay_version"`
		LiveChildren      *int            `json:"live_children"`
		RecentCreations   []time.Time     `json:"recent_creations"`
		VersionWatermark  *time.Time      `json:"version_watermark"`
		Policy            json.RawMessage `json:"policy"`
	}
	read := func(id string) (capture, int64, int64) {
		t.Helper()
		var raw []byte
		var rows, reads int64
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT witness,logical_rows,logical_reads FROM kaname._authority_child_registration_capture_v1('probe.items',$1,64,64)`, id).Scan(&raw, &rows, &reads))
		var got capture
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Greater(t, rows, int64(0))
		require.Greater(t, reads, int64(0))
		require.LessOrEqual(t, rows, int64(64))
		require.LessOrEqual(t, reads, int64(64))
		return got, rows, reads
	}
	missing, _, missingReads := read(candidate)
	require.Nil(t, missing.ParentVersion)
	require.Nil(t, missing.LiveChildren)
	require.Empty(t, missing.RecentCreations)

	mirror("probe.boxes", parent, version)
	var incarnation string
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_child_parent_state(object_type,object_id) VALUES('probe.boxes',$1) RETURNING incarnation::text`, parent).Scan(&incarnation))
	receipt := func(id string, source, created time.Time, inc string) {
		t.Helper()
		exec(`INSERT INTO kaname.authority_child_creation(child_type,child_id,source_version,parent_incarnation,created_at,user_id) VALUES('probe.items',$1,$2,$3::uuid,$4,'usr-capture')`, id, source, inc, created)
	}
	// Потомок, созданный модулем, занимает место и без пользовательской квитанции.
	mirror("probe.items", parent+"/module", version)
	edge("odd_item", parent+"/module", 1)
	// Для учёта нужны и зеркало, и ребро на непосредственного родителя.
	mirror("probe.items", parent+"/mirror-only", version)
	edge("odd_item", parent+"/orphan", 1)
	mirror("probe.items", parent+"/indirect", version)
	edge("odd_item", parent+"/indirect", 2)
	mirror("probe.boxes", parent+"/wrong-type", version)
	edge("odd_box", parent+"/wrong-type", 1)
	first, second, third := version.Add(time.Second), version.Add(2*time.Second), version.Add(3*time.Second)
	receipt(parent+"/first", version, first, incarnation)
	receipt(parent+"/deleted", version, second, incarnation)
	receipt(parent+"/third", version, third, incarnation)
	receipt(parent+"/old", version, version.Add(time.Hour), "00000000-0000-0000-0000-000000000001")
	got, capturedRows, capturedReads := read(candidate)
	require.Equal(t, "probe.boxes", got.ParentType)
	require.Equal(t, "odd_box", got.ParentModel)
	require.Equal(t, parent, got.ParentID)
	require.Equal(t, "child_registrar", got.ParentAction)
	require.NotNil(t, got.ParentVersion)
	require.True(t, version.Equal(*got.ParentVersion))
	require.Equal(t, &incarnation, got.ParentIncarnation)
	require.Nil(t, got.ChildVersion)
	require.Nil(t, got.ReplayVersion)
	require.NotNil(t, got.LiveChildren)
	require.Equal(t, 1, *got.LiveChildren)
	require.Len(t, got.RecentCreations, 2)
	require.True(t, third.Equal(got.RecentCreations[0]))
	require.True(t, second.Equal(got.RecentCreations[1]), "квитанция удалённого потомка учитывается, прежняя инкарнация исключена")
	policy, err := json.Marshal(rule)
	require.NoError(t, err)
	require.JSONEq(t, string(policy), string(got.Policy))
	var pe *pgconn.PgError
	for _, budgets := range [][2]int64{{capturedRows - 1, 64}, {64, capturedReads - 1}} {
		_, err = r.admin.Exec(r.ctx, `SELECT * FROM kaname._authority_child_registration_capture_v1('probe.items',$1,$2,$3)`, candidate, budgets[0], budgets[1])
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "54000", pe.Code, "неполная квота не возвращается")
	}
	// История предыдущей регистрации может опережать текущее время решения.
	require.Nil(t, got.VersionWatermark)
	checkWatermark := func(expected time.Time) {
		t.Helper()
		current, _, _ := read(candidate)
		require.NotNil(t, current.VersionWatermark)
		require.True(t, expected.Equal(*current.VersionWatermark), "ожидалось %s, получено %s", expected, *current.VersionWatermark)
	}
	previousVersion := version.Add(time.Hour)
	receipt(candidate, previousVersion, first, "00000000-0000-0000-0000-000000000001")
	checkWatermark(previousVersion)
	retiredThrough := previousVersion.Add(time.Second)
	exec(`INSERT INTO kaname.resource_registration_retirement(object_type,object_id,relation,subject,delete_through)
VALUES('odd_item',$1,'parent','odd_box:'||$2,$3)`, candidate, parent, retiredThrough)
	checkWatermark(retiredThrough)
	storedFact := retiredThrough.Add(time.Second)
	exec(`INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
VALUES('odd_item',$1,'parent','odd_box:'||$2,$3)`, candidate, parent, storedFact)
	checkWatermark(storedFact)
	storedEdge := storedFact.Add(time.Second)
	exec(`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version)
VALUES('odd_item',$1,'odd_box',$2,2,$3)`, candidate, parent, storedEdge)
	checkWatermark(storedEdge)
	// При избытке потомков результат ограничен порогом ёмкости.
	mirror("probe.items", parent+"/module-two", version)
	edge("odd_item", parent+"/module-two", 1)
	mirror("probe.items", parent+"/module-three", version)
	edge("odd_item", parent+"/module-three", 1)
	capped, _, _ := read(candidate)
	require.NotNil(t, capped.LiveChildren)
	require.Equal(t, 2, *capped.LiveChildren)

	// Для повтора квитанция сверяется с текущей версией, инкарнацией и ребром.
	mirror("probe.items", candidate, version)
	external, _, _ := read(candidate)
	require.NotNil(t, external.ChildVersion)
	require.Nil(t, external.ReplayVersion)
	require.Nil(t, external.LiveChildren)
	require.Empty(t, external.RecentCreations)
	edge("odd_item", candidate, 1)
	receipt(candidate, version.Add(-time.Second), third, incarnation)
	stale, _, _ := read(candidate)
	require.Nil(t, stale.ReplayVersion)
	receipt(candidate, version, third, "00000000-0000-0000-0000-000000000001")
	old, _, _ := read(candidate)
	require.Nil(t, old.ReplayVersion)
	exec(`UPDATE kaname.authority_child_creation SET parent_incarnation=$2::uuid WHERE child_type='probe.items' AND child_id=$1 AND source_version=$3`, candidate, incarnation, version)
	replay, _, _ := read(candidate)
	require.NotNil(t, replay.ReplayVersion)
	require.True(t, version.Equal(*replay.ReplayVersion))
	exec(`DELETE FROM kaname.resource_parent_edge WHERE object_type='odd_item' AND object_id=$1`, candidate)
	detached, _, _ := read(candidate)
	require.Nil(t, detached.ReplayVersion, "квитанция не заменяет ребро на родителя")
	edge("odd_item", candidate, 1)

	exec(`UPDATE kaname.authority_child_parent_state SET closed_at=$2 WHERE object_type='probe.boxes' AND object_id=$1`, parent, third)
	closed, closedRows, closedReads := read(candidate)
	require.Equal(t, missingReads, closedReads, "закрытое состояние останавливает чтение до квоты и повтора")
	require.Nil(t, closed.ChildVersion)
	require.NotNil(t, closed.ClosedAt)
	require.True(t, third.Equal(*closed.ClosedAt))
	require.Nil(t, closed.ReplayVersion)
	require.Nil(t, closed.LiveChildren)
	require.Empty(t, closed.RecentCreations)
	// История создания не входит в чтение закрытого состояния.
	receipt(parent+"/after-close", version, version.Add(4*time.Second), incarnation)
	again, againRows, againReads := read(candidate)
	require.Nil(t, again.ReplayVersion)
	require.Equal(t, closedRows, againRows)
	require.Equal(t, closedReads, againReads)

	_, err = r.runtime.Exec(r.ctx, `SELECT * FROM kaname._authority_child_registration_capture_v1('probe.items',$1,64,64)`, candidate)
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code, "runtime не вправе вызывать закрытую функцию")
	for _, budgets := range [][2]int{{1, 64}, {64, 1}} {
		_, err = r.admin.Exec(r.ctx, `SELECT * FROM kaname._authority_child_registration_capture_v1('probe.items',$1,$2,$3)`, candidate, budgets[0], budgets[1])
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "54000", pe.Code, "для чтения требуется достаточный бюджет")
	}
}
