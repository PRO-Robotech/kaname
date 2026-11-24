// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_mirror_integration_test.go — сторона IAM (принимающего) при
// регистрации AccessBinding в области ресурса: RegisterResource выполняет UPSERT
// строки kaname.resource_mirror И выпускает намерение кортежа владельца в
// kaname.fga_outbox в ОДНОЙ транзакции записи (атомарная совместная фиксация, ban #10);
// UnregisterResource симметрично УДАЛЯЕТ строку зеркала и выпускает отзыв кортежа
// в одной транзакции.
//
// Этот путь лишь ЗАПОЛНЯЕТ зеркало; здесь его не читают для авторизации (это делает
// сведение). Путь кортежа владельца сохранён (идемпотентная доставка хотя бы один раз
// через обработчик очереди).
//
// Пропускается при `go test -short`.
package internal_iam_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

// newRegisterUCWithMirror создаёт сценарий RegisterResource на настоящем пуле с
// выпуском fga_outbox + resource_mirror + открытием транзакции (без соединения FGA).
func newRegisterUCWithMirror(t *testing.T) (*internaliam.RegisterResourceUseCase, *mirrorProbe) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	uc := internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalogfixture.Source()),
		kanamepg.NewRegistrationAudit(),
		kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "compute"})
	return uc, &mirrorProbe{pool: pool, scene: registrationscene.Seed(t, ctx, pool)}
}

// Успешный путь: Create экземпляра compute с метками → появляется строка зеркала,
// кортеж владельца фиксируется в той же транзакции записи.
func TestRegisterResource_B01_MirrorRowAndTupleCoCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	const obj = "compute_instance:inst-abc"

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + p.scene.Project,
		Relation:        "project",
		Object:          obj,
		Labels:          map[string]string{"env": "dev", "team": "core"},
		ParentProjectId: p.scene.Project,
		ParentAccountId: p.scene.Account,
	})
	require.NoError(t, err)

	prj, acc, labels := p.readMirror(t, ctx, "compute.instance", "inst-abc")
	require.Equal(t, p.scene.Project, prj)
	require.Equal(t, p.scene.Account, acc)
	require.Equal(t, map[string]string{"env": "dev", "team": "core"}, labels)

	// Кортеж владельца фиксируется В ТОЙ ЖЕ транзакции записи.
	require.Equal(t, 1, p.outboxCount(t, ctx, obj), "owner-tuple emitted alongside mirror")
}

// Данные с пустыми метками → строка зеркала с labels={} и заполненным родителем.
func TestRegisterResource_B02_EmptyLabelsGraceful(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + p.scene.Project,
		Relation:        "project",
		Object:          "compute_instance:inst-nolabels",
		Labels:          map[string]string{},
		ParentProjectId: p.scene.Project,
	})
	require.NoError(t, err)

	prj, _, labels := p.readMirror(t, ctx, "compute.instance", "inst-nolabels")
	require.Equal(t, p.scene.Project, prj)
	require.Equal(t, map[string]string{}, labels)
}

// Атомарность совместной фиксации: кортеж владельца и строка зеркала появляются вместе.
// Ошибка внутри транзакции записи не оставляет НИ ТОГО НИ ДРУГОГО (проверено путём отката
// в пробах выпуска resource_mirror + fga_outbox). Здесь проверяем
// положительный исход: после успешного Register присутствуют ОБА эффекта.
func TestRegisterResource_B03_AtomicCoCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	const obj = "compute_instance:inst-atomic"

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: obj,
		Labels: map[string]string{"env": "dev"}, ParentProjectId: p.scene.Project, ParentAccountId: p.scene.Account,
	}))

	prj, _, _ := p.readMirror(t, ctx, "compute.instance", "inst-atomic")
	require.Equal(t, p.scene.Project, prj, "mirror present")
	require.Equal(t, 1, p.outboxCount(t, ctx, obj), "tuple present — both committed together")
}

// Идемпотентность: повтор RegisterResource (повтор обработчика) → без дубля зеркала.
func TestRegisterResource_B06_IdempotentMirrorUpsert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	req := &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: "compute_instance:inst-idem",
		Labels: map[string]string{"env": "dev"}, ParentProjectId: p.scene.Project,
	}
	require.NoError(t, uc.Register(ctx, req))
	require.NoError(t, uc.Register(ctx, req), "repeat must be OK (idempotent)")

	require.Equal(t, 1, p.mirrorCount(t, ctx, "compute.instance", "inst-idem"),
		"PK ⇒ exactly one mirror row on repeat (β-06)")
}

// Конкурентность: параллельные Register одного объекта с разными метками →
// ровно одна строка зеркала, детерминированная последняя запись (без частичной записи, ban #10).
func TestRegisterResource_B05_ConcurrentUpsertOneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	labelSets := []map[string]string{
		{"env": "dev"},
		{"env": "prod"},
		{"env": "staging"},
		{"env": "dev", "team": "core"},
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = uc.Register(ctx, &iamv1.RegisterResourceRequest{
				SubjectId: "project:" + p.scene.Project, Relation: "project", Object: "compute_instance:inst-race",
				Labels: labelSets[i%len(labelSets)], ParentProjectId: p.scene.Project,
			})
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent register #%d must succeed (no INTERNAL leak)", i)
	}
	require.Equal(t, 1, p.mirrorCount(t, ctx, "compute.instance", "inst-race"),
		"PK serializes concurrent writers ⇒ exactly one row (β-05)")
	_, _, labels := p.readMirror(t, ctx, "compute.instance", "inst-race")
	require.Contains(t, []string{"dev", "prod", "staging"}, labels["env"],
		"final labels are one deterministic last-write, not a half-merge")
}

// Unregister → строка зеркала удалена И отзыв кортежа выпущен в одной транзакции.
func TestRegisterResource_B07_UnregisterDeletesMirrorAndRevokesTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	const obj = "compute_instance:inst-gone"

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: obj,
		Labels: map[string]string{"env": "dev"}, ParentProjectId: p.scene.Project,
	}))
	require.Equal(t, 1, p.mirrorCount(t, ctx, "compute.instance", "inst-gone"))

	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: obj,
	}))
	require.Equal(t, 0, p.mirrorCount(t, ctx, "compute.instance", "inst-gone"),
		"Unregister removes the mirror row (β-07)")
	require.Equal(t, "fga.tuple.delete", p.lastOutboxEvent(t, ctx, obj),
		"tuple-revoke emitted in the same tx as the mirror delete")
}

// Идемпотентно: Unregister никогда не зарегистрированного объекта → OK, без паники.
func TestRegisterResource_B07b_UnregisterAbsentIsOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	err := uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: "compute_instance:inst-never",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "AW-15 supersedes unknown-key cleanup: no saved scope means refusal")
	var writes int
	require.NoError(t, p.pool.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='compute_instance:inst-never'`).Scan(&writes))
	require.Zero(t, writes)
}

// Обратная совместимость: прежний вызывающий передаёт только поля 1-4 → строка зеркала с
// пустыми метками/родителем (допустимо), кортеж выпущен как прежде.
func TestRegisterResource_B09_LegacyCallerEmptyMirror(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	const obj = "compute_instance:inst-legacy"

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: obj,
		// Без меток / parent_* — прежний compute.
	}))

	prj, acc, labels := p.readMirror(t, ctx, "compute.instance", "inst-legacy")
	require.Equal(t, "", prj)
	require.Equal(t, "", acc)
	require.Equal(t, map[string]string{}, labels)
	require.Equal(t, 1, p.outboxCount(t, ctx, obj), "owner-tuple emitted as before")
}

// Отрицательная проба: неверные метки (ключ с заглавной буквой) → InvalidArgument, без зеркала
// и строки outbox (проверка отвергает до транзакции записи).
func TestRegisterResource_B15_InvalidLabelsRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	const obj = "compute_instance:inst-badlabels"
	// «Ничего не записано» — утверждение обо всей таблице: объектный отбор не
	// увидел бы строку, записанную под чужим объектом, поэтому рядом дельта.
	before := p.totalRows(t, ctx)

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: obj,
		Labels: map[string]string{"ENV": "x"}, ParentProjectId: p.scene.Project,
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err), "invalid label key → InvalidArgument (β-15)")
	require.Equal(t, 0, p.mirrorCount(t, ctx, "compute.instance", "inst-badlabels"), "no mirror row on validation failure")
	require.Equal(t, 0, p.outboxCount(t, ctx, obj), "no outbox row for the object the request named")
	require.Equal(t, before, p.totalRows(t, ctx), "no outbox row on validation failure — at all")
}

// Зеркало несёт ТОЛЬКО метки и родительскую область арендатора (без инфраструктурных
// полей); устаревшая строка сохраняется (висячая допустима) — чтение не паникует.
func TestRegisterResource_B16_MirrorShapeAndDanglingSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + p.scene.Project, Relation: "project", Object: "compute_instance:inst-orphan",
		Labels: map[string]string{"env": "dev"}, ParentProjectId: p.scene.Project, ParentAccountId: p.scene.Account,
	}))

	// Набор столбцов точно равен проекции арендатора (без инфраструктурных столбцов).
	cols := p.columns(t, ctx)
	require.ElementsMatch(t,
		[]string{"object_type", "object_id", "parent_project_id", "parent_account_id", "labels", "source_version", "updated_at"},
		cols, "resource_mirror exposes only tenant-facing labels + parent-scope + monotonic source_version (β-16, β-hardening)")

	// Устаревшая строка без Unregister сохраняется: повторное чтение допустимо.
	prj, _, _ := p.readMirror(t, ctx, "compute.instance", "inst-orphan")
	require.Equal(t, p.scene.Project, prj)
}

// ── Вспомогательные функции ───────────────────────────────────────────────

// mirrorProbe — чтения проб и проект сцены: родителя регистрации kaname выводит
// из своих данных (kaname#982), и регистрация под проектом, которого в kaname
// нет, отвергается.
type mirrorProbe struct {
	pool  *pgxpool.Pool
	scene registrationscene.Scene
}

func (p *mirrorProbe) readMirror(t *testing.T, ctx context.Context, objType, objID string) (prj, acc string, labels map[string]string) {
	t.Helper()
	var raw string
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT parent_project_id, parent_account_id, labels::text
		   FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`, objType, objID).
		Scan(&prj, &acc, &raw))
	labels = map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(raw), &labels))
	return prj, acc, labels
}

func (p *mirrorProbe) mirrorCount(t *testing.T, ctx context.Context, objType, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`, objType, objID).Scan(&n))
	return n
}

// outboxCount / lastOutboxEvent отбирают строки ПО СВОИМ объектам — тем, что
// тест назвал в собственном запросе. Обоснование формы и что случилось с
// прежним «всё, кроме известного посева» — у outboxProbe в
// register_resource_integration_test.go; здесь то же решение, не второе.
func (p *mirrorProbe) outboxCount(t *testing.T, ctx context.Context, objects ...string) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox
		  WHERE payload->>'object' = ANY($1::text[])`, scopedToOwnObjects(t, objects)).Scan(&n))
	return n
}

func (p *mirrorProbe) totalRows(t *testing.T, ctx context.Context) int {
	t.Helper()
	return outboxTotalRows(t, ctx, p.pool)
}

func (p *mirrorProbe) lastOutboxEvent(t *testing.T, ctx context.Context, objects ...string) string {
	t.Helper()
	var et string
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT event_type FROM kaname.fga_outbox
		  WHERE payload->>'object' = ANY($1::text[])
		  ORDER BY id DESC LIMIT 1`, scopedToOwnObjects(t, objects)).Scan(&et))
	return et
}

func (p *mirrorProbe) columns(t *testing.T, ctx context.Context) []string {
	t.Helper()
	rows, err := p.pool.Query(ctx,
		`SELECT column_name FROM information_schema.columns
		  WHERE table_schema = 'kaname' AND table_name = 'resource_mirror'`)
	require.NoError(t, err)
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols = append(cols, c)
	}
	return cols
}
