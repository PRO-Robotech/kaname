// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_rules_t31_iam_integration_test.go — межсервисный отзыв ARM_LABELS
// при смене метки, подтверждающий тест на стороне IAM.
//
// ОБЯЗАТЕЛЬНЫЙ новый интеграционный тест, закрепляющий гарантию немедленного
// отзыва СКВОЗНЫМ проходом через РАЗБОР ОЧЕРЕДИ работника согласования:
//
// выдать участнику ACTIVE через matchLabels:{network:treska}
// → RegisterResource(object="vpc_network:X", labels={}) с НОВОЙ
// source_version (запись потребителя добавит её при обновлении меток)
// → mirror.upsert ПОЛНОСТЬЮ ЗАМЕНЯЕТ метки и ставит в resource_reconcile_outbox
// событие "mirror.upsert" (сценарий RegisterResource, общий коммит по запрету №10)
// → worker.drain, а НЕ прямой вызов ReconcileObject, захватывает событие и
// запускает ReconcileObject(type,id)
// → ТОГДА участник matchLabels НЕМЕДЛЕННО ОТОЗВАН: реальный DELETE из
// access_binding_target_members и запись удаления кортежа FGA
// (цикл выбывших в reconcile.go:480-492).
//
// Ожидание: УСПЕХ на ТЕКУЩЕМ работнике IAM. Дефект целиком
// в записи потребителя; IAM уже верно отзывает доступ, получив в зеркале
// свежие пустые метки. Провал означает находку на стороне IAM.
//
// ТОЛЬКО ТЕСТ (запрет №13): боевой код не затрагивается.
// Запуск: `make test` (testcontainers + Docker). Пропускается при -short.

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// newRegisterUCWired собирает сценарий RegisterResource точно как
// корень сборки (cmd/kaname): запись fga_outbox и resource_mirror,
// начало транзакции, запись события согласования и разрешитель аккаунта.
// Именно подключение записи событий позволяет RegisterResource при смене метки поставить
// событие resource_reconcile_outbox, которое вычитывает работник.
func newRegisterUCWired(pool *pgxpool.Pool) *internal_iam.RegisterResourceUseCase {
	return internal_iam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalogfixture.Source()),
		kanamepg.NewRegistrationAudit(),
		kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"}).
		WithReconcile(kanamepg.NewReconcileEventEmitter()).
		WithAccountResolver(kanamepg.NewProjectAccountResolver())
}

// drainOnce доводит НАСТОЯЩИЙ путь разбора очереди работника до сходимости:
// тест проверяет всю цепочку RegisterResource→outbox→drain→ReconcileObject,
// а НЕ прямой вызов ReconcileObject. Метод разбора не экспортирован, поэтому
// запускаем цикл работника с малым интервалом разбора и большим интервалом обхода,
// затем ждём вычитанного события и отменяем работу. Большой SweepInterval
// не даёт периодическому обходу состязаться с разбором очереди, который и
// проверяется; единственный обход при старте безвреден благодаря идемпотентности.
func drainOnce(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	adapter := kanamepg.NewReconcileAdapter(pool, catalogfixture.Source())
	engine := newReconcilerEngine(pool)
	worker := seed.NewReconcileWorker(engine, adapter, seed.ReconcileWorkerConfig{
		DrainInterval: 20 * time.Millisecond,
		SweepInterval: time.Hour, // не даём периодическому обходу вмешиваться
		BatchSize:     64,
	})

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = worker.Run(runCtx) }()

	// Ждём разбора события работником (sent_at установлен): это
	// доказывает, что событие mirror.upsert потребил РАЗБОР ОЧЕРЕДИ, а не обход.
	require.Eventually(t, func() bool {
		var unsent int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE sent_at IS NULL`).
			Scan(&unsent); err != nil {
			return false
		}
		return unsent == 0
	}, 10*time.Second, 25*time.Millisecond, "worker must drain the resource_reconcile_outbox event")

	cancel()
	<-done
}

// newReconcilerEngine собирает сценарий согласования (ReconcileObject/Binding/
// ExpireBinding) на адаптере pg: этот движок запускает работник.
func newReconcilerEngine(pool *pgxpool.Pool) seed.ReconcileEngine {
	rec, _ := newReconciler(pool)
	return rec
}

// ── смена метки через RegisterResource → немедленный отзыв через очередь ─────

func TestReconcile_T31Iam01_LabelChangeViaRegisterResource_EagerRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "t31iam01")
	rec, _ := newReconciler(pool)

	// Дано: роль с правилами выдаёт v_get/v_list на vpc_network по matchLabels
	// {network:treska} и привязана тонкой привязкой к области проекта участника.
	rule := domain.Rule{
		Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"network": "treska"},
	}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "t31iam01role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	// Дано: сеть в зеркале С подходящей меткой, согласована как
	// ACTIVE (строка участника материализована, запись кортежа FGA поставлена). Строка зеркала
	// создана настоящим сценарием RegisterResource, тем же входом, которым потребитель
	// пользуется при создании, с ранней source_version.
	uc := newRegisterUCWired(pool)
	v0 := time.Now().Add(-time.Minute)
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + string(fx.prj),
		Relation:        "project",
		Object:          "vpc_network:net-treska",
		Labels:          map[string]string{"network": "treska"},
		ParentProjectId: string(fx.prj),
		ParentAccountId: string(fx.accID),
		SourceVersion:   timestamppb.New(v0),
	}))
	require.NoError(t, rec.ReconcileBinding(ctx, bid)) // материализовать участника ACTIVE

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "net-treska")
	require.True(t, ok, "matchLabels member materialized")
	require.Equal(t, domain.VerificationActive, st, "member ACTIVE before label removal")
	require.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:net-treska"), 1,
		"ACTIVE member emits the v_get/v_list write-tuple")

	// Когда: метка УДАЛЕНА на исходном ресурсе, потребитель
	// повторно отправляет RegisterResource с labels={} и НОВОЙ source_version. Это
	// ровно вход, добавляемый при обновлении меток; здесь вызываем его напрямую, ведь IAM —
	// принимающая сторона и обязан отзывать независимо от отправившего потребителя.
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + string(fx.prj),
		Relation:        "project",
		Object:          "vpc_network:net-treska",
		Labels:          map[string]string{}, // метка удалена: UPSERT {}, а не Unregister
		ParentProjectId: string(fx.prj),
		ParentAccountId: string(fx.accID),
		SourceVersion:   timestamppb.New(v0.Add(time.Minute)), // монотонно новая версия
	}))

	// Запускаем НАСТОЯЩИЙ разбор очереди работника: RegisterResource поставил событие согласования
	// mirror.upsert в той же транзакции записи; работник захватывает его и выполняет
	// ReconcileObject сквозным путём, а НЕ прямым вызовом ReconcileObject.
	drainOnce(t, ctx, pool)

	// Тогда (немедленный отзыв): участник matchLabels ИСЧЕЗ — реальный DELETE из
	// access_binding_target_members (цикл выбывших reconcile.go:480-492).
	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "net-treska")
	assert.False(t, stillMember,
		"label removed → member eager-revoked (real DELETE from access_binding_target_members)")

	// И: для отозванного участника записано удаление кортежа FGA.
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "vpc_network:net-treska"), 1,
		"label removed → FGA tuple-delete emitted (visibility revoked)")

	// И: строка зеркала ОСТАЁТСЯ с labels={} (UPSERT, а не Unregister):
	// очередь потребила mirror.upsert, строка существует, но меток нет.
	var mirrorRows int
	var labelsText string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) OVER (), labels::text FROM kaname.resource_mirror
		  WHERE object_type='vpc.network' AND object_id='net-treska'`).Scan(&mirrorRows, &labelsText))
	assert.Equal(t, 1, mirrorRows, "mirror row survives the label removal (upsert, not Unregister)")
	assert.Equal(t, "{}", labelsText, "mirror labels fully replaced with {} (FULL-REPLACE upsert)")

	// И: журнал больше не хранит кортежей отозванного участника, сирот нет.
	var ledger int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND object='vpc_network:net-treska'`, string(bid)).Scan(&ledger))
	assert.Equal(t, 0, ledger, "revoked member leaves no ledger residual (no standing orphan tuple)")
}
