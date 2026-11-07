// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// resource_mirror_t31_g3_integration_test.go — межсервисная
// проверка G-3 на стороне IAM: отзыв ARM_LABELS при смене меток.
//
// Контракт G-3: полное снятие меток (labels → {}) ЖИВОГО ресурса выпускает
// RegisterResource (mirror.upsert) с ПУСТОЙ картой меток, а НЕ
// UnregisterResource. Поэтому строка зеркала должна СОХРАНИТЬСЯ с labels={}
// (а не УДАЛИТЬСЯ, как при Unregister): ресурс ещё существует в своём
// источнике, значит его кортеж владельца / регистрация включения (parent_project_id /
// parent_account_id) остаются целы; лишь селекторы меток перестают совпадать.
// UnregisterResource остаётся только для настоящего Delete ресурса.
//
// Проба проверяет SQL-инвариант G-3 прямо на kaname.resource_mirror
// после RegisterResource(labels={}) с более новым source_version:
// - Строка ПРИСУТСТВУЕТ (count==1), labels='{}'::jsonb (ПОЛНАЯ ЗАМЕНА).
// - parent_project_id / parent_account_id СОХРАНЕНЫ.
// - source_version продвинут (монотонный upsert применён).
// - Выполнен UPSERT, а не DELETE (Unregister снял бы строку).
//
// Ожидание (G-6): ЗЕЛЕНО на текущем выпуске зеркала iam (upsert полностью
// заменяет метки и монотонен по source_version). КРАСНЫЙ исход означал бы дефект стороны IAM.
//
// ТОЛЬКО ПРОБЫ (ban #13): производственный код не затронут.
// Запуск: `make test` (testcontainers + Docker). Пропускается при -short.

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
)

// readMirrorRowT31 читает полную проекцию строки зеркала для арендатора.
// found=false при отсутствии строки (то есть после удаления через Unregister).
func readMirrorRowT31(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) (found bool, parentPrj, parentAcc, labelsText string, sourceVersion time.Time) {
	t.Helper()
	err := pool.QueryRow(ctx,
		`SELECT parent_project_id, parent_account_id, labels::text, source_version
		   FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`,
		objType, objID).Scan(&parentPrj, &parentAcc, &labelsText, &sourceVersion)
	if err != nil {
		return false, "", "", "", time.Time{}
	}
	return true, parentPrj, parentAcc, labelsText, sourceVersion
}

// ── T3.1-G3-01: upsert {} при снятии метки — строка зеркала остаётся (НЕ Unregister) ─

func TestNetworkRepo_T31G301_UpsertNotUnregister_MirrorRowStays(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	uc := internal_iam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalogfixture.Source()),
		kanamepg.NewRegistrationAudit(),
		kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"})

	const objType, objID = "vpc.network", "net-g3"
	// Проект, известный kaname: родителя регистрации kaname выводит сам
	// (kaname#982), и под выдуманным проектом регистрация отвергается.
	scene := registrationscene.Seed(t, ctx, pool)
	prj, acc := scene.Project, scene.Account

	// Дано: сеть зарегистрирована с меткой (выпуск при Create) на v0.
	v0 := time.Now().Add(-time.Minute)
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + prj,
		Relation:        "project",
		Object:          "vpc_network:" + objID,
		Labels:          map[string]string{"network": "treska"},
		ParentProjectId: prj,
		ParentAccountId: acc,
		SourceVersion:   timestamppb.New(v0),
	}))

	found0, prj0, acc0, labels0, srcV0 := readMirrorRowT31(t, ctx, pool, objType, objID)
	require.True(t, found0, "mirror row present after Create-time register")
	require.Equal(t, prj, prj0)
	require.Equal(t, acc, acc0)
	require.JSONEq(t, `{"network":"treska"}`, labels0)

	// Когда: метка полностью снята → потребитель (исправление kacho-iam#113) повторно выпускает
	// RegisterResource (mirror.upsert) с labels={} и БОЛЕЕ НОВЫМ source_version
	// (G-3: upsert {}, а НЕ UnregisterResource).
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + prj,
		Relation:        "project",
		Object:          "vpc_network:" + objID,
		Labels:          map[string]string{}, // Пусто — полное снятие.
		ParentProjectId: prj,
		ParentAccountId: acc,
		SourceVersion:   timestamppb.New(v0.Add(time.Minute)),
	}))

	// Тогда (G-3): строка ВСЁ ЕЩЁ ПРИСУТСТВУЕТ (upsert, а не удаление Unregister) …
	found1, prj1, acc1, labels1, srcV1 := readMirrorRowT31(t, ctx, pool, objType, objID)
	require.True(t, found1,
		"mirror row MUST survive full label removal (G-3: upsert {}, not UnregisterResource DELETE)")

	// …метки ПОЛНОСТЬЮ ЗАМЕНЕНЫ на {} …
	assert.JSONEq(t, `{}`, labels1, "labels fully replaced with {} (selectors stop matching)")

	// …родительская область СОХРАНЕНА (кортеж владельца / регистрация включения живы) …
	assert.Equal(t, prj, prj1, "parent_project_id preserved (registration not torn down)")
	assert.Equal(t, acc, acc1, "parent_account_id preserved (registration not torn down)")

	// …а source_version ПРОДВИНУТ (монотонный upsert применён, изменение действительно было).
	assert.True(t, srcV1.After(srcV0),
		"source_version advanced (monotonic upsert applied the newer label-removal)")

	// Ровно одна строка по PK (object_type, object_id) — без дубля / расщепления.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`,
		objType, objID).Scan(&n))
	assert.Equal(t, 1, n, "single mirror row (PK upsert, no split)")
}
