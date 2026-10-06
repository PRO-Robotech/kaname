// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// current_authz_revision_integration_test.go — производитель токена версии прав
// за внутренним слушателем (приёмка NTF-3, kacho#2918, Р30 «Производитель
// токена», редакция 38; сценарий NTF3-179 (г) в части службы доступа; Д133,
// Д134; полоса K1).
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ПОСТРОЕНО
//
// Службы собирает строитель корня (`buildServices`) — проба не знает и не
// утверждает, каким портом обработчик берёт снимок; регистрация —
// `registerInternalServices`, цепочка — `internalUnaryChain`, рукопожатие —
// mTLS с листом точного SAN; база — свой клон на testcontainers. Круг
// вызывающих — «тот же, что `RegisterResource`»: модуль, чья служебная учётка
// состоит в `module-relation-writers` (право `fga_writer` на кластере); посев —
// настоящий применитель манифестов.
//
// Вызов идёт по полному имени метода с пустым запросом, ответ разбирается по
// дескриптору контракта: до появления метода в контракте проба собирается и
// краснеет ИСХОДОМ вызова, а не отказом сборки пакета.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//   - сертификат модуля-владельца вида (storage): ответ с непустым `authz_rev`,
//     и это ПОЛНЫЙ снимок базы службы доступа на момент вызова (`pg_snapshot`),
//     а не его нижняя граница: транзакция, шедшая в момент вызова, в снимке не
//     видна, закоммиченная до вызова — видна (Р30: ограда «версия права видна в
//     снимке R_E»);
//   - сертификат `notify` (близнец по одному факту — SAN): `PERMISSION_DENIED`
//     `permission denied`, `ErrorInfo{reason: AUTHZ_DENIED}`, токена в ответе
//     нет — токен `notify` берёт из строки события (NTF3-179 (г)).
//
// Порядок несущий: фикстура (дверь признаёт storage писателем и не признаёт
// notify) — до вызова предмета.
package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	// carStorageSAN — модуль-владелец вида пробы (NTF3-179: сертификат storage).
	carStorageSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-storage"
	// carFullMethod — метод предмета.
	carFullMethod = "/kaname.cloud.iam.v1.InternalIAMService/CurrentAuthzRevision"
	carService    = "kaname.cloud.iam.v1.InternalIAMService"
	carMethod     = "CurrentAuthzRevision"

	// carWritersManifest — манифест службы: группа писателей и её право
	// `fga_writer` на кластере (форма — `internal/servicemanifest`).
	carWritersManifest = `
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
	// carStorageManifest — доставленный манифест модуля storage: служебная
	// учётка и вступление в группу писателей.
	carStorageManifest = `
apiVersion: iam/v1
module: storage
resources: []
seed:
  serviceAccounts:
    - name: kacho-storage
      account: system
      description: "Module SA: kacho-storage (probe NTF3-179)"
  joins:
    - serviceAccount: {account: system, name: kacho-storage}
      group: {account: system, name: module-relation-writers}
      why: "проба NTF3-179: модуль-владелец вида зовёт CurrentAuthzRevision"
`
)

// carWorld — служба доступа пробы за внутренним слушателем.
type carWorld struct {
	db  *ntfDB
	lis *ntfListener
}

func newCARWorld(t *testing.T) *carWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("интеграционная проба: нужен Docker")
	}
	db := newNTFDB(t)
	door, _ := ntfDoor(db)
	ntfApply(t, db, carWritersManifest, carStorageManifest)
	carRequireWriterCircle(t, door)

	cfg, err := ntfConfig(t, "")
	require.NoError(t, err, "фикстура: настройка пробы не загрузилась")
	// Ручки без умолчания, которые судит строитель корня, — значения фикстуры
	// (как у `inviteWiringBaseCfg`): без них сборка остановилась бы раньше
	// предмета.
	if cfg.AuthN.Login.HasherFormat == "" {
		cfg.AuthN.Login.HasherFormat = "argon2id"
		cfg.AuthN.Login.HasherMemory = 65536
		cfg.AuthN.Login.HasherIterations = 3
		cfg.AuthN.Login.HasherParallelism = 4
	}
	if cfg.Notifications.CutoffGuard == nil {
		guard := 30 * time.Second
		cfg.Notifications.CutoffGuard = &guard
	}
	if cfg.Invite.TTL == nil {
		ttl := 72 * time.Hour
		cfg.Invite.TTL = &ttl
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := kanamepg.New(db.pool, nil)
	svcs, err := buildServices(db.pool, nil, nil, repo, repo, nil, nil, metrics.NewRegistry(), cfg, nil, logger)
	require.NoError(t, err, "фикстура: строитель корня не собрал службы")
	require.NotNil(t, svcs.internalIAMHandler, "фикстура: строитель корня не собрал InternalIAMService")
	chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
	require.NoError(t, err, "фикстура: цепочка внутреннего слушателя не собрана")
	w := &carWorld{db: db}
	w.lis = ntfServe(t, newNTFPKI(t), chain, func(s grpc.ServiceRegistrar) {
		registerInternalServices(s, svcs, nil, ntfMustConfig(t), nil)
	})
	return w
}

// carRequireWriterCircle — фикстура круга: дверь признаёт учётку storage
// писателем (`fga_writer` на кластере) и НЕ признаёт учётку notify. Без этого
// отказ notify мог бы прийти от пустого круга, а ответ storage — от круга,
// которого никто не проверял.
func carRequireWriterCircle(t *testing.T, door *service.AuthorizeService) {
	t.Helper()
	for _, c := range []struct {
		svc  string
		want bool
	}{{"storage", true}, {"notify", false}} {
		res, err := door.CheckRelation(context.Background(), service.CheckRelationRequest{
			Subject:  "service_account:" + authzguard.ServiceAccountIDForService(c.svc),
			Relation: authzguard.RelationWriteRelation,
			Object:   "cluster:cluster_root",
		})
		require.NoErrorf(t, err, "фикстура: дверь не ответила о круге писателей (%s)", c.svc)
		require.Equalf(t, c.want, res.Allowed, "фикстура: учётка %s в круге писателей — %v, ожидалось %v",
			c.svc, res.Allowed, c.want)
	}
}

// carCall — вызов метода предмета пиром san. Ответ разбирается по дескриптору
// контракта; до объявления метода разбирать нечем, и это отказ предмета.
func (w *carWorld) carCall(t *testing.T, san string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw := &emptypb.Empty{}
	if err := w.lis.dial(t, san).Invoke(ctx, carFullMethod, &emptypb.Empty{}, raw); err != nil {
		return "", err
	}
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(carService)
	require.NoError(t, err, "служба %s не найдена в реестре дескрипторов", carService)
	m := d.(protoreflect.ServiceDescriptor).Methods().ByName(carMethod)
	require.NotNilf(t, m, "метод %s ответил, но не объявлен контрактом", carFullMethod)
	b, err := proto.Marshal(raw)
	require.NoError(t, err)
	resp := dynamicpb.NewMessage(m.Output())
	require.NoError(t, proto.Unmarshal(b, resp), "ответ %s не разбирается по контракту", carFullMethod)
	f := m.Output().Fields().ByName("authz_rev")
	require.NotNilf(t, f, "ответ %s без поля authz_rev", carFullMethod)
	return resp.Get(f).String(), nil
}

// visibleIn — видна ли транзакция xid в снимке tok (текстовая форма
// `pg_snapshot`). Отказ приведения — красный: токен не полный снимок.
func visibleIn(t *testing.T, pool *pgxpool.Pool, xid, tok string) bool {
	t.Helper()
	var v bool
	require.NoErrorf(t, pool.QueryRow(context.Background(),
		`SELECT pg_visible_in_snapshot($1::xid8, $2::pg_snapshot)`, xid, tok).Scan(&v),
		"токен %q не приводится к полному снимку pg_snapshot (Р30: токен — полный снимок, а не его нижняя граница)", tok)
	return v
}

// TestNTF3179g_ModuleOwnerGetsAFullSnapshotAndNotifyIsRefused — NTF3-179 (г).
func TestNTF3179g_ModuleOwnerGetsAFullSnapshotAndNotifyIsRefused(t *testing.T) {
	w := newCARWorld(t)
	ctx := context.Background()

	t.Run("storage: полный снимок на момент вызова", func(t *testing.T) {
		// Транзакция, закоммиченная до вызова, и транзакция, идущая в момент
		// вызова. Обе — в базе службы доступа, своими соединениями фикстуры.
		var committedXID string
		require.NoError(t, w.db.fixture.QueryRow(ctx,
			`SELECT pg_current_xact_id()::text FROM (SELECT 1) x`).Scan(&committedXID))
		inflight, err := w.db.fixture.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = inflight.Rollback(ctx) }()
		var inflightXID string
		require.NoError(t, inflight.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&inflightXID))

		tok, err := w.carCall(t, carStorageSAN)
		require.NoErrorf(t, err, "модуль-владелец вида (storage) не получил токен методом %s", carFullMethod)
		require.NotEmpty(t, tok, "ответ storage с пустым authz_rev")
		require.Truef(t, visibleIn(t, w.db.fixture, committedXID, tok),
			"транзакция %s, закоммиченная до вызова, в токене %q не видна", committedXID, tok)
		require.Falsef(t, visibleIn(t, w.db.fixture, inflightXID, tok),
			"транзакция %s, шедшая в момент вызова, в токене %q видна — ограда пропустила бы её правку", inflightXID, tok)
	})

	t.Run("notify: отказ, токена нет", func(t *testing.T) {
		tok, err := w.carCall(t, ntfNotifySAN)
		require.Emptyf(t, tok, "notify получил токен %q", tok)
		requireAuthzDenied(t, err)
	})
}
