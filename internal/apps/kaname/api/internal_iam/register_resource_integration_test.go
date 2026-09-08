// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_integration_test.go — SEC-C group A (A-01..A-05).
//
// Verifies RegisterResource / UnregisterResource (Internal FGA-proxy):
//   - A-01 happy: tuple enqueued into kaname.fga_outbox (event fga.tuple.write),
//     in the SAME writer-tx (rollback ⇒ no orphan row);
//   - A-02 idempotent register: re-issue same tuple → OK (вторая строка журнала;
//     схлопывает их ПРОЕКЦИЯ — триггер `relation_fact_from_journal` пишет прямой
//     факт через ON CONFLICT, поэтому два намерения дают один факт);
//   - A-03 unregister: enqueues fga.tuple.delete;
//   - A-04 idempotent unregister: missing tuple → OK (no NotFound);
//   - A-05 invalid args: empty subject/relation/object + malformed object →
//     sync InvalidArgument, NO outbox row.
//
// The use-case writes the owner-hierarchy tuple verbatim from the request
// ({subject_id, relation, object}); the SEC-A proto carries the pre-composed
// relation strings.
//
// ЗДЕСЬ СТОЯЛА ССЫЛКА НА ПРИМЕНИТЕЛЯ ДРЕНАЖА — ни его, ни его файла в дереве нет.
// Дренаж снят вместе с внешним движком прав (стадия S6 эпика #747); единственный
// потребитель журнала — триггер проекции, и он складывает прямой факт В ТОЙ ЖЕ
// транзакции. Прежняя проза объявляла асинхронное применение, которого не бывает,
// и следующий читатель искал бы координату, которой не существует (kacho#1049).
//
// Authz-gate (group B) is exercised in the rebac test.
//
// Skipped under `go test -short`.
package internal_iam_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// newRegisterUC builds the RegisterResource use-case backed by a real pool's
// outbox emitter + tx beginner (внешнего вызова нет: строку журнала подхватывает
// триггер проекции в той же транзакции).
func newRegisterUC(t *testing.T) (*internaliam.RegisterResourceUseCase, *outboxProbe) {
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
	)
	return uc, &outboxProbe{pool: pool}
}

func TestRegisterResource_A01_EnqueuesWriteTupleInTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	// Один литерал объекта на запрос И на область отбора — разойтись не могут.
	const obj = "vpc_network:enp00000000000000001"

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1",
		Relation:  "parent",
		Object:    obj,
	})
	require.NoError(t, err)

	n, et, payload := h.lastOutbox(t, ctx, obj)
	require.Equal(t, 1, n, "exactly one outbox row enqueued")
	require.Equal(t, "fga.tuple.write", et)
	require.Equal(t, "project:prj-1", payload["user"])
	require.Equal(t, "parent", payload["relation"])
	require.Equal(t, obj, payload["object"])

	// Здесь стояло ещё одно утверждение — «строка ПОКА НЕ ДОСТАВЛЕНА»
	// (`sent_at IS NULL`). Оно снято вместе со своим предметом (kacho#1042):
	// дренажа у этого журнала нет (стадия S6 эпика #747, `a4b6cfba9`), колонки
	// доставки сняла миграция 20260822160000 (kacho#917). Строка действует
	// С КОММИТА, поэтому «доставлена или нет» — вопрос, которого не существует.
}

func TestRegisterResource_A02_IdempotentRegister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	const obj = "vpc_network:enp00000000000000001"
	req := &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: obj,
	}
	err := uc.Register(ctx, req)
	require.NoError(t, err)
	err = uc.Register(ctx, req) // repeat — must be OK, never AlreadyExists.
	require.NoError(t, err, "repeat register must be OK, not AlreadyExists (idempotency contract)")

	// Two write rows enqueued; схлопывает их ПРОЕКЦИЯ (триггер журнала пишет прямой
	// факт через ON CONFLICT), а не применитель дренажа — его не существует.
	// The RPC never surfaces AlreadyExists.
	n, _, _ := h.lastOutbox(t, ctx, obj)
	require.Equal(t, 2, n)
}

func TestRegisterResource_A03_UnregisterEnqueuesDeleteTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	const obj = "vpc_network:enp00000000000000001"

	err := uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: obj,
	})
	require.NoError(t, err)

	n, et, _ := h.lastOutbox(t, ctx, obj)
	require.Equal(t, 1, n)
	require.Equal(t, "fga.tuple.delete", et)
}

func TestRegisterResource_A04_IdempotentUnregister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, _ := newRegisterUC(t)

	// Tuple never registered — unregister must be OK, never NotFound.
	err := uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp99999999999999999",
	})
	require.NoError(t, err, "unregister of absent tuple must be OK, not NotFound")
}

func TestRegisterResource_A05_InvalidArgsNoOutbox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	cases := []struct {
		name string
		req  *iamv1.RegisterResourceRequest
	}{
		{"empty subject_id", &iamv1.RegisterResourceRequest{Relation: "parent", Object: "vpc_network:enp1"}},
		{"empty relation", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Object: "vpc_network:enp1"}},
		{"empty object", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Relation: "parent"}},
		{"object with space", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp 1"}},
		{"object missing colon", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network"}},
	}
	// Область отбора ВЫВОДИТСЯ из тех же запросов, что уходят в use-case, —
	// её нельзя забыть обновить при правке случая.
	objects := make([]string, 0, len(cases))
	// Снимок размера таблицы ДО: «ничего не записано» — утверждение обо всей
	// таблице, и дельта проверяет его там, куда объектный отбор не смотрит
	// (строка, записанная под чужим объектом).
	before := h.totalRows(t, ctx)

	for _, c := range cases {
		objects = append(objects, c.req.GetObject())
		t.Run(c.name, func(t *testing.T) {
			err := uc.Register(ctx, c.req)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "validation → InvalidArgument")
		})
	}
	n, _, _ := h.lastOutbox(t, ctx, objects...)
	require.Equal(t, 0, n, "no outbox row for any object the request named")
	require.Equal(t, before, h.totalRows(t, ctx), "no outbox row on validation failure — at all")
}

// ── helpers ──────────────────────────────────────────────────────────────────

// outboxProbe reads back kaname.fga_outbox rows for assertions.
type outboxProbe struct{ pool *pgxpool.Pool }

// scopedToOwnObjects — область отбора ПО СВОИМ объектам, а не «всё, кроме
// известного посева». Пустая область запрещена: она не отбирает ничего и не
// утверждает ничего.
//
// Прежняя форма перечисляла посевные объекты списком (`object NOT IN
// ('iam_fgaproxy:system', 'cluster:cluster_root')`), а такой список
// стареет молча: он растёт от работы, к пробе отношения не имеющей, и
// сопровождать его никто не обязан. Миграции 0093/0096 завели членство
// служебных учёток в группе читателей потолков — объект `group:<gid>`, ни в
// одну из двух перечисленных строк не попадающий, — и пять посевных строк
// стали засчитываться пробе как «созданные тестом».
//
// Красная сторона этой формы шумит и потому заметна. Тихая — хуже: тот же
// список, исключив лишнее, даёт «ноль», и утверждение зеленеет, не посмотрев
// ни на одну строку. У положительного отбора этой слепой зоны нет by
// construction — фикстура знает свои объекты, и она же передаёт их в запрос,
// поэтому область отбора и вход не могут разойтись.
//
// Прецеденты того же класса на той же таблице, каждый со своей записью:
// fga_outbox/emitter_integration_test.go (перешла на отбор по своим объектам),
// cluster_admin_grant_integration_test.go (отбор по relation+user — там
// объектный blocklist исключал ещё и СОБСТВЕННЫЕ строки теста, давая ноль),
// access_binding_fga_outbox_integration_test.go (счёт дельты).
//
// Класс держится гейтом `internal/repohygiene`
// `TestProbeSelectsItsOwnRowsPositively`.
func scopedToOwnObjects(t *testing.T, objects []string) []string {
	t.Helper()
	require.NotEmpty(t, objects,
		"проба обязана назвать свои объекты: пустая область отбора считает ноль строк и не утверждает ничего")
	return objects
}

// outboxTotalRows — размер всей таблицы. Годен ТОЛЬКО как дельта (до/после):
// абсолютное число здесь было бы утверждением о посевных миграциях, а не о
// проверяемом коде. Один на обе пробы пакета — двух копий одного предмета в
// этом дереве не заводят.
func outboxTotalRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox`).Scan(&n))
	return n
}

// lastOutbox returns the row count and the latest row's event_type + payload,
// scoped to the objects THIS test named in its own requests.
func (p *outboxProbe) lastOutbox(t *testing.T, ctx context.Context, objects ...string) (count int, eventType string, payload map[string]string) {
	t.Helper()
	own := scopedToOwnObjects(t, objects)
	const mine = `payload->>'object' = ANY($1::text[])`
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox WHERE `+mine, own).Scan(&count))
	payload = map[string]string{}
	if count == 0 {
		return count, "", payload
	}
	var raw string
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT event_type, payload::text FROM kaname.fga_outbox WHERE `+mine+
			` ORDER BY id DESC LIMIT 1`, own).
		Scan(&eventType, &raw))
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))
	return count, eventType, payload
}

func (p *outboxProbe) totalRows(t *testing.T, ctx context.Context) int {
	t.Helper()
	return outboxTotalRows(t, ctx, p.pool)
}
