// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_event_set_integration_test.go — все кортежи одного события
// применяются одним вызовом под одним поколением (приёмка NTF-3, kacho#2918,
// сценарий NTF3-185; Р30 «Единица поколения — событие», редакция 40).
//
// # Что судится
//
// Поколение `g_E` принадлежит событию объекта целиком: регистрация несёт набор
// кортежей события и применяется атомарно — либо весь набор, голова, зеркало и
// цепь одной транзакцией приёма, либо исход REJECTED_STALE без единой записи.
// Кортеж, которого нет в наборе следующего поколения, регистрацией не снимается.
// Снятие адресуется объектом и уносит все кортежи на нём.
//
// # Как проба задаёт набор
//
// Через отражение дескриптора по ИМЕНИ поля (`tuples`, `subject_id`,
// `relation`): проба собирается и на дереве без набора и падает там честным
// красным «поля tuples нет», а не ошибкой компиляции.
//
// # Чего проба НЕ судит — граница названа
//
// Аудиторию поколений (вопрос об аудитории с оградой) и запись снятого при
// надгробии (NTF3-185 (а) «аудитория», (г) «запись снятого») — их производит
// вопрос об аудитории, а не приём; здесь судится только то, что пишет приём.
//
// Пропускается под `go test -short`.
package internal_iam_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// Объекты сценариев: реестр `reg-1` и его репозитории; цепь репозитория —
// `[registry_registry:reg-1, project:prj-1, account:acc-1]` (С24).
const (
	evRegistry   = "registry_registry:reg-1"
	evRepoType   = "registry_repository"
	evRepoDotted = "registry.repositories"
	evOwnerUser  = "user:usr-X"
)

var evChain = []string{evRegistry, "project:prj-1", "account:acc-1"}

// evTuple — кортеж набора события.
type evTuple struct{ subject, relation string }

var (
	evParent = evTuple{evRegistry, "parent"}
	evOwner  = evTuple{evOwnerUser, "owner"}
)

// switchableGate — дверь записи регистрации: домен вызывающего задаёт проба
// (сертификат модуля в обвязке С24).
type switchableGate struct{ domain string }

func (g *switchableGate) Authorize(context.Context) (string, error) { return g.domain, nil }

// eventHarness — обработчик внутренней службы над настоящей базой: регистрация,
// снятие и публикация идут тем же путём, что вызов модуля (дверь, правило
// проксируемой записи, сценарий использования, приём).
type eventHarness struct {
	h    *internaliam.Handler
	gate *switchableGate
	pool *pgxpool.Pool
}

func newEventHarness(t *testing.T) *eventHarness {
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
	).WithResidualTupleReader(kanamepg.NewResidualTupleReader(pool))
	gate := &switchableGate{domain: "registry"}
	return &eventHarness{
		h:    internaliam.NewHandler(nil, nil).WithResourceRegistrar(uc, gate),
		gate: gate,
		pool: pool,
	}
}

// setTuples кладёт набор кортежей события в запрос регистрации по именам полей
// дескриптора.
func setTuples(t *testing.T, req *iamv1.RegisterResourceRequest, tuples []evTuple) {
	t.Helper()
	r := req.ProtoReflect()
	fd := r.Descriptor().Fields().ByName("tuples")
	if fd == nil {
		t.Fatalf("%s: поля `tuples` нет — набор кортежей события в контракт не заведён "+
			"(Р30 «Единица поколения — событие», NTF3-185)", r.Descriptor().FullName())
	}
	if fd.Cardinality() != protoreflect.Repeated || fd.Message() == nil {
		t.Fatalf("%s.tuples: %s %s, ожидается повторяемое сообщение", r.Descriptor().FullName(), fd.Cardinality(), fd.Kind())
	}
	list := r.Mutable(fd).List()
	for _, tp := range tuples {
		el := list.NewElement()
		m := el.Message()
		for name, v := range map[protoreflect.Name]string{"subject_id": tp.subject, "relation": tp.relation} {
			f := m.Descriptor().Fields().ByName(name)
			if f == nil {
				t.Fatalf("%s: поля %q нет", m.Descriptor().FullName(), name)
			}
			m.Set(f, protoreflect.ValueOfString(v))
		}
		list.Append(el)
	}
}

// evReg — регистрация репозитория `reg-1/<name>` набором `tuples` под поколением g.
func evReg(t *testing.T, name string, tuples []evTuple, g int64) *iamv1.RegisterResourceRequest {
	t.Helper()
	req := &iamv1.RegisterResourceRequest{
		Object:      evRepoType + ":reg-1/" + name,
		ParentChain: evChain,
		Generation:  g,
	}
	setTuples(t, req, tuples)
	return req
}

// evUnreg — снятие репозитория `reg-1/<name>` поколением g.
func evUnreg(name string, g int64) *iamv1.UnregisterResourceRequest {
	return &iamv1.UnregisterResourceRequest{Object: evRepoType + ":reg-1/" + name, Generation: g}
}

func (e *eventHarness) register(t *testing.T, req *iamv1.RegisterResourceRequest) error {
	t.Helper()
	_, err := e.h.RegisterResource(context.Background(), req)
	return err
}

func (e *eventHarness) unregister(t *testing.T, req *iamv1.UnregisterResourceRequest) error {
	t.Helper()
	_, err := e.h.UnregisterResource(context.Background(), req)
	return err
}

// head — поколение головы репозитория и признак надгробия.
func (e *eventHarness) head(t *testing.T, name string) (gen int64, withdrawn, present bool) {
	t.Helper()
	err := e.pool.QueryRow(context.Background(),
		`SELECT generation, withdrawn FROM kaname.object_head WHERE object_type = $1 AND object_id = $2`,
		evRepoDotted, "reg-1/"+name).Scan(&gen, &withdrawn)
	if err == pgx.ErrNoRows {
		return 0, false, false
	}
	require.NoError(t, err, "чтение головы reg-1/%s", name)
	return gen, withdrawn, true
}

func (e *eventHarness) requireHead(t *testing.T, name string, wantGen int64, wantWithdrawn bool, why string) {
	t.Helper()
	gen, withdrawn, ok := e.head(t, name)
	require.True(t, ok, "%s: головы reg-1/%s нет", why, name)
	require.Equal(t, wantGen, gen, "%s: поколение головы", why)
	require.Equal(t, wantWithdrawn, withdrawn, "%s: надгробие", why)
}

// facts — кортежи на репозитории в прямом факте, `<субъект>#<отношение>`, с их
// версией прав.
func (e *eventHarness) facts(t *testing.T, name string) map[string]string {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT subject || '#' || relation, authz_rev::text FROM kaname.relation_fact
		  WHERE object_type = $1 AND object_id = $2`, evRepoType, "reg-1/"+name)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, rev string
		require.NoError(t, rows.Scan(&k, &rev))
		out[k] = rev
	}
	require.NoError(t, rows.Err())
	return out
}

func factKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *eventHarness) mirrorPresent(t *testing.T, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		evRepoDotted, "reg-1/"+name).Scan(&n))
	return n > 0
}

func keyOf(tp evTuple) string { return tp.subject + "#" + tp.relation }

// TestRegisterResource_NTF3_185a_EventSetAppliesAtomicallyUnderOneGeneration —
// один вызов с двумя кортежами поколения 1: голова 1, оба кортежа записаны; вызов
// поколения 2 только со структурным кортежем: голова 2, кортеж владения не снят.
func TestRegisterResource_NTF3_185a_EventSetAppliesAtomicallyUnderOneGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 1)))
	e.requireHead(t, name, 1, false, "поколение 1 набором из двух")
	require.Equal(t, []string{keyOf(evParent), keyOf(evOwner)}, factKeys(e.facts(t, name)),
		"поколение 1: оба кортежа события записаны одним применением")

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 2)))
	e.requireHead(t, name, 2, false, "поколение 2")
	require.Equal(t, []string{keyOf(evParent), keyOf(evOwner)}, factKeys(e.facts(t, name)),
		"кортеж владения, которого нет в наборе поколения 2, регистрацией не снимается")
}

// TestRegisterResource_NTF3_185a_Twin_PerTupleDeliveryLosesTheOwner — близнец по
// одному факту: те же два кортежа поколения 1 двумя вызовами по одному кортежу —
// второй не новее головы, REJECTED_STALE: кортеж владения создателя потерян. Ровно
// то, что запрещает применение по кортежу.
func TestRegisterResource_NTF3_185a_Twin_PerTupleDeliveryLosesTheOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 1)))
	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evOwner}, 1)),
		"второй вызов того же поколения — успех вызова (прокси идемпотентен)")
	e.requireHead(t, name, 1, false, "после двух вызовов поколения 1")
	require.Equal(t, []string{keyOf(evParent)}, factKeys(e.facts(t, name)),
		"второй кортеж того же поколения — REJECTED_STALE: кортежа владения нет")
}

// TestRegisterResource_NTF3_185b_RepeatedEventWritesNothing — повтор события
// (тот же объект, тот же набор, поколение равно голове): REJECTED_STALE, ни одной
// записи — голова 2, кортежи и их версия прав прежние. Близнец по одному факту —
// поколение 3: применено.
func TestRegisterResource_NTF3_185b_RepeatedEventWritesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 1)))
	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 2)))
	before := e.facts(t, name)

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 2)))
	e.requireHead(t, name, 2, false, "повтор поколения 2")
	require.Equal(t, before, e.facts(t, name), "повтор события: кортежи и authz_rev каждого не изменены")

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 3)))
	e.requireHead(t, name, 3, false, "близнец: поколение 3 применено")
}

// TestRegisterResource_NTF3_185c_EventSetIsValidated — набор пуст, пара
// повторена, в наборе подстановочный субъект: INVALID_ARGUMENT по полю `tuples`,
// голова и кортежи не меняются. Близнец по одному факту — набор
// `[{registry_registry:reg-1, parent}]` поколения 3: применено.
func TestRegisterResource_NTF3_185c_EventSetIsValidated(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 1)))
	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 2)))
	before := e.facts(t, name)

	for _, c := range []struct {
		why    string
		tuples []evTuple
		desc   string
	}{
		{"пустой набор", nil, "required"},
		{"пара дважды", []evTuple{evOwner, evOwner}, "duplicate user:usr-X#owner"},
		{"подстановочный субъект", []evTuple{{"user:*", "v_get"}}, "wildcard subject is published by SetPublicReadPublication"},
	} {
		t.Run(c.why, func(t *testing.T) {
			err := e.register(t, evReg(t, name, c.tuples, 3))
			require.Error(t, err, "%s: регистрация принята", c.why)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "%s: %v", c.why, err)
			field, desc := badRequestField(err)
			require.Equal(t, "tuples", field, "%s: поле отказа", c.why)
			require.Equal(t, c.desc, desc, "%s: описание отказа", c.why)
			e.requireHead(t, name, 2, false, c.why)
			require.Equal(t, before, e.facts(t, name), "%s: кортежи не изменены", c.why)
		})
	}

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 3)))
	e.requireHead(t, name, 3, false, "близнец: набор [parent] поколения 3")
}

// TestRegisterResource_NTF3_185d_WithdrawalTakesEveryTupleOfTheObject — снятие,
// адресованное объектом, снимает оба кортежа одной транзакцией приёма: живой
// строки зеркала нет, надгробие несёт 3.
func TestRegisterResource_NTF3_185d_WithdrawalTakesEveryTupleOfTheObject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 1)))
	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 2)))
	require.Len(t, e.facts(t, name), 2, "положительный контроль: два кортежа до снятия")

	require.NoError(t, e.unregister(t, evUnreg(name, 3)))
	require.Empty(t, factKeys(e.facts(t, name)), "снятие объекта уносит все кортежи на нём")
	require.False(t, e.mirrorPresent(t, name), "живой строки зеркала после снятия нет")
	e.requireHead(t, name, 3, true, "надгробие снятия")
}

// requireNoProtoField — у сообщения нет поля с этим именем (проверка формы
// запроса, на котором проба строит снятие).
func requireNoProtoField(t *testing.T, m proto.Message, name protoreflect.Name) {
	t.Helper()
	if fd := m.ProtoReflect().Descriptor().Fields().ByName(name); fd != nil {
		t.Fatalf("%s: поле %q ещё в контракте — снятие адресуется не одним объектом",
			m.ProtoReflect().Descriptor().FullName(), name)
	}
}

// TestUnregisterResource_NTF3_185d_WithdrawalSeesTuplesCommittedBeforeItsAdmission —
// регистрация поколения 2 держит голову объекта в незакоммиченной транзакции,
// снятие поколения 3 приходит в это время и ждёт на голове; регистрация
// коммитит кортеж владения. Снятие обязано унести и его: набор снимаемого
// читается ПОСЛЕ сравнения с головой, в транзакции приёма, а не до неё — иначе
// кортеж, закоммиченный между чтением и приёмом, пережил бы снятие объекта.
func TestUnregisterResource_NTF3_185d_WithdrawalSeesTuplesCommittedBeforeItsAdmission(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	e := newEventHarness(t)
	const name = "race"
	requireNoProtoField(t, &iamv1.UnregisterResourceRequest{}, "subject_id")

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 1)))

	// Регистрация поколения 2 — та же форма приёма и журнала, что у пути
	// регистрации, — держит голову объекта до коммита.
	tx, err := e.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	var outcome string
	require.NoError(t, tx.QueryRow(ctx,
		`INSERT INTO kaname.resource_event_intake (change, object_type, object_id, generation, parent_chain)
		 VALUES ('register', $1, $2, 2, $3::text[]) RETURNING outcome`,
		evRepoDotted, "reg-1/"+name, evChain).Scan(&outcome))
	require.Equal(t, "APPLIED", outcome, "положительный контроль: поколение 2 применено в держащей транзакции")
	_, err = tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', 'owner', 'object', $2::text), now())`,
		evOwnerUser, evRepoType+":reg-1/"+name)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- e.unregister(t, evUnreg(name, 3)) }()

	// Снятие дошло до головы и ждёт её замка.
	waitForLockWaiter(t, e.pool, "resource_event_intake")
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, <-done)

	require.Empty(t, factKeys(e.facts(t, name)),
		"кортеж владения, закоммиченный до приёма снятия, пережил снятие объекта")
	e.requireHead(t, name, 3, true, "надгробие снятия")
}

// waitForLockWaiter ждёт, пока в базе появится обслуживающий процесс, ждущий
// замка в операторе над `table`, — не дольше конечного срока: срок вышел —
// проба падает, называя, чего не дождалась (снятие не дошло до головы).
func waitForLockWaiter(t *testing.T, pool *pgxpool.Pool, table string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'
			   AND query LIKE '%' || $1 || '%'`, table).Scan(&n))
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("за 30 с ни один процесс не ждёт замка в операторе над %s — снятие не дошло до головы объекта", table)
		}
		<-tick.C
	}
}
