// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// public_read_order_integration_test.go — публикация объекта для анонимного
// чтения (`user:* #v_get`) судится ВЕРДИКТОМ, и её итог равен намерению
// владельца со старшей версией, в каком бы порядке ни приехали доставки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА НА ВЕРДИКТ, А НЕ НА СТРОКУ ЖУРНАЛА
//
// Строка журнала появлялась всегда: путь чистой выдачи клал её исправно, и
// утверждение «намерение эмитировано» было зелёным. Вердикт при этом не менялся
// НИКОГДА — проекция журнала отбрасывала отношение-глагол целиком, и
// опубликованный репозиторий оставался закрытым для анонимного чтения. Замер на
// стволе до правки: строка журнала 1, прямых фактов 0, вердикт `deny`.
// Утверждение о строке этого не видит by construction; видит только вопрос,
// который задаёт enforcement.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗАКОННЫЙ БЛИЗНЕЦ НЕСУЩИЙ
//
// Отрицание («поздняя доставка не открывает») на стволе до правки выполнялось
// тривиально: не открывало ничто. Проба без положительного близнеца («доставка
// по порядку открывает») зеленела бы ровно на том дефекте, из-за которого
// публикация не работала вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗДЕСЬ, А НЕ У USE-CASE
//
// Пробы пакета use-case с базой конвейер не исполняет: быстрый прогон идёт с
// `-short`, а интеграционное задание отбирает только `internal/repo`,
// `internal/clients`, `internal/reconciler` и `internal/subscriptionjournal`.
// Этот пакет в отбор входит.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// publicReadRig собирает use-case ТАК ЖЕ, как композиционный корень, — без
// пост-коммитного прохода материализации: публикация его не зовёт, а снятие
// ресурса ниже спрашивается вердиктом, а не его побочным эффектом.
func publicReadRig(t *testing.T) (*internal_iam.RegisterResourceUseCase, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	uc := internal_iam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
	).
		WithReconcile(kanamepg.NewReconcileEventEmitter()).
		WithAccountResolver(kanamepg.NewProjectAccountResolver()).
		WithResidualTupleReader(kanamepg.NewResidualTupleReader(pool))
	return uc, pool
}

const (
	publicReadSubject  = "user:*"
	publicReadRelation = "v_get"
	publicReadType     = "registry_repository"
)

func publicReadObject(id string) string { return publicReadType + ":" + id }

// publish / withdraw — доставка намерения владельца ровно той формы, в какой её
// шлёт реестр: только кортеж и версия, без области и меток. Нулевая версия —
// доставка без маркера (контракт трактует её как «-infinity»).
func publish(t *testing.T, uc *internal_iam.RegisterResourceUseCase, id string, v time.Time) {
	t.Helper()
	require.NoError(t, publishE(uc, id, v))
}

func withdraw(t *testing.T, uc *internal_iam.RegisterResourceUseCase, id string, v time.Time) {
	t.Helper()
	require.NoError(t, withdrawE(uc, id, v))
}

// publishE / withdrawE — те же доставки, отдающие ошибку вызывающему: из горутины
// гонки провалить пробу нельзя, поэтому исход собирается и судится после ожидания.
func publishE(uc *internal_iam.RegisterResourceUseCase, id string, v time.Time) error {
	req := &iamv1.RegisterResourceRequest{
		SubjectId: publicReadSubject, Relation: publicReadRelation, Object: publicReadObject(id),
	}
	if !v.IsZero() {
		req.SourceVersion = timestamppb.New(v)
	}
	return uc.Register(context.Background(), req)
}

func withdrawE(uc *internal_iam.RegisterResourceUseCase, id string, v time.Time) error {
	req := &iamv1.UnregisterResourceRequest{
		SubjectId: publicReadSubject, Relation: publicReadRelation, Object: publicReadObject(id),
	}
	if !v.IsZero() {
		req.SourceVersion = timestamppb.New(v)
	}
	return uc.Unregister(context.Background(), req)
}

// anonymousRead — вопрос, который задаёт плоскость данных реестра на анонимном
// pull: субъект `user:*`, отношение `v_get`. Отвечает форма E, как в проде.
func anonymousRead(t *testing.T, pool *pgxpool.Pool, id string) relverdict.Verdict {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: publicReadSubject, ObjectType: publicReadType, ObjectID: id, Relation: publicReadRelation,
	})
	require.NoError(t, err, "вопрос об анонимном чтении обязан получить ответ, а не ошибку")
	return v
}

// publicFact — стоит ли прямой факт публикации. Вторая, независимая от вердикта
// координата: вердикт выносит форма, а факт кладёт проекция журнала.
func publicFact(t *testing.T, pool *pgxpool.Pool, id string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		publicReadType, id, publicReadRelation, publicReadSubject).Scan(&n))
	return n == 1
}

func requirePublic(t *testing.T, pool *pgxpool.Pool, id, why string) {
	t.Helper()
	require.True(t, publicFact(t, pool, id), "факт публикации отсутствует: %s", why)
	require.Equal(t, relverdict.Allow, anonymousRead(t, pool, id), "анонимное чтение запрещено: %s", why)
}

func requirePrivate(t *testing.T, pool *pgxpool.Pool, id, why string) {
	t.Helper()
	require.False(t, publicFact(t, pool, id), "факт публикации стоит: %s", why)
	require.Equal(t, relverdict.Deny, anonymousRead(t, pool, id), "анонимное чтение разрешено: %s", why)
}

// versions — две версии владельца с зазором больше разрешения timestamptz.
func versions() (v1, v2 time.Time) {
	v1 = time.Now().UTC().Truncate(time.Microsecond)
	return v1, v1.Add(time.Millisecond)
}

// TestPublicRead_PublicationReachesTheVerdict — публикация ОТКРЫВАЕТ анонимное
// чтение, снятие ЗАКРЫВАЕТ. Положительный контроль всех проб файла: без него
// каждое отрицание ниже зеленело бы на проекции, не пропускающей ничего.
func TestPublicRead_PublicationReachesTheVerdict(t *testing.T) {
	uc, pool := publicReadRig(t)
	const id = "reg00000000000000pub/team/app"
	v1, v2 := versions()

	requirePrivate(t, pool, id, "до публикации репозиторий закрыт")
	publish(t, uc, id, v1)
	requirePublic(t, pool, id, "владелец опубликовал репозиторий")
	withdraw(t, uc, id, v2)
	requirePrivate(t, pool, id, "владелец снял публикацию")
}

// TestPublicRead_LateRedeliveryAfterWithdrawalDoesNotReopen — поздняя доставка
// СТАРШЕГО открытия после закрытия не возвращает анонимное чтение.
//
// Производитель доставляет открытие дважды — синхронно и надёжной очередью, с
// ОДНОЙ версией из своей writer-транзакции, — а закрытие только очередью. Синхронная
// доставка, задержавшаяся в пути, приходит после закрытия. Итог обязан равняться
// намерению со старшей версией — закрытию.
func TestPublicRead_LateRedeliveryAfterWithdrawalDoesNotReopen(t *testing.T) {
	uc, pool := publicReadRig(t)
	const id = "reg00000000000late/team/app"
	v1, v2 := versions()

	publish(t, uc, id, v1)
	requirePublic(t, pool, id, "первая доставка открытия")
	withdraw(t, uc, id, v2)
	requirePrivate(t, pool, id, "закрытие новее открытия")

	publish(t, uc, id, v1) // запоздавшая вторая доставка того же открытия
	requirePrivate(t, pool, id, "запоздавшая доставка старшего открытия вернула анонимное чтение")
}

// TestPublicRead_InOrderRepublicationOpens — ЗАКОННЫЙ БЛИЗНЕЦ: та же пара
// намерений, где открытие НОВЕЕ закрытия, открывает. Без него проба выше
// зеленела бы и на пути, где открыть нельзя вообще.
func TestPublicRead_InOrderRepublicationOpens(t *testing.T) {
	uc, pool := publicReadRig(t)
	const id = "reg000000000order/team/app"
	v1, v2 := versions()

	withdraw(t, uc, id, v1)
	requirePrivate(t, pool, id, "закрытие без предшествующего открытия")
	publish(t, uc, id, v2)
	requirePublic(t, pool, id, "открытие новее закрытия")

	withdraw(t, uc, id, v1) // запоздавшая доставка старшего закрытия
	requirePublic(t, pool, id, "запоздавшая доставка старшего закрытия сняла более новую публикацию")
}

// TestPublicRead_UnversionedWithdrawalClosesFailClosed — доставка снятия БЕЗ
// версии порядка не доказывает, и потому применяется в сторону отказа: снятие,
// проглоченное за недоказанностью, было бы стоящим лишним доступом. Версия
// хранимого открытия при этом не отступает — запоздавшая доставка того же
// открытия по-прежнему старше ничего не открывает.
func TestPublicRead_UnversionedWithdrawalClosesFailClosed(t *testing.T) {
	uc, pool := publicReadRig(t)
	const id = "reg00000000nover/team/app"
	v1, v2 := versions()

	publish(t, uc, id, v1)
	requirePublic(t, pool, id, "открытие с версией")
	withdraw(t, uc, id, time.Time{})
	requirePrivate(t, pool, id, "снятие без версии обязано закрывать")
	publish(t, uc, id, v1)
	requirePrivate(t, pool, id, "повтор того же открытия после снятия без версии открыл снова")

	// Законный близнец: открытие НОВЕЕ хранимой версии открывает.
	publish(t, uc, id, v2)
	requirePublic(t, pool, id, "открытие новее всего известного")
}

// TestPublicRead_ResourceWithdrawalTakesThePublicationWithIt — снятие САМОГО
// ресурса снимает и его публикацию, под версией снятия. Идентификатор
// репозитория — его ИМЯ внутри реестра: публикация, пережившая удалённый
// репозиторий, отдала бы анонимное чтение следующему репозиторию с тем же
// именем.
func TestPublicRead_ResourceWithdrawalTakesThePublicationWithIt(t *testing.T) {
	uc, pool := publicReadRig(t)
	const (
		reg = "reg0000000000gone"
		id  = reg + "/team/app"
	)
	v1, v2 := versions()
	parent := &iamv1.RegisterResourceRequest{
		SubjectId: "registry_registry:" + reg, Relation: "parent", Object: publicReadObject(id),
		ParentChain: []string{"registry_registry:" + reg}, SourceVersion: timestamppb.New(v1),
	}
	require.NoError(t, uc.Register(context.Background(), parent))
	publish(t, uc, id, v1.Add(time.Microsecond))
	requirePublic(t, pool, id, "опубликованный живой репозиторий")

	require.NoError(t, uc.Unregister(context.Background(), &iamv1.UnregisterResourceRequest{
		SubjectId: parent.SubjectId, Relation: "parent", Object: parent.Object,
		SourceVersion: timestamppb.New(v2),
	}))
	requirePrivate(t, pool, id, "удалённый репозиторий остался публично читаемым")

	publish(t, uc, id, v1.Add(time.Microsecond)) // запоздавшая доставка прежнего открытия
	requirePrivate(t, pool, id, "запоздавшая доставка открытия опубликовала удалённый репозиторий")

	// Законный близнец: репозиторий с тем же именем создан заново и опубликован
	// ПОЗЖЕ снятия — это новое намерение, и оно открывает.
	v3 := v2.Add(time.Millisecond)
	require.NoError(t, uc.Register(context.Background(), &iamv1.RegisterResourceRequest{
		SubjectId: parent.SubjectId, Relation: "parent", Object: parent.Object,
		ParentChain: parent.ParentChain, SourceVersion: timestamppb.New(v3),
	}))
	publish(t, uc, id, v3.Add(time.Microsecond))
	requirePublic(t, pool, id, "новый репозиторий с тем же именем опубликован после снятия прежнего")
}

// TestPublicRead_ConcurrentDeliveriesConvergeToTheNewestIntent — доставки одного
// объекта в ГОНКЕ сходятся к намерению со старшей версией.
//
// На каждый объект подаётся ровно то, что порождает производитель: открытие
// дважды (синхронно и очередью, одна версия), закрытие один раз, — все три
// одновременно, от общего старта. Рядом — наполнитель: доставки чужих объектов в
// те же мгновения, чтобы транзакции делили соединения и порядок захвата. Итог
// по каждому объекту судится вердиктом.
//
// Половина объектов — закрытие НОВЕЕ (итог закрыт), половина — открытие новее
// (итог открыт, законный близнец в той же гонке).
func TestPublicRead_ConcurrentDeliveriesConvergeToTheNewestIntent(t *testing.T) {
	uc, pool := publicReadRig(t)
	const rounds = 24
	base, _ := versions()

	type want struct {
		id     string
		public bool
	}
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		cases []want
		mu    sync.Mutex
		errs  []error
	)
	for i := 0; i < rounds; i++ {
		id := "reg00000000race" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "/team/app"
		older := base.Add(time.Duration(i) * 10 * time.Millisecond)
		newer := older.Add(time.Millisecond)
		closeWins := i%2 == 0
		cases = append(cases, want{id: id, public: !closeWins})

		openV, closeV := older, newer
		if !closeWins {
			openV, closeV = newer, older
		}
		deliveries := []func() error{
			func() error { return publishE(uc, id, openV) },                       // синхронная доставка открытия
			func() error { return publishE(uc, id, openV) },                       // та же, из надёжной очереди
			func() error { return withdrawE(uc, id, closeV) },                     // закрытие, только очередью
			func() error { return publishE(uc, "reg0000000filler/x/"+id, newer) }, // наполнитель
		}
		for _, d := range deliveries {
			wg.Add(1)
			go func(d func() error) {
				defer wg.Done()
				<-start
				if err := d(); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}(d)
		}
	}
	close(start)
	wg.Wait()
	require.Empty(t, errs, "доставка в гонке отвергнута: намерение владельца обязано приниматься, а не отказывать")

	for _, c := range cases {
		if c.public {
			requirePublic(t, pool, c.id, "в гонке победило старшее закрытие вместо новейшего открытия")
		} else {
			requirePrivate(t, pool, c.id, "в гонке победило старшее открытие вместо новейшего закрытия")
		}
	}
}

// TestPublicRead_WithdrawalWhoseTransactionStartedFirstStillCloses — снятие,
// чья транзакция НАЧАЛАСЬ раньше транзакции открытия, а применилась позже,
// закрывает.
//
// Такой ход не выражается вызовом use-case — транзакцию он открывает сам, — и
// потому стоит здесь отдельно, у порта. Он и есть место, где ломается порядок по
// часам НАЧАЛА транзакции: метка строки журнала `now()` — это момент `BEGIN`, а
// не фиксации, и у снятия она оказывается СТАРШЕ метки открытия, которое оно
// обязано снять. Проекция, сравнивающая метки журнала, оставила бы факт стоять.
// Порядок обязан задаваться версией ВЛАДЕЛЬЦА, а не часами службы.
func TestPublicRead_WithdrawalWhoseTransactionStartedFirstStillCloses(t *testing.T) {
	_, pool := publicReadRig(t)
	ctx := context.Background()
	txb := kanamepg.NewPoolTxBeginner(pool)
	pub := kanamepg.NewPublicReadPublisher()
	const id = "reg000000000early/team/app"
	v1, v2 := versions()

	closeTx, err := txb.Begin(ctx) // снятие начало транзакцию ПЕРВЫМ
	require.NoError(t, err)
	defer func() { _ = closeTx.Rollback(ctx) }()
	time.Sleep(5 * time.Millisecond) // метка BEGIN у открытия заведомо позже

	openTx, err := txb.Begin(ctx)
	require.NoError(t, err)
	applied, err := pub.ApplyTx(ctx, openTx, publicReadType, id, true, v1)
	require.NoError(t, err)
	require.True(t, applied, "первое намерение по объекту обязано примениться")
	require.NoError(t, openTx.Commit(ctx))
	requirePublic(t, pool, id, "открытие зафиксировано")

	applied, err = pub.ApplyTx(ctx, closeTx, publicReadType, id, false, v2)
	require.NoError(t, err)
	require.True(t, applied, "снятие новее открытия обязано примениться")
	require.NoError(t, closeTx.Commit(ctx))
	requirePrivate(t, pool, id, "снятие, начавшее транзакцию раньше открытия, не закрыло")
}

// TestPublicRead_ProjectionFoldsOnlyTheOwnerOrderedVerb — различитель проекции
// журнала, по обе стороны.
//
// Строка глагола БЕЗ версии владельца — это копия, выведенная из выдачи
// (реконсайлер кладёт такие в журнал), и форма E выводит её сама: складывать её в
// прямой факт нельзя, иначе у одного права стало бы два источника с разными
// сроками жизни. Строка С версией владельца — публикация, которую выдача не выводит
// ничем; не сложенная, она не существовала бы нигде. Неразбираемая версия роняет
// строку: подменить её меткой журнала значило бы молча вернуть порядок по часам
// службы, от которого поле защищает.
func TestPublicRead_ProjectionFoldsOnlyTheOwnerOrderedVerb(t *testing.T) {
	_, pool := publicReadRig(t)
	ctx := context.Background()
	const derived, owned, broken = "reg00000000deriv/team/app", "reg000000000owned/team/app", "reg00000000broke/team/app"

	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', $2::text, 'object', $3::text), now())`,
		publicReadSubject, publicReadRelation, publicReadObject(derived))
	require.NoError(t, err)
	requirePrivate(t, pool, derived, "глагол без версии владельца (копия выдачи) сложен в прямой факт")

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', $2::text, 'object', $3::text,
		                                              'source_version', now()), now())`,
		publicReadSubject, publicReadRelation, publicReadObject(owned))
	require.NoError(t, err)
	requirePublic(t, pool, owned, "строка, упорядоченная владельцем, не сложена в прямой факт")

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', $2::text, 'object', $3::text,
		                                              'source_version', 'not-a-version'), now())`,
		publicReadSubject, publicReadRelation, publicReadObject(broken))
	require.Error(t, err, "неразбираемая версия владельца обязана ронять строку, а не подменяться меткой журнала")
	requirePrivate(t, pool, broken, "строка с неразбираемой версией оставила факт")
}
