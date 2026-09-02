// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rights_change_reaches_the_edge_integration_test.go — СКВОЗНАЯ проба: изменение
// прав доезжает до потребителя, и его вердикт пересчитывается.
//
// # Почему СКВОЗНАЯ, а не две по половине
//
// Половины здесь две, и каждая по отдельности бывает исправна при неработающем
// целом: владелец прав исправно ПИШЕТ строку, потребитель исправно СПРАШИВАЕТ, а
// предмет у них при этом разный — форма строки, имя метода, смысл курсора,
// значение пустой партии. Две зелёные пробы по половине об этом не говорят
// ничего, и расхождение обнаруживается не ими, а инцидентом.
//
// Поэтому здесь стоит ОДИН вопрос через обе стороны, и каждое звено на пути —
// боевое:
//
//	производитель  — `EmitSubjectChangeEvent` писателя привязок, в его настоящей
//	                 транзакции, а не собственный INSERT пробы;
//	хранилище      — настоящая схема владельца прав, накатанная его миграциями;
//	чтение         — `SubjectChangeService` над `SubjectChangeRepo`;
//	транспорт      — НАСТОЯЩИЙ обработчик `InternalIAMService` на настоящем
//	                 gRPC-сервере, по порождённому контракту;
//	потребитель    — `pkg/subjectchange`, тот самый читатель, который провязан у
//	                 края в композиционном корне;
//	наблюдаемое    — гашение кэша решений.
//
// # Что эта проба СТАЛА ВЫРАЗИМА только после переезда читателя в фундамент
//
// Пока читатель лежал в дереве потребителя, сквозной вопрос было НЕГДЕ задать:
// правило видимости `internal/` не пускает потребителя к производителю и
// обратно, и обе половины оставались достижимы только порознь. Это не свойство
// нашей аккуратности, а свойство языка — и потому сквозная проба была не
// «не написана», а невозможна.
//
// # Направление, которое она заодно и утверждает
//
// Соединение открывает ПОТРЕБИТЕЛЬ. Владелец прав в этой пробе не знает о нём
// ничего: у него нет ни его типа, ни его адреса, и первым здесь поднимается
// именно владелец.
package pg_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/subjectchange"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/iampgtest"
)

// verdictCache — наблюдаемое потребителя: держит ли он ещё закешированный
// вердикт.
//
// Настоящий кэш решений живёт в дереве края и оттуда недостижим — правило
// видимости `internal/`. Заменитель здесь годен ровно потому, что предмет пробы
// не его устройство, а ФАКТ гашения: край провязывает в это же место
// `AuthzMiddleware.InvalidateCache`, и что оно гасит целиком, утверждает его
// собственная проба. Заменитель при этом строго не снисходительнее продукта: он
// не гасит НИЧЕГО, пока его не позовут.
type verdictCache struct {
	held    bool
	flushes int
}

func (c *verdictCache) invalidate() {
	c.held = false
	c.flushes++
}

// TestRightsChangeReachesTheEdgeAndTheVerdictIsRecomputed — сквозной вопрос.
func TestRightsChangeReachesTheEdgeAndTheVerdictIsRecomputed(t *testing.T) {
	if testing.Short() {
		t.Skip("нужна настоящая база (Docker)")
	}

	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие ограничено сроком: отложенное ждёт соединение, которого проба,
	// упавшая внутри открытой транзакции, не вернёт никогда, — и уносит вердикт
	// всего пакета вместе с собой.
	pgtest.ClosePoolAtEnd(t, pool)

	// ── СТОРОНА ВЛАДЕЛЬЦА ПРАВ ────────────────────────────────────────────────
	abRepo := kachopg.New(pool, nil)
	changeRights := func(subjectID, op string) {
		t.Helper()
		w, werr := abRepo.Writer(ctx)
		require.NoError(t, werr)
		require.NoError(t, w.AccessBindingsW().EmitSubjectChangeEvent(ctx,
			access_binding.SubjectChangeEvent{SubjectID: subjectID, Op: op}))
		require.NoError(t, w.Commit(ctx))
	}

	// Транспорт владельца — настоящий обработчик на настоящем сервере.
	// `PollSubjectChanges` объявлен освобождённым от пообъектной проверки и
	// гейтится слушателем, поэтому остальные его зависимости на этом пути не
	// участвуют; подставлять вместо обработчика свою заглушку значило бы
	// проверять форму, которой продукт не производит.
	handler := internal_iam.NewHandler(nil, nil).
		WithSubjectChange(service.NewSubjectChangeService(kachopg.NewSubjectChangeRepo(pool, nil)))

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	iamv1.RegisterInternalIAMServiceServer(srv, handler)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	// ── СТОРОНА ПОТРЕБИТЕЛЯ ───────────────────────────────────────────────────
	// Соединение открывает ОН. Владелец о нём не знает ничего.
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(c context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(c)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cache := &verdictCache{}
	// Такт задан заведомо большим: шаги делает проба вызовом Poll, а не таймер.
	// Ждать настоящего срока значило бы угадывать момент, когда чтение
	// закончилось, — угадывание верное на свободной машине и неверное на занятой.
	reader, err := subjectchange.New(subjectchange.Config{
		Poller: subjectchange.NewReader(conn),
		Flush:  cache.invalidate,
		// Величины выбраны так, чтобы fail-closed по сроку не наступил за
		// секунды прогона, и НЕ ШИРЕ удержания журнала: срок, объявляющий
		// рабочим молчание длиннее того, что владелец хранит, отвергается
		// сборкой (#1758). Проба зовёт `Poll` напрямую, поэтому период здесь
		// задаёт только срок одного вызова.
		Interval: time.Minute,
		// Реестр открытых потоков у владельца отсутствует BY CONSTRUCTION:
		// длинные соединения держит потребитель, и правило видимости `internal/`
		// не пускает сюда его проекцию. Заменитель здесь законен и не ослабляет
		// пробу: её предмет — доезжает ли ИЗМЕНЕНИЕ ПРАВ до кэша решений, а не
		// что делает закрыватель. Что то же самое чтение закрывает настоящий
		// открытый поток, утверждает сквозная проба у потребителя
		// (`gateway/internal/subscriptionstream`,
		// `TestPolledRevocationClosesTheOpenStreamEndToEnd`).
		//
		// Ноль здесь недопустим и отвергается сборкой: необязательный
		// закрыватель делал бы несделанную провязку неотличимой от сделанной
		// (kacho#1022).
		Closer:     noStreamsHere{},
		StaleAfter: 5 * time.Minute,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	// ── ШАГ 1. Первое чтение на холодном процессе НЕ гасит ────────────────────
	//
	// Кэш при старте пуст, и гасить нечего; принять голову журнала за курсор —
	// это отказ переигрывать историю. Без этого утверждения проба ниже зеленела
	// бы на читателе, который гасит кэш на КАЖДОМ чтении: он «сходится» всегда и
	// не сообщает ни о чём.
	changeRights("usrhistorical000001", "binding_upsert")
	cache.held = true
	reader.Poll(ctx)
	require.True(t, cache.held,
		"первое чтение погасило кэш: тогда читатель гасит его при каждом старте "+
			"и переигрывает всю историю журнала, а не сообщает об изменении")
	require.Zero(t, cache.flushes)

	// ── ШАГ 2. ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: без изменения прав кэш живёт ──────────
	//
	// Без него утверждение шага 3 выполнялось бы читателем, который гасит кэш
	// безусловно, — то есть проба зеленела бы на сломанном.
	reader.Poll(ctx)
	require.True(t, cache.held, "кэш погас без изменения прав")
	require.Zero(t, cache.flushes, "гашение произошло, когда журнал не двигался")

	// ── ШАГ 3. СКВОЗНОЙ ВОПРОС: права изменены → вердикт пересчитан ──────────
	changeRights("usrrevokedxxxx00001", "binding_revoke")
	reader.Poll(ctx)
	require.False(t, cache.held,
		"права изменены у ВЛАДЕЛЬЦА, а вердикт у ПОТРЕБИТЕЛЯ не пересчитан: "+
			"строка записана и прочитана, но до кэша решений не доехала")
	require.Equal(t, 1, cache.flushes)

	// ── ШАГ 4. Курсор двинулся: та же строка не гасит второй раз ─────────────
	//
	// Иначе «сходимость» вырождается в гашение на каждом чтении, и отличить
	// работающий отзыв от неработающего снова нечем.
	cache.held = true
	reader.Poll(ctx)
	require.True(t, cache.held, "курсор не двинулся: та же строка гасит кэш повторно")
	require.Equal(t, 1, cache.flushes)

	// ── ШАГ 5. Членство в группе — ТОТ ЖЕ путь ───────────────────────────────
	//
	// Право выдано ГРУППЕ, состав её меняется отдельным глаголом, и привязку это
	// не трогает. Если бы журнал вёз только события привязок, снятый из группы
	// продолжал бы проходить до истечения окна.
	changeRights("grpadminsxxxx000001", "group_member_change")
	reader.Poll(ctx)
	require.False(t, cache.held,
		"смена состава группы до потребителя не доехала: снятый из группы "+
			"продолжит проходить по закешированному вердикту")
	require.Equal(t, 2, cache.flushes)
}

// noStreamsHere — реестр открытых потоков у владельца журнала: пуст всегда.
//
// Длинные соединения держит ПОТРЕБИТЕЛЬ; у владельца их нет и быть не может, и
// сообщать об этом нулём нельзя — ноль означал бы «закрывателя не провязали».
type noStreamsHere struct{}

func (noStreamsHere) CloseSubject(string) int { return 0 }
func (noStreamsHere) CloseAll() int           { return 0 }
