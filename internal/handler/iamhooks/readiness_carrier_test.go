// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// readiness_carrier_test.go — поведение диагностической поверхности владельца
// прав: что она отвечает, а не чем собрана.
//
// # ЗДЕСЬ СОШЛИСЬ ДВА НАБОРА — readiness_test.go снят вместе со своим предметом
//
// Прежний набор проверял собственную форму владельца прав и снят вместе с ней
// (задача продукта #1729). Его три утверждения перешли сюда ЦЕЛИКОМ, и каждое
// стало строже, а не слабее:
//
//	«все здоровы → 200»            → TestReadinessAnswersReadyWhenEveryDependencyIsUp
//	«зависимость упала → 503 с её именем» → TestReadinessNamesEveryFailedDependency
//	                                  (требует ВСЕ имена, а не одно)
//	«живость остаётся чистой»       → TestLivenessStaysUpWhileADependencyIsDown
//
// Сверх них здесь два утверждения, которых прежняя форма выразить не могла
// ВОВСЕ: обработчик ограничен сроком и готовность переходит в отказ на гашении.
package iamhooks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/observability/health"
)

// readinessBudget — сколько проба даёт обработчику готовности на ответ.
//
// Величина ЗАВЕДОМО больше бюджета одного чекера у общего носителя (секунда) и
// заведомо меньше окна пробы kubelet: она различает «обработчик ограничен своим
// сроком» и «обработчик ждёт зависимость столько, сколько та молчит». Точное
// число здесь не утверждается — утверждается ограниченность.
const readinessBudget = 5 * time.Second

// readinessProbe — исход одного обращения к диагностической поверхности.
//
// Тело и код читает ТА ЖЕ горутина, что их произвела: при зависшей зависимости
// обработчик возвращается позже пробы, и общий на двоих регистратор ответа стал
// бы гонкой, а не находкой.
type readinessProbe struct {
	code int
	body string
}

// ask обращается к маршруту и возвращает исход либо признаётся, что ответа не
// дождалась. Второе — НЕ красный вердикт о продукте, а другое утверждение:
// обработчик не ограничен сроком.
func ask(t *testing.T, mux http.Handler, route string) (readinessProbe, bool) {
	t.Helper()
	done := make(chan readinessProbe, 1)
	go func() {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		done <- readinessProbe{code: rec.Code, body: rec.Body.String()}
	}()
	select {
	case got := <-done:
		return got, true
	case <-time.After(readinessBudget):
		return readinessProbe{}, false
	}
}

// Готовность называет КАЖДУЮ упавшую зависимость, а не первую по счёту.
//
// # Предмет
//
// Дежурный читает ответ готовности как список того, что чинить. Обработчик,
// останавливающийся на первой упавшей, называет одну из двух: её чинят,
// перекатывают под — и узнают о второй следующим заходом. Цена — лишний цикл
// выкатки на каждую скрытую зависимость, и платится она в тот момент, когда
// сервис и так лежит.
//
// # Почему это утверждение об iam, а не о носителе
//
// Носитель проверяет своё поведение сам. Здесь утверждается ПРОВОДКА: что
// диагностическая поверхность владельца прав отвечает этим носителем, а не
// собственной формой, которая обходит зависимости по очереди и выходит на первом
// отказе.
func TestReadinessNamesEveryFailedDependency(t *testing.T) {
	mux := muxWithReadiness(
		named("database", func(context.Context) error { return errors.New("db down") }),
		named("lro-worker", func(context.Context) error { return errors.New("worker down") }),
	)

	got, answered := ask(t, mux, "/readyz")
	if !answered {
		t.Fatalf("готовность не ответила за %s — обработчик не ограничен сроком", readinessBudget)
	}
	if got.code != http.StatusServiceUnavailable {
		t.Fatalf("обе зависимости лежат, а готовность ответила %d вместо %d",
			got.code, http.StatusServiceUnavailable)
	}
	for _, name := range []string{"database", "lro-worker"} {
		if !strings.Contains(got.body, name) {
			t.Errorf("ответ готовности не называет упавшую зависимость %q: %s\n"+
				"дежурный починит названную, перекатит под и узнает об остальных следующим "+
				"заходом — цикл выкатки за каждую скрытую зависимость, и платится он на лежащем сервисе",
				name, got.body)
		}
	}
}

// Зависшая зависимость НЕ подвешивает обработчик готовности.
//
// # Предмет
//
// Зависимость отказывает двумя способами, и они не равны. Отказ с ошибкой виден
// сразу; МОЛЧАНИЕ (сеть в полуоткрытом состоянии, база под блокировкой, сосед в
// сборке мусора) не возвращает управления вовсе. Обработчик, зовущий такую
// проверку напрямую, висит вместе с ней: kubelet не получает ни 200, ни 503, а
// ждёт своего срока — и до его истечения под остаётся в ротации, принимая
// трафик, который обслужить не может.
//
// # Чем проверка отличается от «зависимость вернула ошибку»
//
// Проверка ниже НЕ смотрит на отмену контекста намеренно: она моделирует
// зависимость, которая контекст игнорирует. Кооперативная зависимость вернулась
// бы сама, и утверждение зеленело бы на обработчике без всякого бюджета —
// то есть проверяло бы вежливость зависимости вместо ограниченности обработчика.
func TestReadinessDoesNotHangOnAWedgedDependency(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	mux := muxWithReadiness(
		named("database", func(context.Context) error { return nil }),
		named("wedged-peer", func(context.Context) error {
			<-release // контекст игнорируется намеренно, см. шапку
			return nil
		}),
	)

	got, answered := ask(t, mux, "/readyz")
	if !answered {
		t.Fatalf("готовность не ответила за %s: молчащая зависимость подвесила обработчик. "+
			"kubelet не получает ни 200, ни 503 и ждёт своего срока — под остаётся в ротации "+
			"и принимает трафик, который обслужить не может", readinessBudget)
	}
	if got.code != http.StatusServiceUnavailable {
		t.Fatalf("молчащая зависимость обязана читаться как недоступная (%d), получено %d: %s",
			http.StatusServiceUnavailable, got.code, got.body)
	}
	if !strings.Contains(got.body, "wedged-peer") {
		t.Errorf("ответ не называет зависимость, на которой сорвался бюджет: %s", got.body)
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к обоим отрицаниям выше.
//
// Без него оба зеленели бы на обработчике, отвечающем 503 всегда: «называет обе
// упавшие» и «не висит» выполняются тривиально там, где готовности нет вовсе.
func TestReadinessAnswersReadyWhenEveryDependencyIsUp(t *testing.T) {
	mux := muxWithReadiness(
		named("database", func(context.Context) error { return nil }),
		named("lro-worker", func(context.Context) error { return nil }),
	)

	got, answered := ask(t, mux, "/readyz")
	if !answered {
		t.Fatalf("готовность не ответила за %s на здоровых зависимостях", readinessBudget)
	}
	if got.code != http.StatusOK {
		t.Fatalf("все зависимости здоровы, а готовность ответила %d: %s — отрицания соседних "+
			"проб зеленели бы на обработчике, который отказывает всегда", got.code, got.body)
	}
}

// Живость НЕ зависит от зависимостей — второй положительный контроль.
//
// Разведение двух вопросов и есть предмет носителя: подставь готовность в слот
// живости, и блип соседа читается как смерть процесса — шторм перезапусков по
// причине, которая прошла бы сама.
func TestLivenessStaysUpWhileADependencyIsDown(t *testing.T) {
	mux := muxWithReadiness(
		named("database", func(context.Context) error { return errors.New("db down") }),
	)

	got, answered := ask(t, mux, "/healthz")
	if !answered {
		t.Fatalf("живость не ответила за %s — она не вправе зависеть от зависимостей вовсе",
			readinessBudget)
	}
	if got.code != http.StatusOK {
		t.Fatalf("зависимость лежит, а живость ответила %d вместо %d: под уйдёт в перезапуск "+
			"по внешней причине, которая прошла бы сама", got.code, http.StatusOK)
	}
}

// Гашение переводит готовность в ОТКАЗ, а живость оставляет отвечающей.
//
// # Предмет, и он дороже у ЭТОГО сервиса, чем у любого другого
//
// Между началом гашения и остановкой слушателей под обязан выйти из ротации:
// иначе kubelet продолжает слать трафик, пока процесс уже останавливается, и
// вызывающий получает отказ соединения там, где ждал бы перевода на живую
// реплику.
//
// Владелец прав — ЛИСТ графа рёбер: к нему на каждом вызове ходят все прочие
// сервисы (проверка доступа, разрешение проекта, величины пределов). Гасящийся
// под, продолжающий объявлять себя готовым, отправляет в отказ не свой трафик, а
// ЧУЖОЙ — и отказ этот приходит на пути запроса каждого арендатора.
//
// # Почему это утверждение не могло существовать раньше
//
// Прежняя собственная форма состояния гашения не несла вовсе: перевести
// готовность в отказ было НЕЧЕМ, и утверждение не выражалось — не «было
// красным», а не записывалось. Отличие названо здесь, чтобы следующий не принял
// новую проверку за проверку старого свойства.
func TestReadinessRefusesWhileShuttingDownAndLivenessKeepsAnswering(t *testing.T) {
	agg := health.New([]health.Checker{
		named("database", func(context.Context) error { return nil }),
	})
	mux := NewMux(Handlers{Health: agg})

	// Положительный контроль ДО гашения: без него «отказ на гашении» зеленел бы
	// на поверхности, отказывающей всегда.
	before, answered := ask(t, mux, "/readyz")
	if !answered || before.code != http.StatusOK {
		t.Fatalf("до гашения готовность обязана отвечать %d на здоровой зависимости, получено %d "+
			"(ответ получен: %v)", http.StatusOK, before.code, answered)
	}

	agg.SetShuttingDown()

	after, answered := ask(t, mux, "/readyz")
	if !answered {
		t.Fatalf("готовность не ответила за %s после начала гашения", readinessBudget)
	}
	if after.code != http.StatusServiceUnavailable {
		t.Fatalf("гашение началось, а готовность отвечает %d вместо %d: под остаётся в ротации, "+
			"пока слушатели останавливаются, и чужие вызовы приходят в отказ соединения",
			after.code, http.StatusServiceUnavailable)
	}
}

// Обращение НЕ ТЕМ методом отвергается — свойство прежней формы, которое обязано
// пережить смену носителя.
//
// # Почему проверка осталась, хотя обработчик сменился
//
// Прежде метод проверял собственный обработчик; теперь его называет ОБРАЗЕЦ
// маршрута, и отвергает мультиплексор. Механизм другой, свойство то же — и
// ровно поэтому утверждение нужно: при сведении форм теряется обычно не то, о
// чём помнили, а то, что держалось строкой внутри снятого кода.
func TestDiagnosticRoutesRefuseNonGet(t *testing.T) {
	mux := muxWithReadiness(named("database", func(context.Context) error { return nil }))

	for _, route := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, route, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s на POST ответил %d вместо %d: диагностическая поверхность отвечает на "+
				"обращения, которых её контракт не объявляет", route, rec.Code, http.StatusMethodNotAllowed)
		}
	}

	// Законный близнец: объявленный метод по-прежнему проходит — иначе
	// утверждение выше зеленело бы на маршруте, которого нет вовсе.
	got, answered := ask(t, mux, "/healthz")
	if !answered || got.code != http.StatusOK {
		t.Fatalf("объявленный метод обязан проходить: живость ответила %d (ответ получен: %v)",
			got.code, answered)
	}
}
