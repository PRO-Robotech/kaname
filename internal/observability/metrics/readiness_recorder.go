// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// readiness_recorder.go — исход готовности ПО КАЖДОЙ ЗАВИСИМОСТИ, а не одним
// битом (задача продукта #2494).
//
// # Почему один бит недостаточен
//
// Зависимостей готовности три, и каждая означает СВОЮ починку: база недоступна —
// сломан продукт либо среда; образ не той версии, что схема — условие не создано
// (накат не прогнан либо откат поставил прежний образ на новую схему);
// исполнитель операций ещё не поднялся — идёт старт. Наружу выходил один бит
// «под не готов», а имена трёх зависимостей — только в теле пробы, поднятой по
// TLS на внутреннем порту. Чтобы их прочесть, нужен проброс порта и запрос в
// обход проверки сертификата; ни один документ поставки этого не называет.
//
// # Почему имя зависимости и есть различение трёх состояний
//
// Класс починки привязан к ЗАВИСИМОСТИ, а не к тексту её отказа: имя в метке
// отвечает на «продукт сломан или условие не создано» без чтения кода. Разбирать
// текст ошибки было бы вторым разбором того же предмета — и разошёлся бы он
// молча, потому что текст свой у каждого чекера и меняется вместе с ним.
//
// # Почему ряды заводятся НУЛЁМ при регистрации
//
// Клетка, появляющаяся при первом попадании, неотличима от «ещё не случалось»:
// правило тревоги, считающее долю, врёт ровно до первого события. Здесь заводится
// каждая клетка (зависимость × исход), поэтому «готовность не оценивалась ни
// разу» выразимо нулём во ВСЕХ рядах — и это отдельное состояние, а не оттенок
// исправности: пробы, которых никто не спрашивает, не снимают под из ротации.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// ReadinessChecksMetric — исходы оценки готовности по зависимостям.
//
// Собирается ИЗ КОНСТАНТЫ пространства имён: имя ряда — контракт с панелями и
// правилами тревог, и повторённое литералом оно не двигается вместе с ней.
const ReadinessChecksMetric = Namespace + "_readiness_dependency_checks_total"

// Исходы оценки одной зависимости. Набор ЗАКРЫТ: носитель готовности сводит
// всякий отказ и всякий срок к «не готов», и третьего значения у него нет.
const (
	// ReadinessOutcomeReady — зависимость ответила, что здорова.
	ReadinessOutcomeReady = "ready"
	// ReadinessOutcomeUnready — зависимость не ответила либо ответила отказом.
	// Что именно чинить, говорит метка `dependency`.
	ReadinessOutcomeUnready = "unready"
)

// ReadinessOutcomes — закрытый набор исходов.
var ReadinessOutcomes = []string{ReadinessOutcomeReady, ReadinessOutcomeUnready}

// ReadinessRecorder — приёмник исхода готовности. Форма метода [Observe]
// совпадает с объявленной опцией носителя (`health.WithResultObserver`), поэтому
// корень отдаёт приёмник ей напрямую и своего переходника не заводит.
type ReadinessRecorder struct {
	checks *prometheus.CounterVec
}

// ReadinessRecorder заводит приёмник и СЕЙЧАС ЖЕ клетки по названным
// зависимостям.
//
// Набор зависимостей приходит доводом, а не выписывается здесь: его знает
// композиционный корень — он один строит чекеры. Выведенный из того же среза,
// которым построен носитель, он не может от него отстать: добавление чекера
// заводит ряды само.
//
// Пустой набор — ОТКАЗ, а не тихая регистрация: витрина без рядов выглядит
// точно так же, как витрина при исправной готовности, и это ровно то
// неразличение, ради которого приёмник заведён.
//
// Повторный вызов возвращает ТОГО ЖЕ приёмника и досеивает названные клетки:
// носитель готовности собирается в прогоне не единожды, а второй экземпляр
// разложил бы ряды по двум семействам с одним именем и уронил бы старт на
// повторной регистрации.
func (r *Registry) ReadinessRecorder(dependencies []string) *ReadinessRecorder {
	if len(dependencies) == 0 {
		panic("metrics: ReadinessRecorder без зависимостей — рядов не будет ни одного, " +
			"и молчащая витрина неотличима от исправной готовности")
	}
	r.readinessOnce.Do(func() {
		r.readiness = &ReadinessRecorder{
			checks: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: ReadinessChecksMetric,
				Help: "Readiness evaluations per declared dependency and outcome (ready|unready). " +
					"The dependency label IS the class of fix: an unreachable database is the " +
					"operator's product-or-environment problem, an image whose version does not " +
					"match the schema is a condition that was never created (the migration was " +
					"not run, or a rollback put the previous image on the new schema), and an " +
					"operations executor that has not come up yet is a start-up window. Every " +
					"cell is seeded at registration, so ALL rows at zero is a THIRD state — " +
					"readiness was never evaluated, meaning nobody asks the probe and no pod is " +
					"taken out of rotation for a dependency that is down.",
			}, []string{"dependency", "outcome"}),
		}
		r.reg.MustRegister(r.readiness.checks)
	})
	for _, dependency := range dependencies {
		for _, outcome := range ReadinessOutcomes {
			r.readiness.checks.WithLabelValues(dependency, outcome).Add(0)
		}
	}
	return r.readiness
}

// Observe принимает исход ОДНОЙ зависимости за одну оценку готовности.
func (o *ReadinessRecorder) Observe(dependency string, up bool) {
	outcome := ReadinessOutcomeUnready
	if up {
		outcome = ReadinessOutcomeReady
	}
	o.checks.WithLabelValues(dependency, outcome).Inc()
}
