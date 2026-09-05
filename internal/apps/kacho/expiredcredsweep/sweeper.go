// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package expiredcredsweep — платформа снимает удостоверение, чей срок истёк
// более чем на отсрочку назад.
//
// # Предмет
//
// Удостоверение с истёкшим сроком продолжало занимать место под потолком числа
// удостоверений на принципала, пока его явно не отзовут. Для арендатора это
// выглядело так: место кончилось, а в перечне сплошь недействующие строки.
//
// Строка при этом мертва функционально: отбор резолва секрета несёт
// `expires_at > now()`, а на полосе ключевой пары остаток срока не положителен и
// выдача отказывает. Истёкшая строка не даёт ни одного пути входа и не может
// отчеканить ни одного токена. Единственное, что она делает, — занимает место.
//
// # Почему уборка, а не «не считать истёкшие на списании»
//
// `used` — число в строке учёта, меняемое на ±1. Чтобы «не считать истёкшие»,
// его пришлось бы пересчитывать; но момент истечения СОБЫТИЕМ не является, и
// наблюдателя у него нет. Витрина показывала бы одно, а выдача вела бы себя по
// другому. Уборка выражает освобождение места СОБЫТИЕМ — удалением строки, — и
// место возвращает уже существующий триггер списания, без единой правки в нём.
//
// # Арифметика списания НЕ ТРОГАЕТСЯ
//
// Отзыв — физический DELETE строки, и на нём триггер потолка делает
// `used = GREATEST(used - 1, 0)` в ТОЙ ЖЕ транзакции. Уборщик идёт тем же
// оператором, значит возврат места атомарен снятию, а гонку разрешает блокировка
// строки учёта (ban #10) — без «спросить, потом списать».
//
// # Часы — БАЗЫ, а не процесса
//
// Порог снятия судит `now()` СУБД, тот же, которым судит отбор резолва
// (`expires_at > now()`). Уборщик, судящий время из аргументов, и читатель,
// судящий `now()`, тождественны только при синхронности часов: ушедший вперёд
// процесс снял бы строку, которую резолв ещё считает действующей. Поэтому в
// адаптер уезжают ДЛИТЕЛЬНОСТИ, а момент вычисляет база.
package expiredcredsweep

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"time"
)

// Store — долговечная половина уборки. Реализуется адаптером Postgres
// (repo/kacho/pg.ExpiredCredentialReclaimer); use-case никогда не видит pgx.
type Store interface {
	ReclaimExpiredCredentials(ctx context.Context, spec Spec) (Result, error)
}

// Spec — границы одного прогона. Длительности, а не моменты: момент вычисляет
// база своими часами (см. шапку пакета).
type Spec struct {
	// MinDelay — технический пол отсрочки: раньше него не снимается ничто ни
	// при какой настройке, потому что до этого момента живут отчеканенные
	// токены. Он же — индексируемая НЕОБХОДИМАЯ граница отбора.
	MinDelay time.Duration
	// Grace — верхняя отсрочка. Действующая отсрочка строки связана с её
	// собственным сроком: min(Grace, max(MinDelay, срок строки)).
	Grace time.Duration
	// BatchSize — строк на таблицу за прогон. Первый прогон после выкатки
	// снимает накопленное ПАРТИЯМИ, а не одним оператором.
	BatchSize int
	// DryRun — показ без снятия. Необратимое действие, впервые встречающееся с
	// боевым кластером, обязано иметь дешёвый способ спросить «что ты снесёшь».
	DryRun bool
}

// Result — перепись прогона. ДВА числа, а не одно: «снято 0» само по себе не
// отличает «нечего снимать» от «нашёл и не снял».
type Result struct {
	// Found — строк, подлежащих снятию, найдено.
	Found int
	// Reclaimed — строк снято. При DryRun равно нулю при непустом Found — и это
	// законный, а не ошибочный исход.
	Reclaimed int
	// ByKind — разбивка по виду учёта, чтобы перепись называла предмет, а не
	// только величину.
	ByKind map[string]int
}

// Observer — приёмник рядов величин. Журнал сверху, не вместо: мёртвая петля не
// печатает НИЧЕГО, а отсутствие строки правилом тревоги не выражается. Ряд
// прогонов, переставший расти, наблюдаем без чтения журнала.
type Observer interface {
	// SweepObserved принимает исход одного прогона: outcome — закрытый набор
	// ("ok" | "failed" | "dry-run"), found/reclaimed — числа переписи.
	SweepObserved(outcome string, found, reclaimed int)
}

// Sweeper гоняет Store.ReclaimExpiredCredentials по интервалу.
type Sweeper struct {
	store    Store
	spec     Spec
	interval time.Duration
	logger   *slog.Logger
	observer Observer
	// ticker — подменяемые часы для проб; nil → time.NewTicker.
	ticker func(time.Duration) (<-chan time.Time, func())
	// jitter — разъезд первого прогона по репликам; nil → случайный.
	jitter func(time.Duration) time.Duration
}

// New строит уборщика. interval <= 0 → DefaultInterval.
func New(store Store, spec Spec, interval time.Duration, logger *slog.Logger) *Sweeper {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{store: store, spec: spec, interval: interval, logger: logger}
}

// DefaultInterval — час.
//
// Величина обоснована ТОЧНОСТЬЮ относительно отсрочки: час даёт погрешность
// около четырёх процентов от суток. Соседний уборщик секретов работает раз в
// минуту, потому что его предмет измеряется минутами; здесь предмет измеряется
// сутками, и минутный прогон был бы расходом без выигрыша.
const DefaultInterval = time.Hour

// DefaultBatchSize — строк на таблицу за прогон.
//
// Партия ограничивает длительность транзакции, а не «объём работы»: снятие
// строки тянет за собой триггер списания и, у машины, каскад записей доверия.
const DefaultBatchSize = 200

// maxStartupJitter — потолок разъезда первого прогона.
//
// Требование «первый прогон сразу при старте» при перекате даёт N одновременных
// обходов таблицы с максимальным долгом: поднимаются все реплики разом. Разъезд
// обязателен, и он ограничен сверху — иначе перезапуск переставал бы быть
// моментом, когда накопленное снимается.
const maxStartupJitter = 30 * time.Second

// WithTicker подменяет часы (пробы).
func (s *Sweeper) WithTicker(f func(time.Duration) (<-chan time.Time, func())) *Sweeper {
	s.ticker = f
	return s
}

// WithJitter подменяет разъезд (пробы): детерминизм входа.
func (s *Sweeper) WithJitter(f func(time.Duration) time.Duration) *Sweeper {
	s.jitter = f
	return s
}

// WithObserver подключает ряды величин.
func (s *Sweeper) WithObserver(o Observer) *Sweeper {
	s.observer = o
	return s
}

// Run делает первый прогон сразу — перезапуск и есть момент, когда накопленного
// больше всего, — и далее по интервалу, пока жив ctx.
//
// РЕПЛИКИ: клейм — партия берётся отбором с пропуском занятых строк
// (FOR UPDATE SKIP LOCKED в адаптере), поэтому две реплики не спорят за одни и
// те же строки и не снимают одну дважды; первый прогон при этом разводится
// случайной задержкой, иначе перекат даёт N одновременных обходов таблицы с
// максимальным долгом.
//
// Не фатален по контракту: упавший прогон логируется и повторяется, но никогда
// не повод положить процесс.
func (s *Sweeper) Run(ctx context.Context) {
	if d := s.startupJitter(); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	s.SweepOnce(ctx)

	var (
		c    <-chan time.Time
		stop func()
	)
	if s.ticker != nil {
		c, stop = s.ticker(s.interval)
	} else {
		t := time.NewTicker(s.interval)
		c, stop = t.C, t.Stop
	}
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			s.SweepOnce(ctx)
		}
	}
}

// startupJitter — задержка перед ПЕРВЫМ прогоном.
func (s *Sweeper) startupJitter() time.Duration {
	cap := maxStartupJitter
	if s.interval < cap {
		cap = s.interval
	}
	if s.jitter != nil {
		return s.jitter(cap)
	}
	if cap <= 0 {
		return 0
	}
	// Источник — криптографический, и это НЕ про стойкость разъезда: разъезд
	// реплик тайной не является. Слабый источник здесь дал бы находку статического
	// разбора, а подавлять её пометкой значило бы заводить послабление ради одной
	// строки, исполняемой один раз за жизнь процесса. Дешевле взять сильный.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(cap)))
	if err != nil {
		// Отказ источника не повод не пойти: без разъезда реплики начнут обход
		// разом — это хуже по нагрузке, но не по корректности.
		return 0
	}
	return time.Duration(n.Int64())
}

// SweepOnce делает один прогон и печатает перепись — ВСЕГДА, а не только при
// непустой находке.
//
// «Найдено 0 · снято 0» отличимо от «уборщик не крутится» рядом величин
// (Observer), а «нашёл и не снял» — вторым числом переписи. Одно число не
// давало бы ни того, ни другого.
func (s *Sweeper) SweepOnce(ctx context.Context) Result {
	res, err := s.store.ReclaimExpiredCredentials(ctx, s.spec)
	if err != nil {
		// Отказ — СВОЙ исход, и «снято 0» на нём не печатается как успех.
		s.logger.ErrorContext(ctx, "снятие истёкших удостоверений: прогон отказал — места под потолком не возвращены",
			slog.Any("err", err), slog.Int("found", res.Found), slog.Int("reclaimed", res.Reclaimed))
		s.observe("failed", res)
		return res
	}
	outcome := "ok"
	if s.spec.DryRun {
		outcome = "dry-run"
	}
	s.logger.InfoContext(ctx, "снятие истёкших удостоверений: прогон",
		slog.String("outcome", outcome),
		slog.Int("found", res.Found),
		slog.Int("reclaimed", res.Reclaimed),
		slog.Any("by_kind", res.ByKind),
		slog.String("grace", s.spec.Grace.String()),
		slog.String("min_delay", s.spec.MinDelay.String()))
	s.observe(outcome, res)
	return res
}

func (s *Sweeper) observe(outcome string, res Result) {
	if s.observer == nil {
		return
	}
	s.observer.SweepObserved(outcome, res.Found, res.Reclaimed)
}
