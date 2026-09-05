// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sweeper.go — фоновая петля уборки и её проход.
package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Config — величины уборки. ОБЪЯВЛЯЮТСЯ в конфигурации сервиса и проверяются
// при старте: величина, уезжающая в SQL мимо объявления, невидима оператору.
//
// Порогов здесь нет намеренно — они не настраиваются, а вычисляются из
// `pkg/tokenpolicy` (см. Subjects). Настраиваемый порог был бы ручкой, которой
// его молча разводят с предикатом читателя, то есть ручкой заведения дефекта.
type Config struct {
	// Interval — как часто идёт проход.
	Interval time.Duration
	// Batch — сколько строк снимает один оператор.
	//
	// Партии, а не «удалить всё»: первый прогон после выкатки встречает всё,
	// что накопилось за жизнь стенда, и DELETE без предела на такой таблице —
	// длинная транзакция, удерживающая строки, которые горячий путь читает в
	// тот же момент. Уборка не вправе быть причиной отказа на пути запроса.
	Batch int
	// MaxBatchesPerPass — потолок числа партий за проход.
	//
	// Одна партия за тик даёт скорость догона `партия / интервал`, и если темп
	// записи выше — уборщик не догонит НИКОГДА, оставаясь зелёным по всякой
	// проверке «вызвался ли». Проход повторяет партию, пока она уходит полной,
	// но не более потолка: тогда длительность прохода ограничена сверху, а
	// догон меряется проходом, а не тиком.
	MaxBatchesPerPass int
}

// Validate отвергает величины, при которых уборка не работает либо работает
// неограниченно долго.
//
// Отдельный экспортированный метод, потому что страж старта сервиса обязан
// звать ТОТ ЖЕ предикат, что и построитель: две проверки об одном предмете
// разошлись бы молча.
func (c Config) Validate() error {
	var errs []error
	if c.Interval <= 0 {
		errs = append(errs, fmt.Errorf("retention.interval: интервал прохода обязан быть положительным, получено %v", c.Interval))
	}
	if c.Batch <= 0 {
		errs = append(errs, fmt.Errorf("retention.batch: партия обязана быть положительной, получено %d", c.Batch))
	}
	if c.Batch > MaxBatch {
		errs = append(errs, fmt.Errorf(
			"retention.batch: партия %d больше потолка %d — оператор такой длины удерживает строки, "+
				"которые горячий путь читает в тот же момент", c.Batch, MaxBatch))
	}
	if c.MaxBatchesPerPass <= 0 {
		errs = append(errs, fmt.Errorf(
			"retention.max-batches-per-pass: потолок партий за проход обязан быть положительным, получено %d "+
				"(ноль означал бы петлю, которая исполняется и не убирает ничего)", c.MaxBatchesPerPass))
	}
	return errors.Join(errs...)
}

// MaxBatch — потолок величины партии.
//
// Он не про вкус: партия задаёт длину одного оператора DELETE, а тот держит
// строки, которые в этот момент читает путь запроса. Величина выбрана на
// порядок выше рабочей (1000) — ручка остаётся ручкой, но «убрать всё одним
// оператором» ею не выражается.
const MaxBatch = 10_000

// PassResult — исход одного прохода, ПО КАЖДОМУ ПРЕДМЕТУ ОТДЕЛЬНО.
//
// Раздельность не украшение: ноль по одному предмету означает либо «убирать
// нечего», либо «уборка не доходит до этой записи реестра», и общая величина не
// различает эти состояния.
type PassResult struct {
	// Removed — снято строк по каждому предмету. Ключ есть у КАЖДОГО предмета
	// реестра, даже когда снято ноль.
	Removed map[string]int64
	// Batches — сколько партий ушло по каждому предмету.
	Batches map[string]int
	// Errs — отказ по каждому предмету, у которого он был.
	Errs map[string]error
}

// Err — объединённый отказ прохода; nil, если ни один предмет не отказал.
func (r PassResult) Err() error {
	var errs []error
	for name, err := range r.Errs {
		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}
	return errors.Join(errs...)
}

// Counts — накопленное за жизнь процесса. Читается сборщиком метрик: накопитель
// без читателя считает в никуда, и его ноль не утверждает ничего.
type Counts struct {
	// Passes — сколько проходов исполнено. Ноль здесь отличает «убирать нечего»
	// от «петля не идёт вовсе».
	Passes int64
	// Removed — снято строк по каждому предмету за всё время.
	Removed map[string]int64
	// Failures — отказов по каждому предмету за всё время.
	Failures map[string]int64
}

// Sweeper — фоновая уборка по реестру предметов.
type Sweeper struct {
	cfg      Config
	subjects []Subject
	log      *slog.Logger

	mu       sync.Mutex
	passes   int64
	removed  map[string]int64
	failures map[string]int64

	stopped chan struct{}
}

// New собирает уборщика. Отказывает на негодных величинах: уборка, собранная с
// нулевой партией, исполняется и не убирает ничего — то есть выглядит
// работающей, будучи мёртвой.
func New(cfg Config, subjects []Subject, log *slog.Logger) (*Sweeper, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(subjects) == 0 {
		return nil, errors.New("реестр уборки пуст: петля без предметов исполняется и не убирает ничего")
	}
	seen := map[string]bool{}
	for _, s := range subjects {
		if s.Name == "" {
			return nil, errors.New("запись реестра без имени предмета: её ноль нечем назвать в отчёте")
		}
		if s.Sweep == nil {
			return nil, fmt.Errorf("запись реестра %q без уборщика — объявление без предмета", s.Name)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("предмет %q объявлен дважды: два места об одном пороге разойдутся молча", s.Name)
		}
		seen[s.Name] = true
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Sweeper{
		cfg:      cfg,
		subjects: subjects,
		log:      log,
		removed:  map[string]int64{},
		failures: map[string]int64{},
		stopped:  make(chan struct{}),
	}, nil
}

// Pass — один проход по всему реестру.
//
// Экспортирован НАМЕРЕННО: «сборщик работает» обязано быть проверяемо без
// ожидания тикера. Довод не изобретён здесь — его говорит шапка живого уборщика
// дерева (`gateway/internal/idempotencypg/store.go`, `Store.Reap`), и он же
// снимает нужду подавать уборщику часы входом ради проверяемости.
func (s *Sweeper) Pass(ctx context.Context) PassResult {
	res := PassResult{
		Removed: make(map[string]int64, len(s.subjects)),
		Batches: make(map[string]int, len(s.subjects)),
		Errs:    map[string]error{},
	}
	for _, subj := range s.subjects {
		// Ключ заводится ДО первой партии: предмет, по которому снято ноль,
		// обязан быть в отчёте, иначе «нечего убирать» неотличимо от «уборка
		// не доходит».
		res.Removed[subj.Name] = 0
		res.Batches[subj.Name] = 0
		for range s.cfg.MaxBatchesPerPass {
			if ctx.Err() != nil {
				break
			}
			n, full, err := subj.Sweep(ctx, subj.Grace, s.cfg.Batch)
			res.Removed[subj.Name] += n
			res.Batches[subj.Name]++
			if err != nil {
				// Отказ по одному предмету не отменяет остальных: реестр —
				// перечень независимых предметов, а не транзакция.
				res.Errs[subj.Name] = err
				break
			}
			if !full {
				// Партия ушла неполной — снимать больше нечего.
				break
			}
		}
	}
	s.record(res)
	return res
}

// record складывает исход прохода в накопитель и печатает величины.
func (s *Sweeper) record(res PassResult) {
	s.mu.Lock()
	s.passes++
	for name, n := range res.Removed {
		s.removed[name] += n
	}
	for name := range res.Errs {
		s.failures[name]++
	}
	s.mu.Unlock()

	for _, subj := range s.subjects {
		if err, bad := res.Errs[subj.Name]; bad {
			// Отставший уборщик НЕ фатален: строка постоит дольше нужного, а
			// предикат читателя продолжает действовать. Ронять сервис из-за
			// него значило бы менять ограниченное отставание на полный отказ.
			s.log.Warn("retention sweep failed",
				slog.String("subject", subj.Name), slog.String("err", err.Error()))
			continue
		}
		if n := res.Removed[subj.Name]; n > 0 {
			s.log.Info("retention sweep removed rows",
				slog.String("subject", subj.Name),
				slog.Int64("removed", n),
				slog.Int("batches", res.Batches[subj.Name]))
		}
	}
}

// Stats — накопленное за жизнь процесса.
func (s *Sweeper) Stats() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Counts{
		Passes:   s.passes,
		Removed:  make(map[string]int64, len(s.removed)),
		Failures: make(map[string]int64, len(s.failures)),
	}
	// Ключ есть у каждого предмета реестра — и когда снято ноль тоже.
	for _, subj := range s.subjects {
		out.Removed[subj.Name] = s.removed[subj.Name]
		out.Failures[subj.Name] = s.failures[subj.Name]
	}
	return out
}

// Start поднимает фоновую петлю уборки.
//
// Первый проход идёт СРАЗУ, не через интервал: он встречает всё, что накопилось
// за жизнь стенда, и откладывать его на интервал значило бы держать накопленное
// ещё и это время.
//
// РЕПЛИКИ: на-реплику — уборка есть условный оператор `DELETE … WHERE <срок> <=
// now() − порог` с пределом партии и клеймом строк (`FOR UPDATE SKIP LOCKED`).
// Строки заперты самим оператором, поэтому вторая реплика уносит только
// остаток, а на пустой выборке не делает ничего; к соседям проход не ходит.
// Общий замок не нужен: он купил бы отсутствие дубля ценой одиночной точки, у
// которой свой отказ.
func (s *Sweeper) Start(ctx context.Context) {
	go func() {
		defer close(s.stopped)
		ticker := time.NewTicker(s.cfg.Interval)
		defer ticker.Stop()
		s.Pass(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Pass(ctx)
			}
		}
	}()
}

// Wait ждёт завершения петли после отмены контекста и отвечает, дождался ли.
//
// Нужен пробе останова и останову процесса: петля, которую никто не дожидается,
// оставляет незавершённый проход в неопределённом состоянии для наблюдателя —
// хотя частично применённой партии не бывает by construction, партия есть один
// оператор.
func (s *Sweeper) Wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.stopped:
		return true
	case <-t.C:
		return false
	}
}
