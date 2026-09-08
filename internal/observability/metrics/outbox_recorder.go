// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	outboxmetrics "github.com/PRO-Robotech/kacho/pkg/outbox/metrics"
)

// OutboxRecorder — состояние ВСЕХ очередей kaname, снимаемое периодическим
// сканом таблицы, а не логом дренажа.
//
// # Почему это отдельный тип, а не поля в CompensationRecorder
//
// Гейджи ниже размечены лейблом `table` и потому годятся любой очереди сервиса —
// но жили они в типе с именем «компенсация», хотя компенсация — ОДНА из очередей
// сервиса, а не все они. Числа очередей здесь намеренно НЕТ: оно росло у этого
// комментария молча (в день заведения он говорил «три», и это перестало быть
// верным задолго до того, как кто-нибудь перечитал строку). Перечень ВЫВОДИТСЯ:
//
//	git grep -c 'CREATE TABLE kaname\..*outbox' -- services/iam/internal/migrations
//	git grep -l 'outboxmetrics.NewCollector' -- services/iam/cmd ':!*_test.go'
//
// Первое даёт объявленные очереди, второе — наблюдаемые; расхождение между ними
// и есть вопрос, ради которого число вообще называют.
//
// Второй предикат сужен до композиционного корня НЕ для краткости: без сужения
// он находит ЭТОТ ЖЕ комментарий и считает собственное объяснение за наблюдателя
// (замерено: 4 файла вместо 3). Проверка, считающая собственную прозу, — тот
// самый класс, ради которого предикат вообще пишут рядом с числом; поэтому он
// смотрит туда, где наблюдателей ПРОВЯЗЫВАЮТ, а не туда, где о них пишут.
// Имя типа читается как область его действия: следующий,
// кому понадобится наблюдать fga_outbox, увидел бы «это про компенсации» и завёл
// бы вторые гейджи с теми же именами — то есть уронил бы старт на
// duplicate-register ровно тогда, когда механизм наконец провязали целиком.
// Поэтому счётчики компенсации остались у компенсации, а состояние очередей
// вынесено сюда и берётся одним экземпляром на реестр.
//
// # Что здесь есть и почему именно это
//
// Сводные серии по таблице:
//
//	kaname_outbox_backlog_depth{table}              — недоставленных строк
//	kaname_outbox_oldest_pending_age_seconds{table} — возраст головы очереди
//	kaname_outbox_poisoned_count{table}             — отравленных сейчас
//
// Плюс разложение той же очереди ПО НАПРАВЛЕНИЮ:
//
//	kaname_outbox_backlog_depth_by_direction{table,direction}
//	kaname_outbox_oldest_pending_age_by_direction_seconds{table,direction}
//	kaname_outbox_delivered_total{table,direction}
//
// Разложение нужно потому, что сводные серии на очереди с двумя половинами
// остаются здоровыми при полностью мёртвой второй: выдачи прав идут непрерывно —
// ресурсы создают всё время, — поэтому и глубина мала, и голова молода, что бы ни
// происходило со снятием. «Работает» и «ни разу не отозвано» дают ОДИНАКОВУЮ
// картину, и различает их только `delivered_total{direction="withdrawal"}`:
// единственная из четырёх величин, которая отличает «их не было» от «они не
// доезжают».
//
// Набор меток ЗАКРЫТ: имена таблиц и направлений приходят из констант
// composition root, никогда из запроса, поэтому кардинальность не растёт с
// трафиком.
type OutboxRecorder struct {
	backlog *prometheus.GaugeVec
	oldest  *prometheus.GaugeVec
	poison  *prometheus.GaugeVec

	dirBacklog   *prometheus.GaugeVec
	dirOldest    *prometheus.GaugeVec
	dirDelivered *prometheus.CounterVec

	// scans / scanFailures — ИСХОД самого скана.
	//
	// Все измерители выше появляются только после первого УДАЧНОГО скана:
	// измеритель без детей семейства не отдаёт вовсе. Значит «сканер отказывает
	// с самого старта» и «сканера тут нет вовсе» давали ОДНУ картину — пустую, —
	// и величина, заведённая ровно затем, чтобы молчание очереди было слышно,
	// сама молчала неотличимо от исправной работы (#2062).
	//
	// Предварительная инициализация ВОЗРАСТА нулём исходом не была: ноль
	// возраста означает «очередь пуста», то есть ложь до первого скана. У
	// счётчика исходов ноль — законное значение, а отсутствие ряда невозможно by
	// construction: клетки заводятся при провязке сканера.
	scans        *prometheus.CounterVec
	scanFailures *prometheus.CounterVec
}

// newOutboxRecorder регистрирует коллекторы в этом реестре. Зовётся ровно один
// раз — через Registry.OutboxRecorder().
func (r *Registry) newOutboxRecorder() *OutboxRecorder {
	rec := &OutboxRecorder{
		backlog: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: Namespace + "_outbox_backlog_depth",
			Help: "Недоставленные строки outbox-таблицы.",
		}, []string{"table"}),
		oldest: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: Namespace + "_outbox_oldest_pending_age_seconds",
			Help: "Возраст самой старой недоставленной строки outbox-таблицы. " +
				"Отвечает на «висит ли строка дольше N».",
		}, []string{"table"}),
		poison: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: Namespace + "_outbox_poisoned_count",
			Help: "Отравленные (исчерпавшие попытки) строки outbox-таблицы.",
		}, []string{"table"}),
		dirBacklog: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: Namespace + "_outbox_backlog_depth_by_direction",
			Help: "Недоставленные строки очереди по направлению (выдача / снятие).",
		}, []string{"table", "direction"}),
		dirOldest: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: Namespace + "_outbox_oldest_pending_age_by_direction_seconds",
			Help: "Возраст самой старой недоставленной строки одного направления — " +
				"отвечает на «как давно это направление перестало доезжать».",
		}, []string{"table", "direction"}),
		dirDelivered: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_outbox_delivered_total",
			Help: "Доставленные строки очереди по направлению, считаются В МОМЕНТ " +
				"доставки. Единственная величина, отличающая «их не было» от «они не " +
				"доезжают»: ноль по снятию означает, что ни один отзыв прав не был " +
				"применён С МОМЕНТА СТАРТА ПРОЦЕССА. Счётчик, а не измеритель: значение " +
				"не зависит от числа хранимых строк, поэтому уборка доставленных его не " +
				"снижает; порог ставить на increase() за окно.",
		}, []string{"table", "direction"}),
		scans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_outbox_scans_total",
			Help: "Сканы очереди, ДОШЕДШИЕ ДО ЗНАЧЕНИЙ. Ноль при живом процессе " +
				"означает, что состояние очереди не снималось ни разу — то есть " +
				"измерители ниже молчат не потому, что очередь пуста.",
		}, []string{"table"}),
		scanFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_outbox_scan_failures_total",
			Help: "Отказы скана очереди (неверные права, сломанный запрос, " +
				"недоступная база). Порог ставить на increase() за окно; пара с " +
				"kaname_outbox_scans_total отличает «скан не работал ни разу» от " +
				"«очередь пуста».",
		}, []string{"table"}),
	}
	r.reg.MustRegister(rec.backlog, rec.oldest, rec.poison,
		rec.dirBacklog, rec.dirOldest, rec.dirDelivered,
		rec.scans, rec.scanFailures)
	return rec
}

// OutboxRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр коллекторов состояния
// очередей этого реестра, создавая его при первом обращении.
//
// Потребителей столько же, сколько очередей, и собираются они в разных местах
// композиционного корня. Два независимых конструктора уронили бы старт на
// duplicate-register — поэтому экземпляр один и берётся отсюда.
func (r *Registry) OutboxRecorder() *OutboxRecorder {
	r.outboxOnce.Do(func() { r.outbox = r.newOutboxRecorder() })
	return r.outbox
}

// SetBacklogDepth реализует outbox/metrics.Recorder.
//
// Здесь же считается УДАЧНЫЙ скан, и это не побочный эффект, а построение:
// сканер зовёт этот метод ровно один раз за проход и ровно тогда, когда
// значения получены (pkg/outbox/metrics, Collector.Scan — три Set-вызова после
// единственного чтения). Отдельный явный вызов «скан удался» был бы вторым
// местом об одном предмете и разошёлся бы с измерителями молча; счётчик,
// двигающийся ВМЕСТЕ со значением, разойтись с ним не может.
func (rec *OutboxRecorder) SetBacklogDepth(table string, depth float64) {
	rec.backlog.WithLabelValues(table).Set(depth)
	rec.scans.WithLabelValues(table).Inc()
}

// InitScanOutcomes заводит клетки исходов скана нулём, не увеличивая их.
//
// Зовётся при ПРОВЯЗКЕ сканера, а не при первом его проходе: иначе ряды
// появились бы только после первого исхода, и «сканер не сделал ни одного
// прохода» снова выражалось бы отсутствием ряда — тем самым, из-за чего эти
// счётчики и заведены.
func (rec *OutboxRecorder) InitScanOutcomes(table string) {
	rec.scans.WithLabelValues(table)
	rec.scanFailures.WithLabelValues(table)
}

// ObserveScanFailure — ОДИН отказавший проход сканера.
func (rec *OutboxRecorder) ObserveScanFailure(table string) {
	rec.scanFailures.WithLabelValues(table).Inc()
}

// SetOldestPendingAgeSeconds реализует outbox/metrics.Recorder.
func (rec *OutboxRecorder) SetOldestPendingAgeSeconds(table string, age float64) {
	rec.oldest.WithLabelValues(table).Set(age)
}

// SetPoisonedCount реализует outbox/metrics.Recorder.
func (rec *OutboxRecorder) SetPoisonedCount(table string, count float64) {
	rec.poison.WithLabelValues(table).Set(count)
}

// IncPoisoned реализует outbox/metrics.Recorder.
func (rec *OutboxRecorder) IncPoisoned(table string) {
	// Отравленные строки уже отражены SetPoisonedCount по скану таблицы;
	// отдельного монотонного счётчика здесь не заводим, чтобы не держать две
	// величины об одном предмете, из которых расходиться будет одна.
	_ = table
}

// SetBacklogDepthByDirection реализует outbox/metrics.DirectionRecorder.
func (rec *OutboxRecorder) SetBacklogDepthByDirection(table, direction string, depth float64) {
	rec.dirBacklog.WithLabelValues(table, direction).Set(depth)
}

// SetOldestPendingAgeByDirection реализует outbox/metrics.DirectionRecorder.
func (rec *OutboxRecorder) SetOldestPendingAgeByDirection(table, direction string, age float64) {
	rec.dirOldest.WithLabelValues(table, direction).Set(age)
}

// IncDeliveredByDirection — ОДНА доставленная строка направления.
//
// СЧЁТЧИК, инкрементируемый наблюдателем дренажа, а не измеритель, ставящийся
// сканом (#1714): величина объявлена «за всё время», и счёт по живым строкам
// совпадал с этим ровно до появления уборки доставленных строк.
func (rec *OutboxRecorder) IncDeliveredByDirection(table, direction string) {
	rec.dirDelivered.WithLabelValues(table, direction).Inc()
}

// InitDeliveredByDirection заводит серию направления с нулём, не увеличивая её:
// дочерняя серия счётчика иначе появилась бы только после ПЕРВОЙ доставки, и
// «ни одного отзыва не доставлено» выражалось бы отсутствием ряда вместо нуля.
func (rec *OutboxRecorder) InitDeliveredByDirection(table, direction string) {
	rec.dirDelivered.WithLabelValues(table, direction)
}

// Compile-time: адаптер удовлетворяет ОБА corelib-порта.
//
// Разложение по направлению Collector спрашивает у получателя ПРИВЕДЕНИЕМ ТИПА
// в рантайме — потеря этих трёх методов в рефакторинге сборку бы не сломала, а
// молча прекратила бы публиковать единственную серию, отвечающую на «доезжает ли
// снятие вообще». Утверждение ниже — то, что не даёт этому случиться тихо.
var (
	_ outboxmetrics.Recorder          = (*OutboxRecorder)(nil)
	_ outboxmetrics.DirectionRecorder = (*OutboxRecorder)(nil)
)
