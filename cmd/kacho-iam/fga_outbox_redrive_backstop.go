// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_outbox_redrive_backstop.go — возврат отравленных строк очереди tuple'ов
// обратно в работу.
//
// # Чего не хватало
//
// Дренаж классифицирует отказ владельца прав (400 InvalidArgument от OpenFGA,
// PermissionDenied) как ПОСТОЯННЫЙ, и это верно: повтор идентичного запроса
// пройти не может. Отравленная строка при этом выбывает из блокирующего набора
// заявки, поэтому её партиция разблокируется — и именно это спасает соседей от
// вечного затыка. Но сама строка после этого не берётся НИКОГДА.
//
// Комментарий классификатора (pkg/outbox/drainer/classify.go) прямо оговаривает,
// что травление корректно ТОЛЬКО в сервисе, который периодически возвращает
// такие строки в работу. У vpc, compute, nlb, storage и registry такой возврат
// есть. У iam его не было — при том что через `kacho_iam.fga_outbox` физически
// уходит КАЖДАЯ выдача и КАЖДЫЙ отзыв прав платформы. Несимметрия обошлась в
// 22 часа простоя (#431): миграция поставила выдачу в очередь, новая версия
// модели прав приехала на 18 секунд позже, дренаж успел взять строку между этими
// моментами — и право не доехало, пока его не досыпали руками.
//
// # Почему по событию, а не по таймеру
//
// Слепой повтор постоянного отказа — это ровно тот же запрос с тем же исходом,
// оплаченный вызовом к OpenFGA, записью попытки и строкой в журнале. Возврат
// поэтому привязан к СОБЫТИЮ, которое одно только и способно изменить исход:
// **сменилась версия модели прав**. Это и есть причина класса — модель либо не
// знала отношения, либо не знала типа.
//
// Наблюдение события стоит одного запроса `authorization-models?page_size=1`
// в период; пока идентификатор не изменился, к базе не идёт НИ ОДНОГО запроса.
// То есть в здоровом кластере механизм не читает очередь вообще.
//
// # Чего он не делает — названо, чтобы не читалось шире
//
// Строка, отравленная НЕ моделью (искажённый payload, отказ в правах у самого
// iam), сменой модели не воскресает и не должна: её исход от модели не зависит.
// Такая строка остаётся отравленной и видна гейджем `outbox_poisoned` (скан
// очереди, outbox_metrics_wiring.go) плюс отчётом этого цикла, который называет
// ЧИСЛО отравленных при каждом срабатывании. «Ноль отравленных за всё время»
// отличимо от «никто не смотрел» тем, что гейдж пишется каждые 15 секунд.
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/outbox/reconciler"
)

// modelRevisionProbe — порт, объявленный ПОТРЕБИТЕЛЕМ: цикл возврата не нуждается
// ни в чём из клиента OpenFGA, кроме одной наблюдаемой величины. Функциональный
// тип вместо интерфейса — потому что метод ровно один, и подставить его в пробе
// нужно без заведения дублёра, который был бы снисходительнее настоящего.
//
// Пустой идентификатор при nil-ошибке — законное состояние «модели ещё нет»
// (кластер поднимается), а не сбой и не смена.
type modelRevisionProbe func(ctx context.Context) (string, error)

// fgaRedriveProbeInterval — как часто спрашивается версия модели.
//
// Это период НАБЛЮДЕНИЯ события, а не период повтора: пока ответ тот же, ничего
// не происходит. Величина выбрана по цене простоя, а не по цене запроса — в #431
// окно между постановкой строки в очередь и приездом модели составило 18 секунд,
// и минута сверху к 22 часам ничего не добавляет.
const fgaRedriveProbeInterval = 30 * time.Second

// fgaRedriveProbeTimeout — срок одного наблюдения. Недоступный OpenFGA не должен
// подвешивать горутину: неотвеченный опрос — это просто «события не наблюдали»,
// следующий тик спросит снова.
const fgaRedriveProbeTimeout = 5 * time.Second

// startFGAOutboxRedrive поднимает цикл возврата поверх kacho_iam.fga_outbox.
//
// Ключ упорядочения берётся тот же, что исполняет дренаж (`tuple_key`), и это не
// стилистика: заявка дренажа отказывается брать строку впереди ДОСТАВЛЯЕМОГО
// предшественника той же партиции, а возврат отказывается поднимать строку мимо
// уже ДОСТАВЛЕННОГО преемника. Это две половины одного правила; на разных ключах
// каждая половина стережёт партицию, которой не стережёт другая, — и выдача,
// поднятая мимо своего доставленного отзыва, вернула бы снятое право.
func startFGAOutboxRedrive(
	ctx context.Context,
	pool *pgxpool.Pool,
	probe modelRevisionProbe,
	logger *slog.Logger,
) error {
	log := logger.With(slog.String("component", "fga_outbox_redrive"))

	rc, err := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:   fgaOutboxTable,
		Channel: fgaOutboxChannel,
		// Тот же порог, что исполняет дренаж, — не повторённое число: разойдись
		// эти два места, возврат поднимал бы не то, что дренаж травит.
		MaxAttempts: fgaOutboxDrainerConfig().MaxAttempts,
		// Тот же ключ, что у дренажа, — та же КОНСТАНТА, а не поле, вычисляемое
		// вызовом: гейт по дереву резолвит ключ разбором исходника, и адрес,
		// вычисляемый в рантайме, для него неотличим от отсутствующего, то есть
		// эта очередь выпала бы из сверки молча. Совпадение с дренажом при этом
		// держится не только константой — парная проба читает ОБА значения из
		// настройки, с которой работает процесс.
		PartitionColumn: fgaOutboxTupleKeyColumn,
	}, log)
	if err != nil {
		return err
	}

	go runFGAOutboxRedrive(ctx, fgaRedriveProbeInterval, &redriveOnModelChange{
		redrive: rc.RedrivePoisoned,
		probe:   probe,
		log:     log,
	})
	log.Info("fga_outbox poison redrive started (model-revision triggered)",
		"table", fgaOutboxTable,
		"partition_column", fgaOutboxDrainerConfig().PartitionColumn,
		"probe_interval", fgaRedriveProbeInterval.String())
	return nil
}

// redriveOnModelChange — одно наблюдение события и решение по нему.
//
// Вынесено из петли ОТДЕЛЬНЫМ типом, чтобы решение проверялось без часов:
// проба зовёт Tick столько раз, сколько ей нужно, и утверждает, СКОЛЬКО раз
// состоялся проход. Свойство, ради которого механизм заведён, — «повтор
// постоянного отказа не делается вслепую» — это утверждение о ЧИСЛЕ проходов
// при неизменной модели, и на тикере его пришлось бы выводить из времени.
type redriveOnModelChange struct {
	redrive func(context.Context) (int, error)
	probe   modelRevisionProbe
	log     *slog.Logger

	lastSeen string
	observed bool
}

// Tick выполняет одно наблюдение. Возвращает true, если проход возврата
// состоялся.
//
// Первое успешное наблюдение — тоже событие. Процесс, который только что
// стартовал, НЕ ЗНАЕТ, менялась ли модель, пока его не было; а перезапуск — это
// и есть штатный способ, которым закреплённая версия модели меняется у этого
// процесса (KACHO_IAM_OPENFGA_MODEL_ID читается один раз при построении
// клиента). Проход при этом дёшев: на здоровой очереди отравленных строк ноль.
func (r *redriveOnModelChange) Tick(ctx context.Context) bool {
	pctx, cancel := context.WithTimeout(ctx, fgaRedriveProbeTimeout)
	id, err := r.probe(pctx)
	cancel()
	if err != nil {
		// Недоступный OpenFGA — это «событие не наблюдали», а не «события не
		// было». Debug, а не Warn: цикл наблюдения не является контролем
		// безопасности, и шум здесь заглушил бы отчёт о самом возврате.
		r.log.Debug("model revision probe failed; no observation this tick", "err", err)
		return false
	}
	if id == "" {
		return false // модели ещё нет — кластер поднимается; не смена
	}
	if r.observed && id == r.lastSeen {
		return false // ничего не изменилось: к очереди не идём вовсе
	}

	wasObserved, prev := r.observed, r.lastSeen
	r.lastSeen, r.observed = id, true

	n, rerr := r.redrive(ctx)
	if rerr != nil {
		// Проход не состоялся — версия НЕ запоминается как обработанная, иначе
		// одна неудачная попытка съела бы событие целиком и строки остались бы
		// лежать до следующей смены модели.
		r.observed, r.lastSeen = wasObserved, prev
		r.log.Warn("fga_outbox poison redrive failed", "err", rerr)
		return false
	}
	if wasObserved {
		r.log.Warn("authorization model changed; poisoned tuple intents returned to the queue",
			"model_id", id, "previous_model_id", prev, "revived", n)
	} else {
		r.log.Info("fga_outbox poison redrive on first model observation",
			"model_id", id, "revived", n)
	}
	return true
}

// runFGAOutboxRedrive крутит наблюдение на тикере, пока ctx не отменён.
func runFGAOutboxRedrive(ctx context.Context, interval time.Duration, r *redriveOnModelChange) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.Tick(ctx)
		}
	}
}
