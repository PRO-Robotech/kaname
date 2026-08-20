// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// admission.go — потолок темпа и одновременности на вызывающего, на ОБА
// слушателя iam.
//
// # Почему у iam своя проводка, а не носителя контура
//
// Шесть сервисов платформы поднимают слушателей через `pkg/servicehost`, и
// потолок им ставит он — по объявленной оси дескриптора. iam собирает серверы
// сам (две точки сборки в serve.go), поэтому обёртку регистратора ставит здесь.
// Это отличие раскладки, а не решения: величины берутся из ТОГО ЖЕ пола
// платформы, ключи у слушателей те же, и счётчик печатается так же.
//
// # Почему iam ограничивать важнее прочих
//
// Он стоит на пути запроса ВСЕХ остальных доменов: решение о доступе
// спрашивают у него на каждом RPC. Неограниченный поток одного вызывающего сюда
// бьёт не по одному сервису, а по всей платформе — и бьёт в базу, а не в сеть.
//
// # Почему обёртка регистратора, а не звено цепочки
//
// Обёртка получает дескриптор службы целиком и подставляет допуск МЕЖДУ цепочкой
// и обработчиком. Ключом служит личность, которую устанавливают звенья цепочки;
// ограничитель, ключующийся раньше этого решения, снимается подстановкой чужого
// заголовка — то есть ограничивает только того, кто не пытается его обойти.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// admissionReportInterval — как часто в журнал уходит счёт допущенных и
// отвергнутых. Отчёт печатается ВСЕГДА, включая нули: «ноль отказов за всю жизнь
// контроля» обязано быть заметно, иначе мёртвый ограничитель невидим. Отличает
// его от живого ПАРА чисел — ноль отвергнутых при нуле допущенных означает
// «никто не звал», а при миллионе допущенных — «предел ни разу не достигнут».
const admissionReportInterval = time.Minute

// admissionIdleWindow — за сколько простоя ведро субъекта убирается. Величина
// щедрая намеренно: убрать ведро значит вернуть субъекту полный всплеск.
const admissionIdleWindow = 10 * time.Minute

// listenerAdmission — пара ограничителей процесса.
type listenerAdmission struct {
	public   *grpcsrv.Admission
	internal *grpcsrv.Admission
}

// admissionLimits — величины ОБОИХ слушателей: ручки посадки там, где она их
// назвала, и ПОЛ ПЛАТФОРМЫ там, где молчит.
//
// Ноль здесь невозможен by construction: молчание разрешается полом, а не
// пустотой. Именно этим раскладка отличается от прежней, где «величины не
// объявлены» означало «слушатель не ограничен» и выглядело в журнале одной
// строкой предупреждения — то есть контролем, который навешен, исполняется на
// каждом запросе и не отверг ни разу.
//
// Сами ограничители собирает КОМПОЗИЦИОННЫЙ КОРЕНЬ, рядом с серверами, которые
// он ими оборачивает: перепись усыновления возможностей фундамента считает
// клетку по МЕСТУ СБОРКИ СЕРВЕРА, и проводка, спрятанная за безымянным вызовом,
// была бы ей невидима — то есть «провязал» снова стало бы неотличимо от «не
// провязал».
func admissionLimits(cfg config.Config) (public, internal grpcsrv.AdmissionLimits, err error) {
	if public, err = cfg.APIServer.RateLimit.Public.Resolve(grpcsrv.PlatformPublicAdmission()); err != nil {
		return public, internal, fmt.Errorf("api-server.rate-limit.public: %w", err)
	}
	if internal, err = cfg.APIServer.RateLimit.Internal.Resolve(grpcsrv.PlatformInternalAdmission()); err != nil {
		return public, internal, fmt.Errorf("api-server.rate-limit.internal: %w", err)
	}
	return public, internal, nil
}

// arm печатает объявленные величины обоих слушателей.
//
// Печатается ВСЕГДА: посадка обязана быть видна в журнале, а не выводиться из
// отсутствия строки — отсутствие читается как «версия старая» ничуть не реже,
// чем как «потолка нет».
func (l listenerAdmission) arm(logger *slog.Logger, cfg config.Config) {
	for _, a := range []*grpcsrv.Admission{l.public, l.internal} {
		if a == nil {
			continue
		}
		fromPosture := !cfg.APIServer.RateLimit.Public.IsSilent()
		if a.Listener() == "internal" {
			fromPosture = !cfg.APIServer.RateLimit.Internal.IsSilent()
		}
		logger.Info("request admission armed",
			"listener", a.Listener(), "limits", a.Limits().String(), "from_posture", fromPosture)
	}
}

// report — фоновая задача: периодически печатает счётчики обоих слушателей и
// убирает вёдра простаивающих субъектов.
//
// Уборка живёт здесь, а не внутри ограничителя: пространство личностей задаёт
// вызывающий, поэтому у роста числа вёдер обязан быть владелец в композиционном
// корне, а не фоновая горутина, запущенная библиотекой за спиной у процесса.
func (l listenerAdmission) report(ctx context.Context, logger *slog.Logger) {
	t := time.NewTicker(admissionReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			l.logOnce(logger, "request admission final counters")
			return
		case <-t.C:
			for _, a := range []*grpcsrv.Admission{l.public, l.internal} {
				if a != nil {
					a.EvictIdle(admissionIdleWindow)
				}
			}
			l.logOnce(logger, "request admission counters")
		}
	}
}

func (l listenerAdmission) logOnce(logger *slog.Logger, msg string) {
	for _, a := range []*grpcsrv.Admission{l.public, l.internal} {
		if a == nil {
			continue
		}
		s := a.Stats()
		logger.Info(msg,
			"listener", a.Listener(),
			"admitted", s.Admitted,
			"rejected_rate", s.RejectedRate,
			"rejected_in_flight", s.RejectedInFlight,
			"subjects", s.Subjects)
	}
}
