// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// listenerAdmission — ограничители процесса: публичный слушатель и два уровня
// внутреннего.
type listenerAdmission struct {
	public   *grpcsrv.Admission
	internal *grpcsrv.Admission
	// internalInstance — уровень экземпляра внутреннего слушателя (kaname#992):
	// ключ — личность и адрес экземпляра, величины — половина потолка модуля.
	internalInstance *grpcsrv.Admission
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
	for _, a := range []*grpcsrv.Admission{l.public, l.internal, l.internalInstance} {
		if a == nil {
			continue
		}
		fromPosture := !cfg.APIServer.RateLimit.Public.IsSilent()
		if a.Listener() == "internal" || a.Listener() == "internal-instance" {
			fromPosture = !cfg.APIServer.RateLimit.Internal.IsSilent()
		}
		logger.Info("request admission armed",
			"listener", a.Listener(), "limits", a.Limits().String(), "from_posture", fromPosture)
	}
}

// report — фоновая задача: счёт допущенных и отвергнутых плюс уборка вёдер
// простаивающих субъектов.
//
// Тело — общее с остальными композиционными корнями ([grpcsrv.ReportAdmission]):
// оно было написано здесь и у носителя контура слово в слово, а край стал бы
// третьей копией. Метод остаётся, потому что его предмет — ПАРА слушателей
// именно этого процесса.
func (l listenerAdmission) report(ctx context.Context, logger *slog.Logger) {
	grpcsrv.ReportAdmission(ctx, logger, "", l.public, l.internal, l.internalInstance)
}

// ─────────────────────────────────────────────────────────────────────────────
// ДВА УРОВНЯ ДОПУСКА ВНУТРЕННЕГО СЛУШАТЕЛЯ (kaname#992)
//
// Прежде ключом был SAN модуля: все экземпляры одного модуля (плоскость данных
// на каждый реестр, реплики службы) делили ОДНО ведро, и шумный экземпляр
// расходовал предел соседних. Теперь допуск двухуровневый:
//
//   - уровень экземпляра — ключ [instanceSubject]: личность сертификата и
//     адрес пира. Где у экземпляра своя личность, её достаточно; где личность
//     общая, экземпляры различает адрес;
//   - уровень модуля — прежний ключ (SAN) и прежние величины
//     (`api-server.rate-limit.internal`): потолок модуля в целом.
//
// Экземпляр проверяется ПЕРВЫМ: отказ на его уровне не тратит токенов модуля,
// и шумный экземпляр выбирает из потолка модуля не больше своего ведра.

// newInternalAdmissions — ограничители внутреннего слушателя обоих уровней.
func newInternalAdmissions(module, instance grpcsrv.AdmissionLimits, opts ...grpcsrv.AdmissionOption) (listenerAdmission, error) {
	internal, err := grpcsrv.NewAdmission("internal", module, grpcsrv.CertIdentitySubject, opts...)
	if err != nil {
		return listenerAdmission{}, fmt.Errorf("уровень модуля: %w", err)
	}
	perInstance, err := grpcsrv.NewAdmission("internal-instance", instance, instanceSubject, opts...)
	if err != nil {
		return listenerAdmission{}, fmt.Errorf("уровень экземпляра: %w", err)
	}
	return listenerAdmission{internal: internal, internalInstance: perInstance}, nil
}

// instanceAdmissionLimits — величины уровня экземпляра по умолчанию: ПОЛОВИНА
// потолка модуля по каждой оси темпа и одновременности, кратность всплеска та
// же.
//
// Половина — не подобранное число, а свойство: один экземпляр не выбирает
// больше половины потолка модуля, и соседям при любом его шуме остаётся не
// меньше половины. Одновременность не ниже одного — иначе ведро не пропускало
// бы ни одного запроса.
func instanceAdmissionLimits(module grpcsrv.AdmissionLimits) grpcsrv.AdmissionLimits {
	inFlight := module.InFlight / 2
	if inFlight < 1 {
		inFlight = 1
	}
	return grpcsrv.AdmissionLimits{
		ReadPerSec:     module.ReadPerSec / 2,
		MutationPerSec: module.MutationPerSec / 2,
		BurstFactor:    module.BurstFactor,
		InFlight:       inFlight,
	}
}

// instanceSubject — ключ экземпляра вызывающего: личность проверенного
// сертификата и адрес пира без порта (один экземпляр открывает несколько
// соединений). Без проверенной личности — пусто, то есть «не назван».
func instanceSubject(ctx context.Context) string {
	id := grpcsrv.CertIdentitySubject(ctx)
	if id == "" {
		return ""
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return id
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		host = p.Addr.String()
	}
	return id + "@" + host
}

// internalRegistrar — обёртка регистратора внутреннего слушателя обоими
// уровнями. Внутренняя обёртка регистратора исполняется ПЕРВОЙ на пути
// запроса, поэтому уровень экземпляра стоит внутри.
func (l listenerAdmission) internalRegistrar(next grpc.ServiceRegistrar) grpc.ServiceRegistrar {
	return l.internal.Registrar(l.internalInstance.Registrar(next))
}
