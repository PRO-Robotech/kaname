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
// платформы, и счётчик печатается так же. Ключ и классификатор публичного
// слушателя у iam СВОИ, и это уже решение (kaname#991): служба публикуется
// клиентам сама, анонимный вызов ключуется адресом источника, а Check
// относится к чтениям (publicAdmissionSubject, publicCallClass ниже).
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
	"net/netip"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/restfront"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
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

// anonymousSubjectPrefix — приставка ключа анонимного вызывающего.
//
// Знак `<` в типе личности не встречается, поэтому ключ анонимного адреса не
// совпадёт ни с одним ключом вошедшего (`<тип>:<id>`) — бюджет вошедшего и
// бюджет адреса не смешиваются ни при каком входе. Форма — та же, что у ключа
// безымянного запроса фундамента ([grpcsrv.UnattributedSubject]).
const anonymousSubjectPrefix = "<anonymous>@"

// publicAdmissionSubject — ключ ПУБЛИЧНОГО ограничителя (kaname#991).
//
// # Вошедший — личностью, как прежде
//
// Вызывающий с личностью ключуется ею ([grpcsrv.PrincipalSubject]): предел
// объявлен на арендатора, и соединений у него сколько угодно.
//
// # Аноним — адресом, а не общим ведром
//
// У анонима личности нет, и фундамент сводит всех безымянных в ОДНО ведро:
// поток одного источника расходовал бы предел всех анонимных клиентов разом
// (в том числе самопроверки, которые публичный слушатель анониму разрешает).
// Поэтому аноним ключуется адресом источника — без порта: каждое
// переподключение иначе покупало бы свежее ведро.
//
// Адрес источника — адрес пира соединения, кроме одного случая: пир —
// СОБСТВЕННЫЙ REST-фронт, узнанный по проверенному листу (`frontHop`, тот же,
// что у политики вызывающего, ownfronthop.go). Тогда все HTTP-клиенты пришли бы
// с одного адреса — самого фронта, — и источником служит адрес его клиента,
// который фронт пишет своим ключом метаданных ([restfront.MetadataClientAddr]).
// От любого другого пира этот ключ не читается: прислать его может кто угодно.
// Фронт без годного адреса нового ключа не получает — он делит ключ своего пира.
//
// Адрес за балансировщиком сюда приходит тем же путём — адресом соединения,
// который слушатель берёт из заголовка объявленного балансировщика (kaname#989);
// своего разбора заголовков здесь нет.
//
// # Чего ключ не делает
//
// Вне боевой посадки у фронта нет листа (`frontHop` пуст), и все его анонимные
// клиенты делят ключ его адреса — тот же исход, что был для всех до правки.
// Без адреса пира (в процессе такого вызова нет) ключ пуст, и фундамент
// относит вызов к общему безымянному ведру.
func publicAdmissionSubject(frontHop string) grpcsrv.SubjectFunc {
	return func(ctx context.Context) string {
		if s := grpcsrv.PrincipalSubject(ctx); s != "" {
			return s
		}
		if addr := anonymousSourceAddr(ctx, frontHop); addr != "" {
			return anonymousSubjectPrefix + addr
		}
		return ""
	}
}

// anonymousSourceAddr — адрес источника анонимного вызова, приведённый к одной
// записи; пусто — источника не установить.
func anonymousSourceAddr(ctx context.Context, frontHop string) string {
	if frontHop != "" {
		if id, verified := grpcsrv.CertIdentityFromContext(ctx); verified && id == frontHop {
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				if addr, ok := oneClientAddr(md.Get(restfront.MetadataClientAddr)); ok {
					return addr
				}
			}
		}
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host := p.Addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

// oneClientAddr — ровно одно значение, и оно — адрес IPv4 или IPv6 без зоны.
// Две записи одного адреса дают один ключ.
func oneClientAddr(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(values[0]))
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.Unmap().String(), true
}

// publicCallClass — класс вызова на публичном слушателе (kaname#991).
//
// Конвенция продукта распознаёт чтение по имени (`Get`/`List`), и Check под неё
// не подпадает: вопрос о доступе — чтение, мутаций у него нет, а по конвенции он
// платил впятеро более узким бюджетом мутаций. Сужение — ровно один метод,
// названный константой порождённого кода, а не правилом по имени: правило
// «всё, что начинается на Check» купило бы бюджет чтения следующему методу
// молча. BatchCheck остаётся в бюджете мутаций намеренно: один его вызов —
// до ста вопросов к хранилищу отношений подряд.
func publicCallClass(fullMethod string) grpcsrv.CallClass {
	if fullMethod == iamv1.AuthorizeService_Check_FullMethodName {
		return grpcsrv.ClassRead
	}
	return grpcsrv.ClassifyByKachoConvention(fullMethod)
}

// publicAdmissionOptions — опции публичного ограничителя: классификатор вызова.
func publicAdmissionOptions() []grpcsrv.AdmissionOption {
	return []grpcsrv.AdmissionOption{grpcsrv.WithCallClassifier(publicCallClass)}
}
