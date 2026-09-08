// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package presentedcred — читатель удостоверения, ПРЕДЪЯВЛЕННОГО самим
// вызывающим, на публичном слушателе (задача продукта #2077, приёмка
// KAN-AUTHN-1).
//
// # Зачем он существует
//
// Личность на публичном слушателе производилась ровно двумя способами, и оба
// предполагают НАШУ инфраструктуру рядом: клиентский сертификат проверенного
// пира и личность, переданная разрешённым отправителем. В чужом облаке нет ни
// нашего края, чтобы передать, ни модульного сертификата у человека —
// арендатору нечем назваться. Этот читатель и есть третий способ: арендатор
// приходит обычным клиентом и предъявляет то, что мы сами ему выдали.
//
// # Внешней зависимости у проверки нет ПО ПОСТРОЕНИЮ
//
// Подпись проверяется собственным реестром ключей: служба сама издатель.
// Для установки в чужом облаке это не удобство, а условие исполнимости — иначе
// решение о доступе зависело бы от достижимости чего-то, чего у арендатора нет.
//
// # Отзыв читается НА ПРЕДЪЯВЛЕНИИ
//
// Контроль, действующий на выдаче и не действующий на предъявлении, отзывом не
// является: он лишь не выдаёт нового, а предъявленное продолжает проходить до
// истечения срока. Это состояние НЕ СХОДИТСЯ САМО, и окно отзыва равнялось бы
// сроку токена, а не сроку, который мы выбрали. Здесь окно задаёт срок кеша
// положительного вердикта — величина ОПЕРАТОРА, объявленная им и видимая ему.
//
// Отрицательный вердикт не кешируется: восстановленный доступ не ждёт истечения
// записи.
//
// # Отказ ОДИН
//
// Все отказы аутентификации побайтово одинаковы, включая приложенные к ответу
// подробности. Различимый отказ здесь есть ОРАКУЛ: он сообщает предъявителю,
// какая половина предъявленного неверна. Поэтому производитель отказа в пакете
// ровно один — тринадцать вызовов `status.Error` по месту разошлись бы на первой
// же правке текста, и разошлись бы молча.
//
// Подробность — какая именно проверка не сошлась — уходит ОПЕРАТОРУ, в журнал и
// измерители его установки, и никогда предъявителю.
package presentedcred

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// MetadataKey — ключ метаданных, которым удостоверение предъявляется.
//
// Стандартная форма выбрана не из вкуса: иной формы у арендатора нет — он
// приходит обычным клиентом, и всякая своя означала бы, что пользоваться
// службой можно только нашим клиентом.
const MetadataKey = "authorization"

// bearerPrefix — объявленная схема предъявления. Сверяется без учёта регистра
// (схема регистронезависима по RFC 7235), само значение — точно.
const bearerPrefix = "bearer "

// RefusalMessage — ЕДИНСТВЕННЫЙ текст отказа аутентификации.
//
// Он не называет ни причины, ни поля, ни значения: предъявитель не обязан
// узнать, какая половина предъявленного неверна. Текст — часть контракта, и
// экспортирован затем, чтобы проба утверждала ЕГО, а не свою копию.
const RefusalMessage = "credential is not accepted"

// keySetTTL — срок снимка публикуемого набора ключей.
//
// # Почему снимок вообще есть
//
// Набор — величина ОБЩАЯ на всю установку и дорогая: за ним идёт обращение к
// хранилищу. Спрашивать его на каждом предъявлении значило бы отдать
// неаутентифицированному вызывающему усиление один-к-одному в базу: мусор в
// предъявителе стоил бы запроса ДО того, как выяснится, что подпись негодна.
// Кеш вердикта отзыва от этого не защищает — он стоит ниже по потоку и
// персонален.
//
// # Почему именно столько
//
// Величина выбрана заведомо НИЖЕ объявленного платформой потолка, на который уже
// опирается арифметика отсрочки снятия ключа (`tokenpolicy.KeyRemovalGrace`
// складывается из потолка срока токена, потолка снимка у потребителя и запаса).
// То есть снимок у потребителя предусмотрен построением, а не является
// послаблением; беря меньше потолка, мы остаёмся внутри уже посчитанного.
const keySetTTL = 30 * time.Second

// forcedRefreshInterval — минимальный промежуток между ВЫНУЖДЕННЫМИ обновлениями
// снимка.
//
// У обновления два разных повода, и второй не должен проходить через первый:
// «снимок устарел по времени» и «предъявленный идентификатор ключа в снимке не
// найден». Второй — это ротация подписного ключа, и ждать по нему срока годности
// значило бы отвергать живой токен всё окно. Пустить же его без ограничения
// значило бы сделать неизвестный идентификатор усилителем нагрузки — тем самым,
// от которого снимок и заводится. Отсюда собственный, много меньший интервал.
const forcedRefreshInterval = time.Second

// maxCachedVerdicts — потолок числа закешированных положительных вердиктов.
//
// Кеш ключуется предъявленным материалом, то есть его наполняет ВЫЗЫВАЮЩИЙ.
// Без потолка неограниченный рост был бы способом занять память процесса
// предъявлениями, каждое из которых по отдельности законно.
const maxCachedVerdicts = 4096

// Отказы ПОСТРОЕНИЯ. Каждый отдельный: неполная настройка означает читателя,
// который либо принимает лишнее, либо не принимает ничего, — и узналось бы это
// на первом запросе.
var (
	// ErrIssuerRequired — незаданный издатель означает «любой», то есть токен
	// любого происхождения принимался бы как наш.
	ErrIssuerRequired = errors.New("presentedcred: the issuer we accept as our own is not declared")
	// ErrAudienceRequired — незаданный адресат означает «любой»: токен, годный
	// для другой поверхности, проходил бы здесь.
	ErrAudienceRequired = errors.New("presentedcred: the audience of this listener is not declared")
	// ErrAlgorithmsRequired — пустой перечень означает «принимаем любую
	// подпись», и на этом перечне держится сверка заголовка с ключом.
	ErrAlgorithmsRequired = errors.New("presentedcred: the list of accepted signatures has no elements")
	// ErrAlgorithmUnknown — алгоритм вне закрытого словаря платформы.
	ErrAlgorithmUnknown = errors.New("presentedcred: accepted signature list names an algorithm outside the platform dictionary")
	// ErrKeysRequired — без собственного реестра ключей проверять подпись нечем.
	ErrKeysRequired = errors.New("presentedcred: no key registry is wired")
	// ErrRevocationsRequired — без авторитета отзыва контроль действовал бы
	// только на выдаче.
	ErrRevocationsRequired = errors.New("presentedcred: no revocation authority is wired")
	// ErrCacheTTLRequired — срок кеша И ЕСТЬ окно отзыва. Величина, которую
	// построение подставляет молча, предметом стража быть не может.
	ErrCacheTTLRequired = errors.New("presentedcred: the revocation cache lifetime is not declared")
)

// KeySetSource — источник публикуемого набора.
//
// Тем же набором, что отдаётся потребителям, проверяется и подпись здесь: один
// источник, а не второй, — иначе читатель судил бы по другим ключам, чем
// публикует издатель.
type KeySetSource interface {
	PublishedSet(ctx context.Context) ([]domain.PublishedKey, error)
}

// RevocationReader — хранилище отсечек отзыва.
type RevocationReader = tokenrevocation.Reader

// Config — настройка читателя. Каждое поле ОБЯЗАТЕЛЬНО: незаданное здесь
// означает «не сужаем», а не «взять разумное».
type Config struct {
	// Issuer — издатель, которым установка объявила СЕБЯ.
	Issuer string
	// Audience — адресат ЭТОЙ поверхности. Токен, выданный для другой,
	// здесь не годится: тип и адресат — свойства поверхности предъявления.
	Audience string
	// AllowedAlgorithms — перечень принимаемых подписей, ОБЪЯВЛЕННЫЙ
	// установкой. Решение принимается по нему, а не по тому, что заявлено в
	// самом токене.
	AllowedAlgorithms []string
	// Keys — собственный реестр ключей.
	Keys KeySetSource
	// Revocations — авторитет отзыва.
	Revocations RevocationReader
	// RevocationCacheTTL — срок кеша ПОЛОЖИТЕЛЬНОГО вердикта, он же
	// объявленное окно отзыва.
	RevocationCacheTTL time.Duration
	// Clock — источник времени. Передаётся, а не берётся из окружения: без
	// этого обе половины окна отзыва наблюдаются выжиданием, а не
	// детерминированно.
	Clock func() time.Time
	// Logger — журнал ОПЕРАТОРА: сюда уходит причина отказа, которой нет в
	// ответе предъявителю.
	Logger *slog.Logger
	// TrustDomain — домен доверия установки: по нему опознаётся личность модуля
	// из сертификата пира. Приезжает величиной, а не берётся из сборки: пока он
	// был скомпилирован, установка меняла его только пересборкой, и правка
	// величины профиля давала сертификаты, которых эта сторона не признавала.
	//
	// Необъявленный домен — не отказ построения: читатель предъявленного
	// удостоверения работает и там, где личности модуля нет вовсе (внешний
	// клиент). Он лишь не опознаёт НИКОГО, и это фейл-клоуз. Отказ старта —
	// предмет стражи посадки, а не этого конструктора.
	TrustDomain grpcsrv.TrustDomain
}

// Stats — величины по каждому исходу.
//
// Отдаются СНИМКОМ, а не через порт наблюдателя: измерители читают их сами, и
// все три ряда печатаются всегда, включая нулевые. Ряд, появляющийся только
// вместе с первым событием, делает ноль невыразимым — отсутствующий ряд и
// нулевой выглядят одинаково у того, кто смотрит на график.
type Stats struct {
	Accepted    uint64
	Refused     uint64
	Unavailable uint64
}

// Reader — читатель предъявленного удостоверения.
type Reader struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time

	accepted    atomic.Uint64
	refused     atomic.Uint64
	unavailable atomic.Uint64

	mu    sync.Mutex
	cache map[string]time.Time

	keyMu       sync.Mutex
	keys        map[string]domain.PublishedKey
	keysTakenAt time.Time
	lastForced  time.Time
}

// New строит читателя. Неполная настройка — ОТКАЗ ПОСТРОЕНИЯ, а не умолчание.
//
// Асимметрия цены, из которой это выведено: слишком строгая настройка даёт
// отказ В СТАРТЕ — видимый сразу, с именем настройки в тексте; слишком слабая
// даёт принимаемый чужой токен, не видимый никогда.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, ErrIssuerRequired
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, ErrAudienceRequired
	}
	if len(cfg.AllowedAlgorithms) == 0 {
		return nil, ErrAlgorithmsRequired
	}
	for _, alg := range cfg.AllowedAlgorithms {
		if !tokenpolicy.AlgorithmAllowed(alg) {
			return nil, fmt.Errorf("%w: %q", ErrAlgorithmUnknown, alg)
		}
	}
	if cfg.Keys == nil {
		return nil, ErrKeysRequired
	}
	if cfg.Revocations == nil {
		return nil, ErrRevocationsRequired
	}
	if cfg.RevocationCacheTTL <= 0 {
		return nil, ErrCacheTTLRequired
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Reader{cfg: cfg, logger: logger, now: now, cache: map[string]time.Time{}}, nil
}

// Stats возвращает величины по исходам.
func (r *Reader) Stats() Stats {
	return Stats{
		Accepted:    r.accepted.Load(),
		Refused:     r.refused.Load(),
		Unavailable: r.unavailable.Load(),
	}
}

// UnaryOver ставит читателя НАД парой извлечения личности, а не после неё.
//
// # Почему НАД, а не после — это не стиль, а единственная работающая форма
//
// Пара извлечения на двух ветках из трёх снимает носитель личности явным
// снятием, и снятие имеет ПРИОРИТЕТ над любым последующим назначением: так
// устроен носитель платформы, и устроен намеренно — подделанная личность от
// непроверенного пира не должна просачиваться никаким «а потом мы её вернём».
// Читатель, поставленный ПОСЛЕ пары, назначил бы вызывающего, и назначение
// молча не доехало бы до обработчика: отказа нет, личности нет, а дальше
// отсечка анонима отвергает мутацию — по причине, которой в запросе не было.
//
// Поэтому читатель прогоняет пару САМ и решает по её вердикту: полосы взаимно
// исключают друг друга (ось 8 решения), и решение о том, КТО звонит, принимается
// в одном месте, а не складывается из двух назначений.
//
// # Прежний путь при этом не тронут
//
// Запроса БЕЗ предъявленного удостоверения читатель не касается вовсе: пара
// исполняется как исполнялась, и её ветки — доверенный отправитель, непроверенный
// пир, проверенный без переданной личности — работают ровно как прежде.
func (r *Reader) UnaryOver(pair []grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	inner := chainUnary(pair...)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		raw, presented, ambiguous := bearerFrom(ctx)
		if ambiguous {
			return nil, r.refuse("more than one credential presented in one request")
		}
		if !presented {
			return inner(ctx, req, info, handler)
		}
		var pairErr error
		next, err := r.decide(ctx, raw, func(c context.Context) (operations.Principal, bool) {
			var (
				p  operations.Principal
				ok bool
			)
			// Отказ самой пары НЕ ГЛОТАЕТСЯ. Сегодня она его не производит, но
			// она — общий конструктор на семь сервисов: звено, отвергающее
			// запрос, добавят туда, а не сюда, и проглоченный отказ означал бы
			// «пара сказала нет, а мы пошли дальше».
			_, pairErr = inner(c, req, info, func(inner context.Context, _ any) (any, error) {
				p, ok = grpcsrv.TrustedPrincipalFromContext(inner)
				return nil, nil
			})
			return p, ok
		})
		if pairErr != nil {
			return nil, pairErr
		}
		if err != nil {
			return nil, err
		}
		return handler(next, req)
	}
}

// StreamOver — то же на второй полосе.
//
// Стримовых RPC у службы сегодня ноль, и полоса провязывается не ради них:
// полоса без читателя при полосе с читателем — различие, которого никто не
// принимал, и обнаружилось бы оно первым же стримовым RPC.
func (r *Reader) StreamOver(pair []grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	inner := chainStream(pair...)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		raw, presented, ambiguous := bearerFrom(ss.Context())
		if ambiguous {
			return r.refuse("more than one credential presented in one request")
		}
		if !presented {
			return inner(srv, ss, info, handler)
		}
		var pairErr error
		next, err := r.decide(ss.Context(), raw, func(c context.Context) (operations.Principal, bool) {
			var (
				p  operations.Principal
				ok bool
			)
			pairErr = inner(srv, &wrappedStream{ServerStream: ss, ctx: c}, info,
				func(_ any, s grpc.ServerStream) error {
					p, ok = grpcsrv.TrustedPrincipalFromContext(s.Context())
					return nil
				})
			return p, ok
		})
		if pairErr != nil {
			return pairErr
		}
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: next})
	}
}

// decide — единственная точка решения обеих полос.
//
// forwarded возвращает вердикт пары извлечения: КТО передан и вправе ли
// отправитель говорить за него.
func (r *Reader) decide(
	ctx context.Context,
	raw string,
	forwarded func(context.Context) (operations.Principal, bool),
) (context.Context, error) {
	// ЗДЕСЬ СТОЯЛ ОТКАЗ «обе формы личности разом», и он СНЯТ ВМЕСТЕ С ПРЕДМЕТОМ.
	//
	// Прежнее решение требовало отвергать запрос, несущий и предъявленное
	// удостоверение, и переданную личность: неоднозначность о том, кто звонит,
	// догадкой не разрешается. Принцип верен; проверкой он был неисполним.
	// Сочетание производил НАШ ЖЕ край: установив личность, он добавлял её к
	// входящим метаданным, а удостоверение в них уцелевало, — поэтому ветка
	// отвергала бы КАЖДЫЙ проксированный краем запрос.
	//
	// Приёмка KAN-AUTHN-1 редакцией 2 заменила проверку ПОСТРОЕНИЕМ: край
	// снимает арендаторское удостоверение перед пересылкой за себя, установив
	// личность сам (gateway/internal/principalmeta/credential_strip.go). За
	// краем действует переданная личность, напрямую — предъявленная, и
	// сочетания не бывает. Проверку можно обойти, построение — нет.
	//
	// ПАРА ИЗВЛЕЧЕНИЯ ПРОГОНЯЕТСЯ ПО-ПРЕЖНЕМУ, и это не остаток снятой ветки.
	// Её вердикт («кто передан и вправе ли отправитель за него говорить») на
	// этой полосе не читается, но САМА она обязана исполниться: она общий
	// конструктор на семь служб, отказ в неё добавят там, а не здесь, и
	// пропущенный прогон означал бы «пара сказала нет, а мы пошли дальше».
	// Отказ пары вызывающий читает из pairErr.
	_, _ = forwarded(ctx)

	principal, acr, err := r.verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	r.accepted.Add(1)

	// Личность модуля из сертификата пира решается НЕ предъявленным, и на этой
	// полосе она сохраняется: следующие звенья не должны увидеть запрос без
	// модульной личности там, где пир её предъявил.
	//
	// Извлекается ОБЩИМ извлекателем платформы — тем же, что стоит первым в
	// паре обеих полос; своей копии разбора сертификата читатель не заводит.
	// Обе формы извлекателя (unary и stream) кладут в контекст одно и то же,
	// поэтому здесь годится одна: предмет — контекст, а не полоса.
	base := ctx
	_, _ = grpcsrv.UnaryCertIdentityExtract(r.cfg.TrustDomain)(ctx, nil, nil,
		func(c context.Context, _ any) (any, error) {
			base = c
			return nil, nil
		})

	// Происхождение помечается ЗДЕСЬ: звену, решающему о ПРАВЕ ЗВАТЬ, нужно
	// знать не только КТО, но и ЧЕМ он назван, а по носителю личности это не
	// восстанавливается.
	// НОСИТЕЛЬ ДОВЕРЕННОЙ ЛИЧНОСТИ на этой полосе ПУСТ, и это решение, а не
	// упущение. Контекст доставки собирается из ИСХОДНОГО, поэтому пара
	// извлечения обёрткой обработчика не является и своего носителя не оставляет:
	// `grpcsrv.TrustedPrincipalFromContext` и `TrustedACRFromContext` ниже по
	// публичной цепочке отвечают «не доверено».
	//
	// Сегодня читателей у них на публичной цепочке нет (порог доверия и пол
	// наблюдателя провязаны на внутреннем слушателе). Но следующее звено,
	// вставшее сюда и прочитавшее носитель, получит «личность не доверена»: для
	// ЗАПРЕЩАЮЩЕГО звена это fail-closed и терпимо, для ОСВОБОЖДАЮЩЕГО — тихо
	// изменит исход. Поэтому всё, что этой полосе нужно отдать дальше, кладётся
	// в СВОЙ носитель явно, а не добывается из чужого.
	//
	// Уровень доверия из ПРОВЕРЕННОГО удостоверения. Он нужен звену, решающему
	// о праве звать: каталог объявляет порог доверия по каждому глаголу, и на
	// этой полосе край — единственный, кто порог производил, — на пути не стоит.
	// Значение сюда попадает только после полной проверки, поэтому оно не
	// утверждение предъявителя о себе.
	base = callerorigin.WithAssurance(base, acr)
	return callerorigin.With(operations.WithPrincipal(base, principal), callerorigin.PresentedCredential), nil
}

// chainUnary / chainStream складывают перехватчики слева направо вокруг
// обработчика, повторяя семантику grpc.Chain*Interceptor.
func chainUnary(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		chained := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			ic, next := interceptors[i], chained
			chained = func(c context.Context, rq any) (any, error) { return ic(c, rq, info, next) }
		}
		return chained(ctx, req)
	}
}

func chainStream(interceptors ...grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		chained := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			ic, next := interceptors[i], chained
			chained = func(s any, stream grpc.ServerStream) error { return ic(s, stream, info, next) }
		}
		return chained(srv, ss)
	}
}

// verify исполняет все одиннадцать проверок единого перечня.
func (r *Reader) verify(ctx context.Context, raw string) (operations.Principal, string, error) {
	byKID, err := r.keySnapshot(ctx, false)
	if err != nil {
		// Нечитаемый реестр НЕ ЕСТЬ «ключ не найден»: это третий исход, и
		// смешать его с отказом значило бы сделать сбой хранилища неотличимым
		// от негодного токена — для оператора, а не для предъявителя.
		return operations.Principal{}, "", r.unavail("key registry", err)
	}

	claims := jwt.MapClaims{}
	var (
		headerType          string
		ownKeyBroken        error
		registryUnavailable error
	)
	parser := jwt.NewParser(
		// Перечень принимаемых подписей — ОБЪЯВЛЕННЫЙ УСТАНОВКОЙ, а не словарь
		// платформы: решение принимается по нему, а не по тому, что заявлено в
		// самом токене. «Без подписи» отвергается разбором, а не отдельной
		// веткой, которую можно забыть.
		jwt.WithValidMethods(r.cfg.AllowedAlgorithms),
		// Обязательность срока включается ЯВНО: разбор, не встретив срока, не
		// возразит сам ни в одной известной библиотеке.
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(r.cfg.Issuer),
		jwt.WithAudience(r.cfg.Audience),
		// Допуск на расхождение часов — ТОТ ЖЕ, что у остальных проверяющих
		// продукта. Второго значения этой величины не заводится.
		jwt.WithLeeway(tokenpolicy.ClockSkew),
		jwt.WithTimeFunc(r.now),
	)
	tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		// Форма идентификатора ограничивается ДО поиска по реестру, до повода
		// обновить снимок и до журнала: негодная форма не должна доезжать ни
		// до одного из трёх.
		if !domain.ValidKeyIDForm(kid) {
			return nil, errors.New("key id has illegal form")
		}
		pub, ok := byKID[kid]
		if !ok {
			// ВТОРОЙ повод обновить снимок: подписант назвал ключ, которого в
			// снимке нет. Так выглядит ротация, и ждать по ней срока годности
			// значило бы отвергать живой токен всё окно.
			fresh, ferr := r.keySnapshot(ctx, true)
			if ferr != nil {
				registryUnavailable = ferr
				return nil, ferr
			}
			byKID = fresh
			if pub, ok = byKID[kid]; !ok {
				return nil, errors.New("key id does not resolve in our own registry")
			}
		}
		// Способ проверки подписи выбирает КЛЮЧ, а не заголовок: значение из
		// заголовка служит только сверке и никогда — выбором.
		if t.Method.Alg() != string(pub.Algorithm) {
			return nil, errors.New("header algorithm is not the one bound to the key")
		}
		// Параметр, помеченный отправителем обязательным к пониманию, мы обязаны
		// либо исполнить, либо отвергнуть токен ЦЕЛИКОМ. Обратная сторона того
		// же требования — НЕ помеченное неизвестное игнорируется; на этом
		// держится совместимость, поэтому прочие неизвестные поля разбор молча
		// пропускает.
		if ok, name := tokenpolicy.CriticalHeadersUnderstood(critHeaders(t.Header)); !ok {
			return nil, fmt.Errorf("critical header %q is not understood", name)
		}
		headerType, _ = t.Header["typ"].(string)
		key, perr := parsePublicKey(pub.PublicKeyPEM)
		if perr != nil {
			// Ключ ИЗ НАШЕГО реестра не разобрался — это НАША поломка, а не
			// негодный вход. Отметка ставится здесь, потому что выше по стеку
			// отказ разбора неотличим от отказа подписи, и испорченный ключ
			// отвергал бы всё, наращивая ряд «отвергнуто»: оператор пошёл бы
			// разбираться с клиентами.
			ownKeyBroken = perr
		}
		return key, perr
	})
	if err != nil {
		if ownKeyBroken != nil {
			return operations.Principal{}, "", r.unavail("key registry", ownKeyBroken)
		}
		if registryUnavailable != nil {
			return operations.Principal{}, "", r.unavail("key registry", registryUnavailable)
		}
		return operations.Principal{}, "", r.refuse("token did not verify: " + err.Error())
	}
	if !tok.Valid {
		return operations.Principal{}, "", r.refuse("token did not verify")
	}

	// Тип объявляет, для какой поверхности токен выпущен, и сверяет его та
	// поверхность. ОТСУТСТВИЕ типа и НЕСОВПАДЕНИЕ дают один исход: «тип не
	// назван» не означает «любой».
	if headerType != tokenpolicy.TokenTypeAccess {
		return operations.Principal{}, "", r.refuse("token type is not the one this surface accepts")
	}

	revoked, err := r.revoked(ctx, raw, claims)
	if err != nil {
		return operations.Principal{}, "", r.unavail("revocation authority", err)
	}
	if revoked {
		return operations.Principal{}, "", r.refuse("credential is revoked")
	}

	acr, _ := claims["acr"].(string)
	principal, ok := principalFrom(claims)
	if !ok {
		// Токен проверился целиком и не назвал, за кого говорит. Принять его
		// значило бы отдать вызов личности, которой никто не называл, —
		// «назвать некого» и «назван системный» разные состояния.
		return operations.Principal{}, "", r.refuse("verified token names no principal")
	}
	return principal, acr, nil
}

// keySnapshot отдаёт снимок публикуемого набора, обновляя его по одному из двух
// поводов: истёк срок снимка либо ВЫНУЖДЕННО — предъявленный идентификатор ключа
// в снимке не нашёлся.
//
// Вынужденное обновление ограничено собственным интервалом: без него неизвестный
// идентификатор стал бы усилителем нагрузки на хранилище, то есть ровно тем, от
// чего снимок заводится.
func (r *Reader) keySnapshot(ctx context.Context, forced bool) (map[string]domain.PublishedKey, error) {
	now := r.now()

	r.keyMu.Lock()
	fresh := r.keys != nil && now.Sub(r.keysTakenAt) < keySetTTL
	if fresh && !forced {
		snap := r.keys
		r.keyMu.Unlock()
		return snap, nil
	}
	if forced && fresh && now.Sub(r.lastForced) < forcedRefreshInterval {
		// Вынужденное обновление уже было только что: отдаём тот же снимок.
		// Отказ по «ключ не резолвится» наступит выше, и это верно — иначе
		// поток неизвестных идентификаторов стал бы потоком запросов в базу.
		snap := r.keys
		r.keyMu.Unlock()
		return snap, nil
	}
	if forced {
		r.lastForced = now
	}
	r.keyMu.Unlock()

	// Обращение к хранилищу — ВНЕ замка: держать его на время сетевого ожидания
	// значило бы сериализовать за ним весь предъявленный трафик.
	keys, err := r.cfg.Keys.PublishedSet(ctx)
	if err != nil {
		return nil, err
	}
	byKID := make(map[string]domain.PublishedKey, len(keys))
	for _, k := range keys {
		byKID[string(k.KID)] = k
	}

	r.keyMu.Lock()
	r.keys, r.keysTakenAt = byKID, now
	r.keyMu.Unlock()
	return byKID, nil
}

// revoked отвечает, отозван ли токен, с коротким кешем ПОЛОЖИТЕЛЬНОГО вердикта.
//
// Кешируется только «не отозван». Отрицательный вердикт не кешируется намеренно:
// восстановленный доступ не должен ждать истечения записи.
func (r *Reader) revoked(ctx context.Context, raw string, claims jwt.MapClaims) (bool, error) {
	key := verdictKey(raw)
	now := r.now()

	r.mu.Lock()
	until, cached := r.cache[key]
	if cached && now.Before(until) {
		r.mu.Unlock()
		return false, nil
	}
	if cached {
		delete(r.cache, key)
	}
	r.mu.Unlock()

	revoked, err := tokenrevocation.Revoked(ctx, r.cfg.Revocations, claims)
	if err != nil {
		return false, err
	}
	if revoked {
		return true, nil
	}

	r.mu.Lock()
	if len(r.cache) >= maxCachedVerdicts {
		// Обход карты стоит O(n) под общим замком, поэтому платится ТОЛЬКО у
		// потолка, а не на каждом промахе: промах — это каждое первое
		// предъявление токена, и обход на нём сериализовал бы весь
		// предъявленный трафик за одним замком.
		r.pruneLocked(now)
	}
	r.cache[key] = now.Add(r.cfg.RevocationCacheTTL)
	r.mu.Unlock()
	return false, nil
}

// pruneLocked снимает истёкшие записи и, если потолок всё равно достигнут,
// очищает кеш целиком.
//
// Полная очистка при переполнении выбрана намеренно: она стоит одного
// обращения к авторитету на каждый живой токен и не заводит второго правила
// вытеснения, чья редкая ветка никогда не была бы исполнена в пробе.
func (r *Reader) pruneLocked(now time.Time) {
	for k, until := range r.cache {
		if !now.Before(until) {
			delete(r.cache, k)
		}
	}
	if len(r.cache) >= maxCachedVerdicts {
		clear(r.cache)
	}
}

// refuse — ЕДИНСТВЕННЫЙ производитель отказа аутентификации.
//
// Причина уходит ОПЕРАТОРУ: в журнал и в измерители его установки. Наружу —
// суждение, и только оно.
func (r *Reader) refuse(reason string) error {
	r.refused.Add(1)
	r.logger.Warn("presented credential refused",
		slog.String("reason", reason),
		slog.Uint64("refused_total", r.refused.Load()))
	return refusal()
}

// unavail — ответить не смогли. ОТДЕЛЬНЫЙ исход: он чинится в другом месте и
// другим человеком, чем негодный токен.
//
// Наружу он неотличим от отказа намеренно: различимость сообщила бы
// предъявителю о состоянии нашей установки.
func (r *Reader) unavail(what string, err error) error {
	r.unavailable.Add(1)
	r.logger.Error("presented credential could not be judged (fail-closed)",
		slog.String("dependency", what),
		slog.Uint64("unavailable_total", r.unavailable.Load()),
		slog.String("err", err.Error()))
	return refusal()
}

// refusal строит ответ. Ни одной приложенной подробности: два отказа, равные по
// тексту, различимы по приложенному, а на публичной цепочке стоит звено,
// приписывающее машиночитаемую причину отказам ПО ПРАВАМ. Отказ аутентификации
// оформлен своим кодом и потому этого приложения не получает.
func refusal() error {
	return status.Error(codes.Unauthenticated, RefusalMessage)
}

// DeclaredChecks — состав проверок ЭТОГО проверяющего.
//
// Объявление существует затем, чтобы его можно было СВЕРИТЬ с единым перечнем,
// а не читать реализацию глазами. Запись, которой проверяющий не исполняет,
// отсюда нельзя: тогда объявление станет вторым местом об одном предмете, и
// разойдётся оно молча.
func (r *Reader) DeclaredChecks() []tokenpolicy.Check {
	return []tokenpolicy.Check{
		tokenpolicy.CheckAlgorithmAllowed,
		tokenpolicy.CheckKeyID,
		tokenpolicy.CheckSignature,
		tokenpolicy.CheckKeyBoundAlgorithm,
		tokenpolicy.CheckIssuer,
		tokenpolicy.CheckAudience,
		tokenpolicy.CheckTokenType,
		tokenpolicy.CheckExpiry,
		tokenpolicy.CheckNotBefore,
		tokenpolicy.CheckCriticalHeaders,
		tokenpolicy.CheckRevocation,
	}
}

// DeclaredDeviations — обязательные проверки, которых читатель НЕ исполняет.
//
// Перечень ПУСТ, и пуст осознанно: адресат и тип объявлены отступлением у
// авторитета отзыва, потому что он судит о состоянии токена У ИЗДАТЕЛЯ. Здесь
// поверхность предъявления и есть та, чьими свойствами адресат и тип являются, —
// отступления быть не может.
func (r *Reader) DeclaredDeviations() []tokenpolicy.Deviation { return nil }

// bearerFrom достаёт предъявленное удостоверение из метаданных.
//
// Схема сверяется без учёта регистра (RFC 7235), само значение — точно.
// Пустое значение после схемы предъявлением НЕ является: иначе «прислали
// пустую строку» читалось бы как «не предъявляли», и отказ ушёл бы не тому
// звену.
func bearerFrom(ctx context.Context) (raw string, presented, ambiguous bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false, false
	}
	for _, v := range md.Get(MetadataKey) {
		if len(v) < len(bearerPrefix) || !strings.EqualFold(v[:len(bearerPrefix)], bearerPrefix) {
			continue
		}
		val := strings.TrimSpace(v[len(bearerPrefix):])
		if val == "" {
			continue
		}
		if presented {
			// ДВА предъявленных удостоверения — та же неоднозначность о том, кто
			// звонит, что и две формы личности разом. «Побеждает первый» здесь
			// было бы догадкой, и выбирал бы её порядок метаданных.
			return "", false, true
		}
		raw, presented = val, true
	}
	return raw, presented, false
}

// Presented отвечает, приложил ли вызывающий удостоверение к ЭТОМУ запросу.
//
// # Зачем это спрашивают снаружи
//
// Звено, решающее ЧТО ОТВЕТИТЬ не назвавшемуся, обязано отличать «не предъявлял
// вовсе» от «предъявил, и не сошлось»: первому отвечают «назовись», второму —
// единственным побайтово равным отказом. Различие есть свойство ЗАПРОСА, и
// узнаётся оно ровно здесь.
//
// # Почему предикат, а не вторая копия разбора у вызывающего
//
// Ключ метаданных и объявленная схема предъявления живут в этом пакете. Второй
// разбор той же строки разошёлся бы с первым молча — и разошёлся бы именно там,
// где расхождение не видно: на входе, который оба считают годным.
//
// Неоднозначность (два предъявления разом) считается предъявлением: вызывающий
// приложил удостоверение, а то, что их два, — уже вопрос годности, и отвечает на
// него отказ читателя, а не этот предикат.
func Presented(ctx context.Context) bool {
	_, presented, ambiguous := bearerFrom(ctx)
	return presented || ambiguous
}

// principalFrom собирает личность из состава утверждений.
//
// Вид и идентификатор обязательны; отображаемое имя косметическое и при
// отсутствии замещается идентификатором.
func principalFrom(claims jwt.MapClaims) (operations.Principal, bool) {
	pType, _ := claims[domain.ClaimPrincipalType].(string)
	pID, _ := claims[domain.ClaimPrincipalID].(string)
	if pType == "" || pID == "" {
		return operations.Principal{}, false
	}
	display, _ := claims[domain.ClaimPrincipalDisplay].(string)
	if display == "" {
		display = pID
	}
	return operations.Principal{Type: pType, ID: pID, DisplayName: display}, true
}

// verdictKey — ключ кеша вердикта. Хеш, а не сам материал: закешированное
// попадает в дампы памяти и в отладочную печать, и предъявленное удостоверение
// там быть не должно.
func verdictKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// critHeaders приводит `crit` к перечню имён.
//
// Разбор отдаёт заголовок как произвольный JSON, поэтому годятся ровно два вида:
// список строк и его отсутствие. Всё прочее — не перечень имён, и принимать по
// нему решение нельзя; такой вход даёт одно ЗАВЕДОМО неизвестное имя, то есть
// отказ. Молчаливый пропуск здесь означал бы «параметр помечен обязательным, а
// мы не разобрали его форму и приняли токен».
func critHeaders(h map[string]any) []string {
	raw, ok := h["crit"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return []string{"<crit is not a list>"}
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		name, ok := v.(string)
		if !ok {
			return []string{"<crit entry is not a string>"}
		}
		out = append(out, name)
	}
	return out
}

func parsePublicKey(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("public half is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("public half does not parse")
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

// wrappedStream подменяет контекст стрима на тот, в котором назван вызывающий.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedStream) Context() context.Context { return s.ctx }
