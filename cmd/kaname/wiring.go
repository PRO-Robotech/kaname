// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// wiring.go — сборка композиции набора служб kaname.
// Содержит структуру `services` (единую точку композиции), buildServices
// (провязку обработчиков ресурсов), buildAuthZServices (AuthorizeService)
// и небольшие типы адаптеров, необходимые этим функциям.
package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	bootstraptoken "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/bootstrap_token"
	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	clusterpublicapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/clusterpublic"
	grantdelegationapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	identityquotaapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/identityquota"
	interactiveclientapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	internaloperationsapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_operations"
	membershipapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	moduleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/module"
	permissioncatalogapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/permission_catalog"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	sakeysapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/sa_keys"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	sessionrevapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	usertokensapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user_tokens"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// services — собранный набор бизнес-сервисов (один composition-point вместо
// россыпи локальных переменных в runServe). Заполняется buildServices,
// используется register{Public,Internal}Services.
type services struct {
	// accessKeyHandler — AccessKeyService (Ф7, kacho#1273): шесть глаголов
	// ключа доступа на публичном слушателе. Ставится корнем ПОСЛЕ сборки,
	// исполнителя несёт полоса входа.
	accessKeyHandler *access_keys.Handler
	// humanSessionHandler — InternalHumanSessionService.Resolve (Ф3). Ставится
	// корнем ПОСЛЕ сборки: полоса входа строится отдельно, на каждом старте.
	humanSessionHandler *humansession.Handler
	accountHandler      *accountapp.Handler
	projectHandler      *projectapp.Handler
	userHandler         *userapp.Handler
	// Общий UC обеих дверей приглашения; корень подключает один decision runner.
	userInvite            *userapp.InviteUserUseCase
	internalUserHandler   *userapp.InternalHandler
	serviceAccountHandler *serviceaccountapp.Handler
	groupHandler          *groupapp.Handler
	// membershipHandler — MembershipService: чтение принадлежности человека
	// аккаунту. Регистрируется ТОЛЬКО на публичном слушателе — см. довод у
	// registerPublicServices.
	membershipHandler    *membershipapp.Handler
	roleHandler          *roleapp.Handler
	accessBindingHandler *accessbindingapp.Handler
	// grantDelegationHandler — GrantDelegationService (kaname#986): только
	// публичный (арендаторский) слушатель.
	grantDelegationHandler *grantdelegationapp.Handler
	// internalIAMHandler — InternalIAMService (LookupSubject для
	// перехватчика аутентификации api-gateway; Check делегирует AuthorizeService).
	internalIAMHandler *internaliamapp.Handler
	// Тот же UC регистрации, который уже передан обработчику и модулю.
	resourceRegistrar *internaliamapp.RegisterResourceUseCase
	// Единственный recorder запроса: новые object engines получают тот же instance.
	bindingSizeRecorder reconcileapp.SizeRecorder

	// Обработчики ядра авторизации.
	authorizeHandler *authorizeapp.Handler

	// permissionCatalogHandler — PermissionCatalogService.ListPermissionCatalog
	// (модель правил RBAC G): ПУБЛИЧНОЕ синхронное чтение определяемой сервером
	// таксономии назначаемых правил ролей. Метаданные платформы (без чувствительных
	// инфраструктурных сведений — G-D3); доступны аутентифицированным на публичном слушателе.
	permissionCatalogHandler *permissioncatalogapp.Handler

	// Обработчик SAKey — публичный.
	saKeysHandler *sakeysapp.Handler

	// Обработчик UserToken — публичный (персональные access-токены пользователя).
	userTokensHandler *usertokensapp.Handler

	// internalClusterHandler — InternalClusterService: управление RBAC
	// администратором кластера. Только внутренний (запрет #6), на порту 9091.
	internalClusterHandler *clusterapp.Handler

	// publicClusterHandler — ClusterService: ПУБЛИЧНЫЙ двойник
	// InternalClusterService (приёмка ADM-CA, Р1/Р3/Р8). Строится поверх
	// внутреннего обработчика, то есть ТЕХ ЖЕ четырёх экземпляров сценариев — один
	// путь записи в таблицу выдач. Регистрируется только на публичном слушателе.
	publicClusterHandler *clusterpublicapp.Handler

	// interactiveClientHandler — InternalInteractiveClientService: жизненный цикл
	// клиента OAuth2, через которого входит ЧЕЛОВЕК (IAM-INT-1). Только внутренний.
	interactiveClientHandler *interactiveclientapp.Handler

	// moduleHandler — InternalModuleService: четыре глагола над строками
	// каталога прав ОДНОГО модуля (план, применение, два чтения). Internal-only
	// (запрет #6), регистрируется на :9091 и НИКОГДА на внешнем слушателе.
	//
	// Гейт права стоит в use-case первым стейтментом и является ЕДИНСТВЕННОЙ
	// авторизацией этой поверхности: ступень подтверждения личности к ней
	// сегодня не применяется — решение записано в приёмке, а не умолчание.
	moduleHandler *moduleapp.Handler

	// bindingReconciler — ТОТ ЖЕ экземпляр материализации привязки, вынесенный
	// наружу для полосы своего входа: регистрация человека материализует его
	// собственническую выдачу (`buildLoginLane`).
	//
	// Полем, а не вторым построением. Шапка построения ниже обещает «создаётся один раз
	// здесь, чтобы все потребители вели тот же экземпляр», и до задачи #116 это было
	// неправдой: хук внешнего поставщика (снят, kaname#363) собирал свой
	// экземпляр БЕЗ приёмника размера, поэтому гистограмма не видела живой
	// полосы регистрации человека — и выглядела при этом полной. Гистограмма, не
	// видящая полосы, неотличима от гистограммы полосы, по которой нет трафика.
	bindingReconciler *reconcileapp.Reconciler

	// subscriptionDoor — ТА ЖЕ дверь решения, что у списков, вынесенная наружу
	// для сборки сервера потока изменений.
	//
	// Полем, а не вторым построением: сужатель подписки обязан спрашивать ровно
	// то, чем гейтится чтение, и второе значение здесь однажды уже дало два
	// действующих источника ответа на один вопрос об одном объекте.
	subscriptionDoor subscriptionjournal.Door

	// identityQuotaHandler — чтение квот, носителем которых является личность
	// (число аккаунтов). ТОЛЬКО чтение: величину назначает администратор облака.
	identityQuotaHandler *identityquotaapp.Handler

	// sessionRevocationsHandler — InternalSessionRevocationsService:
	// отзыв токенов при выходе и горячий путь api-gateway
	// IsRevoked. Только внутренний (запрет #6), регистрируется на порту 9091.
	sessionRevocationsHandler *sessionrevapp.Handler

	// internalOperationsHandler — InternalOperationsService.ListIamOperations:
	// административная лента всех операций IAM по всему кластеру.
	// Только внутренний (запрет #6), порт 9091; ограничен административным уровнем
	// (проверка ReBAC system_admin@cluster в обработчике и каталог прав шлюза).
	internalOperationsHandler *internaloperationsapp.Handler

	// internalBootstrapTokenHandler — InternalBootstrapTokenService.MintBootstrapToken:
	// неинтерактивная чеканка начального токена RS256 (#58). Только внутренний (запрет #6),
	// регистрируется ТОЛЬКО на порту 9091 и доступен ТОЛЬКО прямым gRPC-подключением с mTLS
	// (без маршрута REST в api-gateway — там он оказался бы без удостоверения).
	// Страж — явный разрешающий список SPIFFE клиентских сертификатов authzguard.CallerPolicy
	// (authn.bootstrap-mint.allowed-client-sans); permission="<exempt>"
	// означает только отсутствие ReBAC Check (до первого токена отношения
	// ещё нет), а НЕ отмену аутентификации.
	internalBootstrapTokenHandler *bootstraptoken.Handler

	// ownGates — ЗНАЧЕНИЕ, КОТОРОЕ ДЕРЖАТ СОБСТВЕННЫЕ СТРАЖИ iam: дверь решения
	// поверх реляционной формы.
	//
	// Выставлено наружу потому, что не все стражи собираются здесь. Потолок чтения
	// на внутреннем слушателе собирается в `runServe`, и ему до сих пор отдавали
	// ГОЛЫЙ транспорт — то есть решение о доступе на каждом читающем RPC
	// внутреннего слушателя уходило мимо двери. Снаружи это выглядело исправно:
	// страж есть, провязан, исполняется на каждом запросе.
	//
	// Пока у `runServe` не было доступа к этому значению, «отдать стражу
	// правильное» было невыполнимо — не из-за недосмотра, а из-за раскладки.
	// Поле закрывает именно это.
	ownGates *authzcascade.Client
}

// ownGateWiringComplaint сообщает, почему собственным стражам авторизации iam нельзя доверять
// при этой провязке, либо "", если можно. Корень композиции превращает жалобу в отказ
// старта; отдельная функция позволяет проверить отказ — os.Exit внутри построителя
// можно лишь прочитать, а работа непроверяемого стража никому не известна.
//
// Условие ОДНО, и оно осталось от четырёх не потому, что требования ослабли, а
// потому, что три из них были условиями ЧУЖОГО транспорта: второй шанс поверх
// доехавших очередью кортежей, страничное чтение структурных фактов и предъявление
// решения сравнению форм. Ни у одного из трёх больше нет предмета — решение
// принимает форма своей базой, и то, чем её дополняли, она читает первым же
// вопросом.
//
// Оставшееся условие — что двери есть чем отвечать. Дверь без формы отвечала бы
// ОШИБКОЙ на каждый вопрос, а не отказом (см. authzcascade.ErrFormNotWired), то
// есть служба поднялась бы и не отвечала бы ни на один вопрос о доступе. Отказ в
// старте называет это прямо: рантайм-диагностика оператору, который иначе не
// поймёт, почему поднявшаяся служба ничего не решает.
//
// НЕ зависит от режима аутентификации. Каждый развёрнутый стенд работает в боевом
// режиме, а страж, отсутствующий на стендах, где заметили бы его срабатывание, не является
// защитой.
//
// Сообщение намеренно называет ручку и последствие: его видит оператор,
// когда стенд не поднимается; отказ, не говорящий, что исправить, не позволяет
// предпринять действие.
func ownGateWiringComplaint(store *authzcascade.Client) string {
	if !store.FormReachable() {
		return "источник вердикта о доступе не провязан: дверь решения собрана без " +
			"реляционной формы, и КАЖДЫЙ вопрос о доступе вернул бы ошибку, а не ответ " +
			"(проверьте строку подключения к базе службы прав)"
	}
	// Условия ПОЗИЦИИ РУБИЛЬНИКА здесь больше нет: рубильник переключал источник
	// вердикта потипово, пока источников было два. Источник один — переключать
	// нечего, и условие снято вместе со своим предметом, а не оставлено пустым.
	return ""
}

// buildServices создает все repo'ы поверх pool и собирает бизнес-сервисы.
// Корень композиции передаёт полностью настроенную дверь решения — провязка
// каждого сценария ресурса безусловна (без резервной заглушки).
// opsRepo — ПОЛНЫЙ репозиторий corelib (operations.NewRepo), а не узкий
// operations.Repo: административные сценарии кластера завершают метаданные Operation
// при терминальной записи (идентификатор выдачи появляется лишь после мутации),
// и эта возможность должна доказываться сборкой, а не приведением типа здесь.
func buildServices(pool, slavePool *pgxpool.Pool, opsRepo operations.FullRepo,
	kanameRepo kanamerepo.Repository,
	// membershipRepo — УЗКИЙ корень чтения членства, приходящий ОТДЕЛЬНЫМ
	// параметром, а не выуживаемый приведением типа из соседнего.
	//
	// Причина названа у самого порта: расширить общий корень значило бы
	// потребовать нового метода от 46 дублёров в 25 файлах проб соседних
	// ресурсов. Приведение типа здесь было бы дешевле по строкам и хуже по
	// существу — оно превращает провязку в утверждение о том, какая реализация
	// пришла, и это утверждение проверялось бы в рантайме, а не сборкой.
	membershipRepo membershipapp.Repo,
	// catalogSource — КАТАЛОЖНЫЙ ФАКТ из ЖИВЫХ строк (задача kacho#1816): какие пары
	// грантуемы и какие глаголы объявлены. Приходит отдельным параметром, а не
	// спрашивается у литерала внутри use-case'ов: ответ на него может измениться
	// в работающем процессе — снятием строки, — и читатель на литерале
	// продолжил бы считать снятый тип живым до следующего перезапуска.
	catalogSource catalog.Source,
	// catalogRows — ЧИТАТЕЛЬ строк каталога, тот же экземпляр, что прочитал их
	// страж паритета на старте. Приходит параметром, а не собирается здесь
	// заново: читатель живого множества в дереве ОДИН, и второй его экземпляр
	// был бы вторым местом об одном предмете — расходиться им нечем сегодня и
	// есть чем завтра.
	catalogRows moduleapp.CatalogStateSource,
	metricsReg *metrics.Registry,
	cfg config.Config,
	// moduleRoster — перечень личностей модулей, прочитанный корнем ОДИН раз с
	// проверкой ошибки (kaname#987): обработчик внутреннего Check, посредник записи
	// отношений и допуск пира у службы решений судят по тому же значению, что
	// политики вызывающего.
	moduleRoster moduleidentity.Roster,
	tokenSigner *tokensigner.Signer, logger *slog.Logger, referencePlans ...*authzmodel.Plans) *services {
	var rolePlans *authzmodel.Plans
	if len(referencePlans) == 1 {
		rolePlans = referencePlans[0]
	}
	_ = slavePool // kanameRepo собирается и передаётся из main()

	// sharedClock — ОДИН источник моментов, сравниваемых с отсечкой отзыва-всех,
	// на все глаголы этого корня (kaname#589): ForceLogout, отзыв-всех, выдача
	// удостоверения человека. Строится на ведущем пуле.
	sharedClock, sharedClockErr := buildSharedClock(pool)
	if sharedClockErr != nil {
		log.Fatalf("shared clock: %v", sharedClockErr)
	}

	// relationStore — ТО значение, которое получают собственные стражи iam, и
	// причина, по которой страж не может спросить «мимо»: другого значения для него
	// в корне нет.
	//
	// Форма собирается на ВЕДУЩЕМ пуле намеренно. Вопрос о доступе читает строки,
	// закоммиченные только что — выдачу, сделанную этим же запросом, — а это ровно
	// то, на чём отстаёт реплика: отзыв, действующий «с коммита», на реплике
	// действовал бы «с момента, когда доехало».
	verdictAsker := relverdict.NewAsker(pool)
	relationStore := authzcascade.WrapAdmitted(verdictAsker, personmarks.New(pool))
	// Разбор оснований выходит НАРУЖУ, а не копится в никуда.
	//
	// Форма считает две вещи, у которых нет иного признака: сколько раз доступ
	// выдан меточной ветвью (по каждой оси отдельно) и сколько отказов дано по
	// основанию «типа нет в словаре модели». Оба состояния, при которых что-то
	// сломано, снаружи выглядят как исправная работа: ось, переставшая
	// спрашиваться, не выдаёт прав по меткам, а опечатка в имени типа отбирает
	// доступ, — и то и другое арендатор читает как «прав не выдали».
	//
	// Провязка ЗДЕСЬ, у единственного места, где собран сам носитель. Величины
	// копились с тех пор, когда их читало теневое сравнение форм; сравнения
	// больше нет, а форма стала единственным источником вердикта — то есть
	// считаются они теперь на живом пути решения о доступе, и читателя у них не
	// было ни одного (kacho#1224).
	//
	// Читается СНИМОК носителя, а не запомненное число: коллектор спрашивает
	// источник на каждом сборе.
	metricsReg.NewRelationVerdictGroundsCollector(func() metrics.RelationVerdictGrounds {
		mirror, iamDirect, earlyStops := verdictAsker.LabelArmGrounds()
		return metrics.RelationVerdictGrounds{
			LabelArmMirror:        mirror,
			LabelArmIAMDirect:     iamDirect,
			EarlyStops:            earlyStops,
			UndeclaredTypeDenials: verdictAsker.UndeclaredTypeDenials(),
		}
	})
	// Отказ в старте, а не надежда: дверь без формы отвечала бы ошибкой на каждый
	// вопрос о доступе, и служба была бы Ready, не решая ничего.
	//
	// НЕ зависит от режима аутентификации: каждый развёрнутый стенд работает в боевом
	// режиме, а страж, отсутствующий на стендах, где заметили бы его срабатывание,
	// не является защитой.
	if complaint := ownGateWiringComplaint(relationStore); complaint != "" {
		logger.Error("refusing to start: " + complaint)
		os.Exit(1)
	}

	// rsabReconciler — ЕДИНСТВЕННЫЙ движок материализации объекта на ПУТИ
	// ЗАПРОСА (явная модель RBAC 2026 P4). Общий для AccessBinding.Create,
	// распространения членства Role.Update, материализации автоматической привязки владельца
	// P6 Account.Create (C-01/C-01b) И хука подготовки первого входа, который получает
	// именно этот экземпляр через `services.bindingReconciler` — прежде он собирал
	// собственный, без приёмника размера (#116).
	//
	// «Каждый потребитель» здесь означает потребителей ПУТИ ЗАПРОСА, и это не оговорка:
	// фоновый воркер обхода (`serve.go`) строит свой экземпляр со своим именем
	// в журнале, и его материализации в эту гистограмму НЕ попадают. Решение
	// о том, должны ли они туда попадать, не принималось — предмет заведён
	// задачей #157.
	rsabReconciler := reconcileapp.New(kanamepg.NewReconcileAdapter(pool, catalogSource), logger, catalogSource)
	var bindingSizeRecorder reconcileapp.SizeRecorder
	if metricsReg != nil {
		// Размер материализации привязки — измерение, не потолок. Он ничего не
		// отвергает: величина, которой привязка может достичь, не измерена, а предел,
		// назначенный до замера, либо отвергнет законную выдачу, либо не отвергнет
		// ничего, оставаясь на вид контролем.
		bindingSizeRecorder = metricsReg.NewBindingMaterializationRecorder()
		rsabReconciler = rsabReconciler.WithSizeRecorder(bindingSizeRecorder)
	}

	// AccountService.
	accountCreate := accountapp.NewCreateAccountUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler)
	accountUpdate := accountapp.NewUpdateAccountUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		// Изменение МЕТОК меняет членство селектора iam-direct, поэтому удаление метки,
		// совпадающей с выдачей ARM_LABELS, — ОТЗЫВ. Межсервисный двойник уже делает
		// это: vpc/compute/nlb повторно вызывают RegisterResource при обновлении меток и запускают
		// прямой проход объекта в процессе (защита удаления устаревшего передаёт объект с
		// имеющимися участниками ПОЛНОМУ пересчёту, удаляющему устаревшие кортежи). Без
		// такой же провязки здесь путь iam имел только совместно коммитимое событие
		// сверки, поэтому задержка отзыва равнялась глубине очереди сверки FIFO —
		// измерено 7м30с в очереди плюс 65с обхода до исчезновения кортежа.
		WithObjectReconciler(rsabReconciler)
	accountDelete := accountapp.NewDeleteAccountUseCase(kanameRepo, opsRepo)
	accountGet := accountapp.NewGetAccountUseCase(kanameRepo).WithRelationStore(relationStore)
	// listScanRec — съём стоимости страницы для списков с добором (kacho#653).
	// Один экземпляр на сборку: гистограммы размечены видом ресурса.
	listScanRec := metricsReg.NewListScanRecorder()

	accountList := accountapp.NewListAccountsUseCase(kanameRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	accountListAllOps := accountapp.NewListAllOperationsUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger)
	accountHandler := accountapp.NewHandler(accountCreate, accountUpdate, accountDelete, accountGet, accountList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo)).
		WithListAllOperations(accountListAllOps)

	// ProjectService.
	projectCreate := projectapp.NewCreateProjectUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		// rbac-contract-a-flat: синхронно материализовать кортеж владельца
		// admin/v_* на только что созданном проекте (синхронный ReconcileObject
		// после коммита через синхронного писателя FGA общего rsabReconciler), чтобы GET сразу
		// после завершения Operation не гонялся с асинхронной выгрузкой fga_outbox (403).
		WithObjectReconciler(rsabReconciler)
	projectUpdate := projectapp.NewUpdateProjectUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		// Изменение МЕТОК меняет членство селектора iam-direct, поэтому удаление метки,
		// совпадающей с выдачей ARM_LABELS, — ОТЗЫВ. Межсервисный двойник уже делает
		// это: vpc/compute/nlb повторно вызывают RegisterResource при обновлении меток и запускают
		// прямой проход объекта в процессе (защита удаления устаревшего передаёт объект с
		// имеющимися участниками ПОЛНОМУ пересчёту, удаляющему устаревшие кортежи). Без
		// такой же провязки здесь путь iam имел только совместно коммитимое событие
		// сверки, поэтому задержка отзыва равнялась глубине очереди сверки FIFO —
		// измерено 7м30с в очереди плюс 65с обхода до исчезновения кортежа.
		WithObjectReconciler(rsabReconciler)
	projectDelete := projectapp.NewDeleteProjectUseCase(kanameRepo, opsRepo)
	projectGet := projectapp.NewGetProjectUseCase(kanameRepo).WithRelationStore(relationStore)
	projectList := projectapp.NewListProjectsUseCase(kanameRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	projectHandler := projectapp.NewHandler(projectCreate, projectUpdate, projectDelete, projectGet, projectList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// UserService + InternalUserService.
	userGet := userapp.NewGetUserUseCase(kanameRepo).WithRelationStore(relationStore)
	userList := userapp.NewListUsersUseCase(kanameRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	userUpdate := userapp.NewUpdateUserUseCase(kanameRepo, opsRepo).
		// То же исправление задержки отзыва, что у accountUpdate выше: iam.user выбирается по меткам,
		// поэтому очистка метки — ОТЗЫВ; без прямого прохода объекта в процессе он
		// ждал очередь сверки FIFO (измерено 7м30с + 65с обхода), вместо
		// сходимости в процессе, как на межсервисном пути RegisterResource.
		WithObjectReconciler(rsabReconciler, logger)
	userDelete := userapp.NewDeleteUserUseCase(kanameRepo, opsRepo)
	userInvite := userapp.NewInviteUserUseCase(kanameRepo, opsRepo, relationStore).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler).
		// Срок строки приглашения (приёмка ID-MAIL-1, §10 п. 22). Величина
		// читается ЗДЕСЬ и передаётся use-case'у: настройки читает
		// композиционный корень, а не бизнес-логика. Умолчание живёт у ручки,
		// поэтому молчащая посадка получает его, а не «без срока».
		WithInviteTTL(cfg.Invite.TTLOrDefault()).
		// Ограничение частоты писем на адрес (приёмка ID-MAIL-1, Р14/Р22,
		// MAIL-25) — одно на оба глагола, отправляющих письмо; счётчик исходов
		// намерения — тоже один. Величину судит страж старта: непозитивную он
		// не пропускает, поэтому здесь читается уже проверенное.
		WithInviteMailRateLimit(inviteMailRateLimit(cfg), metricsReg.InviteMailIntentRecorder())
	// Block/Unblock — административный запрет участию и его снятие. Два РАЗНЫХ
	// типа, поэтому перестановка их здесь — ошибка компиляции, а не контроль,
	// тихо ставший своей противоположностью.
	userBlock := userapp.NewBlockUserUseCase(kanameRepo, opsRepo)
	userUnblock := userapp.NewUnblockUserUseCase(kanameRepo, opsRepo)
	// Исключение из аккаунта — пара к приглашению: тот вводит человека в
	// аккаунт, этот выводит (kacho#1127). Строку личности не трогает.
	userRemoveFromAccount := userapp.NewRemoveFromAccountUseCase(kanameRepo, opsRepo)
	// Повторная отправка письма приглашения — то, что приходит взамен снятого
	// поля ссылки (ID-MAIL-1, §10 п. 9). Право приглашать спрашивается у того
	// же клиента, что у Invite; ограничение частоты и счётчик — те же.
	userResendInvite := userapp.NewResendInviteUseCase(kanameRepo, opsRepo, relationStore,
		inviteMailRateLimit(cfg), metricsReg.InviteMailIntentRecorder())
	userHandler := userapp.NewHandler(userGet, userList, userUpdate, userDelete, userInvite,
		userBlock, userUnblock, userRemoveFromAccount).
		WithResendInvite(userResendInvite).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))
	internalUserHandler := userapp.NewInternalHandler(userGet)

	// ServiceAccountService.
	saCreate := serviceaccountapp.NewCreateServiceAccountUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	saUpdate := serviceaccountapp.NewUpdateServiceAccountUseCase(kanameRepo, opsRepo).
		// То же исправление задержки отзыва, что у accountUpdate выше: iam.serviceAccount
		// выбирается по меткам, поэтому очистка метки — ОТЗЫВ; без прямого прохода объекта
		// в процессе он ждал очередь сверки FIFO (измерено 7м30с + 65с
		// обхода), вместо сходимости в процессе, как на межсервисном
		// пути RegisterResource.
		WithObjectReconciler(rsabReconciler, logger)
	saDelete := serviceaccountapp.NewDeleteServiceAccountUseCase(kanameRepo, opsRepo)
	saGet := serviceaccountapp.NewGetServiceAccountUseCase(kanameRepo).WithRelationStore(relationStore)
	saList := serviceaccountapp.NewListServiceAccountsUseCase(kanameRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	// Disable / Enable — писатели состояния, определяющего, может ли служебная
	// учётная запись аутентифицироваться. Хук токена, выдача ключей
	// и проверка docker-токена читали состояние задолго до появления возможности
	// его задать; до этой провязки изменить его можно было только оператором
	// в базе данных вручную.
	saDisable := serviceaccountapp.NewDisableServiceAccountUseCase(kanameRepo, opsRepo)
	saEnable := serviceaccountapp.NewEnableServiceAccountUseCase(kanameRepo, opsRepo)
	saHandler := serviceaccountapp.NewHandler(saCreate, saUpdate, saDelete, saGet, saList, saDisable, saEnable).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// GroupService.
	groupCreate := groupapp.NewCreateGroupUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	groupUpdate := groupapp.NewUpdateGroupUseCase(kanameRepo, opsRepo).
		// То же исправление задержки отзыва, что у accountUpdate выше: iam.group выбирается по меткам,
		// поэтому очистка метки — ОТЗЫВ. Group.Update оставался последним путём БЕЗ ОБЕИХ
		// частей — совместно коммитимого события сверки и прямого прохода объекта в процессе, — поэтому
		// отзыв сходился лишь тогда, когда периодический обход раз в 30с доходил до привязки.
		// Событие (добавлено в doUpdate) — страховка доставки хотя бы раз; эта провязка добавляет
		// ускоритель, который межсервисный путь RegisterResource запускает в процессе; без него
		// задержка отзыва равна глубине очереди сверки FIFO (измерено 7м30с).
		WithObjectReconciler(rsabReconciler, logger)
	groupDelete := groupapp.NewDeleteGroupUseCase(kanameRepo, opsRepo)
	groupGet := groupapp.NewGetGroupUseCase(kanameRepo).WithRelationStore(relationStore)
	groupList := groupapp.NewListGroupsUseCase(kanameRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	// Р3 (kaname#1037): участник в группу с действующими выдачами — только с правом
	// выдавать на каждой их области; та же дверь решения, что у
	// AccessBindingService.Create. Без провязки добавление отказывает.
	groupAdd := groupapp.NewAddMemberUseCase(kanameRepo, opsRepo).
		WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(kanameRepo, relationStore))
	groupRemove := groupapp.NewRemoveMemberUseCase(kanameRepo, opsRepo)
	// ListMembers называет группу в запросе, поэтому повторно спрашивает модель об
	// этой группе по `v_list` — тому же отношению, которое требует входная дверь,
	// и на том же уровне, что уже есть у двух соседних чтений.
	groupListMembers := groupapp.NewListMembersUseCase(kanameRepo).WithRelationStore(relationStore)
	groupHandler := groupapp.NewHandler(groupCreate, groupUpdate, groupDelete, groupGet, groupList,
		groupAdd, groupRemove, groupListMembers).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// MembershipService — чтение членства на аккаунт-скоупных путях и создание
	// на плоской коллекции (kaname#181, IAM-ID-1 §4 S3.2).
	//
	// У АККАУНТ-СКОУПНЫХ ЧТЕНИЙ ни клиента модели прав, ни фильтра страницы
	// здесь НЕТ, и это утверждение, а не пропуск: единственный гейт этих чтений
	// — пообъектная проверка КРАЯ по аккаунту из пути, а строки отбираются тем
	// же аккаунтом в условии запроса. Провязать сюда второй замок значило бы
	// заменить проверку края кодом, который можно забыть в следующей ветке.
	//
	// СВОЙ СПИСОК (стадия S2) фильтра тоже не несёт — его сужение и есть
	// личность вызывающего: человек берётся из принципала и уходит доводом
	// запроса, других входов у чтения нет (`membershipapp/list_mine.go`).
	//
	// СОЗДАНИЕ — тот же поток, что `UserService.Invite`, и провязывается ТЕМ ЖЕ
	// экземпляром use-case'а (`userInvite`): реконсайлер, срок приглашения и
	// клиент модели прав у обоих глаголов одни. Второй экземпляр разошёлся бы с
	// первым в провязке молча — и разошёлся бы на самом чувствительном: на том,
	// что материализуется после коммита.
	membershipHandler := membershipapp.NewHandler(
		membershipapp.NewGetMembershipUseCase(membershipRepo),
		membershipapp.NewListMembershipsUseCase(membershipRepo),
		membershipapp.NewListMyMembershipsUseCase(membershipRepo),
		userInvite,
	)

	// RoleService.
	roleCreate := roleapp.NewCreateRoleUseCase(kanameRepo, opsRepo, catalogSource).
		WithGrantReferencePlans(rolePlans).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler).
		// Роль, принятая до снятия регистрации названного ключа и записанная после,
		// снятого ключа не называет (kaname#963, Р8).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(pool))
	// Role.Update прав активной роли сверяет кортежи FGA
	// каждой активной привязки этой роли в ТОЙ ЖЕ транзакции писателя (атомарно,
	// запрет #10) через RoleTupleReconciler из access_binding (ему принадлежат
	// построитель кортежей FGA и хранилище сохранённых отправленных кортежей). Без него понижение
	// прав оставляло осиротевшие кортежи FGA, то есть действующие привилегии.
	// Сверщик AccessBinding с областью ресурса
	// общий для AccessBinding.Create (материализация селектора после коммита),
	// воркера serve.go (выгрузка событий, обход, истечение) И распространения членства Role.Update
	// (изменение правил перематериализует членство ARM_LABELS из role.rules
	// каждой активной привязки, немедленно отзывая снятые правила по
	// rule_fp). Один сценарий поверх pg ReconcileAdapter (порт чистой архитектуры).
	// ПРИМЕЧАНИЕ: rsabReconciler создаётся один раз в начале buildServices (общий
	// с материализацией автоматической привязки владельца Account.Create).
	roleUpdate := roleapp.NewUpdateRoleUseCase(kanameRepo, opsRepo, catalogSource).
		WithGrantReferencePlans(rolePlans).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(pool)).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(kanameRepo, rsabReconciler)).
		// Р2 (kaname#1036): правка правил роли с действующими выдачами — только с
		// правом выдавать её на каждой области этих выдач; та же дверь решения, что у
		// AccessBindingService.Create. Без провязки правка правил отказывает.
		WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(kanameRepo, relationStore)).
		// То же исправление задержки отзыва, что у accountUpdate выше, для роли КАК ОБЪЕКТА
		// (iam.role выбирается по меткам, поэтому очистка одной из СОБСТВЕННЫХ меток РОЛИ —
		// ОТЗЫВ доступа К роли, независимый от распространения правил, провязанного
		// выше и отвечающего за то, что роль ВЫДАЁТ). Без прямого прохода
		// объекта в процессе он ждал очередь сверки FIFO (измерено 7м30с + 65с
		// обхода), вместо сходимости в процессе, как на межсервисном
		// пути RegisterResource.
		WithObjectReconciler(rsabReconciler, logger)
	roleDelete := roleapp.NewDeleteRoleUseCase(kanameRepo, opsRepo)
	// roleGet — исправление D-1: системные роли доступны всем (базовый каталог, исключение);
	// ПОЛЬЗОВАТЕЛЬСКИЕ роли проверяются по объектам тем же множеством FGA v_list, что и List
	// (чтение равно применению, D-45). relationStore всегда не nil, поэтому Get пользовательской роли
	// закрывается отказом при сбое FGA (Unavailable, D-47), не раскрывая тело.
	roleGet := roleapp.NewGetRoleUseCase(kanameRepo, catalogSource).WithRelationStore(relationStore)
	// roleList — фильтрация области по объектам: множество FGA v_list на
	// iam_role пересекается с каталогом (системные роли проходят мимо). relationStore
	// всегда не nil, поэтому List закрывается отказом при сбое FGA (D-47).
	roleList := roleapp.NewListRolesUseCase(kanameRepo, catalogSource).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	roleHandler := roleapp.NewHandler(roleCreate, roleUpdate, roleDelete, roleGet, roleList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// AccessBindingService. (rsabReconciler создан выше — общий с
	// распространением членства Role.Update; тот же экземпляр ведёт Create и воркер.)
	abCreate := accessbindingapp.NewCreateAccessBindingUseCase(kanameRepo, opsRepo, catalogSource).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler).
		// Выдача, принятая до снятия регистрации объекта цели и записанная после,
		// живой не остаётся (kaname#963, Р8).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(pool))
	// abDelete — relationStore ведёт страж полномочий выдачи, и ТОЛЬКО его. Удаление
	// кортежей после коммита, которое он также вёл, ушло с внешним хранилищем:
	// EmitRelationDelete внутри транзакции теперь составляет весь механизм, поскольку триггер сворачивает
	// строку журнала в прямой факт в ТОМ ЖЕ коммите. Поэтому отказ
	// виден при завершении Operation по устройству, без гонки со второй записью.
	abDelete := accessbindingapp.NewDeleteAccessBindingUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger)
	// Revoke — F10 (IAM-1-28): МЯГКИЙ отзыв (статус ACTIVE→REVOKED, строка сохранена
	// для срока хранения аудита), в отличие от ЖЁСТКОГО Delete. Тот же страж полномочий выдачи и
	// защиты deletion_protection, что у Delete; то же синхронное удаление кортежей FGA
	// после коммита, чтобы отказ был виден при завершении Operation.
	abRevoke := accessbindingapp.NewRevokeAccessBindingUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger)
	// Update — P6 (C-03): снимает deletion_protection, позволяя удалить защищённую
	// привязку. Тот же страж полномочий выдачи, что у Create/Delete. WithObjectReconciler добавляет
	// перематериализацию меток после коммита: iam.accessBinding выбирается по меткам, поэтому
	// очистка метки, совпадающей с выдачей ARM_LABELS, — ОТЗЫВ; без
	// прохода в процессе его задержка равна глубине очереди сверки FIFO (один воркер,
	// около 5 событий/с ПОЛНОГО пересчёта O(scope) — измерено 7м30с от постановки до выгрузки на
	// соседнем пути iam.project). Совместно коммитимое событие сверки остаётся страховкой.
	abUpdate := accessbindingapp.NewUpdateAccessBindingUseCase(kanameRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	// D-6 (T3.3): RPC чтения AB объединяют существующий базовый доступ себе/по выдаче с
	// видимостью по селектору меток (viewer ∪ v_list на iam_access_binding). relationStore
	// (дверь решения) удовлетворяет ОБОИМ портам: RelationStore (Check) и RelationQueries
	// (контекстная и постраничная формы); WithRelationQueries провязывает базовую
	// видимость по объектам.
	abGet := accessbindingapp.NewGetAccessBindingUseCase(kanameRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	abListByScope := accessbindingapp.NewListByScopeUseCase(kanameRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// F11 (IAM-1-32): единый List — проталкивание viewer ∪ v_list (тот же базовый
	// RelationQueries, что у других чтений AB) ПЛЮС надстраж администратора кластера D-9
	// (RelationStore), без которого администратор кластера, не имеющий
	// кортежа по объекту на iam_access_binding, получил бы здесь пустую страницу, хотя
	// каждое соседнее чтение возвращает полное множество.
	// Соседняя поверхность верхнего яруса супер-доступа читается ОТСЮДА ЖЕ
	// (kacho#914, решение 2): выдают и отзывают кластерного администратора своим
	// глаголом, но спрашивающий «кто имеет доступ» обязан получать полный ответ
	// из ОДНОЙ точки чтения — иначе две поверхности об одном предмете расходятся
	// молча. Читатель тот же, что обслуживает `InternalClusterService.ListAdmins`:
	// второй завёл бы второй способ ответить на один вопрос.
	abList := accessbindingapp.NewListUseCase(kanameRepo).
		WithRelationStore(relationStore).
		WithRelationQueries(relationStore).
		WithClusterAdmins(kanamepg.NewClusterAdminGrantReader(pool)).
		WithListScanRecorder(listScanRec)
	// ListBySubject — тот же вопрос, что и у ListSubjectPrivileges («какие выдачи
	// есть у этого субъекта»), поэтому и допуск у него ТОТ ЖЕ, единым предикатом
	// (kacho#1352). Оба порта обязательны: RelationStore решает полосы надзора облака
	// и делегированного распорядителя, RelationQueries сужает СТРАНИЦУ полосы
	// распорядителя построчно (kacho#1354). Непровязанный порт этим чтением
	// ОТКАЗЫВАЕТ — провязка здесь не удобство, а условие работоспособности полосы.
	abListBySub := accessbindingapp.NewListBySubjectUseCase(kanameRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	abListByAcc := accessbindingapp.NewListByAccountUseCase(kanameRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// ListSubjectPrivileges — обогащённое чтение себя либо администратором аккаунта.
	// RelationStore провязан, чтобы путь авторизации делегированного администратора (FGA admin@account)
	// находил администраторов, не являющихся владельцем домашнего аккаунта (D-4, путь b);
	// RelationQueries — пообъектный вопрос, которым СТРАНИЦА сужается по правам
	// вызывающего (kacho#1354). Непровязанный порт этим чтением ОТКАЗЫВАЕТ, поэтому
	// провязка здесь — не удобство, а условие работоспособности полосы
	// распорядителя аккаунта.
	abListSubjPriv := accessbindingapp.NewListSubjectPrivilegesUseCase(kanameRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// ListAssignableRoles — роли, допустимые для привязки к ресурсу,
	// с аннотацией scope_group. Тот же страж полномочий выдачи, что у ListByScope/Create
	// (RelationStore провязан, чтобы пути полномочий делегированного администратора и области кластера
	// разрешались).
	abListAssignable := accessbindingapp.NewListAssignableRolesUseCase(kanameRepo).
		WithRelationStore(relationStore, logger)
	// Аудит ListByRole (тот же фильтр области по полномочиям выдачи, что у
	// других RPC List) и аудит действующих субъектов ExpandAccess
	// (раскрывает множества пользователей групп через ListSubjects двери).
	abListByRole := accessbindingapp.NewListByRoleUseCase(kanameRepo).
		WithRelationStore(relationStore, logger)
	// ExpandAccess: дверь решения также раскрывает множества пользователей (ListSubjects)
	// И RelationStore для стража полномочий выдачи по объекту (В3 — вызывающий может
	// раскрывать «кто может X» только на объектах, которыми им разрешено управлять, по
	// ТОМУ ЖЕ предикату requireGrantAuthority, который применяют ListByScope/ListByRole).
	abExpandAccess := accessbindingapp.NewExpandAccessUseCase(relationStore).
		WithGrantAuthority(kanameRepo, relationStore, logger)
	// Делегированный путь права выдавать (kaname#986, Р2): делегат выдаёт, отзывает
	// и удаляет выдачи в пределах своего делегирования. Один экземпляр на три глагола
	// — тот же, что у мира проб (`gdWireGrantPath`).
	abDelegated := accessbindingapp.NewDelegatedGrantPath(kanameRepo, relationStore)
	abCreate.WithDelegatedGrantPath(abDelegated)
	abRevoke.WithDelegatedGrantPath(abDelegated)
	abDelete.WithDelegatedGrantPath(abDelegated)
	// GrantDelegationService (kaname#986, Р1): делегирования права выдавать. Право
	// на каждом глаголе решает обработчик (`HANDLER_DECIDES`).
	grantDelegationHandler := grantdelegationapp.NewHandler(
		grantdelegationapp.NewCreateGrantDelegationUseCase(kanameRepo, opsRepo, catalogSource).
			WithRelationStore(relationStore, logger),
		grantdelegationapp.NewGetGrantDelegationUseCase(kanameRepo).WithRelationStore(relationStore),
		grantdelegationapp.NewListGrantDelegationsUseCase(kanameRepo).WithRelationStore(relationStore),
		grantdelegationapp.NewRevokeGrantDelegationUseCase(kanameRepo, opsRepo).WithRelationStore(relationStore, logger),
	).WithUpdate(grantdelegationapp.NewUpdateGrantDelegationUseCase(kanameRepo, opsRepo, catalogSource).WithRelationStore(relationStore, logger))
	abHandler := accessbindingapp.NewHandler(abCreate, abDelete, abGet, abListByScope, abListBySub, abListByAcc,
		abListSubjPriv).
		WithUpdate(abUpdate).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo)).
		WithList(abList).
		WithListAssignableRoles(abListAssignable).
		WithListByRole(abListByRole).
		WithExpandAccess(abExpandAccess).
		WithRevoke(abRevoke)

	// ── Провязка ядра авторизации ─────────────────────────────────────────────────
	authzServices := buildAuthZServices(kanameRepo, relationStore, kanamepg.NewHumanSessionRepo(pool),
		catalogSource, metricsReg, cfg.AuthN.Mode.IsProduction(), moduleRoster)
	// InternalIAMService — LookupSubject (для перехватчика аутентификации
	// api-gateway) и Check (делегирует AuthorizeService.CheckRelation
	// в тот же конвейер FGA + OPA). Только внутренний слушатель, порт 9091: никогда
	// на внешнем эндпоинте (запрет #6). Прежнее «только прямой gRPC» здесь
	// неверно — api-gateway также выставляет эти два метода по REST на своём
	// ВНУТРЕННЕМ мультиплексоре; инвариант — внутренний доступ, а не прямой gRPC.
	lookupSubject := internaliamapp.NewLookupSubjectUseCase(kanameRepo)
	// SEC-C — прокси FGA: RegisterResource / UnregisterResource ставят
	// кортеж иерархии владельца в kaname.fga_outbox в одной транзакции писателя, из которой
	// триггер сворачивает прямой факт в том же коммите. Минимальные полномочия обеспечивает
	// страж ReBAC (проверенная личность модуля → канонический fga_writer аккаунта); его
	// RelationChecker — та же поверхность Check (relationStore).
	// β (эпик «Resource-scoped AccessBinding»): та же транзакция писателя также вставляет/обновляет
	// либо удаляет строку kaname.resource_mirror (метки и родительскую область
	// объекта владельца), атомарно с отправкой кортежа владельца (запрет #10 — D-β3).
	// γ (эпик «Resource-scoped AccessBinding»): ТА ЖЕ транзакция писателя также (D4)
	// заполняет parent_account_id из projects.account_id в той же базе и (Q1=(c))
	// ставит событие resource_reconcile_outbox, чтобы сверщик пересмотрел
	// членство затронутых селекторов/byName — всё атомарно с вставкой/обновлением либо
	// удалением зеркала (запрет #10).
	registerResourceUC := internaliamapp.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewRegistrationTxBeginner(pool),
		// Имя типа КАТАЛОГА читается у ЖИВОЙ строки, в транзакции записи зеркала
		// (kacho#1990). Параметр, а не опция: запасной путь «переводим словарём
		// сборки» молчалив — верный ответ на посеянных типах и неверный на
		// заведённых применением манифеста в работающем процессе.
		kanamepg.NewCatalogTypeReader(),
		// Публикация для анонимного чтения — со СВОИМ порядком: версия владельца,
		// сравниваемая хранилищем, и надгробие снятия (kaname#107). Параметр, а не
		// опция: без порта у публикации нет порядка, и запоздавшая доставка открытия
		// после закрытия вернула бы анонимное чтение приватному объекту.
		kanamepg.NewPublicReadPublisher(),
		// Снятие регистрации объекта снимает его выдачи и названия правил ролей в той
		// же транзакции (kaname#963). Параметр, а не опция: без него освободившийся
		// ключ наследовал бы выдачи прежнего объекта.
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalogSource),
		// Регистрация и снятие объекта модулем пишут событие аудита той же
		// транзакцией (kaname#1005). Параметр, а не опция: без него изменения модели
		// прав модулем оставались бы вне журнала аудита молча.
		kanamepg.NewRegistrationAudit(),
		// Родителя регистрируемого объекта выводит kaname и сверяет с ним сведения
		// модуля в транзакции регистрации (kaname#982). Параметр, а не опция: без
		// него регистрация верила бы модулю.
		kanamepg.NewRegistrationScopeReader(),
	).
		WithReconcile(kanamepg.NewReconcileEventEmitter()).
		WithAccountResolver(kanamepg.NewProjectAccountResolver()).
		// Мгновенная видимость Design-B (VBC-15): после совместного коммита кортежа владельца и зеркала
		// выполнить СИНХРОННЫЙ ReconcileObject (синхронный писатель FGA общего rsabReconciler), чтобы
		// v_get создателя по объекту материализовался до того, как операция создания потребителя
		// сообщит о завершении: создание и немедленный GET получают ALLOW без гонки с асинхронной
		// выгрузкой очереди сверки. Безопасно при nil, ошибка нефатальна (выгрузка и обход страхуют).
		WithObjectReconciler(rsabReconciler, logger).
		// УКАЗАТЕЛЬ ОБЛАСТИ БОЛЬШЕ НЕ ПРИМЕНЯЕТСЯ ВТОРЫМ ПИСАТЕЛЕМ.
		//
		// Он применялся напрямую в чужое хранилище — в обе стороны, после коммита, —
		// потому что реконсайлер его не выводит, а значит никто другой не снял бы его
		// вовремя: ярус администратора аккаунта достаёт объекты ЧЕРЕЗ этот указатель, и
		// пережившее снятие ребро оставляло бы ему доступ к ресурсу, который уже
		// отвечает 404.
		//
		// Строка журнала, положенная той же транзакцией, делает то же самое и раньше:
		// прямой факт складывается из неё триггером в момент коммита. Догонять нечего.
		// Снятие должно отбирать КАЖДОЕ отношение, которое этот прокси мог записать на
		// объекте, а не только названное потребителем. Потребитель называет
		// указатель области, поскольку владеет лишь им; собственный `owner` создателя
		// записан от личности, которую затем никто не хранит, поэтому хранилище — единственная
		// сторона, ещё способная её назвать. Без этого читателя отношение молча переживало
		// объект: отзыв отправлялся, доставлялся и отмечался отправленным без
		// ошибки, а модель продолжала выводить все пять глаголов из оставшегося.
		//
		// Голый транспорт используется намеренно: здесь нужен СТРОГИЙ список объектов,
		// не проходящий через каскадную обёртку, чья задача — расширять ответы на
		// вопросы, а не перечислять физически имеющееся.
		WithResidualTupleReader(kanamepg.NewResidualTupleReader(pool))
	// Оба шага после коммита выше выполняются по возможности: перед ними надёжная очередь,
	// поэтому сбой стоит задержки, а не потери изменения. Это делает постоянно сломанный
	// шаг невидимым — один WARN и продукт продолжает работать медленнее вечно.
	// Приёмник считает ЗАПУСКИ и СБОИ, различая «никогда не отказал»
	// и «никогда не достигнут», и помечает, КАКИМ путём материализации пошла каждая регистрация,
	// чтобы регрессия к ЭКСКЛЮЗИВНОМУ пересчёту была видимым сдвигом между
	// двумя рядами, а не задержкой, которую кто-то должен заметить. Безопасно при nil: без реестра
	// метрик шаги по-прежнему исполняются и журналируются, лишь не считаются.
	if metricsReg != nil {
		registerResourceUC = registerResourceUC.WithMetrics(metricsReg.NewRegisterPostCommitRecorder())
	}
	regGate := authzguard.NewRelationWriteGate(relationStore).
		WithProductionMode(cfg.AuthN.Mode.IsProduction()).
		WithModuleRoster(moduleRoster)
	registerResourceUC.WithRegistrationAuthority(regGate)
	// Писатель отзывов сессий. Адаптер уровня пула поверх
	// session_revocations — путь Revoke InternalSessionRevocationsService
	// и его читатели IsRevoked / ListByUser (одна таблица). ForceLogout через него не
	// пишет: отсечку и запись с исходом кладёт
	// транзакция снятия ниже (kaname#340, kaname#380).
	sessionRevAdapter := kanamepg.NewSessionRevocationsAdapter(pool)
	// Инструментировать горячий путь Check авторизации на границе адаптера (чистая
	// архитектура): декоратор метрик оборачивает порт CheckRelation, который
	// страж InternalIAMService вызывает на каждом RPC (vpc/compute/nlb), записывая
	// гистограмму kaname_authz_check_* и счётчик решений без
	// импорта prometheus сценарием AuthorizeService. Реестр nil → обычный
	// авторизатор (метрики выключены).
	var checkAuthz internaliamapp.Authorizer = authzServices.authorizeSvc
	if metricsReg != nil {
		checkAuthz = metrics.NewInstrumentedAuthorizer(authzServices.authorizeSvc, metricsReg)
	}
	// Авторитет о предъявленном базовом секрете (kacho#1142) — с объявленным пределом
	// на обращение к базе (kaname#379). Сборка — basic_credential_lane.go.
	basicAuthority, basicAuthorityErr := newBasicCredentialAuthority(pool)
	if basicAuthorityErr != nil {
		log.Fatalf("basic credential authority: %v", basicAuthorityErr)
	}
	internalIAMHandler := internaliamapp.NewHandler(lookupSubject, checkAuthz).
		// Личности модулей (kaname#987): Check плоскости данных ограничен
		// доменом её модуля — тот же перечень, что у политик вызывающего.
		WithModuleRoster(moduleRoster).
		// PollSubjectChanges выгружает subject_change_outbox для сброса кеша
		// авторизации api-gateway. Только внутренний (порт 9091).
		//
		// Журнал процесса адаптеру НАЗЫВАЕТСЯ, а не берётся умолчанием: чтение
		// идёт окном до границы устоявшегося, и удержание границы
		// незавершившимся писателем — единственное состояние, в котором край
		// молчит при живых событиях. Без жалобы в журнал процесса оно
		// неотличимо от «событий нет» (kacho#1374).
		WithSubjectChange(service.NewSubjectChangeService(
			kanamepg.NewSubjectChangeRepo(pool, logger))).
		// SEC-C — RPC прокси FGA и страж авторизации ReBAC.
		WithResourceRegistrar(registerResourceUC, regGate).
		// kacho#1142 — авторитет о предъявленном базовом секрете. Край зовёт его на
		// промахе своего кэша вердикта; отзыв доходит до предъявления тем, что
		// резолв не находит СНЯТОЙ строки.
		WithBasicCredentialResolver(basicAuthority).
		WithLogger(logger).
		// ForceLogout СНИМАЕТ НАШИ записи сессии входа, кладёт отсечку и запись
		// события с исходом снятия — одной транзакцией (kaname#340). Отсечка
		// сама по себе лишь останавливает выдачу, оставляя живую сессию; снятие
		// и превращает отказ в выход. Прежде у посадки внешнего поставщика сессия
		// снималась у него (kaname#313); поставщика больше нет (kaname#363), и
		// сессия входа человека — всегда наша строка.
		WithOwnSessions(kanamepg.NewHumanSessionRepo(pool)).
		// Момент отсечки ForceLogout — общим источником (kaname#589).
		WithCutoffClock(sharedClock).
		// ForceLogout возвращает Operation — названная строка сохраняется здесь
		// до записи отсечки и терминально после неё, чтобы идентификатор, полученный
		// администратором, можно было запросить, а принудительный выход появлялся в
		// списке операций, как любая другая мутация.
		WithOperations(opsRepo).
		// Дополнительный страж ReBAC для ForceLogout (§«AuthN+AuthZ
		// ВЕЗДЕ»): требует system_admin@cluster у аутентифицированного субъекта.
		// relationStore удовлетворяет authzguard.RelationChecker; при nil закрывается отказом.
		WithAdminChecker(relationStore).
		// F5 (IAM-1-13): GetRoleCompiled — внутренняя проекция скомпилированных прав
		// (две проекции; публичный RoleService несёт только rules[]).
		WithRoleCompiledReader(roleapp.NewGetRoleCompiledUseCase(kanameRepo))
	// ЧИТАТЕЛЬ ПЕРЕПИСИ ИСХОДОВ ПОЛОСЫ БАЗОВОГО СЕКРЕТА — вплотную к построению
	// (kaname#379). Наружу полоса отвечает одним отказом на любую причину;
	// отсечка отзыва-всех, «строки нет» и «секрет не тот» различимы только в
	// этой переписи и в журнале, и без читателя перепись осталась бы в памяти
	// процесса. Держит `basic_credential_outcomes_wiring_test.go`.
	metricsReg.NewBasicCredentialOutcomeCollector(
		basicCredentialCells(), basicCredentialOutcomeReader(internalIAMHandler))

	// ── InternalSessionRevocationsService ─────────────────────────────────
	// Revoke (выход), IsRevoked (горячий путь api-gateway) и
	// ListByUser (административный аудит). Только внутренний (запрет #6).
	//
	// ListByUser отвечает о пользователе, НАЗВАННОМ В ЗАПРОСЕ, поэтому авторизуется
	// относительно него через то же хранилище отношений, что у UserService.Get.
	// Собственные стражи слушателя сужают вызывающий МОДУЛЬ и не читают `user_id`;
	// без провязки RPC обслуживает лишь самого вызывающего.
	sessionRevocationsHandler := sessionrevapp.NewHandler(
		sessionrevapp.NewRevokeUseCase(sessionRevAdapter, opsRepo, sharedClock),
		sessionRevAdapter,
	).WithRelationStore(relationStore).
		// SessionCutoffOf — отсечка субъекта на полосу БРАУЗЕРНОЙ сессии края.
		// Читатель ТОТ ЖЕ, которым пользуются полосы выдачи: два ответа об одной
		// отсечке разошлись бы молча, и разошлись бы там, где расхождение
		// означает «выведен по одной полосе и работает по другой».
		WithCutoffReader(kanamepg.NewUserTokenRevocationRepo(pool))

	// ── Провязка SAKey (статические ключи класса A служебных учёток) ─────────
	saKeysH := buildSAKeysHandler(pool, opsRepo, cfg, logger)

	// ── UserToken wiring (персональные access-токены пользователя, наша чеканка) ──
	userTokensH := buildUserTokensHandler(pool, opsRepo, cfg, sharedClock, logger)

	// ── InternalBootstrapTokenService — неинтерактивная чеканка начального токена (#58) ──
	// Чеканит НАШ подписант: дороги к внешнему поставщику на этом пути нет ни
	// одной (задача kacho#1119). Сборка — bootstrap_token.go.
	bootstrapTokenH, bootstrapErr := buildBootstrapTokenHandler(pool, cfg, tokenSigner, logger)
	// Отказ построения здесь — «контур включён, а выпускать нечем». Это отказ в
	// СТАРТЕ, а не деградация: стенд, поднявшийся Ready с неработающей чеканкой
	// бутстрапа, сообщает о беде на первом запросе — то есть тогда, когда
	// кластер поднимают и чинить уже поздно.
	if bootstrapErr != nil {
		log.Fatalf("bootstrap-token mint: %v", bootstrapErr)
	}

	// ── InternalClusterService ────────────────────────────────────────────
	clusterReader := kanamepg.NewClusterReader(pool)
	clusterGrantWriter := kanamepg.NewClusterAdminGrantWriter(pool)
	clusterGrantReader := kanamepg.NewClusterAdminGrantReader(pool)
	clusterRelEmitter := kanamepg.NewFGAOutboxEmitter()
	clusterTxb := kanamepg.NewPoolTxBeginner(pool)
	clusterSubjectState := kanamepg.NewSubjectStateReader(pool)

	clusterGetUC := clusterapp.NewGetClusterUseCase(clusterReader)
	// Надёжный отправитель audit_outbox — атомарно пишет
	// строку соответствия iam.cluster_admin.{granted,revoked} внутри
	// транзакции писателя выдачи/отзыва (запрет #10). Общий адаптер без состояния.
	clusterAuditEmitter := kanamepg.NewAuditOutboxEmitter(pool)
	// Дополнительный страж ReBAC (§«AuthN+AuthZ ВЕЗДЕ»):
	// административные RPC кластера с наибольшей зоной поражения обязаны исполнять СОБСТВЕННЫЙ
	// Check system_admin на каждом RPC, не полагаясь лишь на политику вызывающего шлюза. relationStore
	// (дверь решения) удовлетворяет authzguard.RelationChecker. При nil сценарий
	// закрывается отказом, если провязка отсутствует.
	clusterGrantUC := clusterapp.NewGrantAdminUseCase(
		clusterGrantWriter, clusterGrantReader, clusterRelEmitter, clusterTxb, opsRepo,
	).WithSubjectStateReader(clusterSubjectState).WithAdminChecker(relationStore).
		WithAuditEmitter(clusterAuditEmitter)
	clusterRevokeUC := clusterapp.NewRevokeAdminUseCase(
		clusterGrantWriter, clusterRelEmitter, clusterTxb, opsRepo,
	).WithAdminChecker(relationStore).
		WithAuditEmitter(clusterAuditEmitter)
	clusterListUC := clusterapp.NewListAdminsUseCase(clusterGrantReader)
	internalClusterHandler := clusterapp.NewHandler(clusterGetUC, clusterGrantUC, clusterRevokeUC, clusterListUC)
	// Публичный близнец — над ТЕМ ЖЕ обработчиком, а не над второй сборкой
	// сценариев (Р3): второй экземпляр сценариев был бы второй копией проверок.
	publicClusterHandler := clusterpublicapp.NewHandler(internalClusterHandler)

	// ── InternalInteractiveClientService — клиент интерактивного входа (IAM-INT-1) ──
	// Аудитория каждого регистрируемого этой службой клиента — аудитория КРАЯ,
	// та же `https://{API_DOMAIN}`, которую запрашивает начальная чеканка и
	// проверяет шлюз. Это решение iam, а не поле запроса (Р2):
	// аудиторию от вызывающего можно задать, но нельзя задать правильно, а неверную
	// край отвергнет намного позже создания клиента.
	interactiveAudience := os.Getenv("KANAME_INTERACTIVE_CLIENT_AUDIENCE")
	if interactiveAudience == "" {
		interactiveAudience = "https://" + cfg.AuthN.ResolveDomain()
	}
	interactiveRepo := kanamepg.NewInteractiveClientRepo(pool)
	// Исполнитель заведения строится над НАШИМ реестром и хешером полосы входа;
	// без хешера — отказ старта, а не клиент без материала (kaname#405, ban #16).
	interactiveProvider, err := interactiveClientProvider(cfg, kanamepg.NewOAuthCeremonyRepo(pool))
	if err != nil {
		log.Fatalf("interactive client executor: %v", err)
	}
	interactiveCreate := interactiveclientapp.NewCreateUseCase(interactiveRepo, interactiveProvider,
		opsRepo, []string{interactiveAudience}, logger)
	interactiveClientHandler := interactiveclientapp.NewHandler(
		interactiveclientapp.NewGetUseCase(interactiveRepo),
		interactiveclientapp.NewListUseCase(interactiveRepo),
		interactiveCreate,
		interactiveclientapp.NewUpdateUseCase(interactiveRepo, opsRepo, logger),
		interactiveclientapp.NewDeleteUseCase(interactiveRepo, interactiveProvider, opsRepo, logger),
	)

	// ── InternalOperationsService — административная лента операций всего кластера ────────────────
	// §«AuthN+AuthZ ВЕЗДЕ»: страж ReBAC в обработчике (relationStore,
	// удовлетворяющий authzguard.RelationChecker) требует system_admin@cluster даже
	// при обходе api-gateway и прямом подключении к :9091. При nil сценарий
	// закрывается отказом, если провязка отсутствует.
	internalOperationsUC := internaloperationsapp.NewListIamOperationsUseCase(opsRepo).
		WithAdminChecker(relationStore)
	internalOperationsHandler := internaloperationsapp.NewHandler(internalOperationsUC)

	// ЗДЕСЬ СОБИРАЛСЯ АВТОРИТЕТ ВЕЛИЧИН — пять административных глаголов и два
	// служебных чтения (разрешение действующей величины и её дельта). Модуль
	// выпилен из службы доступа целиком решением владельца 2026-09-06
	// (PRO-Robotech/kacho#2117, приёмка KAN-QUOTA-1, стадия S4).
	//
	// Порядок был вынужденным и соблюдён: сперва пять потребителей платформы
	// перестали спрашивать домен величин (`quota.authority: not-deployed`,
	// kacho#2596), и только потом снят отвечающий. Обратный порядок оборвал бы
	// каждую их мутацию — недоступность авторитета на пути запроса fail-closed.
	//
	// СОБСТВЕННЫЕ ПОТОЛКИ СЛУЖБЫ ОТСЮДА НЕ УХОДИЛИ (перечень — таблица
	// `config.OwnCeilingKnobs`): их величину объявляет
	// посадка (`config.OwnCeilingsConfig`, проекция в `kaname.own_ceilings`), и
	// арендаторское чтение своего потолка собирается ниже.

	// ── IdentityQuotaService — квоты, носителем которых является ЛИЧНОСТЬ ──
	// Сегодня такой вид один — число аккаунтов, — и он единственный, чей носитель
	// не проект и не аккаунт: аккаунт есть корень аренды, и потолок над ним лежит
	// на том, что существует ДО него.
	//
	// Читается ТОЛЬКО о себе: поля запроса, которым можно было бы назвать чужую
	// личность, у контракта нет. Без этой поверхности потолок над аккаунтом
	// ограничивал бы невидимо — а самообслуживаемое создание аккаунта есть первое
	// действие, к которому платформа приглашает, и отказ на нём без объяснения
	// неотличим от поломки.
	identityQuotaHandler := identityquotaapp.NewHandler(kanamepg.NewIdentityQuotaRepo(pool))

	// ── PermissionCatalogService — публичный каталог модели правил RBAC G ──
	// Проекция в коде (authzmap + domain): без репозитория, без вызова пира, без состояния.
	permissionCatalogHandler := permissioncatalogapp.NewHandler(
		permissioncatalogapp.NewListPermissionCatalogUseCase(catalogSource))

	// ── InternalModuleService — каталог прав ОДНОГО модуля (задача kacho#1034) ──
	//
	// Применитель здесь — ГЛАГОЛЬНЫЙ (`NewVerbApplier`), а не тот, которым
	// пользуется путь старта: он сверяет опору БЕЗУСЛОВНО и требует
	// подтверждения с обоими потолками. Различает их ТИП, а не флаг — подать
	// сюда стартовый нельзя, и это проверяет сборка.
	//
	// Производитель ПЛАНОВОГО состояния (отпечаток модуля и оценки последствий)
	// приходит отдельным портом. Непровязанный, он означает отказ `Plan`, и отказ
	// этот закрывает и `Apply`: подтверждения, которое тот требует, взять негде.
	//
	// Провязан он ЗДЕСЬ и над ТЕМ ЖЕ пулом, что писатель, — иначе отпечаток,
	// показанный планом, читался бы из другой базы, чем сверяет CAS применения.
	// Оценка последствий при этом идёт читающей транзакцией (`READ ONLY`), а её
	// предикаты — те же, что вставляет в свои операторы писатель.
	moduleApplier := modulecatalog.NewVerbApplier(kanamepg.NewCatalogWriteRepo(pool))
	modulePlanState := kanamepg.NewCatalogPlanRepo(pool)
	moduleDelivery := newManifestDeliverySource(cfg.Manifests)
	// Применённая пара редакции модуля (kaname#865) — над ТЕМ ЖЕ пулом, что
	// писатель: `Get` показывает то, что записал оператор сравнения-и-записи.
	moduleEditions := kanamepg.NewCatalogRepo(pool)
	moduleHandler := moduleapp.NewHandler(
		moduleapp.NewPlanUseCase(moduleDelivery, catalogRows, modulePlanState).
			WithAdminChecker(relationStore),
		moduleapp.NewApplyUseCase(moduleDelivery, moduleApplier, opsRepo, logger).
			WithAdminChecker(relationStore),
		moduleapp.NewGetUseCase(catalogRows, moduleEditions).WithAdminChecker(relationStore),
		moduleapp.NewListUseCase(catalogRows).WithAdminChecker(relationStore),
	)

	return &services{
		subscriptionDoor:       relationStore,
		accountHandler:         accountHandler,
		projectHandler:         projectHandler,
		userHandler:            userHandler,
		userInvite:             userInvite,
		internalUserHandler:    internalUserHandler,
		serviceAccountHandler:  saHandler,
		groupHandler:           groupHandler,
		membershipHandler:      membershipHandler,
		roleHandler:            roleHandler,
		accessBindingHandler:   abHandler,
		grantDelegationHandler: grantDelegationHandler,
		internalIAMHandler:     internalIAMHandler,
		resourceRegistrar:      registerResourceUC,
		bindingSizeRecorder:    bindingSizeRecorder,
		internalClusterHandler: internalClusterHandler,
		publicClusterHandler:   publicClusterHandler,

		// Жизненный цикл клиента интерактивного входа.
		interactiveClientHandler: interactiveClientHandler,

		// каталог прав одного модуля — план, применение, два чтения.
		moduleHandler: moduleHandler,

		// квоты личности — единственная поверхность, читаемая о себе самом.
		identityQuotaHandler: identityQuotaHandler,

		// Отзыв токенов (выход).
		sessionRevocationsHandler: sessionRevocationsHandler,

		// Административная лента операций всего кластера.
		internalOperationsHandler: internalOperationsHandler,

		// Неинтерактивная чеканка начального токена (#58).
		internalBootstrapTokenHandler: bootstrapTokenH,

		// Ядро авторизации.
		authorizeHandler: authzServices.authorize,

		// Модель правил RBAC G — публичный каталог назначаемых правил ролей.
		permissionCatalogHandler: permissionCatalogHandler,

		// SAKey (статические ключи класса A; токен чеканит наш подписант).
		saKeysHandler: saKeysH,

		// UserToken (персональные access-токены пользователя, наша чеканка).
		userTokensHandler: userTokensH,

		// ЗНАЧЕНИЕ, которое держат стражи, собираемые в runServe.
		ownGates:          relationStore,
		bindingReconciler: rsabReconciler,
	}
}

// interactiveClientProvider — ЧЕМ исполняются заведение и снятие клиента
// интерактивного входа (задача kaname#313).
//
// Прежде это была развилка посадки: у посадки внешнего поставщика клиента
// заводил поставщик по административной дороге, у своей — наш реестр. Поставщика
// больше нет (kaname#363), и развилки тоже: исполнитель один.
//
// ПОЧЕМУ ВЫБОР ЗДЕСЬ, А НЕ ВЕТВЬЮ В USE-CASE. Глагол ресурса про реестр не
// знает и знать ему нечем: он просит порт завести клиента и снять его.
//
// ИСПОЛНИТЕЛЬ СОБИРАЕТСЯ НАД РЕЕСТРОМ И ХЕШЕРОМ (задача kaname#405): клиент
// конфиденциален, и проверочное значение его секрета нечем положить без
// хешера. Хешер — объявленного класса записи полосы входа, ТОТ ЖЕ
// производитель, которым корень пишет приманку проверяющего (`laneHasher`):
// другой класс сделал бы отказ незаведённому клиенту по цене отличным от
// отказа заведённому, и время ответа перечисляло бы клиентов. Сборка без него —
// ОШИБКА, и корень отказывает в старте, называя недостающее; отката к
// публичному клиенту нет.
func interactiveClientProvider(cfg config.Config, registry kanamepg.ClientSecretStore,
) (interactiveclientapp.ProviderClients, error) {
	h, err := laneHasher(cfg)
	if err != nil {
		return nil, fmt.Errorf("interactive client secret hasher: %w", err)
	}
	return kanamepg.NewOwnInteractiveClientProvider(registry, h)
}

// saKeyIssuanceIsOurs — переведён ли контур выдачи ключей служебных учёток на
// свою чеканку (задача kacho#1120, подфаза Ф4б эпика kacho#896).
//
// ПРЕДИКАТ — ЭНДПОИНТ ОБМЕНА, А НЕ ПОДПИСАНТ. Ключ служебной учётки предъявляет
// подписанное утверждение ВНЕШНИЙ вызывающий, и обменивает он его на нашем
// токен-эндпоинте. Подписант без эндпоинта дал бы ключ, которому некуда пойти:
// зеркала уже нет, а своей дороги ещё нет. Настройка при этом требует включённой
// чеканки от включённого эндпоинта (`ClientTokenConfig.Validate`), поэтому
// «эндпоинт включён» влечёт «подписант есть», а не наоборот.
//
// Отдельная функция, а не ветка внутри сборки: выбор полосы — утверждение о том,
// как посадка выдаёт удостоверение, и его надо уметь спросить, не собирая контур
// целиком (тот же довод, что у выбора полосы обмена докер-токена).
func saKeyIssuanceIsOurs(cfg config.Config) bool {
	// Само условие живёт в настройке (`Config.SAKeyIssuanceIsOurs`), а не здесь:
	// читателей у него три — эта сборка, страж старта над требованием
	// связанного токена (задача kacho#1137) и требование боевого старта в
	// таблице требований (задача #337), — и копии одного условия разошлись бы молча. Функция
	// остаётся точкой, которую спрашивают, не собирая контур.
	return cfg.SAKeyIssuanceIsOurs()
}

// buildSAKeysHandler провязывает обработчик SAKeyService — статические ключи класса A
// служебных учётных записей.
func buildSAKeysHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config,
	logger *slog.Logger) *sakeysapp.Handler {
	saClientRepo := kanamepg.NewSAOAuthClientRepo(pool)

	// ОТВЕТ О ПОСАДКЕ ПРИНИМАЕТСЯ ЗДЕСЬ.
	//
	// Ключевая пара и федеративный ключ обмениваются ТОКЕН-ЭНДПОИНТОМ платформы
	// (`authn.client-token.enabled`), и другого исполнителя обмена у ключа нет:
	// регистрация клиента у внешнего поставщика снята вместе со столбцом, где
	// лежало назначенное им имя (kaname#362). Без эндпоинта эти два вида
	// отвергаются на выдаче синхронно, с именем ручки; секрет эндпоинта не
	// требует и выдаётся. Дороги к поставщику эта сборка не строит вовсе.
	//
	// В БОЕВЫХ РЕЖИМАХ ПОСАДКА БЕЗ ЭНДПОИНТА НЕ ПОДНИМАЕТСЯ. Её отвергает
	// страж старта — строка контура выдачи в таблице требований полос
	// (`config.LaneRequirements`, задача #337); вердикт стража по режимам держит
	// `TestSAKeyIssuanceWarning_ReachedOnlyOutsideProductionModes`, а то, что
	// отказ стража завершает процесс в `main` до этой сборки, —
	// `TestSAKeyIssuanceWarning_ProductionRefusalStopsMainBeforeWiring`. Чарт её
	// не собирает ни в каком режиме (`kaname-svc.requireClientTokenEndpoint`).
	//
	// В РЕЖИМЕ РАЗРАБОТЧИКА ОНА ПОДНИМАЕТСЯ, и потому неработающая выдача
	// называется при старте один раз, с ручкой, которой снимается: молчание
	// оставило бы дефект до пути запроса. Второго отказа старта здесь не
	// заводится — у комбинации он один и живёт в таблице полос.
	ownIssuance := saKeyIssuanceIsOurs(cfg)
	if !ownIssuance {
		// Предупреждение одно на посадку и называет ОБА пути выдачи, которые
		// здесь отказывают: решение у них одно (`saKeyIssuanceIsOurs`), и
		// сборка токенов человека второй строки не печатает.
		logger.Warn("выдача ключевой пары и федеративного ключа служебных учёток и ключевой пары "+
			"человека на этой посадке отказывает: ключ обменивается токен-эндпоинтом платформы, "+
			"а он не включён — выдаётся только секрет",
			"отказывают", "SAKeyService.Issue (KEYPAIR, FEDERATED), UserTokenService.Issue (KEYPAIR)",
			"authn.client-token.enabled", cfg.AuthN.ClientToken.Enabled,
			"снимается", "включением authn.client-token.enabled — контур выдачи на свою чеканку "+
				"(задача kacho#1120)")
	}

	// Надёжный отправитель audit_outbox — пишет строки iam.sa_key.issued /
	// iam.sa_key.revoked внутри транзакции воркера SAKey, атомарно с
	// изменением отображения ключа (запрет #10). Полезная нагрузка не несёт ключевого материала.
	auditEmitter := kanamepg.NewAuditOutboxEmitter(pool)

	issueUC := sakeysapp.NewIssueSAKeyUseCase(saClientRepo, kanamepg.NewPoolTxBeginner(pool), opsRepo)
	// Есть ли у посадки токен-эндпоинт — решается ЗДЕСЬ, в единственном месте
	// сборки: это свойство посадки, и use-case его не выводит.
	if ownIssuance {
		issueUC.WithOwnIssuance()
	}
	// Перечень доверенных издателей федеративного ключа — НАША таблица (kacho#1124):
	// писатель провязан здесь, читает её проверка утверждения на пути запроса.
	issueUC.WithTrustedIssuerWriter(kanamepg.NewTrustedIssuerRepo(pool))
	// Провязать удаление секрета после Issue. После завершения Operation
	// через MarkDone с открытым client_secret этот адаптер pg очищает
	// поле client_secret в сериализованном proto response_data (BYTEA) одним
	// оператором UPDATE строки operations. Идемпотентно.
	issueUC.WithResponseRedactor(kanamepg.NewOpsResponseRedactor(pool, "kaname"))
	issueUC.WithAuditEmitter(auditEmitter)
	// Grace-окно перед затиранием одноразового private_key_pem: поллящий клиент
	// (docker-login / CI / UI) должен успеть прочитать ключ из op.response до его
	// вычистки. Без окна затирание выигрывало гонку и клиент получал пустое поле.
	issueUC.WithRedactGrace(cfg.AuthN.SAKeyRedactGrace)
	// Ограничение срока машинного удостоверения. Ключ служебной учётки — то,
	// чем аутентифицируется машина, а машинные субъекты освобождены от
	// повышения подтверждения (у машины нет второго фактора); исключение действует лишь пока
	// само удостоверение ограничено по времени. DefaultTTL заменяет прежнее
	// «ttl_seconds пропущен ⇒ бессрочно»; MaxTTL — включительный верхний предел.
	issueUC.DefaultTTL = cfg.AuthN.SAKeyDefaultTTL
	issueUC.MaxTTL = cfg.AuthN.SAKeyMaxTTL
	// Вывести сбои удаления секрета (ошибка, исчерпание попыток, перехваченная паника)
	// отдельной горутины — единственного места, где ключ может остаться неочищенным.
	issueUC.WithLogger(logger)
	revokeUC := sakeysapp.NewRevokeSAKeyUseCase(saClientRepo, kanamepg.NewPoolTxBeginner(pool), opsRepo)
	revokeUC.WithAuditEmitter(auditEmitter)
	revokeUC.WithLogger(logger)
	listKeysUC := sakeysapp.NewListSAKeysUseCase(saClientRepo)

	// Посадка контура печатается ВСЕГДА: оператору, разбирающему выдачу, это
	// первое, что нужно знать.
	logger.Info("sa_keys wired", "own_issuance", ownIssuance)

	return sakeysapp.NewHandler(issueUC, revokeUC, listKeysUC)
}

// buildUserTokensHandler провязывает обработчик UserTokenService — персональные
// access-токены пользователя (поток private_key_jwt к НАШЕМУ издателю).
//
// Клиента у внешнего поставщика этот контур не заводит и не снимает (kacho#1121),
// поэтому ни клиента администрирования поставщика, ни приёмника компенсирующих
// намерений здесь нет: компенсировать нечего — единственный след выдачи это своя
// строка, и она либо закоммичена, либо откачена.
func buildUserTokensHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config,
	sharedClock revocationpolicy.Clock, logger *slog.Logger) *usertokensapp.Handler {
	userClientRepo := kanamepg.NewUserOAuthClientRepo(pool)

	// Надёжный отправитель audit_outbox — пишет строки iam.user_token.{issued,revoked}
	// внутри транзакции воркера, атомарно с изменением отображения токена (запрет #10). Нагрузка без
	// ключевого материала.
	auditEmitter := kanamepg.NewAuditOutboxEmitter(pool)

	// Момент выдачи — тем же общим источником, что отсечка (kaname#589).
	issueUC := usertokensapp.NewIssueUserTokenUseCase(userClientRepo, kanamepg.NewPoolTxBeginner(pool), opsRepo).
		WithIssuanceClock(sharedClock)
	// Есть ли у посадки токен-эндпоинт — ТО ЖЕ условие, что у сборки ключей
	// служебных учёток (`saKeyIssuanceIsOurs`), а не второе чтение ручки:
	// ключевую пару человека обменивает тот же эндпоинт. Без него она не
	// выдаётся; предупреждение старта печатает сборка ключей — одно на оба пути.
	ownIssuance := saKeyIssuanceIsOurs(cfg)
	if ownIssuance {
		issueUC.WithOwnIssuance()
	}
	// Post-Issue секрет-редактор: после MarkDone с plaintext private_key_pem этот
	// pg-adapter затирает поле в proto-marshalled response_data (BYTEA) одним UPDATE.
	issueUC.WithResponseRedactor(kanamepg.NewOpsResponseRedactor(pool, "kaname"))
	issueUC.WithAuditEmitter(auditEmitter)
	// Grace-окно перед затиранием одноразового private_key_pem: поллящий клиент
	// (CLI/UI) должен успеть прочитать ключ из op.response до вычистки.
	issueUC.WithRedactGrace(cfg.AuthN.UserTokenRedactGrace)
	// Вывод сбоев удаления секрета отдельной горутины.
	issueUC.WithLogger(logger)
	revokeUC := usertokensapp.NewRevokeUserTokenUseCase(userClientRepo, kanamepg.NewPoolTxBeginner(pool), opsRepo)
	revokeUC.WithAuditEmitter(auditEmitter)
	listUC := usertokensapp.NewListUserTokensUseCase(userClientRepo)

	logger.Info("user_tokens wired", "provider_client_registration", "none", "own_issuance", ownIssuance)

	return usertokensapp.NewHandler(issueUC, revokeUC, listUC)
}

// authzServiceBundle — обработчики, произведённые buildAuthZServices.
type authzServiceBundle struct {
	authorize *authorizeapp.Handler
	// authorizeSvc — исходный сценарий AuthorizeService, вынесенный наружу, чтобы
	// страж InternalIAMService.Check делегировал ТОМУ ЖЕ конвейеру FGA.
	authorizeSvc *service.AuthorizeService
}

// buildAuthZServices собирает AuthorizeService поверх ДВЕРИ РЕШЕНИЯ.
//
// Значение одно, и это главное изменение снятия движка: край и собственные стражи
// спрашивают ОДИН объект. Прежде их было два — голый транспорт у края и обёрнутый
// у стражей, — и держались они порознь именно потому, что край добавлял к ответу
// движка то, чего обёртка не добавляла. Добавлять больше нечего: цепь областей и
// надзор администратора облака форма поднимает своим планом, поэтому «два ответа
// на один вопрос» стало невозможным по устройству, а не по договорённости.
//
// sessions — записи сессий человека: из записи сессии вопроса служба выводит
// доводы способов и момента условия `mfa_fresh` (kaname#133, исход (а)).
//
// catalogSource — каталог модулей из живых строк, тот же экземпляр, что у ролей и
// выдач: из него вопрос анонимной самопроверки берёт глагол типа (kaname#994).
func buildAuthZServices(kanameRepo kanamerepo.Repository, ownGates *authzcascade.Client,
	sessions service.SessionRecords, catalogSource catalog.Source, metricsReg *metrics.Registry, prodMode bool,
	modules moduleidentity.Roster) authzServiceBundle {

	// ClusterAdminChecker — плоский надзор администратора облака. Он спрашивает о
	// типе `cluster`, то есть о ДРУГОМ объекте, чем тот, о котором идёт вопрос, —
	// поэтому потиповое переключение источника его и не захватывало. Теперь он
	// спрашивает ту же дверь: одна форма отвечает на оба вопроса.
	authSvc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           ownGates,
		ClusterAdminChecker: ownGates,
		SessionRecords:      sessions,
		Catalog:             catalogSource,
	})
	whoAmIUC := authorizeapp.NewWhoAmIUseCase(kanameRepo, ownGates)
	// WithCallerAuthority провязывает страж полномочий вызывающего (субъект арендатора может
	// спрашивать решения доступа лишь о себе, об управляемом им ресурсе либо как
	// администратор кластера). ТА ЖЕ дверь решения отвечает на Check полномочий;
	// проверенный пир PDP модуля проходит. Этот страж не является вторым мнением
	// за более узкой проверкой шлюза: запись каталога этих RPC доступна
	// любому аутентифицированному субъекту, поэтому этот страж — единственный.
	//
	// WithInsecureAnonymousPeer — ИСКЛЮЧЕНИЕ для стенда без mTLS, где
	// публичный и внутренний слушатели неразличимы. По умолчанию при сомнении
	// следует отказ; отступает от этого лишь небоевой режим AuthN.
	// Полоса КРАЯ наблюдается ЗДЕСЬ, на границе адаптера: между транспортом
	// публичной службы и решателем встаёт декоратор, считающий вопросы края и
	// вопросы сужателя списочной выдачи. До него счётчик владельца прав видел
	// одну полосу из трёх, и всякое «проверок в секунду», снятое с него, было
	// занижено — на пути чтения по идентификатору ровно вдвое (задача kacho#772).
	//
	// nil-реестр даёт неинструментированный решатель — ровно как у соседней
	// полосы `CheckRelation` выше по файлу.
	var edgeAuthz authorizeapp.Authorizer = authSvc
	if metricsReg != nil {
		edgeAuthz = metrics.NewInstrumentedSubjectAuthorizer(authSvc, metricsReg)
	}
	authzH := authorizeapp.NewHandler(edgeAuthz, whoAmIUC).
		WithCallerAuthority(ownGates).
		WithInsecureAnonymousPeer(!prodMode).
		WithModuleRoster(modules)

	return authzServiceBundle{
		authorize:    authzH,
		authorizeSvc: authSvc,
	}
}

// inviteMailRateLimit — ограничение частоты писем на адрес из настройки, в
// форме порта. Страж старта уже отверг непозитивное; здесь только перенос.
func inviteMailRateLimit(cfg config.Config) outboxtypes.InviteMailRateLimit {
	return outboxtypes.InviteMailRateLimit{
		MaxPerWindow: cfg.Invite.MailRateLimit.MaxPerWindow,
		Window:       cfg.Invite.MailRateLimit.Window,
	}
}
