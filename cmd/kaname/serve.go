// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// serve.go — runServe: полный жизненный цикл бинарника kaname.
// Провязывает пулы → хранилища → службы → gRPC-серверы, HTTP-слушатели и
// дренажи, затем запускает их параллельно с общим спуском остановки, который
// срабатывает по SIGTERM / SIGINT либо по ошибке любой задачи.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/PRO-Robotech/corelib/authz"
	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/observability"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/servicecontract"
	"github.com/PRO-Robotech/corelib/servicehost"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/edgecredential"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/diagnostics"
	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/tokenintrospecthttp"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/restfront"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// grpcStopper — поверхность graceful/forced остановки gRPC-сервера. *grpc.Server
// реализует ее; интерфейс делает stopGRPCBounded юнит-тестируемым без реального
// сервера и сетевого слушателя.
type grpcStopper interface {
	GracefulStop()
	Stop()
}

// stopGRPCBounded даёт серверу gracefulTimeout на дренаж идущих RPC, а затем
// принудительно зовёт Stop(): иначе зависший унарный обработчик держал бы
// GracefulStop вечно, и остановка не завершилась бы никогда.
func stopGRPCBounded(srv grpcStopper, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		srv.Stop()
	}
}

func runServe(cfg config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Страж стоит ЗДЕСЬ, а не только в main: сборка, поднявшая слушатели в обход
	// объявления, отвечала бы клиенту отказом с ПУСТЫМ доменом — то есть молча
	// перестала бы называть себя. Умолчания у величины нет намеренно: то, что
	// построение подставляет молча, предметом стража быть не может (задача
	// продукта kacho#2099, сценарий WIRE-3-03 приёмки WIRE-1).
	if err := refusaldomain.Require(); err != nil {
		return fmt.Errorf("refusal domain: %w", err)
	}

	// logger.level проверен в main (cfg.Validate); SlogLevel здесь отказать не
	// может. Защитный откат на INFO держит композиционный корень всюду определённым.
	logLevel, _ := cfg.Logger.SlogLevel()
	logger := observability.NewSloggerLevel(os.Stdout, logLevel)
	slog.SetDefault(logger)

	for _, w := range cfg.InsecureDevWarnings() {
		logger.Warn(w)
	}
	logAuthnMode(logger, cfg.AuthN.Mode)

	// Посадка процесса — ЧЕРЕЗ ЦЕНТРАЛЬНЫЙ ДЕСКРИПТОР, и до первого соединения
	// с базой (задача продукта kacho#1406). Место выбрано не по вкусу: страж
	// шифрования до собственной базы, стоящий ПОСЛЕ открытия пула, судит
	// соединение, которое уже открыто, — то есть на боевой посадке с
	// `sslmode=disable` открытый канал успел бы состояться.
	posture, perr := describePosture(cfg, logger)
	if perr != nil {
		return fmt.Errorf("посадка процесса: %w", perr)
	}

	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	defer pool.Close()

	// Загрузочный страж: служба не поднимается поверх базы прежней установки.
	//
	// Стоит ПЕРВЫМ из стражей базы и до любой записи: он спрашивает не «посильна
	// ли эта база», а «та ли это база вообще». Схема переименована, переноса нет
	// (решение владельца — только чистая установка), и старт поверх прежней базы
	// завёл бы пустую схему рядом, оставив прежние строки невидимыми. Отказ,
	// отложенный за другие проверки, пришёл бы позже и назвал бы не тот предмет.
	if err := assertNoRetiredSchema(ctx, pool); err != nil {
		return err
	}

	// Загрузочный страж: посадка не вправе обещать базе больше соединений, чем
	// та принимает. Стоит СРАЗУ за созданием пула — до того, как процесс начнёт
	// открывать соединения по работе: проверка, отложенная дальше, узнаёт о
	// расхождении тогда же, когда о нём узнаёт арендатор.
	if err := assertConnBudgetFits(ctx, pool, cfg.Repository.Postgres.ReplicaBudget); err != nil {
		return err
	}

	// ПРОЕКЦИЯ СОБСТВЕННЫХ ПОТОЛКОВ — до любого слушателя (приёмка `KAN-QUOTA-1`,
	// `П25`; довод и цена — own_ceilings_apply.go).
	//
	// Величину объявляет посадка, а списывает единственный атомарный оператор в
	// базе: триггер не читает настройку процесса ни при каком построении, поэтому
	// объявленное обязано доехать до схемы. Это единственный её перевозчик.
	//
	// Стоит ЗДЕСЬ, а не ниже: первый же принятый запрос вправе создать ресурс,
	// чей потолок эта проекция и объявляет. Слушатель, поднятый раньше, открыл бы
	// окно, в котором действует величина ПРЕДЫДУЩЕГО пуска, а журнал уже сообщил
	// новую.
	if err := projectOwnCeilings(ctx, logger, kanamepg.NewOwnCeilingRepo(pool), cfg.OwnCeilings); err != nil {
		return err
	}
	// ПРОЕКЦИЯ ТЕМПА ЗАВЕДЕНИЯ (Ф4 Р5, kacho#1270) — тем же местом и по той же
	// причине: триггер читает величину из строки авторитета, и её объявляет
	// профиль (незаданная — отказ старта стражем полосы).
	if err := projectAdmissionRate(ctx, logger, kanamepg.NewOwnCeilingRepo(pool), cfg); err != nil {
		return err
	}

	// slave-pool wiring (read-replica). Если slave-url
	// настроен и отличается от master URL — отдельный pgxpool для read-TX'ов;
	// иначе slavePool = nil и kanamepg.New() сделает fallback на master.
	var slavePool *pgxpool.Pool
	if slaveDSN := cfg.SlaveDSN(); slaveDSN != "" {
		slavePool, err = coredb.NewPool(ctx, slaveDSN)
		if err != nil {
			return fmt.Errorf("new slave pool: %w", err)
		}
		defer slavePool.Close()
		logger.Info("kaname CQRS slave-pool enabled (read-replica)",
			"slave_url_masked", maskDSN(cfg.Repository.Postgres.SlaveURL))
	} else {
		logger.Info("kaname CQRS slave-pool disabled — Reader-TX fallback to master")
	}

	// Schema = `kaname`. cfg.DSN() уже несет
	// `options=-c search_path=kaname,public` — unqualified-references из repo-кода
	// резолвятся в kaname. operations-repo дополнительно передает схему явно
	// для квалификации SQL-операций.
	//
	// ОБЁРНУТ надстройкой, выбирающей текст отказа по НОСИТЕЛЮ (приёмка kacho#2439):
	// совет «повтори запрос» верен там, где вызывающий держит соединение, и не
	// верен на терминальном исходе операции — там повторять некому, потому что
	// тело исполняется один раз. Оборачивание здесь, в композиционном корне, и
	// РОВНО ОДИН раз: сырой репозиторий, попавший в use-case мимо надстройки,
	// вернул бы синхронный текст в строку операции, и заметить это можно было бы
	// только у арендатора.
	opsRepo := shared.NewTerminalRefusalRepo(operations.NewRepo(pool, "kaname"))

	// Фоновая уборка терминальных строк таблицы операций.
	//
	// Строка заводится КАЖДОЙ мутацией — контракт объявляет мутации асинхронными,
	// и `Operation` возвращается вместо ресурса, — а снятия строк не было ни у
	// одного из восьми владельцев. Порог, предикат и расписание объявлены в
	// `pkg/operations` и `pkg/retention` ОДИН раз: восемь расписаний об одном
	// предмете разошлись бы молча.
	if _, err := operations.StartRetentionSweep(
		ctx, opsRepo, operations.DefaultRetentionConfig(),
		logger,
	); err != nil {
		return fmt.Errorf("фоновая уборка таблицы операций: %w", err)
	}

	// Межсервисный gRPC-вызов: kaname — листовой владелец Account/Project,
	// поэтому исходящих клиентов к соседям у него сейчас нет (другие службы
	// звонят к нему — `iam.v1.ProjectService.Get` и прочее).

	// kanameRepo общий для всех use-case по ресурсам.
	kanameRepo := kanamepg.New(pool, slavePool)

	// ВЫБОРА ПОСТАВЩИКА РЕШЕНИЯ О ДОСТУПЕ ЗДЕСЬ БОЛЬШЕ НЕТ.
	//
	// Он существовал, пока решение принимал внешний движок отношений: переменная
	// окружения выбирала адаптер, адаптер поднимался клиентом, клиент восстанавливался
	// конкретным типом ради полей, которых нет у порта. Ничего этого не осталось —
	// решение вычисляет реляционная форма в базе самой службы, и собирается она там же,
	// где всё остальное, что читает эту базу (см. buildServices).

	// Реестр Prometheus владеет сборщиками /metrics. Создаётся один раз и делится
	// между HTTP-слушателем метрик, перехватчиками gRPC-серверов (обоих
	// слушателей) и декоратором authz-Check. Чистая архитектура: prometheus
	// импортируется только здесь (композиционный корень) и в пакете адаптера метрик.
	metricsReg := metrics.NewRegistry()

	// ЧТО ЭТОТ ДВОИЧНЫЙ ФАЙЛ ГОВОРИТ О СЕБЕ — первым рядом витрины, до всего
	// прочего. Первый вопрос дежурного — «какая версия у меня работает», и служба
	// поставляется ОТДЕЛЬНО от платформы, где такие вопросы закрывает чужой
	// инвентарь. Величины приходят со штампа сборки (buildstamp.go), а не с ручки
	// профиля; непроставленный штамп называет себя словом, а не притворяется
	// версией.
	metricsReg.RegisterBuildInfo(buildVersion, buildRevision)

	// Состояние пулов соединений. До этой строки насыщение пула не наблюдалось
	// ничем: снаружи «запрос ждал свободного соединения» и «запрос сам по себе
	// медленный» выглядят одинаково — растянутой задержкой RPC, — а лечатся
	// противоположным (потолок пула против правки запроса). Разбор величин — у
	// коллектора в pkg/db.
	//
	// Пулов два, и метка `pool` их различает: без неё занятость реплики читалась
	// бы как занятость ведущего. Реплика регистрируется БЕЗУСЛОВНО, даже когда
	// slave-url не настроен и slavePool == nil: решение «пула нет — серий нет»
	// принимает коллектор, поэтому ветки здесь не нужно, а отсутствие серий
	// pool="replica" и есть честный ответ на «есть ли отдельный пул чтений».
	metricsReg.RegisterPoolStats("primary", pool)
	metricsReg.RegisterPoolStats("replica", slavePool)

	// КАТАЛОГ МОДУЛЯ: одно чтение, страж паритета и снимок — в таком порядке и
	// ДО сборки служб (задача kacho#1816).
	//
	// Читатель живого множества ОДИН (`kanamepg.NewCatalogRepo`), и вызывающих у
	// него двое: страж, сверяющий строки с литералом, и снимок, которым отвечают
	// читатели на пути запроса. Дай каждому свой запрос — получишь два места об
	// одном предмете, и разойдутся они молча. Отсюда величина, которую
	// утверждает проба `IAM-CT-2-01`: операторов к таблицам каталога за время
	// старта ровно столько, сколько шлёт сам страж.
	//
	// ПОЧЕМУ ЗДЕСЬ, А НЕ В ЗАДАЧАХ СТАРТА, где страж стоял прежде. Снимок нужен
	// use-case'ам создания и правки роли, реконсайлеру и адаптеру выдач — то
	// есть до `buildServices`. Порядок, ради которого страж заводился, при этом
	// СОХРАНЁН: пересчёт проекции «роль → тип × глагол» идёт задачей ниже, то
	// есть по-прежнему ПОСЛЕ стража, и расхождение не проявляется отказом
	// пересчёта.
	//
	// Отказ ФАТАЛЕН и приходит РАНЬШЕ, чем прежде: расхождение не рассасывается
	// повторами, а снаружи выглядит как «прав не выдали». Пустой каталог — это
	// «условие не создано» (миграции не применены), и он тоже обязан назваться
	// прямо, а не отвергать все правила арендатора разом.
	// ДОСТАВКА МАНИФЕСТОВ — ПЕРЕД стражем паритета (задача kacho#1875).
	//
	// Манифест и есть та опорная сторона, на которую страж переезжает (kacho#1861).
	// Сорванная доставка обязана назваться своим именем РАНЬШЕ, чем о
	// расхождении заговорит страж: иначе оператор прочтёт отказ доставки как
	// расхождение каталога и пойдёт чинить не то.
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}

	// ОПОРА ПАРИТЕТА — сразу за чтением доставки и ДО первой записи (kacho#1861).
	//
	// Опора складывается из ДВУХ слагаемых: перечень, порождённый сборкой, и то,
	// что объявила доставка. Пока слагаемое было одно, живая строка, которой
	// образ не несёт, отвергалась при любом входе — то есть объявить свой модуль
	// данными было нельзя, и установка в чужом облаке требовала пересборки
	// образа. При этом соседняя половина того же старта — композиция модели
	// прав — новый тип уже принимает; две половины противоречили друг другу.
	//
	// Отказ ФАТАЛЕН и приходит РАНЬШЕ применения: он означает ровно одно —
	// доставка ПЕРЕОПРЕДЕЛЯЕТ форму строки, которую образ уже объявил. Мягкий
	// проход здесь отдал бы данным оператора власть переписывать имя типа, по
	// которому выдаются права.
	catalogAnchor, anErr := modulecatalog.AnchorOfDelivery(deliveredManifests)
	if anErr != nil {
		return anErr
	}
	// Расширение опоры называется ПОИМЁННО, а не одним счётчиком: оно законно,
	// но молчаливым быть не вправе — по той же причине, по какой поимённо
	// называется снятое. Строка, которой образ не несёт, есть решение оператора,
	// и оператор обязан видеть его в журнале старта.
	if added := catalogAnchor.AddedRows(); len(added) > 0 {
		logger.Info("доставка расширила опору паритета сверх образа",
			slog.Int("added", len(added)),
			slog.Any("rows", added))
	}

	// МОДЕЛЬ ПРАВ — сразу за чтением доставки и ДО всего, что её читает
	// (задачи kacho#1969, kacho#2002).
	//
	// Место выбрано не «поближе к манифестам»: установка запрещена после первого
	// чтения модели, а читают её пути вердикта и разбора прав ниже. Значит
	// композиция обязана встать здесь — раньше первого читателя и позже
	// доставки, из которой она собирается. Другого окна между этими двумя
	// границами нет.
	//
	// Отказ ФАТАЛЕН на каждом звене: собранная модель, не прошедшая допуск, —
	// это данные оператора, расширяющие модель прав установки, и мягкий проход
	// здесь означал бы контроль, который не откажет ни разу.
	//
	// Отчёт композиции корень сохраняет: из него шаг «модель против каталога»
	// ниже узнаёт, какой модуль принёс в модель процесса тип вне канона
	// (kaname#865, Д10) — второй композиции для этого не заводится.
	composedReport, cErr := installComposedModel(logger, deliveredManifests)
	if cErr != nil {
		return cErr
	}

	// ПРИМЕНЕНИЕ ДОСТАВЛЕННОГО — между чтением доставки и стражем паритета
	// (задача kacho#1034).
	//
	// Применитель — ЕДИНСТВЕННЫЙ писатель строк каталога в прод-коде; до этой
	// провязки его не звал никто, и каталог наполнял посев миграции, то есть
	// объявленное манифестом состояние доезжало до базы только пересборкой
	// образа. Довод о месте, порядке и о том, почему отказ фатален, —
	// документ `docs/engineering/architecture/module-catalog-applier-runs-at-boot.md`;
	// порядок держит гейт `module_catalog_apply_wiring_test.go`, а не этот
	// комментарий.
	//
	// Страж НИЖЕ судит то, что применитель ТОЛЬКО ЧТО записал: ConfigMap с
	// манифестами — данные оператора, а не релиза, и в одиночку он не вправе
	// расширить каталог за пределы того, что знает образ.
	catalogApplier := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(pool))
	// Наблюдатель — ОТДЕЛЬНЫМ оператором, а не цепочкой к конструктору: гейт
	// провязки (`module_catalog_apply_wiring_test.go`) опознаёт связывание по
	// вызову конструктора в правой части, и цепочка увела бы применителя
	// из-под его наблюдения — молча.
	catalogApplier = catalogApplier.WithObserver(metricsReg.NewModuleCatalogRecorder())
	// Применённые ПОЛНОСТЬЮ — ровно они едут применителям ролей и посева ниже
	// (kaname#865, Д3): модуль, пропущенный как младшая редакция либо
	// отвергнутый конфликтом содержимого, не получает и их. Опора паритета выше
	// и страж ниже судят доставку целиком, как прежде.
	appliedManifests, notAppliedManifests, aErr := applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests)
	if aErr != nil {
		return aErr
	}

	// МОДЕЛЬ ПРОТИВ КАТАЛОГА — сразу за применителем каталога и ДО стража
	// паритета, ролей и посева (kaname#865, Д10). Модель процесса выше собрана
	// из всей доставки; модуль, документ которого каталог пропустил либо
	// отверг и который принёс в модель тип вне канона, останавливает пуск:
	// модель доступа не собирается из документа, который каталог отверг. Довод
	// — шапка `model_catalog_agreement.go`; порядок и доводы держит гейт
	// `model_catalog_agreement_wiring_test.go`, а не этот комментарий.
	if mcErr := assertModelAgreesWithCatalog(logger, notAppliedManifests, composedReport); mcErr != nil {
		return mcErr
	}

	catalogRepo := kanamepg.NewCatalogRepo(pool)
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo, catalogAnchor)
	// Перепись печатается ВСЕГДА, независимо от исхода: без неё «ноль
	// расхождений» неотличимо от «ноль прочитанного».
	logger.Info("перепись каталога модуля",
		slog.Int("anchor_modules", catalogCensus.AnchorModules),
		slog.Int("anchor_resources", catalogCensus.AnchorResources),
		slog.Int("anchor_verbs", catalogCensus.AnchorVerbs),
		slog.Int("row_modules", catalogCensus.RowModules),
		slog.Int("row_resources", catalogCensus.RowResources),
		slog.Int("row_verbs", catalogCensus.RowVerbs),
		slog.Int("retired_modules", catalogCensus.RetiredModules),
		slog.Int("retired_resources", catalogCensus.RetiredResources),
		slog.Int("retired_verbs", catalogCensus.RetiredVerbs),
		slog.Int("missing", len(catalogCensus.MissingRows)),
		slog.Int("withdrawn", len(catalogCensus.WithdrawnRows)),
		slog.Int("extra", len(catalogCensus.ExtraRows)),
		slog.Int("anchor_added_by_delivery", len(catalogCensus.AnchorAdded)))
	// Снятое называется ПОИМЁННО, а не одним счётчиком. Счётчик отвечает на
	// вопрос «сколько», а оператору, читающему журнал старта, нужен другой:
	// ЧТО именно перестало выдаваться. Снятие проходит молча by construction —
	// оно и заведено затем, чтобы не ронять пуск, — поэтому единственное место,
	// где его видно, это здесь.
	if len(catalogCensus.WithdrawnRows) > 0 {
		logger.Info("строки каталога сняты решением — старт продолжается",
			slog.Any("rows", catalogCensus.WithdrawnRows))
	}
	if catErr != nil {
		return fmt.Errorf("каталог модуля: %w", catErr)
	}
	// Снимок наполняется ТЕМИ ЖЕ строками, которые прочитал страж, — своего
	// чтения не заводит. ОБЕИМИ половинами: снятые строки страж читает и так, и
	// до этой правки они здесь выбрасывались — отчего свежезапущенный процесс
	// отвечал арендатору пустым перечнем снятого до первого обновления
	// (kacho#1814). Пара берётся одним методом переписи, чтобы её нельзя было
	// разлучить по дороге.
	catalogSnapshot, csErr := catalog.NewSnapshot(catalogCensus.Halves(), catalogRepo,
		logger.With(slog.String("component", "catalog_snapshot")),
		metricsReg.NewCatalogSnapshotRecorder())
	if csErr != nil {
		return fmt.Errorf("снимок каталога модуля: %w", csErr)
	}

	// Каталог прав — ОДНО чтение на процесс, и оно здесь, потому что первым его
	// спрашивает производитель правил роли (ниже). Прежде реестр загружался
	// перед порогом acr; все его читатели берут ЭТО связывание. Второй
	// загрузки не заводится: она разошлась бы с первой молча.
	//
	// Число читателей здесь НЕ называется: оно живёт в шапке самого зеркала
	// под машинным маркером и сверяется гейтом с разбором дерева. Здесь
	// стояло «три читателя» — второе место об одном числе, и оно состарилось
	// молча на четвёртом.
	permRegistry, err := seed.LoadPermissionRegistry(ctx, logger)
	if err != nil {
		return fmt.Errorf("load permission catalog: %w", err)
	}

	// ПРИМЕНЕНИЕ РОЛЕЙ ДОСТАВЛЕННОГО — ПОСЛЕ стража паритета каталога
	// (задача kacho#2010).
	//
	// Применитель ролей — единственный писатель строк `kaname.roles` в
	// прод-коде помимо миграции; до этой провязки его не звал никто, и
	// объявленная манифестом роль доезжала до базы только пересборкой образа.
	// Довод о месте, порядке и о том, почему отказ фатален, — шапка
	// `module_roles_apply.go`; порядок держит гейт
	// `module_roles_apply_wiring_test.go`, а не этот комментарий.
	//
	// Каталожный факт берётся из ТЕХ ЖЕ живых строк, которые прочитал страж:
	// третьего чтения каталога на старте не заводится.
	rolesRights, rightsActions, rightsUnattributed, rrErr := buildModuleRoleRights(
		catalogCensus.Live, permRegistry)
	logger.Info("производитель правил роли модуля",
		slog.Int("catalog_actions", rightsActions),
		slog.Int("unattributed_entries", rightsUnattributed))
	if rrErr != nil {
		return fmt.Errorf("роли модуля: %w", rrErr)
	}
	rolesApplier := moduleroles.NewApplier(moduleroles.NewRepoTxRunner(kanameRepo), rolesRights)
	if raErr := applyDeliveredModuleRoles(ctx, logger, rolesApplier, appliedManifests); raErr != nil {
		return raErr
	}
	// Роли СВОЕГО манифеста службы (kaname#1003) — тем же применителем, после
	// доставленных: новая роль модуля iam заводится объявлением манифеста образа,
	// а не миграцией. Довод — шапка `applyImageModuleRoles`. Свой манифест читается
	// здесь и тот же связанный идентификатор уходит ниже применителю посева.
	ownManifest, omErr := loadOwnManifest(logger)
	if omErr != nil {
		return omErr
	}
	if riErr := applyImageModuleRoles(ctx, logger, rolesApplier, ownManifest); riErr != nil {
		return riErr
	}

	// ПРИМЕНЕНИЕ ПОСЕВА — ПОСЛЕ применения ролей (задачи kacho#2452, kaname#106).
	//
	// Сначала СВОЙ манифест службы, встроенный в образ: группу пишущих кортежи
	// `module-relation-writers` и её выдачу заводит сама служба, на любой
	// установке. Затем ДОСТАВЛЕННЫЕ манифесты: служебные учётки модулей
	// платформы, их членства и выдачи заводит этот путь, а не миграция службы —
	// миграция применяется везде, включая установку без платформы, и заводила
	// там пять личностей чужого продукта. Условием доставленных служит ДОСТАВКА
	// — её кладёт зонтичный чарт платформы и не кладёт чарт самостоятельной
	// службы; своё доставкой не связано.
	//
	// Свой манифест читается ЗДЕСЬ и подаётся применителю посева ОТДЕЛЬНЫМ
	// доводом — в перечень доставки он не подмешивается: доставку читают
	// несколько потребителей старта, а получатель у своего манифеста ровно один
	// (Р3 приёмки MRW-1). Довод о месте, порядке и о том, почему отказ фатален,
	// — шапка `module_seed_apply.go`; порядок и раздельность доводов держит гейт
	// `module_seed_apply_wiring_test.go`, а не этот комментарий.
	//
	// Доставленные едут сюда ПРИМЕНЁННЫМИ (kaname#865, Д3): модуль доставки,
	// пропущенный как младшая редакция либо отвергнутый конфликтом, посева не
	// получает. Свой манифест службы этим отбором НЕ сужается и подаётся всегда:
	// он встроен в образ, доставкой не связан, и порядок редакций доставки о нём
	// не говорит ничего — модуль `iam` доставки и встроенный документ суть два
	// разных входа.
	seedApplier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	if seErr := applyModuleSeed(ctx, logger, seedApplier, ownManifest, appliedManifests); seErr != nil {
		return seErr
	}

	// Подключаем Prometheus-Recorder и логгер к default-registry LRO-worker'а и
	// поднимаем его dispatcher ДО приема трафика. Без этого default-registry держит
	// NopRecorder (live terminal-write/inflight метрики мертвы), а operations.Ready()
	// остается false до первого Run, поэтому readiness не отражает worker.
	// ConfigureDefault обязан предшествовать Start.
	lroRec := metricsReg.NewLRORecorder()
	// AccessBinding.Create исполняется на этом реестре по умолчанию. Operation.done
	// означает, что выдача надёжно зафиксирована; доступ выдачи на объект
	// материализуется в конечном счёте (синхронное сведение после фиксации,
	// событие в той же фиксации и страховочная периодическая подмётка), а не
	// ждёт op.done.
	if err := operations.ConfigureDefault(
		operations.WithRecorder(lroRec),
		operations.WithLogger(logger),
	); err != nil {
		return fmt.Errorf("configure LRO default-registry: %w", err)
	}
	operations.Start()

	// Orphan-reconciler backstop: разрешает осиротевшие done=false операции умершего
	// процесса (kill-9 / истекший terminal-write budget) в терминал по
	// committed-реальности ресурса. Boot-sweep + периодический фон; non-fatal.
	startLROReconciler(ctx, pool, kanameRepo, catalogSnapshot, lroRec, logger)

	// Надёжная страховка одноразовых учётных данных, выложенных в ответы
	// ЗАВЕРШЁННЫХ операций. Сверщик выше их не покрывает: он берёт done=false, а
	// эти строки к моменту выкладки учётных данных уже done=true.
	if err := startSecretBackstop(ctx, pool, cfg, logger); err != nil {
		return fmt.Errorf("secret backstop: %w", err)
	}

	// Снятие истёкших удостоверений (задача kacho#1264). Провязка ОБЯЗАТЕЛЬНА и
	// стоит рядом с уборщиком секретов: уборщик без вызывающего — механизм,
	// который выглядит существующим и не делает ничего, а таких в этом сервисе
	// уже два.
	startExpiredCredentialReclaim(ctx, pool, cfg, metricsReg, logger)

	// Своя чеканка токенов (задача kacho#897): ключница, подписывающий ключ и
	// подписант. Собирается ДО поверхностей, потому что от неё зависят обе —
	// выдача докер-токена и публикация нашей записи набора.
	signingKeystore, tokenSigner, err := buildTokenSigning(ctx, pool, cfg, logger)
	if err != nil {
		return fmt.Errorf("своя чеканка токенов: %w", err)
	}
	startSigningKeyMaintenance(ctx, signingKeystore, logger)

	// ЛИЧНОСТИ МОДУЛЕЙ (kaname#984) — ОДИН перечень на все пути признания
	// вызывающего, прочитанный ОДИН раз и ДО сборки служб (kaname#987): обе
	// политики вызывающего, пол системного читателя, посредник записи отношений,
	// допуск пира у службы решений, обработчик внутреннего Check, полоса входа и
	// поверхность выдачи получают ЭТОТ объект. Второго чтения нет: у нулевого
	// перечня разная семантика у потребителей — политике это отказ, обработчику
	// Check «сужать некого», — и чтение, глотающее ошибку, развело бы их молча.
	// Модулем признаётся только объявленная пара, и признанная личность зовёт
	// только методы своего профиля.
	//
	// Центры, к которым привязаны личности (kaname#988), читаются ЗДЕСЬ, при
	// подъёме: нечитаемый файл центра — отказ старта, а не перечень, молча
	// признающий меньше, чем объявила установка.
	moduleRoster, err := cfg.AuthN.LoadModuleRoster()
	if err != nil {
		return fmt.Errorf("module identities: %w", err)
	}

	svcs := buildServices(pool, slavePool, opsRepo, kanameRepo, kanameRepo, catalogSnapshot,
		// Тот же экземпляр читателя, что прочитал строки для стража паритета
		// и для снимка: третьего чтения каталога на старте не заводится.
		catalogRepo,
		metricsReg, cfg, moduleRoster, tokenSigner, logger)

	// Полоса входа паролем, регистрация и наша сессия (Ф3 kacho#1269, Ф4
	// kacho#1270) — строится на каждом старте (kaname#363): отказ сборки есть
	// отказ старта с именем ручки. Собирается ПОСЛЕ служб: регистрация
	// ПРИНИМАЕТ тот же реконсайлер материализации привязки, что путь запроса
	// (`sign_in_lane_reconciler_test.go`), а не строит свой; и ДО уборки,
	// потому что её таблицы — предметы той же петли.
	lane, err := buildLoginLane(ctx, cfg, moduleRoster, pool, kanameRepo, svcs.bindingReconciler, metricsReg, logger)
	if err != nil {
		return err
	}

	// Фоновая уборка таблиц, чей рост задаёт внешний (задача kacho#1292). Три
	// предмета обслуживает ОДНА петля: три расписания об одном предмете
	// разошлись бы молча. Здесь — только СБОРКА: запуск стоит после последнего
	// отказа старта (`startRetentionSweeps`, #253).
	retentionSweeper, err := buildRetentionSweeper(pool, cfg, metricsReg, lane.retentionReapers(), logger)
	if err != nil {
		return err
	}
	// `InternalHumanSessionService.Resolve` — внутренний слушатель, исполнитель
	// от полосы (Ф3-45).
	svcs.humanSessionHandler = lane.resolveHandler()
	// `UserService/ResetSecondFactor` (Ф12 Р10) — теми же хранилищами, что
	// полоса (Ф12-37).
	if reset := lane.resetSecondFactorUseCase(kanameRepo, opsRepo); reset != nil {
		svcs.userHandler.WithResetSecondFactor(reset)
	}
	// `UserService/ResetAccessKeys` (kaname#638) — теми же хранилищами, что
	// полоса: ключи и их испытания, отсечка личности.
	if reset := lane.resetAccessKeysUseCase(kanameRepo, opsRepo); reset != nil {
		svcs.userHandler.WithResetAccessKeys(reset)
	}
	// `AccessKeyService` (Ф7, kacho#1273) — шесть глаголов ключа доступа теми
	// же хранилищами, что полоса.
	svcs.accessKeyHandler, err = lane.accessKeyHandler(cfg, opsRepo, metricsReg, logger)
	if err != nil {
		return err
	}

	// gRPC servers. PrincipalExtract-interceptor читает
	// x-kacho-principal-* metadata-headers, которые api-gateway auth-interceptor
	// прокидывает после JWT-валидации, и кладет в ctx через operations.WithPrincipal.
	// Use-case'ы вызывают operations.NewFromContext(ctx, ...) → реальный principal
	// попадает в operations.principal_*.
	productionMode := cfg.AuthN.Mode.IsProduction()
	// SEC-H (corelib SEC-B): серверные учётные данные mTLS, включаемые по
	// слушателю. enable=false (по умолчанию) → без защиты (обратная совместимость
	// разработки, сценарий SEC-H-01); enable=true → RequireAndVerifyClientCert
	// (сертификат сервера и CA клиента), отказ на отсутствующей или негодной
	// тройке сертификатов (без молчаливого спуска к незащищённому, сценарий
	// SEC-H-02). Публичный и внутренний слушатели — два независимых ребра.
	// Загружается отдельным загрузчиком envconfig из
	// KANAME_{PUBLIC,INTERNAL}_SERVER_MTLS_* (как у vpc).
	mtlsCfg, err := config.LoadMTLS()
	if err != nil {
		return fmt.Errorf("load server mTLS config: %w", err)
	}
	publicServerCreds, err := mtlsCfg.PublicServerCreds()
	if err != nil {
		return fmt.Errorf("public listener mTLS creds: %w", err)
	}
	internalServerCreds, err := mtlsCfg.InternalServerCreds()
	if err != nil {
		return fmt.Errorf("internal listener mTLS creds: %w", err)
	}

	// Серверный TLS HTTP-слушателя: слушатель Prometheus /metrics (:9095) был
	// ОТКРЫТЫМ ТЕКСТОМ. TLS по ребру, по умолчанию выключен (как SEC-H
	// grpcsrv.TLSServer): enable=false → nil *tls.Config → net.Listener остаётся
	// открытым текстом (побайтно как сегодня, стенд dev/newman не меняется);
	// enable=true → clientAuthMode ребра, объявленный полем TLS профиля
	// поверхности (server-tls-only — только шифрование, умолчание ребра метрик без
	// сертификата сборщика; mutual — RequireAndVerifyClientCert).
	// mtlsCfg.Validate() отказывает на старте, если ЛЮБОЕ ребро включено с
	// неполным для своего режима набором сертификатов либо с
	// неизвестным clientAuthMode.
	if verr := mtlsCfg.Validate(); verr != nil {
		return fmt.Errorf("listener mTLS config invalid: %w", verr)
	}
	metricsTLSConfig, err := mtlsCfg.MetricsServerTLSConfig()
	if err != nil {
		return fmt.Errorf("metrics listener mTLS config: %w", err)
	}
	// Серверный TLS слушателя jwks-proxy: ОДНОСТОРОННИЙ (по умолчанию
	// server-tls-only — проверяющий реестра предъявляет лишь доверие к серверу и
	// никогда клиентский сертификат; mutual сломал бы свойство проверяющего
	// «не тронут»). По умолчанию выключен → nil → слушатель остаётся открытым
	// текстом (в разработке побайтно прежний).
	jwksProxyTLSConfig, err := mtlsCfg.JWKSProxyServerTLSConfig()
	if err != nil {
		return fmt.Errorf("jwks-proxy listener mTLS config: %w", err)
	}
	// docker-token listener (:9096) server-TLS: ONE-WAY. По нему едет HTTP Basic,
	// чей пароль — приватный ключ ключа служебной учётки (сервер его не хранит,
	// срок жизни не ограничен), поэтому в production plaintext здесь запрещён —
	// requireRegistryTokenTLS ниже.
	registryTokenTLSConfig, err := mtlsCfg.RegistryTokenServerTLSConfig()
	if err != nil {
		return fmt.Errorf("registry-token listener mTLS config: %w", err)
	}
	restTLSConfig, err := mtlsCfg.RESTServerTLSConfig()
	if err != nil {
		return fmt.Errorf("public REST front mTLS config: %w", err)
	}
	internalRESTTLSConfig, err := mtlsCfg.InternalRESTServerTLSConfig()
	if err != nil {
		return fmt.Errorf("internal REST front mTLS config: %w", err)
	}

	// ОБЪЯВЛЕНИЕ собственных REST-фронтов — единственное, и читают его двое:
	// самоотчёт о посадке ниже и профили поверхностей, по которым фронты
	// поднимаются. Порознь прочитанные, эти двое разошлись бы молча
	// (см. тип ownRESTFront).
	restFront := ownRESTFront{addr: cfg.APIServer.RESTListenAddress(), tls: restTLSConfig}
	internalRESTFront := ownRESTFront{
		addr: cfg.APIServer.InternalRESTListenAddress(),
		tls:  internalRESTTLSConfig,
	}

	if err := requireGRPCListenerMTLS(productionMode, mtlsCfg); err != nil {
		return err
	}
	if err := requireRegistryTokenTLS(productionMode,
		cfg.APIServer.RegistryToken.ListenAddress(), mtlsCfg); err != nil {
		return err
	}
	if err := requireIssuingListenerAsksForACertificate(cfg, mtlsCfg); err != nil {
		return err
	}
	if err := requireLoginLaneTLS(productionMode, cfg, mtlsCfg); err != nil {
		return err
	}
	// Транспорт остальных HTTP-рёбер. Их ручки задавал ЗОНТИЧНЫЙ чарт монорепо;
	// у отдельно поставленной службы его нет, а адреса всех трёх приходят
	// умолчанием процесса и потому непусты всегда — то есть без этого стража
	// профиль, о них умолчавший, поднимал три слушателя открытым текстом.
	if err := requireHTTPEdgeTLS(productionMode, iamHTTPEdges(
		cfg.APIServer.MetricsListenAddress(),
		cfg.APIServer.JWKSProxy.ListenAddress(),
		cfg.APIServer.RESTListenAddress(),
		cfg.APIServer.InternalRESTListenAddress(),
		mtlsCfg,
	)); err != nil {
		return err
	}
	// Раздельность поверхностей есть свойство СОКЕТА: «внутреннее не
	// опубликовано наружу» проверяемо ровно тогда, когда оно недосягаемо.
	// Совпавшие адреса делают требование невыполнимым by construction, и делают
	// это МОЛЧА — порт занимает тот слушатель, что успел подняться первым.
	if err := requireRESTUpstreamCredential(productionMode,
		cfg.APIServer.RESTListenAddress(),
		cfg.APIServer.InternalRESTListenAddress(),
		mtlsCfg,
	); err != nil {
		return err
	}
	// Рубеж внутреннего фронта бывает только транспортным: своего он не заводит,
	// а к собственному слушателю идёт СВОИМ удостоверением — значит «кому позволено
	// дотянуться» решает рукопожатие и больше ничто (см. internalrestclientauth.go).
	if err := requireInternalRESTMutualClientAuth(productionMode,
		cfg.APIServer.InternalRESTListenAddress(), mtlsCfg,
	); err != nil {
		return err
	}
	// А ЧЕМ фронт называется дальше — предмет отдельный, и решается он здесь.
	// Рукопожатие выше отвечает «кому позволено дотянуться»; пер-RPC политика
	// вызывающего спрашивает следующее: чей лист предъявлен её слушателю. Лист
	// этот — собственный лист службы, и читается он из того файла, который фронт
	// фактически предъявляет (см. ownfronthop.go).
	ownFrontSAN, err := ownFrontHopSAN(mtlsCfg, cfg.AuthN.TrustDomain())
	if err != nil {
		return err
	}
	if err := requireOwnFrontHopIdentity(productionMode,
		cfg.APIServer.InternalRESTListenAddress(),
		cfg.APIServer.RESTListenAddress(),
		mtlsCfg, cfg.AuthN.TrustDomain(), ownFrontSAN,
	); err != nil {
		return err
	}
	// Различимость адресов поверхностей судится НЕ ЗДЕСЬ, а там, где собран срез
	// подъёма: сверять надо ВСЕ поверхности, а адреса не-gRPC приходят профилем
	// поверхности, которого на этом шаге ещё нет. Прежде страж стоял здесь и
	// сверял четыре адреса из восьми (kacho#2639).

	// Самоотчёт о security-posture: ПОСЛЕ boot-guard'ов (cfg.Validate() в main,
	// mtlsCfg.Validate() и production-гейт обоих gRPC-листенеров выше — конфиг
	// уже ПРИНЯТ процессом) и ДО подъёма листенеров. authz_check — факт проводки
	// PDP-бэкенда (iam гейтит свои RPC внутренними floor'ами поверх relation-store,
	// а не чужим Check). Production-posture гейт обязан утверждать на этом
	// наблюдаемом факте, а не на хранимом конфиге (см. observability.BootPosture).
	// Половина ПОЛНОТЫ ПРОВЯЗКИ у полосности посадки личности (задача kacho#1125).
	// Стоит ЗДЕСЬ, а не в config.Validate(): настройка собранных объектов не
	// видит и выразить их отсутствие не может. Отказ — отдельный текст, и он
	// НЕ заменяется посадочной проверкой.
	//
	// Перепись печатается и на успешном старте: «ноль недостижимых записей»
	// обязано быть отличимо от «каталог не читали».
	laneWiring := observeLaneWiring(ctx, tokenSigner, lane.signInMethods(), lane, logger)
	logger.Info("identity posture lane wiring", laneWiringCensus(laneWiring)...)
	if err := config.ValidateLaneWiring(cfg, laneWiring); err != nil {
		return fmt.Errorf("identity posture lane: %w", err)
	}

	observability.LogBootPosture(logger,
		bootPosture(posture, cfg, mtlsCfg, svcs.ownGates.FormReachable(),
			restFront, internalRESTFront))

	// Политика ВЫЗЫВАЮЩЕГО по RPC для внутреннего слушателя (аудит C1/C3/H3/M1).
	// iam здесь НЕ проверяет отношения конечного пользователя повторно — api-gateway
	// единственная входная дверь авторизации платформы (проверяет JWT и выполняет
	// проверку отношений пользователя через iam.Check). :9091 исполняет лишь то,
	// КТО ВПРАВЕ ЗВАТЬ каждый RPC:
	//   - Пол: каждый внутренний RPC требует проверенного сертификата модуля mTLS
	//     (в боевом режиме отказ, в разработке пустая операция, как RelationWriteGate).
	//   - Только край: привилегированные административные RPC за краем
	//     (GatewayFrontedInternalRPCs) вправе звать ТОЛЬКО SA api-gateway; прямой
	//     вызов от любого другого модуля → ОТКАЗ в боевом режиме (закрывает C1/C3:
	//     скомпрометированный модуль плоскости данных не поднимет права через :9091).
	//   - По SAN: MintBootstrapToken (SANRestrictedInternalRPCs) допускает ТОЛЬКО
	//     SPIFFE SAN клиентских сертификатов, перечисленные оператором в
	//     authn.bootstrap-mint.allowed-client-sans, — исполняется в КАЖДОМ режиме,
	//     а пустой перечень отказывает всем (у выпуска токена администратора
	//     кластера нет вызывающего по умолчанию; через api-gateway он тоже
	//     недостижим — REST-маршрута к нему у края нет). Config.Validate вдобавок
	//     не даёт стартовать боевому бинарнику, у которого выпуск включён при
	//     пустом перечне.
	// Записи fga-proxy (Register/Unregister) НЕ входят в набор «только край» и
	// судятся в обработчике стражем RelationWriteGate (fga_writer): их зовут SA
	// модулей vpc/compute/nlb, а не край.
	//
	// Хоп собственного REST-фронта объявляется ЗДЕСЬ и допускается ровно к полу:
	// круг края он не проходит никогда, потому что краем не является и о том,
	// кто за ним стоит, ничего не сообщает. Величина взята из сертификата,
	// который фронт предъявляет, — разойтись с проводом ей нечем.
	//
	// ЛИЧНОСТИ МОДУЛЕЙ (kaname#984) — перечень прочитан выше, до сборки служб,
	// и это тот же объект, что получили обработчики (см. `moduleRoster`).
	internalCallerPolicy := authzguard.NewCallerPolicy(productionMode, authzguard.GatewayFrontedInternalRPCs()).
		WithSANAllowlist(map[string][]string{
			authzguard.BootstrapMintFullMethod: cfg.AuthN.BootstrapMint.AllowedSANs(),
		}).
		WithOwnFrontHop(ownFrontSAN).
		WithModuleRoster(moduleRoster)

	// ПОЛ `system_viewer` по RPC на наборе внутренних ЧИТАЮЩИХ RPC (authN+authZ
	// исполняются везде: страж читающих RPC уровня viewer). Для ReadFloorRPCs он
	// требует, чтобы SA МОДУЛЯ ВЫЗЫВАЮЩЕГО (выводится из проверенного SAN mTLS тем
	// же выводом, что у стража fga-proxy) держал грубое отношение кластера
	// `system_viewer@cluster:cluster_root`, — через ТОТ ЖЕ порт RelationChecker
	// (дверь решения), что у RelationWriteGate / iam.Check. По умолчанию ВЫКЛЮЧЕН:
	// dev/newman (prod=false) → сквозной проход БЕЗ действия (стенд newman
	// побайтно прежний). В боевом режиме отказ: нет проверенного SAN →
	// PermissionDenied; ошибка вычислителя прав → Unavailable. ОСВОБОЖДЕНЫ (НЕТ
	// в ReadFloorRPCs): Check точки решения (INV-FLOOR-5), IsRevoked горячего
	// пути (INV-FLOOR-6) и все мутации (fga_writer / system_admin / только край;
	// INV-FLOOR-8). Стоит в цепочке ПОСЛЕ internalCallerPolicy и повторяет её
	// отбор по боевому режиму. Законные SA-читатели — api-gateway, vpc и compute,
	// и только эти трое — засеяны system_viewer@cluster миграцией 0014. Оператор
	// сети тоже его держал, с SEC-L 0010; миграция 0081 отозвала его вместе с
	// личностью, так что этот пол проходят ровно три субъекта.
	//
	// Порт получает `svcs.ownGates`, а НЕ голый транспорт. Здесь долго стоял
	// транспорт, и это давало ровно тот класс, который под-фаза закрывает:
	// решение о доступе на каждом читающем RPC внутреннего слушателя уходило
	// движку мимо второго шанса и мимо сравнения форм. Страж при этом
	// присутствовал, был провязан и исполнялся — снаружи неотличимо от
	// исправного.
	internalSystemViewerFloor := authzguard.NewSystemViewerFloor(svcs.ownGates, authzguard.ReadFloorRPCs()).
		WithModuleRoster(moduleRoster).
		WithProductionMode(productionMode)

	// ПОЛ `required_acr_min` (ступень усиления) по RPC на внутреннем слушателе
	// для привилегированных RPC ЗА КРАЕМ (authN+authZ исполняются везде;
	// «внутреннее = доверенное, mTLS достаточно» — ЗАПРЕЩЁННОЕ допущение).
	// `required_acr_min` исполняется на публичном пути (StepUpGate края), но край
	// ТЕРЯЕТ acr при повторном вызове на :9091 — поэтому RPC за краем
	// с acr_min>0 (InternalClusterService/{Get,GrantAdmin,RevokeAdmin,ListAdmins}
	// уже несут acr_min=2) внутри по acr не проверяется. Этот пол закрывает
	// плечо: для каждого RPC за краем с acr_min>0 в каталоге он исполняет
	// `acr >= acr_min` (то же ранжирование acrlevel.Satisfies, что у края), читая
	// acr из ctx, доверенного по FD-4 (пересылается лишь на проверенном mTLS
	// ребре край→iam). SA модулей-служб (vpc/compute fgaproxy) по acr
	// ОСВОБОЖДЕНЫ (это не пользователи), а internalCallerPolicy уже ОТКАЗЫВАЕТ
	// SAN не края на RPC за краем РАНЬШЕ этого пола, так что освобождением не
	// злоупотребить (5.4-06). По умолчанию ВЫКЛЮЧЕН: dev/newman (prod=false) →
	// сквозной проход БЕЗ действия (стенд newman побайтно прежний, 5.4-07). В
	// боевом режиме отказ: отсутствующий, недостаточный или недоверенный acr на
	// RPC, требующем acr, → PermissionDenied с сигналом усиления RFC-9470 в
	// подробностях статуса. FQN→acr_min берётся из встроенного каталога прав.
	// Стоит в цепочке ПОСЛЕ UnaryTrustedPrincipalExtract (ставит acr)
	// и internalCallerPolicy.
	// Реестр прав загружен ВЫШЕ, вместе с производителем правил роли: одно
	// чтение встроенного каталога на процесс, три читателя.
	internalACRFloor := authzguard.NewACRFloor(permRegistry, authzguard.GatewayFrontedInternalRPCs()).
		WithProductionMode(productionMode)

	// Политика ВЫЗЫВАЮЩЕГО по RPC для ПУБЛИЧНОГО слушателя (:9090) — сестра
	// internalCallerPolicy выше и по той же причине: iam НЕ проверяет отношения
	// конечного пользователя повторно на своих слушателях (api-gateway —
	// единственная входная дверь авторизации), так что любой, кто дошёл до
	// публичного RPC с пересланной личностью, действует её полномочиями. :9090 НЕ
	// только для края: пять модулей-потребителей зовут ProjectService.Get на пути
	// своего запроса, а оператор пространств имён веером обходит
	// AccountService.List → ProjectService.List, — но им нужны ровно эти чтения и
	// ничего больше. Политика допускает край везде, а всякий другой проверенный
	// модуль — только на RPC, который его называет (PublicPeerCallableRPCs), так
	// что скомпрометированный сосед вовсе не достаёт ни CRUD арендатора, ни записи
	// выдач, ни выпуска учётных данных. В боевом режиме отказ; в разработке пустая
	// операция (у стенда newman нет mTLS, а значит, нет проверенного сертификата,
	// по которому решать). Это вторая половина сужения: перечень пересыльщиков
	// ниже решает, КТО ВПРАВЕ ГОВОРИТЬ ЗА ПОЛЬЗОВАТЕЛЯ, а эта политика — НА КАКОМ RPC.
	publicCallerPolicy := authzguard.NewPublicCallerPolicy(
		productionMode, authzguard.PublicPeerCallableRPCs(), permRegistry,
		// Реализация порта присутствия удостоверения: КЛЮЧ метаданных и
		// объявленная схема предъявления живут у читателя, и второй их разбор
		// разошёлся бы с первым молча — на входе, который оба считают годным.
		presentedcred.Presented).
		WithModuleRoster(moduleRoster)

	// РУБЕЖ ПОЛОЖЕНИЯ ПОДТВЕРЖДЕНИЯ (kaname#456, Р4б, Р4в) — ОДНО значение на
	// оба слушателя и обе полосы, сразу после политики вызывающего: человек с
	// неподтверждённым адресом получает отказ Р3 раньше пола системного
	// читателя, пола ступени, анти-анонима, двери и обработчика. Вид принципала
	// — строкой людей (`personmarks`), не утверждением токена.
	addressGate := authzguard.NewAddressGate(personmarks.New(pool)).
		WithRefusalObserver(func() {
			metricsReg.LoginLaneRecorder().AddressVerificationObserved(humansession.VerificationPositionRefusedListener)
		})

	// СОБСТВЕННАЯ ДВЕРЬ iam — пообъектный вопрос о доступе на публичном
	// слушателе.
	//
	// Отвечает на то, чего две политики выше не спрашивают ВООБЩЕ. Они судят,
	// КТО ЗВОНИТ (проверенный сертификат модуля) и ЗА КОГО ему позволено
	// говорить; вопроса «а можно ли ЭТОМУ субъекту ЭТОТ объект» на публичной
	// полосе не задавал никто, и комментарии обеих политик говорят это прямым
	// текстом: решение оставлено краю.
	//
	// Пока iam стоит за нашим краем, довод верен. Вынесенный в чужое облако iam
	// края не имеет по устройству — и тогда «дверь держит кто-то другой»
	// означает, что её не держит никто: аутентифицированный арендатор читает
	// чужой аккаунт и удаляет чужой проект. Разбор и замер — в шапке
	// файла authzguard/own_door.go.
	//
	// Решатель — СВОЙ (`svcs.ownGates`, полоса `servicecontract.AuthzSelf`): iam
	// владелец модели, ребра к себе не бывает. Провязывается ЗДЕСЬ, а не у
	// носителя, по той же причине, что и измеритель задержки выше, — свои
	// слушатели iam строит сам.
	//
	// Дверь действует ВО ВСЕХ режимах, а не только в production. Полосы выше
	// вырождаются в dev намеренно (на стенде нет mTLS, и решать им не о чем);
	// здесь решать есть о чём при любой посадке, а режим, в котором пообъектной
	// проверки нет, и есть та самая dev-insecure посадка, которую запрещает
	// ban #16. Собственные пообъектные стражи iam (AllowsVGet) по этой же
	// причине никогда не были default-off.
	publicObjectDoor, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{
		SelfCheck: svcs.ownGates,
		Logger:    logger,
		// Окно отзыва — величина ОПЕРАТОРА посадки, а не платформы: кешируется
		// только положительный вердикт, поэтому срок жизни записи и есть время,
		// которое субъект с отобранным правом продолжает проходить.
		PositiveTTL: cfg.AuthZ.CacheTTL,
	})
	if err != nil {
		return err
	}

	// Измеритель задержки — ОДИН на процесс, полос у него две.
	//
	// Тот же измеритель, что носитель входящего пути ставит остальным шести
	// сервисам: ряды iam ложатся в общее семейство платформы, и вопрос «где во
	// всей платформе вырос хвост» остаётся одним запросом. Слушателей iam строит
	// сам, минуя носитель, поэтому провязать измеритель обязан здесь — отказ
	// старта О13 сюда не достаёт.
	//
	// Две полосы: `OperationService` и пара `Internal*` служатся обоими
	// слушателями, и слитый ряд был бы средним двух разных величин — публичный
	// вызов приходит от арендатора через край, внутренний — от соседнего модуля
	// по mTLS.
	//
	// Отказ регистрации — отказ подъёма, а не предупреждение: он означает
	// несогласованное объявление серии, и поднять процесс значило бы отдать ему
	// диагностическую поверхность без семейства, которого на ней не будет никогда.
	latency, err := grpcsrv.NewServerLatency(metricsReg.Registerer())
	if err != nil {
		return fmt.Errorf("измеритель задержки обслуженного вызова: %w", err)
	}

	// Читатель удостоверения, ПРЕДЪЯВЛЕННОГО самим вызывающим (kacho#2077).
	//
	// Без него личность на публичном слушателе производится ровно двумя
	// способами, и оба предполагают НАШУ инфраструктуру рядом: клиентский
	// сертификат проверенного пира и личность, переданная разрешённым
	// отправителем. В чужом облаке нет ни края, чтобы передать, ни модульного
	// сертификата у человека — арендатору нечем назваться, и все публичные
	// службы отвечают ему честным и бесполезным отказом.
	//
	// nil означает «приём выключен» и законен: под посадкой внешнего
	// поставщика личность приходит через край, и читателю нечего делать. Под
	// посадкой own выключенный приём отвергается стражем настройки, а не
	// молчаливым nil здесь.
	var presentedReader *presentedcred.Reader
	if cfg.AuthN.PresentedCredential.Enabled {
		basicAuthority, err := newBasicCredentialAuthority(pool)
		if err != nil {
			return fmt.Errorf("basic credential authority: %w", err)
		}
		if signingKeystore == nil {
			// Настройка это уже отвергла (страж связывает приём с чеканкой), и
			// отказ здесь — не второй страж, а отказ ПОСТРОЕНИЯ: собранный
			// наполовину читатель отвергал бы всё, и узналось бы это на первом
			// запросе арендатора.
			return fmt.Errorf("приём предъявленного удостоверения включён, но собственного " +
				"реестра ключей нет — проверять подпись нечем")
		}
		presentedReader, err = presentedcred.New(presentedcred.Config{
			BasicCredentials:   basicAuthority,
			Issuer:             cfg.AuthN.TokenSigning.Issuer,
			Audience:           cfg.AuthN.PresentedCredential.Audience,
			AllowedAlgorithms:  cfg.AuthN.TokenSigning.AllowedAlgorithmList(),
			Keys:               signingKeystore,
			Revocations:        kanamepg.NewMintedTokenRevocationRepo(pool),
			RevocationCacheTTL: cfg.AuthN.PresentedCredential.RevocationCacheTTL,
			Logger:             logger.With(slog.String("component", "presented_credential")),
			// Домен доверия — ТОТ ЖЕ объект, что уезжает в пару звеньев
			// извлечения личности: читатель предъявленного удостоверения
			// разбирает личность модуля тем же общим извлекателем, и своя
			// величина здесь разошлась бы с той молча.
			TrustDomain: cfg.AuthN.TrustDomain(),
		})
		if err != nil {
			return fmt.Errorf("читатель предъявленного удостоверения: %w", err)
		}
		metricsReg.NewPresentedCredentialCollector(func() metrics.PresentedCredentialCounts {
			st := presentedReader.Stats()
			return metrics.PresentedCredentialCounts{
				Accepted: st.Accepted, Refused: st.Refused, Unavailable: st.Unavailable,
			}
		})
	}

	// Публичная цепочка собирается ОДНИМ сборщиком, и его же зовут пробы
	// цепочки (IAM-PNE-1-21 А, самопроверка анонима): они судят ту цепочку,
	// что уезжает в слушатель, а не собранную рядом копию. Порядок звеньев и
	// доводы — в шапке `publicListenerChain`.
	publicUnaryLinks, publicStreamLinks, err := publicListenerChain(cfg, logger, latency, permRegistry,
		presentedReader, publicCallerPolicy, addressGate, publicObjectDoor)
	if err != nil {
		return fmt.Errorf("цепочка публичного слушателя: %w", err)
	}
	grpcSrv := grpcsrv.NewServer(
		publicServerCreds,
		grpc.ChainUnaryInterceptor(publicUnaryLinks...),
		grpc.ChainStreamInterceptor(publicStreamLinks...),
	)
	// Внутренний слушатель (порт 9091) отделён сетью, но НЕ доверен: authN+authZ
	// исполняются на КАЖДОМ внутреннем RPC (§«authN+authZ везде»; закрывает
	// аудит C1/C3/H3/M1).
	//
	// Порядок цепочки перехватчиков (каждый исполняется раньше следующего):
	//  1. UnaryCertIdentityExtract — проверенный SAN клиентского сертификата mTLS
	//     (личность модуля) → ctx; незащищённый слушатель (разработка) → пустая
	//     операция.
	//  2. UnaryTrustedPrincipalExtract — метаданные x-kacho-principal-* → ctx, но
	//     под доверием по инварианту FD-4 И по перечню пересыльщиков: пересланный
	//     принципал конечного пользователя виден ниже (operations.principal_* /
	//     аудит / granted_by) ТОЛЬКО когда шаг 1 доказал, что пир проверен mTLS, И
	//     личность его сертификата — из перечисленных оператором в
	//     authn.trusted-forwarder-sans. У любого другого пира метаданные
	//     ОТБРАСЫВАЮТСЯ (носитель откатывается к SystemPrincipal), так что ни
	//     вызывающий без сертификата, ни соседний модуль со своим законным
	//     сертификатом не ПОДДЕЛАЮТ принципала аудита (против подмены). На
	//     незащищённом слушателе разработки метаданные по-прежнему принимаются
	//     (обратная совместимость). Для authZ НЕ доверяются — пользовательскую
	//     авторизацию уже провёл край. ОБЯЗАН идти после UnaryCertIdentityExtract.
	//  3. internalCallerPolicy — политика вызывающего по RPC: пол (проверенный
	//     сертификат модуля на КАЖДОМ RPC) и «только край» (привилегированные
	//     административные RPC — лишь от SA api-gateway); в боевом режиме отказ, в
	//     разработке пустая операция; ПЛЮС плечо «по SAN» для выпуска токена
	//     администратора кластера, которое допускает лишь явно перечисленные SPIFFE
	//     SAN клиентских сертификатов и исполняется в КАЖДОМ режиме (пустой
	//     перечень отказывает всем).
	//  4. internalSystemViewerFloor — пол `system_viewer` по RPC на наборе
	//     ЧИТАЮЩИХ RPC (ReadFloorRPCs): SA модуля вызывающего обязан держать
	//     `system_viewer@cluster:cluster_root` (Check уровня отношения сверх
	//     грубого пола mTLS выше). В боевом режиме отказ (PermissionDenied /
	//     Unavailable); в разработке пустая операция. Освобождены (нет в
	//     ReadFloorRPCs): Check точки решения, IsRevoked горячего пути, все
	//     мутации. ОБЯЗАН идти после internalCallerPolicy (ему нужен уже
	//     пройденный тот же пол проверенного SAN).
	//  5. internalACRFloor — пол `required_acr_min` (ступень усиления) по RPC на
	//     наборе ЗА КРАЕМ: для RPC за краем с acr_min>0 в каталоге пересланный и
	//     доверенный по FD-4 acr обязан ему удовлетворять (иначе PermissionDenied
	//     и сигнал усиления). Вызывающие SA модулей и RPC не за краем по acr
	//     освобождены. В боевом режиме отказ; в разработке пустая операция.
	//     ОБЯЗАН идти после UnaryTrustedPrincipalExtract (ставит acr) и
	//     internalCallerPolicy (которая первой отказывает SAN не края на RPC за
	//     краем, так что освобождением SA не злоупотребить).
	internalUnary := append([]grpc.UnaryServerInterceptor{
		// Измеритель задержки первым — здесь живёт горячий путь пер-RPC гейта
		// прав (`InternalIAMService.Check`), и его задержка есть задержка КАЖДОГО
		// вызова всей платформы: она входит слагаемым в чужие хвосты, поэтому
		// собственный ряд у неё обязан быть.
		latency.UnaryServerInterceptor(grpcsrv.ListenerInternal),
		// Восстановление после паники — сразу внутри метрик, с тем же доводом, что
		// у публичной цепочки: паника обработчика или перехватчика на горячем пути
		// точки решения не должна ронять процесс (это отказ по всему кластеру); она
		// сводится к записанному в журнал codes.Internal для одного запроса.
		grpcsrv.UnaryPanicRecovery(logger),
		// Довод тот же, что у публичной цепочки, и на тех же условиях: отказ этого
		// слушателя тоже несёт машиночитаемую причину, так что клиенту не нужно
		// знать, какой слушатель (или какой слой) сказал «нет». Причина
		// дописывается — PreconditionFailure усиления, поднятый полом acr ниже,
		// остаётся нетронутым. См. deny_details.go.
		authzguard.DenyDetailUnary(permRegistry),
	}, identityUnary(cfg)...)
	internalUnary = append(internalUnary,
		internalCallerPolicy.Unary(),
		addressGate.Unary(),
		internalSystemViewerFloor.Unary(),
		internalACRFloor.Unary(),
	)
	internalStream := append([]grpc.StreamServerInterceptor{
		latency.StreamServerInterceptor(grpcsrv.ListenerInternal),
		grpcsrv.StreamPanicRecovery(logger),
	}, identityStream(cfg)...)
	internalStream = append(internalStream,
		internalCallerPolicy.Stream(),
		addressGate.Stream(),
		internalSystemViewerFloor.Stream(),
		internalACRFloor.Stream(),
	)
	internalSrv := grpcsrv.NewServer(
		internalServerCreds,
		grpc.ChainUnaryInterceptor(internalUnary...),
		grpc.ChainStreamInterceptor(internalStream...),
	)
	logger.Info("kaname listener mTLS",
		"public_mtls", mtlsCfg.PublicServerMTLS.Enable,
		"internal_mtls", mtlsCfg.InternalServerMTLS.Enable,
		"metrics_mtls", mtlsCfg.MetricsServerMTLS.Enable,
		"jwks_proxy_mtls", mtlsCfg.JWKSProxyServerMTLS.Enable)
	// Потолок темпа и одновременности НА ВЫЗЫВАЮЩЕГО. Регистрация идёт ЧЕРЕЗ
	// обёртку ограничителя: он получает дескриптор службы целиком и подставляет
	// допуск МЕЖДУ цепочкой звеньев и обработчиком — то есть ПОСЛЕ того, как
	// личность вызывающего установлена. Забыть метод здесь не на чем: перечня
	// методов у вызывающего нет.
	//
	// Служебные поверхности (здоровье, отражение) регистрирует конструктор
	// сервера ДО обёртки и под предел не попадают намеренно: отказ проверке
	// готовности означал бы перезапуск пода из-за нагрузки на API.
	publicAdmissionLimits, internalAdmissionLimits, err := admissionLimits(cfg)
	if err != nil {
		return err
	}
	// Ключи у слушателей РАЗНЫЕ, и это не деталь: публичный ключуется личностью
	// конечного пользователя (за краем сидит арендатор, и предел объявлен на
	// него), внутренний — личностью СЕРТИФИКАТА вызывающего модуля, потому что
	// запрос модуля несёт личности разных арендаторов и ключ по арендатору
	// дробил бы бюджет соседа на тысячу вёдер. У внутреннего этот ключ — уровень
	// модуля; под ним стоит уровень экземпляра того же модуля (ниже).
	publicAdmission, err := grpcsrv.NewAdmission("public", publicAdmissionLimits, grpcsrv.PrincipalSubject)
	if err != nil {
		return fmt.Errorf("ограничитель допуска публичного слушателя: %w", err)
	}
	// Внутренний слушатель — ДВА уровня (kaname#992): экземпляр вызывающего
	// (личность и адрес) и модуль в целом (SAN, прежние величины посадки).
	// Шумный экземпляр выбирает не больше своего ведра и соседа не душит.
	internalAdmissions, err := newInternalAdmissions(internalAdmissionLimits, instanceAdmissionLimits(internalAdmissionLimits))
	if err != nil {
		return fmt.Errorf("ограничитель допуска внутреннего слушателя: %w", err)
	}
	admission := listenerAdmission{public: publicAdmission,
		internal: internalAdmissions.internal, internalInstance: internalAdmissions.internalInstance}
	admission.arm(logger, cfg)

	registerPublicServices(publicAdmission.Registrar(grpcSrv), svcs, opsRepo)
	registerInternalServices(admission.internalRegistrar(internalSrv), svcs, pool, cfg, logger)

	publicAddr := cfg.APIServer.ListenAddress()
	internalAddr := cfg.APIServer.InternalListenAddress()
	listener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		return err
	}
	internalListener, err := net.Listen("tcp", internalAddr)
	if err != nil {
		_ = listener.Close()
		return err
	}

	// ── НЕ-gRPC ПОВЕРХНОСТИ: четыре профиля ТОЙ ЖЕ функции ──────────────────
	//
	// Решение владельца (XC-7, в-1): не-gRPC слушатели входят в контур ОТДЕЛЬНЫМ
	// профилем, а не полями общего дескриптора. У iam их шесть, и предметы у них
	// РАЗНЫЕ — скрейп, выдача docker-токена, полоса входа, публикатор набора
	// ключей проверки, публичный и внутренний REST-фронты. Профиль их не смешивает: разницу несут
	// значения двух осей — откуда поверхность досягаема и чем аутентифицирует, — и
	// именно их пара судится (снаружи досягаемая поверхность с объявленным
	// ОТСУТСТВИЕМ аутентификации не поднимается вовсе).
	//
	// Что ушло вместе с ручной сборкой: каскад закрытий уже привязанных
	// слушателей на каждом последующем отказе (пять вложенных лестниц, из которых
	// одна теряла слушатель скрейпа), четыре одинаковых блока гашения в общем
	// триггере и четыре набора одних и тех же сроков, выписанных по месту.
	surfaceMode, merr := servicecontract.ParseMode(cfg.AuthN.Mode.String())
	if merr != nil {
		return fmt.Errorf("посадка процесса для профиля поверхностей: %w", merr)
	}

	// Контекст не-gRPC поверхностей. Отдельный от корневого: гасить их надо по
	// общему триггеру остановки, который срабатывает и от сигнала, и от краха
	// любого из двух gRPC-слушателей.
	surfaceCtx, stopSurfaces := context.WithCancel(context.Background())
	defer stopSurfaces()

	// Носитель готовности строится ЗДЕСЬ и отдаётся тому, кто его монтирует, и
	// гашению: оно переводит `/readyz` в 503 ДО остановки серверов (см.
	// triggerShutdown ниже). Без этого носитель был бы, а дёрнуть его было бы
	// некому (kacho#1752).
	//
	// Поверхности вебхуков внешнего поставщика личности здесь больше нет: хуки
	// сняты вместе с поставщиком (kaname#363), и дверь, которую некому звать, не
	// поднимается ни на каком старте.
	readiness := buildReadiness(pool, metricsReg)

	// (1) Скрейп. Никогда не публичная gRPC-поверхность: внутренняя
	// кардинальность туда не выносится.
	metricsAddr := cfg.APIServer.MetricsListenAddress()
	// Живость и готовность пода — на ЭТОЙ поверхности (kaname#360): она есть
	// на каждом старте.
	metricsMux := diagnostics.NewMux(diagnostics.Handlers{Health: readiness})
	metricsMux.Handle("/metrics", metricsReg.Handler())
	metricsSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "диагностика (/metrics)",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(metricsAddr, knobMetrics+" не задан профилем развёртывания: скрейпа, живости и готовности пода на этой посадке нет"),
		Handler: metricsMux,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
			"снята осознанно: поверхность выставлена только на внутренний Service и несёт " +
				"счётчики процесса, живость и готовность по ИМЕНАМ зависимостей — ни секретов, " +
				"ни данных арендатора на проводе нет"),
		TLS: metricsTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности диагностики: %w", err)
	}

	// (2) Выдача docker-токена (`/iam/token`, Registry v2 auth-server).
	//
	// Единственная ВНЕШНЕ досягаемая поверхность iam: `docker login` приходит
	// через вход кластера. Её аутентификация — предъявление БАЗОВОГО ТОКЕНА
	// ДОСТУПА (kacho#1142), от которого сервер хранит только свёртку. Ключевой
	// материал в поле пароля снят задачей kacho#1143 и принимается лишь пока открыто
	// объявленное оператором окно перехода (ручка ниже).
	registryTokenAddr := cfg.APIServer.RegistryToken.ListenAddress()
	// Вход сборки полосы ПЕРЕЛАГАЕТСЯ из настройки одной функцией
	// (registryTokenBuildConfig ниже): всякая ручка полосы доезжает до сборки
	// через неё, и проба переложения судит ровно то, что получает сборка.
	//
	// Неразборчивое значение сюда не доходит: его отвергает страж старта
	// `RegistryTokenConfig.Validate` — его зовёт `config.Config.Validate`, а её,
	// в свою очередь, `main` ДО `runServe`, и на её отказе процесс выходит
	// кодом 1. Отказ ниже поэтому недостижим на живой посадке и стоит здесь
	// затем, чтобы значение не оказалось использовано неразобранным, если
	// когда-нибудь эту функцию позовут в обход `main`.
	// Адрес источника осей темпа — ОДНО правило на все точки поверхности выдачи
	// (приёмка ceremony-pace-is-named-by-number.md, Р7): адрес от края только
	// при проверенном сертификате края, иначе адрес пира. Строится до сборки
	// докерной полосы: её анонимная выдача — тоже точка этой поверхности
	// (kaname#928), и на ней адрес берётся ещё и у объявленного доверенного
	// пересыльщика — прокси реестра (kaname#930). Режим слушателя, при котором
	// край и пересыльщик вообще узнаваемы, требует страж
	// requireIssuingListenerAsksForACertificate.
	issuingSource := issuingsource.New(cfg.AuthN.TrustDomain(), moduleRoster)
	registryTokenBuild, rtErr := registryTokenBuildConfig(cfg.APIServer.RegistryToken, registryTokenRuntime{
		logger: logger,
		source: issuingSource,
		// НАШ подписант — единственный издатель полосы. Выключенная своя
		// чеканка даёт здесь nil, и сборка отказывает в старте, называя оба
		// выхода (kaname#494): другого издателя у полосы нет.
		signer: tokenSigner,
		// Счётчик исходов провязывается БЕЗУСЛОВНО, а не вместе с окном:
		// он обязан считать и отказы прежнему виду, то есть работать именно
		// на посадке БЕЗ окна — иначе оператор, у которого обновление
		// сломало вход арендаторам, узнаёт об этом из жалобы.
		credentialKindObserver: metricsReg.RegistryTokenCredentialKindRecorder(),
		// Предел ОДНОГО обращения авторитета о базовом секрете к базе — тот
		// же, что у полос выдачи токена: оператор этой полосы для строки
		// человека читает и отсечку отзыва-всех (kaname#379).
		basicCredentialTimeout: credentialLanePeerTimeout,
	})
	if rtErr != nil {
		return fmt.Errorf("registry token shim: %w", rtErr)
	}
	if registryTokenKeyMaterialWindow := registryTokenBuild.KeyMaterialWindowUntil; !registryTokenKeyMaterialWindow.IsZero() {
		// Открытое окно — ОСЛАБЛЕНИЕ ПОСАДКИ, и оно обязано быть заметно в
		// самоотчёте процесса: посадка, о которой процесс молчит, отличима от
		// строгой только чтением настройки, а её при разборе инцидента читают
		// последней. Истёкшее окно называется тем же сообщением: ручка, которой
		// больше нечего открывать, — находка, а не норма.
		logger.Warn("docker token: key-material transition window is declared",
			"until", registryTokenKeyMaterialWindow.Format(time.RFC3339),
			"open_now", time.Now().Before(registryTokenKeyMaterialWindow),
			"knob", "api-server.registry-token.key-material-window-until",
			"effect", "the docker lane keeps accepting key material in the password field until that instant",
			"close_when", "kaname_registry_token_credential_kind_total{outcome=\"key_material_accepted_in_window\"} stops growing")
	}
	var registryTokenHandler http.Handler
	if registryTokenAddr != "" {
		mux, berr := registrytokenwire.Build(pool, registryTokenBuild)
		if berr != nil {
			return fmt.Errorf("registry token shim: %w", berr)
		}
		// Перепись точки анонимной выдачи правила адреса источника — вплотную
		// к сборке полосы (kaname#930): рост её клетки отличает неверно
		// названного пересыльщика от залпа одного клиента.
		metricsReg.NewRegistryTokenSourceFallbackCollector(registryTokenSourceFallbackReasons(), registryTokenSourceFallbackReader(issuingSource))
		// Токен-эндпоинт платформы (задача kacho#898) монтируется на ЭТУ ЖЕ
		// поверхность, а не заводит свою. Вид выдачи «учётные данные клиента»
		// задан формой запроса, а не нашим выбором порта; второй внешний
		// слушатель об одном предмете разошёлся бы с первым в периметре,
		// посадке TLS и профиле развёртывания — и разошёлся бы молча.
		//
		// Приземление, а не провязка на будущее: с этого места проверяющий
		// утверждение получает ПРОИЗВОДСТВЕННОГО вызывающего. Проверяющий без
		// него выглядит исправным ровно потому, что его пробы подают ему то,
		// что он умеет разобрать.
		// Церемония OAuth `authorization_code` нашими силами (приёмка LINE-A-1,
		// kaname#423) — при поднятом токен-эндпоинте: её полосы обмена живут на
		// нём, а эндпоинт авторизации и метаданные обнаружения монтируются на
		// ЭТУ ЖЕ внешнюю поверхность выдачи и нигде больше (сценарий 23). При
		// выключенном эндпоинте (только вне боевого режима) — nil, и её пути
		// здесь не резолвятся.
		//
		// Адрес источника осей темпа — то же правило issuingSource, что у
		// докерной полосы выше: одно на все точки поверхности.
		ceremony, cerr := buildCeremonySurface(pool, cfg, tokenSigner,
			ceremonyKeySource(signingKeystore), lane.secretChecker(), lane.secretCheckCost(),
			metricsReg.LoginLaneRecorder(), issuingSource, logger)
		if cerr != nil {
			return fmt.Errorf("ceremony: %w", cerr)
		}
		clientTokenHandler, cterr := buildClientTokenEndpoint(pool, cfg, tokenSigner, logger, ceremony, issuingSource)
		if cterr != nil {
			return fmt.Errorf("client token endpoint: %w", cterr)
		}
		if clientTokenHandler != nil {
			mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)
			// ЧИТАТЕЛЬ ПЕРЕПИСИ ИСХОДОВ — ВПЛОТНУЮ К МОНТИРОВАНИЮ (kacho#2501), как у
			// двух соседних поверхностей выдачи. Обработчик несёт перепись с
			// пред-засевом по каждому объявленному исходу; без читателя она
			// оставалась в памяти процесса, и «ноль отказов за всю жизнь полосы»
			// было неотличимо от «полоса не исполнялась ни разу» — при том, что
			// через эту полосу в отдельной установке выдаётся ВСЯКОЕ
			// арендаторское удостоверение.
			//
			// Набор исходов приходит из того же закрытого словаря, которым засеяна
			// перепись: полнота витрины тогда не зависит от чужого засева.
			metricsReg.NewClientTokenOutcomeCollector(
				clienttokenhttp.DeclaredOutcomes(), clientTokenOutcomeReader(clientTokenHandler))
			// Перепись правила адреса источника — там же: её клетки есть
			// измеренное свидетельство того, что край и служба сошлись.
			metricsReg.NewIssuingSourceFallbackCollector(issuingSourceFallbackCells(), issuingSourceFallbackReader(issuingSource))
		}
		if ceremony != nil {
			// Объявление поверхности называет эти пути, потому что маршрутизатор
			// их разрешает (issuingSurfaceAuthOf ниже), а не по флагу рядом.
			mux.Handle(ceremonyhttp.AuthorizePath, ceremony.Authorize)
			mux.Handle(ceremonyhttp.DiscoveryPath, ceremony.Discovery)
			// Читатель переписи исходов — вплотную к монтажу, как у соседних
			// полос выдачи: наружу отказы церемонии неразличимы, различимость —
			// здесь.
			metricsReg.NewCeremonyOutcomeCollector(ceremonyhttp.DeclaredOutcomes(), ceremony.Census.Read)
		}
		registryTokenHandler = mux
	}
	registryTokenSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "выдача токенов (/iam/token, /iam/v1/token)",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(registryTokenAddr, knobRegistryToken+" не задан профилем развёртывания: docker login на этой посадке не обслуживается"),
		Handler: registryTokenHandler,
		Reach:   servicecontract.ReachExternal,
		Auth:    issuingSurfaceAuthOf(registryTokenHandler),
		// Транспорт поверхности — TLS, собранный из профиля развёртывания выше.
		TLS: registryTokenTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности выдачи docker-токена: %w", err)
	}

	// (3а) Полоса входа паролем — глаголы формы (перечень —
	// `loginlanehttp.Paths()`) на своём слушателе, взаимный TLS, вызывающий —
	// ровно край (Ф3, Р7). Полоса строится на каждом старте, и поверхность
	// поднимается вместе с ней.
	loginLaneSurface, err := loginLaneSurface(cfg, surfaceMode, logger, lane, mtlsCfg)
	if err != nil {
		return fmt.Errorf("профиль поверхности полосы входа: %w", err)
	}

	// (3) Публикатор ПУБЛИЧНЫХ ключей проверки — наша запись набора на пути
	// `authn.token-signing.key-set-path`.
	//
	// Здесь аутентификация снята — и это ЗАДОКУМЕНТИРОВАННОЕ исключение, а не
	// упущение (§AuthN+AuthZ ВЕЗДЕ): поверхность выставлена только на
	// внутренний Service, идёт по односторонней TLS и несёт исключительно
	// публичный материал. Профиль требует, чтобы это было СКАЗАНО — и говорит это
	// в журнале на каждом старте, а не только в чужом документе.
	//
	// Проверить обоснование можно по паре осей: снятие принято потому, что
	// досягаемость объявлена внутренней. Объяви кто-нибудь эту поверхность
	// внешней — старт бы отказал.
	jwksProxyAddr := cfg.APIServer.JWKSProxy.ListenAddress()
	var jwksProxyHandler http.Handler
	if jwksProxyAddr != "" {
		// (4а) ЗАПИСЬ ОДНА — НАША (kaname#361).
		//
		// Рядом с ней стояла запись зеркала публичного набора прежнего
		// издателя; она ушла вместе с ним, и её верхнего хопа, его якоря и
		// счётчиков в корне больше нет. Вторую запись привязка отвергает в
		// старте: вернувшись, она снова поставила бы ключ другого издателя
		// рядом с нашим на том же слушателе.
		//
		// Записи нет, когда своя чеканка выключена: публиковать тогда нечего, и
		// привязка отказывает в старте, называя ручку слушателя, — слушатель,
		// объявленный профилем и не несущий ни одной записи, отвечал бы каждому
		// спросившему отказом.
		var records []jwksproxyhttp.Record
		if signingKeystore != nil {
			ourKeySet := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
				Source: signingKeystore,
				Logger: logger.With(slog.String("component", "jwks_own_keyset")),
			})
			// Читатели величин. Выданные считаются наравне с отказами: пока
			// наружу выходят одни отказы, ноль в них отвечает сразу на два
			// вопроса — «отказов не было» и «сюда никто не приходил».
			metricsReg.NewOwnKeySetCollector(func() metrics.OwnKeySetCounts {
				st := ourKeySet.Stats()
				return metrics.OwnKeySetCounts{Served: st.Served, Unavailable: st.Unavailable, Empty: st.Empty}
			})
			metricsReg.NewSigningKeyCollector(func() metrics.SigningKeyCounts {
				st := signingKeystore.Stats()
				return metrics.SigningKeyCounts{
					Generated: st.Generated, Activated: st.Activated, Retired: st.Retired,
					Removed: st.Removed, Compromised: st.Compromised, Failures: st.Failures,
					Sweeps: st.Sweeps,
				}
			})
			records = append(records, jwksproxyhttp.Record{
				Issuer:  cfg.AuthN.TokenSigning.Issuer,
				Path:    cfg.AuthN.TokenSigning.ResolveKeySetPath(),
				Handler: ourKeySet,
			})
		}
		binding, berr := jwksproxyhttp.NewBinding(records)
		if berr != nil {
			// Издатель без записи источника, вторая запись рядом с нашей или
			// слушатель без единой записи — ОТКАЗ В СТАРТЕ, а не молчаливый
			// перебор записей и не путь, выведенный из самого издателя.
			return fmt.Errorf("привязка «издатель → источник набора» (слушатель %s=%q, своя чеканка включена: %t): %w",
				knobJWKSProxy, jwksProxyAddr, signingKeystore != nil, berr)
		}
		jwksMux, merr := jwksproxyhttp.NewMux(binding)
		if merr != nil {
			return fmt.Errorf("маршруты публикации набора: %w", merr)
		}
		// (4б) Авторитет отзыва НАШИХ токенов — на том же внутреннем
		// слушателе. Отзыв, который читается только на выдаче, отзывом не
		// является: предъявленное продолжало бы проходить до истечения срока,
		// и это состояние не сходится само.
		if signingKeystore != nil {
			// Обоснование снятия authN, выданное НАБОРУ КЛЮЧЕЙ, на эту
			// поверхность НЕ распространяется: там на проводе только
			// публичный материал, здесь — предъявленный токен. Слушатель,
			// который сертификата даже не запрашивает, оставил бы авторитету
			// нечем отказать, поэтому такой стенд не поднимается вовсе.
			// УСЛОВИЕ ЖИВЁТ ИМЕНОВАННЫМ СТРАЖЕМ, а не встроенной ветвью.
			// Встроенной оно и было — и потому не судилось пробой боевого
			// профиля: та зовёт стражей ПОИМЁННО, и обещание её шапки
			// «появится у подъёма новое условие — профиль покраснеет»
			// не исполнялось для условия без имени (задача kacho#2476).
			if err := requireRevocationAuthorityCallerAuth(
				signingKeystore != nil, jwksProxyAddr, mtlsCfg); err != nil {
				return err
			}
			introspect := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
				Issuer:            cfg.AuthN.TokenSigning.Issuer,
				Keys:              signingKeystore,
				Revocations:       kanamepg.NewMintedTokenRevocationRepo(pool),
				Logger:            logger.With(slog.String("component", "token_introspection")),
				RequireClientCert: true,
			})
			metricsReg.NewTokenIntrospectionCollector(func() metrics.IntrospectCounts {
				st := introspect.Stats()
				return metrics.IntrospectCounts{
					Active: st.Active, Inactive: st.Inactive, Unavailable: st.Unavailable,
				}
			})
			jwksMux.Handle(tokenintrospecthttp.IntrospectPath, introspect)
		}
		jwksProxyHandler = jwksMux
	}
	jwksProxySurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "публикатор набора ключей проверки (authn.token-signing.key-set-path)",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(jwksProxyAddr, knobJWKSProxy+" не задан профилем развёртывания: плоскости данных реестра неоткуда взять ключи проверки, и её верификация останется закрытой"),
		Handler: jwksProxyHandler,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
			"снята ОСОЗНАННО и задокументированно (§AuthN+AuthZ ВЕЗДЕ): внутренний " +
				"Service, односторонняя TLS, на проводе только публичный материал проверки " +
				"подписи — ни секретов, ни данных арендатора"),
		TLS: jwksProxyTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности публикатора набора ключей: %w", err)
	}

	// (4) и (5) Собственные REST-фронты службы — публичный и внутренний.
	//
	// Пока служба стоит за краем платформы, её HTTP-поверхность принадлежит
	// краю. Вынесенная отдельным продуктом, края она не имеет by construction,
	// и её REST обязан существовать сам.
	//
	// Оба фронта — обычные КЛИЕНТЫ собственных gRPC-слушателей: запрос по HTTP
	// проходит ровно ту цепочку звеньев, что и тот же запрос по gRPC. Иначе к
	// одному обработчику вели бы два пути с разными решениями по дороге.
	restUpstream, err := mtlsCfg.RESTUpstreamDialOption()
	if err != nil {
		return fmt.Errorf("удостоверение REST-фронта для собственного слушателя: %w", err)
	}
	restDialOpts := []grpc.DialOption{restUpstream}

	restAddr := restFront.addr
	var restHandler http.Handler
	if restFront.Enabled() {
		restHandler, err = restfront.NewPublic(surfaceCtx, restfront.DialTarget(publicAddr), restDialOpts)
		if err != nil {
			return fmt.Errorf("публичный REST-фронт: %w", err)
		}
	}
	restSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:   "собственный публичный REST-фронт",
		Mode:   surfaceMode,
		Logger: logger,
		Addr: addrAxis(restAddr, knobPublicREST+" не задан профилем развёртывания: "+
			"собственной HTTP-поверхности у службы на этой посадке нет, и арендатор "+
			"дотянется до неё только через край платформы, которого у отдельно "+
			"поставленной службы нет"),
		Handler: restHandler,
		Reach:   servicecontract.ReachExternal,
		// Ось ВЫВОДИТСЯ из того, построено ли звено, а не вписывается: здесь
		// стояла константа, и она объявляла работу механизма на посадке, где
		// его нет (kacho#2194).
		Auth: restFrontAuthAxis(presentedReader != nil),
		TLS:  restFront.tls,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности публичного REST-фронта: %w", err)
	}

	internalRESTAddr := internalRESTFront.addr
	var internalRESTHandler http.Handler
	if internalRESTFront.Enabled() {
		internalRESTHandler, err = restfront.NewInternal(surfaceCtx, restfront.DialTarget(internalAddr), restDialOpts,
			// Кого фронт пускает, решает фронт: слушатель видит пиром сам фронт
			// (SEC-1017-1). Тот же перечень личностей, что у политик вызывающего.
			authzguard.InternalFrontAdmission(productionMode, moduleRoster, cfg.AuthN.TrustDomain()))
		if err != nil {
			return fmt.Errorf("внутренний REST-фронт: %w", err)
		}
	}
	internalRESTSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:   "собственный внутренний REST-фронт",
		Mode:   surfaceMode,
		Logger: logger,
		Addr: addrAxis(internalRESTAddr, knobInternalREST+" не задан "+
			"профилем развёртывания: служебные поверхности по HTTP на этой посадке "+
			"не обслуживаются"),
		Handler: internalRESTHandler,
		Reach:   servicecontract.ReachClusterInternal,
		// Ось ВЫВОДИТСЯ из фактического режима ребра, а не вписывается: здесь
		// стояла константа, называвшая проверенный сертификат модуля механизмом
		// аутентификации ВЫЗЫВАЮЩЕГО, — а этот сертификат называет ХОП. Тот же
		// приём, что применён к публичному фронту (kacho#2194).
		Auth: internalRESTFrontAuthAxis(mtlsCfg.InternalRESTRequiresClientCert()),
		TLS:  internalRESTFront.tls,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности внутреннего REST-фронта: %w", err)
	}

	// Срез подъёма несёт ПАРУ «ручка профиля + принятый профиль»: ручку не
	// вывести из дескриптора, а страж различимости адресов обязан назвать её в
	// отказе — иначе оператор знает, что не так, и не знает, где это чинить.
	httpSurfaces := []raisedSurface{
		{knobMetrics, metricsSurface},
		{knobRegistryToken, registryTokenSurface},
		{knobLoginLane, loginLaneSurface},
		{knobJWKSProxy, jwksProxySurface},
		{knobPublicREST, restSurface},
		{knobInternalREST, internalRESTSurface},
	}

	// ВСЕ поверхности, которые поднимает корень, слушают разные адреса.
	//
	// Стоит ЗДЕСЬ, а не среди прочих стражей посадки: перечень берётся из того
	// самого среза, которым поверхности поднимаются, поэтому «сверено меньше,
	// чем поднимается» непредставимо. Цена размещения названа честно: сокеты
	// gRPC-слушателей к этому моменту уже привязаны, зато ни один сокет
	// поверхности — ещё нет, и отказ приходит до того, как хоть одна начнёт
	// слушать. Разбор — в шапке `restfrontaddr.go`.
	surfaceAddrCheck, err := requireDistinctSurfaceAddrs(append(
		[]surfaceAddr{
			{knobPublicGRPC, cfg.APIServer.ListenAddress()},
			{knobInternalGRPC, cfg.APIServer.InternalListenAddress()},
		},
		surfaceAddrsOfRaised(httpSurfaces)...,
	))
	if err != nil {
		return err
	}
	// Перепись печатается и на успешном старте: «ноль совпадений» обязано быть
	// отличимо от «ничего не сверяли».
	logger.Info("раздельность адресов поверхностей", surfaceAddrCheck.Fields()...)

	// Про не-gRPC поверхности здесь больше не сообщается: о себе докладывает
	// каждая сама при подъёме, и доклад несёт то, чего эта строка не несла
	// никогда, — откуда поверхность досягаема и чем аутентифицирует. Числа тут
	// тоже нет: у него не оказалось владельца, и прежняя редакция говорила
	// «четыре» при шести.
	logger.Info("kaname listening",
		"public_endpoint", publicAddr,
		"internal_endpoint", internalAddr)

	gracefulTimeout := cfg.APIServer.GracefulShutdown
	if gracefulTimeout <= 0 {
		gracefulTimeout = 10 * time.Second
	}

	// HTTP-слушателей корпоративного SSO (SCIM и SAML) в этой службе нет; вход,
	// сеанс и выпуск токенов — собственные у службы (внешнего поставщика
	// личности нет).

	// Параллельный запуск
	// public-сервера + internal-сервера + shutdown-waiter через
	// `errgroup.Group` (`golang.org/x/sync/errgroup`).
	// Failure-isolation: первая ошибка / SIGTERM / SIGINT триггерит
	// graceful-stop ОБОИХ серверов. sync.Once гарантирует, что параллельные
	// триггеры (SIGTERM пришел одновременно с crash internal'а) не сделают
	// двойной GracefulStop.
	// Собственная отмена счётчика допуска: он обязан вернуть управление и тогда,
	// когда гашение начал крах слушателя, а не сигнал. Общего контекста для
	// этого мало — он сигнальный.
	admissionCtx, stopAdmission := context.WithCancel(context.Background())
	defer stopAdmission()

	// КОРЕНЬ ГАШЕНИЯ — ОДНА РУЧКА НА ОБЕ ПРИЧИНЫ (kacho#2506).
	//
	// Причин гашения две: сигнал среды и КРАХ слушателя, дренажа, поверхности.
	// Сигнальный контекст знает одну — отменить его изнутри нечем, его отмена
	// стоит `defer`-ом и срабатывает уже ПОСЛЕ `group.Wait()`. Поэтому фоновые
	// задачи берут контекст ОТСЮДА: он производен от сигнального (сигнал гасит
	// его транзитивно) и отменяется гашением по краху.
	//
	// Разбор цены прежнего устройства — в шапке `root_shutdown.go`; здесь он не
	// пересказывается.
	rootShutdown := newRootShutdown(ctx, func() {
		// ПЕРВЫМ делом — снять под из ротации: kubelet перестаёт слать
		// трафик ДО того, как серверы начнут отказывать. Порядок здесь и
		// есть предмет: флип после остановки не успевает ничего.
		readiness.SetShuttingDown()
		stopAdmission()
		stopGRPCBounded(internalSrv, gracefulTimeout)
		stopGRPCBounded(grpcSrv, gracefulTimeout)
		// Поверхности гасятся ОДНОЙ отменой их общего контекста. Прежде здесь
		// стояли одинаковые блоки со своим сроком в каждом, и каждая новая
		// поверхность требовала следующего — то есть место, где поверхность
		// забывают погасить, воспроизводилось при каждом добавлении. Числа
		// здесь нет намеренно: оно росло молча (в день заведения комментарий
		// говорил «четыре»), а перечень выводится из `httpSurfaces`.
		stopSurfaces()
		// Постановки письма восстановления, начатые до гашения, дожидаются
		// ПОСЛЕ слушателей: новых не придёт, начатые доедут (Ф5 Р2).
		lane.drain()
	})
	defer rootShutdown.Stop()
	// taskCtx — контекст ФОНОВЫХ ЗАДАЧ. Отдельное имя, а не затенение `ctx`:
	// одно имя на два контекста читалось бы как один, и следующий взял бы
	// сигнальный, думая, что берёт корневой.
	taskCtx := rootShutdown.Context()
	triggerShutdown := rootShutdown.Trigger

	tasks := []func() error{
		// Счёт допущенных и отвергнутых по каждому слушателю. Печатается ВСЕГДА,
		// включая нули: «ноль отказов за всю жизнь контроля» обязано быть
		// заметно, иначе мёртвый ограничитель невидим.
		func() error {
			admission.report(admissionCtx, logger)
			return nil
		},
		// публичный gRPC-сервер
		func() error {
			err := grpcSrv.Serve(listener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				triggerShutdown()
				return fmt.Errorf("public grpc server: %w", err)
			}
			return nil
		},
		// internal gRPC server (admin, наружу не публикуется)
		func() error {
			err := internalSrv.Serve(internalListener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				logger.Error("internal grpc server stopped", "err", err)
				triggerShutdown()
				return fmt.Errorf("internal grpc server: %w", err)
			}
			return nil
		},
		// Задача-ожидатель: ЛЮБАЯ причина гашения → graceful-stop обоих + дрейн
		// LRO worker'ов. Ждёт КОРНЕВОЙ контекст, а не сигнальный: прежняя
		// редакция просыпалась только по сигналу, и при крахе слушателя
		// `group.Wait()` не возвращался вовсе (kacho#2506).
		func() error {
			rootShutdown.Await()
			drainCtx, cancelDrain := context.WithTimeout(context.Background(), 3*gracefulTimeout)
			defer cancelDrain()
			if err := operations.Wait(drainCtx); err != nil {
				logger.Warn("operations workers did not finish in time",
					"err", err, "active", operations.Active())
			}
			return nil
		},
	}

	// Не-gRPC поверхности. Порты привязываются ЗДЕСЬ, до постановки задач:
	// занятый адрес есть ошибка посадки, и узнать о ней надо до того, как процесс
	// объявит себя поднявшимся. Прежде подъём целиком уезжал в задачу супервизора,
	// и отказ привязки становился кодом возврата процесса, успевшего сколько
	// угодно проработать.
	//
	// Ожидание ставится задачей ВСЕГДА, даже когда поверхность объявлена
	// выключенной: тогда оно сразу возвращается, а причина уже названа в журнале.
	// Условная постановка вернула бы то самое молчание, ради устранения которого
	// выключение стало объявлением.
	for _, surface := range httpSurfaces {
		wait, serr := servicehost.ServeSurface(surfaceCtx, surface.desc)
		if serr != nil {
			stopSurfaces()
			return fmt.Errorf("поверхность %q (%s): %w",
				surface.desc.Spec().Name, surface.knob, serr)
		}
		tasks = append(tasks, func() error {
			if werr := wait(); werr != nil {
				logger.Error("не-gRPC поверхность остановлена с ошибкой",
					"surface", string(surface.desc.Spec().Name),
					"knob", surface.knob, "err", werr)
				triggerShutdown()
				return fmt.Errorf("поверхность %q (%s): %w",
					surface.desc.Spec().Name, surface.knob, werr)
			}
			return nil
		})
	}
	// Корпоративный SSO (SCIM и SAML) этот набор слушателей не обслуживает.

	// ДРЕНАЖА ЖУРНАЛА НАМЕРЕНИЙ ЗДЕСЬ НЕТ — снят вместе с адресатом.
	//
	// Он читал `kaname.fga_outbox` и применял каждую строку к внешнему движку
	// отношений. Движка нет; журнал ОСТАЁТСЯ и остаётся не «на всякий случай»:
	// прямой факт, из которого форма собирает вердикт, складывается ИЗ ЭТОГО ЖУРНАЛА
	// триггером (миграция 0098). Снять журнал вместе с дренажом значило бы обесточить
	// источник собственного вердикта — и обесточить тихо: таблица осталась бы на
	// месте, запросы продолжили бы исполняться, а ответы поехали бы в сторону отказа.

	// ТОЛЧКА К КРАЮ ЗДЕСЬ НЕТ — направление развёрнуто (задача kacho#1024).
	//
	// Здесь стоял дренаж `kaname.subject_change_outbox`, который дозванивался до
	// края и гасил его кэш решений. Это было ребро ИЗ ЛИСТА ОБРАТНО К ПОТРЕБИТЕЛЮ:
	// iam объявлен листом графа рёбер — его зовут, он не зовёт никого, — а адрес края
	// был вдобавок ОБЯЗАТЕЛЬНОЙ ручкой, поэтому владелец прав не поднимался там, где
	// края нет вовсе. Именно это делало вынос iam отдельным продуктом невыразимым.
	//
	// Соединение открывает ПОТРЕБИТЕЛЬ: край сам читает журнал смены субъекта
	// курсором (`InternalIAMService.PollSubjectChanges`, провязано у края) и гасит
	// свой кэш сам. Владелец прав о крае больше не знает и знать ему нечем.
	//
	// ЖУРНАЛ ОСТАЁТСЯ и остаётся не «на всякий случай»: он и есть то, что читает
	// потребитель. Изменилась его природа — из очереди с доставкой он стал журналом
	// с курсором: выборка идёт по `id > $1`. Величин доставки у него больше НЕТ —
	// `sent_at`/`attempt_count`/`last_error`/`notified_at` сняты вместе с частичным
	// индексом по неотправленным строкам, после того как писателей не осталось
	// (миграция 20260829181500, задача kacho#1396). Схема перестала обещать доставку,
	// которой нет, а не только перестала её выполнять.

	// Наблюдаемость очереди компенсаций: глубина, возраст самой старой
	// недоставленной строки, число отравленных. Дренажа у неё нет — нет ни
	// производителя, ни исполнителя (kaname#363), — и скан держит видимыми
	// строки, пережившие прежнюю посадку. Скан не мутирует таблицу и не может
	// уронить под — ошибки логируются.
	tasks = append(tasks, func() error {
		runProviderCompensationMetrics(taskCtx, pool, metricsReg.OutboxRecorder(), logger)
		return nil
	})

	// ПИСЬМО ПРИГЛАШЕНИЯ: дренаж очереди, возврат отравленных строк и
	// наблюдаемость (приёмка ID-MAIL-1, Р23/Р25; §10 пп. 20–21).
	//
	// Намерение отправить письмо со-коммичено строкой приглашения в её же
	// транзакции, а исполняется ЗДЕСЬ — at-least-once, поэтому оно переживает и
	// смерть процесса, и недоступность почтового узла. Дренаж поднимается
	// ВСЕГДА, в том числе при необъявленной почтовой полосе: тогда отправитель
	// на каждой попытке даёт наблюдаемый исход «настройка» — громко и в свою
	// клетку счётчика, — а не молчит. Не поднять его значило бы завести очередь,
	// у которой нет исполнителя: намерения копятся, письма не уходят, и всё
	// выглядит работающим, потому что приглашение-то создаётся.
	inviteMailDrainerTask, imerr := buildInviteMailDrainer(
		pool, cfg, metricsReg.InviteMailRecorder(), logger)
	if imerr != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		return fmt.Errorf("invite mail drainer wiring: %w", imerr)
	}
	tasks = append(tasks, func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("invite mail drainer panicked", "panic", r)
				err = fmt.Errorf("invite mail drainer panic: %v", r)
			}
			if err != nil {
				triggerShutdown()
			}
		}()
		return inviteMailDrainerTask(taskCtx)
	})
	// Возврат отравленных, наблюдаемость очереди и уборка доставленных строк.
	// Ошибка сборки останавливает старт: уборка, собранная молча и не
	// исполняющаяся, оставляет очередь расти вечно.
	if berr := startInviteMailBackstop(
		taskCtx, pool, cfg, metricsReg.OutboxRecorder(), logger); berr != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		return fmt.Errorf("invite mail backstop wiring: %w", berr)
	}
	// СКАНА ЖУРНАЛА СМЕНЫ СУБЪЕКТА ЗДЕСЬ НЕТ — у него больше нет предмета.
	//
	// Он мерил ДОСТАВКУ: возраст самой старой неотправленной строки и число
	// отравленных. Обе величины имеют смысл, только пока строки кто-то помечает
	// отправленными. С разворотом направления (задача kacho#1024) таких не осталось:
	// потребитель читает журнал курсором. Колонки, по которым скан считал, сняты
	// следом (задача kacho#1396) — теперь его нельзя не только осмыслить, но и написать.
	//
	// Оставленный скан отвечал бы РАСТУЩИМ возрастом на исправной службе — тревога,
	// которая звонит всегда, есть тревога, которую отключают первой. Ровно это уже
	// случилось у соседней очереди, и её разбор стоит абзацем выше в
	// `outbox_metrics_wiring.go`.
	// Журнал аудита: состояние очереди. Теперь у неё есть доставка (вывоз
	// ниже), поэтому величины сканера читаются как обычно: глубина падает,
	// возраст головы ограничен сверху. До появления приёмника они лишь делали
	// молчание слышимым — растущая глубина и стареющая голова были верным
	// описанием, а не сигналом сбоя.
	tasks = append(tasks, func() error {
		runAuditOutboxMetrics(taskCtx, pool, metricsReg.OutboxRecorder(), logger)
		return nil
	})
	// Очередь сверки прав: состояние. У неё есть и доставка (дренаж ниже), и
	// отсечка (kacho#2050) — а отсечка без наблюдаемости делает отказ ТИХИМ: строка,
	// перешагнувшая порог, из клейма выпадает и перестаёт жаловаться. Разбор —
	// `reconcile_outbox_metrics_wiring.go`.
	tasks = append(tasks, func() error {
		runReconcileOutboxMetrics(taskCtx, pool, metricsReg.OutboxRecorder(), logger)
		return nil
	})
	// Журнал аудита: вывоз в приёмник. Строится ДО запуска задач, чтобы ошибка
	// сборки останавливала старт, а не всплывала фоном: журнал, который не
	// вывозится, снаружи неотличим от журнала, в котором нечего вывозить.
	auditShipper, err := buildAuditShipper(pool, metricsReg.OutboxRecorder(), logger)
	if err != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		return fmt.Errorf("audit shipper wiring: %w", err)
	}
	tasks = append(tasks, func() error {
		return auditShipper.Run(taskCtx)
	})
	// ВОЗВРАТА ОТРАВЛЕННЫХ СТРОК у журнала нет, и это следствие контракта
	// приёмника, а не упущение: класса «не приму никогда» у него не существует,
	// поэтому травить нечего — непринятая запись ждёт следующей попытки.

	// Рост числа ЛИЧНОСТЕЙ. Потолок на аккаунты личности (484002) обходится
	// заведением личностей, и это накопление не производила ни одна величина:
	// «личностей за всё время» и «сколько их появилось за час» не спрашивал
	// никто. Замер читает НАКОПИТЕЛЬНЫЙ журнал (задача kacho#619) — падать этой величине
	// некуда, поэтому над ней определён рост, — и держит рядом счётчик своих
	// исходов, иначе ноль на витрине означал бы сразу и «личностей не было», и
	// «замер не снят». Это страховка, а не мера: отказ по такому порогу пришёл бы
	// следующему честному человеку, поэтому порог только наблюдается.
	// Петля обновления снимка каталога. БЕЗ НЕЁ снимок наполняется однажды на
	// старте и больше не перечитывается: снятие модуля перестаёт доезжать до
	// пути запроса до перезапуска службы, и состояние не сходится само (kacho#1945).
	// Отказ круга петлю не прерывает — он уже сообщён журналом и счётчиком, а
	// прекращение обновлений сменило бы ограниченное отставание на бессрочное.
	// Провязку держит гейт `TestIAM1945_CatalogSnapshotBuiltByTheRootIsAlsoStartedByIt`:
	// построенный корнем снимок обязан быть им же и запущен.
	tasks = append(tasks, func() error {
		catalogSnapshot.Run(taskCtx, catalogSnapshotRefreshPeriod())
		return nil
	})

	identityGrowth := newIdentityGrowthSampler(kanamepg.NewIdentityGrowthRepo(pool))
	metricsReg.NewIdentityGrowthCollector(identityGrowth.Counts)
	tasks = append(tasks, func() error {
		identityGrowth.Run(taskCtx, logger)
		return nil
	})

	// Сверщик стартового администратора. Выдаёт `system_admin@cluster_root`
	// пользователю, названному KANAME_BOOTSTRAP_ROOT_EMAIL, и ставит кортеж FGA в
	// транзакционный fga_outbox, из которого триггер сворачивает прямой факт в
	// той же фиксации. Строка пользователя отражается лишь при первом входе или
	// вставке фикстуры — это гонится со стартом, — поэтому однократный вызов
	// пропустил бы её, и кортеж администратора кластера не записался бы вовсе
	// (дефект B). Сверщик повторяет попытки, пока выдача не зафиксируется; по
	// контракту он нефатален (удобство старта по мере возможности, никогда не
	// жёсткий барьер). Без переменной окружения — пустая операция.
	bootstrapEmail := os.Getenv("KANAME_BOOTSTRAP_ROOT_EMAIL")
	bootstrapReconciler := seed.NewBootstrapReconciler(
		func(ctx context.Context) (seed.BootstrapAdminResult, error) {
			return seed.RunBootstrapAdmin(ctx, pool, logger, seed.BootstrapAdminInput{Email: bootstrapEmail})
		},
		seed.BootstrapReconcilerConfig{
			Interval: 10 * time.Second,
			Logger:   logger.With(slog.String("component", "bootstrap_admin_reconciler")),
			// Исход КАЖДОЙ попытки уезжает счётчиком: петля незавершающая по
			// контракту и на неисполнимом посеве печатает только Debug, поэтому
			// «доступ не выдан ни разу» иначе неотличимо от «выдан сразу».
			Observer: metricsReg.NewBootstrapAdminRecorder(),
		},
	)
	tasks = append(tasks, bootstrapAdminTask(logger, bootstrapEmail, func() error {
		return bootstrapReconciler.Run(taskCtx)
	}))

	// γ — исполнитель сверки (эпик «Resource-scoped AccessBinding», D7). Дренирует
	// resource_reconcile_outbox (Q1=(c), по событиям; пишется атомарно в
	// RegisterResource) → заново оценивает выдачи, ссылающиеся на изменённый
	// объект (членство по селектору, вхождение byName, проверка PENDING→ACTIVE),
	// И периодически подметает каждую селекторную выдачу (D12, эшелон защиты), а
	// также снимает выдачи с истёкшим TTL (D9, жадный отзыв). Исполнитель внутри
	// процесса (новой посадки нет); по контракту нефатален.
	reconcileAdapter := kanamepg.NewReconcileAdapter(pool, catalogSnapshot)
	reconcileEngine := reconcile.New(reconcileAdapter,
		logger.With(slog.String("component", "rsab_reconciler")), catalogSnapshot)
	// resource_reconcile_outbox дренажится NOTIFY-driven (паритет с fga_outbox drainer):
	// AFTER INSERT триггер (миграция 0042) шлет pg_notify на канал
	// kaname_resource_reconcile_outbox, reconcileAdapter LISTEN'ит его и будит worker —
	// смена меток ресурса материализует label-selector грант в пределах одного reconcile-
	// прохода, а не ждет poll-тика. DrainInterval теперь poll-fallback на пропущенный NOTIFY
	// (idle-conn-reset): NOTIFY несет latency, поэтому дефолт поднят со 150ms до 1s — реже
	// холостых claim'ов, а recovery при потере NOTIFY все равно ≤1s (и под 30s sweep'ом).
	// Sweep (полный проход) остается 30s как defense-in-depth. Оба интервала override-ятся env.
	//
	// Обе величины — ВТОРАЯ ступень цепочки отзыва гранта, и обе судятся при
	// старте: посадка, объявившая обход шире потолка политики, процесс не
	// поднимает. Пара читается ОДИН раз и той же парой уезжает в воркер —
	// прочтя ручку дважды, страж и воркер разошлись бы там, где переменную
	// меняли между вызовами. Разбор — `reconcile_window.go`.
	reconcileWindows := readReconcileWindows()
	if err := reconcileWindows.validate(authz.RevocationPolicy.MaterializationCeiling); err != nil {
		return err
	}
	reconcileWorker := seed.NewReconcileWorker(reconcileEngine, reconcileAdapter, seed.ReconcileWorkerConfig{
		SweepInterval: reconcileWindows.Sweep,
		DrainInterval: reconcileWindows.Drain,
		Notify:        reconcileAdapter,
		Logger:        logger.With(slog.String("component", "rsab_reconciler")),
	})
	tasks = append(tasks, func() error {
		logger.Info("rsab reconciler-worker starting (selector membership + containment + expiry)")
		return reconcileWorker.Run(taskCtx)
	})

	// Досев и сводящий проход на старте (старт не роняют): (1) выдача владельца
	// аккаунтам, которых миграция не видела (идемпотентный SQL); (2) СВОДЯЩИЙ
	// проход по всем действующим выдачам под замком-одиночкой процесса — при N
	// репликах его исполняет одна; (3) отчёт сверки, журналируемый как ворота.
	// Обход по таймеру реконсайлера выше держит сведёнными выдачи с селектором и
	// с двумя и более субъектами; у выдачи одному субъекту лишний кортеж после
	// смены вычисления снимает только сводящий проход, поэтому он повторяется по
	// такту (kaname#1006). Один BackfillAdapter над пулом — у прохода и у отчёта.
	backfillAdapter := kanamepg.NewBackfillAdapter(pool)
	// Сводящий проход — путь отзыва лишнего кортежа у выдачи одному субъекту
	// (kaname#1006): у каждой выдачи свой срок, исход по выдаче — в счётчик, и
	// проход повторяется по такту (задача ниже), а не только при старте. Ручки —
	// `binding_converge_wiring.go`, читаются один раз.
	convergeWindows := readBindingConvergeWindows()
	backfillRunner := seed.NewBackfillRunner(
		reconcileEngine,
		backfillAdapter,
		seed.BackfillConfig{
			Logger:         logger.With(slog.String("component", "p8_backfill")),
			BindingTimeout: convergeWindows.BindingTimeout,
			Observer:       metricsReg.NewBindingConvergeRecorder(),
		},
	)
	// Такт стартует ПОСЛЕ стартовой задачи досева (на любом её исходе): первый
	// проход обязан идти после пересчёта проекций ролей, а не наперегонки с ним.
	startupSeedDone := make(chan struct{})
	tasks = append(tasks, func() error {
		select {
		case <-startupSeedDone:
		case <-taskCtx.Done():
			return nil
		}
		backfillRunner.RunEvery(taskCtx, convergeWindows.Interval)
		return nil
	})
	verifyGate := seed.NewVerifyGate(backfillAdapter,
		logger.With(slog.String("component", "p8_verify_gate"))).
		// Страж переключения Design-B: НАСТОЯЩИЙ Check по тройке требуемого
		// отношения каждой живой выдачи — доказывает, что материализованный кортеж
		// v_* СВОДИТСЯ к отношению исполнения, по которому судит каталог, а не
		// только что ведомость непуста (слепая зона класса дефекта Design-A). nil
		// допустим (проверяющий недоступен → нефатальный пропуск).
		WithRelationChecker(svcs.ownGates)
	// Разовая уборка выдач, чья область УЖЕ УДАЛЕНА (kacho#810, продолжение kacho#792).
	//
	// ПОЧЕМУ ПЕРЕД ПОДМЁТКОЙ РЕКОНСАЙЛА, А НЕ ПОСЛЕ. Подмётка обходит КАЖДУЮ
	// активную выдачу и материализует её кортежи — включая висячие. Пойди уборка
	// второй, тот же старт сперва выписал бы кортежи выдачам, которые сам же
	// сейчас снимет: лишняя работа, лишние строки очереди и пара «выдача-отзыв» на
	// одном ключе партиции. Уборка первой снимает строки до того, как подмётка их
	// увидит, и обходу нечего материализовать.
	//
	// ПОЧЕМУ ЭТО БЕЗОПАСНО ЗАПУСКАТЬ САМО. Обе таблицы — и `access_bindings`, и
	// `projects`/`accounts` — лежат в ОДНОЙ базе iam, то есть в одной единице
	// снятия и восстановления копии. Состояния «проекты потерялись, выдачи
	// остались» согласованное восстановление не производит by construction,
	// поэтому порога вида «слишком много, отказываюсь» здесь нет: на живом стенде
	// висячими были 145 выдач из 193, и любой правдоподобный порог отказал бы
	// ровно там, где уборка и нужна. Радиус одного старта ограничен потолком
	// прогона, каждая область оставляет событие аудита.
	orphanScopeSweeper := seed.NewOrphanScopeSweeper(kanameRepo, kanamepg.NewOrphanScopeAdapter(pool),
		seed.OrphanScopeConfig{Logger: logger.With(slog.String("component", "orphan_scope_sweep"))})
	// Проход по строкам зеркала, оставшимся БЕЗ РОДИТЕЛЯ (`kacho#2051`).
	//
	// Провязан РЯДОМ с уборкой висячих областей и по тем же причинам: обе читают
	// собственную базу iam, обе идемпотентны, обе берут общий на кластер замок и
	// ограничены потолком прогона. Ключи замков РАЗНЫЕ ("OSSW" против "OMSW") —
	// два разных прохода не вправе исключать друг друга.
	//
	// Почему на старте, а не по расписанию: осиротевшая строка не лечится сама и
	// не лечится арендатором — она просто невидима материализации, и чем дольше
	// живёт, тем дольше владелец не видит своего ресурса. Старт — момент, когда
	// проход заведомо никому не мешает.
	orphanMirrorSweeper := seed.NewOrphanMirrorSweeper(kanamepg.NewOrphanMirrorAdapter(pool),
		seed.OrphanMirrorConfig{Logger: logger.With(slog.String("component", "orphan_mirror_sweep"))})
	// Проход по строкам зеркала, чей проект НАЗВАН и не резолвится (стадия S2
	// приёмки `non-empty-project-is-not-deleted.md`, kacho#1231).
	//
	// Предмет не пересекается с проходом выше: тот берёт строки без родителя
	// вовсе, этот — с родителем, которого нет. Это остаток, который отказ по
	// непустоте не закрывает по построению (окно доставки регистрации), и без
	// прохода он невидим: такую строку не видит ни одна выдача и не назовёт ни
	// один отказ. Проход ничего не удаляет и родителя не выдумывает — только
	// называет и печатает перепись; свой ключ замка ("OMPN"), свой потолок.
	danglingProjectMirrorSweeper := seed.NewDanglingProjectMirrorSweeper(
		kanamepg.NewDanglingProjectMirrorAdapter(pool),
		seed.DanglingProjectMirrorConfig{Logger: logger.With(slog.String("component", "dangling_project_mirror_sweep"))})
	// Счётчик исходов пересчёта проекции глаголов роли — по одной системной роли.
	// Успехи считаются наравне с отказами: без знаменателя «ноль отказов» не
	// отличается от «пересчёта не было вовсе».
	roleVerbReseed := metricsReg.NewRoleVerbReseedRecorder()
	// Счётчик исходов пересчёта проекции объявленных сегментов правила — своя
	// метрика, а не метка у соседней: у полос разные предметы, и общая метка
	// поднимала бы тревогу одинаково там, где арендатор получает отказ, и там,
	// где перестаёт работать наша собственная проверка (kacho#1821).
	ruleRefReseed := metricsReg.NewRuleRefReseedRecorder()
	tasks = append(tasks, func() error {
		defer close(startupSeedDone)
		if ores, oerr := orphanScopeSweeper.RunOnce(taskCtx); oerr != nil {
			logger.Warn("orphan-scope sweep failed (next boot will retry)",
				slog.Any("err", oerr),
				slog.Int("scopes_revoked", ores.ScopesRevoked),
				slog.Int("bindings_revoked", ores.BindingsRevoked))
		}
		// Перепись прохода по зеркалу печатается НА ЛЮБОМ исходе, включая чистый:
		// «сирот ноль» обязано быть отличимо от «проход не состоялся», а строки
		// журнала у этих двух случаев иначе одинаковы — их нет.
		if mres, merr := orphanMirrorSweeper.RunOnce(taskCtx); merr != nil {
			logger.Warn("orphan-mirror sweep failed (next boot will retry)",
				slog.Any("err", merr), slog.String("census", mres.Census()))
		} else if mres.Executed {
			logger.Info("orphan-mirror sweep: "+mres.Census(),
				slog.Int("left_to_owner", len(mres.LeftToOwner)))
		}
		// Перепись прохода по родителю-проекту печатается на ЛЮБОМ исходе,
		// включая чистый, и на чистом дереве проход ПРОХОДИТ, а не падает:
		// проверка, падающая на достижении своей цели, толкает держать сироту
		// ради зелёного.
		if dres, derr := danglingProjectMirrorSweeper.RunOnce(taskCtx); derr != nil {
			logger.Warn("dangling-project-mirror sweep failed (next boot will retry)",
				slog.Any("err", derr), slog.String("census", dres.Census()))
		} else if dres.Executed {
			logger.Info("dangling-project-mirror sweep: "+dres.Census(),
				slog.Int("named", len(dres.Named)), slog.Bool("truncated", dres.Truncated))
		}
		// Разность зеркала и живого каталога — ЧИТАЕТСЯ, а не чинится
		// (kacho#1828). Держателем может быть только чтение: ключ на
		// `(dotted, live)` запретил бы снятие типа, пока у арендатора есть хоть
		// один такой ресурс, и довод записан у самого оператора вставки.
		//
		// Отзыв ОТНИМАЕТ доступ, поэтому проход ничего не отзывает и ничего не
		// роняет: решение по каждой неразрешимой строке принимает владелец. Чего
		// ему не хватало — ВЕЛИЧИНЫ: читатель в дереве был, а на поднятом стенде
		// его не спрашивал никто, и «разности нет» было неотличимо от «не
		// мерили» ни одной строкой журнала.
		//
		// Перепись печатается НА ЛЮБОМ исходе, включая чистый, и называет оба
		// числа. Уровень выбирается по НЕРАЗРЕШИМОЙ части: снятое с преемником —
		// объявленное свойство дерева, и жалоба на нём краснела бы после всякого
		// законного снятия типа.
		if drows, dscanned, derr := resource_mirror.Divergence(taskCtx, pool); derr != nil {
			logger.Warn("resource-mirror divergence unread (next boot will retry)",
				slog.Any("err", derr))
		} else if census := resource_mirror.DivergenceCensus(drows, dscanned); len(
			resource_mirror.UnresolvableDivergence(drows)) > 0 {
			logger.Warn("resource-mirror divergence: "+census,
				slog.Int("unresolvable", len(resource_mirror.UnresolvableDivergence(drows))))
		} else {
			logger.Info("resource-mirror divergence: " + census)
		}
		if oerr := seed.BackfillOwnerBindings(taskCtx, pool); oerr != nil {
			logger.Warn("p8 backfill: owner-binding data-backfill failed (sweep/next boot will retry)", slog.Any("err", oerr))
		}
		// Страж расхождения литерала и строк каталога отработал РАНЬШЕ — в
		// композиционном корне, до сборки служб (задача kacho#1816): его чтением
		// наполняется снимок каталога, а снимок нужен use-case'ам. Порядок,
		// ради которого страж заводился, этим не нарушен: пересчёт ниже
		// по-прежнему идёт ПОСЛЕ стража, поэтому расхождение не проявляется
		// отказом пересчёта — то есть чужой полосой.
		//
		// Пересчёт проекции «роль → тип объекта × глагол» — СВОЯ полоса отказа.
		//
		// Проекция есть то, из чего цепь вердикта собирает ответ «разрешено ли
		// действие». Пока её отказ приезжал сюда обёрнутым в ошибку досева выше,
		// он печатался уровнем ЧУЖОЙ полосы (`Warn` — «ожидаемое отклонение,
		// ретрай штатен»), и различить «база не ответила» от «механизм не
		// работает» было нечем. Полос две, и они расходятся по исходу:
		// транзиентная сообщается `Error` и старт не роняет (проекция
		// самолечащая, менять ограниченное отставание на полный отказ службы
		// нельзя); структурная — системные роли есть, пересеяна ни одна —
		// РОНЯЕТ старт, потому что «повтори позже» на ней есть ложь.
		verbs, verr := seed.ReseedSystemRoleVerbs(taskCtx, kanameRepo, pool,
			catalogSnapshot.Facts(), roleVerbReseed)
		if verr != nil {
			logger.Error("пересчёт проекции глаголов роли отказал",
				slog.Any("err", verr),
				slog.Int("roles_examined", verbs.Examined),
				slog.Int("roles_reseeded", verbs.Reseeded),
				slog.Int("roles_failed", verbs.Failed))
		}
		// Перепись печатается ВСЕГДА, независимо от исхода: без неё «ноль
		// пересеянных» неотличимо от «ноль прочитанных».
		logger.Info("перепись пересчёта проекции глаголов роли",
			slog.Int("roles_examined", verbs.Examined),
			slog.Int("roles_reseeded", verbs.Reseeded),
			slog.Int("roles_failed", verbs.Failed),
			slog.Int("pairs", verbs.Pairs))
		if verbs.Structural() {
			return fmt.Errorf("пересчёт проекции глаголов роли: осмотрено %d системных ролей, "+
				"пересеяно 0 — повтор даст то же самое, и цепь вердикта собирает ответ "+
				"«разрешено ли действие» из строк, которых нет: %w",
				verbs.Examined, verr)
		}
		// Пересчёт проекции ОБЪЯВЛЕННЫХ СЕГМЕНТОВ правила — третья сторона того
		// же правила и СВОЯ полоса отказа (kacho#1821).
		//
		// Системная роль заводится сырым SQL миграции и путём пользовательской
		// роли не проходит никогда. Без этой полосы у роли, заведённой будущей
		// миграцией, строк `role_rule_ref` не появлялось бы вовсе — ключи
		// референта оказывались бы ни при чём, и молчаливый пропуск, ради
		// которого референт заводился, вернулся бы для системной половины.
		//
		// ПОЧЕМУ ЭТА ПОЛОСА НЕ РОНЯЕТ СТАРТ, в отличие от соседней. Проекция
		// глаголов есть то, из чего собирается ответ «разрешено ли действие»: её
		// отсутствие ОТНИМАЕТ доступ молча, и «повтори позже» на ней есть ложь.
		// Проекция сегментов — СТРАЖ ЦЕЛОСТНОСТИ правила: её отсутствие доступа
		// не отнимает, оно снимает проверку. Ронять службу целиком из-за
		// ненаписанного стража значило бы менять ограниченную потерю проверки на
		// полный отказ. Поэтому здесь `Error` плюс счётчик плюс перепись — и
		// структурная полоса НАЗВАНА в тексте, а не проглочена.
		refs, rerr := seed.ReseedSystemRoleRuleRefs(taskCtx, kanameRepo, pool, ruleRefReseed)
		if rerr != nil {
			logger.Error("пересчёт проекции сегментов правила отказал",
				slog.Any("err", rerr),
				slog.Bool("structural", refs.Structural()),
				slog.Int("roles_examined", refs.Examined),
				slog.Int("roles_reseeded", refs.Reseeded),
				slog.Int("roles_failed", refs.Failed))
		}
		// Перепись печатается ВСЕГДА, независимо от исхода: без неё «ноль
		// пересеянных» неотличимо от «ноль прочитанных».
		logger.Info("перепись пересчёта проекции сегментов правила",
			slog.Int("roles_examined", refs.Examined),
			slog.Int("roles_reseeded", refs.Reseeded),
			slog.Int("roles_failed", refs.Failed),
			slog.Int("refs", refs.Refs))
		// Перепись встроенного доступа. Системные выдачи можно ОТОЗВАТЬ — это и есть
		// предмет kacho#893/#895, — поэтому их отсутствие обязано быть видно оператору, а
		// не выглядеть поломкой продукта.
		seed.LogSystemGrantCensus(taskCtx, pool, logger.With(slog.String("component", "system_grants")))
		// Перепись прохода печатает сам проход, на любом исходе. Отказ старт не
		// роняет: отказавшие выдачи повторяет такт `RunEvery` (задача выше), без
		// перезапуска процесса.
		res, berr := backfillRunner.RunOnce(taskCtx)
		if berr != nil {
			logger.Error("сводящий проход по выдачам на старте свёл не все — повторит такт",
				slog.Duration("interval", convergeWindows.Interval),
				slog.Bool("executed", res.Executed),
				slog.Int("bindings_failed", res.BindingsFailed),
				slog.Any("err", berr))
		}
		if res.Executed {
			report, verr := verifyGate.Verify(taskCtx)
			if verr != nil {
				logger.Warn("p8 verify-gate: verify failed", slog.Any("err", verr))
			} else {
				logger.Info("p8 verify-gate result (contract gated on no-access-loss)",
					slog.Bool("no_access_loss", report.NoAccessLoss),
					slog.Int("bindings_checked", report.BindingsChecked),
					slog.Int("failures", len(report.Failures)))
			}
			// ДЫМОВАЯ ПРОБА ПРЯМОГО ПУТИ НА СТАРТЕ СНЯТА (#119), и снята вместе с
			// предметом, а не ослаблена.
			//
			// Она заводила в БОЕВОМ зеркале поднятого кластера синтетический объект
			// ЧУЖОГО домена (`vpc.network`) внутри настоящего аккаунта. Две беды
			// сразу. Установка без модулей платформы такой живой строки каталога не
			// несёт — у пробы там нет предмета вовсе, при том что служба исправна.
			// И убирала она за собой половину: строка зеркала снималась, а строки
			// ведомости, которые проба вызвала своим сведением, оставались — и
			// следующий отчёт честно находил материализованное чтение на объекте,
			// которого больше нет. На чистой установке это печаталось отказом о
			// СОБСТВЕННОЙ синтетике, неотличимым для оператора от поломки.
			//
			// Свой тип вместо чужого не подошёл, и это ЗАМЕР, а не мнение: ни один
			// из семи собственных типов службы содержательного кортежа владельца не
			// материализует — материализуется зеркальный тип домена-потребителя.
			// Значит «проверять себя своим типом» этим механизмом невыразимо.
			//
			// Свойство, которое проба утверждала, покрыто интеграционно и без неё:
			// прямая материализация свежего объекта проверяется против настоящего
			// сведения — селекторная полоса
			// (`TestP8_05_VerifyGate_NoAccessLoss_ForwardMaterializes`), владельческая
			// (`Test224_OwnerWildcard_ForwardMaterializesContent`), и эти проверки
			// исполняются конвейером, тогда как отчёт на старте ничего не гейтил.
			// Сам механизм вместе с методами порта снят из дерева (#148).
			// Отчёт о том, РАЗРЕШАЮТСЯ ли материализованные чтения (F-12 / VBC-19):
			// настоящий Check по каждой тройке v_* активной выдачи. Именно отчёт:
			// вызывающий журналирует вердикт и ничего не переключает (#119).
			relReport, rerr := verifyGate.VerifyRelationSatisfiesAction(taskCtx)
			if rerr != nil {
				logger.Warn("p8 verify-gate: relation-satisfies-action check failed", slog.Any("err", rerr))
			} else {
				logger.Info("p8 verify-gate: do materialized read tuples resolve",
					slog.Bool("no_access_loss", relReport.NoAccessLoss),
					slog.Int("bindings_checked", relReport.BindingsChecked),
					slog.Int("failures", len(relReport.Failures)),
					slog.Int("admission_refused", len(relReport.Refusals)))
			}
		}
		return nil
	})

	// Пересчёт ОЧЕРЕДИ глаголов правил (kaname#878) — своя задача, а не шаг
	// досева: он идёт, пока жив процесс (очередь пополняется и после опустения —
	// перекатка, сорванный пересчёт на старте), и досев за ним не ждёт. Пока роль в очереди, её строки селекторов несут верхнюю границу
	// глаголов («по роли»), и окно миграции открыто — поэтому перепись КАЖДОГО
	// прохода печатается с длиной очереди, а отказ прохода — уровнем Error.
	// Старт он не роняет: отказ роли оставляет её в очереди до следующего
	// прохода, а не отнимает доступ. Снимается вместе с переходным стражем схемы
	// при пустой очереди на всех установках (шапка `seed/selector_verbs_queue.go`).
	tasks = append(tasks, func() error {
		derr := seed.DrainSelectorVerbsQueue(taskCtx, kanameRepo, pool, catalogSnapshot,
			selectorVerbsQueueRetry, func(c seed.SelectorVerbsCensus, perr error) {
				attrs := []any{
					slog.Int("roles_examined", c.Examined),
					slog.Int("roles_regrained", c.Regrained),
					slog.Int("roles_failed", c.Failed),
					slog.Int("queue_pending", c.Pending),
				}
				if perr != nil {
					logger.Error("пересчёт очереди глаголов правил отказал", append(attrs, slog.Any("err", perr))...)
					return
				}
				logger.Info("перепись пересчёта очереди глаголов правил", attrs...)
			})
		if derr != nil && taskCtx.Err() == nil {
			logger.Error("пересчёт очереди глаголов правил остановлен", slog.Any("err", derr))
		}
		return nil
	})

	// Уборки по сроку — ресурсного журнала подписки (своим уборщиком, довод в
	// `subscription_wiring.go`) и таблиц службы — запускаются ЗДЕСЬ: после
	// последнего отказа старта и на корневом контексте задач (#253, шапка
	// `startRetentionSweeps`).
	if err := startRetentionSweeps(taskCtx, retentionSweeper, pool, cfg, logger); err != nil {
		return err
	}

	var group errgroup.Group
	for _, task := range tasks {
		group.Go(task)
	}
	err = group.Wait()
	cancel()
	return err
}

// identityUnary / identityStream — цепочка извлечения личности вызывающего,
// ОДНА на оба листенера.
//
// Пара, а не одиночный извлекатель: сначала классифицируется транспорт и
// снимается личность клиентского сертификата (CertIdentityExtract), и только
// потом переданная в метаданных личность конечного пользователя принимается —
// и только от пира, чья личность сертификата перечислена оператором.
//
// Список отправителей приходит ТОЛЬКО из конфигурации и никогда не задаётся
// здесь литералом: пустой список для corelib означает не «никому», а «любому
// пиру с проверенным сертификатом» (pkg/grpcsrv principalIsTrusted сужает круг
// лишь на непустом списке), и переданная личность становится субъектом решения о
// правах. Боевой режим на пустом списке не стартует (config.Validate →
// validateProductionTrustedForwarders).
//
// Почему список ОБЩИЙ на оба листенера. Законные отправители ходят и туда, и
// туда: api-gateway держит адреса обоих портов (KACHO_API_GATEWAY_IAM_GRPC :9090
// и ..._IAM_INTERNAL_GRPC :9091), consumer-модули берут проект на :9090 и зовут
// Check / fga-proxy на :9091, оператор пространств имён читает аккаунты и проекты
// на :9090. Внутренний периметр от сужения не освобождён — «internal = trusted»
// у нас запрещённое допущение. НА КАКОМ RPC отправитель вправе появиться,
// решают пер-RPC политики вызывающего (authzguard.PublicCallerPolicy на :9090,
// authzguard.CallerPolicy на :9091) — это ортогональный, второй слой.
// Домен доверия приходит ОТТУДА ЖЕ — из конфигурации, и никогда не задаётся
// здесь литералом. Круг отправителей отвечает на вопрос «кому позволено
// говорить за пользователя», домен — на предыдущий: чьи предъявители вообще
// наши. Скомпилированный домен означал бы, что установка меняет его только
// пересборкой: сертификаты выпускаются под доменом из величины профиля, и
// правка величины оставила бы принимающую сторону прежней — молча.
func identityUnary(cfg config.Config) []grpc.UnaryServerInterceptor {
	return grpcsrv.PrincipalExtractUnary(cfg.AuthN.TrustDomain(), cfg.AuthN.TrustedForwarders())
}

func identityStream(cfg config.Config) []grpc.StreamServerInterceptor {
	return grpcsrv.PrincipalExtractStream(cfg.AuthN.TrustDomain(), cfg.AuthN.TrustedForwarders())
}

// publicIdentityUnary / publicIdentityStream — цепочка личности ПУБЛИЧНОГО
// слушателя: общая пара извлечения плюс читатель предъявленного удостоверения.
//
// # Почему у публичного слушателя свой сборщик
//
// Слушателей два, и вопрос «чем вызывающий назвался» у них РАЗНЫЙ. К внутреннему
// дозванивается соседний модуль по mTLS, и предъявленное удостоверение там —
// лишний способ назваться, которого никто не просил. К публичному приходит
// арендатор, у которого в чужом облаке нет ни нашего края, чтобы передать
// личность, ни модульного сертификата; предъявленное — единственное, чем он
// располагает.
//
// # Почему ДОБАВЛЕНИЕ, а не своя сборка
//
// Читатель ДОПОЛНЯЕТ общую пару, а не заменяет её: собранная с нуля публичная
// цепочка потеряла бы круг разрешённых отправителей, и прежний путь отвалился
// бы молча — пробы внутреннего слушателя остались бы зелёными.
//
// # Читатель стоит НАД парой, и это единственная работающая форма
//
// Пара извлечения на двух ветках из трёх снимает носитель личности ЯВНЫМ
// снятием, и снятие имеет приоритет над любым последующим назначением — так
// устроен носитель платформы, и устроен намеренно. Читатель, поставленный
// после пары, назначил бы вызывающего, и назначение молча не доехало бы до
// обработчика. Поэтому читатель прогоняет пару сам и решает по её вердикту:
// полосы взаимно исключают друг друга, и решение о том, КТО звонит,
// принимается в одном месте. Держится это исходом, а не комментарием:
// личность, назначенная читателем, обязана доживать до обработчика.
//
// # Последнее звено — чем звонит человек, переданный краем
//
// За решением «кто звонит» стоит читатель переданного краем удостоверения
// (`internal/edgecredential`, kaname#677): номер записи сессии и номер
// выпуска, которыми край называет текущую сессию человека. Он берёт вердикт
// пары о доверенном отправителе и своего не заводит, поэтому стоит ПОСЛЕ неё и
// внутри этого сборщика: цепочка, собранная мимо сборщика, потеряла бы его
// молча, а пробы размещения (`edge_credential_chain_test.go`) собирают её им.
// Внутреннему слушателю он не нужен: глагол, читающий текущую сессию (снятие
// ключа доступа), там не смонтирован.
func publicIdentityUnary(cfg config.Config, presented *presentedcred.Reader) []grpc.UnaryServerInterceptor {
	pair := identityUnary(cfg)
	if presented == nil {
		return append(pair, edgecredential.Unary())
	}
	return []grpc.UnaryServerInterceptor{presented.UnaryOver(pair), edgecredential.Unary()}
}

func publicIdentityStream(cfg config.Config, presented *presentedcred.Reader) []grpc.StreamServerInterceptor {
	pair := identityStream(cfg)
	if presented == nil {
		return append(pair, edgecredential.Stream())
	}
	return []grpc.StreamServerInterceptor{presented.StreamOver(pair), edgecredential.Stream()}
}

// requireGRPCListenerMTLS — оба gRPC-слушателя обязаны идти под TLS в боевом
// режиме.
//
// M1 — инвариант старта: боевой режим ОБЯЗАН вести внутренний слушатель
// кластера (:9091) под mTLS RequireAndVerifyClientCert. Без этого у политики
// вызывающего по RPC нет проверенного SAN модуля, по которому судить, — любой,
// кто дошёл до :9091, обошёл бы authN/authZ. Никакого молчаливого спуска к
// незащищённому в боевом режиме. Обращённый к арендатору :9090 несёт то же
// требование.
//
// # ПОЧЕМУ ИМЕНОВАННЫЙ СТРАЖ, А НЕ ВСТРОЕННАЯ ВЕТВЬ (задача kacho#2514)
//
// Условие жило встроенной ветвью в теле подъёма, и проба боевого профиля
// повторяла его СВОИМИ утверждениями — то есть два места об одном предмете,
// расходящиеся молча: подъём обзаводится новым условием, а проба о нём не знает
// и остаётся зелёной. Ровно этот класс закрыт для соседей тем, что проба зовёт
// САМИ стражи; безымянное условие позвать нельзя by construction, поэтому оно
// оставалось исключением, о котором никто не решал.
//
// Имя здесь — не косметика: гейт `TestEveryNamedStartupGuardIsJudgedByTheProductionProfile`
// требует, чтобы КАЖДЫЙ именованный страж судился пробой боевого профиля, и
// вынесение условия под имя вводит его в область этого гейта.
func requireGRPCListenerMTLS(productionMode bool, mtlsCfg config.MTLSConfig) error {
	if !productionMode {
		return nil
	}
	if !mtlsCfg.InternalServerMTLS.Enable {
		return fmt.Errorf("production mode requires internal listener mTLS " +
			"(RequireAndVerifyClientCert); refusing to start with insecure :9091")
	}
	if !mtlsCfg.PublicServerMTLS.Enable {
		return fmt.Errorf("production mode requires public listener mTLS (TLS); " +
			"refusing to start with insecure :9090")
	}
	return nil
}

// requireRegistryTokenTLS — слушатель docker-token (`/iam/token`, :9096) в
// production обязан нести TLS.
//
// По этому сокету едет HTTP Basic, чей пароль — ПРИВАТНЫЙ КЛЮЧ ключа служебной
// учётки: сервер его не хранит вовсе (выводит SPKI из предъявленного и сверяет с
// сохранённым публичным), поэтому этот хоп — единственное место в системе, где
// приватный ключ транзитит. Срок жизни ключа не ограничен и ротации нет: снятый с
// провода, он предъявляется напрямую, без окна TTL — то есть ущерб не ограничен
// ничем, в отличие от короткоживущего bearer'а на соседней ноге, которая гейт
// получила давно.
//
// Пустой адрес ⇒ слушатель не поднимается, гейтить нечего. В dev — no-op
// (тот же порядок, что у прочих HTTP-рёбер: default-off, стенд байт-идентичен).
func requireRegistryTokenTLS(productionMode bool, addr string, mtlsCfg config.MTLSConfig) error {
	if !productionMode || strings.TrimSpace(addr) == "" {
		return nil
	}
	if !mtlsCfg.RegistryTokenServerMTLS.Enable {
		return fmt.Errorf("production mode requires TLS on the docker-token listener %s "+
			"(set KANAME_REGISTRYTOKEN_SERVER_MTLS_ENABLE=true with its cert/key): the "+
			"HTTP Basic password on this hop is the service-account key's private key, which "+
			"this server never stores and which never expires; refusing to start with it in the clear",
			addr)
	}
	return nil
}

// registryTokenRuntime — входы сборки докерной полосы, которые даёт не
// настройка, а композиционный корень: журнал, подписант, счётчик исходов и
// предел обращения авторитета к базе.
type registryTokenRuntime struct {
	logger                 *slog.Logger
	signer                 *tokensigner.Signer
	credentialKindObserver registrytokenuc.CredentialKindObserver
	basicCredentialTimeout time.Duration
	// source — правило адреса источника поверхности выдачи (Р7): ключ темпа
	// анонимной выдачи (kaname#928). Одно на все точки поверхности.
	source *issuingsource.Rule
}

// registryTokenBuildConfig — ЕДИНСТВЕННОЕ переложение настройки докерной полосы
// в вход её сборки.
//
// Функция отдельна от runServe затем, чтобы проба переложения судила тот самый
// вход, который получает сборка на живой посадке: ручка, объявленная в
// настройке и не переложенная сюда, — ручка без читателя (контроль на вид
// есть, предмета у него нет), и увидеть это можно только исходом сборки,
// собранной из настройки.
func registryTokenBuildConfig(rt config.RegistryTokenConfig, run registryTokenRuntime) (registrytokenwire.BuildConfig, error) {
	// Мгновение окна перехода берётся у настройки РАЗОБРАННЫМ: сборка полосы
	// получает мгновение, а не строку, и своего разбора не заводит. Второй
	// разборщик того же значения разошёлся бы с первым молча — и разошёлся бы
	// именно там, где расхождение не видно, потому что на годном входе оба
	// отвечают одинаково.
	window, err := rt.KeyMaterialWindowUntil()
	if err != nil {
		return registrytokenwire.BuildConfig{}, err
	}
	// Публичный принципал анонимного чтения (kaname#495) — тоже разобранным
	// стражем формы. Пустое — анонимный поток выключен, и вход без
	// удостоверения получает 401-вызов (fail-closed).
	anonymous, err := rt.AnonymousPrincipal()
	if err != nil {
		return registrytokenwire.BuildConfig{}, err
	}
	var source func(*http.Request) string
	if run.source != nil {
		// Доверенный пересыльщик точки (kaname#930) переносится как есть: его
		// форму в домене доверия разобрал страж старта `RegistryTokenConfig.Validate`.
		source = run.source.RegistryTokenPoint(rt.AnonymousForwarderSAN)
	}
	return registrytokenwire.BuildConfig{
		AnonymousClientID:        anonymous,
		AnonymousPerSourcePerSec: rt.AnonymousPerSourcePerSec,
		Source:                   source,
		Realm:                    rt.TokenIssuer(),
		Service:                  rt.TokenService(),
		Logger:                   run.logger,
		Signer:                   run.signer,
		TokenTTL:                 rt.TokenTTL(),
		KeyMaterialWindowUntil:   window,
		CredentialKindObserver:   run.credentialKindObserver,
		BasicCredentialTimeout:   run.basicCredentialTimeout,
	}, nil
}

// publicListenerChain — сборщик цепочки публичного слушателя (:9090), обеих
// полос: однократного вызова и потока.
//
// # Почему сборщик, а не сборка по месту
//
// Цепочку судят пробы — что ступень формы идентификатора стоит до двери у
// каждого глагола класса (IAM-PNE-1-21 А), что безымянный вызывающий не
// доходит до решателя. Собери проба цепочку сама — и она судила бы вторую
// проводку, которой в проде нет: звено, добавленное в корень, пробе осталось
// бы невидимым, и наоборот. Поэтому корень и пробы зовут ЭТУ функцию, а
// звенья, несущие собственные зависимости (политика вызывающего, ворота
// адреса, дверь), приходят параметрами: их строит корень из настройки, проба —
// из своего мира.
//
// Имена `publicUnary`, `publicStream`, `publicCallerPolicy`, `addressGate`, `cfg`
// несущие: по ним стражи текста корня (address_gate_wiring_test.go,
// trusted_forwarders_wiring_test.go) находят цепочку и её звенья.
func publicListenerChain(
	cfg config.Config,
	logger *slog.Logger,
	latency *grpcsrv.ServerLatency,
	permRegistry authzguard.DenyActionLookup,
	presentedReader *presentedcred.Reader,
	publicCallerPolicy *authzguard.PublicCallerPolicy,
	addressGate *authzguard.AddressGate,
	publicObjectDoor *authzguard.OwnDoor,
) (publicUnaryLinks []grpc.UnaryServerInterceptor, publicStreamLinks []grpc.StreamServerInterceptor, err error) {
	// Звено формы идентификатора строится из ТОЙ ЖЕ двери, которая стоит за
	// ним: оно читает её карту, и отказ сборки (нет судьи, судья не знает вида
	// глагола класса) — отказ старта, а не цепочка без звена.
	publicIDFormLink, err := publicObjectDoor.FormUnary(publicIDForm{})
	if err != nil {
		return nil, nil, err
	}

	// Anti-anonymous guard перед мутирующими RPC: минимальная защита от
	// анонимного создания Account/Project/AccessBinding/Group/SA/Role
	// в дополнение к вопросу о доступе через AuthorizeService.
	//
	// Порядок: измеритель задержки (оборачивает всё) → recovery → обогатитель
	// отказа → личность вызывающего (publicIdentityUnary: сертификат, переданная
	// личность от разрешённого отправителя, затем предъявленное удостоверение) →
	// пер-RPC политика вызывающего → ворота адреса → анти-аноним → форма
	// идентификатора → дверь.
	publicUnary := append([]grpc.UnaryServerInterceptor{
		// Измеритель задержки первым — он оборачивает цепочку целиком, поэтому
		// длительность и код накрывают ВЕСЬ вызов, включая вопрос о доступе.
		// Стоя внутри решения о доступе, он оставил бы неизмеренным каждый отказ
		// по правам — то есть исход, ради которого метрику и смотрят.
		latency.UnaryServerInterceptor(grpcsrv.ListenerPublic),
		// Перехват паники — сразу внутри измерителя: паника в любом нижележащем
		// звене или обработчике становится записанным в журнал codes.Internal
		// для ОДНОГО этого запроса, а не роняет весь процесс PDP (измеритель
		// всё равно учитывает код Internal, потому что перехват стоит внутри него).
		grpcsrv.UnaryPanicRecovery(logger),
		// Внешнее из звеньев авторизации — чтобы видеть отказ, порождённый ЛЮБЫМ
		// из них и обработчиком: прикрепляет машиночитаемую причину, по которой
		// различает клиент. Важнее всего это там, где iam сам решает об
		// авторизации по данным (строки, отфильтрованные по области): там край не
		// задаёт поглагольной проверки, и больше ничто на пути не называет
		// действие, а отказ по области был побайтово неотличим от промаха
		// каталога. См. deny_details.go.
		authzguard.DenyDetailUnary(permRegistry),
	}, publicIdentityUnary(cfg, presentedReader)...)
	publicUnary = append(publicUnary,
		publicCallerPolicy.Unary(),
		addressGate.Unary(),
		authzguard.AntiAnonymousUnary(logger),
		// Форма идентификатора — после подлинности (анониму она не отвечает) и
		// ДО вопроса о праве: ответ на неверную форму не зависит ни от
		// выданного, ни от того, администратор ли вызывающий (kaname#168).
		publicIDFormLink,
		// Дверь — ПОСЛЕДНЕЙ: субъект к этому месту уже назван и уже отсечён,
		// если он аноним, поэтому вопрос к модели задаётся только о том, кого
		// есть о чём спрашивать. Обратный порядок тратил бы обращение к модели
		// на запрос, который всё равно отвергнут.
		publicObjectDoor.Unary(),
	)
	publicStream := append([]grpc.StreamServerInterceptor{
		// Срок жизни подписки — своя серия и своя сетка корзин: это другая
		// величина, и общая с задержкой вызова не разрешала бы ни ту, ни другую.
		latency.StreamServerInterceptor(grpcsrv.ListenerPublic),
		grpcsrv.StreamPanicRecovery(logger),
	}, publicIdentityStream(cfg, presentedReader)...)
	publicStream = append(publicStream,
		publicCallerPolicy.Stream(),
		addressGate.Stream(),
		authzguard.AntiAnonymousStream(logger),
		// Та же дверь на второй полосе. Стримовых RPC у iam сегодня НОЛЬ
		// (`git grep -c 'returns (stream' -- proto/kaname/cloud/iam/v1` → 0),
		// поэтому провязка ничего не решает СЕЙЧАС и стоит здесь ради того,
		// чтобы решать, когда предмет появится: полоса без двери при полосе с
		// дверью — это различие, которого никто не принимал, и обнаружилось бы
		// оно первым же стримовым RPC. Соседняя политика провязана на обе полосы
		// по той же причине.
		//
		// Звена формы на этой полосе НЕТ, и это решение, а не пропуск: в классе
		// формы потоковых глаголов ноль, и проба
		// `TestIAM_PNE_1_21_A_FormStageHasNoStreamLane` краснеет на первом.
		publicObjectDoor.Stream(),
	)
	return publicUnary, publicStream, nil
}
