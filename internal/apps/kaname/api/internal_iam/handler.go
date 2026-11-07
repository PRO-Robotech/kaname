// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package internal_iam — InternalIAMService (только внутренний, порт gRPC :9091).
//
// Запрет №6 (Internal.* не публикуется на внешней точке входа): только внутренний сервис.
// Регистрируется ТОЛЬКО на внутреннем слушателе (порт 9091).
//
// Инвариант — INTERNAL-ONLY, а не «только gRPC». LookupSubject и Check несут
// http-аннотации, и api-gateway заводит им REST-маршруты на СВОЁМ внутреннем mux
// (`/iam/v1/internal/iam:{lookupSubject,check}`); на внешний listener они не
// выходят. Сам gateway ходит сюда gRPC-direct — чтобы его auth-интерсептор не
// рекурсировал через собственную цепочку (loop-prevention), а не потому что
// маршрута нет.
//
// Методы:
//   - LookupSubject(by external_id|id|email) — для auth-interceptor api-gateway
//     после валидации JWT.
//
// - Check — проверка прав на один кортеж; передаёт вызов AuthorizeService.
// Вызывается перехватчиками прав каждого RPC в
//
//	kacho-vpc / kacho-compute / kacho-loadbalancer.
package internal_iam

import (
	"context"
	stderrors "errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// Authorizer — узкий интерфейс порта над service.AuthorizeService, открывающий только
// проверку родного отношения, нужную стражу InternalIAMService.
// Реализуется *service.AuthorizeService напрямую либо
// декоратором с метриками (*metrics.InstrumentedAuthorizer), подключённым в
// корне сборки. Экспортирован, чтобы корень мог назвать его при
// выборе обычного варианта или варианта с метриками.
type Authorizer interface {
	CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error)
}

// subjectChanger — узкий интерфейс порта над service.SubjectChangeService,
// открывающий только сценарий PollSubjectChanges. Реализация —
// *service.SubjectChangeService.
type subjectChanger interface {
	PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) ([]service.SubjectChange, int64, error)
}

// relationWriteGate — узкий порт проверки прав RPC регистрации ресурсов.
// Authorize выводит личность служебной учётной записи из клиентского сертификата mTLS и
// проверяет ReBAC `fga_writer` на `cluster:cluster_root` (kacho#914). Реализация —
// *authzguard.RelationWriteGate.
type relationWriteGate interface {
	Authorize(ctx context.Context) (callerDomain string, err error)
}

// resourceRegistrar — узкий порт сценария RegisterResource /
// UnregisterResource. Реализация — *RegisterResourceUseCase. Register
// потребляет поля зеркала (метки и родительскую область), а также защитную
// source_version через registerInput; Unregister потребляет кортеж и
// source_version метки удаления через unregisterInput (строка зеркала удаляется по первичному ключу,
// условно по версии метки удаления).
type resourceRegistrar interface {
	Register(ctx context.Context, in registerInput) error
	Unregister(ctx context.Context, in unregisterInput) error
	RecordRefusal(ctx context.Context, in unregisterInput, unregister bool, outcome string) error
}

// roleCompiledReader — узкий порт чтения скомпилированной проекции разрешений
// роли (redesign-2026 F5 GetRoleCompiled). Реализация —
// *role.GetRoleCompiledUseCase, подключённый в корне сборки. nil → RPC отвечает
// закрытым отказом Unavailable. Ошибки (неверный id → InvalidArgument, отсутствие → NotFound)
// уже оформлены сценарием как статусы gRPC.
type roleCompiledReader interface {
	Execute(ctx context.Context, id domain.RoleID) ([]string, error)
}

// Handler — gRPC server для InternalIAMService.
type Handler struct {
	iamv1.UnimplementedInternalIAMServiceServer

	lookup        *LookupSubjectUseCase
	authz         Authorizer
	subjectChange subjectChanger
	roleCompiled  roleCompiledReader

	// Страж регистрации ресурсов. Оба поля nil, если стек регистрации
	// не подключён (деградация/dev): RegisterResource тогда возвращает
	// Unavailable, закрытый отказ.
	registrar resourceRegistrar
	regGate   relationWriteGate

	// basicCredentials — авторитет о предъявленном базовом секрете (kacho#1142).
	// nil → глагол fail-closed Unavailable.
	basicCredentials basicCredentialResolver

	// basicOutcomes — перепись исходов полосы базового секрета по глаголу и
	// исходу (kaname#379). Нулевое значение готово к работе.
	basicOutcomes basicCredentialCensus

	// logger — поверхность НАБЛЮДАЕМОСТИ отказов. Различимость причин отказа
	// живёт здесь, а не в том, что видит предъявитель: «ноль отказов за всю
	// жизнь контроля» обязано быть заметно, иначе мёртвый контроль невидим.
	logger *slog.Logger

	// adminCheck — дополнительный страж ReBAC system_admin@cluster для
	// привилегированных административных RPC (ForceLogout). nil → закрытый отказ стража.
	// См. requireSystemAdmin в force_logout.go.
	adminCheck authzguard.RelationChecker

	// operations — репозиторий Operation, в котором ForceLogout сохраняет строку операции
	// до изменения и окончательно после него. nil → RPC отвечает
	// закрытым отказом Unavailable вместо идентификатора несуществующей строки.
	operations forceLogoutOperationRepo

	// ownSessions — снятие НАШИХ записей сессии входа (`human_sessions`),
	// отсечка и запись события одной транзакцией (kaname#340). nil → ForceLogout
	// отвечает закрытым отказом Unavailable.
	ownSessions OwnSessions

	// cutoffClock — ОБЩИЙ для всех реплик источник момента отсечки ForceLogout
	// (kaname#589). nil → ForceLogout отвечает закрытым отказом Unavailable.
	cutoffClock revocationpolicy.Clock

	// modules — личности модулей установки (kaname#987): Check плоскости
	// данных ограничен доменом её модуля. Нулевое значение не признаёт никого,
	// и тогда привязка не применяется ни к кому — вызывающих этого глагола без
	// признанной личности пропускает или отвергает политика вызывающего, а через
	// внутренний REST-фронт их не пускает его допуск (`authzguard.HopAdmits`).
	// Значение — тот же объект, что у политик вызывающего: корень читает перечень
	// один раз с проверкой ошибки, и нулевым здесь он бывает лишь объявленным
	// пустым (в боевом режиме это отказ старта).
	modules moduleidentity.Roster
}

// WithModuleRoster подставляет перечень личностей модулей установки — тот же,
// что у политик вызывающего (kaname#984).
func (h *Handler) WithModuleRoster(r moduleidentity.Roster) *Handler {
	h.modules = r
	return h
}

// NewHandler — конструктор. `authz` может быть nil, если стек FGA
// не настроен (dev); тогда Check возвращает Unavailable вместо
// Unimplemented (закрытый отказ стража).
func NewHandler(l *LookupSubjectUseCase, authz Authorizer) *Handler {
	return &Handler{lookup: l, authz: authz}
}

// WithLogger — подключает журнал процесса к обработчику.
// Вызывается из корня сборки (cmd/kaname/main.go).
func (h *Handler) WithLogger(l *slog.Logger) *Handler {
	h.logger = l
	return h
}

// WithSubjectChange — подключает SubjectChangeService к обработчику.
func (h *Handler) WithSubjectChange(sc subjectChanger) *Handler {
	h.subjectChange = sc
	return h
}

// WithResourceRegistrar — подключает сценарий RegisterResource и страж прав ReBAC.
// Оба должны быть не nil для работы RPC регистрации
// ресурсов; иначе RPC отвечают закрытым отказом (Unavailable при отсутствии
// сценария, PermissionDenied при отказе стража).
func (h *Handler) WithResourceRegistrar(registrar resourceRegistrar, gate relationWriteGate) *Handler {
	h.registrar = registrar
	h.regGate = gate
	return h
}

// validateProxyTuple сохраняет эталон совместимости скомпилированной политики для
// проверок общей политики. Сама регистрация использует validateRegistrationShape
// и обязательную транзакционную проверку владельца каталога; скомпилированный словарь
// не может разрешать или отвергать динамически доставленный тип.
func validateProxyTuple(callerDomain, subject, relation, object string) error {
	// Словарь владения типом подаётся ЗДЕСЬ: правило живёт в общем фундаменте, а
	// закрытая таблица типов — за границей его видимости (см. proxy_type_owner.go).
	// Без него «чей это тип» отвечала бы приставка имени, то есть соглашение об
	// именовании, и тип, чьё имя приставке не подчиняется, был бы невыразим (kacho#1885).
	if err := proxytuple.ValidateTuple(callerDomain, subject, relation, object,
		proxytuple.WithTypeOwner(catalogTypeOwner{})); err != nil {
		return proxyWriteRefusal()
	}
	return nil
}

// validateRegistrationShape проверяет только безопасную форму до TX. Допуск
// нестандартного отношения завершается точной тройкой parents живого каталога;
// оно не становится глобально разрешённым отношением прокси.
func validateRegistrationShape(module, subject, relation, object string) error {
	if module == "" || strings.ContainsAny(module, "* \t\n") {
		return proxyWriteRefusal()
	}
	if proxytuple.Hierarchical(proxytuple.Relation(relation)) || proxytuple.IsPublicReadGrant(subject, relation) {
		if err := proxytuple.ValidateTuple("", subject, relation, object); err != nil {
			return proxyWriteRefusal()
		}
		return nil
	}
	if validateRelationString("subject_id", subject) != nil || validateRelationString("object", object) != nil || !registrationRelationName(relation) {
		return proxyWriteRefusal()
	}
	subjectType, subjectID, _ := strings.Cut(subject, ":")
	if subjectType == "system_class" || strings.Contains(subjectID, "*") {
		return proxyWriteRefusal()
	}
	objectType, _, _ := strings.Cut(object, ":")
	for _, forbidden := range proxytuple.ForbiddenObjectTypes() {
		if objectType == forbidden {
			return proxyWriteRefusal()
		}
	}
	return nil
}

func registrationRelationName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// proxyWriteRefusal — ЕДИНСТВЕННЫЙ производитель отказа проксируемой записи по
// правам: его отдают и правило приёма здесь, и политика записи модуля в use-case
// (kaname#982, Р3). Ответ побайтово один — `PERMISSION_DENIED`, `permission
// denied`, деталей нет, — и какая оговорка отвергла, не наблюдаемо; второй
// производитель того же текста разошёлся бы с первым молча.
func proxyWriteRefusal() error {
	return status.Error(codes.PermissionDenied, "permission denied")
}

// RegisterResource — внутренний прокси FGA: ставит запись кортежа иерархии владельца
// в kaname.fga_outbox, из которой триггер складывает прямой факт тем
// же коммитом. Идемпотентен: повтор того же кортежа → OK, никогда AlreadyExists.
//
// Права: исключён из каталога proto; минимум привилегий проверяется ЗДЕСЬ через ReBAC
// (проверенная личность модуля → допустимая каноническая учётная запись fga_writer). Внутренний :9091.
func (h *Handler) RegisterResource(ctx context.Context, req *iamv1.RegisterResourceRequest) (response *iamv1.RegisterResourceResponse, err error) {
	defer func() { err = h.registrationRefusal(ctx, req, false, err) }()
	domain, err := h.authorizeRegistration(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateRegistrationShape(domain, req.GetSubjectId(), req.GetRelation(), req.GetObject()); err != nil {
		return nil, err
	}
	if h.registrar == nil {
		return nil, status.Error(codes.Unavailable, "fga proxy not configured")
	}
	if err := h.registrar.Register(ctx, req); err != nil {
		// Переводим ошибку сценария единым преобразователем признака ошибки в gRPC:
		// статусы проверки проходят как есть, ErrUnavailable → Unavailable
		// (повторяемый закрытый отказ), любая ошибка pgx/базы без признака → непрозрачный
		// codes.Internal "internal error" (инвариант усиления №1: никогда не возвращать
		// сырой текст драйвера host/port/user/db и не раскрывать его через codes.Unknown).
		return nil, shared.MapRepoErr(err)
	}
	return &iamv1.RegisterResourceResponse{}, nil
}

// UnregisterResource — внутренний прокси FGA: ставит удаление кортежа иерархии
// владельца. Идемпотентен: отсутствующий кортеж → OK, никогда NotFound (исполнитель
// превращает cannot_delete в успех). Тот же страж прав, что у RegisterResource.
func (h *Handler) UnregisterResource(ctx context.Context, req *iamv1.UnregisterResourceRequest) (response *iamv1.UnregisterResourceResponse, err error) {
	defer func() { err = h.registrationRefusal(ctx, req, true, err) }()
	domain, err := h.authorizeRegistration(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateRegistrationShape(domain, req.GetSubjectId(), req.GetRelation(), req.GetObject()); err != nil {
		return nil, err
	}
	if h.registrar == nil {
		return nil, status.Error(codes.Unavailable, "fga proxy not configured")
	}
	if err := h.registrar.Unregister(ctx, req); err != nil {
		// То же преобразование признаков ошибок в gRPC, что у RegisterResource: непрозрачный Internal
		// для ошибок pgx/базы без признака; без утечки сырого текста и codes.Unknown.
		return nil, shared.MapRepoErr(err)
	}
	return &iamv1.UnregisterResourceResponse{}, nil
}

// Отказ пишет только обработчик: сюда сходятся ворота, политика и use-case.
// Без подтверждённой личности модуля событие регистрации не приписывается SAN.
func (h *Handler) registrationRefusal(ctx context.Context, in unregisterInput, unregister bool, refusal error) error {
	var outcome string
	switch status.Code(refusal) {
	case codes.PermissionDenied:
		outcome = "permission_denied"
	case codes.FailedPrecondition:
		outcome = "failed_precondition"
	default:
		return refusal
	}
	if _, _, verified := authzguard.ModuleActor(ctx); !verified {
		return refusal
	}
	if h.registrar == nil {
		return shared.MapRepoErr(stderrors.New("registration audit not configured"))
	}
	if err := h.registrar.RecordRefusal(ctx, in, unregister, outcome); err != nil {
		return shared.MapRepoErr(err)
	}
	return refusal
}

// authorizeRegistration запускает страж ReBAC и возвращает домен модуля
// вызывающего (vpc/compute/nlb) для привязки типа объекта. nil страж → закрытый отказ
// PermissionDenied: никогда не разрешать молча неподключённый страж в боевом режиме.
func (h *Handler) authorizeRegistration(ctx context.Context) (string, error) {
	if h.regGate == nil {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return h.regGate.Authorize(ctx)
}

// TOMBSTONE. `WriteCreatorTuple` стоял здесь и снят (kacho#788): он писал кортёж
// создателя в движок НАПРЯМУЮ, мимо `kaname.fga_outbox`, поэтому проекция
// `relation_fact` (миграция 0098) его не увидела бы никогда. Вызывающих не
// осталось ни одного — все пять соседей ушли на RegisterResource. Порт записи
// (`relationWriter`) снят вместе с методом НАМЕРЕННО: тип без него нельзя
// переоткрыть одной строкой вызова.

func (h *Handler) LookupSubject(ctx context.Context, req *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
	return h.lookup.Execute(ctx, req)
}

// Check — проверка прав на один кортеж.
//
// Тонкая транспортная обёртка: передаёт вызов AuthorizeService.CheckRelation, который
// выполняет тот же конвейер FGA `Check` и ограничителя OPA, что публичный
// сценарий AuthorizeService.Check. InternalIAMService.CheckRequest имеет родную форму
// FGA ({subject_id, relation, object}): вызывающий, перехватчик каждого RPC vpc/compute,
// уже перевёл RPC → отношение, поэтому шаг
// действие→отношение здесь не нужен.
//
// Общий страж: на проводе нет контекста `action` или условия для отдельного вызова,
// поэтому надстройка OPA видит синтезированное действие (тип объекта.отношение).
func (h *Handler) Check(ctx context.Context, req *iamv1.CheckRequest) (*iamv1.CheckResponse, error) {
	if req.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument subject_id: required")
	}
	if req.GetRelation() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument relation: required")
	}
	if req.GetObject() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument object: required")
	}
	// Плоскость данных спрашивает только о типах объектов своего модуля
	// (kaname#987): вопрос о чужом типе — отказ до решателя.
	if module, recognized := h.modules.FromContext(ctx); recognized {
		if err := h.requireCheckInCallerDomain(module, req.GetObject()); err != nil {
			return nil, err
		}
	}
	if h.authz == nil {
		// Источник вердикта не провязан — fail-closed (интерсептор читает
		// Unavailable как отказ, а не как «пропустить страж»).
		return nil, status.Error(codes.Unavailable, "authz unavailable: verdict source not wired")
	}

	res, err := h.authz.CheckRelation(ctx, service.CheckRelationRequest{
		Subject:  req.GetSubjectId(),
		Relation: req.GetRelation(),
		Object:   req.GetObject(),
		// Требование свежести передаётся дальше, и оно ВЫПОЛНЕНО безусловно:
		// вердикт читает ведущую базу службы, поэтому собственная закоммиченная
		// запись вызывающего видна следующему же чтению по построению.
		//
		// Поле остаётся не «на всякий случай», а как ИМЯ требования: пути чтения с
		// отстающей реплики сегодня нет (он вне границ приёмки R7-3), и появится
		// он — различать требование будет тот, кто его заведёт. Прежде на этом
		// поле ветвился вызов к чужому хранилищу, отвечавшему со своей копии.
		HigherConsistency: req.GetConsistency() == iamv1.CheckRequest_HIGHER_CONSISTENCY,
	})
	if err != nil {
		switch {
		case strings.HasPrefix(err.Error(), "Illegal argument"):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case stderrors.Is(err, iamerr.ErrUnavailable):
			// Полоса классифицируется ТИПИЗИРОВАННЫМ признаком (устойчиво к
			// переписыванию текста), а не префиксом строки.
			//
			// Текст ФИКСИРОВАН — как у INTERNAL ниже и по той же причине: цепочка
			// признака недоступности ведёт к ЧУЖОМУ производителю (база, сосед,
			// гейт прав), и её текст вызывающему не адресован. Прежде здесь стоял
			// разбор цепочки, то есть обёртка вызывающего доезжала до провода
			// дословно (задача kacho#2464).
			//
			// Подробность уходит в ЖУРНАЛ: у глагола есть логгер, и «ноль отказов
			// за всю жизнь контроля» обязано быть заметно.
			if h.logger != nil {
				// Корреляционный идентификатор вызывающего доезжает до записи:
				// поле `trace_id` объявлено на этой проверке ровно ради того,
				// чтобы отказ нашёлся по нему, и до kacho#1351 не читалось
				// ничем. Полоса публичная несла его и прежде — неверна была их
				// РАЗНИЦА, и решал её никто.
				h.logger.WarnContext(ctx, "authorization verdict unavailable",
					slog.Any("error", err), shared.TraceAttr(req.GetTraceId()))
			}
			return nil, status.Error(codes.Unavailable, shared.UnavailableMessage)
		default:
			// Непрозрачный INTERNAL: нераспознанные ошибки не возвращают err.Error(), иначе
			// утёк бы текст драйвера pgx/базы: host/port/user/db.
			return nil, status.Error(codes.Internal, "internal error")
		}
	}

	resp := &iamv1.CheckResponse{Allowed: res.Allowed}
	if !res.Allowed {
		resp.Reason = strings.Join(res.DenyReasons, "; ")
	}
	return resp, nil
}

// Теневое сравнение формы E с движком здесь НЕ живёт, и это решение, а не
// пропуск: сравнивать надо ОКОНЧАТЕЛЬНЫЙ вердикт, а он складывается в
// `service.AuthorizeService` — к ответу движка там добавляются надзор
// администратора облака и структурный запасной путь. Сравнение, поставленное у
// транспорта, сверяло бы форму E с половиной ответа; кроме того, у транспорта
// оно покрывало ровно один вопрос из тех, что сервис отвечает. Механика — в
// `service/shadow_port.go`, свойство держит гейт
// `TestEveryEngineAskingQuestionAlsoAsksTheShadowForm`.

// PollSubjectChanges — вычитывает subject_change_outbox по курсору возрастающего id.
// Только внутренний: слушатель внутри кластера, запрет №6.
func (h *Handler) PollSubjectChanges(ctx context.Context, req *iamv1.PollSubjectChangesRequest) (*iamv1.PollSubjectChangesResponse, error) {
	if h.subjectChange == nil {
		return nil, status.Error(codes.Unavailable, "subject change service not configured")
	}
	changes, headID, err := h.subjectChange.PollSubjectChanges(ctx, req.GetSinceId(), req.GetLimit())
	if err != nil {
		// «Позиции ещё нет» — состояние холодного старта, а не отказ хранилища:
		// назвать его общим отказом значило бы посоветовать вызывающему разбирать
		// поломку там, где верный следующий шаг — переспросить. Отдельный тон
		// восстанавливает этот шаг (`retryable`), и он же не даёт вызывающему
		// принять ноль за позицию (kacho#1374).
		if stderrors.Is(err, service.ErrSubjectChangeNotSettled) {
			slog.WarnContext(ctx, "subject change journal position is not settled yet", "err", err)
			return nil, status.Error(codes.Unavailable, "subject change position not settled")
		}
		// «Позиция утрачена» — ТРЕТЬЯ полоса, и слить её нельзя ни с одной из
		// двух соседних (задача kacho#1712).
		//
		// С «позиции ещё нет» — потому что советы противоположны: та говорит
		// «переспроси на следующем такте», эта — «повтор не пройдёт НИКОГДА,
		// пересядь». Вызывающий, прочитавший вторую как первую, повторял бы с
		// утраченной позиции вечно, и петля отзыва встала бы навсегда — молча
		// для клиента, у которого кэш вердиктов отвечает по снятым правам.
		//
		// С общим отказом — потому что `INTERNAL` текста не несёт по
		// построению (он приносит имена схемы и драйвера), а возобновимая
		// позиция ОБЯЗАНА доехать: без неё вызывающему некуда сесть.
		//
		// Отказ собирается ТЕМ ЖЕ конструктором, каким его разбирает край:
		// собственная сборка деталей здесь была бы вторым местом об одном
		// предмете и разошлась бы с настоящим читателем молча — обе непусты, обе
		// выглядят полосой, а совпасть перестают навсегда.
		var lost *service.SubjectChangePositionLostError
		if stderrors.As(err, &lost) {
			slog.WarnContext(ctx, "subject change position is no longer resumable",
				"since_id", req.GetSinceId(), "earliest_resumable_position", lost.EarliestResumable)
			return nil, subjectchange.PositionLost(lost.EarliestResumable)
		}
		slog.ErrorContext(ctx, "poll subject changes", "err", err)
		return nil, status.Error(codes.Internal, "subject change poll failed")
	}
	resp := &iamv1.PollSubjectChangesResponse{HeadId: headID}
	for _, c := range changes {
		resp.Changes = append(resp.Changes, &iamv1.SubjectChange{
			Id:          c.ID,
			SubjectId:   c.SubjectID,
			Op:          c.Op,
			SubjectType: c.SubjectType,
		})
	}
	return resp, nil
}
