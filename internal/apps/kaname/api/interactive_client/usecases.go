// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/operations"
	corevalidate "github.com/PRO-Robotech/corelib/validate"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// resourceKind — имя вида в сообщении о неверной форме идентификатора. Одна
// константа не даёт разойтись синхронной проверке формы и тексту отсутствия.
const resourceKind = "interactive client"

// Способы аутентификации клиента на токен-эндпоинте — словарь схемы
// (`interactive_clients_auth_method_ck`, kaname#317). Способ решает реестр,
// который держит клиента; use-case судит согласие способа с материалом.
//
// Слова берутся у фундамента (`oauthceremony.ClientAuth*`), а не заводятся
// здесь: колонку пишет реестр этой службы, а читает церемония фундамента
// (`oauth_ceremony_vaults.go`), и два словаря одной колонки разошлись бы молча.

// grantTypesInteractive — ЕДИНСТВЕННАЯ форма, которую регистрирует этот ресурс.
// Это константа, а не поле запроса: ресурс существует именно ради этой формы.
// Предложенный выбор вызывающий не смог бы оценить, и код ниже его не читает.
var grantTypesInteractive = []string{"authorization_code", "refresh_token"}

// validateID — неверная форма своего идентификатора даёт синхронный
// INVALID_ARGUMENT; это всегда первая проверка принимающего его RPC. Без неё
// неверный идентификатор доходит до хранилища и возвращает NOT_FOUND,
// утверждая отсутствие ресурса, которого вызывающий не называл.
//
// corevalidate.ResourceID по контракту пропускает ПУСТУЮ строку, поэтому
// обязательность проверяется здесь явно: иначе пустой идентификатор прошёл бы
// дальше и вернулся как `InteractiveClient  not found`.
func validateID(id string) error {
	if id == "" {
		return shared.InvalidArg("interactive_client_id", "interactive_client_id: required")
	}
	return corevalidate.ResourceID(resourceKind, ids.PrefixInteractiveClientHyphen, id)
}

// parseNameFilter — разрешено одно поле (`name=`), в соответствии с фазой
// фильтрации платформы. Всё прочее отвергается ПО ИМЕНИ, а не игнорируется:
// молча снятый фильтр вернул бы страницу, которой вызывающий не просил.
func parseNameFilter(filter string) (string, error) {
	if strings.TrimSpace(filter) == "" {
		return "", nil
	}
	const p = "name="
	f := strings.TrimSpace(filter)
	if !strings.HasPrefix(f, p) {
		return "", shared.InvalidArg("filter", "Illegal argument filter")
	}
	v := strings.Trim(strings.TrimPrefix(f, p), `"'`)
	if v == "" {
		return "", shared.InvalidArg("filter", "Illegal argument filter")
	}
	return v, nil
}

// ── Get ──────────────────────────────────────────────────────────────────────

// GetUseCase — синхронное чтение одного клиента.
type GetUseCase struct{ repo clientRepo }

// NewGetUseCase — конструктор.
func NewGetUseCase(r clientRepo) *GetUseCase { return &GetUseCase{repo: r} }

// Execute — прямое чтение: правильная форма идентификатора без строки даёт NOT_FOUND.
func (uc *GetUseCase) Execute(ctx context.Context, id string) (domain.InteractiveClient, error) {
	if err := validateID(id); err != nil {
		return domain.InteractiveClient{}, err
	}
	c, err := uc.repo.Get(ctx, domain.InteractiveClientID(id))
	if err != nil {
		return domain.InteractiveClient{}, shared.MapRepoErr(err)
	}
	return c, nil
}

// ── List ─────────────────────────────────────────────────────────────────────

// ListUseCase — синхронное чтение страниц с курсором.
type ListUseCase struct{ repo clientRepo }

// NewListUseCase — конструктор.
func NewListUseCase(r clientRepo) *ListUseCase { return &ListUseCase{repo: r} }

// ListResult — страница и курсор следующей.
type ListResult struct {
	Clients       []domain.InteractiveClient
	NextPageToken string
}

// Execute — форма пагинации проверяется ПЕРВОЙ, поэтому негодный токен или
// размер страницы вне диапазона даёт INVALID_ARGUMENT независимо от прав
// вызывающего и содержимого хранилища. `page_size` вне диапазона ОТВЕРГАЕТСЯ,
// а не подрезается: молчаливая подрезка вернула бы другую страницу, и вызывающий
// об этом не узнал бы.
func (uc *ListUseCase) Execute(ctx context.Context, pageSize int64, pageToken, filter string) (ListResult, error) {
	if pageSize < 0 || pageSize > int64(shared.MaxListPageSize) {
		return ListResult{}, shared.InvalidArg("page_size", "Illegal argument page_size")
	}
	if err := shared.ValidatePageToken("page_token", pageToken); err != nil {
		return ListResult{}, err
	}
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return ListResult{}, err
	}
	name, err := parseNameFilter(filter)
	if err != nil {
		return ListResult{}, err
	}

	rows, next, err := uc.repo.List(ctx, int(size), pageToken, name)
	if err != nil {
		return ListResult{}, shared.MapRepoErr(err)
	}
	return ListResult{Clients: rows, NextPageToken: next}, nil
}

// ── Create ───────────────────────────────────────────────────────────────────

// CreateUseCase — регистрирует клиента в собственном реестре службы, затем
// записывает его. Клиент конфиденциальный; секрет показывается один раз,
// в ответе этого вызова (kaname#405).
type CreateUseCase struct {
	repo      clientRepo
	provider  ProviderClients
	opsRepo   operations.Repo
	audiences []string
	logger    *slog.Logger
}

// providerReleaseTimeout — верхний предел вызова отзыва регистрации. Отвязан
// от отмены вызывающего: отзыв должен состояться и тогда, когда запроса
// уже нет.
const providerReleaseTimeout = 5 * time.Second

// releaseProviderClient снимает регистрацию, сделанную до коммита строки,
// прямым идемпотентным отзывом.
//
// Прежде основным путём было СОХРАНЁННОЕ намерение отзыва регистрации у внешнего
// поставщика личности: оно переживало гибель процесса и отказ вызова отзыва.
// Внешний поставщик снят (kaname#363); реестр теперь собственный, отзыв — вызов
// к нему. Писатель намерения снят вместе с поставщиком.
func (uc *CreateUseCase) releaseProviderClient(ctx context.Context, clientID, reason string) {
	if clientID == "" {
		return
	}
	relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerReleaseTimeout)
	defer cancel()

	if err := uc.provider.Deregister(relCtx, clientID); err != nil && uc.logger != nil {
		// Нет ни намерения, ни отзыва: регистрация остаётся у поставщика,
		// и эта строка — единственная зацепка для ручного снятия.
		uc.logger.ErrorContext(relCtx,
			"interactive client: provider registration left behind after a failed insert",
			"provider_client_id", clientID, "reason", reason, "err", err.Error())
	}
}

// NewCreateUseCase — конструктор. `audiences` берётся из собственной конфигурации
// iam (Р2): вызывающий его не задаёт, значение возвращается только в ответе.
func NewCreateUseCase(r clientRepo, p ProviderClients, ops operations.Repo, audiences []string, logger *slog.Logger) *CreateUseCase {
	return &CreateUseCase{repo: r, provider: p, opsRepo: ops, audiences: audiences, logger: logger}
}

// Execute — проверка → сохранение Operation → регистрация в реестре → сверка
// тройки секрета → вставка строки с проверочным значением → разделение тел
// ответа (хранится без секрета, показывается с ним).
//
// ПОЧЕМУ ВЫЗОВ ПОСТАВЩИКА ПРЕДШЕСТВУЕТ ЗАПИСИ СТРОКИ И ЧЕМ ЭТО ОПЛАЧЕНО.
// Строка обязана нести идентификатор клиента поставщика, поэтому регистрация
// идёт первой. Если вставка затем отказывает, обычно из-за занятого имени,
// только что зарегистрированный клиент отзывается. Без компенсации у поставщика
// остался бы сирота, которого платформа не записала и не может назвать:
// никто не снял бы его, и он продолжал бы принимать церемонии.
//
// Строка Operation сохраняется ДО обоих побочных действий, поэтому полученный
// вызывающим идентификатор всегда доступен для опроса. Отказ записывается
// терминальной ошибкой, а не оставляет вызывающего опрашивать отсутствующую строку.
func (uc *CreateUseCase) Execute(ctx context.Context, req *iamv1.CreateInteractiveClientRequest) (*operationpb.Operation, error) {
	id := ids.NewHyphenID(ids.PrefixInteractiveClientHyphen)
	c := domain.InteractiveClient{
		ID: domain.InteractiveClientID(id),
		// Пустое имя — законный вход создания и означает «назови сам»: до
		// записи его заменяет имя, производное от идентификатора (kacho#1279). Имя
		// клиента уникально на ВЕСЬ кластер, поэтому умолчание обязано быть
		// производным именно от идентификатора — он глобально уникален by
		// construction, и два безымянных создания не столкнутся БЕЗ
		// проверки-перед-вставкой (запрет #10).
		Name:                   domain.InteractiveClientName(corevalidate.NameOrDefault(req.GetName(), id)),
		Description:            domain.Description(req.GetDescription()),
		Labels:                 labelsFromProto(req.GetLabels()),
		RedirectURIs:           req.GetRedirectUris(),
		PostLogoutRedirectURIs: req.GetPostLogoutRedirectUris(),
		Status:                 domain.InteractiveClientActive,
	}
	// Проверяется та же сущность, которая будет сохранена: правило для вызывающего
	// и правило, которому удовлетворяет строка, — одно правило.
	if err := c.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create interactive client %s", c.Name),
		&iamv1.CreateInteractiveClientMetadata{InteractiveClientId: string(c.ID)},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	fail := func(err error) error {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return gerr
	}
	// failTraced — отказ пути, чья причина — НАШ текст: ответ реестра (в том
	// числе срыв чеканки секрета), несогласие тройки, сборка тела ответа. Наружу
	// у него фиксированный текст INTERNAL, поэтому причина уходит в журнал
	// службы общим путём (`shared.LogMappedErr`) — иначе у дефекта реестра нет
	// следа нигде. Отказ ВСТАВКИ сюда не идёт намеренно: его причина — текст
	// хранилища, и IC-SECRET-13 (б) требует, чтобы отказ вне словаря не эхал
	// его и в журнал (`TestIntegration_IC13b_InternalInsertRefusalEchoesNothing`).
	failTraced := func(err error) error {
		_ = shared.LogMappedErr(ctx, uc.logger, "InteractiveClient.Create", err, shared.MapRepoErr(err))
		return fail(err)
	}

	pc, err := uc.provider.Register(ctx, ProviderClientSpec{
		Name:                   string(c.Name),
		RedirectURIs:           c.RedirectURIs,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		Audiences:              uc.audiences,
		GrantTypes:             grantTypesInteractive,
	})
	if err != nil {
		return nil, failTraced(err)
	}
	// Согласие тройки «способ ⟺ материал ⟺ секрет» — ДО вставки (задача #405).
	// Схема держит только одно направление; без этой проверки возможен клиент
	// со способом секретом, которому нечего предъявить никогда.
	if err := secretMaterialAgrees(pc); err != nil {
		uc.releaseProviderClient(ctx, pc.ClientID, "registry answered a secret material that disagrees with the method")
		return nil, failTraced(err)
	}
	c.ClientID = pc.ClientID
	c.GrantTypes = pc.GrantTypes
	c.TokenEndpointAuthMethod = pc.TokenEndpointAuthMethod
	c.Audiences = pc.Audiences

	// Проверочное значение ложится ТЕМ ЖЕ оператором, что строка (Р5): второго
	// писателя материала нет.
	created, err := uc.repo.Insert(ctx, c, pc.SecretVerifier)
	if err != nil {
		// При отказе вставки отзываем регистрацию прямым вызовом. Отмена запроса
		// этот вызов не отменяет; его срок ограничен providerReleaseTimeout.
		uc.releaseProviderClient(ctx, pc.ClientID, "client row was not inserted")
		return nil, fail(err)
	}

	// Тело для строки операции — без секрета, тело вызывающему — с ним (Р3).
	// Оба собираются ДО терминальной записи и живут в этом вызове, а не в поле
	// use-case: use-case один на все запросы, и поле стало бы общим
	// состоянием — секрет одного вызывающего мог бы уйти другому.
	stored, shown, err := createResponses(created, pc.Secret)
	if err != nil {
		// Тело вызывающему не собралось — секрет не будет показан никому, и
		// клиент, которого никто не может доказать, не остаётся: строка
		// снимается, заведение у реестра отзывается.
		uc.abandonCreated(ctx, created)
		// Причина — только ТЕКСТОМ (%v), в цепочку она не входит нарочно:
		// чужой признак в цепочке переклассифицировал бы отказ в MapRepoErr.
		return nil, failTraced(iamerr.Wrapf(iamerr.ErrInternal, "interactive client Create: %v", err))
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, stored); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(ctx, "interactive client Create: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	// Подмена ПОСЛЕ записи: в строке лежит тело без секрета, вызывающий
	// получает тело с ним.
	op.Done, op.Response = true, shown
	return shared.OperationToProto(&op), nil
}

// secretMaterialAgrees — согласие тройки «способ ⟺ материал ⟺ секрет» в ответе
// реестра. Способ секретом приходит с секретом И проверочным значением, `none`
// — без обоих; иное сочетание и способ вне словаря — дефект реестра, и отказ
// у него фиксированного текста (`INTERNAL`), без строки и без секрета.
func secretMaterialAgrees(pc ProviderClient) error {
	hasSecret, hasMaterial := !pc.Secret.IsZero(), !pc.SecretVerifier.IsZero()
	switch pc.TokenEndpointAuthMethod {
	case string(oauthceremony.ClientAuthBasic), string(oauthceremony.ClientAuthPost):
		if hasSecret && hasMaterial {
			return nil
		}
	case string(oauthceremony.ClientAuthNone):
		if !hasSecret && !hasMaterial {
			return nil
		}
	}
	return iamerr.Wrapf(iamerr.ErrInternal,
		"interactive client registry answered method %q with secret present=%t and verification value present=%t",
		pc.TokenEndpointAuthMethod, hasSecret, hasMaterial)
}

// abandonCreated снимает строку, записанную заведением, ответ которого не
// собрался, и отзывает заведение у реестра. Отвязано от отмены вызывающего по
// той же причине, что `releaseProviderClient`: снятие обязано состояться и
// тогда, когда запроса уже нет.
func (uc *CreateUseCase) abandonCreated(ctx context.Context, created domain.InteractiveClient) {
	relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerReleaseTimeout)
	defer cancel()
	if _, _, err := uc.repo.Delete(relCtx, created.ID); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(relCtx,
			"interactive client: row of an abandoned Create left behind",
			"interactive_client_id", string(created.ID), "err", err.Error())
	}
	uc.releaseProviderClient(ctx, created.ClientID, "operation response could not be built")
}

// ── Update ───────────────────────────────────────────────────────────────────

// UpdateUseCase — применяет изменяемые поля.
type UpdateUseCase struct {
	repo    clientRepo
	opsRepo operations.Repo
	logger  *slog.Logger
}

// NewUpdateUseCase — конструктор.
func NewUpdateUseCase(r clientRepo, ops operations.Repo, logger *slog.Logger) *UpdateUseCase {
	return &UpdateUseCase{repo: r, opsRepo: ops, logger: logger}
}

// mutableFields — известный набор полей для сверки маски обновления.
var mutableFields = []string{"name", "description", "labels", "redirect_uris", "post_logout_redirect_uris"}

// immutableFields — названы отдельно, чтобы маска с таким полем отвергалась
// ПО ИМЕНИ. Проверяются ДО известного набора: их в нём нет, поэтому общий отказ
// "unknown field" сработал бы первым и вызывающий не узнал бы, что поле существует,
// но изменению не подлежит.
var immutableFields = []string{"id", "created_at", "client_id", "audiences", "grant_types", "token_endpoint_auth_method", "status"}

// Execute — проверка маски, затем запись.
func (uc *UpdateUseCase) Execute(ctx context.Context, req *iamv1.UpdateInteractiveClientRequest) (*operationpb.Operation, error) {
	id := req.GetInteractiveClientId()
	if err := validateID(id); err != nil {
		return nil, err
	}

	paths := req.GetUpdateMask().GetPaths()
	// Сначала неизменяемые — см. комментарий у immutableFields.
	for _, p := range paths {
		for _, im := range immutableFields {
			if normalizeFieldPath(p) == im {
				return nil, shared.InvalidArg("update_mask",
					fmt.Sprintf("%s is immutable after InteractiveClient.Create", im))
			}
		}
	}
	known := make(map[string]struct{}, len(mutableFields)*2)
	for _, f := range mutableFields {
		known[f] = struct{}{}
	}
	normalized := make([]string, 0, len(paths))
	for _, p := range paths {
		normalized = append(normalized, normalizeFieldPath(p))
	}
	if err := corevalidate.UpdateMask("update_mask", normalized, known); err != nil {
		return nil, err
	}

	cur, err := uc.repo.Get(ctx, domain.InteractiveClientID(id))
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Пустая маска — PATCH целого объекта по изменяемым полям (api-conventions).
	// Сообщение запроса вовсе не несёт неизменяемых полей, поэтому вне этого набора
	// в теле нечего применять или игнорировать (kaname#562).
	set := make(map[string]bool, len(paths))
	for _, p := range paths {
		set[normalizeFieldPath(p)] = true
	}
	all := len(paths) == 0
	if all || set["name"] {
		cur.Name = domain.InteractiveClientName(req.GetName())
	}
	if all || set["description"] {
		cur.Description = domain.Description(req.GetDescription())
	}
	if all || set["labels"] {
		cur.Labels = labelsFromProto(req.GetLabels())
	}
	if all || set["redirect_uris"] {
		cur.RedirectURIs = req.GetRedirectUris()
	}
	if all || set["post_logout_redirect_uris"] {
		cur.PostLogoutRedirectURIs = req.GetPostLogoutRedirectUris()
	}
	// Обновлённая сущность проверяется ТЕМИ ЖЕ правилами, что при Create:
	// Update не должен пропускать изменяемое поле в форме, которую Create отвергнет.
	if err := cur.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update interactive client %s", id),
		&iamv1.UpdateInteractiveClientMetadata{InteractiveClientId: id},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	updated, err := uc.repo.Update(ctx, cur)
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	resp, merr := operationResponse(updated)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, resp); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(ctx, "interactive client Update: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done, op.Response = true, resp
	return shared.OperationToProto(&op), nil
}

// ── Delete ───────────────────────────────────────────────────────────────────

// DeleteUseCase — снимает клиента у поставщика и его строку.
type DeleteUseCase struct {
	repo     clientRepo
	provider ProviderClients
	opsRepo  operations.Repo
	logger   *slog.Logger
}

// NewDeleteUseCase — конструктор.
func NewDeleteUseCase(r clientRepo, p ProviderClients, ops operations.Repo, logger *slog.Logger) *DeleteUseCase {
	return &DeleteUseCase{repo: r, provider: p, opsRepo: ops, logger: logger}
}

// Execute — идемпотентен по построению.
//
// Снятие уже отсутствующего клиента успешно и отвечает тем же кодом, что первое:
// вызывающий просил отсутствия клиента, и тот отсутствует. Первой снимается строка;
// отзыв у поставщика следует только тогда, когда строка действительно снята.
// Иначе повторный Delete снова просил бы поставщика снять уже снятое.
func (uc *DeleteUseCase) Execute(ctx context.Context, id string) (*operationpb.Operation, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete interactive client %s", id),
		&iamv1.DeleteInteractiveClientMetadata{InteractiveClientId: id},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	removed, existed, err := uc.repo.Delete(ctx, domain.InteractiveClientID(id))
	if err != nil {
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}
	if existed && removed.ClientID != "" {
		if derr := uc.provider.Deregister(ctx, removed.ClientID); derr != nil {
			// Строки уже нет, поэтому платформа больше не может назвать этого клиента
			// поставщика. Отказ не проглатывается: эта строка позволяет найти
			// оставшуюся регистрацию.
			if uc.logger != nil {
				uc.logger.ErrorContext(ctx,
					"interactive client: row removed but provider deregistration failed",
					"provider_client_id", removed.ClientID, "err", derr.Error())
			}
			gerr := shared.MapRepoErr(derr)
			_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
			return nil, gerr
		}
	}
	// Ответ возвращает снятый ресурс, если он был; при идемпотентном повторе —
	// только идентификатор: описывать больше нечего, а выдуманное тело описало бы
	// строку, которой нет.
	removed.ID = domain.InteractiveClientID(id)
	resp, merr := operationResponse(removed)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, resp); err != nil && uc.logger != nil {
		uc.logger.ErrorContext(ctx, "interactive client Delete: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done, op.Response = true, resp
	return shared.OperationToProto(&op), nil
}

// normalizeFieldPath — маски приходят в snake_case (proto) либо camelCase
// (REST через grpc-gateway). Оба написания называют одно поле и принимаются;
// отказ одному из них поставил бы ответ в зависимость от выбранного входа.
func normalizeFieldPath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		ch := p[i]
		if ch >= 'A' && ch <= 'Z' {
			b.WriteByte('_')
			b.WriteByte(ch - 'A' + 'a')
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func labelsFromProto(in map[string]string) domain.Labels {
	if len(in) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(in))
	for k, v := range in {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}
