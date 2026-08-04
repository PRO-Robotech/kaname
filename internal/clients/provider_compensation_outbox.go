// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// provider_compensation_outbox.go — компенсация частично исполненной саги
// «зарегистрировать OAuth-клиента у провайдера → закоммитить свою строку».
//
// Здесь три части одной цепочки:
//   - ProviderCompensationOutbox — writer намерения; порт объявлен у каждого
//     потребителя (dependency rule), здесь живёт единственная реализация;
//   - DecodeProviderCompensation — Decoder[T] для corelib-дренажа;
//   - NewProviderCompensationApplier — Applier[T], исполняющий снятие у
//     провайдера идемпотентно.
//
// Почему намерение коммитится СВОЕЙ транзакцией, а не writer-TX: компенсируется
// именно та транзакция, которая откатилась, поэтому нести намерение ей нечем.
// Это осознанно слабее co-commit'а внутри одной БД и сильнее вызова «в надежде»:
// пережившее рестарт намерение доставит дренаж.
package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/outbox"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
)

const (
	// ProviderCompensationTable — полное имя очереди компенсаций.
	ProviderCompensationTable = "kacho_iam.provider_compensation_outbox"
	// ProviderCompensationChannel — LISTEN-канал (триггер миграции 0079).
	ProviderCompensationChannel = "kacho_iam_provider_compensation_outbox"
	// EventProviderOAuthClientDelete — снять OAuth-клиента у провайдера.
	// Словарь закрыт CHECK'ом в миграции: расширение требует и кода, и миграции.
	EventProviderOAuthClientDelete = "provider.oauth_client.delete"
	// EventProviderTrustGrantDelete — снять доверительный грант у провайдера
	// (миграция 0080). Отдельный вид, а не поле первого: у него другой предмет,
	// другая координата снятия и другой вызов к провайдеру.
	EventProviderTrustGrantDelete = "provider.trust_grant.delete"
	// providerCompensationKind — resource_kind денормализованной колонки.
	providerCompensationKind = "ProviderOAuthClient"
	// providerTrustGrantKind — resource_kind для компенсации доверия.
	providerTrustGrantKind = "ProviderTrustGrant"
)

// ProviderCompensationEvent — расшифрованный payload одной строки очереди.
type ProviderCompensationEvent struct {
	// ClientID — идентификатор клиента У ПРОВАЙДЕРА (не наш id). Именно он и
	// есть единственная координата, по которой осиротевший объект можно снять.
	ClientID string `json:"client_id"`
	// Origin — какая сага его заняла (sa_key / user_token / interactive_client).
	// Только атрибуция: применение от него не зависит.
	Origin string `json:"origin"`
	// GrantID — идентификатор ДОВЕРИТЕЛЬНОГО ГРАНТА у провайдера. Заполнен
	// ровно у компенсаций вида EventProviderTrustGrantDelete и взаимно
	// исключается с ClientID (проверка миграции 0080 отвергает строку, где оба
	// непусты либо оба пусты: у намерения обязан быть ровно один предмет).
	GrantID string `json:"grant_id,omitempty"`
	// Reason — почему компенсируем. Короткая своя строка, НЕ текст ошибки
	// провайдера (тот мог бы утащить в очередь его внутренние подробности).
	Reason string `json:"reason"`
}

// CompensationEmitObserver — счётчик ЗАПИСАННЫХ намерений. Считается отдельно
// от исполненных: без обеих величин «ноль компенсаций» у здорового облака и
// «ноль компенсаций» у непровязанного механизма выглядят одинаково.
type CompensationEmitObserver interface {
	// IncCompensationEmitted — outcome "ok" (намерение записано) либо "error"
	// (записать не удалось, вызывающий уходит на запасной прямой путь).
	IncCompensationEmitted(origin, outcome string)
}

// ProviderCompensationOutbox — durable writer компенсирующих намерений поверх
// пула iam.
//
// ПОЧЕМУ НАМЕРЕНИЕ, А НЕ ПРЯМОЙ ВЫЗОВ. Клиента у провайдера приходится
// регистрировать ДО коммита своей строки: строка обязана нести client_id,
// который назначает провайдер. Значит между «создано у провайдера» и
// «закоммичено у нас» есть окно, и если коммит не прошёл, снять созданное
// обязаны мы. Прямой вызов снятия гарантией не является: он сам может отказать
// (тот же провайдер и лежит), а процесс может умереть между провалом коммита и
// уборкой. В обоих случаях у провайдера остаётся объект, о котором в нашей БД
// нет ни одной записи, — назвать его нечем и убрать некому.
//
// Транзакция, чей провал компенсируется, ОТКАЧЕНА, поэтому намерение не может
// ехать в ней: оно коммитится собственной транзакцией до того, как Operation
// помечается ошибкой. Это осознанно слабее co-commit'а внутри одной БД и
// сильнее вызова «в надежде».
type ProviderCompensationOutbox struct {
	pool *pgxpool.Pool
	obs  CompensationEmitObserver
}

// NewProviderCompensationOutbox конструирует writer.
func NewProviderCompensationOutbox(pool *pgxpool.Pool) *ProviderCompensationOutbox {
	return &ProviderCompensationOutbox{pool: pool}
}

// WithEmitObserver подключает счётчик записанных намерений. Composition-root only.
func (o *ProviderCompensationOutbox) WithEmitObserver(obs CompensationEmitObserver) *ProviderCompensationOutbox {
	o.obs = obs
	return o
}

// observe — единая точка учёта исхода записи, чтобы ни одна ветка возврата не
// осталась непосчитанной.
func (o *ProviderCompensationOutbox) observe(origin string, err error) error {
	if o.obs != nil {
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		o.obs.IncCompensationEmitted(origin, outcome)
	}
	return err
}

// EmitHydraClientDelete записывает намерение снять OAuth-клиента.
//
// Собственная транзакция и собственный commit: вызывающий уже откатил свою.
// Ошибка ВОЗВРАЩАЕТСЯ, а не глотается — вызывающий обязан по ней перейти на
// запасной прямой вызов, иначе «намерение записано» стало бы утверждением,
// которое никто не проверял.
func (o *ProviderCompensationOutbox) EmitHydraClientDelete(ctx context.Context, clientID, origin, reason string) error {
	if o == nil || o.pool == nil {
		return errors.New("provider compensation outbox: no pool")
	}
	if clientID == "" {
		// Пустой client_id — компенсация без предмета; CHECK миграции отвергнет
		// её на записи, но отказать раньше честнее (ошибка называет причину).
		return o.observe(origin, errors.New("provider compensation outbox: client_id required"))
	}
	tx, err := o.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return o.observe(origin, fmt.Errorf("provider compensation outbox: begin: %w", err))
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := outbox.Emit(ctx, tx, ProviderCompensationTable,
		providerCompensationKind, clientID, EventProviderOAuthClientDelete,
		map[string]any{"client_id": clientID, "origin": origin, "reason": reason},
	); err != nil {
		return o.observe(origin, fmt.Errorf("provider compensation outbox: emit: %w", err))
	}
	if err := tx.Commit(ctx); err != nil {
		return o.observe(origin, fmt.Errorf("provider compensation outbox: commit: %w", err))
	}
	committed = true
	return o.observe(origin, nil)
}

// DecodeProviderCompensation — drainer.Decoder. Строка, у которой предмет не
// назван РОВНО ОДИН раз, нерастолковываема и не станет таковой при повторе →
// это ПОСТОЯННАЯ ошибка (дренаж отравляет строку и показывает её оператору), а
// не вечный ретрай.
//
// Требуется именно «ровно один», а не «хотя бы один»: строка с двумя предметами
// не даёт применителю выбрать вызов, и любой выбор был бы догадкой. Проверка
// миграции 0080 держит то же свойство на записи — здесь оно повторено потому,
// что декодер обязан оставаться верным и для строк, записанных до неё.
func DecodeProviderCompensation(payload []byte) (ProviderCompensationEvent, error) {
	var ev ProviderCompensationEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return ProviderCompensationEvent{}, fmt.Errorf("%w: decode provider compensation payload: %w", drainer.ErrPermanent, err)
	}
	switch {
	case ev.ClientID == "" && ev.GrantID == "":
		return ProviderCompensationEvent{}, fmt.Errorf(
			"%w: provider compensation payload names no subject (neither client_id nor grant_id)", drainer.ErrPermanent)
	case ev.ClientID != "" && ev.GrantID != "":
		return ProviderCompensationEvent{}, fmt.Errorf(
			"%w: provider compensation payload names two subjects (client_id and grant_id)", drainer.ErrPermanent)
	}
	return ev, nil
}

// EmitTrustGrantDelete записывает намерение снять доверительный грант.
//
// Зачем это durable, а не вызов на месте: веер доверительных грантов не
// транзакционен у провайдера, отказ на k-м оставляет k-1 стоять, а процесс
// может умереть между этим отказом и уборкой. Оставшийся грант — выданное
// доверие: провайдер продолжает принимать внешнее утверждение субъекта, хотя
// ключа, ради которого доверие выдавалось, у нас нет.
//
// Собственная транзакция и собственный commit — по тому же доводу, что и у
// EmitHydraClientDelete: компенсируется та транзакция, которая откатилась.
func (o *ProviderCompensationOutbox) EmitTrustGrantDelete(ctx context.Context, grantID, origin, reason string) error {
	if o == nil || o.pool == nil {
		return errors.New("provider compensation outbox: no pool")
	}
	if grantID == "" {
		return o.observe(origin, errors.New("provider compensation outbox: grant_id required"))
	}
	tx, err := o.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return o.observe(origin, fmt.Errorf("provider compensation outbox: begin: %w", err))
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := outbox.Emit(ctx, tx, ProviderCompensationTable,
		providerTrustGrantKind, grantID, EventProviderTrustGrantDelete,
		map[string]any{"grant_id": grantID, "origin": origin, "reason": reason},
	); err != nil {
		return o.observe(origin, fmt.Errorf("provider compensation outbox: emit: %w", err))
	}
	if err := tx.Commit(ctx); err != nil {
		return o.observe(origin, fmt.Errorf("provider compensation outbox: commit: %w", err))
	}
	committed = true
	return o.observe(origin, nil)
}

// ProviderClientReleaser — то, что умеет снять у провайдера занятое сагой.
// Реализуется clients.HydraAdminClient; обе операции идемпотентны (404 → nil).
type ProviderClientReleaser interface {
	DeleteOAuthClient(ctx context.Context, clientID string) error
	DeleteJWTBearerTrustGrant(ctx context.Context, grantID string) error
}

// CompensationObserver — счётчики исполненных компенсаций. Нужны, чтобы «ноль
// компенсаций за всю жизнь» было ОТЛИЧИМО от «механизм мёртв»: без счётчика оба
// состояния выглядят одинаково — тихо.
type CompensationObserver interface {
	// IncCompensationApplied — компенсация исполнена (клиент снят ИЛИ его уже
	// не было). origin — атрибуция саги.
	IncCompensationApplied(origin string)
}

// NewProviderCompensationApplier — drainer.Applier: снимает клиента у
// провайдера.
//
// Идемпотентность лежит на releaser'е: провайдер отвечает 404 на повторное
// снятие, и клиент трактует 404 как исполнено. Поэтому повтор доставки
// безопасен, и никакой отдельной защиты от двойного применения не нужно.
//
// Классификация отказа — обычная (drainer.Classify): недоступность провайдера
// транзиентна и ретраится, отказ по существу запроса приезжает завёрнутым в
// ErrPermanent из декодера. Отдельной корзины «прочее» здесь нет by
// construction: применение делает ровно один вызов.
func NewProviderCompensationApplier(
	releaser ProviderClientReleaser, obs CompensationObserver,
) drainer.Applier[ProviderCompensationEvent] {
	return func(ctx context.Context, eventType string, ev ProviderCompensationEvent) error {
		// Развилка идёт по ВИДУ события, а не по «какое поле непусто»: вид —
		// то, что записал автор намерения, а вывод из формы payload был бы
		// догадкой применителя о чужом решении. Неизвестный вид — ПОСТОЯННЫЙ
		// отказ: повтор его не растолкует, и корзины «прочее» здесь нет.
		switch eventType {
		case EventProviderOAuthClientDelete:
			if err := releaser.DeleteOAuthClient(ctx, ev.ClientID); err != nil {
				return fmt.Errorf("release provider oauth client: %w", err)
			}
		case EventProviderTrustGrantDelete:
			if err := releaser.DeleteJWTBearerTrustGrant(ctx, ev.GrantID); err != nil {
				return fmt.Errorf("release provider trust grant: %w", err)
			}
		default:
			return fmt.Errorf("%w: unknown provider compensation event type %q",
				drainer.ErrPermanent, eventType)
		}
		if obs != nil {
			obs.IncCompensationApplied(ev.Origin)
		}
		return nil
	}
}
