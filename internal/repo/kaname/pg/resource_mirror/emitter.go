// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package resource_mirror — приём регистрации и снятия объекта в проекцию
// службы доступа: зеркало `kaname.resource_mirror`, цепь предков
// `kaname.resource_parent_edge` и голова объекта `kaname.object_head`.
//
// Зеркало — ВЫХОДНАЯ денормализованная копия меток и родителя ресурсов ЧУЖИХ
// владельцев (compute, vpc, registry, …); источник истины остаётся у владельца.
// Наполняется ПУШЕМ по ребру «владелец → служба доступа»: служба доступа никого
// не зовёт, граф вызовов ацикличен.
//
// # Производитель проекции — триггер базы, а не этот пакет
//
// Этот пакет проекцию НЕ пишет. Он кладёт намерение строкой приёма
// `kaname.resource_event_intake`, а сравнение поколения с головой и запись
// головы, зеркала и цепи делает ОДИН производитель — триггер `resource_event`
// (миграция `20261007084833_object_generation_has_one_projection_producer.sql`;
// приёмка NTF-3, Р30 «Приём поколения — CAS», «Поколение и проекция — один
// производитель»). Исход приёма возвращается той же вставкой. Писать таблицы
// проекции мимо него нечем и незачем — это держит гейт
// `internal/repohygiene` `TestObjectProjectionHasOneProducer` (NTF3-180 (г)).
//
// # Атомарность с намерением кортежа
//
// UpsertTx / DeleteTx исполняются в ТОЙ ЖЕ транзакции, что и запись намерения
// кортежа владельца в `fga_outbox`: откат вызывающей транзакции не оставляет ни
// проекции, ни намерения (запрет #10).
package resource_mirror

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Row — намерение регистрации одного объекта. Labels nil — пустой объект `{}`.
type Row struct {
	// ObjectType — тип в словаре КАТАЛОГА ресурсов (`vpc.network`): им названы
	// зеркало и голова. Цепь предков триггер кладёт словарём МОДЕЛИ — перевод
	// делает он, у той же строки каталога, чью ливность спрашивает.
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	Labels          map[string]string

	// Generation — поколение объекта у владельца: строго растущее целое на
	// каждое изменение объекта. Обязательно (`> 0`): приёма без поколения нет.
	// Применяется, только если строго новее головы объекта (включая надгробие
	// снятия); иначе исход REJECTED_STALE — не записано ничего.
	Generation int64

	// ParentChain — цепь предков от БЛИЖАЙШЕГО к дальнему, каждый элемент
	// `"<type>:<id>"`. Пусто — «предков нет»: применённая регистрация заменяет
	// набор рёбер объекта целиком. Вывод цепи из области — обязанность ВЛАДЕЛЬЦА
	// (pkg/ownerregister.ParentChain).
	//
	// Когда обе колонки родителя пусты, триггер выводит их из этой же цепи —
	// ближайший предок вида `project` и ближайший вида `account` (kacho#2051):
	// строка с цепью и без колонок невидима материализации.
	ParentChain []string
}

// Outcome — исход приёма одного намерения. Оба факта решает база, ни один не
// берётся со слов вызывающего:
//
//   - Applied — поколение строго новее головы, проекция записана. Ложь —
//     REJECTED_STALE: запоздалая либо повторная доставка, не изменившая ничего.
//   - ProjectionUnchanged — применённая регистрация сдвинула ТОЛЬКО поколение:
//     родитель и метки — всё, что читает отбор, — уже были теми же. Ничто
//     материализованное по прежним фактам устареть не могло.
type Outcome struct {
	Applied             bool
	ProjectionUnchanged bool
}

// Исходы приёма — ЗАКРЫТЫЙ словарь триггера `resource_event`
// (столбец `resource_event_intake.outcome`).
const (
	OutcomeApplied         = "APPLIED"
	OutcomeRejectedStale   = "REJECTED_STALE"
	OutcomeUnknownType     = "UNKNOWN_TYPE"
	OutcomeMalformedParent = "MALFORMED_PARENT"
)

// StmtIntake — вставка намерения в приём. Объявлена ОДИН раз и экспортирована:
// её же шлёт пачкой посевщик сетки порядков (`../scalegrid`), потому что мерит
// стоимость того, что выпускает продукт, — копия текста там расходилась бы
// молча (#1890).
//
// Параметры $1..$8: вид намерения (`register` | `unregister`), тип объекта,
// идентификатор, поколение, проект-родитель, аккаунт-родитель, метки (jsonb),
// цепь предков (text[]).
const StmtIntake = `INSERT INTO kaname.resource_event_intake
	   (change, object_type, object_id, generation,
	    parent_project_id, parent_account_id, labels, parent_chain)
	 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::text[])
	 RETURNING outcome, coalesce(projection_unchanged, false), coalesce(refused, '')`

// Виды намерения приёма.
const (
	ChangeRegister   = "register"
	ChangeUnregister = "unregister"
)

// UpsertTx кладёт намерение РЕГИСТРАЦИИ в приём, в транзакции вызывающего, и
// возвращает исход триггера.
//
// Отказы входу — ошибки, а не исходы: тип вне живого каталога (сам объект или
// звено цепи) — `ErrUnknownResourceType`, называющий тип; звено цепи не формы
// `"<type>:<id>"` — ошибка, называющая звено. Пропуск непонятого звена сделал
// бы цепь короче настоящей, и объект оказался бы под тем предком, под которым он
// не находится. Ни при одном отказе триггер не записывает ничего.
func UpsertTx(ctx context.Context, tx pgx.Tx, row Row) (Outcome, error) {
	if tx == nil {
		return Outcome{}, fmt.Errorf("resource_mirror: tx must not be nil")
	}
	if row.Generation <= 0 {
		return Outcome{}, fmt.Errorf("resource_mirror: generation %d of %s:%s is not positive — "+
			"there is no admission without a generation", row.Generation, row.ObjectType, row.ObjectID)
	}
	labels := row.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	payload, err := json.Marshal(labels)
	if err != nil {
		return Outcome{}, fmt.Errorf("resource_mirror: marshal labels: %w", err)
	}
	chain := row.ParentChain
	if chain == nil {
		chain = []string{}
	}
	return intake(ctx, tx, ChangeRegister, row.ObjectType, row.ObjectID, row.Generation,
		row.ParentProjectID, row.ParentAccountID, payload, chain)
}

// DeleteTx кладёт намерение СНЯТИЯ объекта в приём и возвращает исход.
//
// Применённое снятие убирает строку зеркала и цепь предков и оставляет
// НАДГРОБИЕ — голову объекта с поколением снятия: регистрация поколения не новее
// него зеркала не восстанавливает. Снятие не новее головы — REJECTED_STALE.
//
// Снятие каталог-условия НЕ спрашивает, и это решение: условие приёма связывает
// ВХОД, а снятие убирает уже лежащее. Ресурс, чей тип сняли с платформы после
// регистрации, обязан оставаться удаляемым — снятие типа мягкое, строка
// каталога остаётся, и имя модели по ней резолвится по-прежнему.
func DeleteTx(ctx context.Context, tx pgx.Tx, objectType, objectID string, generation int64) (Outcome, error) {
	if tx == nil {
		return Outcome{}, fmt.Errorf("resource_mirror: tx must not be nil")
	}
	if generation <= 0 {
		return Outcome{}, fmt.Errorf("resource_mirror: generation %d of %s:%s is not positive — "+
			"there is no admission without a generation", generation, objectType, objectID)
	}
	return intake(ctx, tx, ChangeUnregister, objectType, objectID, generation, "", "", []byte("{}"), []string{})
}

// intake исполняет вставку приёма и разбирает исход по ЗАКРЫТОМУ словарю:
// незнакомое слово — ошибка, а не «прочее».
func intake(ctx context.Context, tx pgx.Tx, change, objectType, objectID string, generation int64,
	parentProject, parentAccount string, labels []byte, chain []string,
) (Outcome, error) {
	var outcome, refused string
	var unchanged bool
	if err := tx.QueryRow(ctx, StmtIntake,
		change, objectType, objectID, generation, parentProject, parentAccount, labels, chain,
	).Scan(&outcome, &unchanged, &refused); err != nil {
		return Outcome{}, fmt.Errorf("resource_mirror: %s %s:%s: %w", change, objectType, objectID, err)
	}
	switch outcome {
	case OutcomeApplied:
		return Outcome{Applied: true, ProjectionUnchanged: unchanged}, nil
	case OutcomeRejectedStale:
		return Outcome{}, nil
	case OutcomeUnknownType:
		if change == ChangeRegister && refused == objectType {
			// Отказ НАЗЫВАЕТ тип и правило: без имени вызывающий не знает, что
			// чинить. Перечень грантуемых типов платформа отдаёт арендатору сама
			// (PermissionCatalogService), оракулом отказ не является.
			return Outcome{}, iamerr.Wrapf(iamerr.ErrUnknownResourceType,
				"resource type %q is not a live entry of the platform resource catalog", refused)
		}
		return Outcome{}, iamerr.Wrapf(iamerr.ErrUnknownResourceType,
			"resource type %q has no entry in the platform resource catalog, so its "+
				"rights-model type name cannot be resolved", refused)
	case OutcomeMalformedParent:
		return Outcome{}, fmt.Errorf("resource_parent_edge: непонятая форма предка %q "+
			"(ожидается \"<type>:<id>\")", refused)
	default:
		return Outcome{}, fmt.Errorf("resource_mirror: %s %s:%s: незнакомый исход приёма %q",
			change, objectType, objectID, outcome)
	}
}

// HeadGenerationTx — поколение головы объекта (последнее применённое, включая
// надгробие снятия); `0` — головы нет, ни одно поколение не применялось.
//
// Нужно ОДНОМУ виду вызывающего — владельцу собственного синтетического
// объекта службы (дымовая проба посева), который сам себе владелец и потому
// сам ставит своё следующее поколение. Чужим объектам поколение ставит их
// владелец: прочитать голову и прибавить единицу за него значило бы выдумать
// поколение, которое владелец потом законно пришлёт как более старое.
func HeadGenerationTx(ctx context.Context, tx pgx.Tx, objectType, objectID string) (int64, error) {
	var g int64
	err := tx.QueryRow(ctx,
		`SELECT coalesce((SELECT generation FROM kaname.object_head
		                   WHERE object_type = $1 AND object_id = $2), 0)`,
		objectType, objectID).Scan(&g)
	if err != nil {
		return 0, fmt.Errorf("resource_mirror: head of %s:%s: %w", objectType, objectID, err)
	}
	return g, nil
}
