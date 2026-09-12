// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	corequota "github.com/PRO-Robotech/corelib/quota"
	"github.com/PRO-Robotech/corelib/quota/quotaread"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Чтение квот, носителем которых является ЛИЧНОСТЬ.
//
// # Чем это отличается от пяти прочих владельцев
//
// У них снимок величины приезжает от соседа и может отставать; у владельца
// величин авторитет лежит в этой же базе, и списание обновляет снимок в том же
// операторе. Поэтому здесь нет ни резолва по сети, ни курсора дельты, ни
// материализации на стороне Go — есть чтение и добор недостающего из авторитета.
//
// # Почему ответ добирается, а не отдаётся как есть
//
// Строка учёта заводится триггером на первом же аккаунте, поэтому у всякой
// вошедшей личности она есть. Но она СНИМАЕТСЯ, когда администратор отзывает
// величину: строка не вправе пережить авторитет, иначе отказ назвал бы предел,
// которого больше нет. В этом окне чтение обязано ответить не пустым набором —
// пустой был бы прочитан как «предела нет», ровно наоборот действительности.

// IdentityQuotaSchema — схема, в которой у владельца величин лежит таблица учёта.
const IdentityQuotaSchema = "kaname"

// IdentityQuotaRepo — чтение квот личности.
type IdentityQuotaRepo struct {
	pool *pgxpool.Pool
}

// NewIdentityQuotaRepo — constructor. Composition root: cmd/kaname/wiring.go.
func NewIdentityQuotaRepo(pool *pgxpool.Pool) *IdentityQuotaRepo {
	return &IdentityQuotaRepo{pool: pool}
}

// IdentityOfUser — внешний идентификатор входа по строке пользователя.
//
// Отдельным глаголом, а не полем ответа: строка пользователя есть ЧЛЕНСТВО в
// одном аккаунте, а личность — то, что их держит. Смешать их в одном значении
// значило бы дать вызывающему повод считать одно другим ровно там, где различие и
// несущее.
//
// Пустой внешний идентификатор — законное состояние строки (приглашённый, ещё не
// вошедший), и оно НЕ является личностью: у такого субъекта нечего считать.
// Отказ здесь называет предмет, а не отдаёт пустой ответ.
func (r *IdentityQuotaRepo) IdentityOfUser(ctx context.Context, userID domain.UserID) (string, error) {
	const q = `SELECT external_id FROM kaname.users WHERE id = $1`
	var external string
	if err := r.pool.QueryRow(ctx, q, string(userID)).Scan(&external); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", string(userID))
		}
		return "", fmt.Errorf("read identity of user: %w", err)
	}
	if external == "" {
		return "", iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"User %s carries no login identity", string(userID))
	}
	return external, nil
}

// States отдаёт квоты личности — полным набором её видов, никогда пустым.
//
// Порядок — по виду, тем же признаком, что и на пути из базы: набор, добранный из
// авторитета, обязан идти так же, как набор, прочитанный из строк учёта, иначе
// клиент увидел бы перестановку там, где ничего не менялось.
func (r *IdentityQuotaRepo) States(ctx context.Context, identity string) ([]quotaread.State, error) {
	if identity == "" {
		// Пустой носитель прочитал бы чужие строки ровно тогда, когда в таблице
		// однажды окажется строка с пустым идентификатором. Отказ дешевле.
		return nil, iamerr.Wrapf(iamerr.ErrFailedPrecondition, "identity: required")
	}

	// Оператор чтения — ОБЩИЙ (`pkg/quota.ListStates`): таблица у всех владельцев
	// одна и та же с точностью до имени схемы, и своя копия здесь разошлась бы с
	// соседями на составе столбцов или на порядке.
	states, err := corequota.ListStates(ctx, r.pool, IdentityQuotaSchema, CarrierIdentity, identity)
	if err != nil {
		return nil, err
	}

	// ВЕЛИЧИНА ВИДА ПОСАДКИ БЕРЁТСЯ У ПОСАДКИ, а не из снимка строки учёта
	// (приёмка `KAN-QUOTA-1`, `П25`, сценарий `KAN-Q3-05`).
	//
	// Снимок в строке учёта обновляется СПИСАНИЕМ, поэтому между сменой величины
	// и следующим созданием ресурса он отстаёт. Отдать его арендатору значило бы
	// назвать потолок, который уже не действует, — то есть отправить его менять
	// поведение, которое уже изменено.
	//
	// Двух источников это не заводит: источник ОДИН — проекция посадки, а снимок
	// есть производное от него, обновляемое на пути списания ради текста отказа.
	// Читающий путь предпочитает источник производному, а не спорит с ним.
	for i := range states {
		if !domain.IsPostureStatedKind(domain.LimitKind(states[i].Kind)) {
			continue
		}
		value, ok, serr := statedOwnCeiling(ctx, r.pool, states[i].Kind)
		if serr != nil {
			return nil, serr
		}
		if ok {
			states[i].Limit = value
			states[i].SourceScope = scopeDefault
			states[i].SourceScopeID = ""
		}
	}

	have := make(map[string]bool, len(states))
	for _, st := range states {
		have[st.Kind] = true
	}

	// Добор недостающего ИЗ АВТОРИТЕТА. Вид, у которого величина не назначена ни
	// на одной области, в ответ не попадает вовсе — и это не пропуск: «потолок не
	// назван» есть отказ, а не бесконечность, и показывать его числом было бы
	// неправдой в обе стороны.
	for _, e := range domain.CountableEntries() {
		if e.Carrier != domain.CarrierIdentity || have[string(e.Kind)] {
			continue
		}
		st, ok, derr := r.statedDefault(ctx, string(e.Kind), identity)
		if derr != nil {
			return nil, derr
		}
		if ok {
			states = append(states, st)
		}
	}

	sortStatesByKind(states)
	return states, nil
}

// statedDefault читает величину, назначенную на умолчании.
//
// Только умолчание, и это ограничение НАЗВАНО: словарь областей знает DEFAULT,
// ACCOUNT и PROJECT, и ни одна из двух последних к личности не применима.
// Личный потолок отдельному человеку сегодня невыразим — это предмет, а не
// умолчание, за которое можно спрятаться.
func (r *IdentityQuotaRepo) statedDefault(
	ctx context.Context, kind, identity string,
) (quotaread.State, bool, error) {
	var (
		value   int64
		scope   string
		scopeID string
	)

	// ИСТОЧНИК ВЫБИРАЕТСЯ ПО РОЛИ ВИДА — тем же различением, каким его выбирает
	// списание (`П25`). Читать величину из другого места, чем списывает триггер,
	// значило бы отдать арендатору число, по которому отказ не наступает.
	if domain.IsPostureStatedKind(domain.LimitKind(kind)) {
		stated, ok, serr := statedOwnCeiling(ctx, r.pool, kind)
		if serr != nil {
			return quotaread.State{}, false, serr
		}
		if !ok {
			// Посадка вид не объявила. Ответить нулём нельзя: ноль есть решение
			// «не заводить», а здесь величина неизвестна — и «потолок не назван»
			// есть отказ, а не бесконечность и не запрет.
			return quotaread.State{}, false, nil
		}
		value, scope, scopeID = stated, scopeDefault, ""
	} else {
		const q = `
			SELECT limit_value, scope, scope_id
			  FROM kaname.limits
			 WHERE withdrawn_at IS NULL AND kind = $1 AND scope = 'DEFAULT'`
		if err := r.pool.QueryRow(ctx, q, kind).Scan(&value, &scope, &scopeID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return quotaread.State{}, false, nil
			}
			return quotaread.State{}, false, fmt.Errorf("read stated default for %s: %w", kind, err)
		}
	}
	return quotaread.State{
		Kind: kind,
		// Потребление нулевое не по умолчанию, а по факту: строки учёта нет,
		// значит ни одна вставка ещё не списывала место.
		Used:          0,
		Limit:         value,
		SourceScope:   scope,
		SourceScopeID: scopeID,
		CarrierType:   CarrierIdentity,
		CarrierID:     identity,
	}, true, nil
}

// CarrierIdentity — носитель «личность» в том виде, в каком он стоит в столбце.
//
// Отдельная константа адаптера, а не ссылка на доменную: значение принадлежит
// СХЕМЕ (оно стоит в `carrier_type` и в предикате триггера), и адаптер обязан
// называть его тем же литералом, что база. Совпадение с доменной константой
// закреплено пробой, а не подразумевается.
const CarrierIdentity = "identity"

// scopeDefault — область, которой отвечает величина ПОСАДКИ.
//
// `DEFAULT` — не «за неимением лучшего», а честный ответ на вопрос, ради которого
// поле заведено: «кто может поднять этот потолок». Величина посадки одна на
// установку и принадлежит тому, кто её ставит, — то есть ни арендатору, ни его
// аккаунту, ни его проекту. Словарь области у контракта закрыт тремя значениями и
// расширению не подлежит: имя и номер уезжают арендатору в каждом ответе.
const scopeDefault = "DEFAULT"

// sortStatesByKind — единственное место, задающее порядок ответа.
func sortStatesByKind(states []quotaread.State) {
	for i := 1; i < len(states); i++ {
		for j := i; j > 0 && states[j].Kind < states[j-1].Kind; j-- {
			states[j], states[j-1] = states[j-1], states[j]
		}
	}
}
