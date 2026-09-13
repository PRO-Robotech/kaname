// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal

// narrow.go — КЛИЕНТ СУЖАТЕЛЯ подписки: вопрос о снятом предмете адресуется и
// ему самому, и его захваченным областям.
//
// # Зачем он вообще нужен
//
// Вердикт службы соединяет выдачу с ОБЛАСТЯМИ объекта, а звено вместимости для
// собственных типов выводится из самой ресурсной строки. Снятие строки убирает
// звено, и пообъектный вопрос о снятом предмете отвечает «нет» — всем. Сервер
// потока судит снятия по якорю, но якорь оболочки прибит к проекту, а предметы
// службы вместимы аккаунтом. Разбор целиком — §2.3 APPROVED-приёмки.
//
// Без этого клиента подписчик, снявший опрос, держал бы снятые строки ВЕЧНО, и
// держал бы молча: ни отказа, ни пропуска в нумерации у него не было бы.
//
// # Почему это НЕ второй вердикт
//
// Вопрос идёт в ТУ ЖЕ дверь и тем же предикатом отношений, что у списков.
// Меняется только предмет вопроса — и только для тех идентификаторов, чья строка
// журнала есть СНЯТИЕ. Живой предмет спрашивается как обычно, и ветвь областей
// его не касается: иначе это было бы расширение доступа к живому.
//
// # Почему АДДИТИВНО, а не вместо
//
// У вердикта две ветви: выдача, достающая до предмета через звено вместимости, и
// ПРЯМОЙ ФАКТ на самом предмете, звена не спрашивающий вовсе. Замещающая форма
// теряла бы вторую — владелец аккаунта держит своё право прямым фактом, а
// захваченная область аккаунта есть кластер, и о снятии собственного аккаунта он
// не узнал бы, тогда как читатель кластера узнал бы.
//
// # ЦЕНА НАЗВАНА, а не подразумевается
//
// Тот, кому виден аккаунт, узнаёт о снятии предмета в нём — включая предмет,
// который ему самому виден не был: вид, идентификатор, факт снятия; ни
// состояния, ни содержимого. Это тот же размен, который контракт принял для
// проектного якоря, перенесённый на якорь, который у службы есть.

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/corelib/listnarrow"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
)

// scopeKey — ключ памятки вердиктов об областях: у партии обычно один субъект и
// одна-две области, и платить вопросом за каждое повторение незачем.
type scopeKey struct {
	subject   string
	scopeType string
	scopeID   string
	relation  string
}

// Scope — одна захваченная область предмета: тип объекта модели прав и его
// идентификатор.
type Scope struct {
	Type string
	ID   string
}

// Door — дверь решения о доступе. Узкий порт, и он ТОТ ЖЕ, что у списков:
// второй источник ответа на один вопрос об одном объекте здесь уже однажды
// разошёлся, и заводить его снова нельзя.
type Door interface {
	BatchCheckWithContext(ctx context.Context, subject, relation string,
		objects []string, condCtx map[string]any) (allowed []bool, err error)
}

// RemovalScopes — журнал в той части, которая нужна сужателю: какие из названных
// предметов СНЯТЫ и какие области у них захвачены.
//
// Порт объявлен здесь, а не импортирован, чтобы клиент не зависел от того, кто
// ему отвечает.
type RemovalScopes interface {
	// CapturedScopes возвращает области ТОЛЬКО для снятых предметов. Предмет, у
	// которого снятия нет, в ответе отсутствует — и это несущее: наличие ключа
	// и есть признак «строка журнала по нему снятие».
	CapturedScopes(ctx context.Context, kind string, ids []string) (map[string][]Scope, error)
}

// NarrowClient — реализация порта сужателя фундамента.
//
// Сужатель строится из этого клиента (`listnarrow.New`), поэтому владелец
// отвечает на КАЖДЫЙ пообъектный вопрос, оставаясь при штатном типе сужателя.
type NarrowClient struct {
	door     Door
	removals RemovalScopes
}

// NewNarrowClient — сборка из композиционного корня.
func NewNarrowClient(door Door, removals RemovalScopes) *NarrowClient {
	return &NarrowClient{door: door, removals: removals}
}

// BatchCheck — вердикты В ПОРЯДКЕ ВОПРОСОВ и ТОЙ ЖЕ ДЛИНЫ.
//
// Контракт длины и порядка держится позиционной записью: ответ пишется в СВОЙ
// индекс и никогда не дописывается. Переставленный вердикт отфильтровал бы поток
// чужим ответом, и заметить это вызывающий не может.
//
// Отказ двери прекращает партию целиком: «не смог спросить» и «доступа нет» —
// разные миры, и представление первого на успешном пути сделало бы недоступность
// базы неотличимой от законного отказа.
func (c *NarrowClient) BatchCheck(ctx context.Context, checks []listnarrow.Check) ([]bool, error) {
	out := make([]bool, len(checks))
	if len(checks) == 0 {
		return out, nil
	}
	if c.door == nil {
		return nil, fmt.Errorf("subscriptionjournal: дверь решения не провязана — " +
			"сужатель без неё пропускал бы весь журнал молча")
	}

	// Первая половина вопроса: про сам предмет, как у списков.
	if err := c.askAboutSubjects(ctx, checks, out); err != nil {
		return nil, err
	}

	// Вторая половина: только для тех, кому отказано И чья строка журнала —
	// снятие. Живого предмета она не касается by construction.
	if err := c.askAboutCapturedScopes(ctx, checks, out); err != nil {
		return nil, err
	}
	return out, nil
}

// askAboutSubjects — обычный пообъектный вопрос, сгруппированный по тройке
// «субъект, тип, отношение»: дверь принимает один вопрос о многих объектах
// ОДНОГО типа.
func (c *NarrowClient) askAboutSubjects(
	ctx context.Context, checks []listnarrow.Check, out []bool,
) error {
	type key struct{ subject, resourceType, relation string }
	groups := make(map[key][]int, len(checks))
	for i, ch := range checks {
		if ch.Subject == "" || ch.ResourceType == "" || ch.ResourceID == "" {
			// Безымянный вызывающий и неадресуемый объект отсекаются
			// БЕЗУСЛОВНО: за этим методом нет пообъектной проверки на крае.
			continue
		}
		k := key{ch.Subject, ch.ResourceType, ch.RequiredRelation}
		groups[k] = append(groups[k], i)
	}

	for k, idx := range groups {
		objects := make([]string, len(idx))
		for j, i := range idx {
			objects[j] = checks[i].ResourceType + ":" + checks[i].ResourceID
		}
		allowed, err := c.door.BatchCheckWithContext(ctx, k.subject, k.relation, objects, nil)
		if err != nil {
			return err
		}
		if len(allowed) != len(objects) {
			// Короткий ответ неотличим от страницы отказов, и страница молчаливых
			// отказов — ровно тот дефект, который сужение обязано не вносить.
			return fmt.Errorf("subscriptionjournal: дверь ответила %d вердиктами "+
				"на %d вопросов — смещение индексов выдало бы вердикт одного "+
				"объекта за другой", len(allowed), len(objects))
		}
		for j, i := range idx {
			out[i] = allowed[j]
		}
	}
	return nil
}

// askAboutCapturedScopes — вторая половина вопроса.
//
// Спрашивается ТОЛЬКО про отказанные предметы и ТОЛЬКО если строка журнала по
// ним — снятие. Отношения берутся у ОБЛАСТИ, а не у предмета: вопрос здесь
// «виден ли вызывающему этот аккаунт», и предикат его чтения объявлен один раз
// (`authzfilter.RelationsFor`).
func (c *NarrowClient) askAboutCapturedScopes(
	ctx context.Context, checks []listnarrow.Check, out []bool,
) error {
	if c.removals == nil {
		return nil
	}

	// Отказанные, сгруппированные по виду: журнал спрашивается одним запросом на
	// вид, а не по вопросу на предмет.
	denied := make(map[string][]string)
	for i, ch := range checks {
		if out[i] || ch.Subject == "" || ch.ResourceType == "" || ch.ResourceID == "" {
			continue
		}
		denied[ch.ResourceType] = append(denied[ch.ResourceType], ch.ResourceID)
	}
	if len(denied) == 0 {
		return nil
	}

	scopes := make(map[string]map[string][]Scope, len(denied))
	for kind, ids := range denied {
		got, err := c.removals.CapturedScopes(ctx, kind, ids)
		if err != nil {
			return err
		}
		scopes[kind] = got
	}

	// Вердикт по области спрашивается один раз на четвёрку «субъект, тип области,
	// её идентификатор, отношение»: у партии обычно один субъект и одна-две
	// области.
	memo := make(map[scopeKey]bool)

	for i, ch := range checks {
		if out[i] || ch.Subject == "" {
			continue
		}
		captured := scopes[ch.ResourceType][ch.ResourceID]
		for _, sc := range captured {
			if sc.Type == "" || sc.ID == "" {
				continue
			}
			allowed, err := c.scopeAllows(ctx, memo, ch.Subject, sc)
			if err != nil {
				return err
			}
			if allowed {
				out[i] = true
				break
			}
		}
	}
	return nil
}

// scopeAllows — виден ли вызывающему объект области.
//
// Предикат чтения области берётся у ЕДИНСТВЕННОГО объявления видимости службы,
// а не выписывается рядом: второй перечень разошёлся бы с первым молча, и
// разошёлся бы в сторону лишнего доступа.
func (c *NarrowClient) scopeAllows(
	ctx context.Context, memo map[scopeKey]bool, subject string, sc Scope,
) (bool, error) {
	for _, relation := range authzfilter.RelationsFor(sc.Type) {
		k := scopeKey{subject: subject, scopeType: sc.Type, scopeID: sc.ID, relation: relation}
		if allowed, ok := memo[k]; ok {
			if allowed {
				return true, nil
			}
			continue
		}
		verdicts, err := c.door.BatchCheckWithContext(ctx, subject, relation,
			[]string{sc.Type + ":" + sc.ID}, nil)
		if err != nil {
			return false, err
		}
		if len(verdicts) != 1 {
			return false, fmt.Errorf("subscriptionjournal: дверь ответила %d "+
				"вердиктами на один вопрос об области", len(verdicts))
		}
		memo[k] = verdicts[0]
		if verdicts[0] {
			return true, nil
		}
	}
	return false, nil
}

// Compile-time assertion: клиент обязан удовлетворять порту фундамента.
var _ listnarrow.AuthorizeClient = (*NarrowClient)(nil)
