// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzcascade

// own_gates.go — ОДНО значение, которое получают все стражи службы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОДНО, А НЕ ПО ЗНАЧЕНИЮ НА СТРАЖА
//
// Композиционный корень провязывает эту дверь ВЕЗДЕ, где спрашивают о доступе.
// Тогда «страж спросил мимо» невозможно by construction: другого значения для
// него в корне нет. Именно расхождение двух значений — по одному у каждой
// поверхности — однажды и дало два действующих источника ответа на один вопрос
// об одном объекте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ НЕТ И БОЛЬШЕ НЕ БУДЕТ
//
// Запасного пути нет. Форма не ответила — вызывающий получает ОШИБКУ, а не отказ:
// «не смог спросить» и «доступа нет» — разные миры, и представление первого на
// успешном пути делает недоступность базы неотличимой от законного отказа.
//
// Второй попытки со «структурными фактами» тоже нет: она существовала ради
// движка, который знал только доехавшее очередью. Форма читает те же
// закоммиченные строки первым же вопросом (см. package doc).

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// Asker — реляционная форма, отвечающая на вопрос о доступе своей базой.
//
// Объявлен ПОРТОМ, а не конкретным типом, по двум причинам: дверь остаётся
// переходником и не тянет за собой pgx, а проба может подставить форму, которая
// НЕ ОТВЕЧАЕТ, — иначе исход «форма не ответила» непроверяем, а он тут главный.
type Asker interface {
	// Allowed — вердикт об объекте. Ошибка означает «ответа нет».
	Allowed(ctx context.Context, subject, objectType, objectID, relation string,
		condCtx map[string]any) (bool, error)
	// AllowedMany — вердикт о СТРАНИЦЕ объектов одного типа, одной читающей
	// транзакцией: все объекты страницы видят один снимок базы.
	AllowedMany(ctx context.Context, subject, objectType string, objectIDs []string,
		relation string, condCtx map[string]any) ([]bool, error)
	// SubjectsPage — кто держит отношение на объекте, страницей с курсором.
	SubjectsPage(ctx context.Context, objectType, objectID, relation, afterID string,
		limit int) (subjects []string, nextAfter string, err error)
	// Sources — кого называют основания права на объекте (разбор «почему»).
	Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error)
	// DirectRelations — какие отношения субъект уже держит на объекте (текст отказа).
	DirectRelations(ctx context.Context, subject, objectType, objectID string,
		limit int) ([]string, error)
	// DirectRelationsMany — то же о СТРАНИЦЕ объектов одного типа, одним вопросом:
	// хвост текста отказа платится на каждом отказанном объекте, а страница
	// списка отказами и состоит.
	DirectRelationsMany(ctx context.Context, subject, objectType string, objectIDs []string,
		limit int) (map[string][]string, error)
}

// Client — дверь решения поверх формы.
type Client struct {
	form Asker
}

// Wrap собирает дверь.
//
// nil-форма — законный вход только для пробы, которая о доступе не спрашивает
// вовсе: каждый вопрос к такой двери возвращает ОШИБКУ, а не «нет». Боевая
// посадка в этом состоянии находиться не должна, и это проверяет отказ в старте
// (`ownGateWiringComplaint`), а не надежда.
func Wrap(form Asker) *Client {
	return &Client{form: form}
}

// FormReachable — есть ли у двери чем отвечать. Читает страж старта.
func (c *Client) FormReachable() bool { return c != nil && c.form != nil }

// ErrFormNotWired — дверь собрана без формы.
//
// Отдельная ошибка, а не «нет»: тип, у которого источник ответа не провязан,
// отвечал бы отказом на КАЖДЫЙ вопрос, и снаружи это неотличимо от честного
// отказа модели.
var ErrFormNotWired = fmt.Errorf("authzcascade: дверь решения собрана без формы — спросить не у кого")

// Check — clients.RelationStore / authzguard.RelationChecker.
func (c *Client) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return c.CheckWithContext(ctx, subject, relation, object, nil)
}

// CheckWithContext — clients.RelationQueries / authzguard.ContextRelationChecker /
// authzfilter.ObjectChecker.
func (c *Client) CheckWithContext(
	ctx context.Context, subject, relation, object string, condCtx map[string]any,
) (bool, error) {
	if c == nil || c.form == nil {
		return false, ErrFormNotWired
	}
	ref, ok := parseObjectRef(object)
	if !ok {
		// Неразобранный объект — НЕ отказ. Вернув «нет», дверь превратила бы
		// опечатку в законный отказ, который никто никогда не найдёт.
		return false, fmt.Errorf("authzcascade: объект %q не разбирается как «тип:идентификатор»", object)
	}
	return c.form.Allowed(ctx, subject, ref.Type, ref.ID, relation, condCtx)
}

// CheckWithContextConsistent — вопрос, которому нужен СВЕЖИЙ ответ.
//
// У формы это тождество обычному вопросу, и это не упрощение: она читает
// ведущую базу службы, а «сильное чтение» существовало ровно затем, чтобы
// заставить чужое хранилище не отвечать со своей отстающей копии. Метод остаётся
// ИМЕНЕМ вопроса — вызывающий по-прежнему объявляет, что отставание ему
// недопустимо, — и перестаёт быть просьбой к чужому транспорту.
func (c *Client) CheckWithContextConsistent(
	ctx context.Context, subject, relation, object string, condCtx map[string]any,
) (bool, error) {
	return c.CheckWithContext(ctx, subject, relation, object, condCtx)
}

// BatchCheckWithContext — clients.RelationQueries / authzfilter.BatchObjectChecker.
//
// Ответ той же длины и в порядке заданных объектов: верный, но переставленный
// вердикт отфильтровал бы страницу чужим ответом. Объекты разных типов в одной
// партии — ошибка, а не молчаливое разбиение: страница списка по построению
// однотипна, и партия, где это не так, означает ошибку вызывающего.
func (c *Client) BatchCheckWithContext(
	ctx context.Context, subject, relation string, objects []string, condCtx map[string]any,
) ([]bool, error) {
	if c == nil || c.form == nil {
		return nil, ErrFormNotWired
	}
	if len(objects) == 0 {
		return nil, nil
	}
	objectType := ""
	ids := make([]string, len(objects))
	for i, object := range objects {
		ref, ok := parseObjectRef(object)
		if !ok {
			return nil, fmt.Errorf("authzcascade: объект %q не разбирается как «тип:идентификатор»", object)
		}
		if objectType == "" {
			objectType = ref.Type
		} else if ref.Type != objectType {
			return nil, fmt.Errorf(
				"authzcascade: партия несёт два типа объектов (%q и %q) — вердикты по ним "+
					"собираются разными планами, и один ответ на два вопроса был бы вердиктом, "+
					"которого никто не выносил", objectType, ref.Type)
		}
		ids[i] = ref.ID
	}
	return c.form.AllowedMany(ctx, subject, objectType, ids, relation, condCtx)
}

// ListSubjects — clients.RelationQueries: кто держит отношение на объекте.
//
// Курсор проходит НАСКВОЗЬ: страница без продолжения оставляет остаток
// недостижимым при живых правах.
func (c *Client) ListSubjects(
	ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string,
) ([]string, string, error) {
	if c == nil || c.form == nil {
		return nil, "", ErrFormNotWired
	}
	return c.form.SubjectsPage(ctx, objectType, objectID, relation, pageToken, pageSize)
}

// ListUsers — access_binding.PrincipalLister: развёрнутый набор принципалов.
//
// Второй результат — признак усечения У ИСТОЧНИКА. Форма его не производит:
// перечисление постранично и продолжаемо, поэтому неполного ответа, о котором
// нельзя спросить дальше, у неё не бывает. Признак остаётся в подписи, потому что
// его читает вызывающий, и всегда false — это ЧЕСТНОЕ значение, а не заглушка.
//
// userTypes сужает по типу субъекта; пустой набор — «любой».
func (c *Client) ListUsers(
	ctx context.Context, objectType, objectID, relation string, userTypes []string,
) ([]string, bool, error) {
	if c == nil || c.form == nil {
		return nil, false, ErrFormNotWired
	}
	want := make(map[string]struct{}, len(userTypes))
	for _, t := range userTypes {
		want[t] = struct{}{}
	}

	out := make([]string, 0, 64)
	after := ""
	// Предел обходов — не осторожность, а граница: перечисление принципалов
	// объекта конечно, и обход, который её не имеет, на испорченном курсоре
	// вертелся бы вечно, держа соединение живого запроса.
	const maxPages = 64
	for page := 0; page < maxPages; page++ {
		subjects, next, err := c.form.SubjectsPage(ctx, objectType, objectID, relation, after, 0)
		if err != nil {
			return nil, false, err
		}
		for _, s := range subjects {
			if len(want) > 0 {
				ref, ok := parseObjectRef(s)
				if !ok {
					continue
				}
				if _, allowed := want[ref.Type]; !allowed {
					continue
				}
			}
			out = append(out, s)
		}
		if next == "" {
			return out, false, nil
		}
		after = next
	}
	return nil, false, fmt.Errorf(
		"authzcascade: перечисление принципалов %s:%s#%s не сошлось за %d страниц — "+
			"частичный ответ здесь читался бы как полный набор имеющих право",
		objectType, objectID, relation, maxPages)
}

// Sources — кого называют основания права на объекте.
func (c *Client) Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error) {
	if c == nil || c.form == nil {
		return nil, ErrFormNotWired
	}
	return c.form.Sources(ctx, objectType, objectID, relation)
}

// DirectRelations — какие отношения субъект уже держит на объекте.
func (c *Client) DirectRelations(
	ctx context.Context, subject, objectType, objectID string, limit int,
) ([]string, error) {
	if c == nil || c.form == nil {
		return nil, ErrFormNotWired
	}
	return c.form.DirectRelations(ctx, subject, objectType, objectID, limit)
}

// DirectRelationsMany — те же прямые отношения о СТРАНИЦЕ объектов одного типа.
//
// Дверь остаётся переходником: она не собирает страницу из одиночных ответов, а
// передаёт вопрос форме целиком. Собирать её здесь значило бы завести второе
// место, знающее, во что обходится страница, — и оно бы разошлось с формой молча.
func (c *Client) DirectRelationsMany(
	ctx context.Context, subject, objectType string, objectIDs []string, limit int,
) (map[string][]string, error) {
	if c == nil || c.form == nil {
		return nil, ErrFormNotWired
	}
	return c.form.DirectRelationsMany(ctx, subject, objectType, objectIDs, limit)
}

// Compile-time guards: дверь обязана быть подставима на каждом порту, который
// провязывает композиционный корень.
var (
	_ clients.RelationStore   = (*Client)(nil)
	_ clients.RelationQueries = (*Client)(nil)
)
