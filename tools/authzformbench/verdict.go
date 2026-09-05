// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Вычисление вердикта формы E — ОДИН артефакт, параметризованный источником
// фактов.
//
// Матрица собирается не из одного места: ячейки харнесса снимаются на своей,
// синтетической схеме, а ячейки каскада и механики доставки — там, где эти
// предметы существуют, то есть на мигрированной схеме iam. Признак «откуда снята
// ячейка» различает МЕСТА и молча пропустил бы случай, когда форма E в одном
// месте и форма E в другом — два разных кода, напечатанных одной строкой формы.
// Поэтому вердикт вычисляет ровно этот тип, а различие мест выражается
// источником фактов, который ему подан.
//
// Пакет `services/iam/tools/authzformbench` не `internal`, поэтому позвать этот артефакт
// изнутри `services/iam/...` законно; обратное направление запрещено правилом
// `internal/`, и раскладка на этом и построена.

// TableNames — имена таблиц источника фактов.
//
// Схемы у мест снятия разные, а запрос один: то, что у синтетической схемы
// называется одним именем, у iam называется другим, и именно это различие
// выражается здесь — а не второй реализацией того же вердикта.
type TableNames struct {
	Mirror          string // зеркало объектов: тип · идентификатор · оба родителя · метки
	Projects        string // проект → аккаунт
	Accounts        string // аккаунт → кластер
	Bindings        string // выдача: область и роль
	BindingSubjects string // субъекты выдачи
	Selectors       string // правило-селектор выдачи (по меткам)
	RoleVerbs       string // роль → глаголы, которые она даёт
	AccountAdmins   string // каскад, уровень 3
	ClusterAdmins   string // каскад, уровни 1-2
}

// FactSource — то, поверх чего форма E вычисляет вердикт.
//
// Интерфейс узкий намеренно: вердикт обязан быть ОДНИМ запросом, поэтому от
// источника нужен ровно один метод чтения и словарь имён.
type FactSource interface {
	Names() TableNames
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// CascadeChain — объявленная цепь обхода каскада. Глубина ОГРАНИЧЕНА и это факт
// дерева, а не допущение: три верхних уровня доступа разрешаются каскадом
// намеренно (аварийный путь не должен зависеть от состояния конвейера), а
// вложенности групп в продукте нет.
const CascadeChain = "leaf → project → account → cluster"

// CascadeDepth — число уровней, которые проходит соединение. Печатается рядом с
// измеренным временем: глубина объявляется, а не подразумевается.
const CascadeDepth = 3

// RelationalVerdict — вердикт формы E.
type RelationalVerdict struct {
	Src FactSource
}

// allowedSQL — единственный запрос вердикта.
//
// Три источника разрешения, и они перечислены сверху вниз по стоимости:
//
//  1. выдача — субъект назван в привязке, роль привязки даёт спрошенный глагол,
//     объект попадает под правило-селектор привязки и лежит в её области
//     (проектной либо аккаунтной — вложенность области транзитивна);
//  2. каскад, уровень 3 — администратор аккаунта, которому принадлежит проект
//     объекта;
//  3. каскад, уровни 1-2 — администратор кластера, которому принадлежит аккаунт.
//
// Каскадные ветви НЕ читают материализованного состава и вообще ничего, что
// доставляется очередью: они разрешаются соединением по родительским указателям
// в момент запроса. Это то же свойство, которым каскад обладает сегодня, и оно
// здесь сохранено, а не изобретено.
func (v RelationalVerdict) allowedSQL() string {
	t := v.Src.Names()
	// Имена подставляются из закрытой структуры, заполняемой самим харнессом;
	// пользовательского ввода в этой строке нет ни одного.
	return fmt.Sprintf(`
SELECT m.object_id
  FROM %[1]s m
 WHERE m.object_type = $1
   AND m.object_id = ANY($2::text[])
   AND (
     EXISTS (
       SELECT 1
         FROM %[5]s s
         JOIN %[4]s b  ON b.id = s.binding_id
         JOIN %[7]s rv ON rv.role = b.role AND rv.verb = $4
         JOIN %[6]s sel ON sel.binding_id = b.id AND sel.object_type = m.object_type
        WHERE s.subject = $3
          AND m.labels @> sel.labels
          AND ( (b.scope_type = 'project' AND b.scope_id = m.parent_project_id)
             OR (b.scope_type = 'account' AND b.scope_id = m.parent_account_id) )
     )
     OR EXISTS (
       SELECT 1
         FROM %[2]s p
         JOIN %[8]s aa ON aa.account_id = p.account_id
        WHERE p.id = m.parent_project_id AND aa.subject = $3
     )
     OR EXISTS (
       SELECT 1
         FROM %[2]s p
         JOIN %[3]s a  ON a.id = p.account_id
         JOIN %[9]s ca ON ca.cluster_id = a.cluster_id
        WHERE p.id = m.parent_project_id AND ca.subject = $3
     )
   )`, t.Mirror, t.Projects, t.Accounts, t.Bindings, t.BindingSubjects,
		t.Selectors, t.RoleVerbs, t.AccountAdmins, t.ClusterAdmins)
}

// Allowed отвечает на вопрос о доступе для ЦЕЛОЙ страницы идентификаторов ОДНИМ
// запросом.
//
// Пообъектный обход здесь не предусмотрен вовсе — и это не оптимизация, а
// требование к сужателю: страница продукта до тысячи объектов, и форма, которая
// платит за неё транзакцией на объект, измеряла бы не себя, а свой способ
// вызова. Одиночная проверка — та же функция на массиве из одного элемента, то
// есть один и тот же код на обеих полосах чтения.
func (v RelationalVerdict) Allowed(ctx context.Context, subject, verb, objectType string,
	objectIDs []string) (map[string]bool, error) {
	out := make(map[string]bool, len(objectIDs))
	for _, id := range objectIDs {
		out[id] = false
	}
	rows, err := v.Src.Query(ctx, v.allowedSQL(), objectType, objectIDs, subject, verb)
	if err != nil {
		return nil, fmt.Errorf("вердикт формы E: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("вердикт формы E, разбор строки: %w", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("вердикт формы E, чтение результата: %w", err)
	}
	return out, nil
}

// splitObject разбирает `тип:идентификатор` — форму, в которой объекты названы в
// общем словаре намерения.
func splitObject(obj string) (objectType, objectID string, err error) {
	i := strings.IndexByte(obj, ':')
	if i <= 0 || i == len(obj)-1 {
		return "", "", fmt.Errorf("объект %q не в форме тип:идентификатор", obj)
	}
	return obj[:i], obj[i+1:], nil
}
