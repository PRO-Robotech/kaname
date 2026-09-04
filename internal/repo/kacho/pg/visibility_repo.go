// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// visibility_repo.go — pgx implementation of visibility.ReaderIface: the
// structural facts of ONE caller, resolved in ONE statement.
//
// Read the port's doc first (internal/repo/kacho/visibility). The two decisions
// worth restating where the SQL lives:
//
//   - every judgement is resolved TOWARDS INCLUSION. A REVOKED binding is the
//     only one dropped; PENDING counts, expired counts, a wildcard scope counts.
//     The set is a superset of the visible on purpose — the model decides, this
//     query only selects candidates;
//   - the type name is read in BOTH dictionaries. `access_bindings.resource_type`
//     speaks the model's ("project"), while a row that came through the resource
//     mirror may speak the catalog's ("iam.project"). A join that matched only one
//     spelling would never match the other, and would do so silently — the same
//     class migration 0091 fixed for the scope chain.
//
// # Сведение двух словарей — ПЕРЕВОДОМ У ВЛАДЕЛЬЦА, а не разбором строки (#2003)
//
// Здесь стояло ОТРЕЗАНИЕ последнего сегмента после точки, и оно переводом не
// является: правило «отрезать» не следует ни из чего. Совпадало оно с переводом
// у ДВУХ типов из семи (`iam.account` → `account`, `iam.project` → `project`) —
// и ровно этими двумя проверяют «работает ли вообще», поэтому промах на
// остальных пяти был тихим. Замер по закрытой таблице: отрезание даёт верное имя
// у 2 точечных ключей из 27.
//
// Вывести имя типа из пары «модуль.ресурс» нельзя НИ ОДНИМ выражением, и это не
// оценка, а объявленный факт дерева: правило `objectType ← <module>_<resource>`
// снято целиком (миграция `catalog_resource_carries_the_model_type`), потому что
// у `storage`/`registry` имя ресурса множественное при единственном типе
// (`storage.volumes` → `storage_volume`), а у ярусных предков тип идёт вовсе без
// приставки модуля (`iam.account` → `account`). Имя обязано ПРИЕХАТЬ строкой
// манифеста — и приезжает: колонкой `catalog_resource.object_type`.
//
// Отсюда перевод стоит В ЗАПРОСЕ, а не в Go:
//
//	точки НЕТ  → это уже словарь модели → тождество. Пересечения у словарей нет
//	             by construction (CHECK `access_bindings_resource_ck` не пускает
//	             точку в колонку выдачи), поэтому другого прочтения не существует;
//	точка ЕСТЬ → это словарь каталога → имя берётся у ЖИВОЙ СТРОКИ, тем же
//	             оператором и в том же снимке, что и чтение кандидатов.
//
// Это ТОТ ЖЕ ход, каким переведён производитель зеркала (#1982,
// `resource_mirror/model_dictionary.go`), и то же его обоснование. Разница одна:
// там перевод — условие ЗАПИСИ, и промах обязан быть громким отказом; здесь это
// путь ЧТЕНИЯ, где отказывать не на чем — непереводимый точечный ключ остаётся
// собой и попадает под имя, которого не спрашивает ни один вызывающий. То есть
// сужает, а не открывает: выдумать имя было бы хуже промаха.
//
// ЛИВНОСТЬ НЕ СПРАШИВАЕТСЯ, и это решение, а не упущение — то же, что у
// производителя: тип, снятый с платформы ПОСЛЕ выдачи, обязан продолжать
// резолвиться, иначе уже выданное тихо перестало бы попадать в кандидаты при
// живой строке выдачи. Снятие типа мягкое (`live = false`, строка остаётся),
// поэтому промах перевода означает тип, которого у платформы не было НИКОГДА.
//
// Перевод одним оператором сохраняет и то, ради чего памятка вообще заведена:
// один проход независимо от числа дозаполнений страницы. Строка каталога
// однозначна by construction — PK (module, resource) плюс CHECK
// `dotted = module || '.' || resource` при бесточечном модуле, — поэтому левое
// соединение не может размножить строку выдачи.

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/visibility"
)

// visibilityReader — visibility.ReaderIface over pgx.Tx, so the memo shares the
// snapshot of the page reads it feeds.
type visibilityReader struct {
	tx pgx.Tx
}

// scopeOfQuery returns two kinds of row:
//
//	('own',   '',      <account id>)  — the subject owns this account
//	('grant', <type>,  <object id>)   — a grant of his names this object
//
// One statement, so the memo is one round-trip regardless of how many refills
// the page later needs.
const scopeOfQuery = `
WITH grp AS (
    SELECT gm.group_id
      FROM kacho_iam.group_members gm
     WHERE gm.member_type = $1 AND gm.member_id = $2
),
bnd AS (
    SELECT ab.id, ab.resource_type, ab.resource_id
      FROM kacho_iam.access_bindings ab
     WHERE ab.status <> 'REVOKED'
       AND EXISTS (
             SELECT 1
               FROM kacho_iam.access_binding_subjects s
              WHERE s.binding_id = ab.id
                AND ( (s.subject_type = $1 AND s.subject_id = $2)
                   OR (s.subject_type = 'group'
                       AND s.subject_id IN (SELECT group_id FROM grp)) )
       )
),
tgt AS (
    -- Область выдачи названа ДВУМЯ таблицами, и обе читаются: колонки
    -- resource_type/resource_id самой выдачи — область, названная поимённо, а
    -- access_binding_target_members — то, что дал разбор выборки по меткам.
    -- Взять одну значило бы потерять весь второй вид выдач у того, кто ходит
    -- только им.
    SELECT b.resource_type AS otype, b.resource_id AS oid FROM bnd b
    UNION
    SELECT m.object_type, m.object_id
      FROM kacho_iam.access_binding_target_members m
      JOIN bnd b ON b.id = m.binding_id
)
SELECT 'own'::text AS kind, ''::text AS otype, a.id AS oid
  FROM kacho_iam.accounts a
 WHERE $1 = 'user' AND a.owner_user_id = $2
UNION ALL
-- Имя типа приводится к словарю МОДЕЛИ переводом у владельца словаря: точечный
-- ключ каталога резолвится живой строкой, бесточечный — уже модельный и остаётся
-- собой (соединение по нему не совпадает никогда: колонка dotted точку несёт
-- всегда). Непереводимый точечный ключ остаётся собой ОСОЗНАННО — см. шапку файла.
SELECT 'grant'::text, COALESCE(cr.object_type, t.otype), t.oid
  FROM tgt t
  LEFT JOIN kacho_iam.catalog_resource cr ON cr.dotted = t.otype`

func (r *visibilityReader) ScopeOf(ctx context.Context, s visibility.Subject) (visibility.Scope, error) {
	out := visibility.Scope{GrantedObjects: map[string][]string{}}
	// An unnamed subject reaches nothing. Asked rather than assumed, because the
	// zero Scope has to mean "no candidates" and not "everything".
	if s.Type == "" || s.ID == "" {
		return out, nil
	}

	rows, err := r.tx.Query(ctx, scopeOfQuery, s.Type, s.ID)
	if err != nil {
		return visibility.Scope{}, mapErr(err, "", "")
	}
	defer rows.Close()

	scoped := map[string]struct{}{}
	for rows.Next() {
		var kind, otype, oid string
		if err := rows.Scan(&kind, &otype, &oid); err != nil {
			return visibility.Scope{}, mapErr(err, "", "")
		}
		if oid == "" {
			continue
		}
		if kind == "own" {
			out.OwnedAccounts = append(out.OwnedAccounts, oid)
			scoped[oid] = struct{}{}
			continue
		}
		// Имя уже названо словарём модели: перевод сделан запросом, у владельца
		// словаря. Второго перевода здесь не заводится — он и был снятым дефектом.
		switch t := otype; {
		case t == "" || t == "*" || t == "cluster" || oid == "*":
			// A cluster-scoped or wildcard grant reaches every row; narrowing by
			// account or id would then be narrower than the model.
			out.Unrestricted = true
		case t == "account":
			scoped[oid] = struct{}{}
		default:
			out.GrantedObjects[t] = append(out.GrantedObjects[t], oid)
		}
	}
	if err := rows.Err(); err != nil {
		return visibility.Scope{}, mapErr(err, "", "")
	}

	out.ScopedAccounts = make([]string, 0, len(scoped))
	for id := range scoped {
		out.ScopedAccounts = append(out.ScopedAccounts, id)
	}
	return out, nil
}

var _ visibility.ReaderIface = (*visibilityReader)(nil)
