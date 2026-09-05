// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package planrows_test

// fixtures_test.go — планы, на которых проверяется САМ ПРИБОР.
//
// Форма фикстур снята с настоящих планов запроса вердикта (замеры 0.2а приёмки
// R7-1, ревизия cc5919348), а не придумана: имена полей — те, что печатает
// Postgres, а числа — те, на которых наблюдался каждый из разобранных классов.
// Фикстура, снисходительнее продукта, прячет ровно тот дефект, ради которого её
// заводят, поэтому здесь воспроизводятся ИМЕННО наблюдавшиеся формы:
//
//   - `WorkTable Scan` и `Index Scan resource_parent_edge` идут с `loops = 2`
//     (рекурсивный обход) — без множителя их вклад занижается вдвое;
//   - `Bitmap Index Scan` несёт ТОЛЬКО `Index Name`, а `Relation Name` — его
//     пара `Bitmap Heap Scan`; наивная сумма листьев задваивает отношение
//     (наблюдалось 4 против 2 на `role_rule_selectors`);
//   - `group_members` даёт ДВА `Index Scan`, и это НЕ дубль, а две ветви `UNION`
//     внутри CTE `speaker` — схлопывание по имени потеряло бы настоящий доступ;
//   - отброшенное соединением живёт на `Nested Loop`, у которого `Relation Name`
//     нет вовсе;
//   - `Heap Fetches` на широкой оси равен 1.

// fullPlan — план, несущий все разобранные формы сразу.
//
// Отнесённая сумма считается так (и это ровно то, что утверждают пробы):
//
//	role_rule_selectors   Bitmap Heap Scan            2 × 1 =  2
//	                      Bitmap Index Scan (пара)     не входит
//	group_members         Index Scan (ветвь UNION 1)   1 × 1 =  1
//	group_members         Index Scan (ветвь UNION 2)   1 × 1 =  1
//	resource_parent_edge  Index Scan                   2 × 2 =  4
//	access_bindings       Index Only Scan              3 × 1 =  3
//	relation_fact         Seq Scan                     5 × 1 =  5
//	                                                   ИТОГО  = 16
//
// Не отнесено: Limit, Sort, Nested Loop, CTE Scan, WorkTable Scan, Result — шесть
// узлов, 1 + 1 + 3 + 7 + (1 × 2) + 1 = 15 строк.
//
// Отброшено: фильтр 20 на `relation_fact`, перепроверка 3 на `role_rule_selectors`
// (потерявший точность bitmap — то, что Postgres печатает здесь на самом деле),
// соединение 12 на `Nested Loop`. Итого 35, и все три слагаемых видны порознь.
const fullPlan = `[
  {
    "Plan": {
      "Node Type": "Limit",
      "Actual Rows": 1, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "Sort",
          "Sort Key": ["condition_name"],
          "Actual Rows": 1, "Actual Loops": 1,
          "Plans": [
            {
              "Node Type": "Nested Loop",
              "Join Type": "Inner",
              "Actual Rows": 3, "Actual Loops": 1,
              "Rows Removed by Join Filter": 12,
              "Plans": [
                {
                  "Node Type": "CTE Scan",
                  "CTE Name": "scope",
                  "Actual Rows": 7, "Actual Loops": 1
                },
                {
                  "Node Type": "Bitmap Heap Scan",
                  "Relation Name": "role_rule_selectors",
                  "Alias": "rrs",
                  "Actual Rows": 2, "Actual Loops": 1,
                  "Rows Removed by Index Recheck": 3,
                  "Plans": [
                    {
                      "Node Type": "Bitmap Index Scan",
                      "Index Name": "role_rule_selectors_by_role",
                      "Actual Rows": 2, "Actual Loops": 1
                    }
                  ]
                },
                {
                  "Node Type": "Index Scan",
                  "Relation Name": "group_members",
                  "Index Name": "group_members_pkey",
                  "Alias": "gm",
                  "Actual Rows": 1, "Actual Loops": 1
                },
                {
                  "Node Type": "Index Scan",
                  "Relation Name": "group_members",
                  "Index Name": "group_members_pkey",
                  "Alias": "gm_1",
                  "Actual Rows": 1, "Actual Loops": 1
                },
                {
                  "Node Type": "Result",
                  "Actual Rows": 1, "Actual Loops": 1,
                  "Plans": [
                    {
                      "Node Type": "WorkTable Scan",
                      "CTE Name": "scope",
                      "Actual Rows": 1, "Actual Loops": 2
                    },
                    {
                      "Node Type": "Index Scan",
                      "Relation Name": "resource_parent_edge",
                      "Index Name": "resource_parent_edge_pkey",
                      "Alias": "e",
                      "Actual Rows": 2, "Actual Loops": 2
                    }
                  ]
                },
                {
                  "Node Type": "Index Only Scan",
                  "Relation Name": "access_bindings",
                  "Index Name": "access_bindings_by_scope",
                  "Alias": "ab",
                  "Actual Rows": 3, "Actual Loops": 1,
                  "Heap Fetches": 1
                },
                {
                  "Node Type": "Seq Scan",
                  "Relation Name": "relation_fact",
                  "Alias": "rf",
                  "Actual Rows": 5, "Actual Loops": 1,
                  "Rows Removed by Filter": 20
                }
              ]
            }
          ]
        }
      ]
    }
  }
]`

// loopsOnePlan — тот же план, у которого рекурсивная пара идёт с `loops = 1`.
//
// Отрицательное плечо пробы множителя: величина обязана СОВПАСТЬ с суммой без
// множителя, иначе множитель применяется не там, где циклы, а всегда.
const loopsOnePlan = `[
  {
    "Plan": {
      "Node Type": "Result",
      "Actual Rows": 1, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "WorkTable Scan",
          "CTE Name": "scope",
          "Actual Rows": 1, "Actual Loops": 1
        },
        {
          "Node Type": "Index Scan",
          "Relation Name": "resource_parent_edge",
          "Index Name": "resource_parent_edge_pkey",
          "Actual Rows": 2, "Actual Loops": 1
        }
      ]
    }
  }
]`

// loopsTwoPlan — он же с наблюдавшимся `loops = 2` на обоих узлах.
const loopsTwoPlan = `[
  {
    "Plan": {
      "Node Type": "Result",
      "Actual Rows": 1, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "WorkTable Scan",
          "CTE Name": "scope",
          "Actual Rows": 1, "Actual Loops": 2
        },
        {
          "Node Type": "Index Scan",
          "Relation Name": "resource_parent_edge",
          "Index Name": "resource_parent_edge_pkey",
          "Actual Rows": 2, "Actual Loops": 2
        }
      ]
    }
  }
]`

// dictionaryPlan — `Bitmap Index Scan` БЕЗ предка `Bitmap Heap Scan`.
//
// Оборонительная ветвь разрешения индекса: родства нет, поэтому отношение берётся
// из справочника «индекс → отношение», собранного ИЗ ЭТОГО ЖЕ плана по узлу,
// который несёт оба ключа. Справочник выводится из плана, а не выписан в коде
// прибора: выписанный не двигается от нового отношения в запросе и продолжает
// печатать нули по своим.
const dictionaryPlan = `[
  {
    "Plan": {
      "Node Type": "Nested Loop",
      "Actual Rows": 1, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "Index Scan",
          "Relation Name": "access_bindings",
          "Index Name": "access_bindings_by_scope",
          "Actual Rows": 4, "Actual Loops": 1
        },
        {
          "Node Type": "Bitmap Index Scan",
          "Index Name": "access_bindings_by_scope",
          "Actual Rows": 6, "Actual Loops": 1
        }
      ]
    }
  }
]`

// neitherKeyPlan — узел без обоих ключей рядом с законным отношением.
//
// Положительный контроль стоит В ТОЙ ЖЕ фикстуре: без него «не отнесено 1» было
// бы неотличимо от «прибор не отнёс ничего».
const neitherKeyPlan = `[
  {
    "Plan": {
      "Node Type": "Nested Loop",
      "Actual Rows": 9, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "Function Scan",
          "Function Name": "unnest",
          "Actual Rows": 3, "Actual Loops": 1
        },
        {
          "Node Type": "Seq Scan",
          "Relation Name": "relation_fact",
          "Actual Rows": 5, "Actual Loops": 1
        }
      ]
    }
  }
]`

// unknownTypePlan — узел с типом, которого в словаре прибора нет.
//
// «Custom Scan» здесь не выдумка: его печатает любое расширение, добавляющее свой
// узел. Предмет пробы не в самом типе, а в том, что незнакомое обязано попасть в
// корзину С ЧИСЛОМ, а не выпасть из суммы молча.
const unknownTypePlan = `[
  {
    "Plan": {
      "Node Type": "Nested Loop",
      "Actual Rows": 2, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "Custom Scan",
          "Custom Plan Provider": "нечто",
          "Actual Rows": 11, "Actual Loops": 1
        },
        {
          "Node Type": "Seq Scan",
          "Relation Name": "relation_fact",
          "Actual Rows": 5, "Actual Loops": 1
        }
      ]
    }
  }
]`

// gatherPlan — принудительный параллельный план.
//
// Узел назван «Seq Scan» с признаком `Parallel Aware`, а не «Parallel Seq Scan»:
// приставку печатает ТЕКСТОВЫЙ вывод EXPLAIN, а в JSON её нет. Фикстура, взявшая
// текстовое написание, разошлась бы с продуктом молча — и разошлась бы именно
// там, где план параллельный, то есть где занижение и живёт.
//
// Наблюдался ТОЛЬКО принудительным прогоном: на естественном плане `Gather` не
// появился ни разу, включая N = 10⁵. Держится проба ради будущего — плана,
// перевернувшегося на прогонный по большой таблице; утверждение о множителе на
// НЕЁ не опирается (см. loopsTwoPlan) именно потому, что она сегодня вырождена.
const gatherPlan = `[
  {
    "Plan": {
      "Node Type": "Gather",
      "Workers Planned": 2,
      "Workers Launched": 2,
      "Actual Rows": 12, "Actual Loops": 1,
      "Plans": [
        {
          "Node Type": "Seq Scan",
          "Parallel Aware": true,
          "Relation Name": "relation_fact",
          "Actual Rows": 4, "Actual Loops": 3
        }
      ]
    }
  }
]`

// singleScanPlan — план, в котором отнесено ВСЁ.
//
// Нужен ровно затем, чтобы перепись печаталась и в случае «не отнесено 0»: проба,
// падающая на достижении своей цели, толкает держать неотнесённый узел ради
// зелёного.
const singleScanPlan = `[
  {
    "Plan": {
      "Node Type": "Seq Scan",
      "Relation Name": "relation_fact",
      "Alias": "rf",
      "Actual Rows": 5, "Actual Loops": 1
    }
  }
]`
