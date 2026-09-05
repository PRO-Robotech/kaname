// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Форма E на ПОЛНОЙ модели: та же идея, что у измеренной в XC-10 (вердикт —
// запрос поверх зеркала, состав не материализован), но выражение вердикта
// СОБИРАЕТСЯ из разбора канонической модели, а не выписано под один тип.
//
// # Почему это отдельное хранилище, а не правка измеренного
//
// Измеренная форма E (`relational.go`) несёт ОДНО выражение вердикта на один тип
// с тремя источниками. Переписать её под полную модель значило бы сдвинуть числа
// XC-10 — и отчёт, уже принятый как база сравнения, перестал бы описывать то, что
// в дереве. Поэтому полномодельная форма живёт рядом, а связь между ними
// удерживается пробой: на сценарии XC-10 обе обязаны отвечать одинаково
// (`TestNarrowAndFullFormEAgreeOnTheBenchScenario`). Две реализации одного
// предмета расходятся молча — эта не сможет.
//
// # Что здесь появляется сверх измеренной формы
//
//   - цепь родительства ПРОИЗВОЛЬНОЙ формы (объект → реестр → проект → аккаунт →
//     кластер), а не «объект → проект»: типы модели привязаны по-разному, и
//     привязанный к кластеру не принадлежит ни одному арендатору;
//   - строки фактов: владелец аккаунта, владелец объекта, администратор,
//     подстановочное публичное чтение — источники, которых у фикстуры XC-10 не
//     было вовсе;
//   - членство в группе, в том числе вложенной;
//   - глагол, выводимый от другого глагола (`v_addtargets` от `v_update`).

// fullRelSchemaDDL — схема формы E под полную модель.
//
// Индексы названы поимённо и заведены под КАЖДЫЙ запрос, который схема
// обслуживает: без них замер и проба мерили бы невнимательность автора. Сверх
// этого ничего не заведено.
const fullRelSchemaDDL = `
CREATE TABLE mirror (
    object_type text  NOT NULL,
    object_id   text  NOT NULL,
    labels      jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (object_type, object_id)
);
CREATE INDEX mirror_labels_idx ON mirror USING gin (labels);

CREATE TABLE edges (
    object_type text NOT NULL,
    object_id   text NOT NULL,
    pointer     text NOT NULL,
    parent_type text NOT NULL,
    parent_id   text NOT NULL,
    PRIMARY KEY (object_type, object_id, pointer, parent_type, parent_id)
);
CREATE INDEX edges_parent_idx ON edges (parent_type, parent_id);

CREATE TABLE relation_facts (
    object_type text NOT NULL,
    object_id   text NOT NULL,
    relation    text NOT NULL,
    subject     text NOT NULL,
    PRIMARY KEY (object_type, object_id, relation, subject)
);
CREATE INDEX relation_facts_subject_idx ON relation_facts (subject, relation);

CREATE TABLE bindings (
    id         text PRIMARY KEY,
    scope_type text NOT NULL,
    scope_id   text NOT NULL,
    role       text NOT NULL
);
CREATE INDEX bindings_scope_idx ON bindings (scope_type, scope_id);

CREATE TABLE binding_subjects (
    binding_id text NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
    subject    text NOT NULL,
    PRIMARY KEY (binding_id, subject)
);
CREATE INDEX binding_subjects_subject_idx ON binding_subjects (subject);

CREATE TABLE binding_selectors (
    binding_id  text  NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
    object_type text  NOT NULL,
    labels      jsonb NOT NULL,
    PRIMARY KEY (binding_id, object_type)
);

CREATE TABLE role_verbs (
    role text NOT NULL,
    verb text NOT NULL,
    PRIMARY KEY (role, verb)
);
`

// identRe — то, что вправе попасть в текст запроса как имя отношения или тип.
//
// Имена приходят из разобранного файла репозитория, а не от пользователя, и
// всё-таки проверяются: «оно и так безопасно» живёт ровно до первого имени,
// которое таковым не окажется, а замечено это будет не здесь.
var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// fullRelStore — форма E над полной моделью.
type fullRelStore struct {
	pool   *pgxpool.Pool
	schema string
	model  *Model
	plans  map[string]Plan

	// mutate — правка плана ПЕРЕД сборкой запроса. Заполняется только пробой
	// инъекции: гейт обязан быть показан способным упасть, а показать это можно
	// только сняв у него предмет. В обычном прогоне поле пусто.
	mutate func(Plan) Plan

	// weaken — снятие ОДНОГО конъюнкта запроса, тоже только для пробы инъекции.
	//
	// Снятие атома целиком — грубая инъекция: она доказывает, что источник
	// спрашивают, но не что спрашивают его ПРАВИЛЬНО. Дефект, на котором был
	// отвергнут первый заход XC-10, лежал именно внутри атома выдачи: условие
	// области было тождественно истинным на одноарендной фикстуре. Поэтому
	// конъюнкты снимаются поимённо и по одному.
	weaken weakening
}

// weakening — какой конъюнкт снят. Пустое значение означает «ничего не снято».
type weakening string

const (
	weakenNothing      weakening = ""
	weakenScope        weakening = "область выдачи"
	weakenSelector     weakening = "правило-селектор по меткам"
	weakenGroupClosure weakening = "замыкание субъекта по группам"
	weakenParentDepth  weakening = "различение предка и самого объекта"
)

// newFullRelStore поднимает схему и компилирует план КАЖДОГО отношения КАЖДОГО
// типа заранее.
//
// Заранее — потому что невыразимое обязано быть названо ДО того, как задан хоть
// один вопрос: план, скомпилированный по требованию, дал бы «невыразимо» вперемешку
// с ответами, и отчёт не смог бы отличить «спросили и разошлись» от «не спросили».
func newFullRelStore(ctx context.Context, dsn, schema string, m *Model) (*fullRelStore, error) {
	if !identRe.MatchString(strings.ReplaceAll(schema, "-", "_")) {
		return nil, fmt.Errorf("имя схемы %q не годится в идентификатор", schema)
	}
	boot, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("подключение к БД формы E: %w", err)
	}
	defer boot.Close()
	if _, err := boot.Exec(ctx, `CREATE SCHEMA `+quoteIdent(schema)); err != nil {
		return nil, fmt.Errorf("создание схемы %s: %w", schema, err)
	}
	if _, err := boot.Exec(ctx, `SET search_path TO `+quoteIdent(schema)+`; `+fullRelSchemaDDL); err != nil {
		return nil, fmt.Errorf("схема формы E (полная модель): %w", err)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("пул формы E (полная модель): %w", err)
	}

	st := &fullRelStore{pool: pool, schema: schema, model: m, plans: map[string]Plan{}}
	for _, t := range m.Types {
		for _, r := range t.Relations {
			p, cerr := m.Compile(t.Name, r.Name)
			if cerr != nil {
				pool.Close()
				return nil, fmt.Errorf("компиляция %s.%s: %w", t.Name, r.Name, cerr)
			}
			st.plans[t.Name+"."+r.Name] = p
		}
	}
	return st, nil
}

// Plan возвращает скомпилированный план отношения.
func (s *fullRelStore) Plan(typeName, relation string) (Plan, bool) {
	p, ok := s.plans[typeName+"."+relation]
	return p, ok
}

// Close сносит схему явно: брошенная схема попала бы в чужой замер объёма.
func (s *fullRelStore) Close(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+quoteIdent(s.schema)+` CASCADE`)
	s.pool.Close()
	return err
}

// Seed кладёт мир в схему формы E.
func (s *fullRelStore) Seed(ctx context.Context, rows relRows) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	exec := func(sql string, argsets [][]any) error {
		for _, a := range argsets {
			if _, err := tx.Exec(ctx, sql, a...); err != nil {
				return fmt.Errorf("%s: %w", strings.SplitN(strings.TrimSpace(sql), " ", 3)[2], err)
			}
		}
		return nil
	}
	if err := exec(`INSERT INTO mirror (object_type, object_id, labels) VALUES ($1,$2,$3::jsonb)`,
		toArgs3(rows.Mirror)); err != nil {
		return err
	}
	if err := exec(`INSERT INTO edges (object_type, object_id, pointer, parent_type, parent_id)
	                VALUES ($1,$2,$3,$4,$5)`, toArgs5(rows.Edges)); err != nil {
		return err
	}
	if err := exec(`INSERT INTO relation_facts (object_type, object_id, relation, subject)
	                VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, toArgs4(rows.Facts)); err != nil {
		return err
	}
	if err := exec(`INSERT INTO bindings (id, scope_type, scope_id, role) VALUES ($1,$2,$3,$4)`,
		toArgs4(rows.Bindings)); err != nil {
		return err
	}
	if err := exec(`INSERT INTO binding_subjects (binding_id, subject) VALUES ($1,$2)`,
		toArgs2(rows.BindSubj)); err != nil {
		return err
	}
	if err := exec(`INSERT INTO binding_selectors (binding_id, object_type, labels) VALUES ($1,$2,$3::jsonb)`,
		toArgs3(rows.Selectors)); err != nil {
		return err
	}
	if err := exec(`INSERT INTO role_verbs (role, verb) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		toArgs2(rows.RoleVerbs)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func toArgs2(in [][2]string) [][]any {
	out := make([][]any, 0, len(in))
	for _, r := range in {
		out = append(out, []any{r[0], r[1]})
	}
	return out
}

func toArgs3(in [][3]string) [][]any {
	out := make([][]any, 0, len(in))
	for _, r := range in {
		out = append(out, []any{r[0], r[1], r[2]})
	}
	return out
}

func toArgs4(in [][4]string) [][]any {
	out := make([][]any, 0, len(in))
	for _, r := range in {
		out = append(out, []any{r[0], r[1], r[2], r[3]})
	}
	return out
}

func toArgs5(in [][5]string) [][]any {
	out := make([][]any, 0, len(in))
	for _, r := range in {
		out = append(out, []any{r[0], r[1], r[2], r[3], r[4]})
	}
	return out
}

// ── вердикт ───────────────────────────────────────────────────────────────────

// ErrPlanNotExpressible — у отношения нет выражения в форме E целиком.
//
// Это НЕ отказ в доступе и не сбой: третий исход, который обязан быть отличим от
// обоих. Свернуть его в «запрещено» значило бы напечатать совпадение там, где
// вопрос не задавался, — и именно так невыразимая часть модели стала бы
// невидимой.
var ErrPlanNotExpressible = fmt.Errorf("отношение не выражается в схеме формы E целиком")

// Allowed отвечает на вопрос о доступе для целой страницы идентификаторов ОДНИМ
// запросом, собранным из скомпилированного плана.
func (s *fullRelStore) Allowed(ctx context.Context, subject, relation, objectType string,
	objectIDs []string) (map[string]bool, error) {
	p, ok := s.Plan(objectType, relation)
	if !ok {
		return nil, fmt.Errorf("плана для %s.%s нет — отношение не объявлено", objectType, relation)
	}
	if s.mutate != nil {
		p = s.mutate(p)
	}
	if !p.Expressible() {
		return nil, fmt.Errorf("%w: %s.%s — %s", ErrPlanNotExpressible, objectType, relation,
			strings.Join(p.Unclassified, "; "))
	}
	sql, err := s.planSQL(p)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(objectIDs))
	for _, id := range objectIDs {
		out[id] = false
	}
	rows, err := s.pool.Query(ctx, sql, subjectSeeds(subject), objectType, objectIDs)
	if err != nil {
		return nil, fmt.Errorf("вердикт формы E (%s.%s): %w", objectType, relation, err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// planSQL собирает запрос из атомов плана.
//
// Пустая дизъюнкция — ОШИБКА, а не «никому нельзя»: план без единого источника
// означает, что компиляция ничего не поняла, и тихий отказ на каждый вопрос
// совпал бы с движком на всей отрицательной половине вопросника.
func (s *fullRelStore) planSQL(p Plan) (string, error) {
	if len(p.Atoms) == 0 {
		return "", fmt.Errorf("план %s.%s пуст — ни одного источника разрешения", p.Type, p.Relation)
	}
	var terms []string
	for _, a := range p.Atoms {
		switch a.Kind {
		case AtomBinding:
			if !identRe.MatchString(a.Relation) {
				return "", fmt.Errorf("глагол %q не годится в идентификатор", a.Relation)
			}
			labels := "AND m.labels @> sel.labels"
			if s.weaken == weakenSelector {
				labels = ""
			}
			scope := `AND EXISTS (SELECT 1 FROM anc
                             WHERE anc.o_type = m.object_type AND anc.o_id = m.object_id
                               AND anc.a_type = b.scope_type AND anc.a_id = b.scope_id)`
			if s.weaken == weakenScope {
				scope = ""
			}
			terms = append(terms, fmt.Sprintf(`
     EXISTS (SELECT 1
               FROM bindings b
               JOIN role_verbs rv ON rv.role = b.role AND rv.verb = '%s'
               JOIN binding_selectors sel ON sel.binding_id = b.id AND sel.object_type = m.object_type
               JOIN binding_subjects bs ON bs.binding_id = b.id
              WHERE bs.subject IN (SELECT id FROM subj)
                %s
                %s)`, a.Relation, labels, scope))
		case AtomFact:
			if !identRe.MatchString(a.Relation) {
				return "", fmt.Errorf("отношение %q не годится в идентификатор", a.Relation)
			}
			if a.ParentType == "" {
				terms = append(terms, fmt.Sprintf(`
     EXISTS (SELECT 1 FROM relation_facts f
              WHERE f.object_type = m.object_type AND f.object_id = m.object_id
                AND f.relation = '%s' AND f.subject IN (SELECT id FROM subj))`, a.Relation))
				continue
			}
			if !identRe.MatchString(a.ParentType) {
				return "", fmt.Errorf("тип предка %q не годится в идентификатор", a.ParentType)
			}
			depthGuard := "AND a.depth > 0"
			if s.weaken == weakenParentDepth {
				depthGuard = ""
			}
			terms = append(terms, fmt.Sprintf(`
     EXISTS (SELECT 1 FROM anc a
               JOIN relation_facts f ON f.object_type = a.a_type AND f.object_id = a.a_id
                                    AND f.relation = '%s'
              WHERE a.o_type = m.object_type AND a.o_id = m.object_id
                AND a.a_type = '%s' %s
                AND f.subject IN (SELECT id FROM subj))`, a.Relation, a.ParentType, depthGuard))
		default:
			return "", fmt.Errorf("план %s.%s несёт атом неизвестного вида", p.Type, p.Relation)
		}
	}

	// `subj` — субъект и всякое множество-подмножество (userset), в которое он
	// входит, транзитивно. Пары «тип#отношение», годные в субъекты, ВЫВЕДЕНЫ из
	// модели (`usersetPairs`), а не выписаны: сегодня это ровно `group#member`, и
	// появление второй пары не должно требовать правки этого файла.
	//
	// Обход рекурсивный, а не в один уровень: модель ДОПУСКАЕТ вложенность
	// (`group.member` принимает `group#member`), и обход в один уровень отвечал бы
	// верно на всякой фикстуре без вложенности и молча неверно на первой же с ней.
	//
	// `anc` — объект и его предки. Глубина ограничена и объявлена: цепь
	// родительства в этой модели конечна, а неограниченный обход по данным,
	// которые пишет другой сервис, — это ожидание, что данные всегда правильны.
	pairs := usersetPairsSQL(s.model)
	closure := `
  UNION
    SELECT f.object_type || ':' || f.object_id || '#' || f.relation
      FROM relation_facts f JOIN subj ON f.subject = subj.id
     WHERE (f.object_type || '#' || f.relation) IN (` + pairs + `)`
	if s.weaken == weakenGroupClosure {
		closure = ""
	}
	return fmt.Sprintf(`
WITH RECURSIVE
subj(id) AS (
    SELECT * FROM unnest($1::text[])%s
),
anc(o_type, o_id, a_type, a_id, depth) AS (
    SELECT m.object_type, m.object_id, m.object_type, m.object_id, 0
      FROM mirror m WHERE m.object_type = $2 AND m.object_id = ANY($3::text[])
  UNION
    SELECT anc.o_type, anc.o_id, e.parent_type, e.parent_id, anc.depth + 1
      FROM anc JOIN edges e ON e.object_type = anc.a_type AND e.object_id = anc.a_id
     WHERE anc.depth < %d
)
SELECT DISTINCT m.object_id
  FROM mirror m
 WHERE m.object_type = $2 AND m.object_id = ANY($3::text[])
   AND (%s
   )`, closure, MaxPointerDepth+2, strings.Join(terms, "\n     OR")), nil
}

// usersetPairsSQL — перечень пар «тип#отношение», которые модель принимает в
// субъекты, в виде списка литералов для `IN`.
//
// Пустой перечень означал бы, что множеств-подмножеств в модели нет, и замыкание
// субъекта выродилось бы в него самого. Это законно, но обязано быть выражено
// заведомо ложным литералом, а не пустыми скобками: пустой `IN ()` — синтаксическая
// ошибка, и запрос упал бы не там, где причина.
func usersetPairsSQL(m *Model) string {
	seen := map[string]bool{}
	var out []string
	for _, t := range m.Types {
		for _, r := range t.Relations {
			for _, term := range r.Terms {
				if term.Kind != TermDirect {
					continue
				}
				for _, d := range term.Direct {
					if d.Userset == "" || seen[d.Type+"#"+d.Userset] {
						continue
					}
					seen[d.Type+"#"+d.Userset] = true
					out = append(out, "'"+d.Type+"#"+d.Userset+"'")
				}
			}
		}
	}
	if len(out) == 0 {
		return "''"
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
