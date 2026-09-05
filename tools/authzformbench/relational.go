// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Форма E — реляционная: вердикт вычисляется ЗАПРОСОМ поверх того же зеркала
// объектов, что живёт у iam сегодня, без внешнего движка отношений.
//
// Устройство зеркала не выдумано здесь, а взято измеренным: одна таблица из семи
// колонок — тип объекта · идентификатор · родительский проект · родительский
// аккаунт · метки · версия источника · время правки. Ни имени, ни статуса, ни
// размещения в ней нет, поэтому запрос вправе спросить только про тип, метки и
// родителя — и ничего сверх этого здесь не спрашивается. Колонки, которых запрос
// не читает (версия источника, время правки), всё равно заведены: величина объёма
// обязана быть объёмом НАСТОЯЩЕЙ строки, а не подрезанной ради замера.
//
// Что здесь считается ВЫДАЧЕЙ (решение названо до первой строки этого файла):
// вставка строки привязки и её правила-селектора, и ничего больше. Разворота в
// материализованный состав нет by construction — состав вычисляется запросом на
// чтении. Значит операция «выдать» у двух форм мерит РАЗНЫЕ события, и это
// объявляется, а не усредняется.
//
// Что здесь считается СТРУКТУРНЫМ и в выдачу не входит: строки зеркала, цепь
// родительства (проект → аккаунт → кластер) и таблица «роль → глаголы». Всё это
// есть у формы одинаково с указателями родителя у движка и существует независимо
// от того, выдано ли кому-нибудь что-нибудь.

// benchLabel — метка, по которой объект входит в набор. Одна и та же и у
// правила-селектора привязки, и у строки зеркала: набор сужается меткой, как в
// продукте, а не перечислением идентификаторов.
var benchLabel = map[string]string{"authzformbench": "in-set"}

func benchLabelJSON() []byte {
	b, err := json.Marshal(benchLabel)
	if err != nil { // недостижимо: сериализуется константная карта строк
		panic(err)
	}
	return b
}

// relTables — имена таблиц формы E в её собственной схеме.
func relTables() TableNames {
	return TableNames{
		Mirror:          "resource_mirror",
		Projects:        "projects",
		Accounts:        "accounts",
		Bindings:        "access_bindings",
		BindingSubjects: "access_binding_subjects",
		Selectors:       "role_rule_selectors",
		RoleVerbs:       "role_verbs",
		AccountAdmins:   "account_admins",
		ClusterAdmins:   "cluster_admins",
	}
}

// relSchemaDDL — схема, спроектированная так, как её спроектировали бы в
// продукте: ключ у каждой строки, внешний ключ там, где ссылка живёт в той же
// БД, и индекс под КАЖДЫЙ запрос, который эта схема обслуживает.
//
// Индексы названы поимённо, потому что без них замер померил бы невнимательность
// автора, а не форму: `subject` — точка входа проверки; `labels` — предикат
// вхождения в набор (GIN, потому что спрашивается `@>`); оба родительских
// указателя — сцепка выдачи с областью; `account_id` проекта — звено каскада.
// Сверх этого ничего не заведено: схема, подогнанная под замер, — та же подгонка,
// что число, подобранное после прогона.
const relSchemaDDL = `
CREATE TABLE resource_mirror (
    object_type       text        NOT NULL,
    object_id         text        NOT NULL,
    parent_project_id text        NOT NULL,
    parent_account_id text        NOT NULL,
    labels            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    source_version    text        NOT NULL DEFAULT '',
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (object_type, object_id)
);
CREATE INDEX resource_mirror_project_idx ON resource_mirror (parent_project_id);
CREATE INDEX resource_mirror_account_idx ON resource_mirror (parent_account_id);
CREATE INDEX resource_mirror_labels_idx  ON resource_mirror USING gin (labels);

CREATE TABLE accounts (
    id         text PRIMARY KEY,
    cluster_id text NOT NULL
);

CREATE TABLE projects (
    id         text PRIMARY KEY,
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT
);
CREATE INDEX projects_account_idx ON projects (account_id);

CREATE TABLE access_bindings (
    id         text PRIMARY KEY,
    scope_type text NOT NULL CHECK (scope_type IN ('project', 'account')),
    scope_id   text NOT NULL,
    role       text NOT NULL
);
CREATE INDEX access_bindings_scope_idx ON access_bindings (scope_type, scope_id);

CREATE TABLE access_binding_subjects (
    binding_id text NOT NULL REFERENCES access_bindings(id) ON DELETE CASCADE,
    subject    text NOT NULL,
    PRIMARY KEY (binding_id, subject)
);
CREATE INDEX access_binding_subjects_subject_idx ON access_binding_subjects (subject);

CREATE TABLE role_rule_selectors (
    binding_id  text  NOT NULL REFERENCES access_bindings(id) ON DELETE CASCADE,
    object_type text  NOT NULL,
    labels      jsonb NOT NULL,
    PRIMARY KEY (binding_id, object_type)
);

CREATE TABLE role_verbs (
    role text NOT NULL,
    verb text NOT NULL,
    PRIMARY KEY (role, verb)
);

CREATE TABLE account_admins (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    subject    text NOT NULL,
    PRIMARY KEY (account_id, subject)
);
CREATE INDEX account_admins_subject_idx ON account_admins (subject);

CREATE TABLE cluster_admins (
    cluster_id text NOT NULL,
    subject    text NOT NULL,
    PRIMARY KEY (cluster_id, subject)
);
CREATE INDEX cluster_admins_subject_idx ON cluster_admins (subject);
`

// relGrantTables / relStructuralTables — разделение, от которого зависит колонка
// объёма. Строка выдачи исчезает вместе с выдачей; структурная — остаётся.
var (
	relGrantTables      = []string{"access_bindings", "access_binding_subjects", "role_rule_selectors"}
	relStructuralTables = []string{"resource_mirror", "projects", "accounts", "role_verbs",
		"account_admins", "cluster_admins"}
)

// relStore — одно хранилище прав формы E: своя схема в своей БД.
//
// Своя, а не датастор движка, по двум причинам сразу: иначе смешались бы объём
// (величина снимается по таблицам) и нагрузка (буферы, занятые миллионами
// кортежей движка, наказали бы чтение формы E за чужие данные).
type relStore struct {
	pool   *pgxpool.Pool
	tracer *stmtTracer
	schema string
	sc     Scenario
	prod   ProducerStatus
}

// Names/Query — реализация FactSource: тот же пул, та же трассировка.
func (r *relStore) Names() TableNames { return relTables() }

func (r *relStore) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return r.pool.Query(ctx, sql, args...)
}

func (r *relStore) verdict() RelationalVerdict { return RelationalVerdict{Src: r} }

// Place назван без имени схемы намеренно: схема у каждого хранилища своя, и
// печать одной из многих читалась бы как утверждение про все. Признак обязан
// различать МЕСТО (харнесс против пакета каскада) и СХЕМУ (синтетическая против
// мигрированной), а не экземпляр.
func (r *relStore) Place() string {
	return "services/iam/tools/authzformbench · своя БД формы E (синтетическая схема, своя на хранилище)"
}

func (r *relStore) StmtProducer() ProducerStatus { return r.prod }

func (r *relStore) Teardown(ctx context.Context) error {
	// Схема сносится ЯВНО, а не оставляется сборщику: величина объёма читается по
	// таблицам этой же БД, и брошенная схема попала бы в чужой замер.
	_, err := r.pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+quoteIdent(r.schema)+` CASCADE`)
	r.pool.Close()
	if err != nil {
		return fmt.Errorf("снос схемы %s: %w", r.schema, err)
	}
	return nil
}

// ── засев ─────────────────────────────────────────────────────────────────────

// Seed кладёт структурное состояние и, если попросили, выдачу.
//
// Структурные строки приходят тем же общим словарём, что у форм A–BCD: указатель
// «кластер → аккаунт» становится строкой аккаунта, «аккаунт → проект» — строкой
// проекта, «проект → объект» — строкой зеркала. Метки объектов набора кладутся
// здесь же, а не выдачей: зеркало наполняют ВЛАДЕЛЬЦЫ объектов, и оно существует
// независимо от того, выдано ли кому-нибудь право. Приписать метки выдаче значило
// бы назвать ценой выдачи чужую работу.
func (r *relStore) Seed(ctx context.Context, structural, grant []Tuple) (Counters, error) {
	w := r.tracer.open()
	err := r.seed(ctx, structural, grant)
	return Counters{StmtSQL: w.close()}, err
}

func (r *relStore) seed(ctx context.Context, structural, grant []Tuple) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начать транзакцию засева: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var accounts, projects []Tuple
	var mirror []Tuple
	for _, t := range structural {
		switch t.Relation {
		case "cluster":
			accounts = append(accounts, t)
		case "account":
			projects = append(projects, t)
		case "project":
			mirror = append(mirror, t)
		default:
			return fmt.Errorf("структурная строка с неизвестным отношением %q — общий словарь разошёлся", t.Relation)
		}
	}

	for _, t := range accounts {
		if _, err := tx.Exec(ctx, `INSERT INTO accounts (id, cluster_id) VALUES ($1, $2)`,
			t.Object, t.User); err != nil {
			return fmt.Errorf("аккаунт: %w", err)
		}
	}
	for _, t := range projects {
		if _, err := tx.Exec(ctx, `INSERT INTO projects (id, account_id) VALUES ($1, $2)`,
			t.Object, t.User); err != nil {
			return fmt.Errorf("проект: %w", err)
		}
	}

	// Зеркало кладётся ОДНИМ стейтментом на весь набор: строку на объект пишет
	// продукт пообъектно, но замер меряет форму, а не способ её вызова.
	// Метка строки зеркала — не только у объектов набора: помечен и объект чужого
	// арендатора. Иначе отказ на нём объяснялся бы селектором, и конъюнкт области
	// остался бы без единого утверждения о себе (см. Scenario.ForeignObject).
	labelled := r.sc.LabelledInMirror()
	var (
		types    []string
		ids      []string
		projIDs  []string
		labelSet []bool
	)
	for _, t := range mirror {
		ot, oid, err := splitObject(t.Object)
		if err != nil {
			return err
		}
		types = append(types, ot)
		ids = append(ids, oid)
		projIDs = append(projIDs, t.User)
		labelSet = append(labelSet, labelled[t.Object])
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `
INSERT INTO resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels, source_version)
SELECT s.ot, s.oid, s.pid, p.account_id,
       CASE WHEN s.lab THEN $5::jsonb ELSE '{}'::jsonb END,
       'seed'
  FROM unnest($1::text[], $2::text[], $3::text[], $4::bool[]) AS s(ot, oid, pid, lab)
  JOIN projects p ON p.id = s.pid`,
			types, ids, projIDs, labelSet, benchLabelJSON()); err != nil {
			return fmt.Errorf("зеркало: %w", err)
		}
	}

	// «Роль → глаголы» — это МОДЕЛЬ формы E, аналог модели авторизации у движка:
	// она объявляет, какие глаголы даёт роль, и живёт независимо от привязок.
	for _, v := range r.sc.Verbs {
		if _, err := tx.Exec(ctx, `INSERT INTO role_verbs (role, verb) VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, r.sc.Role, v); err != nil {
			return fmt.Errorf("глаголы роли: %w", err)
		}
	}

	if len(grant) > 0 {
		if err := applyIntent(ctx, tx, grant, true); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("коммит засева: %w", err)
	}
	return nil
}

// ── мутации ───────────────────────────────────────────────────────────────────

func (r *relStore) Write(ctx context.Context, tuples []Tuple) (Counters, error) {
	return r.mutate(ctx, tuples, true)
}

func (r *relStore) Remove(ctx context.Context, tuples []Tuple) (Counters, error) {
	return r.mutate(ctx, tuples, false)
}

func (r *relStore) mutate(ctx context.Context, tuples []Tuple, add bool) (Counters, error) {
	w := r.tracer.open()
	err := r.inTx(ctx, func(tx pgx.Tx) error { return applyIntent(ctx, tx, tuples, add) })
	return Counters{StmtSQL: w.close()}, err
}

// InlineGrant — предмет выдачи и сама выдача в ОДНОЙ транзакции.
//
// Это то, чего у движка отношений нет by construction, и главный довод
// безопасности у отзыва: право, снятое в транзакции писателя, не зависит от того,
// доехала ли доставка. Ячейка меряет ровно эту атомарность, а не скорость.
func (r *relStore) InlineGrant(ctx context.Context, data, grant []Tuple) (Counters, error) {
	return r.inline(ctx, data, grant, true)
}

func (r *relStore) InlineRevoke(ctx context.Context, data, revoke []Tuple) (Counters, error) {
	return r.inline(ctx, data, revoke, false)
}

func (r *relStore) inline(ctx context.Context, data, intent []Tuple, add bool) (Counters, error) {
	w := r.tracer.open()
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		// Предмет выдачи — всегда запись: даже при отзыве данные ресурса не
		// удаляются, они трогаются той же транзакцией, что снимает право.
		if err := applyStructural(ctx, tx, data); err != nil {
			return err
		}
		return applyIntent(ctx, tx, intent, add)
	})
	return Counters{StmtSQL: w.close()}, err
}

func (r *relStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начать транзакцию: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("коммит: %w", err)
	}
	return nil
}

// applyStructural кладёт строки зеркала для НОВЫХ объектов — предмет выдачи в
// операциях «в той же транзакции».
func applyStructural(ctx context.Context, tx pgx.Tx, data []Tuple) error {
	if len(data) == 0 {
		return nil
	}
	var types, ids, pids []string
	for _, t := range data {
		if t.Relation != "project" {
			return fmt.Errorf("предмет выдачи с отношением %q — ожидался указатель проекта", t.Relation)
		}
		ot, oid, err := splitObject(t.Object)
		if err != nil {
			return err
		}
		types = append(types, ot)
		ids = append(ids, oid)
		pids = append(pids, t.User)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels, source_version)
SELECT s.ot, s.oid, s.pid, p.account_id, $4::jsonb, 'inline'
  FROM unnest($1::text[], $2::text[], $3::text[]) AS s(ot, oid, pid)
  JOIN projects p ON p.id = s.pid
    ON CONFLICT (object_type, object_id) DO UPDATE SET labels = EXCLUDED.labels`,
		types, ids, pids, benchLabelJSON()); err != nil {
		return fmt.Errorf("предмет выдачи: %w", err)
	}
	return nil
}

// applyIntent переводит общий словарь намерения в строки формы E.
//
// Перевод — на стороне формы E, и это осознанный размен: общий словарь оставляет
// производителей намерения (`Grant`, `RelabelOne`, `RevokeSubject`) нетронутыми,
// а значит пять прежних форм измеряются ровно тем же кодом, что и до появления
// шестой. Неизвестное отношение — ОШИБКА, а не пропуск: молча проглоченное
// намерение дало бы форму E, выигравшую запись тем, что она её не сделала.
func applyIntent(ctx context.Context, tx pgx.Tx, tuples []Tuple, add bool) error {
	type bindingRow struct{ scopeType, scopeID, role string }
	bindings := map[string]bindingRow{}
	subjects := map[string][]string{}
	selectors := map[string]bool{}
	var labelled []string
	var accAdmins, cluAdmins []Tuple

	for _, t := range tuples {
		switch {
		case strings.HasPrefix(t.Relation, bindingRelPrefix):
			role := strings.TrimPrefix(t.Relation, bindingRelPrefix)
			scopeType, _, err := splitObject(t.User)
			if err != nil {
				return err
			}
			if scopeType != "project" && scopeType != "account" {
				return fmt.Errorf("область выдачи %q не проект и не аккаунт", scopeType)
			}
			// Идентификатор области хранится ЦЕЛИКОМ, с префиксом типа: ровно в
			// такой форме его несут родительские указатели зеркала, и обрезка
			// префикса здесь сделала бы сравнение тождественно ложным — то есть
			// выдачу, не разрешающую ничего и молча.
			bindings[t.Object] = bindingRow{scopeType, t.User, role}
		case t.Relation == bindingSubjectRel:
			subjects[t.Object] = append(subjects[t.Object], t.User)
		case t.Relation == bindingSelectorRel:
			selectors[t.Object] = true
		case t.Relation == labelsRel:
			_, oid, err := splitObject(t.Object)
			if err != nil {
				return err
			}
			labelled = append(labelled, oid)
		case t.Relation == cascadeAccountAdminRel:
			accAdmins = append(accAdmins, t)
		case t.Relation == cascadeClusterAdminRel:
			cluAdmins = append(cluAdmins, t)
		default:
			return fmt.Errorf("намерение с неизвестным отношением %q — общий словарь разошёлся", t.Relation)
		}
	}

	if add {
		for id, b := range bindings {
			if _, err := tx.Exec(ctx,
				`INSERT INTO access_bindings (id, scope_type, scope_id, role) VALUES ($1, $2, $3, $4)`,
				id, b.scopeType, b.scopeID, b.role); err != nil {
				return fmt.Errorf("привязка: %w", err)
			}
		}
		for id, subs := range subjects {
			if _, err := tx.Exec(ctx,
				`INSERT INTO access_binding_subjects (binding_id, subject)
				 SELECT $1, s FROM unnest($2::text[]) AS s`, id, subs); err != nil {
				return fmt.Errorf("субъекты привязки: %w", err)
			}
		}
		for id := range selectors {
			if _, err := tx.Exec(ctx,
				`INSERT INTO role_rule_selectors (binding_id, object_type, labels) VALUES ($1, $2, $3::jsonb)`,
				id, BenchType, benchLabelJSON()); err != nil {
				return fmt.Errorf("правило-селектор: %w", err)
			}
		}
		if len(labelled) > 0 {
			if _, err := tx.Exec(ctx,
				`UPDATE resource_mirror SET labels = $2::jsonb, updated_at = now()
				  WHERE object_type = $3 AND object_id = ANY($1::text[])`,
				labelled, benchLabelJSON(), BenchType); err != nil {
				return fmt.Errorf("вход объектов в набор: %w", err)
			}
		}
		for _, t := range accAdmins {
			if _, err := tx.Exec(ctx,
				`INSERT INTO account_admins (account_id, subject) VALUES ($1, $2)`,
				t.Object, t.User); err != nil {
				return fmt.Errorf("администратор аккаунта: %w", err)
			}
		}
		for _, t := range cluAdmins {
			if _, err := tx.Exec(ctx,
				`INSERT INTO cluster_admins (cluster_id, subject) VALUES ($1, $2)`,
				t.Object, t.User); err != nil {
				return fmt.Errorf("администратор кластера: %w", err)
			}
		}
		return nil
	}

	for id, subs := range subjects {
		if _, err := tx.Exec(ctx,
			`DELETE FROM access_binding_subjects WHERE binding_id = $1 AND subject = ANY($2::text[])`,
			id, subs); err != nil {
			return fmt.Errorf("отзыв субъектов: %w", err)
		}
	}
	for id := range selectors {
		if _, err := tx.Exec(ctx, `DELETE FROM role_rule_selectors WHERE binding_id = $1`, id); err != nil {
			return fmt.Errorf("снятие правила-селектора: %w", err)
		}
	}
	for id := range bindings {
		if _, err := tx.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, id); err != nil {
			return fmt.Errorf("снятие привязки: %w", err)
		}
	}
	if len(labelled) > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE resource_mirror SET labels = '{}'::jsonb, updated_at = now()
			  WHERE object_type = $2 AND object_id = ANY($1::text[])`,
			labelled, BenchType); err != nil {
			return fmt.Errorf("выход объектов из набора: %w", err)
		}
	}
	for _, t := range accAdmins {
		if _, err := tx.Exec(ctx, `DELETE FROM account_admins WHERE account_id = $1 AND subject = $2`,
			t.Object, t.User); err != nil {
			return fmt.Errorf("снятие администратора аккаунта: %w", err)
		}
	}
	for _, t := range cluAdmins {
		if _, err := tx.Exec(ctx, `DELETE FROM cluster_admins WHERE cluster_id = $1 AND subject = $2`,
			t.Object, t.User); err != nil {
			return fmt.Errorf("снятие администратора кластера: %w", err)
		}
	}
	return nil
}

// ── чтение ────────────────────────────────────────────────────────────────────

func (r *relStore) Check(ctx context.Context, subject, verb, object string) (bool, Counters, error) {
	ot, oid, err := splitObject(object)
	if err != nil {
		return false, Counters{}, err
	}
	w := r.tracer.open()
	res, err := r.verdict().Allowed(ctx, subject, verb, ot, []string{oid})
	c := Counters{StmtSQL: w.close()}
	if err != nil {
		return false, c, err
	}
	return res[oid], c, nil
}

func (r *relStore) BatchCheck(ctx context.Context, subject, verb string, objects []string) ([]bool, Counters, error) {
	w := r.tracer.open()
	out, err := r.ask(ctx, subject, verb, objects)
	return out, Counters{StmtSQL: w.close()}, err
}

// CheckPage — целая страница ОДНИМ запросом.
//
// Разложение на партии и параллелизм — свойство движка (его потолок пакетного
// вопроса), а не общего требования: у формы E партии нет, и число частей здесь
// всегда единица. Это ОБЪЯВЛЯЕТСЯ (число частей возвращается и печатается), а не
// усредняется с чужим разложением.
func (r *relStore) CheckPage(ctx context.Context, subject, verb string, objects []string,
	_, _ int) ([]bool, int, Counters, error) {
	w := r.tracer.open()
	out, err := r.ask(ctx, subject, verb, objects)
	return out, 1, Counters{StmtSQL: w.close()}, err
}

func (r *relStore) ask(ctx context.Context, subject, verb string, objects []string) ([]bool, error) {
	if len(objects) == 0 {
		return nil, fmt.Errorf("пустая страница — вопрос без предмета")
	}
	ot, _, err := splitObject(objects[0])
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(objects))
	for _, o := range objects {
		t, id, err := splitObject(o)
		if err != nil {
			return nil, err
		}
		if t != ot {
			return nil, fmt.Errorf("страница смешивает типы объектов: %q и %q", ot, t)
		}
		ids = append(ids, id)
	}
	res, err := r.verdict().Allowed(ctx, subject, verb, ot, ids)
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(ids))
	for i, id := range ids {
		out[i] = res[id]
	}
	return out, nil
}

// ── объём ─────────────────────────────────────────────────────────────────────

// Volume считает объём ТЕМ ЖЕ правилом, каким его считает база сравнения: строки
// — за вычетом структурных, байты — по всем строкам хранилища, размер отношений —
// целиком и отдельно. Правило унаследовано намеренно: колонка, посчитанная у
// шестой формы иначе, чем у пяти прежних, сравнима только на бумаге.
func (r *relStore) Volume(ctx context.Context) (Volume, error) {
	var v Volume
	var err error
	if v.GrantRows, v.GrantBytes, err = r.sumTables(ctx, relGrantTables); err != nil {
		return Volume{}, err
	}
	structRows, structBytes, err := r.sumTables(ctx, relStructuralTables)
	if err != nil {
		return Volume{}, err
	}
	v.StructuralRows, v.StructuralBytes = structRows, structBytes
	v.GrantBytes += structBytes // байты — по ВСЕМ строкам, как у базы сравнения

	all := append(append([]string{}, relGrantTables...), relStructuralTables...)
	for _, t := range all {
		var sz int64
		if err := r.pool.QueryRow(ctx,
			`SELECT pg_total_relation_size($1::regclass)`, r.schema+"."+t).Scan(&sz); err != nil {
			return Volume{}, fmt.Errorf("размер отношения %s: %w", t, err)
		}
		v.TableBytes += sz
	}
	return v, nil
}

func (r *relStore) sumTables(ctx context.Context, tables []string) (rows, bytes int64, err error) {
	for _, t := range tables {
		var n, b int64
		// Имя таблицы — из закрытого перечня этого файла, не из ввода.
		q := fmt.Sprintf(`SELECT count(*), COALESCE(sum(pg_column_size(x.*)), 0) FROM %s x`, quoteIdent(t))
		if err := r.pool.QueryRow(ctx, q).Scan(&n, &b); err != nil {
			return 0, 0, fmt.Errorf("объём таблицы %s: %w", t, err)
		}
		rows += n
		bytes += b
	}
	return rows, bytes, nil
}

// quoteIdent — идентификатор в кавычках. Имена схем строятся харнессом из имени
// формы и номера повтора, но кавычки ставятся всё равно: молчаливое допущение о
// том, что имя «и так безопасно», живёт ровно до первого имени с дефисом.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// newRelStore создаёт схему формы E и пул с собственным счётчиком стейтментов.
func newRelStore(ctx context.Context, dsn, schema string, sc Scenario) (*relStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("разбор строки подключения формы E: %w", err)
	}
	tracer := &stmtTracer{}
	cfg.ConnConfig.Tracer = tracer
	// Страница разрешается одним запросом, но повторы чтения идут подряд, а засев
	// и снос — своими соединениями; горсти хватает с запасом.
	cfg.MaxConns = 8
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	// Схема создаётся ДО пула с этим search_path: иначе первое же соединение
	// открылось бы с путём в несуществующую схему.
	boot, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("подключение к БД формы E: %w", err)
	}
	defer boot.Close()
	if _, err := boot.Exec(ctx, `CREATE SCHEMA `+quoteIdent(schema)); err != nil {
		return nil, fmt.Errorf("создание схемы %s: %w", schema, err)
	}
	if _, err := boot.Exec(ctx, `SET search_path TO `+quoteIdent(schema)+`; `+relSchemaDDL); err != nil {
		return nil, fmt.Errorf("схема формы E: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("пул формы E: %w", err)
	}
	st := &relStore{pool: pool, tracer: tracer, schema: schema, sc: sc}
	st.prod = verifyRelStmtProducer(ctx, st)
	if !st.prod.OK {
		pool.Close()
		return nil, fmt.Errorf("производитель StmtSQL формы E не прошёл контроль: %s", st.prod.Note)
	}
	return st, nil
}

// verifyRelStmtProducer — контроль производителя `StmtSQL` формы E в ОБЕ стороны,
// на её собственном соединении и на её собственном счётчике.
//
// Контроль исполняется при открытии КАЖДОГО хранилища, а не однажды при старте:
// счётчик привязан к пулу, пул создаётся на хранилище, и «проверили один раз в
// начале» означало бы утверждение об одном пуле, напечатанное про все.
func verifyRelStmtProducer(ctx context.Context, r *relStore) ProducerStatus {
	place := "форма E (Postgres формы E)"
	producer := "счётчик стейтментов на pgx.Tracer собственного пула"

	idleW := r.tracer.open()
	if idle := idleW.close(); idle != 0 {
		return ProducerStatus{Place: place, Producer: producer,
			Note: fmt.Sprintf("холостая дельта %d вместо 0 — счётчик мерит фон", idle)}
	}
	w := r.tracer.open()
	var one int
	if err := r.pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return ProducerStatus{Place: place, Producer: producer, Note: err.Error()}
	}
	if got := w.close(); got != 1 {
		return ProducerStatus{Place: place, Producer: producer,
			Note: fmt.Sprintf("один стейтмент дал дельту %d вместо 1", got)}
	}
	return ProducerStatus{Place: place, Producer: producer, OK: true,
		Note: "холостая дельта 0, один стейтмент дал 1"}
}
