// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// xc12f5_labelcost_test.go — ПРОГОН Ф5: перезамер стоимости полномодельной формы
// на ПУТИ МЕТОК.
//
// # Почему прогон живёт здесь, а прибор — в tools/authzformbench
//
// Прибор один, и второго рядом не заводится: словарь операций, правило отнесения,
// исходы, окно неверного ответа, сторона движка и отчёт — всё это
// `tools/authzformbench/labelcost.go`, и этот файл их ИМПОРТИРУЕТ.
//
// А живёт он здесь по причине, которая от вкуса не зависит: измеряемая форма E —
// это `relverdict`, продуктовый запрос по настоящим таблицам iam, и он лежит под
// `services/iam/internal/`. Правило видимости Go разрешает импортировать такой
// пакет только из дерева `services/iam/`. Прогон, положенный рядом с прибором,
// мерил бы не продукт, а воспроизведение продукта в приборе — ровно ту оговорку,
// которую полномодельный прогон XC-10 назвал против собственного интереса.
// Поэтому: прибор — там, где ему место, прогон — там, где достижимы ОБЕ стороны.
//
// # Что здесь измеряется, а что взято как есть
//
// Измеряется: работа и ОКНО НЕВЕРНОГО ОТВЕТА на пути меток у двух форм.
// Взято как есть: сам вердикт формы E (`relverdict.Ask`) и его согласие с
// движком — это предмет Ф2/Ф3 и их проб, здесь не перепроверяется.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	bench "github.com/PRO-Robotech/kacho/tools/authzformbench"
)

// f5Gate — прогон поднимает контейнеры и пишет сотни тысяч строк; `go test ./...`
// не должен платить за это случайно. Пропуск здесь — не «тихо зелено»: без
// переменной прогон не запрашивали, а запрошенный он НЕ пропускается ни по
// какой причине.
const f5Gate = "AUTHZFORMBENCH_F5"

// f5Label — метка правила. Ключ обязан пройти `kacho_iam.kacho_labels_valid`
// (`^[a-z][-_./@a-z0-9]{0,62}$`), поэтому он проверен схемой, а не выбран на глаз.
const (
	f5LabelKey   = "authzformbench"
	f5LabelValue = "f5"

	f5Account = "acc-f5"
	f5Project = "prj-f5"
	f5Role    = "rol-f5"
	f5Binding = "abn-f5"

	// f5Type — тип в словаре МОДЕЛИ ПРАВ: им задают вопрос и им названы обе
	// стороны цепи предков.
	f5Type = "vpc_network"
)

// f5CatalogType — ТОТ ЖЕ тип в словаре КАТАЛОГА: им названы `resource_mirror`,
// `role_verb.object_type` и `role_rule_selectors.object_types`. Посев обязан
// класть в каждую колонку её словарь — иначе замер снимается с запроса, который
// не находит НИЧЕГО, и кривая описывает пустоту.
//
// Берётся у каталога напрямую, а не переводчиком продукта: общий вызов сместил
// бы обе стороны одинаково.
var f5CatalogType = func() string {
	dotted, known := authzmap.DottedType(f5Type)
	if !known {
		panic("authzformbench: тип " + f5Type + " не объявлен в каталоге")
	}
	return dotted
}()

// f5Verbs / f5Subjects — M и S. Заданы здесь, чтобы кривая по N снималась при
// неизменных двух других множителях: иначе наклон принадлежал бы не N.
var f5Verbs = []string{"get", "list", "update", "delete"}

func f5Subjects(s int) []string {
	out := make([]string, 0, s)
	for i := 0; i < s; i++ {
		out = append(out, fmt.Sprintf("user:usr-f5-%02d", i))
	}
	return out
}

// ── форма E: продуктовый запрос по настоящим таблицам iam ─────────────────────

type relLabelForm struct {
	pool  *pgxpool.Pool
	asker *relverdict.Asker
	sc    bench.LabelScenario
	cnt   *bench.SQLStmtCounter
	prod  bench.ProducerStatus
}

func (r *relLabelForm) Name() string { return "форма E (relverdict, таблицы iam)" }

func (r *relLabelForm) Place() string {
	return "services/iam/internal/repo/kacho/pg/relverdict · схема kacho_iam (pgtest)"
}

func (r *relLabelForm) StmtProducer() bench.ProducerStatus { return r.prod }

// ApplyRule пишет ПРАВИЛО: роль с ветвью меток, её проекцию глаголов и выдачу на
// область проекта. Ни одной строки на объект — в этом и состоит предмет L1.
func (r *relLabelForm) ApplyRule(ctx context.Context) (bench.Counters, int, error) {
	w := r.cnt.Open()
	rows := 0
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return bench.Counters{StmtSQL: w.Close()}, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		VALUES ($1, $2, '[]'::jsonb,
		        jsonb_build_array(jsonb_build_object(
		            'module', 'authzformbench', 'resources', jsonb_build_array('*'),
		            'verbs', $3::jsonb)),
		        'cluster_kacho_root')`,
		f5Role, "authzformbench.f5", jsonArray(r.sc.Verbs)); err != nil {
		return bench.Counters{StmtSQL: w.Close()}, rows, fmt.Errorf("роль: %w", err)
	}
	rows++
	for _, v := range r.sc.Verbs {
		if _, err := tx.Exec(ctx, `INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
			VALUES ($1, $2, $3)`, f5Role, f5CatalogType, v); err != nil {
			return bench.Counters{StmtSQL: w.Close()}, rows, fmt.Errorf("глагол роли: %w", err)
		}
		rows++
	}
	if _, err := tx.Exec(ctx, `INSERT INTO kacho_iam.role_rule_selectors
		  (role_id, rule_fp, arm, object_types, match_labels)
		VALUES ($1, 'fp-f5', 'labels', ARRAY[$2::text], $3::jsonb)`,
		f5Role, f5CatalogType, labelJSON(r.sc)); err != nil {
		return bench.Counters{StmtSQL: w.Close()}, rows, fmt.Errorf("правило-селектор: %w", err)
	}
	rows++
	if _, err := tx.Exec(ctx, `INSERT INTO kacho_iam.access_bindings
		  (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		f5Binding, subjID(r.sc.Subjects[0]), f5Role, f5Project); err != nil {
		return bench.Counters{StmtSQL: w.Close()}, rows, fmt.Errorf("выдача: %w", err)
	}
	rows++
	for i, s := range r.sc.Subjects {
		if _, err := tx.Exec(ctx, `INSERT INTO kacho_iam.access_binding_subjects
			  (binding_id, subject_type, subject_id, ordinal) VALUES ($1, 'user', $2, $3)`,
			f5Binding, subjID(s), i); err != nil {
			return bench.Counters{StmtSQL: w.Close()}, rows, fmt.Errorf("субъект выдачи: %w", err)
		}
		rows++
	}
	if err := tx.Commit(ctx); err != nil {
		return bench.Counters{StmtSQL: w.Close()}, rows, err
	}
	return bench.Counters{StmtSQL: w.Close()}, rows, nil
}

// DropRule снимает правило. Удаление, а не перевод в REVOKED: предмет L1 —
// стоимость ПЕРВОГО ответа по свежему правилу, и повтор по отозванной строке
// мерил бы другое.
func (r *relLabelForm) DropRule(ctx context.Context) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM kacho_iam.access_bindings WHERE id = $1`, f5Binding); err != nil {
		return err
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM kacho_iam.roles WHERE id = $1`, f5Role)
	return err
}

// Settle — работа формы E по событию метки.
//
// Её нет: метка живёт в той же базе, что и вердикт, и читается на пути запроса.
// Ноль тем не менее ИЗМЕРЯЕТСЯ — окно счётчика открывается и закрывается, — иначе
// он был бы взят из рассуждения и неотличим от несработавшего счётчика.
func (r *relLabelForm) Settle(ctx context.Context, ev bench.LabelEvent) (bench.Counters, int, error) {
	if ev.Kind == bench.EventRuleRevoked {
		// Отзыв правила — РАБОТА формы E, и она у неё есть: одна строка выдачи
		// переводится в отозванные. Строк на объект по-прежнему ноль, и именно это
		// сравнивается с удалением N × M × S кортежей у движка.
		w := r.cnt.Open()
		tag, err := r.pool.Exec(ctx, `UPDATE kacho_iam.access_bindings
			SET status = 'REVOKED', revoked_at = now() WHERE id = $1 AND status = 'ACTIVE'`, f5Binding)
		c := bench.Counters{StmtSQL: w.Close()}
		if err != nil {
			return c, 0, err
		}
		return c, int(tag.RowsAffected()), nil
	}
	w := r.cnt.Open()
	return bench.Counters{StmtSQL: w.Close()}, 0, nil
}

func (r *relLabelForm) Check(ctx context.Context, subject, relation, objectID string) (bool, bench.Counters, error) {
	w := r.cnt.Open()
	ok, err := r.asker.Allowed(ctx, subject, f5Type, objectID, relation, nil)
	return ok, bench.Counters{StmtSQL: w.Close()}, err
}

// Page — страница договора у формы E: тот же предикат перечислением, курсором,
// из СВОЕЙ таблицы. Возвращается пересечение с набором кандидатов, чтобы вопрос
// у обеих форм был один и тот же: «сколько из ЭТИХ объектов доступно».
func (r *relLabelForm) Page(ctx context.Context, subject, relation string, ids []string) (int, int, bench.Counters, error) {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	w := r.cnt.Open()
	got, _, err := r.asker.Objects(ctx, subject, f5Type, []string{relation}, len(ids))
	c := bench.Counters{StmtSQL: w.Close()}
	if err != nil {
		return 0, 0, c, err
	}
	allowed := 0
	for _, id := range got {
		if want[id] {
			allowed++
		}
	}
	// Часть одна: страница сужается ОДНИМ запросом, разложения на части нет.
	return allowed, 1, c, nil
}

func (r *relLabelForm) Teardown(context.Context) error { return nil }

// ── общий мир: зеркало объектов и цепь предков ───────────────────────────────

// f5World — то, что есть у обеих форм ОДИНАКОВО.
//
// Изменение метки применяется ЗДЕСЬ и до старта секундомера: правило отнесения
// п.2 запрещает приписывать зеркало какой-либо из форм. Момент коммита
// возвращается наружу и служит нулём отсчёта окна для обеих.
type f5World struct {
	pool *pgxpool.Pool
	eng  *bench.Store
	sc   bench.LabelScenario
	// engStructural — заведён ли у движка структурный указатель созданного
	// объекта. Нужен, чтобы возврат состояния не пытался снять то, чего нет.
	engStructural map[string]bool
}

func (w *f5World) Commit(ctx context.Context, ev bench.LabelEvent) (time.Time, error) {
	switch ev.Kind {
	case bench.EventEntered:
		if _, err := w.pool.Exec(ctx, `UPDATE kacho_iam.resource_mirror SET labels = $3::jsonb
			WHERE object_type = $1 AND object_id = $2`, f5CatalogType, ev.ObjectID, labelJSON(w.sc)); err != nil {
			return time.Time{}, err
		}
	case bench.EventLeft:
		if _, err := w.pool.Exec(ctx, `UPDATE kacho_iam.resource_mirror SET labels = '{}'::jsonb
			WHERE object_type = $1 AND object_id = $2`, f5CatalogType, ev.ObjectID); err != nil {
			return time.Time{}, err
		}
	case bench.EventCreated:
		if err := w.insertMirror(ctx, []string{ev.ObjectID}, true); err != nil {
			return time.Time{}, err
		}
		if err := w.engineStructural(ctx, ev.ObjectID); err != nil {
			return time.Time{}, err
		}
	case bench.EventRuleRevoked:
		// Общего изменения у отзыва правила нет: правило — состояние формы, а не
		// зеркала. Отсчёт окна начинается там же, где у остальных, — до того как
		// форма сделает хоть что-нибудь.
	}
	return time.Now(), nil
}

func (w *f5World) Revert(ctx context.Context, ev bench.LabelEvent) error {
	switch ev.Kind {
	case bench.EventEntered:
		_, err := w.pool.Exec(ctx, `UPDATE kacho_iam.resource_mirror SET labels = '{}'::jsonb
			WHERE object_type = $1 AND object_id = $2`, f5CatalogType, ev.ObjectID)
		return err
	case bench.EventLeft:
		_, err := w.pool.Exec(ctx, `UPDATE kacho_iam.resource_mirror SET labels = $3::jsonb
			WHERE object_type = $1 AND object_id = $2`, f5CatalogType, ev.ObjectID, labelJSON(w.sc))
		return err
	case bench.EventCreated:
		if _, err := w.pool.Exec(ctx, `DELETE FROM kacho_iam.resource_parent_edge
			WHERE object_type = $1 AND object_id = $2`, f5Type, ev.ObjectID); err != nil {
			return err
		}
		_, err := w.pool.Exec(ctx, `DELETE FROM kacho_iam.resource_mirror
			WHERE object_type = $1 AND object_id = $2`, f5CatalogType, ev.ObjectID)
		return err
	}
	return nil
}

// engineStructural пишет движку указатель родителя созданного объекта — его
// копию строки зеркала. Общая часть, не приписываемая ни одной форме.
func (w *f5World) engineStructural(ctx context.Context, objectID string) error {
	if w.engStructural[objectID] {
		return nil
	}
	if _, err := w.eng.WriteTuples(ctx, []bench.Tuple{{
		User: "project:" + f5Project, Relation: "project", Object: w.sc.Ref(objectID),
	}}); err != nil {
		return err
	}
	w.engStructural[objectID] = true
	return nil
}

// insertMirror кладёт объекты в зеркало и цепь предков одним стейтментом на
// таблицу: посев построчно на N=10000 мерил бы терпение, а не форму.
func (w *f5World) insertMirror(ctx context.Context, ids []string, labelled bool) error {
	labels := "{}"
	if labelled {
		labels = labelJSON(w.sc)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO kacho_iam.resource_mirror
		  (object_type, object_id, parent_project_id, parent_account_id, labels)
		SELECT $1, u, $2, $3, $4::jsonb FROM unnest($5::text[]) AS u
		ON CONFLICT (object_type, object_id) DO UPDATE SET labels = EXCLUDED.labels`,
		f5CatalogType, f5Project, f5Account, labels, ids); err != nil {
		return fmt.Errorf("зеркало: %w", err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO kacho_iam.resource_parent_edge
		  (object_type, object_id, parent_type, parent_id, depth)
		SELECT $1, u, 'project', $2, 1 FROM unnest($3::text[]) AS u
		ON CONFLICT DO NOTHING`, f5Type, f5Project, ids); err != nil {
		return fmt.Errorf("ребро предка: %w", err)
	}
	return nil
}

// ── прогон ────────────────────────────────────────────────────────────────────

func TestXC12F5LabelPathCost(t *testing.T) {
	if os.Getenv(f5Gate) == "" {
		t.Skipf("установи %s=1, чтобы снять замер (поднимаются контейнеры, пишутся сотни тысяч строк)", f5Gate)
	}
	ctx := context.Background()

	stack, err := bench.SharedStack(ctx)
	if err != nil {
		t.Fatalf("стек замера не поднялся: %v", err)
	}
	t.Cleanup(bench.CloseSharedStack)

	modelPath, canon, err := bench.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("каноническая модель: %v", err)
	}
	dsl, _, err := bench.ModelFor(bench.FormA, string(canon))
	if err != nil {
		t.Fatalf("модель формы движка: %v", err)
	}
	modelJSON, err := bench.TransformDSL(dsl)
	if err != nil {
		t.Fatalf("трансформ модели: %v", err)
	}

	ns := parseNs(t, os.Getenv("AUTHZFORMBENCH_F5_NS"), []int{10, 100, 1000, 10000})
	subjects := f5Subjects(envInt(t, "AUTHZFORMBENCH_F5_SUBJECTS", 5))

	var cells []bench.LabelCell
	var schedule []string
	var lastProd bench.ProducerStatus

	for _, n := range ns {
		sc := bench.LabelScenario{
			N: n, Verbs: f5Verbs, Subjects: subjects,
			ObjectType: f5Type, ProjectID: f5Project, AccountID: f5Account,
			LabelKey: f5LabelKey, LabelValue: f5LabelValue,
			PageSize: 1000, Partition: 50, Parallelism: 8,
		}
		cfg := scheduleFor(n)
		schedule = append(schedule, fmt.Sprintf("N=%d: запись %d · чтение %d · событие %d",
			n, cfg.WriteRepeats, cfg.ReadRepeats, cfg.EventRepeats))

		counter := bench.NewSQLStmtCounter()
		pool := newTracedPool(t, ctx, counter)
		prod := counter.Verify(ctx, pool, "форма E (Postgres iam, pgtest)")
		lastProd = prod
		if !prod.OK {
			t.Fatalf("производитель стейтментов формы E не прошёл контроль: %s", prod.Note)
		}

		store, err := stack.NewStore(ctx, fmt.Sprintf("f5-n%d", n), modelJSON)
		if err != nil {
			t.Fatalf("store движка при N=%d: %v", n, err)
		}

		world := &f5World{pool: pool, eng: store, sc: sc, engStructural: map[string]bool{}}
		seedCommon(t, ctx, world, sc)

		engForm := bench.NewEngineLabelForm(store, sc)
		relForm := &relLabelForm{pool: pool, asker: relverdict.NewAsker(pool), sc: sc, cnt: counter, prod: prod}

		t.Logf("── N=%d: движок (ожидаемых кортежей состава %d)", n, sc.ExpectedTuples())
		cells = append(cells, bench.RunLabelPath(ctx, world, engForm, sc, cfg)...)
		t.Logf("── N=%d: форма E", n)
		cells = append(cells, bench.RunLabelPath(ctx, world, relForm, sc, cfg)...)

		if err := engForm.Teardown(ctx); err != nil {
			t.Logf("снятие store движка N=%d: %v", n, err)
		}
		pool.Close()
	}

	// Путь модели печатается ОТ КОРНЯ ДЕРЕВА: абсолютный путь рабочей копии в
	// провенансе — координата, которой у читателя нет, и он ищет по ней файл,
	// которого на его машине не существует.
	if i := strings.Index(modelPath, "proto/"); i >= 0 {
		modelPath = modelPath[i:]
	}
	sum := sha256.Sum256(canon)
	prov := bench.CollectProvenance(stack, modelPath, hex.EncodeToString(sum[:])[:16])
	// Производители перечисляются ЗАНОВО, а не дополняются: сборщик провенанса
	// называет производителя формы E ПРИБОРА, а прибор здесь мерит не её. Строка о
	// производителе, который в этом прогоне не участвовал, — утверждение,
	// пережившее свой предмет, и читалась бы она как относящаяся к этим числам.
	prov.StmtProducers = []bench.ProducerStatus{stack.StmtProducer, lastProd}

	in := bench.LabelReportInput{
		Prov: prov, Config: scheduleFor(ns[0]), Ns: ns,
		Scenario: bench.LabelScenario{
			N: 0, Verbs: f5Verbs, Subjects: subjects, ObjectType: f5Type,
			ProjectID: f5Project, LabelKey: f5LabelKey, LabelValue: f5LabelValue,
			PageSize: 1000, Partition: 50, Parallelism: 8,
		},
		RepeatSchedule: strings.Join(schedule, " · "),
		RunCommand: "AUTHZFORMBENCH_F5=1 go test ./services/iam/internal/repo/kacho/pg/relverdict/ " +
			"-run TestXC12F5LabelPathCost -count=1 -v -timeout 180m",
		QueueNote:  f5QueueNote,
		Unmeasured: f5Unmeasured(),
	}

	var sb strings.Builder
	bench.ReportLabelPath(&sb, in, cells)
	fmt.Print(sb.String())
	if out := os.Getenv("AUTHZFORMBENCH_F5_OUT"); out != "" {
		if err := os.WriteFile(filepath.Clean(out), []byte(sb.String()), 0o600); err != nil {
			t.Fatalf("запись отчёта: %v", err)
		}
		t.Logf("отчёт записан в %s", out)
	}

	measured := 0
	for _, c := range cells {
		if c.Outcome == bench.Measured {
			measured++
		}
	}
	if measured == 0 {
		t.Fatal("ни одна ячейка не измерена — отчёт не является сравнением")
	}
	t.Logf("ячеек: %d измерено, %d прочих", measured, len(cells)-measured)
}

// f5QueueNote — что у продукта стоит между коммитом метки и началом пересчёта.
//
// Сказано текстом и БЕЗ числа-«пола», потому что числа-пола здесь нет: обе очереди
// пробуждаются уведомлением, а периоды опроса — запасной путь. Назвать период
// опроса нижней границей окна значило бы придумать величину в отчёте, весь предмет
// которого — чтобы величины были измеренными.
const f5QueueNote = `
Очередь реконсайла iam (resource_reconcile_outbox) и очередь движка (fga_outbox)
пробуждаются УВЕДОМЛЕНИЕМ (LISTEN/NOTIFY, триггер AFTER INSERT). Задержка
уведомления прибором НЕ измерялась: прибор держит движок и Postgres, а не сервис.
Периоды опроса — ЗАПАСНОЙ путь на пропущенное уведомление, и они разные:
  · очередь реконсайла  KACHO_IAM_RECONCILE_DRAIN_INTERVAL_MS, умолчание 1000 мс;
                        полный проход (sweep) — 30 000 мс;
  · очередь движка      PollFallback 30 000 мс, повтор с отступом 1000…30 000 мс,
                        до 10 попыток.
Отсюда: окно движка в проде = измеренное здесь ПЛЮС задержка уведомления на
штатном пути ЛИБО плюс период запасного, если уведомление потеряно. Ни одно из
этих слагаемых к измеренному не прибавлено — правило отнесения п.7.
Форму E это не касается ни на одном из двух путей: у неё между изменением метки и
вердиктом нет очереди вовсе, и её окно измерено целиком.`

// f5Unmeasured — то, чего этот прогон не измеряет, названное до чтения его чисел.
func f5Unmeasured() []string {
	return []string{
		"ЗАДЕРЖКА УВЕДОМЛЕНИЯ ОЧЕРЕДИ. Штатный путь пробуждения обеих очередей продукта — " +
			"LISTEN/NOTIFY; прибор их не поднимает и эту задержку не измерял. Периоды опроса, " +
			"названные в отчёте, — запасной путь, и «полом» окна они НЕ объявлены: назвать периодом " +
			"опроса нижнюю границу того, что штатно им не ограничено, значило бы придумать величину.",
		"БОЕВОЙ РЕКОНСАЙЛЕР. Развёртка правила в кортежи считается прибором, а не " +
			"`…/access_binding/reconcile/`. Значит про эту половину измерено «столько стоит развёртка», " +
			"а не «столько стоит развёртка ИМЕННО ЭТИМ кодом»; его собственные запросы к зеркалу и " +
			"диффу состава в число обращений движка не входят и увеличили бы его, а не уменьшили.",
		"КЭШИ ВЕРДИКТОВ. Оба кэша (края и общей библиотеки) живут над ОТВЕТОМ и переживают смену " +
			"источника, поэтому здесь не поднимались. На окно отзыва они действуют одинаково у обеих " +
			"форм и прибавляются к нему у ОБЕИХ — но в этих числах их нет.",
		"СЕЛЕКТИВНОСТЬ МЕТКИ. Правило накрывает ВЕСЬ набор (совпадение по метке — 100%). Правило, " +
			"накрывающее долю набора, здесь не задавалось: доля меняет число кортежей у движка " +
			"линейно, а у формы E — ничего, и это утверждение не проверялось прогоном.",
		"НАГРУЗКА. Замер однопользовательский: конкурентных писателей и читателей нет. Поведение " +
			"обеих форм под параллелью — отдельный предмет, и переносить эти числа на него нельзя.",
		"УСЛОВНЫЕ ЗАПИСИ. Отношения с условием (свежесть подтверждения личности) на пути меток не " +
			"участвуют — ни один глагол условия не несёт. Их предмет — Ф4, не Ф5.",
	}
}

// ── посев ─────────────────────────────────────────────────────────────────────

// seedCommon кладёт общую часть: арендную обвязку, N помеченных объектов и один
// непомеченный запасной. Посев в измеряемые величины не входит.
func seedCommon(t *testing.T, ctx context.Context, w *f5World, sc bench.LabelScenario) {
	t.Helper()
	// Арендная обвязка кладётся ОДНОЙ транзакцией: ссылка между аккаунтом и его
	// владельцем круговая, и её внешний ключ отложен до COMMIT. Построчный посев
	// в автокоммите проверяет ключ на каждой строке и падает на первой же —
	// проверено исполнением, а не рассуждением.
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция посева обвязки: %v", err)
	}
	txExec(t, ctx, tx, `INSERT INTO kacho_iam.clusters (id, name)
		VALUES ('cluster_kacho_root', 'kacho') ON CONFLICT DO NOTHING`)
	txExec(t, ctx, tx, `INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		VALUES ($1, 'authzformbench-f5', $2) ON CONFLICT DO NOTHING`, f5Account, subjID(sc.Subjects[0]))
	for _, s := range sc.Subjects {
		txExec(t, ctx, tx, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			VALUES ($1, $1, $1 || '@kacho.local', $2) ON CONFLICT DO NOTHING`, subjID(s), f5Account)
	}
	// Посторонний — субъект отрицательного контроля. Он ЗАВЕДЁН, но не назван ни в
	// одной выдаче: без него «разрешено субъекту правила» неотличимо от
	// «разрешено всякому, кто существует».
	txExec(t, ctx, tx, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		VALUES ('usr-stranger-not-in-any-binding', 'ext-stranger',
		        'stranger@kacho.local', $1) ON CONFLICT DO NOTHING`, f5Account)
	txExec(t, ctx, tx, `INSERT INTO kacho_iam.projects (id, account_id, name)
		VALUES ($1, $2, 'authzformbench-f5') ON CONFLICT DO NOTHING`, f5Project, f5Account)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит посева обвязки: %v", err)
	}

	ids := sc.Objects()
	for i := 0; i < len(ids); i += 5000 {
		end := i + 5000
		if end > len(ids) {
			end = len(ids)
		}
		if err := w.insertMirror(ctx, ids[i:end], true); err != nil {
			t.Fatalf("посев зеркала: %v", err)
		}
	}
	// Запасной объект события: он ЕСТЬ, но метки не несёт. Отдельный, а не взятый
	// из набора: событие на объекте набора меняло бы сам набор от повтора к повтору.
	if err := w.insertMirror(ctx, []string{sc.SpareEnter()}, false); err != nil {
		t.Fatalf("посев запасного объекта: %v", err)
	}

	// Структурная часть движка — его копия зеркала, общая и потому вне замера.
	var structural []bench.Tuple
	for _, id := range append(append([]string{}, ids...), sc.SpareEnter()) {
		structural = append(structural, bench.Tuple{
			User: "project:" + f5Project, Relation: "project", Object: sc.Ref(id)})
	}
	if _, err := w.eng.WriteTuples(ctx, structural); err != nil {
		t.Fatalf("посев структурных кортежей движка: %v", err)
	}
	for _, id := range append(append([]string{}, ids...), sc.SpareEnter()) {
		w.engStructural[id] = true
	}
}

// ── вспомогательное ───────────────────────────────────────────────────────────

func newTracedPool(t *testing.T, ctx context.Context, c *bench.SQLStmtCounter) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.Tracer = c.Tracer()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	return pool
}

func txExec(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("посев (%s): %v", strings.SplitN(strings.TrimSpace(sql), "\n", 2)[0], err)
	}
}

// scheduleFor — повторы по N.
//
// Уменьшаются с ростом N НЕ ради удобства: при N=10000 один повтор L5 удаляет и
// возвращает 200 000 кортежей, и прогон из пяти повторов мерил бы терпение.
// Число повторов КАЖДОЙ ячейки печатается в отчёте своей колонкой, поэтому
// расписание не прячется за усреднением.
func scheduleFor(n int) bench.LabelConfig {
	cfg := bench.DefaultLabelConfig()
	switch {
	case n >= 10000:
		cfg.WriteRepeats, cfg.EventRepeats = 1, 1
	case n >= 1000:
		cfg.WriteRepeats, cfg.EventRepeats = 2, 3
	}
	return cfg
}

func parseNs(t *testing.T, s string, def []int) []int {
	t.Helper()
	if strings.TrimSpace(s) == "" {
		return def
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			t.Fatalf("перечень N: %v", err)
		}
		out = append(out, n)
	}
	return out
}

func envInt(t *testing.T, key string, def int) int {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return n
}

// subjID — идентификатор субъекта без типа: таблицы iam хранят пару, а вопрос
// задаётся строкой. Разбор в одном месте, чтобы форма имени не разошлась.
func subjID(subject string) string {
	if i := strings.IndexByte(subject, ':'); i >= 0 {
		return subject[i+1:]
	}
	return subject
}

func labelJSON(sc bench.LabelScenario) string {
	return fmt.Sprintf(`{%q:%q}`, sc.LabelKey, sc.LabelValue)
}

func jsonArray(items []string) string {
	q := make([]string, 0, len(items))
	for _, s := range items {
		q = append(q, fmt.Sprintf("%q", s))
	}
	return "[" + strings.Join(q, ",") + "]"
}
