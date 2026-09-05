// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package parentedge_test

// completeness_integration_test.go — объект зеркала без цепи до корня есть
// НАХОДКА, а не молчание.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Форма E отвечает на вопрос о доступе, поднимаясь по цепи предков объекта.
// Объект, у которого цепи нет, отвечает «нет прав» — и этот отказ НЕОТЛИЧИМ от
// честного: он той же формы, с тем же кодом, и ни один прогон его не покажет.
//
// Это зеркало дефекта, на котором был отвергнут первый заход замера: там
// конъюнкт был тождественно ЛОЖЕН, здесь — молчаливо пуст. Оба выглядят как
// работающая проверка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ФИКСТУРА СЕЕТ ЧЕРЕЗ ПРОИЗВОДИТЕЛЯ, А НЕ СЫРЫМ SQL
//
// Прежняя редакция клала рёбра прямо в таблицу. Тогда «у каждого объекта есть
// цепь» — свойство ФИКСТУРЫ: она сама и положила то, что потом пересчитывала.
// Проверено прогоном: производителю вырезали запись рёбер целиком, и проба
// осталась ЗЕЛЁНОЙ на всех трёх кейсах — то есть она не могла упасть на том
// самом дефекте, ради которого заведена.
//
// Теперь регистрация идёт ТЕМ ЖЕ вызовом, которым её делает продукт
// (resource_mirror.UpsertTx — единственный производитель рёбер в дереве).
// Цепь появляется, только если её ДЕЙСТВИТЕЛЬНО пишет код продукта; регистрация
// без цепи — ровно то, что производит потребитель, который её не шлёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ ПЕЧАТАЕТ И ПОЧЕМУ ИМЕННО ЭТО
//
// Пару чисел: сколько строк зеркала осмотрено и сколько из них без цепи. «Ноль
// непокрытых» обязано быть отличимо от «ноль осмотренных» — на пустом зеркале
// гейт падает, потому что молчание там означает «сверять было нечего», а не
// «всё покрыто».
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА, НАЗВАННАЯ ЯВНО
//
// Короткая цепь — не дефект. Объект корневого уровня (сам аккаунт, сам кластер)
// предка не имеет по построению, и требовать его значило бы требовать цепи,
// которой нет в природе. Гейт судит НАЛИЧИЕ цепи у тех, у кого зеркало знает
// предка, а не её длину.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// rootLevelTypes — типы, у которых предка нет по построению.
//
// Перечень закрыт и назван: это НЕ послабление «нам лень заполнить», а факт
// модели — над аккаунтом стоит кластер, над кластером ничего. Появится тип, у
// которого предка нет по другой причине, — он вносится сюда с этой причиной, а
// не тихо исключается предикатом.
var rootLevelTypes = map[string]string{
	"account": "над аккаунтом только кластер; сам аккаунт предка в зеркале не имеет",
	"cluster": "корень иерархии областей",
}

// catalogFormOf — имя типа в словаре КАТАЛОГА, взятое у каталога напрямую.
//
// Не через переводчик продукта: общий вызов сместил бы фикстуру и продукт
// одинаково, и проба доказывала бы согласие перевода с самим собой.
func catalogFormOf(t *testing.T, modelType string) string {
	t.Helper()
	dotted, known := authzmap.DottedType(modelType)
	if !known {
		t.Fatalf("тип %q не объявлен в каталоге — фикстура назвала бы словарь, "+
			"которого нет", modelType)
	}
	return dotted
}

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgtest.NewDB(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("пул к тестовой БД: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// registration — намерение ОДНОГО потребителя: что он сообщает о своём объекте.
//
// Именованный тип, а не голый набор аргументов: «цепь не выслана» обязано
// читаться в фикстуре так же, как оно выглядит в дереве, — отсутствием значения
// у названного поля, а не пустой строкой в третьей позиции.
type registration struct {
	// consumer — чьё намерение изображается. Попадает в текст падения, чтобы
	// находка называла ПОТРЕБИТЕЛЯ, а не только объект.
	consumer string
	// objectType — тип в словаре КАТАЛОГА: им регистрация называет объект, и им
	// назван `resource_mirror.object_type`. Цепь предков при этом ложится
	// словарём МОДЕЛИ — перевод делает писатель, и перепись ниже обязана его
	// повторить, иначе она сравнивала бы два разных словаря и объявила бы без
	// цепи ВСЁ.
	objectType string
	objectID   string
	// parentChain — цепь предков от ближайшего к дальнему, `"<type>:<id>"`.
	// Пусто = потребитель цепи НЕ ШЛЁТ (и это ровно то состояние, которое гейт
	// обязан находить у не-корневых объектов).
	parentChain []string
	// parentProjectID — прежняя, двухуровневая форма предка. Оставлена, чтобы
	// законный близнец отличался от находки ТОЛЬКО цепью.
	parentProjectID string
}

// register проводит намерение ЧЕРЕЗ ПРОИЗВОДИТЕЛЯ — тем же вызовом, которым это
// делает продукт, — и требует, чтобы запись действительно применилась.
//
// Проверка `Applied` здесь не формальность: молча не применившаяся регистрация
// оставила бы зелёной обе стороны гейта, и он снова утверждал бы свойство своей
// фикстуры.
func register(t *testing.T, pool *pgxpool.Pool, r registration, version time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция регистрации %s:%s: %v", r.objectType, r.objectID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out, err := resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      r.objectType,
		ObjectID:        r.objectID,
		ParentProjectID: r.parentProjectID,
		ParentChain:     r.parentChain,
		SourceVersion:   version,
	})
	if err != nil {
		t.Fatalf("регистрация %s (%s:%s): %v", r.consumer, r.objectType, r.objectID, err)
	}
	if !out.Applied {
		t.Fatalf("регистрация %s (%s:%s) не применилась — фикстура ничего не посеяла, "+
			"и обе стороны гейта стали бы зелёными ни на чём",
			r.consumer, r.objectType, r.objectID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("фиксация регистрации %s:%s: %v", r.objectType, r.objectID, err)
	}
}

// seedThroughProducer проводит набор намерений, выдавая каждому свой маркер
// версии (регистрации приходят в разное время, и монотонная защита строки это
// читает).
func seedThroughProducer(t *testing.T, pool *pgxpool.Pool, regs ...registration) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i, r := range regs {
		register(t, pool, r, base.Add(time.Duration(i)*time.Millisecond))
	}
}

// uncovered — строки зеркала без единого ребра, кроме корневых типов.
//
// # Почему один стейтмент, а не «прочитать зеркало и спросить по строке»
//
// Утверждение здесь — КВАНТОР по множеству, и он обязан остаться одним вопросом
// к базе: перепись, разложенная на строку-за-строкой, перестаёт быть переписью и
// выводит пробу из-под гейта `internal/repohygiene`
// TestCensusFixturesSeedThroughTheProducer — он узнаёт перепись ровно по одному
// стейтменту, называющему ОБЕ таблицы.
//
// # Почему в запрос едет словарь
//
// Зеркало названо словарём КАТАЛОГА, цепь — словарём МОДЕЛИ. Прямое соединение
// колонок объявило бы без цепи КАЖДЫЙ объект: гейт краснел бы всегда и по
// неверной причине. Соответствие приезжает параметрами, собранными ЕДИНСТВЕННЫМ
// переходником (`authzmap`), — второго словаря в дереве не заводится.
func uncovered(t *testing.T, pool *pgxpool.Pool) (examined int, missing []string) {
	t.Helper()
	ctx := context.Background()

	catalogNames, modelNames := typeDictionaryPairs()
	rows, err := pool.Query(ctx,
		`WITH dict(catalog_name, model_name) AS (SELECT * FROM unnest($1::text[], $2::text[]))
		 SELECT m.object_type, m.object_id,
		        EXISTS (SELECT 1 FROM kacho_iam.resource_parent_edge e
		                 WHERE e.object_type = COALESCE(
		                         (SELECT d.model_name FROM dict d
		                           WHERE d.catalog_name = m.object_type), m.object_type)
		                   AND e.object_id = m.object_id)
		   FROM kacho_iam.resource_mirror m`, catalogNames, modelNames)
	if err != nil {
		t.Fatalf("перепись зеркала: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, id string
		var hasEdge bool
		if err := rows.Scan(&typ, &id, &hasEdge); err != nil {
			t.Fatalf("чтение строки зеркала: %v", err)
		}
		examined++
		if hasEdge {
			continue
		}
		// Корневые типы названы словарём модели: находка обязана называться так
		// же, как её увидит вопрос о доступе.
		modelType := authzmap.ModelTypeName(typ)
		if _, root := rootLevelTypes[modelType]; root {
			continue
		}
		missing = append(missing, modelType+":"+id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("обход зеркала: %v", err)
	}
	return examined, missing
}

// typeDictionaryPairs — соответствие словарей ДЛЯ ЗАПРОСА, собранное из каталога
// единственным переходником.
func typeDictionaryPairs() (catalogNames, modelNames []string) {
	for _, e := range authzmap.Catalog() {
		catalogName := e.Module + "." + e.Resource
		catalogNames = append(catalogNames, catalogName)
		modelNames = append(modelNames, authzmap.ModelTypeName(catalogName))
	}
	return catalogNames, modelNames
}

// Законная сторона: каждое намерение несёт свою цепь, корневой объект — не находка.
//
// Зелёное здесь означает, что цепь написал ПРОДУКТ: фикстура рёбер не касается.
func TestParentEdgeCompleteness_SilentWhenEveryRegistrationCarriesItsChain(t *testing.T) {
	pool := openPool(t)
	seedThroughProducer(t, pool,
		registration{
			consumer: "vpc", objectType: catalogFormOf(t, "vpc_network"), objectID: "net-1",
			parentProjectID: "prj-1",
			parentChain:     []string{"project:prj-1", "account:acc-1"},
		},
		registration{
			consumer: "iam", objectType: catalogFormOf(t, "project"), objectID: "prj-1",
			parentChain: []string{"account:acc-1"},
		},
		// Корневой уровень: предка нет по построению, цепи нет — и это НЕ находка.
		registration{consumer: "iam", objectType: catalogFormOf(t, "account"), objectID: "acc-1"},
	)

	examined, missing := uncovered(t, pool)
	t.Logf("осмотрено строк зеркала: %d; без цепи: %d", examined, len(missing))

	if examined == 0 {
		t.Fatal("зеркало пусто — «ноль непокрытых» здесь означало бы «сверять было нечего»")
	}
	if len(missing) != 0 {
		t.Fatalf("гейт нашёл непокрытые на законном множестве: %v", missing)
	}
}

// Сторона дефекта: потребитель цепи НЕ ШЛЁТ — гейт обязан НАЗВАТЬ объект.
//
// Это не искусственная порча состояния: ровно такую регистрацию производит
// сервис, который поле цепи не заполняет. Разница с законной стороной — одно
// поле намерения, всё остальное совпадает.
func TestParentEdgeCompleteness_NamesTheObjectWhoseRegistrationCarriedNoChain(t *testing.T) {
	pool := openPool(t)
	seedThroughProducer(t, pool,
		registration{
			consumer: "vpc (цепь не выслана)", objectType: catalogFormOf(t, "vpc_network"), objectID: "net-1",
			parentProjectID: "prj-1",
		},
		registration{
			consumer: "iam", objectType: catalogFormOf(t, "project"), objectID: "prj-1",
			parentChain: []string{"account:acc-1"},
		},
	)

	examined, missing := uncovered(t, pool)
	t.Logf("осмотрено строк зеркала: %d; без цепи: %d %v", examined, len(missing), missing)

	if len(missing) != 1 || missing[0] != "vpc_network:net-1" {
		t.Fatalf("объект без цепи не назван: %v — молчание здесь неотличимо от честного "+
			"отказа в правах, потому что форма отказа та же", missing)
	}
}

// Производитель ДЕЙСТВИТЕЛЬНО в петле: цепь глубже двух уровней доезжает целиком.
//
// Без этого утверждения законная сторона осталась бы зелёной и у производителя,
// который пишет только первое звено, — а объект, чей ближайший предок не проект
// и не аккаунт, именно так и выпадает из области выдачи.
func TestParentEdgeCompleteness_ProducerWritesEveryLinkOfTheChain(t *testing.T) {
	pool := openPool(t)
	seedThroughProducer(t, pool, registration{
		consumer: "registry", objectType: catalogFormOf(t, "registry_repository"), objectID: "repo-1",
		parentChain: []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"},
	})

	ctx := context.Background()
	rows, err := pool.Query(ctx,
		`SELECT depth, parent_type, parent_id
		   FROM kacho_iam.resource_parent_edge
		  WHERE object_type = 'registry_repository' AND object_id = 'repo-1'
		  ORDER BY depth`)
	if err != nil {
		t.Fatalf("чтение цепи: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var depth int
		var typ, id string
		if err := rows.Scan(&depth, &typ, &id); err != nil {
			t.Fatalf("чтение звена: %v", err)
		}
		got = append(got, typ+":"+id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("обход цепи: %v", err)
	}
	want := []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"}
	if len(got) != len(want) {
		t.Fatalf("звеньев цепи %d, ожидалось %d: %v — усечённая цепь ставит объект под "+
			"предка, под которым он не находится", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("звено %d = %q, ожидалось %q (порядок — от ближайшего к дальнему)",
				i+1, got[i], want[i])
		}
	}
}

// Предпосылка самого гейта: на пустом зеркале он падает, а не молчит.
func TestParentEdgeCompleteness_FailsOnAnEmptyMirror(t *testing.T) {
	pool := openPool(t)
	examined, missing := uncovered(t, pool)
	if examined != 0 || len(missing) != 0 {
		t.Fatalf("пустое зеркало дало осмотрено=%d непокрытых=%d — предпосылка пробы неверна",
			examined, len(missing))
	}
	// Именно этот исход и обязан быть отказом у боевого гейта: «ноль непокрытых»
	// на нуле осмотренных не есть покрытие.
	t.Log("подтверждено: ноль осмотренных отличимо от нуля непокрытых")
}
