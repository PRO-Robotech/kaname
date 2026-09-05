// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// applyall_test.go — применение ВСЕЙ доставки как одного действия (задача #1034).
//
// # Почему это отдельный глагол, а не цикл в композиционном корне
//
// Корень провязывает, а не решает. Что применение идёт МОДУЛЬ ЗА МОДУЛЕМ, каждый
// своей транзакцией; что порядок детерминирован; что отказ называет модуль и
// останавливает применение; что перепись складывается по всем модулям — это
// решения, и место им рядом с применителем, а не в цикле, который следующий
// сервис перепишет по-своему.
//
// # Что здесь НЕ утверждается
//
// О базе эти пробы не говорят НИЧЕГО: писатель подставной, и он нарочно
// снисходительнее настоящего — атомарность, замок, порядок ключа и
// идемпотентность оператором доказаны против живой Postgres
// (`module_catalog_applier_integration_test.go`). Здесь предмет один: КАК
// применитель обходит доставку и что он о ней говорит.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// recordingWriter — подставной писатель, ведущий ЖУРНАЛ вызовов.
//
// Журнал, а не счётчик: предмет проб — ПОРЯДОК обхода доставки, и счётчик о нём
// не говорит ничего.
type recordingWriter struct {
	calls []string
	// failOnModule — модуль, на котором писатель отказывает. Отказ приходит на
	// строке модуля: он первый, поэтому «применение остановилось» отличимо от
	// «применение прошло наполовину».
	failOnModule string
	// unchangedModules — модули, чья строка уже стоит: `changed=false`.
	unchangedModules map[string]bool
	// audited — следы применения, дошедшие до писателя.
	audited []modulecatalog.AppliedEvent
	// resettleAuthor / pruneAuthor — АВТОР, с которым звали обе ведомости (#2005).
	// Захватывается, а не игнорируется: «автор доехал до писателя» и «автор
	// записан в строку» — разные факты, и первый проверяется здесь, без базы.
	resettleAuthor string
	pruneAuthor    string
}

var errWriterRefused = errors.New("подставной писатель отказал")

func (w *recordingWriter) LockCatalog(context.Context) error {
	w.calls = append(w.calls, "lock")
	return nil
}

func (w *recordingWriter) LockModuleResources(_ context.Context, module string) error {
	w.calls = append(w.calls, "lock_resources:"+module)
	return nil
}

func (w *recordingWriter) ReadModule(_ context.Context, module string) (catalog.Rows, error) {
	w.calls = append(w.calls, "read:"+module)
	return catalog.Rows{}, nil
}

// ReadCatalog — вход сверки опоры (шаг 8 применителя).
//
// Эти пробы идут по пути СТАРТА (`modulecatalog.NewApplier`), а он сверку опоры
// не делает: её делает страж сразу после применения, и его отказ есть отказ
// пуска. Значит метод здесь НЕ ЗОВЁТСЯ — и записывает он это в журнал вызовов
// намеренно: появись «read_catalog» в переписи пути старта, полосы перепутаны, и
// проба скажет об этом, а не промолчит.
//
// Отдаёт при этом каталог, СОШЕДШИЙСЯ с опорой: если полосы всё же перепутают,
// падать проба обязана на журнале вызовов — по предмету, — а не на сверке, до
// которой её предмет не касается.
func (w *recordingWriter) ReadCatalog(context.Context) (modulecatalog.CatalogState, error) {
	w.calls = append(w.calls, "read_catalog")
	return modulecatalog.NewCatalogState(seed.LiteralRows(), catalog.Rows{}), nil
}

func (w *recordingWriter) UpsertModule(_ context.Context, module string) (bool, error) {
	w.calls = append(w.calls, "module:"+module)
	if module == w.failOnModule {
		return false, errWriterRefused
	}
	return !w.unchangedModules[module], nil
}

func (w *recordingWriter) UpsertResource(_ context.Context, r catalog.ResourceRow) (bool, error) {
	w.calls = append(w.calls, "resource:"+r.Module+"."+r.Resource)
	return !w.unchangedModules[r.Module], nil
}

func (w *recordingWriter) UpsertVerb(_ context.Context, v catalog.VerbRow) (bool, error) {
	w.calls = append(w.calls, "verb:"+v.Module+"."+v.Resource+"."+v.Verb)
	return !w.unchangedModules[v.Module], nil
}

func (w *recordingWriter) ResettleTenantProjections(_ context.Context,
	_ []catalog.ResourceRow, _ []catalog.VerbRow, _ string, appliedBy string) (modulecatalog.Resettled, error) {
	w.calls = append(w.calls, "resettle")
	w.resettleAuthor = appliedBy
	return modulecatalog.Resettled{}, nil
}

func (w *recordingWriter) RetireVerb(_ context.Context, v catalog.VerbRow, _ string) (bool, error) {
	w.calls = append(w.calls, "retire_verb:"+v.Module+"."+v.Resource+"."+v.Verb)
	return true, nil
}

func (w *recordingWriter) RetireResource(_ context.Context, r catalog.ResourceRow, _ string) (bool, error) {
	w.calls = append(w.calls, "retire_resource:"+r.Module+"."+r.Resource)
	return true, nil
}

func (w *recordingWriter) PruneRetiredSelectorTypes(_ context.Context,
	_ []catalog.ResourceRow, appliedBy string) (modulecatalog.Pruned, error) {
	w.calls = append(w.calls, "prune")
	w.pruneAuthor = appliedBy
	return modulecatalog.Pruned{}, nil
}

// ConfirmModuleState — вход подтверждения (шаг 2 применителя).
//
// Эти пробы идут по пути СТАРТА, а он подтверждения не несёт by construction:
// доставка применяется целиком, плана не было. Значит метод здесь НЕ ЗОВЁТСЯ —
// и записывает он это в журнал вызовов намеренно: появись «confirm» в переписи
// пути старта, полосы перепутаны, и проба скажет об этом, а не промолчит.
func (w *recordingWriter) ConfirmModuleState(context.Context, string, string) (bool, error) {
	w.calls = append(w.calls, "confirm")
	return true, nil
}

// EmitApplied — след применения (шаг 11).
//
// Записывает АКТОРА, а не факт вызова: предмет следа — кто применил, и журнал,
// хранящий только «emit», зеленел бы на записи с подставленным автором.
func (w *recordingWriter) EmitApplied(_ context.Context, ev modulecatalog.AppliedEvent) error {
	w.calls = append(w.calls, "audit:"+ev.Actor+":"+ev.Source)
	w.audited = append(w.audited, ev)
	return nil
}

// recordingTx — исполнитель транзакций над одним писателем. Считает ОТКРЫТЫЕ
// транзакции: «одна транзакция на модуль» иначе нечем утверждать.
type recordingTx struct {
	w       *recordingWriter
	txOpen  int
	txErrs  int
	rolled  int
	commits int
}

func (r *recordingTx) RunInWriteTx(ctx context.Context,
	fn func(context.Context, modulecatalog.CatalogWriter) error) error {
	r.txOpen++
	if err := fn(ctx, r.w); err != nil {
		r.txErrs++
		r.rolled++
		return err
	}
	r.commits++
	return nil
}

func fixtureManifest(module string, resources ...string) *manifest.Manifest {
	m := &manifest.Manifest{APIVersion: "iam/v1", Module: module}
	for _, name := range resources {
		m.Resources = append(m.Resources, manifest.Resource{
			// `objectType` проставляется всегда: манифест без него негоден —
			// его отвергают загрузчик, деривация и схема. Фикстура без поля
			// была снисходительнее продукта (#1816).
			ObjectType: module + "_" + name,
			Name:       name,
			Verbs:      []manifest.Verb{{Name: "get"}},
		})
	}
	return m
}

// TestApplyAllWalksEveryManifestInOrderAndOnePerTransaction — доставка
// применяется ЦЕЛИКОМ, в порядке подачи, по одной транзакции на модуль.
//
// Порядок утверждается ЖУРНАЛОМ, а не числом: два модуля, применённые в обратном
// порядке, дают то же число вызовов.
func TestApplyAllWalksEveryManifestInOrderAndOnePerTransaction(t *testing.T) {
	w := &recordingWriter{}
	tx := &recordingTx{w: w}
	applier := modulecatalog.NewApplier(tx)

	census, err := applier.ApplyAll(context.Background(), []*manifest.Manifest{
		fixtureManifest("alpha", "widgets"),
		fixtureManifest("beta", "gadgets"),
	})
	require.NoError(t, err)

	require.Equal(t, 2, census.Applied, "применено манифестов не два: %s", census)
	require.Equal(t, 2, tx.txOpen,
		"транзакций открыто %d — «одна транзакция на модуль» держится ЭТИМ числом, "+
			"а не комментарием", tx.txOpen)
	require.Equal(t, 2, tx.commits)
	require.Zero(t, tx.rolled)

	// Порядок: сперва весь alpha, затем весь beta. Смешение означало бы, что
	// применитель обходит доставку не по модулям.
	joined := strings.Join(w.calls, " ")
	alphaAt := strings.Index(joined, "module:alpha")
	betaAt := strings.Index(joined, "module:beta")
	require.NotEqual(t, -1, alphaAt)
	require.NotEqual(t, -1, betaAt)
	require.Less(t, alphaAt, betaAt,
		"доставка применена не в порядке подачи — при отказе на середине состояние "+
			"каталога зависело бы от порядка обхода каталога доставки: %v", w.calls)
	require.Contains(t, w.calls, "resource:alpha.widgets")
	require.Contains(t, w.calls, "resource:beta.gadgets")
}

// TestApplyAllStopsOnTheFirstRefusalAndNamesTheModule — отказ ОСТАНАВЛИВАЕТ
// применение и НАЗЫВАЕТ модуль.
//
// Продолжать нельзя: применитель — производитель каталога, и «часть модулей
// применилась, часть нет, и мы не сказали какая» есть состояние, которое
// оператору нечем разобрать. Перепись при этом возвращается ВСЕГДА, иначе «отказ
// на первом» неотличим от «отказ на последнем».
func TestApplyAllStopsOnTheFirstRefusalAndNamesTheModule(t *testing.T) {
	w := &recordingWriter{failOnModule: "beta"}
	tx := &recordingTx{w: w}
	applier := modulecatalog.NewApplier(tx)

	census, err := applier.ApplyAll(context.Background(), []*manifest.Manifest{
		fixtureManifest("alpha", "widgets"),
		fixtureManifest("beta", "gadgets"),
		fixtureManifest("gamma", "gizmos"),
	})
	require.Error(t, err, "отказ писателя не доехал до вызывающего — старт продолжился бы "+
		"с каталогом, которого никто не производил")
	require.ErrorIs(t, err, modulecatalog.ErrWriteFailed)
	require.Contains(t, err.Error(), "beta",
		"отказ не назвал модуль — оператор пойдёт разбирать не тот манифест: %v", err)

	require.Equal(t, 1, census.Applied,
		"перепись не называет, сколько успело примениться до отказа: %s", census)
	require.Equal(t, 2, tx.txOpen,
		"после отказа применение продолжилось — третий модуль применяться не должен")
	require.NotContains(t, w.calls, "module:gamma",
		"применение не остановилось на первом отказе: %v", w.calls)
}

// TestApplyAllReportsNoChangeWhenTheCatalogAlreadyMatches — перепись отличает
// «применено и сдвинуло» от «применено и совпало».
//
// Это и есть ответ на «идемпотентно ли применение доставки целиком»: второй
// подряд старт обязан сказать «изменений ноль». Без этой величины «применили» не
// отличается от «прошли мимо».
func TestApplyAllReportsNoChangeWhenTheCatalogAlreadyMatches(t *testing.T) {
	w := &recordingWriter{unchangedModules: map[string]bool{"alpha": true, "beta": true}}
	tx := &recordingTx{w: w}
	applier := modulecatalog.NewApplier(tx)

	census, err := applier.ApplyAll(context.Background(), []*manifest.Manifest{
		fixtureManifest("alpha", "widgets"),
		fixtureManifest("beta", "gadgets"),
	})
	require.NoError(t, err)
	require.Equal(t, 2, census.Applied)
	require.False(t, census.Changed(),
		"применение к совпадающему каталогу объявлено изменившим — «применили» перестало "+
			"отличаться от «прошли мимо»: %s", census)
	require.Zero(t, census.ChangedModules)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию выше: без него `Changed()==false` было бы
	// зелено и у переписи, которая ничего не считает.
	w2 := &recordingWriter{}
	census2, err2 := modulecatalog.NewApplier(&recordingTx{w: w2}).ApplyAll(
		context.Background(), []*manifest.Manifest{fixtureManifest("alpha", "widgets")})
	require.NoError(t, err2)
	require.True(t, census2.Changed(),
		"применение к ПУСТОМУ каталогу объявлено не изменившим — перепись не считает: %s", census2)
	require.Equal(t, 1, census2.ChangedModules)
}

// TestApplyAllOnAnEmptyDeliveryTouchesNothing — доставки нет: применять нечего,
// и это НЕ отказ.
//
// Незаявленная доставка — законное состояние (`config.ManifestsConfig`: пустой
// каталог означает «доставка не объявлена»), и применитель обязан отличать её от
// сорванной: сорванную отвергает читатель доставки, до применителя она не
// доходит вовсе.
func TestApplyAllOnAnEmptyDeliveryTouchesNothing(t *testing.T) {
	w := &recordingWriter{}
	tx := &recordingTx{w: w}

	census, err := modulecatalog.NewApplier(tx).ApplyAll(context.Background(), nil)
	require.NoError(t, err,
		"пустая доставка отвергнута — посадка, её не объявившая, перестала бы подниматься")
	require.Zero(t, census.Applied)
	require.False(t, census.Changed())
	require.Zero(t, tx.txOpen,
		"на пустой доставке открыта транзакция — применитель трогает базу там, где "+
			"применять нечего")
	require.Empty(t, w.calls)
}

// TestApplyAllRefusesAnUnderivableManifestBeforeOpeningATransaction — манифест,
// из которого не выводятся строки, отвергается ДО открытия транзакции.
//
// Отдельный отказ, а не общий: он чинится правкой манифеста, а не состоянием
// базы, и слив их в один текст, мы отправили бы оператора разбирать базу.
//
// # Здесь стояла проверка ПУСТОГО ИМЕНИ МОДУЛЯ — её премиса была неверна
//
// Первая редакция подавала манифест без имени модуля и ждала `ErrDerive`.
// Деривация имени модуля не судит, и это ПРАВИЛЬНО: пустое имя отвергает КЛЮЧ
// (`catalog_module_nonempty CHECK (module <> ”)`, миграция
// `20260901113757_rule_segments_have_a_referent.sql:132`) — инвариант внутри
// одной БД держится конструкцией БД, а не software-проверкой (запрет #10).
// Утверждать это подставным писателем нельзя ВОВСЕ: он снисходительнее
// настоящего by construction, и проба зеленела бы на дублирующей проверке в коде
// ровно так же, как на ключе. Ключ утверждается против живой Postgres —
// `TestModuleCatalogApplyAllIsRefusedByTheKeyOnAnEmptyModuleName`.
//
// Реальный и достижимый здесь класс — другой: имя РЕСУРСА и имя ДЕЙСТВИЯ судит
// сама деривация, и её отказ обязан прийти до транзакции.
func TestApplyAllRefusesAnUnderivableManifestBeforeOpeningATransaction(t *testing.T) {
	w := &recordingWriter{}
	tx := &recordingTx{w: w}

	census, err := modulecatalog.NewApplier(tx).ApplyAll(context.Background(),
		[]*manifest.Manifest{{
			APIVersion: "iam/v1", Module: "alpha",
			Resources: []manifest.Resource{{Name: "  ", ObjectType: "alpha_widgets", Verbs: []manifest.Verb{{Name: "get"}}}},
		}})
	require.Error(t, err)
	require.ErrorIs(t, err, modulecatalog.ErrDerive)
	require.Contains(t, err.Error(), "alpha",
		"отказ деривации не назвал модуль — оператор пойдёт разбирать не тот манифест: %v", err)
	require.Zero(t, census.Applied)
	require.Zero(t, tx.txOpen,
		"негодный манифест дошёл до транзакции — отказ разбора смешался бы с отказом базы")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же манифест с непустым именем ресурса проходит.
	// Без него отрицание выше зеленело бы на применителе, отвергающем всякий вход.
	w2 := &recordingWriter{}
	tx2 := &recordingTx{w: w2}
	census2, err2 := modulecatalog.NewApplier(tx2).ApplyAll(context.Background(),
		[]*manifest.Manifest{{
			APIVersion: "iam/v1", Module: "alpha",
			Resources: []manifest.Resource{{Name: "widgets", ObjectType: "alpha_widgets", Verbs: []manifest.Verb{{Name: "get"}}}},
		}})
	require.NoError(t, err2)
	require.Equal(t, 1, census2.Applied)
	require.Equal(t, 1, tx2.txOpen)
}
