// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_verb_sole_writer_integration_test.go — контракт ОСТАВШЕГОСЯ ЕДИНСТВЕННОГО
// писателя проекции «роль → тип объекта × глагол».
//
// Приёмка `role-verb-projection-sole-writer.md`, сценарии IAM-RV-1-02, -03, -09.
//
// # Почему эти три пробы здесь, а не у досева
//
// Проекция есть СОСТОЯНИЕ роли, и держит его слой репозитория: форму строки,
// отображение отказов и транзакционность. После сведения писателей досев обязан
// звать этот же метод через порт — значит его контракт становится контрактом
// ОБОИХ путей, и закреплять его надо там, где он живёт, а не там, где его зовут.
//
// # Что здесь ЗАМЕЩЕНО и чем — сказано прямо
//
// Приёмка формулирует -02 и -03 через вызовы клиента (`RoleService.Create` /
// `Update` + поллинг операции). Пробы ниже подают тот же вход слоем ниже: пары
// берутся ТОЙ ЖЕ производственной функцией перевода, которой пользуются оба пути
// (`authzmap.RoleVerbsFromSelectors(rules.MaterializingSelectors())`), а не
// вычисляются проверкой по-своему. Замещение сужает утверждение: о транспорте,
// операции и правах эти пробы не говорят НИЧЕГО, и их зелёный этого не покрывает.

import (
	stderrors "errors"

	"context"
	"sort"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// roleVerbPairsOf — перевод правил в пары ТОЙ ЖЕ функцией, что у обоих путей
// записи. Своя копия перевода в пробе завела бы второе место, знающее
// соответствие, и разошлась бы с продуктом молча.
func roleVerbPairsOf(rules domain.Rules) []domain.RoleVerb {
	return authzmap.RoleVerbsFromSelectors(rules.MaterializingSelectors())
}

// writeRoleVerbs — вызов писателя через ПОРТ, в собственной транзакции.
func writeRoleVerbs(t *testing.T, ctx context.Context, repo kanamerepo.Repository,
	roleID domain.RoleID, pairs []domain.RoleVerb) error {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err, "открыть транзакцию записи")
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	if verr := w.RolesW().ReplaceRoleVerbs(ctx, roleID, pairs); verr != nil {
		return verr
	}
	if cerr := w.Commit(ctx); cerr != nil {
		return cerr
	}
	committed = true
	return nil
}

// projectionOf — пары роли из таблицы, отсортированные: колонки порядка не
// несут, поэтому утверждать надо СОСТАВ, а не последовательность.
func projectionOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID domain.RoleID) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT object_type, verb FROM kaname.role_verb WHERE role_id = $1`, string(roleID))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ot, v string
		require.NoError(t, rows.Scan(&ot, &v))
		out = append(out, ot+"/"+v)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// pairsAsStrings — те же пары в той же форме, что читает `projectionOf`.
func pairsAsStrings(pairs []domain.RoleVerb) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.ObjectType+"/"+p.Verb)
	}
	sort.Strings(out)
	return out
}

// IAM-RV-1-02 — путь роли кладёт проекцию (ХАРАКТЕРИЗУЮЩИЙ ЗАМОК).
//
// Замок, а не RED: поведение дерево уже даёт, и проба заводится затем, чтобы оно
// ПЕРЕЖИЛО снятие второй реализации. Требовать от неё красноты запрещено §5.0
// приёмки — ослабление зелёного сценария ради красноты есть порча пробы.
func TestIAMRV102_RoleWritePathPutsTheProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv102")
	acc := seedAccount(t, ctx, repo, "acc-rv102", owner)
	roleID := seedAccountRole(t, ctx, pool, acc.ID, "rv102_role")

	rules := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "update"}}}
	pairs := roleVerbPairsOf(rules)
	require.NotEmptyf(t, pairs, "правило не даёт ни одной пары — утверждение ниже было бы "+
		"вакуумным: оно выполнялось бы на писателе, не пишущем ничего")

	require.NoError(t, writeRoleVerbs(t, ctx, repo, roleID, pairs))

	t.Logf("осмотрено пар правила: %d", len(pairs))
	require.Equal(t, pairsAsStrings(pairs), projectionOf(t, ctx, pool, roleID),
		"проекция роли обязана нести РОВНО пары этого правила — по составу, не по порядку")
}

// IAM-RV-1-03 — правка СНИМАЕТ глагол из проекции (ХАРАКТЕРИЗУЮЩИЙ ЗАМОК).
//
// Замена ПОЛНАЯ, а не досыпка: глагол, снятый из правил, обязан исчезнуть.
// Досыпка означала бы, что отзыв права не применяется, — причём молча, потому что
// добавление проходит успешно и проверка «строки записаны» этого не заметит.
func TestIAMRV103_UpdateRemovesAVerbAndKeepsTheRest(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv103")
	acc := seedAccount(t, ctx, repo, "acc-rv103", owner)
	roleID := seedAccountRole(t, ctx, pool, acc.ID, "rv103_role")

	before := roleVerbPairsOf(domain.Rules{
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "update"}},
	})
	after := roleVerbPairsOf(domain.Rules{
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get"}},
	})
	require.NotEmpty(t, after, "правило после правки не даёт ни одной пары — проба не отличила "+
		"бы снятие ОДНОГО глагола от обнуления проекции")
	require.Greaterf(t, len(before), len(after),
		"правка обязана снимать хотя бы одну пару, иначе утверждение вакуумно (было %d, стало %d)",
		len(before), len(after))

	require.NoError(t, writeRoleVerbs(t, ctx, repo, roleID, before))
	require.Equal(t, pairsAsStrings(before), projectionOf(t, ctx, pool, roleID))

	require.NoError(t, writeRoleVerbs(t, ctx, repo, roleID, after))

	got := projectionOf(t, ctx, pool, roleID)
	t.Logf("пар было %d, стало %d", len(before), len(got))
	require.Equal(t, pairsAsStrings(after), got,
		"снятый глагол обязан исчезнуть, а остальные пары остаться — иначе проба не отличает "+
			"снятие от обнуления")
	require.NotEmpty(t, got, "проекция обнулена целиком: это НЕ снятие одного глагола")
}

// IAM-RV-1-09 — пустая пара отвергается КОДОМ КОНТРАКТА, и ни одна пара роли не
// записана.
//
// Приёмка относит сценарий к RED, потому что пробы, утверждающей это КАК КОНТРАКТ
// оставшегося единственного писателя, нет ни одной: свойство в дереве есть и
// после сведения обязано пережить снятие копии, а не быть унаследованным молча.
//
// Частичная проекция ХУЖЕ отсутствующей: роль объявляет право, которого в ней
// нет, и вердикт по её выдаче отказывает молча.
//
// # Почему утверждается КОД, а не просто «пришла ошибка»
//
// Инвариант держит БАЗА — ограничения `role_verb_type_nonempty` и
// `role_verb_verb_nonempty` миграции 0085, — а не код Go (запрет #10). Отсюда
// объявленная приёмкой (§7) ось инъекции «снять проверку пустоты в оставшемся
// писателе» НЕИСПОЛНИМА ПО ПОСТРОЕНИЮ: программной проверки в писателе больше
// нет, а была она строгим подмножеством ограничений базы и вдобавок ЗАСЛОНЯЛА их
// ответ. Замер обеих полос на одном и том же входе:
//
//	проверка Go   → *errors.errorString, sentinel'а НЕТ,
//	                текст `role_verb: пустая пара ("","get")`
//	ограничение БД → ErrInvalidArg, текст «Illegal argument: value violates a constraint»
//
// То есть отказ приезжал вызывающему НЕКЛАССИФИЦИРОВАННЫМ там, где база отвечает
// кодом, который конвенции и предписывают за отказ проверки входа, — и приезжал
// первым, потому что проверка стояла до вставки.
//
// Мёртвая ось заменена двумя живыми, и обе ходят в ту сторону, откуда беда
// приходит на самом деле:
//
//	завести в писателе проверку, заслоняющую базу своим кодом → код перестаёт
//	  быть INVALID_ARGUMENT → эта проба краснеет;
//	снять ограничение базы новой миграцией → отказа нет вовсе → краснеет
//	  утверждение ниже о том, что отказ пришёл.
//
// Утверждается при этом НАБЛЮДАЕМОЕ — код и состояние проекции, — а не то, какой
// слой ответил: слой есть решение, которое вправе смениться, а контракт нет.
func TestIAMRV109_EmptyPairIsRefusedAndNothingIsWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv109")
	acc := seedAccount(t, ctx, repo, "acc-rv109", owner)
	roleID := seedAccountRole(t, ctx, pool, acc.ID, "rv109_role")

	lawful := roleVerbPairsOf(domain.Rules{
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get"}},
	})
	require.NotEmpty(t, lawful, "законный набор пуст — положительный контроль был бы вакуумным")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПЕРВЫМ: набор без пустых пар записывается целиком.
	// Без него отрицание ниже зеленело бы на писателе, отвергающем всё.
	require.NoError(t, writeRoleVerbs(t, ctx, repo, roleID, lawful))
	require.Equal(t, pairsAsStrings(lawful), projectionOf(t, ctx, pool, roleID))

	for name, broken := range map[string][]domain.RoleVerb{
		"пустой тип":    append(append([]domain.RoleVerb{}, lawful...), domain.RoleVerb{ObjectType: "", Verb: "get"}),
		"пустой глагол": append(append([]domain.RoleVerb{}, lawful...), domain.RoleVerb{ObjectType: "iam.role", Verb: ""}),
	} {
		t.Run(name, func(t *testing.T) {
			err := writeRoleVerbs(t, ctx, repo, roleID, broken)
			require.Errorf(t, err, "пара с пустым полем принята: перевод дал НИЧЕГО, и записать "+
				"это тихо значит потерять право, которое роль объявляет")
			require.Truef(t, stderrors.Is(err, iamerr.ErrInvalidArg),
				"отказ пришёл НЕКЛАССИФИЦИРОВАННЫМ (%T: %v) — а обязан нести код отказа "+
					"проверки входа. Неклассифицированная ошибка доезжает до края фиксированным "+
					"INTERNAL, то есть вызывающему сообщается поломка службы там, где он прислал "+
					"негодный вход и в силах его починить", err, err)

			// Ни одна пара из отвергнутого набора не записана: транзакция отката
			// оставляет прежнее состояние целиком.
			require.Equal(t, pairsAsStrings(lawful), projectionOf(t, ctx, pool, roleID),
				"после отказа проекция роли изменилась — частичная проекция хуже отсутствующей")
		})
	}
}
