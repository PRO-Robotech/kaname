// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0081_retire_operator_sa_integration_test.go — снятие служебной
// учётки сетевого оператора и всего, что ей выдано.
//
// # Предмет
//
// Миграция 0076 сняла мёртвый веер оператора — роль, привязку, селекторы — и
// намеренно оставила две вещи: строку служебной учётки и кластерный кортеж
// `system_viewer@cluster:cluster_kacho_root` из посева 0010. 0081 снимает обе.
//
// # Почему это не снятие живого
//
// Кортеж адресован ОДНОМУ субъекту. `cluster.system_viewer` объявлен в модели
// как `[user, service_account]` — прямое назначение без userset и без `from`,
// поэтому он не раскрывается ни на кого, кроме своего субъекта. Довод 0076 про
// «второго, действующего читателя» верен по наблюдению и не о том предмете: там
// перечислены читатели ОТНОШЕНИЯ (пол внутреннего листенера, чтение
// инфра-чувствительного поля у vpc), а не держатели ЭТОГО кортежа. Живые
// читатели держат СВОИ кортежи — их сеет 0014 для api-gateway / vpc / compute,
// и здесь это утверждается положительным контролем: после снятия у оператора
// все три остаются на месте.
//
// Предпосылка «отношение прямое» проверяется отдельно и по модели, а не по
// памяти: сделают его производным — контроль покраснеет раньше, чем кто-то
// сошлётся на этот файл как на разрешение снять чужой кортеж.
//
// # Чем это НЕ является
//
// Утверждения ниже не про «строк стало меньше»: у каждого отрицания есть
// положительный контроль на том же запросе. Пустая база, разъехавшийся предикат
// и несделанный посев дали бы «ноль у оператора» даром.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
)

// operatorSubjectSQL / operatorSVASQL — детерминированные выражения личности
// оператора, те же, что в посеве 0009/0010 и в самой 0081. Проба пинит ИМЕННО
// его строки, а не похожие.
const (
	operatorSVASQL     = `'sva' || substr(md5('kacho-vpc-operator'), 1, 17)`
	operatorSubjectSQL = `'service_account:' || (` + operatorSVASQL + `)`
)

// readerSvcsKeptByRetirement — модули, чьи кортежи `system_viewer@cluster`
// обязаны пережить снятие (посев 0014). Это положительная половина: без неё
// «у оператора ноль» неотличимо от «выкосили всех».
var readerSvcsKeptByRetirement = []string{"api-gateway", "vpc", "compute"}

func countSQL(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, q, args...).Scan(&n))
	return n
}

// operatorSAPresent / operatorWriteIntents / operatorDeleteIntents — три
// наблюдаемых, по которым судится снятие.
func operatorSAPresent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	return countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = `+operatorSVASQL)
}

func operatorWriteIntents(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	return countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.write'
		    AND payload->>'user' = `+operatorSubjectSQL)
}

func operatorDeleteIntents(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	return countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.delete'
		    AND payload->>'relation' = 'system_viewer'
		    AND payload->>'object'   = 'cluster:cluster_kacho_root'
		    AND payload->>'user'     = `+operatorSubjectSQL)
}

func readerTuplesIntact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, when string) {
	t.Helper()
	for _, svc := range readerSvcsKeptByRetirement {
		subject := `'service_account:' || ('sva' || substr(md5('kacho-` + svc + `'), 1, 17))`
		require.Equal(t, 1, countSQL(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.service_accounts
			  WHERE id = 'sva' || substr(md5('kacho-`+svc+`'), 1, 17)`),
			"%s: учётка модуля %q обязана остаться — снимается ОДИН субъект, а не класс", when, svc)
		require.Equal(t, 1, countSQL(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE event_type = 'fga.tuple.write'
			    AND payload->>'relation' = 'system_viewer'
			    AND payload->>'object'   = 'cluster:cluster_kacho_root'
			    AND payload->>'user'     = `+subject),
			"%s: кортеж system_viewer@cluster модуля %q обязан остаться: он ЕГО, а не оператора — "+
				"именно это различие 0076 и упустил", when, svc)
		require.Zero(t, countSQL(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE event_type = 'fga.tuple.delete'
			    AND payload->>'user' = `+subject),
			"%s: модулю %q выписан отзыв кортежа — снятие вышло за своего субъекта", when, svc)
	}
}

// TestMigration0081_RetiresOperatorIdentityAndItsGrants — до миграции учётка и её
// кластерный кортеж на месте; после — учётки нет, невыданных намерений нет,
// выданный кортеж отозван; у трёх живых читателей всё цело.
func TestMigration0081_RetiresOperatorIdentityAndItsGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 80)

	// ── ДО: предпосылка. Без неё «ноль после» получено бы даром.
	totalSAsBefore := countSQL(t, ctx, pool, `SELECT count(*) FROM kacho_iam.service_accounts`)
	t.Logf("осмотрено на версии 80: служебных учёток=%d", totalSAsBefore)
	require.NotZero(t, totalSAsBefore, "предпосылка нарушена: посев не завёл ни одной служебной учётки")
	require.Equal(t, 1, operatorSAPresent(t, ctx, pool),
		"предпосылка нарушена: на версии 80 учётки оператора нет — снимать было бы нечего")
	require.Equal(t, 1, operatorWriteIntents(t, ctx, pool),
		"предпосылка нарушена: на версии 80 нет кортежа system_viewer@cluster оператора (посев 0010)")
	readerTuplesIntact(t, ctx, pool, "до снятия")

	// ── Применяем РЕАЛЬНУЮ 0081 через goose (не копию её текста).
	require.NoError(t, applyOneMore(t, db),
		"миграция 0081 не применилась: снятие учётки оператора ещё не написано")

	// ── ПОСЛЕ.
	require.Zero(t, operatorSAPresent(t, ctx, pool),
		"учётка оператора осталась: предъявить её некому — ни каталога модуля, ни чарта, "+
			"выпускающего её сертификат, — а строка в таблице принципалов это место, куда "+
			"выдача приезжает без чьего-либо решения")
	require.Zero(t, operatorWriteIntents(t, ctx, pool),
		"у оператора осталось невыданное намерение выдачи: доставленное позже отзыва вернуло бы кортеж")
	require.Equal(t, 1, operatorDeleteIntents(t, ctx, pool),
		"отзыв кортежа system_viewer@cluster не поставлен в очередь: удаление строки посева стирает "+
			"запись о намерении, а не сам кортеж в хранилище отношений")
	require.Equal(t, 0, countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.access_bindings
		  WHERE subject_type = 'service_account' AND subject_id = `+operatorSVASQL),
		"у оператора осталась привязка")
	require.Equal(t, 0, countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.access_binding_subjects
		  WHERE subject_type = 'service_account' AND subject_id = `+operatorSVASQL),
		"оператор остался со-получателем чужой привязки")

	require.Equal(t, totalSAsBefore-1, countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.service_accounts`),
		"снята не ровно одна учётка — радиус снятия шире своего субъекта")
	readerTuplesIntact(t, ctx, pool, "после снятия")

	// ── Повторное применение ТЕЛА той же миграции: строгий no-op.
	//
	// Гоняем настоящий текст файла, а не его пересказ: копия разошлась бы с
	// оригиналом и проверяла бы себя.
	require.NoError(t, applyMigrationUpBody(t, db, "0081"),
		"повторное применение 0081 отказало — на базе, где учётки уже нет, миграция обязана быть no-op")
	require.Zero(t, operatorSAPresent(t, ctx, pool), "повтор: учётка вернулась")
	require.Zero(t, operatorWriteIntents(t, ctx, pool), "повтор: намерение выдачи вернулось")
	require.Equal(t, 1, operatorDeleteIntents(t, ctx, pool),
		"повтор задвоил отзыв: очередь обязана нести ровно одно намерение на кортеж")
	readerTuplesIntact(t, ctx, pool, "после повтора")
}

// TestMigration0081_PremiseClusterSystemViewerIsDirectOnly — предпосылка снятия,
// проверенная по модели.
//
// Всё рассуждение 0081 держится на одном свойстве: `cluster.system_viewer` —
// ПРЯМОЕ назначение, поэтому кортеж не раскрывается ни на кого, кроме своего
// субъекта, и снятие у одного субъекта не трогает других. Сделают отношение
// производным (`or …` / `… from …`) — рассуждение перестанет быть верным, и
// узнать об этом надо здесь, а не из отчёта о доступе.
//
// Контроль в обе стороны: рядом с прямым отношением разбирается заведомо
// ПРОИЗВОДНОЕ из той же модели — если предикат не отличает одно от другого, он
// не измеряет свойство и «прямое» получено даром.
func TestMigration0081_PremiseClusterSystemViewerIsDirectOnly(t *testing.T) {
	model := readFGAModel(t)

	systemViewer, ok := clusterRelationBody(model, "system_viewer")
	require.True(t, ok, "в модели не найдено `define system_viewer` у типа cluster — "+
		"предпосылка снятия недоказуема, а её отсутствие незаметно")
	require.NotContains(t, systemViewer, " from ",
		"cluster.system_viewer стал производным (%q): кортеж больше не ограничен своим субъектом, "+
			"и довод, по которому 0081 сняла кортеж оператора, надо перепроверять", systemViewer)
	require.NotContains(t, systemViewer, " or ",
		"cluster.system_viewer получил дизъюнкт (%q): см. выше", systemViewer)

	// Контроль: `viewer` у того же типа ПРОИЗВОДНОЕ — предикат обязан это увидеть.
	viewer, ok := clusterRelationBody(model, "viewer")
	require.True(t, ok, "контроль: в модели не найдено `define viewer` у типа cluster")
	require.Contains(t, viewer, " or ",
		"контроль: cluster.viewer больше не производное (%q) — предикат перестал различать прямое "+
			"и производное, значит утверждение о system_viewer получено даром", viewer)
}

// readFGAModel читает каноничную модель прав из proto-дерева — источник истины, а
// не копию в чарте, которая генерируется из неё.
func readFGAModel(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "..", "..",
		"proto", "kacho", "cloud", "iam", "v1", "fga_model.fga")
	b, err := os.ReadFile(path) // #nosec G304 -- фиксированный путь в дереве репозитория
	require.NoError(t, err, "не прочитана модель прав %s", path)
	require.NotEmpty(t, b, "модель прав пуста — предпосылка проверялась бы на пустоте")
	return string(b)
}

// clusterRelationBody возвращает правую часть `define <rel>:` внутри блока
// `type cluster`. Разбор ограничен блоком намеренно: то же имя отношения
// встречается у других типов с другим телом, и общий поиск по файлу ответил бы
// про чужой тип.
func clusterRelationBody(model, rel string) (string, bool) {
	lines := strings.Split(model, "\n")
	inCluster := false
	typeRe := regexp.MustCompile(`^type\s+(\w+)`)
	defRe := regexp.MustCompile(`^\s*define\s+` + regexp.QuoteMeta(rel) + `\s*:\s*(.*)$`)
	for _, ln := range lines {
		if m := typeRe.FindStringSubmatch(ln); m != nil {
			inCluster = m[1] == "cluster"
			continue
		}
		if !inCluster {
			continue
		}
		if m := defRe.FindStringSubmatch(ln); m != nil {
			return strings.TrimSpace(m[1]), true
		}
	}
	return "", false
}
