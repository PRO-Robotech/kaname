// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_channel_has_a_listener_integration_test.go — канал уведомления читается
// по ЖИВОЙ схеме, а не по тексту миграций.
//
// # Почему по живой схеме
//
// Текстовый предикат по `pg_notify('…')` в файлах миграций считает производителем
// и то объявление, чей предмет уже снят более поздней миграцией. Такая находка
// ложна, а ложная находка выключает проверку быстрее, чем её чинят: перепись
// того же класса по дереву дала три канала без слушателя, и один из трёх
// (`storage_outbox`) оказался именно этим — таблицу сняли, объявление осталось.
//
// Поэтому здесь проигрывается вся цепь миграций и спрашивается ИТОГОВОЕ
// состояние: какие триггеры живы и что делают их функции.
//
// # Половина, которой здесь НЕ БЫЛО: потребитель (задача #1398)
//
// Имя файла обещало слушателя, а утверждалось только одно — что канал ПРОИЗВОДИТСЯ
// или не производится. Слушателя не спрашивал никто. Разница не academic: канал
// `kacho_iam_subject_outbox_added` лишился своего дренажа (задача #1024, направление
// развёрнуто — журнал читает потребитель курсором), и проба осталась зелёной, потому
// что триггер на месте. Хуже того, этот канал стоял тут ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ с
// подписью «у которого слушатель ЕСТЬ» — то есть файл утверждал ложное ровно в том
// месте, которое доказывает, что отрицание рядом не вакуумно.
//
// Поэтому здесь спрашиваются ОБЕ стороны и в одном прогоне:
//
//	производитель — живая схема (какой триггер что шлёт);
//	потребитель   — дерево (называет ли прод-код это имя как имя канала).
//
// Половинчатая проверка этот класс не ловит by construction: со стороны схемы канал
// без слушателя выглядит ровно как канал со слушателем, а со стороны дерева
// снятый триггер выглядит ровно как никогда не заводившийся.
package migrations_test

import (
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// TestIntegration_SessionRevokedChannelHasNoProducerLeft — регрессия на снятие
// канала, у которого не было и не могло быть потребителя (#755).
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт session_revoked» зеленело бы и на пустом ответе — на опечатке в запросе, на
// не накатившейся схеме, на переименованной колонке каталога.
func TestIntegration_SessionRevokedChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #755.
	assert.NotContains(t, channels, "session_revoked",
		"канал снят вместе с триггером: слушателя у него нет и построить его нельзя — "+
			"у края нет драйвера Postgres, а прямое чтение базы iam краем это ban #8")

	// Положительный контроль на том же запросе, в том же прогоне: канал, у которого
	// слушатель ЕСТЬ, производителя сохранил.
	//
	// Здесь стоял `kacho_iam_subject_outbox_added` — и он перестал быть контролем
	// раньше, чем его сняли: слушателя у него не осталось (#1024), то есть подпись
	// «у которого слушатель ЕСТЬ» стала ложной при зелёной пробе. Контроль
	// перепривязан к каналу, чей слушатель ПРОВЕРЯЕТСЯ — соседним утверждением
	// этого же файла, а не подписью.
	assert.Contains(t, channels, notifyChannelWithAProvenConsumer,
		"рабочий канал очереди обязан остаться — если пропал и он, снято лишнее, "+
			"а не только беспотребительское")
}

// TestIntegration_AuditEventChannelHasNoProducerLeft — регрессия на снятие
// канала журнала аудита (#795).
//
// Отдельной пробой, а не строкой в соседней: предметы РАЗНЫЕ. Там канал сняли,
// потому что его слушателем по замыслу был край, а край слушать не может by
// construction. Здесь — потому что уведомление будило доставку, которой не
// существовало. Доставка появилась (#812), и канал всё равно не вернулся: вывоз
// журнала будится ОПРОСОМ, потому что требования к задержке доставки аудита
// нет, а канал — это ещё одно соединение со своим переподключением и своим
// отказом (решение и предикат пересмотра — в реестре отступлений iam,
// audit-outbox-has-no-receiver.md, имя файла историческое). Свернуть два разных
// основания в одну пробу значило бы оставить в дереве одно из них — и следующий
// читатель применил бы не то.
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт audit_event» зеленело бы и на пустом ответе — на опечатке в запросе, на
// не накатившейся схеме, на переименованной колонке каталога.
func TestIntegration_AuditEventChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #795.
	assert.NotContains(t, channels, "audit_event",
		"канал снят вместе с триггером: вывоз журнала будится опросом, и возвращать "+
			"канал не за чем — задержка доставки аудита ничем не ограничена")

	// Положительный контроль на том же запросе, в том же прогоне.
	//
	// Здесь стоял `kacho_iam_fga_outbox` с подписью «канал очереди tuple'ов, у
	// которого слушатель ЕСТЬ», и подпись была ЛОЖНОЙ при зелёной пробе: дренаж
	// журнала намерений снят вместе с внешним движком отношений, а свёртка прямого
	// факта синхронна (0098) — будить некого. Сам канал снят миграцией
	// 20260829123045, его регрессия — notify_channel_intent_journal_integration_test.go
	// (#1436).
	//
	// Контроль, потерявший предмет, и есть половина, которая доказывает, что
	// отрицание рядом не вакуумно, — поэтому он перепривязан к каналу, чей
	// потребитель ЖИВ и назван прод-кодом (`repo/kacho/pg/reconcile_notify.go`,
	// `LISTEN` на reconcileOutboxChannel).
	//
	// Имя вынесено в [notifyChannelWithAProvenConsumer], а не выписано литералом,
	// потому что свойство «у этого канала есть потребитель» здесь не ОБЪЯВЛЯЕТСЯ, а
	// проверяется: потеряй он потребителя — краснеет
	// [TestIntegration_EveryProducedNotifyChannelIsNamedByAConsumer], а не подпись в
	// комментарии. Обе прежние подписи разошлись с деревом именно молча, и каждая
	// стояла ровно в том месте, которое доказывает, что отрицание рядом не вакуумно.
	assert.Contains(t, channels, notifyChannelWithAProvenConsumer,
		"рабочий канал очереди обязан остаться — если пропал и он, снято "+
			"лишнее, а не только беспотребительское")

	// И третье, ради чего проба нужна больше двух предыдущих: ТАБЛИЦА цела.
	// Снят был канал, а не журнал; проба, утверждающая только отсутствие канала,
	// зеленела бы и на миграции, снёсшей вместе с ним весь аудит.
	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kacho_iam.audit_outbox') IS NOT NULL`).
		Scan(&exists))
	assert.True(t, exists,
		"журнал аудита обязан остаться: снималось объявление уведомления, а не таблица")
}

// freshIamSchema — пустая БД с целиком накатанной цепью миграций iam.
func freshIamSchema(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(db, "."), "цепь миграций обязана накатиться целиком")
	return db
}

// notifyChannelsProducedBy — каналы, которые шлёт хоть одна функция ЖИВОГО
// триггера схемы kacho_iam.
//
// Читается каталог, а не файлы: функция без триггера ничего не шлёт, и триггер,
// снятый поздней миграцией, производителем не является.
func notifyChannelsProducedBy(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT DISTINCT p.prosrc
		  FROM pg_trigger tg
		  JOIN pg_proc p ON p.oid = tg.tgfoid
		  JOIN pg_class c ON c.oid = tg.tgrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE NOT tg.tgisinternal
		   AND n.nspname = 'kacho_iam'
		   AND p.prosrc ILIKE '%pg_notify%'`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var channels []string
	for rows.Next() {
		var src string
		require.NoError(t, rows.Scan(&src))
		channels = append(channels, notifyChannelLiterals(src)...)
	}
	require.NoError(t, rows.Err())
	return channels
}

// notifyChannelLiterals — имена каналов из тела функции: первый аргумент каждого
// pg_notify, взятый как строковый литерал.
func notifyChannelLiterals(src string) []string {
	var out []string
	rest := src
	for {
		i := strings.Index(rest, "pg_notify(")
		if i < 0 {
			return out
		}
		rest = rest[i+len("pg_notify("):]
		open := strings.Index(rest, "'")
		if open < 0 {
			return out
		}
		close := strings.Index(rest[open+1:], "'")
		if close < 0 {
			return out
		}
		out = append(out, rest[open+1:open+1+close])
		rest = rest[open+1+close:]
	}
}

// notifyChannelWithAProvenConsumer — канал, который в этом файле служит
// ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ: у него есть и живой производитель, и потребитель.
//
// Он вынесен в одно имя, а не выписан у каждого утверждения, ровно потому, что
// прежние два контроля разошлись с деревом по отдельности и молча. Само его
// свойство здесь не объявляется, а ПРОВЕРЯЕТСЯ —
// [TestIntegration_EveryProducedNotifyChannelIsNamedByAConsumer] требует
// потребителя от каждого производимого канала, включая этот. Потеряй он
// потребителя — краснеет тот гейт, а не подпись в комментарии.
const notifyChannelWithAProvenConsumer = "kacho_iam_resource_reconcile_outbox"

// TestIntegration_SubjectChangeChannelHasNoProducerLeft — регрессия на снятие
// канала журнала смены субъекта (#1398).
//
// Отдельной пробой, а не строкой в соседней: основание СВОЁ. У #755 слушателя не
// было никогда; здесь слушатель БЫЛ и снят решением — дренаж, толкавший
// инвалидацию краю, убран вместе с обратным ребром (#1024), а журнал остался и
// читается потребителем курсором (`InternalIAMService.PollSubjectChanges`).
// Свернуть разные основания в одну пробу значило бы оставить в дереве одно из
// них, и следующий читатель применил бы не то.
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт kacho_iam_subject_outbox_added» зеленело бы и на пустом ответе.
func TestIntegration_SubjectChangeChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #1398.
	assert.NotContains(t, channels, "kacho_iam_subject_outbox_added",
		"канал снят вместе с триггером: дренаж, который его слушал, убран вместе с "+
			"ребром iam→край (#1024), а потребитель читает журнал курсором и в базу "+
			"владельца прав не ходит (ban #8)")

	// Положительный контроль на том же запросе, в том же прогоне.
	assert.Contains(t, channels, notifyChannelWithAProvenConsumer,
		"рабочий канал очереди обязан остаться — если пропал и он, снято лишнее, "+
			"а не только беспотребительское")

	// И третье: ЖУРНАЛ цел. Снималось объявление уведомления, а не журнал, —
	// его читает потребитель, и проба, утверждающая только отсутствие канала,
	// зеленела бы и на миграции, снёсшей вместе с ним весь журнал.
	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kacho_iam.subject_change_outbox') IS NOT NULL`).
		Scan(&exists))
	assert.True(t, exists,
		"журнал смены субъекта обязан остаться: его читает край курсором по id")
}

// notifyChannelConsumerExemptions — производимые каналы БЕЗ потребителя, законные
// по решению: у каждого назван предмет, в котором решение принимается.
//
// Ведомость ИСТЕКАЕТ САМА: запись, которой больше нечего прощать, — находка.
// Без этого свойства снятый канал оставил бы за собой прощение, и следующий
// беспотребительский, названный так же, уехал бы под него незамеченным.
//
// Ведомость не «список известного красного»: она не вычитается из вердикта молча,
// а печатается в переписи и обязана назвать задачу. Прощение без предмета — это
// подпорка, за которой никто не отвечает.
//
// # Сегодня она ПУСТА, и это цель, а не поломка
//
// Единственная её запись прощала `kacho_iam_fga_outbox` (#1436) — канал, чей дренаж
// был снят вместе с внешним движком отношений. Прощение прожило ровно до того, как
// предмет сняли: триггер убран миграцией 20260829123045, регрессия —
// notify_channel_intent_journal_integration_test.go. Схема канала больше не
// производит, прощать нечего, запись снята.
//
// Снял её не человек по памяти, а САМ ЭТОТ ГЕЙТ: на первом же прогоне после переноса
// он покраснел строкой «прощение потеряло предмет». Это и есть то свойство, ради
// которого ведомость устроена так, а не списком, — и это же единственный законный
// способ её сократить. Пустая ведомость на гейте ПРОХОДИТ: он падает на записи без
// предмета, а не на их отсутствии, — иначе запись держали бы ради зелёного.
var notifyChannelConsumerExemptions = map[string]string{}

// TestIntegration_EveryProducedNotifyChannelIsNamedByAConsumer — гейт КЛАССА:
// у канала есть либо производитель И потребитель, либо ни того ни другого.
//
// # Почему обе стороны в ОДНОМ прогоне
//
// Это разрыв, невидимый ни с одной стороны по отдельности: схема говорит «триггер
// жив» и права; дерево говорит «чтения канала на месте» и тоже право; не сходятся
// они только вместе. Две пробы по половине остались бы зелёными обе.
//
// # Чем судится потребитель
//
// Имя канала, СВЯЗАННОЕ прод-кодом как имя канала: значение объявления, чьё имя
// оканчивается на `Channel`, либо значение поля `Channel` в составном литерале.
// Узел синтаксического дерева, а не подстрока, — поэтому комментарий, пример в
// шапке и имя типа исключены BY CONSTRUCTION.
//
// Контроль предиката, ради которого выбрана эта форма: текстовый поиск
// `"kacho_iam_fga_outbox"` по не-тестовым файлам Go находит ДВА вхождения, и оба —
// комментарии (`pkg/outbox/drainer/doc.go`, пример объявления; `drainer.go`,
// пояснение поля). Текстовый предикат объявил бы у этого канала потребителя,
// которого нет, — то есть промолчал бы ровно на предмете гейта.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. имя, СОБРАННОЕ из кусков либо прочитанное из настройки: литерала нет вовсе,
//     судить нечего;
//  2. имя, переданное в чтение канала не через `Channel` и не через объявление с
//     таким именем (например позиционным аргументом собственной обёртки). Ошибка
//     здесь идёт в сторону НАХОДКИ, а не молчания: канал будет назван
//     беспотребительским при живом потребителе — и это верное направление ошибки
//     для гейта, потому что находка разбирается, а молчание нет.
//
// Обратная сторона (потребитель называет канал, которого схема не производит)
// здесь НЕ судится и не по недосмотру: в этом дереве прод-код законно называет
// каналы ЧУЖИХ схем (`compute_fga_outbox`, `nlb_…`), и их производителей эта
// схема не содержит by construction. Вопрос «кому принадлежит названный канал»
// решается у владельца своей схемы, а не здесь.
func TestIntegration_EveryProducedNotifyChannelIsNamedByAConsumer(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	produced := uniqueSorted(notifyChannelsProducedBy(t, db))
	named, files, literals := notifyChannelNamesInProdGo(t)

	t.Logf("перепись: схема производит каналов %d (%s); дерево: не-тестовых файлов Go "+
		"разобрано %d, строковых литералов осмотрено %d, имён каналов связано %d; "+
		"в ведомости прощений %d",
		len(produced), strings.Join(produced, ", "), files, literals, len(named),
		len(notifyChannelConsumerExemptions))

	// Предпосылки: ни одно отрицание ниже не имеет смысла на пустой переписи.
	require.NotEmpty(t, produced,
		"схема не производит НИ ОДНОГО канала — либо цепь не накатилась, либо запрос "+
			"к каталогу читает не то; на такой переписи гейт зеленеет, ничего не проверив")
	require.NotEmpty(t, named,
		"в дереве не связано НИ ОДНОГО имени канала — разбор перестал видеть предмет, "+
			"и тогда беспотребительским он объявит беспотребительским всякий канал, а не найденный")

	findings := unpairedChannels(produced, named)
	if len(findings) > 0 {
		t.Errorf("канал производится и не потребляется — %d шт.:\n  %s\n\n"+
			"Уведомление шлётся на каждой строке и не будит никого: механизм объявлен, "+
			"производителя эффекта у него нет. Со стороны это неотличимо от работающего "+
			"быстрого пути, и следующий читатель построит на нём вывод.\n"+
			"Снятие: либо завести слушателя, либо снять триггер НОВОЙ миграцией (образцы — "+
			"755001, 795001), либо внести канал в notifyChannelConsumerExemptions, назвав "+
			"задачу, в которой решение принимается.",
			len(findings), strings.Join(findings, "\n  "))
	}

	// Ведомость истекает сама: прощать больше нечего — снимайте запись.
	producedSet := make(map[string]bool, len(produced))
	for _, ch := range produced {
		producedSet[ch] = true
	}
	var stale []string
	for ch := range notifyChannelConsumerExemptions {
		if !producedSet[ch] {
			stale = append(stale, ch)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("прощение потеряло предмет — %d запись(и):\n  %s\n\n"+
			"Схема этот канал больше не производит, а прощение осталось. Следующий "+
			"беспотребительский канал с тем же именем уехал бы под него незамеченным.\n"+
			"Снятие: убрать запись из notifyChannelConsumerExemptions.",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// notifyChannelNamesInProdGo — имена каналов, СВЯЗАННЫЕ прод-кодом дерева.
//
// Возвращает вместе с ними объём осмотренного: «ноль имён» на нуле файлов и «ноль
// имён» на четырёх тысячах — разные утверждения, и вызывающий обязан их различать.
func notifyChannelNamesInProdGo(t *testing.T) (names map[string]bool, files, literals int) {
	t.Helper()

	paths, err := treecorpus.UnderWithSuffix(repoRootFromMigrations(t), ".go")
	require.NoError(t, err, "состав дерева взять неоткуда — вердикт был бы свойством "+
		"рабочего каталога, а не коммита")

	names = make(map[string]bool)
	for _, abs := range paths {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git этого же дерева
		if rerr != nil {
			continue
		}
		found, seen, perr := channelNamesBoundIn(abs, src)
		if perr != nil {
			// Файл, который не разбирается, судить нечем. Он не считается
			// прочитанным — иначе объём осмотренного завысился бы.
			continue
		}
		files++
		literals += seen
		for _, n := range found {
			names[n] = true
		}
	}
	return names, files, literals
}

// channelNamesBoundIn — имена каналов, связанные ОДНИМ файлом, и число
// осмотренных в нём строковых литералов.
//
// Связыванием считаются две формы, и обе — узлы синтаксического дерева:
//
//	const fooChannel = "kacho_x"      // объявление, чьё имя оканчивается на Channel
//	drainer.Config{Channel: "kacho_x"} // поле составного литерала
//
// Комментарий строковым литералом не является, поэтому пример в шапке пакета и
// пояснение поля сюда не попадают — ровно то, ради чего разбор синтаксический.
func channelNamesBoundIn(rel string, src []byte) (names []string, literals int, err error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, 0, err
	}

	add := func(e ast.Expr) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return
		}
		v, uerr := strconv.Unquote(lit.Value)
		if uerr != nil || v == "" {
			return
		}
		names = append(names, v)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				literals++
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if i >= len(node.Values) || !strings.HasSuffix(name.Name, "Channel") {
					continue
				}
				add(node.Values[i])
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && key.Name == "Channel" {
				add(node.Value)
			}
		}
		return true
	})
	return names, literals, nil
}

// repoRootFromMigrations — корень рабочего дерева: ближайший вверх каталог с go.mod.
func repoRootFromMigrations(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatal("не найден корень репозитория (каталог с go.mod)")
		}
		dir = parent
	}
}

// uniqueSorted — детерминированный вход для утверждений и переписи.
func uniqueSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
