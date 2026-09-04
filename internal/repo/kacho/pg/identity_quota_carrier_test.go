// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ ИСКАТЬ СХЕМУ: ПО ПРЕДМЕТУ, А НЕ ПО ИМЕНИ ФАЙЛА
//
// Здесь стояло имя файла миграции, и оно ПЕРЕЖИЛО СВОЙ ПРЕДМЕТ в тот день, когда
// цепь миграций сервиса была сведена в одну первичную: файла не стало, проба
// отказала чтением, а свойство, которое она держала, никуда не делось — оно
// по-прежнему лежит в поставляемой схеме.
//
// Имя файла и не было предметом: миграцию мог бы переименовать перенос, а её
// содержимое — пережить редакцию. Предмет — ОБЪЯВЛЕНИЕ, и по нему же оно
// теперь и ищется. Referent от числа файлов не зависит.

// upBlockOf — исполняемая половина миграции. Половина обязательна: строка,
// снимающая объявление, лежит в откате, и предикат без разделения по блокам
// прочитал бы её как действительность.
func upBlockOf(body string) string {
	up := strings.Index(body, "-- +goose Up")
	down := strings.Index(body, "-- +goose Down")
	if up < 0 {
		return ""
	}
	if down < 0 || down < up {
		return body[up:]
	}
	return body[up:down]
}

var reMigrationVersion = regexp.MustCompile(`^([0-9]+)_`)

// deliveredSchemaDeclaring отдаёт ПОСТАВЛЯЕМУЮ миграцию с наибольшей версией,
// чей блок Up несёт названный якорь.
//
// Наибольшую — потому что goose применяет по числу и последнее объявление
// переживает предыдущие. Читается встроенный набор (`migrations.FS`), а не
// каталог на диске: поставляется именно он, и расхождение диска с поставкой
// сделало бы вердикт пробы утверждением о чужом дереве.
func deliveredSchemaDeclaring(t *testing.T, anchor string) (name, up string) {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err, "поставляемый набор миграций не прочитан: судить не о чем")
	seen, best := 0, -1
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		seen++
		raw, rerr := migrations.FS.ReadFile(e.Name())
		require.NoErrorf(t, rerr, "миграция %s не прочитана: отказ чтения — не пропуск", e.Name())
		block := upBlockOf(string(raw))
		if block == "" || !strings.Contains(block, anchor) {
			continue
		}
		m := reMigrationVersion.FindStringSubmatch(e.Name())
		require.NotNilf(t, m, "у миграции %s нет числовой версии в имени: порядок "+
			"применения по такому имени не установить", e.Name())
		v, cerr := strconv.Atoi(m[1])
		require.NoErrorf(t, cerr, "версия миграции %s не число", e.Name())
		if v > best {
			best, name, up = v, e.Name(), block
		}
	}
	require.NotZerof(t, seen, "в поставляемом наборе НОЛЬ миграций: предпосылка ложна, и "+
		"молчание пробы означало бы «ничего не прочитано»")
	require.NotEmptyf(t, name, "среди %d поставляемых миграций ни одна не объявляет %q: "+
		"это ОТКАЗ, а не согласие — либо якорь пережил свой предмет, либо объявление снято",
		seen, anchor)
	t.Logf("осмотрено миграций %d; действующее объявление %q — %s", seen, anchor, name)
	return name, up
}

// Носитель «личность» назван ОДИНАКОВО в трёх местах, и это проверено, а не
// подразумевается.
//
// Три места: каталог видов (доменная константа), адаптер (литерал, которым он
// адресует строки) и схема (предикат триггера и ограничение столбца). Значение
// принадлежит СХЕМЕ — оно стоит в `carrier_type`, — поэтому у адаптера свой
// литерал, а не ссылка на доменную константу: адаптер обязан называть то, что
// лежит в базе, даже если домен однажды назовёт это иначе.
//
// Цена расхождения асимметрична и потому неочевидна. Разойдись они — списание
// писало бы строки под одним носителем, а чтение спрашивало под другим:
// потребление арендатору показывалось бы нулевым при полном потолке, а отказ
// приходил бы «на пустом месте». Ни сборка, ни одна из сторон по отдельности
// этого не заметят.
func TestIdentityCarrierIsNamedTheSameEverywhere(t *testing.T) {
	t.Parallel()

	require.Equal(t, string(domain.CarrierIdentity), kachopg.CarrierIdentity,
		"каталог видов и адаптер называют носителя по-разному: списание и чтение "+
			"разойдутся по строкам, и ни одна сторона этого не увидит")

	// Схема — третье место, и оно решающее: именно её значение оказывается в
	// столбце. Читается ПОСТАВЛЯЕМАЯ СХЕМА, а не память о ней и не имя файла.
	name, up := deliveredSchemaDeclaring(t, carrierConstraint)
	require.Containsf(t, up, "'"+kachopg.CarrierIdentity+"'",
		"схема (%s) не называет носителя %q ни разу — адаптер адресует строки значением, "+
			"которого в базе нет", name, kachopg.CarrierIdentity)

	set := closedSetOf(t, up, carrierConstraint, "carrier_type")
	require.Containsf(t, set, "'"+kachopg.CarrierIdentity+"'",
		"ограничение %s не перечисляет носителя %q (набор: %s): строка учёта личности "+
			"не вставится вовсе, и потолок молча перестанет действовать",
		carrierConstraint, kachopg.CarrierIdentity, set)

	// ЗЕРКАЛО. Без него «носитель перечислен» было бы верно и на предикате,
	// который вернул полфайла: в таком наборе нашлось бы что угодно.
	require.NotContainsf(t, set, "'нет-такого-носителя'",
		"в разобранный набор попало значение, которого в нём быть не может (%s): "+
			"разобран не набор, а окрестность — и членство в нём ничего не значит", set)
}

// carrierConstraint — имя ограничения, несущего закрытый набор носителей.
//
// ИМЯ, А НЕ КООРДИНАТА: оно одно и то же в обеих формах записи схемы —
// рукописной и в форме свода (`pg_dump`), — тогда как всё остальное в них
// различается.
const carrierConstraint = "project_resource_quotas_carrier_ck"

var (
	// Две ЗАКОННЫЕ формы одного закрытого набора. Рукописная пишет `IN (…)`,
	// свод — `= ANY (ARRAY[…])`. Распознаватель, знающий одну, на второй не
	// краснеет и не зеленеет: он МОЛЧИТ, и «набор не разобран» становится
	// неотличимо от «набор пуст».
	reClosedSetIn  = regexp.MustCompile(`(?s)\bIN\s*\(([^)]*)\)`)
	reClosedSetAny = regexp.MustCompile(`(?s)=\s*ANY\s*\(\s*ARRAY\[([^\]]*)\]\s*\)`)
)

// closedSetOf вырезает закрытый набор значений колонки из НАЗВАННОГО ограничения.
//
// Область поиска ограничена самим ограничением — от его имени до следующего
// `CONSTRAINT` либо конца: у соседнего ограничения той же таблицы свой набор по
// той же колонке, и предикат без границы прочитал бы чужой.
func closedSetOf(t *testing.T, up, constraint, column string) string {
	t.Helper()
	at := strings.Index(up, constraint)
	require.Positivef(t, at, "ограничения %s в поставляемой схеме нет: закрытого набора "+
		"носителей не существует, и потолок не держится ничем", constraint)
	region := up[at+len(constraint):]
	if next := strings.Index(region, "CONSTRAINT "); next > 0 {
		region = region[:next]
	}
	col := strings.Index(region, column)
	require.Positivef(t, col, "ограничение %s не упоминает колонку %s: разбирать нечего",
		constraint, column)
	region = region[col+len(column):]
	if m := reClosedSetIn.FindStringSubmatch(region); m != nil {
		return m[1]
	}
	if m := reClosedSetAny.FindStringSubmatch(region); m != nil {
		return m[1]
	}
	t.Fatalf("закрытый набор колонки %s в ограничении %s не разобран НИ В ОДНОЙ из "+
		"известных форм записи: молчание здесь означало бы «не прочитано», а не "+
		"«носитель перечислен».\nОкрестность: %.200s", column, constraint, region)
	return ""
}

// Вид `iam.account` объявлен с носителем «личность» — и это утверждение о
// КАТАЛОГЕ, а не о константе.
//
// Отрицание рядом с положительным: у соседнего вида того же домена носитель
// ДРУГОЙ. Без него проба зеленела бы и на каталоге, где носитель у всех один.
func TestAccountKindIsCarriedByTheIdentity(t *testing.T) {
	t.Parallel()

	carrier, ok := domain.CarrierOfKind("iam.account")
	require.True(t, ok, "вида `iam.account` в каталоге нет: потолка над аккаунтом не существует")
	require.Equal(t, domain.CarrierIdentity, carrier,
		"аккаунт считается не в личности: носитель обязан быть ВНЕШНИМ по отношению "+
			"к предмету счёта, а проект и аккаунт этому не удовлетворяют by construction")

	neighbour, ok := domain.CarrierOfKind("iam.project")
	require.True(t, ok)
	require.Equal(t, domain.CarrierAccount, neighbour,
		"положительный контроль: у соседнего вида того же домена носитель другой, "+
			"поэтому совпадение выше — свойство записи, а не одинаковость каталога")
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ
//
// Разбор закрытого набора — распознаватель, а распознаватель без инъекции ловит
// написание, а не предмет: на неизвестной ему форме он не краснеет и не
// зеленеет, он МОЛЧИТ. Кормится НАСТОЯЩАЯ поставляемая схема с точечной правкой.

// carrierSetForms — те же значения набора в ДВУХ законных записях: рукописной и
// в форме свода (`pg_dump`).
var carrierSetForms = [2]string{
	"carrier_type = ANY (ARRAY['project'::text, 'account'::text, 'identity'::text, " +
		"'iam.user'::text, 'iam.serviceAccount'::text])",
	"carrier_type IN ('project', 'account', 'identity', 'iam.user', 'iam.serviceAccount')",
}

// carrierSetWithoutIdentity — тот же набор БЕЗ носителя, обе формы.
//
// Правится набор ЦЕЛИКОМ, а не одно значение в нём: подстрока `'identity'::text, `
// стоит и у соседнего ограничения той же таблицы, и точечная правка попала бы в
// чужой набор — то есть инъекция сломала бы не то, о чём отчиталась.
var carrierSetWithoutIdentity = [2]string{
	"carrier_type = ANY (ARRAY['project'::text, 'account'::text, " +
		"'iam.user'::text, 'iam.serviceAccount'::text])",
	"carrier_type IN ('project', 'account', 'iam.user', 'iam.serviceAccount')",
}

// TestIdentityCarrierInjectionRemovedFromTheSetIsSeen — ОБЯЗАН УВИДЕТЬ ПРОПАЖУ.
//
// Носитель снят из набора точечной правкой настоящей схемы. Разбор обязан
// вернуть набор БЕЗ него: вернув его, он читал бы окрестность, а не набор, и
// «носитель перечислен» было бы верно при любом содержимом ограничения.
func TestIdentityCarrierInjectionRemovedFromTheSetIsSeen(t *testing.T) {
	t.Parallel()
	_, up := deliveredSchemaDeclaring(t, carrierConstraint)
	broken, applied := carrierSetEdit(up, carrierSetForms[0], carrierSetWithoutIdentity[0],
		carrierSetForms[1], carrierSetWithoutIdentity[1])
	require.Equalf(t, 1, applied, "правок применено %d вместо одной: набор носителей не "+
		"найден НИ В ОДНОЙ из известных форм записи, и «разбор увидел пропажу» ничего "+
		"не доказывало бы", applied)
	require.NotContainsf(t, closedSetOf(t, broken, carrierConstraint, "carrier_type"),
		"'"+kachopg.CarrierIdentity+"'",
		"разбор вернул носителя, снятого из набора: читается окрестность, а не набор")
}

// TestIdentityCarrierInjectionHandWrittenFormIsReadToo — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Тот же набор, записанный РУКОПИСНОЙ формой. Смысл не меняется ни в одном
// знаке, и разбор обязан прочитать его так же: иначе на дереве, записанном
// рукой, проба молчала бы не потому, что носитель перечислен.
func TestIdentityCarrierInjectionHandWrittenFormIsReadToo(t *testing.T) {
	t.Parallel()
	_, up := deliveredSchemaDeclaring(t, carrierConstraint)
	handWritten := strings.Replace(up, carrierSetForms[0], carrierSetForms[1], 1)
	require.NotEqual(t, up, handWritten, "перевод в рукописную форму не состоялся: "+
		"набор в форме свода в схеме не найден, и молчание разбора ничего не сказало бы "+
		"о второй форме")
	require.Containsf(t, closedSetOf(t, handWritten, carrierConstraint, "carrier_type"),
		"'"+kachopg.CarrierIdentity+"'",
		"разбор не прочитал набор в РУКОПИСНОЙ форме: он судит написание, а не предмет")
}

// TestIdentityCarrierInjectionNeighbourConstraintIsNotRead — ГРАНИЦА ОБЛАСТИ.
//
// У соседних ограничений той же таблицы свой набор по ТОЙ ЖЕ колонке. Разбор без
// границы прочитал бы чужой — и «носитель перечислен» стало бы утверждением о
// соседе. Метка кладётся с ОБЕИХ сторон: и в ограничение перед искомым, и в
// стоящее после.
func TestIdentityCarrierInjectionNeighbourConstraintIsNotRead(t *testing.T) {
	t.Parallel()
	_, up := deliveredSchemaDeclaring(t, carrierConstraint)
	const markBefore, markAfter = "'метка-соседа-сверху'", "'метка-соседа-снизу'"

	before := "CONSTRAINT project_resource_quotas_account_mirror_ck CHECK ("
	after := "CONSTRAINT project_resource_quotas_limit_ck CHECK ("
	require.Containsf(t, up, before, "соседнего ограничения СВЕРХУ в схеме нет: границу "+
		"проверять не на чем, и её «соблюдение» ничего не значило бы")
	require.Containsf(t, up, after, "соседнего ограничения СНИЗУ в схеме нет: то же самое")

	polluted := strings.Replace(up, before,
		before+"carrier_type IN ("+markBefore+") AND ", 1)
	polluted = strings.Replace(polluted, after,
		after+"carrier_type IN ("+markAfter+") AND ", 1)

	set := closedSetOf(t, polluted, carrierConstraint, "carrier_type")
	require.NotContains(t, set, markBefore, "разбор прочитал набор ограничения, стоящего "+
		"ВЫШЕ искомого: область не ограничена сверху")
	require.NotContains(t, set, markAfter, "разбор прочитал набор ограничения, стоящего "+
		"НИЖЕ искомого: область не ограничена снизу")
	require.Containsf(t, set, "'"+kachopg.CarrierIdentity+"'",
		"положительный контроль: свой набор при этом прочитан не был — граница режет "+
			"не там, и отрицания выше зеленели бы на пустом наборе")
}

// carrierSetEdit — точечная правка набора в той форме, которая в схеме есть.
//
// Возвращает число применённых правок: инъекция обязана требовать РОВНО одной,
// иначе «разбор увидел» ничего не доказывает.
func carrierSetEdit(up, dumpOld, dumpNew, handOld, handNew string) (string, int) {
	out, applied := up, 0
	for _, f := range [][2]string{{dumpOld, dumpNew}, {handOld, handNew}} {
		if strings.Contains(out, f[0]) {
			out = strings.Replace(out, f[0], f[1], 1)
			applied++
		}
	}
	return out, applied
}
