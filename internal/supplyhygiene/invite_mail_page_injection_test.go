// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Инъекция держателя «страница не отрицает механизм, который дерево несёт» — В
// ОБЕ СТОРОНЫ И ПО КАЖДОЙ ОСИ.
//
// Осей у держателя две, и они отвечают на РАЗНЫЕ вопросы, поэтому доказываются
// порознь:
//
//  1. РАСПОЗНАВАТЕЛЬ СТРАНИЦЫ. Отрицание существования — находка; условная
//     фраза о ненастроенном узле — молчание. Второе и есть тот текст, которым
//     страницы правятся: без него «покраснело» не отличалось бы от «краснеет на
//     любом упоминании письма».
//  2. ЗАМЕР ЖИВОСТИ ПОЛОСЫ. Дерево с производителями — три из трёх; дерево без
//     них — ноль (тогда отрицание на странице ЗАКОННО); производители, названные
//     только в КОММЕНТАРИИ, — ноль, потому что комментарий ничего не производит.
//
// Дельта каждого мира против его положительного близнеца — ОДИН факт: либо
// формулировка страницы, либо наличие маркера в исполняемой части.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// pageDenies — страница в том виде, в каком она лгала до #2525.
const pageDenies = `## Приглашение

` + "`Operation.metadata`" + ` вернёт ` + "`magicLinkUrl`" + ` — ссылку первого входа, которую админ передаёт
приглашённому вручную (автоотправка email не интегрирована).
`

// pageTellsTheTruth — ЗАКОННЫЙ БЛИЗНЕЦ: тот же предмет, названный фактически.
// Отличается от мира выше ОДНИМ фактом — формулировкой, — и обязан молчать.
const pageTellsTheTruth = `## Приглашение

` + "`Operation.metadata`" + ` вернёт ` + "`magicLinkUrl`" + ` — ссылку первого входа. Автоотправка письма
существует: пока почтовый узел не объявлен ключами ` + "`inviteMail.*`" + `, письмо не уходит и
ссылку передаёт админ.
`

// pageDeniesInEnglish — та же находка на английском: предикат на одном языке
// недобирает МОЛЧА, поэтому словарь двуязычен и это доказывается.
const pageDeniesInEnglish = `## Invite

The admin hands the link over manually: automatic email is not implemented.
`

func TestInviteMailPageInjection_DenialIsAFinding(t *testing.T) {
	claims, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageDenies)})
	require.Equal(t, 1, census.Claims, "отрицание существования обязано быть находкой")
	require.Len(t, claims, 1)
	require.Equal(t, "p.mdx", claims[0].Page)
	require.Equal(t, 4, claims[0].Line, "находка обязана называть строку")
}

func TestInviteMailPageInjection_TruthfulWordingIsSilent(t *testing.T) {
	claims, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageTellsTheTruth)})
	require.NotZerof(t, census.Subjects, "предмет обязан быть ОСМОТРЕН и на законном "+
		"близнеце — иначе молчание означает «не читали», а не «нарушения нет»")
	require.Zero(t, census.Claims, "условная фраза о ненастроенном узле — законна")
	require.Empty(t, claims)
}

func TestInviteMailPageInjection_EnglishDenialIsAFinding(t *testing.T) {
	_, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageDeniesInEnglish)})
	require.Equal(t, 1, census.Claims, "английская форма отрицания обязана находиться")
}

func TestInviteMailPageInjection_EmptyCorpusIsNotClean(t *testing.T) {
	_, census := findAbsenceClaims(map[string][]byte{})
	require.Zero(t, census.Pages)
	require.Zerof(t, census.Subjects, "пустой корпус обязан давать НОЛЬ осмотренного — "+
		"именно на это число держатель и роняет прогон")
}

// writeGo — один исходник синтетического дерева.
func writeGo(t *testing.T, dir, name, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
}

func TestInviteMailLaneProducers_LiveTreeIsFound(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "outbox.go", "package a\n\nconst t = \"kaname.invite_mail_outbox\"\n")
	writeGo(t, dir, "wiring.go", "package a\n\nvar m = \"kaname invite mail drainer starting\"\n")
	writeGo(t, dir, "metrics.go", "package a\n\nconst r = \"kaname_invite_mail_outcomes_total\"\n")

	found, filesRead, err := inviteMailLaneProducers(dir)
	require.NoError(t, err)
	require.Equal(t, 3, filesRead)
	require.Len(t, found, 3, "живая полоса обязана дать все три производителя")
}

func TestInviteMailLaneProducers_TreeWithoutTheLaneIsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "other.go", "package a\n\nconst t = \"kaname.some_other_outbox\"\n")

	found, filesRead, err := inviteMailLaneProducers(dir)
	require.NoError(t, err)
	require.Equal(t, 1, filesRead, "обход обязан состояться — иначе «полосы нет» "+
		"неотличимо от «не искали»")
	require.Emptyf(t, found, "дерево без полосы обязано давать ноль производителей: "+
		"именно в этом мире отрицание на странице ЗАКОННО")
}

func TestInviteMailLaneProducers_CommentIsNotAProducer(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "prose.go", "package a\n\n"+
		"// Полоса пишет в kaname.invite_mail_outbox и считает\n"+
		"// kaname_invite_mail_outcomes_total, а процесс печатает\n"+
		"// kaname invite mail drainer starting.\n")

	found, filesRead, err := inviteMailLaneProducers(dir)
	require.NoError(t, err)
	require.Equal(t, 1, filesRead)
	require.Emptyf(t, found, "комментарий ничего не производит: держатель, читающий "+
		"прозу, признал бы производителем собственное объяснение")
}

func TestInviteMailLaneProducers_TestFileIsNotAProducer(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "x_test.go", "package a\n\nconst t = \"kaname.invite_mail_outbox\"\n")

	found, filesRead, err := inviteMailLaneProducers(dir)
	require.NoError(t, err)
	require.Zerof(t, filesRead, "проба не производит полосу: фикстура, назвавшая очередь, "+
		"выдала бы снятую полосу за живую")
	require.Empty(t, found)
}

// ─────────────────────────────────────────────────────────────────────────────
// ТРЕТЬЯ ОСЬ: СЛОВАРЬ ЗНАЕТ ВСЕ ФОРМЫ, В КОТОРЫХ КОРПУС ПИШЕТ ПРЕДМЕТ
//
// Первая редакция держателя судила предмет ФИКСИРОВАННЫМИ формами, а корпус его
// СКЛОНЯЕТ. Страница, написанная в родительном падеже, оказывалась вне
// наблюдения целиком: не находкой и не чистой, а НЕВИДИМОЙ — держатель молчал,
// и молчание это ничем не отличалось от исправной работы.
//
// Цена измерена: осматривалось 3 вхождения из 5, и обе лживые строки
// first-credential.mdx не читались ни разу. Расширение словаря подняло
// осмотренное 3 → 5 при неизменной прежней полосе — то есть прибавка была
// СЛЕПОЙ ЗОНОЙ, а не регрессией дерева.
//
// Каждая форма доказывается ОТДЕЛЬНО: форма, о которой распознаватель не знает,
// не даёт ни красного, ни зелёного.

// pageDeniesInflected — предмет в родительном падеже, отрицание голое. Ровно
// тот текст, что жил на странице до второго захода #2525.
const pageDeniesInflected = `## Что должно быть до начала

Администратор передаёт ссылку приглашённому вручную — автоматической отправки
письма в продукте нет.
`

// pageInflectedButTruthful — ЗАКОННЫЙ БЛИЗНЕЦ склонённой формы: тот же падеж,
// то же слово «нет» на странице, но отрицание НЕ управляет предметом — оно
// стоит за пределами узкого окна и относится к другому предмету.
const pageInflectedButTruthful = `## Что должно быть до начала

Автоматическая отправка письма в продукте есть: пока не объявлен почтовый узел,
письмо не уходит и ссылку передаёт администратор.

Отдельно, про другое: команды входа в терминале, отдающей токен, — нет; первое
удостоверение человека рождается в браузере.
`

// pageNegationInsideAWord — «нет» внутри слова отрицанием не является. Без
// границы слова держатель нашёл бы его в «интернет» и покраснел бы на тексте,
// который ничего не отрицает.
// Слово с «нет» внутри стоит ВПЛОТНУЮ к предмету — иначе оно вне узкого окна, и
// проба зеленела бы при снятой границе слова, ничего не проверив. Первая
// редакция этой фикстуры отставила его на ~90 байт и была именно такой.
const pageNegationInsideAWord = `## Приглашение

Автоотправка идёт через интернет, как только объявлен почтовый узел.
`

// pageDeniesBareEnglish — голое отрицание английской формы.
const pageDeniesBareEnglish = `## Invite

The admin hands the link over manually: there is no automatic email in the product.
`

func TestInviteMailPageInjection_InflectedSubjectIsSeen(t *testing.T) {
	_, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageDeniesInflected)})
	require.NotZerof(t, census.Subjects, "склонённая форма предмета обязана быть ОСМОТРЕНА: "+
		"форма, о которой распознаватель не знает, не даёт ни красного, ни зелёного — "+
		"она невидима, и это худший исход из трёх")
}

func TestInviteMailPageInjection_InflectedDenialIsAFinding(t *testing.T) {
	claims, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageDeniesInflected)})
	require.Equal(t, 1, census.Claims, "склонённый предмет с голым отрицанием — находка")
	require.Len(t, claims, 1)
	require.Equal(t, 3, claims[0].Line, "находка обязана называть строку")
}

func TestInviteMailPageInjection_FarNegationIsSilent(t *testing.T) {
	claims, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageInflectedButTruthful)})
	require.NotZerof(t, census.Subjects, "предмет обязан быть осмотрен и на близнеце")
	require.Zerof(t, census.Claims, "голое «нет», не управляющее предметом, отрицанием НЕ "+
		"является: узкое окно и есть та граница, ради которой заведён второй словарь")
	require.Empty(t, claims)
}

func TestInviteMailPageInjection_NegationInsideAWordIsNotADenial(t *testing.T) {
	_, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageNegationInsideAWord)})
	require.NotZero(t, census.Subjects)
	require.Zerof(t, census.Claims, "«нет» внутри «интернет» отрицанием не является — "+
		"без границы слова держатель краснел бы на правдивом тексте")
}

func TestInviteMailPageInjection_BareEnglishDenialIsAFinding(t *testing.T) {
	_, census := findAbsenceClaims(map[string][]byte{"p.mdx": []byte(pageDeniesBareEnglish)})
	require.Equal(t, 1, census.Claims, "корпус двуязычен: словарь на одном языке "+
		"недобирает МОЛЧА")
}

func TestInviteMailPageInjection_OverlappingPatternsCountSubjectOnce(t *testing.T) {
	// Вход подобран так, что под него подходят ДВА образца сразу: и «автоматическ…
	// + отправк…», и «автоматически + отправ…». Форма корявая, и именно поэтому
	// взята: на грамотном тексте образцы не пересекаются, и проба, написанная на
	// нём, зеленела бы при снятом схлопывании, ничего не проверив. Первая
	// редакция этой пробы была именно такой.
	const overlapping = "автоматически отправка писем"

	var matched int
	for _, re := range subjectPatterns {
		matched += len(re.FindAllStringIndex(overlapping, -1))
	}
	require.Equalf(t, 2, matched, "фикстура обязана быть ДЕЙСТВИТЕЛЬНО перекрывающейся: "+
		"вход, под который подходит один образец, о схлопывании не утверждает ничего")

	// Перепись объявлена объёмом ОСМОТРЕННОГО: сосчитав вхождение дважды,
	// держатель отчитался бы о работе, которой не делал.
	require.Len(t, subjectOccurrences(overlapping), 1,
		"перекрывающиеся образцы дают ОДНО вхождение")
}
