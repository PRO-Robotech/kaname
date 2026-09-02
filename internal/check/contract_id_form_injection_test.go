// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта формы идентификатора УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом (contract_id_form_test.go) на чистом дереве зелен, и это ничего не
// говорит о том, умеет ли он краснеть. Здесь ему подаются дефекты — по одному на
// каждое написание, которым этот корпус приводит пример идентификатора, — и рядом
// с каждым стоит ЗАКОННЫЙ БЛИЗНЕЦ той же формы, на котором гейт обязан молчать.
// Без второй половины проверка ловила бы написание, а не существо, и первый же
// ложный срабат её отключил бы.

// TestScannerKnowsEveryWritingOfAnIDExample — распознаватель видит пример
// идентификатора в КАЖДОМ написании корпуса. Написание, которого он не знает, —
// не редкость, а слепая зона: всё, записанное так, оказывается вне наблюдения.
func TestScannerKnowsEveryWritingOfAnIDExample(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		prefix string
		sep    string
	}{
		{"многоточие слитно", "// Account id (`acc…`).", "acc", ""},
		{"многоточие дефис", "// Account id (`acc-…`).", "acc", "-"},
		{"многоточие подчёркивание", "// Account id (`acc_…`).", "acc", "_"},
		{"xxx подчёркивание", `//   "user:<usr_xxx>"`, "usr", "_"},
		{"xxx слитно", `//   "user:<usrxxx>"`, "usr", ""},
		{"угловая скобка с цифрой, дефис", "// форма `mbr-<17>`.", "mbr", "-"},
		{"угловая скобка с цифрой, слитно", "// новый формат `soc<17-crockford>`", "soc", ""},
		{"угловая скобка со словом body", "// legacy `soc_<body>` принимается", "soc", "_"},
		{"регулярное выражение", "// Must match `^usr_[0-9a-hjkmnp-tv-z]{17}$`", "usr", "_"},
		{"объявление формы, дефис", "// Resource id prefix: `usr-`.", "usr", "-"},
		{"объявление формы, слитно", "// Resource id prefix: `usr`.", "usr", ""},
		{"объявление формы, подчёркивание", "// Resource id prefix: `cag_`.", "cag", "_"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanIDExamples(c.text)
			require.Lenf(t, got, 1, "написание %q не распознано ни разу — слепая зона", c.text)
			require.Equal(t, c.prefix, got[0].prefix)
			require.Equal(t, c.sep, got[0].sep, "разделитель прочитан неверно: %q", got[0].raw)
		})
	}
}

// TestScannerIsSilentOnTextThatOnlyLOOKSLikeAnID — законные близнецы. Без них
// распознаватель ловил бы форму, а не существо, и его сняли бы на первом же
// ложном срабате.
func TestScannerIsSilentOnTextThatOnlyLOOKSLikeAnID(t *testing.T) {
	legal := []string{
		"  map<string, string> labels = 4;",
		"  repeated string list<string> = 1;",
		"// TLS endpoint either (the `Internal…Service` name matches `HasInternalSuffix`,",
		"// Anchor object id (`cluster_kacho_root`).",
		"// `system:<bootstrap>` — the literal principal of the seeding flow.",
		"// access_bindings ⋈ roles — a within-DB JOIN.",
		"// The account is not a request field — it is resolved from the subject.",
	}
	for _, line := range legal {
		require.Emptyf(t, scanIDExamples(line),
			"на законной строке распознаватель нашёл пример идентификатора: %q", line)
	}
}

// TestJudgeFlagsAFormTheProductDoesNotMint — вердикт по одному примеру: неверный
// разделитель — находка, верный — молчание. Пара по каждому построению.
func TestJudgeFlagsAFormTheProductDoesNotMint(t *testing.T) {
	pairs := []struct {
		name      string
		defect    idExample
		legalTwin idExample
	}{
		{
			"слитная форма против дефиса",
			idExample{prefix: "usr", sep: "-", raw: "usr-…"},
			idExample{prefix: "usr", sep: "", raw: "usr…"},
		},
		{
			"слитная форма против подчёркивания",
			idExample{prefix: "grp", sep: "_", raw: "grp_xxx"},
			idExample{prefix: "grp", sep: "", raw: "grp…"},
		},
		{
			"дефисный канон против слитной формы",
			idExample{prefix: "lim", sep: "", raw: "lim…"},
			idExample{prefix: "lim", sep: "-", raw: "lim-…"},
		},
		{
			"подчёркивание против слитной формы",
			idExample{prefix: "cag", sep: "", raw: "cag<17>"},
			idExample{prefix: "cag", sep: "_", raw: "cag_<17>"},
		},
		{
			"SQL-чеканка дефисом против слитной формы",
			idExample{prefix: "mbr", sep: "", raw: "mbr<17>"},
			idExample{prefix: "mbr", sep: "-", raw: "mbr-<17>"},
		},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			require.NotEmptyf(t, judgeExample(p.defect),
				"дефект %q принят как годный", p.defect.raw)
			require.Emptyf(t, judgeExample(p.legalTwin),
				"законная форма %q объявлена находкой", p.legalTwin.raw)
		})
	}
}

// TestJudgeFlagsAPrefixThatIsNotInTheTable — префикс без строки таблицы есть
// находка, а не умолчание: сверить его форму не с чем.
func TestJudgeFlagsAPrefixThatIsNotInTheTable(t *testing.T) {
	require.NotEmpty(t, judgeExample(idExample{prefix: "zzz", sep: "-", raw: "zzz-…"}),
		"неизвестный префикс прошёл молча — гейт объявил бы «расхождений 0» о том, чего не сверял")
}

// TestLegacyLedgerSilencesOnlyItsOwnEntry — послабление гасит РОВНО своё
// написание. Половина без второй превратила бы ведомость в маску.
func TestLegacyLedgerSilencesOnlyItsOwnEntry(t *testing.T) {
	require.Empty(t, judgeExample(idExample{prefix: "soc", sep: "_", raw: "soc_<body>"}),
		"запись ведомости не погасила своё же написание")
	require.NotEmpty(t, judgeExample(idExample{prefix: "usr", sep: "_", raw: "usr_<body>"}),
		"ведомость погасила чужое написание — она стала маской")
}

// TestProducerCheckFailsWhenTheMintingSiteIsGone — доказательство, что проверка
// производителя способна упасть: строка со ссылкой на несуществующее место
// чеканки обязана быть названа.
func TestProducerCheckFailsWhenTheMintingSiteIsGone(t *testing.T) {
	root := monorepoRoot(t)

	alive, filesAlive := prefixesWithoutAProducer(t, root,
		[]mintedPrefix{{"usr", mintConcatenated, "ids.NewID(domain.PrefixUser)", []string{"services/iam"}}})
	require.NotZero(t, filesAlive, "обход пуст — контроль беспредметен")
	require.Empty(t, alive, "живое место чеканки объявлено исчезнувшим")

	gone, filesGone := prefixesWithoutAProducer(t, root,
		[]mintedPrefix{{"usr", mintConcatenated, "ids.NewID(domain.PrefixThatWasRetired)", []string{"services/iam"}}})
	require.NotZero(t, filesGone, "обход пуст — контроль беспредметен")
	require.Len(t, gone, 1, "исчезнувшее место чеканки прошло молча")
}

// TestLegacyLedgerEntryExpiresWithItsAcceptor — запись послабления, чьей
// принимающей проверки в миграциях больше нет, обязана быть названа.
func TestLegacyLedgerEntryExpiresWithItsAcceptor(t *testing.T) {
	root := monorepoRoot(t)

	alive, filesAlive := legacyFormsWithoutASubject(t, root,
		[]legacyAcceptedForm{{"soc", "_", "'^soc_?[0-9a-hjkmnp-tv-z]{17}$'"}})
	require.NotZero(t, filesAlive, "обход миграций пуст — контроль беспредметен")
	require.Empty(t, alive, "живое послабление объявлено истёкшим")

	expired, filesExpired := legacyFormsWithoutASubject(t, root,
		[]legacyAcceptedForm{{"zzz", "_", "'^zzz_?[0-9a-hjkmnp-tv-z]{17}$'"}})
	require.NotZero(t, filesExpired, "обход миграций пуст — контроль беспредметен")
	require.Len(t, expired, 1, "послабление без предмета прошло молча")
}

// TestGateReadsTheContractThatIsActuallyOnDisk — предпосылка обхода: каталог
// контракта существует и непуст. «Ноль расхождений» на пустом обходе значило бы
// «ноль прочитанного», а не «ноль находок».
func TestGateReadsTheContractThatIsActuallyOnDisk(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(monorepoRoot(t), iamContractDir))
	require.NoError(t, err)
	protos := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".proto" {
			protos++
		}
	}
	require.NotZero(t, protos, "контракт iam пуст — обход гейта беспредметен")
	t.Logf("перепись: файлов контракта на диске %d", protos)
}
