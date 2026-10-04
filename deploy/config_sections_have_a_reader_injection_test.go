// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// config_sections_have_a_reader_injection_test.go — СПОСОБНОСТЬ ПРОБЫ СЕКЦИЙ
// УПАСТЬ, доказанная настоящим шаблоном и настоящим типом с одной правкой на
// случай, плюс правдивость шапки шаблона о своём держателе.
package deploy_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func realConfigSectionInputs(t *testing.T) (string, []string) {
	t.Helper()
	raw, err := os.ReadFile(configMapTemplatePath)
	require.NoError(t, err)
	return string(raw), configTypeSections(reflect.TypeOf(config.Config{}))
}

func copyLedger(extra map[string]string, drop ...string) map[string]string {
	out := map[string]string{}
	for k, v := range configSectionsNotRendered {
		out[k] = v
	}
	for _, d := range drop {
		delete(out, d)
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func TestConfigSectionsInjection_LegitimateTwinIsGreen(t *testing.T) {
	body, process := realConfigSectionInputs(t)
	findings, census, err := judgeConfigSections(body, process, configSectionsNotRendered)
	require.NoError(t, err)
	require.Emptyf(t, findings, "%s\n%s", census, strings.Join(findings, "\n"))
	require.Positive(t, census.Template)
	require.Positive(t, census.Process)
}

func TestConfigSectionsInjection_SectionWithoutAReaderIsFound(t *testing.T) {
	body, process := realConfigSectionInputs(t)
	require.Equal(t, 1, strings.Count(body, "\n    invite-mail:"), "инъекции не на чем стоять")
	body = strings.Replace(body, "\n    invite-mail:", "\n    invite-mails:", 1)
	findings, _, err := judgeConfigSections(body, process, configSectionsNotRendered)
	require.NoError(t, err)
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, `"invite-mails" шаблон рендерит`, "секция без читателя обязана быть названа")
	require.Contains(t, joined, `читает секцию "invite-mail"`, "обратная сторона обязана назвать потерянную секцию")
	require.Len(t, findings, 2)
}

func TestConfigSectionsInjection_ProcessSectionNeitherRenderedNorForgivenIsFound(t *testing.T) {
	body, process := realConfigSectionInputs(t)
	findings, _, err := judgeConfigSections(body, process, copyLedger(nil, "authz"))
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], `читает секцию "authz"`)
}

func TestConfigSectionsInjection_StaleLedgerEntriesAreFound(t *testing.T) {
	body, process := realConfigSectionInputs(t)
	findings, _, err := judgeConfigSections(body, process, copyLedger(map[string]string{
		"invite":        "прощение тому, кого рендерят",
		"retired-thing": "прощение секции, которой нет",
	}))
	require.NoError(t, err)
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, `называет "invite", а шаблон её теперь рендерит`)
	require.Contains(t, joined, `называет "retired-thing", а у `+"`config.Config`"+` такой секции нет`)
	require.Len(t, findings, 2)
}

func TestConfigSectionsInjection_OpaqueSectionDirectiveIsFound(t *testing.T) {
	body, process := realConfigSectionInputs(t)
	body = strings.Replace(body, "\n    invite:", "\n    {{- include \"kaname-svc.extraSections\" . | nindent 4 }}\n    invite:", 1)
	findings, census, err := judgeConfigSections(body, process, configSectionsNotRendered)
	require.NoError(t, err)
	require.Equal(t, 1, census.Opaque)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "форма, которой проба не судит")
}

func TestConfigSectionsInjection_EmptyInputsRefuse(t *testing.T) {
	body, process := realConfigSectionInputs(t)
	_, _, err := judgeConfigSections("data:\n  other: x\n", process, nil)
	require.Error(t, err)
	_, _, err = judgeConfigSections(body, nil, nil)
	require.Error(t, err)
}

// templateHolderRef — координата пробы, названная в тексте шаблона.
var templateHolderRef = regexp.MustCompile(`deploy/([A-Za-z0-9_]+_test\.go)`)

// TestConfigMapHeaderNamesAHolderThatExists — шапка шаблона называет держателя
// класса «секция без читателя», и каждый названный ею файл лежит в ЭТОМ дереве.
func TestConfigMapHeaderNamesAHolderThatExists(t *testing.T) {
	raw, err := os.ReadFile(configMapTemplatePath)
	require.NoError(t, err)
	// Предмет — ШАПКА: первый комментарий шаблона. Координаты ниже по файлу
	// говорят о других классах и судятся своими держателями.
	header := templateComment.FindString(string(raw))
	require.NotEmpty(t, header, "у шаблона %s нет шапки-комментария", configMapTemplatePath)
	refs := templateHolderRef.FindAllStringSubmatch(header, -1)
	require.NotEmpty(t, refs, "шапка %s не называет держателя ни одной координатой", configMapTemplatePath)
	named := false
	for _, r := range refs {
		// База — корень ЭТОГО модуля, выведенный подъёмом до маркера, а не
		// рабочий каталог прогона: под чужим деревом относительный путь указал
		// бы на чужой файл.
		_, statErr := os.Stat(filepath.Join(serviceRoot(t), "deploy", r[1]))
		require.NoErrorf(t, statErr, "%s называет deploy/%s, которого в дереве нет — "+
			"утверждение пережило свой предмет", configMapTemplatePath, r[1])
		if r[1] == "config_sections_have_a_reader_test.go" {
			named = true
		}
	}
	require.True(t, named, "шапка %s не называет держателя класса секций "+
		"(config_sections_have_a_reader_test.go)", configMapTemplatePath)
}
