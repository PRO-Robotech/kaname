// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// process_knob_names_injection_test.go — доказательство того, что судья имён
// ручек процесса СПОСОБЕН упасть и МОЛЧИТ на законных близнецах. Каждая
// инъекция меняет ровно один факт против контроля.
package supplyhygiene

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// soundKnobSource — законный близнец: своя ручка приставкой службы, нейтральная
// ручка, имя чужой ручки ВНУТРИ текста отказа (формы имени не имеет) и имя
// платформы в комментарии (литералом не является).
const soundKnobSource = `package sample

import "os"

// KACHO_REGISTRY_SERVICE_AUD — ручка соседа, названа здесь только словами.
func read() (string, string, string) {
	a := os.Getenv("KANAME_BOOTSTRAP_ROOT_EMAIL")
	b := os.Getenv("PLATFORM_TREE")
	c := "the registry ships it as KACHO_REGISTRY_SERVICE_AUD and advertises it"
	return a, b, c
}
`

func TestProcessKnobNamesControl_SoundSourceIsSilent(t *testing.T) {
	census, findings := JudgeProcessKnobNames(map[string][]byte{"cmd/sample/knobs.go": []byte(soundKnobSource)})
	require.Empty(t, findings, "годный исходник объявлен нарушением: судья ловит форму, а не существо")
	require.Equal(t, 1, census.Files)
	require.Equal(t, 2, census.EnvShaped, "контроль беспредметен: литералов формы имени должно быть два")
}

func TestProcessKnobNamesInjection_PlatformNamedKnobIsNamedWithItsLine(t *testing.T) {
	src := soundKnobSource + `
func more() string { return os.Getenv("KACHO_IAM_SIDECAR_PORT") }
`
	_, findings := JudgeProcessKnobNames(map[string][]byte{"cmd/sample/knobs.go": []byte(src)})
	require.Len(t, findings, 1, "ровно один внесённый дефект — ровно одна находка")
	require.Equal(t, "KACHO_IAM_SIDECAR_PORT", findings[0].Name)
	require.Equal(t, 13, findings[0].Line, "находка обязана назвать строку, а не файл целиком")
	require.Contains(t, findings[0].String(), "cmd/sample/knobs.go:13")
}

func TestProcessKnobNamesInjection_PrefixLiteralIsJudgedToo(t *testing.T) {
	// Имя, собираемое при исполнении из приставки: приставка формы имени
	// (с хвостовым подчёркиванием) судится сама.
	src := soundKnobSource + `
func home(name string) string { return os.Getenv("KACHO_HOME_" + name) }
`
	_, findings := JudgeProcessKnobNames(map[string][]byte{"cmd/sample/knobs.go": []byte(src)})
	require.Len(t, findings, 1)
	require.Equal(t, "KACHO_HOME_", findings[0].Name)
}

func TestProcessKnobNamesInjection_DiacriticFormIsNotBlindSpot(t *testing.T) {
	// Диакритическая форма в имени переменной формы имени не имеет (не ASCII) —
	// и это граница, названная в шапке: форма имени переменной окружения
	// латинская by construction, оболочка не экспортирует иную. Судья обязан
	// МОЛЧАТЬ, а не падать: иначе он ловил бы слово, а не ручку.
	src := soundKnobSource + `
func odd() string { return "KACHŌ_X" }
`
	_, findings := JudgeProcessKnobNames(map[string][]byte{"cmd/sample/knobs.go": []byte(src)})
	require.Empty(t, findings)
}

func TestProcessKnobNamesInjection_TestFilesAreNotJudged(t *testing.T) {
	src := soundKnobSource + `
func fixture() string { return os.Getenv("KACHO_FIXTURE") }
`
	_, findings := JudgeProcessKnobNames(map[string][]byte{"cmd/sample/knobs_test.go": []byte(src)})
	require.Empty(t, findings, "проба называет имя как предмет своей проверки и не судится")
}

func TestProcessKnobNamesInjection_UnparsedFileIsVisible(t *testing.T) {
	census, _ := JudgeProcessKnobNames(map[string][]byte{"cmd/sample/broken.go": []byte("package (")})
	require.Equal(t, []string{"cmd/sample/broken.go"}, census.Unparsed, "пропуск обязан быть виден")
	require.Zero(t, census.Files)
}

// ── Домен доверия: тот же корпус, другой предмет ────────────────────────────

// soundTrustSource — законный близнец: SPIFFE-имя в комментарии (литералом не
// является) и слово «spiffe» без схемы адреса.
const soundTrustSource = `package sample

// Круг отправителей: spiffe://example.invalid/ns/x/sa/y — только в объяснении.
func kind() string { return "spiffe" }
`

func TestProcessTrustDomainControl_SoundSourceIsSilent(t *testing.T) {
	census, findings := JudgeProcessTrustDomainLiterals(map[string][]byte{"cmd/sample/trust.go": []byte(soundTrustSource)})
	require.Empty(t, findings)
	require.Equal(t, 1, census.Files)
	require.Equal(t, 1, census.Literals, "контроль беспредметен: литерал обязан быть осмотрен")
}

func TestProcessTrustDomainInjection_LiteralSPIFFENameIsNamedWithItsLine(t *testing.T) {
	src := soundTrustSource + `
const sanTrustPrefix = "spiffe://kacho.cloud/ns/"
`
	_, findings := JudgeProcessTrustDomainLiterals(map[string][]byte{"cmd/sample/trust.go": []byte(src)})
	require.Len(t, findings, 1)
	require.Equal(t, "spiffe://kacho.cloud/ns/", findings[0].Name)
	require.Equal(t, 6, findings[0].Line)
}

func TestProcessTrustDomainInjection_TestFilesAreNotJudged(t *testing.T) {
	src := soundTrustSource + `
const fixtureSAN = "spiffe://example.invalid/ns/x/sa/y"
`
	_, findings := JudgeProcessTrustDomainLiterals(map[string][]byte{"cmd/sample/trust_test.go": []byte(src)})
	require.Empty(t, findings)
}
