// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subjectstategate_test

// gate_test.go — гейт доказывается инъекцией в ОБЕ стороны и объявляет объём
// осмотренного.
//
// Инъекция в одну сторону («верни дефект — покраснел») доказывает лишь, что
// гейт умеет краснеть. Вторая половина — законная конструкция той же формы:
// состояние прочитано и по нему судят. Без неё первый же ложный срабат гейт
// отключит.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/tools/subjectstategate"
)

// iamRoot — дерево, которое судит гейт (пакет лежит в services/iam/tools/…).
const iamRoot = "../.."

// TestGate_IamTreeIsClean — боевой прогон по дереву iam.
func TestGate_IamTreeIsClean(t *testing.T) {
	rep, err := subjectstategate.Inspect(iamRoot)
	require.NoError(t, err)

	// Перепись — отдельное утверждение: «ноль находок» не должно быть
	// неотличимо от «ноль прочитанных файлов».
	require.Greater(t, rep.FilesParsed, 100,
		"гейт разобрал %d файлов — это не похоже на дерево iam", rep.FilesParsed)
	require.Greater(t, rep.CallsInspected, 0,
		"гейт не осмотрел ни одного вызова аксессора состояния — предмет проверки исчез")
	require.Empty(t, rep.PremiseFailures,
		"предпосылка гейта перестала быть верной: %v", rep.PremiseFailures)

	require.Empty(t, rep.Findings,
		"состояние личности прочитано и выброшено: %v\n\n"+
			"Аксессор отдаёт состояние вместе со строкой именно для того, чтобы по нему\n"+
			"судили: «строка нашлась» решением о доступе не является. Либо примени\n"+
			"состояние, либо сними его с сигнатуры аксессора — но не выбрасывай молча.",
		rep.Findings)

	// Объявленные исключения — не тишина: их видно числом и списком, иначе
	// «сколько мест отказалось судить состояние» становится неизвестным.
	t.Logf("осмотрено: файлов=%d, вызовов аксессоров=%d, аксессоров объявлено=%v, исключений=%d",
		rep.FilesParsed, rep.CallsInspected, rep.AccessorsFound, len(rep.Exemptions))
	for _, e := range rep.Exemptions {
		t.Logf("исключение: %s — %s", e.Pos, e.Reason)
	}
}

// TestGate_ExemptionNeedsANamedReason — метка без причины не считается: «не
// смотрим» без основания и есть искомый дефект.
func TestGate_ExemptionNeedsANamedReason(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

type repo struct{}

func (r *repo) AccountForUser(id string) (string, bool, error) { return "", false, nil }
`,
		"caller.go": `package x

func mint(r *repo, id string) error {
	// state-not-consulted:
	_, _, err := r.AccountForUser(id)
	return err
}
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1, "метка без причины исключением не является")
	require.Empty(t, rep.Exemptions)
}

// TestGate_ExemptionWithReasonIsAccepted — обоснованное исключение принимается и
// остаётся видимым числом.
func TestGate_ExemptionWithReasonIsAccepted(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

type repo struct{}

func (r *repo) AccountForUser(id string) (string, bool, error) { return "", false, nil }
`,
		"caller.go": `package x

func revoke(r *repo, id string) error {
	// state-not-consulted: отзыв — уборка, а не аутентификация.
	_, _, err := r.AccountForUser(id)
	return err
}
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Empty(t, rep.Findings)
	require.Len(t, rep.Exemptions, 1)
	require.Contains(t, rep.Exemptions[0].Reason, "уборка")
}

// TestGate_StaleExemptionIsAFinding — исключение живёт, пока у него есть
// предмет: место перестало выбрасывать состояние, а метка осталась.
func TestGate_StaleExemptionIsAFinding(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

type repo struct{}

func (r *repo) AccountForUser(id string) (string, bool, error) { return "", false, nil }
`,
		"caller.go": `package x

import "errors"

func mint(r *repo, id string) error {
	// state-not-consulted: было когда-то, теперь судим по состоянию.
	_, mayAuthenticate, err := r.AccountForUser(id)
	if err != nil {
		return err
	}
	if !mayAuthenticate {
		return errors.New("not active")
	}
	return nil
}
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Empty(t, rep.Findings)
	require.NotEmpty(t, rep.PremiseFailures, "метке больше нечего исключать — это находка")
	require.Contains(t, rep.PremiseFailures[0], "нечего исключать")
}

// TestGate_RedOnInjectedDiscard — вернули дефект: гейт краснеет и НАЗЫВАЕТ
// координату.
func TestGate_RedOnInjectedDiscard(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

type repo struct{}

func (r *repo) AccountForUser(id string) (string, bool, error) { return "", false, nil }
`,
		"caller.go": `package x

func mint(r *repo, id string) error {
	_, _, err := r.AccountForUser(id)
	return err
}
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1, "выброшенное состояние обязано быть находкой")
	require.Contains(t, rep.Findings[0].Pos, "caller.go:4", "находка обязана назвать координату")
	require.Equal(t, "AccountForUser", rep.Findings[0].Accessor)
}

// TestGate_SilentOnLegitimateUse — законная конструкция той же формы: состояние
// прочитано в переменную и по нему судят. Гейт обязан молчать.
func TestGate_SilentOnLegitimateUse(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

import "errors"

type repo struct{}

func (r *repo) AccountForUser(id string) (string, bool, error) { return "", false, nil }
`,
		"caller.go": `package x

import "errors"

func mint(r *repo, id string) error {
	_, mayAuthenticate, err := r.AccountForUser(id)
	if err != nil {
		return err
	}
	if !mayAuthenticate {
		return errors.New("not active")
	}
	return nil
}
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Empty(t, rep.Findings, "судят по состоянию — это не находка")
	require.Equal(t, 1, rep.CallsInspected, "вызов обязан быть осмотрен, а не пропущен")
}

// TestGate_IgnoresTextThatMerelyMentionsTheAccessor — гейт читает исполняемую
// часть: то же слово в комментарии и в строковом литерале находкой не является.
func TestGate_IgnoresTextThatMerelyMentionsTheAccessor(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

type repo struct{}

func (r *repo) AccountForUser(id string) (string, bool, error) { return "", false, nil }
`,
		"prose.go": `package x

// Тут описано, почему нельзя писать _, _, err := r.AccountForUser(id).
const doc = "_, _, err := r.AccountForUser(id)"
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Empty(t, rep.Findings, "комментарий и строковый литерал — не код")
}

// TestGate_RedWhenItsOwnPremiseIsGone — аксессор переименовали: запрет
// обоснован фактом, которого больше нет, и гейт обязан это сказать сам.
func TestGate_RedWhenItsOwnPremiseIsGone(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"nothing.go": `package x

func unrelated() {}
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.NotEmpty(t, rep.PremiseFailures,
		"ни один объявленный аксессор не найден — это находка, а не тишина")
	require.Len(t, rep.PremiseFailures, len(subjectstategate.Accessors))
}

// TestGate_RedWhenSignatureShifted — у аксессора изменилось число результатов:
// позиция состояния могла сместиться, и запрет обязан это заметить.
func TestGate_RedWhenSignatureShifted(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"accessors.go": `package x

type repo struct{}

func (r *repo) AccountForUser(id string) (string, error) { return "", nil }
func (r *repo) AccountForServiceAccount(id string) (string, bool, error) { return "", false, nil }
func (r *repo) UserInviteStatus(id string) (string, error) { return "", nil }
func (r *repo) ServiceAccountEnabled(id string) (bool, error) { return false, nil }
`,
	})

	rep, err := subjectstategate.Inspect(dir)
	require.NoError(t, err)
	require.Len(t, rep.PremiseFailures, 1)
	require.Contains(t, rep.PremiseFailures[0], "AccountForUser")
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	return dir
}
