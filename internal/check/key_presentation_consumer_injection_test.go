// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_presentation_consumer_injection_test.go — доказательство способности
// пробы «у предъявления ключа нет потребителя уровня сессии» упасть И смолчать.
//
// Инъекция подаёт СИНТЕТИЧЕСКИЙ корпус в тот же вердикт, что судит дерево
// (`check.JudgeKeyPresentationConsumers`): проверяются разбор импорта, отнесение
// обращения к функции, ведомость законных мест и её самоистечение. Ось на
// каждую законную форму записи обращения; каждый случай роняет ТОЛЬКО
// проверяемое.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const kpHomeRel = check.AssuranceHomeRel + "/level.go"

// kpHome — словарь: объявляет оба имени предъявления ключа.
const kpHome = `package assurance
var MethodWebAuthn = Method{"webauthn"}
func KeyAssertion(userVerified, backupEligible bool) Presentation { return Presentation{method: MethodWebAuthn} }
func other() Presentation { return KeyAssertion(true, false) }
`

const kpDecoderRel = "internal/apps/kaname/api/humansession/change_password.go"

// kpDecoder — декодер слов записи: переводит уже записанные слова в
// предъявления правила. Законное место — одно.
const kpDecoder = `package humansession
import "github.com/PRO-Robotech/kaname/internal/assurance"
func presentationsOf(methods []string) []assurance.Presentation {
	var out []assurance.Presentation
	for _, m := range methods {
		switch m {
		case assurance.MethodWebAuthn.String():
			out = append(out, assurance.KeyAssertion(false, true))
		}
	}
	return out
}
`

const kpProducerRel = "internal/apps/kaname/api/access_keys/finish_assertion.go"

// kpProducer — производитель: проверка утверждения строит предъявление для
// своего ответа. Законное место — второе.
const kpProducer = `package access_keys
import "github.com/PRO-Robotech/kaname/internal/assurance"
func (uc *FinishAssertionUseCase) Execute(ctx ctxT, in FinishAssertionInput) (FinishAssertionOutput, error) {
	return FinishAssertionOutput{Presentation: assurance.KeyAssertion(true, false)}, nil
}
`

func kpCorpus() check.TreeCorpus {
	return check.TreeCorpus{kpHomeRel: kpHome, kpDecoderRel: kpDecoder, kpProducerRel: kpProducer}
}

func kpLedger() map[string]check.KeyPresentationLawfulUse {
	return map[string]check.KeyPresentationLawfulUse{
		kpDecoderRel:  {Func: "presentationsOf", Why: "декодер слов записи"},
		kpProducerRel: {Func: "Execute", Why: "производитель ответа проверки утверждения"},
	}
}

func kpJudge(t *testing.T, corpus check.TreeCorpus, ledger map[string]check.KeyPresentationLawfulUse) ([]string, check.KeyPresentationCensus) {
	t.Helper()
	findings, census, err := check.JudgeKeyPresentationConsumers(corpus, ledger)
	if err != nil {
		t.Fatalf("вердикт на инъекции: %v", err)
	}
	return findings, census
}

// TestKeyPresentationProbeIsSilentOnALawfulTree — КОНТРОЛЬ: на законном корпусе
// молчит, называет обе декларации словаря и оба обращения декодера.
func TestKeyPresentationProbeIsSilentOnALawfulTree(t *testing.T) {
	t.Parallel()
	findings, census := kpJudge(t, kpCorpus(), kpLedger())
	if len(findings) != 0 {
		t.Fatalf("проба краснеет на ЗАКОННОМ корпусе: %s", strings.Join(findings, "; "))
	}
	if census.HomeDeclarations != len(check.KeyPresentationNames) || census.Uses != 3 || census.LawfulUses != 3 {
		t.Fatalf("перепись неверна: деклараций в словаре %d из %d, обращений %d, законных %d (ожидалось все, 3, 3)",
			census.HomeDeclarations, len(check.KeyPresentationNames), census.Uses, census.LawfulUses)
	}
}

// TestKeyPresentationProbeRedsOnEveryConsumerForm — КРАСНОЕ: предъявление ключа
// взято вне словаря и вне декодера — в каждой форме записи, которую разбор знает.
func TestKeyPresentationProbeRedsOnEveryConsumerForm(t *testing.T) {
	t.Parallel()
	const lane = "internal/apps/kaname/api/humansession/step_up_key.go"
	cases := []struct{ name, rel, src string }{
		{"способ ключа добавлен в предъявленное полосы", lane, `package humansession
import "github.com/PRO-Robotech/kaname/internal/assurance"
func (uc *StepUpUseCase) key(s Session) []string { return withMethod(s.PresentedMethods, assurance.MethodWebAuthn) }
`},
		{"утверждение ключа построено из ответа проверки", "internal/apps/kaname/api/access_keys/session.go", `package access_keys
import "github.com/PRO-Robotech/kaname/internal/assurance"
func presented(out FinishAssertionOutput) assurance.Presentation {
	return assurance.KeyAssertion(out.UserVerified, out.BackupEligible)
}
`},
		{"импорт словаря под другим именем", lane, `package humansession
import lvl "github.com/PRO-Robotech/kaname/internal/assurance"
func (uc *StepUpUseCase) key() lvl.Method { return lvl.MethodWebAuthn }
`},
		{"импорт словаря точкой", lane, `package humansession
import . "github.com/PRO-Robotech/kaname/internal/assurance"
func (uc *StepUpUseCase) key() Presentation { return KeyAssertion(true, false) }
`},
		{"вторая функция в файле декодера", kpDecoderRel, kpDecoder + `
func keyLevel() assurance.Presentation { return assurance.KeyAssertion(true, false) }
`},
		{"значение в объявлении пакета", lane, `package humansession
import "github.com/PRO-Robotech/kaname/internal/assurance"
var keyMethod = assurance.MethodWebAuthn
`},
		{"предъявление взято ГОТОВЫМ из ответа проверки, без имени словаря", "internal/apps/kaname/api/humansession/key_login.go", `package humansession
func (uc *KeyLoginUseCase) issue(ctx ctxT, w Writer, out access_keys.FinishAssertionOutput, user U) error {
	presented := append(uc.base(), out.Presentation)
	_, _, err := IssueSession(ctx, w, IssueInput{User: user, Presented: presented})
	return err
}
`},
		{"производитель сам начал писать уровень сессии", kpProducerRel, `package access_keys
import "github.com/PRO-Robotech/kaname/internal/assurance"
func (uc *FinishAssertionUseCase) Execute(ctx ctxT, in FinishAssertionInput) (FinishAssertionOutput, error) {
	p := assurance.KeyAssertion(true, false)
	_ = uc.sessions.PresentInSession(ctx, in.Session, []string{"webauthn"}, "2", in.Digest, in.At)
	return FinishAssertionOutput{Presentation: p}, nil
}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := kpCorpus()
			corpus[tc.rel] = tc.src
			findings, census := kpJudge(t, corpus, kpLedger())
			joined := strings.Join(findings, "\n")
			if len(findings) == 0 {
				t.Fatalf("проба НЕ покраснела на форме %q (обращений %d, законных %d)", tc.name, census.Uses, census.LawfulUses)
			}
			if !strings.Contains(joined, "потребител") || !strings.Contains(joined, tc.rel) {
				t.Fatalf("находка не о предмете либо без координаты:\n  %s", joined)
			}
			t.Logf("красное: %s", findings[0])
		})
	}
}

// TestKeyPresentationProbeStaysSilentOnLegitimateTwins — МОЛЧАНИЕ на формах
// того же вида, которые потребителем не являются.
func TestKeyPresentationProbeStaysSilentOnLegitimateTwins(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, rel, src string }{
		{"имя в комментарии и в строке", "internal/apps/kaname/api/humansession/doc.go", `package humansession
// assurance.MethodWebAuthn и assurance.KeyAssertion здесь только названы.
func explain() string { return "assurance.KeyAssertion is not called here" }
`},
		{"обращение внутри самого словаря", check.AssuranceHomeRel + "/best.go", `package assurance
func best(m Method) Presentation {
	if m == MethodWebAuthn {
		return KeyAssertion(true, false)
	}
	return Presentation{method: m}
}
`},
		{"одноимённое имя ЧУЖОГО пакета", "internal/apps/kaname/api/access_keys/names.go", `package access_keys
import "github.com/PRO-Robotech/kaname/internal/domain"
var kind = domain.MethodWebAuthn
`},
		{"словарь импортирован, ключ не назван", "internal/apps/kaname/api/humansession/level.go", `package humansession
import "github.com/PRO-Robotech/kaname/internal/assurance"
func password() assurance.Presentation { return assurance.PasswordPresented() }
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := kpCorpus()
			corpus[tc.rel] = tc.src
			if findings, _ := kpJudge(t, corpus, kpLedger()); len(findings) != 0 {
				t.Fatalf("проба краснеет на законной форме %q: %s", tc.name, strings.Join(findings, "; "))
			}
		})
	}
}

// TestKeyPresentationLedgerExpires — запись ведомости, которой нечего
// исключать, — находка: декодер перестал брать ключ, а запись осталась.
func TestKeyPresentationLedgerExpires(t *testing.T) {
	t.Parallel()
	corpus := kpCorpus()
	corpus[kpDecoderRel] = `package humansession
func presentationsOf(methods []string) []string { return methods }
`
	findings, _ := kpJudge(t, corpus, kpLedger())
	if !strings.Contains(strings.Join(findings, "\n"), "больше нечего исключать") {
		t.Fatalf("запись без предмета не истекла: %s", strings.Join(findings, "; "))
	}
}

// TestKeyPresentationProbeNamesAMissingVocabulary — словарь без имён ключа даёт
// ноль деклараций: проба дерева роняет на нём прогон, а не зеленеет молча.
func TestKeyPresentationProbeNamesAMissingVocabulary(t *testing.T) {
	t.Parallel()
	_, census := kpJudge(t, check.TreeCorpus{
		kpHomeRel:    "package assurance\nvar MethodPassword = Method{\"password\"}\n",
		kpDecoderRel: kpDecoder,
	}, kpLedger())
	if census.HomeDeclarations != 0 {
		t.Fatalf("словарь без имён ключа прочитан как объявляющий их: %d", census.HomeDeclarations)
	}
}
