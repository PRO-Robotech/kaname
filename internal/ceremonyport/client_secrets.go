// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// SecretVerifierStore — справочник проверочных значений секрета клиента.
// Реализует `(*pg.OAuthCeremonyRepo).ClientSecretVerifier`.
//
// Контракт, на котором стоит порт сверки: клиента нет — отказ с признаком
// `iamerr.ErrNotFound`; клиент есть, секрета у него нет (публичный клиент) —
// (пусто, ложь, nil); прочий отказ — справочник не ответил.
type SecretVerifierStore interface {
	ClientSecretVerifier(ctx context.Context, clientID string) (domain.LoginVerifier, bool, error)
}

// SecretChecker — проверяющий секрета. Реализует `*passwordverify.Verifier`:
// значение секрета чеканит тот же хешер, что пишет пароли, и сверяет тот же
// проверяющий.
type SecretChecker interface {
	VerifyPresented(stored domain.LoginVerifier, presented passwordverify.Presented) passwordverify.Result
	// Aligned — полоса «материала нет» вычисляется против выравнивающего
	// значения, а не отвечает мгновенно.
	Aligned() bool
}

// ClientSecrets — адаптер порта сверки секрета клиента
// (`oauthceremony.ClientSecretVerifier`).
//
// # Отказ неизвестному клиенту стоит столько же, сколько неверному секрету
//
// Церемония зовёт порт ровно один раз на доказательство — и для клиента,
// которого справочник знает, и для клиента, которого не знает. Половина
// службы — цена: клиент, которого нет, клиент без секрета и неназванный клиент
// сверяются проверяющим против ОТСУТСТВИЯ материала, и проверяющий вычисляет
// сверку против выравнивающего значения того же класса (исход «материала
// нет»). Поэтому сборка требует выровненного проверяющего: без выравнивающего
// значения эта полоса отвечала бы мгновенно, и время ответа перечисляло бы
// зарегистрированных клиентов.
//
// # Исходов три
//
//   - совпал → SecretMatched;
//   - не совпал, секрета нет, клиента нет → SecretMismatched;
//   - сверка не состоялась — справочник не ответил, ёмкость проверяющего занята,
//     хранимое значение не читается → отказ ОПЕРАЦИИ, а не вердикт. Отказ не
//     несёт случая фундамента: церемония прочла бы его нарушением контракта.
//
// # Предъявленный секрет
//
// Адаптер не ведёт журнала и не видит значения: оно уходит проверяющему
// типом фундамента, а тексты отказов называют клиента и исход, но не секрет.
type ClientSecrets struct {
	store   SecretVerifierStore
	checker SecretChecker
}

var (
	_ oauthceremony.ClientSecretVerifier = (*ClientSecrets)(nil)
	_ passwordverify.Presented           = oauthceremony.PresentedSecret{}
)

// NewClientSecrets собирает адаптер. Без справочника сверять не с чем, без
// проверяющего нечем, а невыровненный проверяющий отвечал бы неизвестному
// клиенту дешевле, чем известному, — сборка отказывает, а не отвечает на первом
// запросе.
func NewClientSecrets(store SecretVerifierStore, checker SecretChecker) (*ClientSecrets, error) {
	switch {
	case store == nil:
		return nil, errors.New("ceremonyport: client secret verifier needs the verifier store")
	case checker == nil:
		return nil, errors.New("ceremonyport: client secret verifier needs the secret checker")
	case !checker.Aligned():
		return nil, errors.New("ceremonyport: the secret checker has no decoy; a refusal to an unknown " +
			"client would cost less than a refusal to a wrong secret")
	}
	return &ClientSecrets{store: store, checker: checker}, nil
}

// VerifyClientSecret сверяет секрет, предъявленный от имени клиента clientID.
func (c *ClientSecrets) VerifyClientSecret(ctx context.Context, clientID string, presented oauthceremony.PresentedSecret) (oauthceremony.SecretVerdict, error) {
	stored, err := c.material(ctx, clientID)
	if err != nil {
		return oauthceremony.SecretVerdictUnspecified, err
	}
	res := c.checker.VerifyPresented(stored, presented)
	switch res.Outcome {
	case passwordverify.OutcomeMatched:
		return oauthceremony.SecretMatched, nil
	case passwordverify.OutcomeMismatched, passwordverify.OutcomeMaterialMissing:
		// «Материала нет» получает только пустое значение: клиента нет, секрета
		// у него нет либо клиент не назван. Для церемонии это один вердикт с
		// неверным секретом — различать их наружу значило бы перечислять
		// клиентов.
		return oauthceremony.SecretMismatched, nil
	case passwordverify.OutcomeCapacityExhausted:
		return oauthceremony.SecretVerdictUnspecified, fmt.Errorf("ceremonyport: client %s: secret not verified: "+
			"the checker is at capacity (%s)", clientID, res.Outcome)
	case passwordverify.OutcomeFormatNotInRegistry, passwordverify.OutcomeBodyNotParsable,
		passwordverify.OutcomeParamsAboveCeiling:
		return oauthceremony.SecretVerdictUnspecified, fmt.Errorf("ceremonyport: client %s: secret not verified: "+
			"the stored verification value is not readable (%s)", clientID, res.Outcome)
	default:
		// Словарь исходов закрыт, и у каждого его исхода выше свой ответ;
		// исход вне словаря — не вердикт.
		return oauthceremony.SecretVerdictUnspecified, fmt.Errorf("ceremonyport: client %s: secret not verified: "+
			"the checker answered %q, which is not in its dictionary", clientID, res.Outcome)
	}
}

// material — проверочное значение клиента; пусто — клиента нет, секрета у него
// нет либо клиент не назван. Ошибка — справочник не ответил.
func (c *ClientSecrets) material(ctx context.Context, clientID string) (domain.LoginVerifier, error) {
	if clientID == "" {
		// Неназванный клиент — клиент, которого у службы нет: справочник не
		// спрашивается (он отверг бы пустой идентификатор как неверный
		// аргумент, то есть отказом операции), но сверка вычисляется.
		return domain.LoginVerifier{}, nil
	}
	stored, has, err := c.store.ClientSecretVerifier(ctx, clientID)
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return domain.LoginVerifier{}, nil
	case err != nil:
		return domain.LoginVerifier{}, fmt.Errorf("ceremonyport: client %s: the secret verifier store did not answer: %w",
			clientID, err)
	case !has:
		return domain.LoginVerifier{}, nil
	}
	return stored, nil
}
