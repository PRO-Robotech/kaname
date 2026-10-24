// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// step_up_keys_fake_test.go — дублёр ветви ключа церемонии повышения
// (kaname#827) для проб глаголов второго фактора, чей предмет — не ключ:
// испытаний он не выдаёт, ключей не знает. Позванный — отвечает «нет»
// значением, а не отказом хранилища: проба, которой ветвь ключа понадобилась
// бы, увидела бы это отказом, а не успехом.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

type noStepUpChallenges struct{}

func (noStepUpChallenges) IssueStepUpChallenge(context.Context, domain.StepUpChallenge) error {
	return nil
}

func (noStepUpChallenges) ConsumeStepUpChallenge(context.Context, domain.HumanSessionID, []byte, time.Time) (bool, error) {
	return false, nil
}

func (noStepUpChallenges) StepUpChallengeState(context.Context, domain.HumanSessionID, []byte, time.Time) (domain.StepUpChallengeState, error) {
	return domain.StepUpChallengeNotIssued, nil
}

func (noStepUpChallenges) KeyByCredentialID(context.Context, []byte) (domain.AccessKey, bool, error) {
	return domain.AccessKey{}, false, nil
}

func (noStepUpChallenges) CredentialIDsOf(context.Context, domain.UserID) ([][]byte, error) {
	return nil, nil
}

// sfKeys — ветвь ключа глаголов второго фактора проб: привязка с непустым
// перечнем происхождений (ключи включены), хранилище — дублёр выше.
func sfKeys() humansession.StepUpKeys {
	return humansession.StepUpKeys{
		Store: noStepUpChallenges{},
		Binding: webauthnverify.Binding{RPID: clkRPID, Origins: []string{clkOrigin},
			Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
		ChallengeTTL: access_keys.ChallengeTTL, UserVerification: access_keys.UserVerificationAssertion,
	}
}
