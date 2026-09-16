// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// declared_test.go — «отвечает ли хранимое значение объявленному» (фаза Ф2,
// часть П2; приёмка ID-PW-1 §5 PWV-11, строки 11.2 и 11.4, и PWV-07, строка 07.3).
//
// Решение о переписывании принимает полоса входа (Ф3); ЗДЕСЬ производится то,
// чем она его принимает: ответ на вопрос «формат и параметры этого значения —
// те, что объявлены сегодня?». Ответ один и на формат, и на параметры:
// «объявленный формат» и «объявленные параметры» суть ОДНО требование, а не
// два, иначе значение объявленного формата с низшим параметром осталось бы
// лежать навсегда.
package passwordverify_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func TestMeetsDeclared_FormatAndEveryParameterAreOneRequirement(t *testing.T) {
	t.Parallel()

	declared := passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      65536,
			domain.CostParamArgon2Iterations:  3,
			domain.CostParamArgon2Parallelism: 4,
		},
	}

	cases := []struct {
		name     string
		material string
		want     bool
		why      string
	}{
		{
			name:     "формат B ровно объявленных параметров — отвечает",
			material: argon2idValue(t, rightPassword, 65536, 3, 4, 32),
			want:     true,
			why:      "записи быть не должно: иначе стоимость входа станет функцией числа входов",
		},
		{
			name:     "формат B выше объявленного по каждому параметру — отвечает",
			material: argon2idValue(t, rightPassword, 131072, 10, 8, 32),
			want:     true,
			why:      "«не ниже объявленного» — значение сильнее объявленного переписывать не за чем",
		},
		{
			name:     "формат B ниже объявленного по ПАМЯТИ — не отвечает",
			material: argon2idValue(t, rightPassword, 32768, 3, 4, 32),
			want:     false,
			why:      "хотя бы один параметр ниже объявленного — значение переписывается наравне с форматом A",
		},
		{
			name:     "формат B ниже объявленного по ИТЕРАЦИЯМ — не отвечает",
			material: argon2idValue(t, rightPassword, 65536, 2, 4, 32),
			want:     false,
		},
		{
			name:     "формат B ниже объявленного по ПАРАЛЛЕЛЬНОСТИ — не отвечает",
			material: argon2idValue(t, rightPassword, 65536, 3, 2, 32),
			want:     false,
		},
		{
			name:     "формат A — не отвечает ни при каких параметрах",
			material: bcryptValue(t, rightPassword, 14),
			want:     false,
			why:      "наследуемый формат объявленным не бывает: он только читаемый",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newVerifier(t, 4, newRecordingObserver())
			got, err := v.MeetsDeclared(verifierOf(t, c.material), declared)
			require.NoError(t, err, "годное значение обязано быть разобрано")
			require.Equalf(t, c.want, got, "%s", c.why)
		})
	}
}

// TestMeetsDeclared_UnreadableValueIsNotSilentlyDeclaredAnswering — значение,
// которого продукт не читает, НЕ отвечает объявленному и говорит об этом
// отказом: молчаливое «отвечает» оставило бы его лежать навсегда, молчаливое
// «не отвечает» послало бы полосу входа переписывать неразобранное.
func TestMeetsDeclared_UnreadableValueIsNotSilentlyDeclaredAnswering(t *testing.T) {
	t.Parallel()

	declared := passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      65536,
			domain.CostParamArgon2Iterations:  3,
			domain.CostParamArgon2Parallelism: 4,
		},
	}
	v := newVerifier(t, 4, newRecordingObserver())

	for _, c := range []struct{ name, material string }{
		{"признак вне перечня", "$scrypt$ln=15$c2FsdA$aGFzaA"},
		{"тело не разбирается", "$argon2id$v=19$m=нечисло,t=3,p=4$c2FsdA$aGFzaA"},
		{"параметр выше потолка", argon2idValueWithParams(t, 131073, 3, 4)},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.MeetsDeclared(verifierOf(t, c.material), declared)
			require.Error(t, err, "нечитаемое значение обязано отвечать отказом, а не «да» либо «нет»")
		})
	}

	// Положительный контроль: годное значение отказом не отвечает.
	_, err := v.MeetsDeclared(verifierOf(t, argon2idValue(t, rightPassword, 65536, 3, 4, 32)), declared)
	require.NoError(t, err)
}

// TestDeclared_RefusesWhatTheRegistryDoesNotWrite — объявленным бывает только
// записываемый формат перечня, и только с параметрами между полом и потолком
// его записи: страж старта (Ф3) сверяет ручку ЭТИМ.
func TestDeclared_RefusesWhatTheRegistryDoesNotWrite(t *testing.T) {
	t.Parallel()

	good := passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      65536,
			domain.CostParamArgon2Iterations:  3,
			domain.CostParamArgon2Parallelism: 4,
		},
	}
	require.NoError(t, good.Validate(), "положительный контроль: объявленное ровно на поле обязано быть годным")

	onCeiling := passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      131072,
			domain.CostParamArgon2Iterations:  10,
			domain.CostParamArgon2Parallelism: 8,
		},
	}
	require.NoError(t, onCeiling.Validate(), "обе границы включены: ровно на потолке — годно")

	bad := []struct {
		name string
		d    passwordverify.Declared
		says string
	}{
		{
			name: "только читаемый формат",
			d: passwordverify.Declared{Format: domain.PasswordHashFormatBcrypt,
				Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: 12}},
			says: "only-readable",
		},
		{
			name: "формат вне перечня",
			d: passwordverify.Declared{Format: "scrypt",
				Params: map[domain.PasswordHashCostParam]uint32{}},
			says: "registry",
		},
		{
			name: "параметр выше потолка записи",
			d: passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
				Params: map[domain.PasswordHashCostParam]uint32{
					domain.CostParamArgon2Memory:      131073,
					domain.CostParamArgon2Iterations:  3,
					domain.CostParamArgon2Parallelism: 4,
				}},
			says: "ceiling",
		},
		{
			name: "параметр ниже пола записи",
			d: passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
				Params: map[domain.PasswordHashCostParam]uint32{
					domain.CostParamArgon2Memory:      32768,
					domain.CostParamArgon2Iterations:  3,
					domain.CostParamArgon2Parallelism: 4,
				}},
			says: "floor",
		},
		{
			name: "параметр не назван вовсе",
			d: passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
				Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamArgon2Memory: 65536}},
			says: "required",
		},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			err := c.d.Validate()
			require.Error(t, err, "объявленное обязано быть отвергнуто")
			require.Containsf(t, err.Error(), c.says,
				"отказ обязан называть причину — иначе он не восстанавливает следующий шаг: %v", err)
		})
	}
}
