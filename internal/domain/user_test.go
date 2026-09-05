// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"strings"
	"testing"
)

// TestUser_Validate_AcceptsRowWithoutAccount — IAM-ID-1-58, стадия S2.
//
// Человек перестал быть «человеком В аккаунте»: принадлежность выражает строка
// `kacho_iam.memberships`, а не колонка строки личности, и членств у одного
// человека бывает несколько. Значит самовалидация доменной сущности НЕ вправе
// требовать непустого аккаунта: строка, которую переход обязан создать, не
// проходила бы собственную валидацию — целевая форма была бы невыразима в домене.
//
// Инвариант при этом НЕ ослаблен: `users.account_id` остаётся `NOT NULL` с
// внешним ключом до стадии S4 (`470001_memberships_expand.sql`), то есть держит
// его СХЕМА, а не software-проверка (ban #10).
//
// Здесь стояло обратное утверждение — `TestUser_Validate_AccountIDRequired`,
// закреплявшее требование непустоты. Оно переписано ВМЕСТЕ со снятием проверки,
// а не оставлено рядом: проба, закрепляющая снятое поведение, делает вердикт
// ложным в ту же секунду, когда поведение меняется.
func TestUser_Validate_AcceptsRowWithoutAccount(t *testing.T) {
	base := User{
		ID:           "usr_00000000000000000",
		AccountID:    "acc_00000000000000000",
		Email:        "u@example.com",
		InviteStatus: InviteStatusActive,
		ExternalID:   "kratos-sub-abc",
	}

	// Положительный контроль: валидатор в принципе пропускает годную строку.
	// Без него «принимает без аккаунта» было бы неотличимо от «принимает всё».
	if err := base.Validate(); err != nil {
		t.Fatalf("годная строка обязана проходить Validate: %v", err)
	}

	// Предмет сценария: принадлежности нет — строка принимается.
	withoutAccount := base
	withoutAccount.AccountID = ""
	if err := withoutAccount.Validate(); err != nil {
		t.Fatalf("строка человека без принадлежности аккаунту обязана проходить "+
			"самовалидацию (IAM-ID-1-58): %v", err)
	}

	// Отрицательные контроли: прочие обязательные поля по-прежнему проверяются,
	// то есть принятие выше — свойство ИМЕННО аккаунта, а не капитуляция
	// валидатора. Каждый контроль утверждает и ИМЯ поля в отказе.
	t.Run("пустая почта отвергается", func(t *testing.T) {
		bad := base
		bad.Email = ""
		err := bad.Validate()
		if err == nil {
			t.Fatalf("пустая почта обязана отвергаться")
		}
		if !strings.Contains(err.Error(), "email") {
			t.Errorf("отказ обязан называть поле email, получено: %v", err)
		}
	})

	t.Run("ACTIVE без внешнего идентификатора отвергается", func(t *testing.T) {
		bad := base
		bad.ExternalID = ""
		err := bad.Validate()
		if err == nil {
			t.Fatalf("ACTIVE без external_id обязан отвергаться")
		}
		if !strings.Contains(err.Error(), "external_id") {
			t.Errorf("отказ обязан называть поле external_id, получено: %v", err)
		}
	})

	t.Run("PENDING с внешним идентификатором отвергается", func(t *testing.T) {
		bad := base
		bad.InviteStatus = InviteStatusPending
		err := bad.Validate()
		if err == nil {
			t.Fatalf("PENDING с непустым external_id обязан отвергаться")
		}
		if !strings.Contains(err.Error(), "external_id") {
			t.Errorf("отказ обязан называть поле external_id, получено: %v", err)
		}
	})

	// И зеркало: снятие проверки не должно оставить в отказах упоминания
	// account_id — иначе «принимает» и «отвергает молча под другим именем»
	// были бы неотличимы.
	t.Run("отказ не упоминает account_id ни при каком входе", func(t *testing.T) {
		bad := withoutAccount
		bad.Email = ""
		err := bad.Validate()
		if err == nil {
			t.Fatalf("контроль испорчен: этот вход обязан отвергаться по почте")
		}
		if strings.Contains(err.Error(), "account_id") {
			t.Errorf("самовалидация всё ещё требует принадлежности: %v", err)
		}
	})
}
