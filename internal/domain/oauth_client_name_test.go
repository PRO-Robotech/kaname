// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// oauth_client_name_test.go — доменная валидация имени токена
// (`OAuthClientName`): единственная форма имени дерева, как у всякого другого
// имени iam.
//
// ЗДЕСЬ СТОЯЛ ДРУГОЙ КОНТРАКТ, И ОН СНЯТ (#1279). Прежняя редакция утверждала
// три вещи, каждая из которых была верна на момент записи и перестала быть
// верной вместе с формой: пустое имя допустимо · ведущая цифра отвергается ·
// имя короче трёх символов отвергается. Ослабить эти утверждения было нельзя —
// у них исчез предмет, — поэтому они ЗАМЕНЕНЫ утверждениями о том, что
// действует.
//
// Пустое имя не «стало запрещённым»: оно осталось законным ВХОДОМ выпуска и
// означает «назови сам». Просто судит его теперь не этот тип, а пара «проверка
// входа + подстановка умолчания» в use-case — и там же она доказана
// (`api/sa_keys/name_canon_test.go`, `api/user_tokens/name_canon_test.go`).
// Этот тип судит то, что БУДЕТ ЗАПИСАНО, а записи с пустым именем не бывает.
package domain

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/validate/nameform"
)

func TestOAuthClientName_Validate(t *testing.T) {
	tests := []struct {
		name    string
		in      OAuthClientName
		wantErr string // substring; "" = expect nil
	}{
		{name: "обычное имя", in: "prod-ci-key", wantErr: ""},
		{name: "имя с цифрами", in: "token-2026", wantErr: ""},
		{name: "три символа", in: "abc", wantErr: ""},
		// Две оси, на которых прежняя форма iam была УЖЕ канона. Обе стоят
		// именно среди ПРИНИМАЕМЫХ: возврат к прежней форме краснит пробу, тогда
		// как одни отрицания его бы не заметили.
		{name: "цифра первым символом", in: "9lives", wantErr: ""},
		{name: "один символ", in: "a", wantErr: ""},
		// Ось, на которой прежняя форма была ШИРЕ канона.
		{name: "дефис последним символом отвергается", in: "trail-", wantErr: "Illegal argument name"},
		{name: "пустое имя отвергается", in: "", wantErr: "Illegal argument name"},
		{name: "заглавные отвергаются", in: "My-Token", wantErr: "Illegal argument name"},
		{name: "подчёркивание отвергается", in: "my_token", wantErr: "Illegal argument name"},
		{name: "пробел отвергается", in: "My Token", wantErr: "Illegal argument name"},
		{name: "дефис первым символом отвергается", in: "-token", wantErr: "Illegal argument name"},
		{name: "длиннее 63 символов отвергается", in: OAuthClientName(strings.Repeat("a", 64)), wantErr: "Illegal argument name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Предпосылка: образец обязан согласоваться с ЕДИНСТВЕННЫМ
			// объявлением формы. Разойдись они — проба утверждала бы про форму,
			// которой в дереве нет, и утверждала бы уверенно.
			if want := tt.wantErr == ""; nameform.OK(string(tt.in)) != want {
				t.Fatalf("образец %q разошёлся с каноном (%s): здесь он объявлен %v",
					tt.in, nameform.Form, want)
			}
			err := tt.in.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want err containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestSAOAuthClient_Validate_Name — имя интегрировано в self-validating
// инвариант SA-token: каноничное проходит, негодное отвергается по единому
// текстовому контракту.
func TestSAOAuthClient_Validate_Name(t *testing.T) {
	base := ServiceAccountOAuthClient{
		ID:              "soc01abcdefghjkmnpqr",
		SvaID:           "sva_01",
		OAuthClientID:   "hydra-cli",
		CreatedByUserID: "usr_01",
	}

	ok := base
	ok.Name = "prod-ci-key"
	if err := ok.Validate(); err != nil {
		t.Fatalf("каноничное имя обязано пройти, got %v", err)
	}

	// Ось «цифра первым символом» — положительный контроль: прежняя форма iam
	// её отвергала, и без этого случая возврат к ней прошёл бы незамеченным.
	digit := base
	digit.Name = "9lives"
	if err := digit.Validate(); err != nil {
		t.Fatalf("имя с ведущей цифрой обязано пройти, got %v", err)
	}

	bad := base
	bad.Name = "Bad_Name"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal argument name") {
		t.Fatalf("want name rejection, got %v", err)
	}

	// Пустое имя до записи не доживает, поэтому self-validating инвариант его
	// отвергает: подстановка умолчания стоит РАНЬШЕ, в use-case выпуска.
	empty := base
	if err := empty.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal argument name") {
		t.Fatalf("пустое имя не может доживать до записи, got %v", err)
	}
}

// TestUserOAuthClient_Validate_Name — то же для user-token.
func TestUserOAuthClient_Validate_Name(t *testing.T) {
	base := UserOAuthClient{
		ID:              "uoc01abcdefghjkmnpqr",
		UserID:          "usr_01",
		OAuthClientID:   "hydra-cli",
		CreatedByUserID: "usr_01",
	}

	ok := base
	ok.Name = "laptop-token"
	if err := ok.Validate(); err != nil {
		t.Fatalf("каноничное имя обязано пройти, got %v", err)
	}

	digit := base
	digit.Name = "9lives"
	if err := digit.Validate(); err != nil {
		t.Fatalf("имя с ведущей цифрой обязано пройти, got %v", err)
	}

	bad := base
	bad.Name = "Laptop Token"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal argument name") {
		t.Fatalf("want name rejection, got %v", err)
	}

	empty := base
	if err := empty.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal argument name") {
		t.Fatalf("пустое имя не может доживать до записи, got %v", err)
	}
}
