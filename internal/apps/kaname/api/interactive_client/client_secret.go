// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// client_secret.go — НОСИТЕЛЬ секрета конфиденциального интерактивного клиента
// в памяти процесса (задача PRO-Robotech/kaname#405, приёмка
// confidential-interactive-client-secret-shown-once, Р3).
//
// Секрет существует ровно в одном месте — в ответе вызова `Create`. От
// исполнителя заведения до поля ответа он едет этим типом, а не строкой:
// строку печатает всякий общий путь вывода — форматирование ошибки, журнал,
// JSON, — и «показан один раз» стало бы «напечатан там, где упала строка
// журнала». Носитель устроен так же, как проверочный материал способа входа
// (`domain.LoginVerifier`) и предъявленный секрет церемонии
// (`oauthceremony.PresentedSecret`):
//
//   - форматирование на ЛЮБОМ глаголе и журнал отдают заглушку, JSON и
//     текстовая форма ОТКАЗЫВАЮТ — молча выданное пустое читалось бы как
//     «секрета нет»;
//   - значение лежит ЗА УКАЗАТЕЛЕМ: форматирование обходит неэкспортированное
//     поле, не спрашивая методов типа, и на вложенной глубине печатает адрес, а
//     не содержимое;
//   - выход у значения ОДИН — `IntoResponse`, заполнение поля ответа. Метода,
//     отдающего строку, у типа нет вовсе, поэтому «достать и положить в журнал»
//     невыразимо без правки этого файла.
//
// Поля в `domain.InteractiveClient` секрет не получает: эту сущность передают
// хранилище, проекция и журналы, и поле там было бы вторым местом, где секрет
// живёт.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// clientSecretRedacted — то, что видит всякий путь вывода вместо значения.
const clientSecretRedacted = "[redacted interactive client secret]"

// ErrClientSecretNotSerializable — носитель не сериализуется. Отказ ГРОМКИЙ:
// пустое, выданное молча, было бы ложью «секрета нет».
var ErrClientSecretNotSerializable = errors.New("interactive client secret is not serializable")

// ClientSecret — секрет конфиденциального клиента, выданный реестром.
// Нулевое значение — секрета нет (клиент со способом `none`).
type ClientSecret struct {
	box *clientSecretBox
}

type clientSecretBox struct {
	value string
}

// NewClientSecret — секрет, отчеканенный реестром, как есть. Пустой
// отвергается: отсутствие секрета выражается нулевым носителем, а не пустым
// значением в непустом.
func NewClientSecret(value string) (ClientSecret, error) {
	if value == "" {
		return ClientSecret{}, errors.New("interactive client secret: empty")
	}
	return ClientSecret{box: &clientSecretBox{value: value}}, nil
}

// IsZero — секрета нет.
func (s ClientSecret) IsZero() bool { return s.box == nil || s.box.value == "" }

// IntoResponse — ЕДИНСТВЕННЫЙ выход значения: заполнение поля `client_secret`
// ответа вызова `Create`. Нулевой носитель поле не трогает.
func (s ClientSecret) IntoResponse(resp *iamv1.CreateInteractiveClientResponse) {
	if s.IsZero() || resp == nil {
		return
	}
	resp.ClientSecret = s.box.value
}

// String — заглушка.
func (s ClientSecret) String() string { return clientSecretRedacted }

// GoString — заглушка и для `%#v`.
func (s ClientSecret) GoString() string {
	return "interactiveclient.ClientSecret{" + clientSecretRedacted + "}"
}

// Format — заглушка на ЛЮБОМ глаголе форматирования, включая `%x` и `%q`.
func (s ClientSecret) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, s.GoString())
		return
	}
	_, _ = io.WriteString(f, clientSecretRedacted)
}

// LogValue — заглушка для журнала.
func (s ClientSecret) LogValue() slog.Value { return slog.StringValue(clientSecretRedacted) }

// MarshalJSON — отказ.
func (s ClientSecret) MarshalJSON() ([]byte, error) { return nil, ErrClientSecretNotSerializable }

// MarshalText — отказ.
func (s ClientSecret) MarshalText() ([]byte, error) { return nil, ErrClientSecretNotSerializable }
