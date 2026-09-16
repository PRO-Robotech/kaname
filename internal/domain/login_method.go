// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// login_method.go — способ входа человека (фаза Ф2, задача `kacho#1268`).
//
// Способ — СТРОКА своей таблицы (`kaname.user_login_methods`), а не колонка в
// зеркале человека: второй вид способа тогда заводится правкой словаря, а не
// переносом каждой строки (F4d, Р4). Санкция: одобренная Ф1, ведомость §5,
// строка Ф2; F4d-13…F4d-15, причём F4d-13 — ЧАСТИЧНО.
//
// F4d-13 требует от строки «вид способа, проверочный материал, уровень доверия
// и состояние». Держатся вид и материал; уровень доверия и состояние здесь НЕ
// заведены, и это решение, а не пропуск. Уровень есть функция вида способа:
// хранимый рядом, он стал бы вторым написанием одного значения, а «уровень
// уверенности как значение нашего хранилища» Ф1 §0.2 прямо относит к фазе Ф11 и
// не санкционирует. Состояния у способа сегодня ровно одно — «есть», и оно
// выражается существованием строки; производителя второго состояния нет. Каждое
// заводится потом добавлением колонки с умолчанием, без переноса строк.
// Носители: уровень доверия — PRO-Robotech/kacho#1280 (Ф11), состояние —
// PRO-Robotech/kacho#1281 (Ф12); решение — PRO-Robotech/kacho#1268 (комментарий 5680711802).

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// LoginMethodKind — вид способа входа. Словарь ЗАКРЫТ и совпадает с
// ограничением таблицы `user_login_methods_kind_check`.
//
// Вид сегодня один. Второй — одноразовый код по времени — заводится ВМЕСТЕ со
// своим производителем (Ф12): значение словаря без производителя обещало бы
// возможность, которой нет.
type LoginMethodKind string

// LoginMethodPassword — пароль: строка несёт его проверочный материал.
const LoginMethodPassword LoginMethodKind = "password"

var loginMethodKinds = []LoginMethodKind{LoginMethodPassword}

// LoginMethodKinds — словарь видов; копия, чтобы вызывающий не мог его расширить.
func LoginMethodKinds() []LoginMethodKind {
	out := make([]LoginMethodKind, len(loginMethodKinds))
	copy(out, loginMethodKinds)
	return out
}

// ParseLoginMethodKind — вид из строки. Написание одно: регистр и пробелы не
// нормализуются, иначе вид становится несколькими значениями.
func ParseLoginMethodKind(s string) (LoginMethodKind, error) {
	k := LoginMethodKind(s)
	if err := k.Validate(); err != nil {
		return "", err
	}
	return k, nil
}

// Validate — вид из словаря.
func (k LoginMethodKind) Validate() error {
	for _, known := range loginMethodKinds {
		if k == known {
			return nil
		}
	}
	allowed := make([]string, len(loginMethodKinds))
	for i, known := range loginMethodKinds {
		allowed[i] = string(known)
	}
	return fmt.Errorf("Illegal argument login_method.kind %q (allowed: %s)", string(k), strings.Join(allowed, "|"))
}

// loginVerifierRedacted — то, что видит всякий путь вывода вместо материала.
const loginVerifierRedacted = "[redacted login verifier]"

// ErrLoginVerifierNotSerializable — материал не сериализуется. Отказ ГРОМКИЙ:
// молча выданное пустое читалось бы как «материала нет», то есть было бы ложью
// о строке.
var ErrLoginVerifierNotSerializable = errors.New("login verifier is not serializable")

// LoginVerifier — проверочный материал способа входа: хеш пароля в той форме, в
// какой его создала функция хеширования (прежнего поставщика либо наша). Это
// СЕКРЕТ: хеш не пароль, но перебор офлайн по нему возможен.
//
// Устройство выбрано так, чтобы материал не уезжал из процесса ни одним общим
// путём вывода:
//
//   - форматирование, журнал и `String` отдают заглушку;
//   - JSON и текстовая форма ОТКАЗЫВАЮТ;
//   - материал лежит ЗА УКАЗАТЕЛЕМ. Форматирование обходит неэкспортированное
//     поле, не вызывая методов типа, и печатает его содержимое сырым; указатель
//     на вложенной глубине печатается адресом, а не содержимым. Так тип
//     защищён и там, где его методы не спрашиваются.
//
// Выход у материала ОДИН — `Reveal`. Его вызывающих держит гейт дерева
// `internal/check` `TestLoginVerifierStaysInside`.
//
// Нулевое значение означает «материала нет» и в строку способа не проходит:
// отсутствие материала выражается ОТСУТСТВИЕМ строки.
//
// Сравнение через `==` сверяет указатели, а не материал. Сверка предъявленного с
// хранимым — дело проверяющего (часть П2), и только постоянным временем.
type LoginVerifier struct {
	box *loginVerifierBox
}

type loginVerifierBox struct {
	material string
}

// NewLoginVerifier — материал как есть, ДОСЛОВНО: без обрезки и нормализации.
// Перенесённый хеш держит вход прежним паролем ровно пока он побайтово тот же
// (Р1 Ф1). Пустой материал отвергается.
func NewLoginVerifier(material string) (LoginVerifier, error) {
	if material == "" {
		return LoginVerifier{}, fmt.Errorf("Illegal argument login_method.verifier: required")
	}
	return LoginVerifier{box: &loginVerifierBox{material: material}}, nil
}

// IsZero — материала нет.
func (v LoginVerifier) IsZero() bool { return v.box == nil || v.box.material == "" }

// Reveal — ЕДИНСТВЕННЫЙ выход материала. Звать его вправе только места,
// перечисленные гейтом `TestLoginVerifierStaysInside`.
func (v LoginVerifier) Reveal() string {
	if v.box == nil {
		return ""
	}
	return v.box.material
}

// String — заглушка.
func (v LoginVerifier) String() string { return loginVerifierRedacted }

// GoString — заглушка и для `%#v`.
func (v LoginVerifier) GoString() string {
	return "domain.LoginVerifier{" + loginVerifierRedacted + "}"
}

// Format — заглушка на ЛЮБОМ глаголе форматирования, включая `%x` и `%q`.
func (v LoginVerifier) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, v.GoString())
		return
	}
	_, _ = io.WriteString(f, loginVerifierRedacted)
}

// LogValue — заглушка для журнала.
func (v LoginVerifier) LogValue() slog.Value { return slog.StringValue(loginVerifierRedacted) }

// MarshalJSON — отказ.
func (v LoginVerifier) MarshalJSON() ([]byte, error) { return nil, ErrLoginVerifierNotSerializable }

// MarshalText — отказ.
func (v LoginVerifier) MarshalText() ([]byte, error) { return nil, ErrLoginVerifierNotSerializable }

// LoginMethod — строка способа входа.
//
// Ключ — пара (`UserID`, `Kind`): второй способ того же вида человеку
// отвергается базой. `UserID` — идентификатор ЧЕЛОВЕКА (`users.id`), а не
// внешний субъект и не почта: у приглашённого внешнего субъекта нет, почта
// изменяема.
type LoginMethod struct {
	UserID   UserID
	Kind     LoginMethodKind
	Verifier LoginVerifier
	// CreatedAt назначает запись; на входе игнорируется.
	CreatedAt time.Time
}

// Validate — строка, годная к записи. Отказ не несёт материала.
func (m LoginMethod) Validate() error {
	if m.UserID == "" {
		return fmt.Errorf("Illegal argument login_method.user_id: required")
	}
	if err := m.Kind.Validate(); err != nil {
		return err
	}
	if m.Verifier.IsZero() {
		return fmt.Errorf("Illegal argument login_method.verifier: required")
	}
	return nil
}
