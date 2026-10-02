// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package assurance — ПРАВИЛО ВЫВОДА уровня уверенности сессии и СЛОВАРЬ
// способов предъявления, объявленные вместе (приёмка Ф11
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`,
// Р1, Р2, Р3, Р8, Р9; задача kacho#1280).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Уровень уверенности — поле НАШЕЙ сессии на оси каталога прав («1», «2»,
// «3»). Он ВЫВОДИТСЯ из множества предъявленного в этой сессии одним правилом
// и записывается в сессию одним писателем — этим правилом. Ни край, ни страж
// посадки, ни хранилище способов входа второго вывода не заводят: край проверяет
// лишь принадлежность оси, страж посадки считает ЭТИМ ЖЕ правилом
// (PresentableLevels), а в строке способа входа уровня нет вовсе — уровень
// ключа есть свойство утверждения, а не способа (Р3), и записанный в строку он
// был бы неверен для каждого утверждения, где проверки не было.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРАВИЛО (Р2) — уровень есть НАИВЫСШАЯ строка, чьё условие выполнено
//
//	«3» — утверждение ключа доступа с проверкой пользователя, сделанное ключом,
//	      НЕ допускающим резервного копирования (Р3);
//	«2» — утверждение ключа доступа (любое) · либо пароль И второй фактор
//	      (код по времени либо запасной код);
//	«1» — пароль · либо код восстановления;
//	 —  — ничего из перечисленного: сессия НЕ выдаётся; исхода «0» у выдачи нет.
//
// Три свойства правила несущие, и каждое держится построением:
//
//   - МОНОТОННО: каждое условие — «содержит», ни одно — «не содержит», поэтому
//     добавленное предъявление уровень не понижает никогда; снять уровень можно
//     только вместе с сессией — отзывом;
//   - ЗАКРЫТО: правило определено на закрытом словаре (Methods); у типа способа
//     нет экспортированного поля, и способ вне словаря не собирается;
//   - ОДНО: строки — данные (rows), и всякий, кому нужен уровень, зовёт LevelOf.
//     Второй писатель уровня в дереве — находка гейта `internal/check`
//     (assurance_level_sole_writer.go), второе объявление словаря — находка
//     гейта там же (assurance_method_vocabulary.go).
//
// ПРЕДЪЯВЛЕНИЕ — ЭТО СВЕРКА, А НЕ ЗАДАНИЕ. Предъявлено то, что сверено с уже
// хранимым: пароль — с проверочным значением, код — с чеканенным, утверждение
// ключа — с открытым ключом. Задание нового пароля (восстановление, смена)
// предъявлением не является; сверка только что заданного — является.
//
// КОД ВОССТАНОВЛЕНИЯ ДАЁТ «1» И КО «2» НЕ ПРИБАВЛЯЕТ: он доказывает владение
// ящиком почты — способ вернуть доступ, а не удостоверение личности. Засчитай
// его во «2» — и правило выдавало бы «2» за «ящик плюс устройство» без единого
// знания.
//
// ─────────────────────────────────────────────────────────────────────────────
// СЛОВАРЬ (Р8) — закрыт, один, объявлен здесь
//
// Имена: password · totp · lookup_secret · webauthn · recovery_code. Первые
// четыре — имена, которыми уже говорят два читателя в дереве (литерал условия
// модели прав и перечень способов церемонии консоли); recovery_code — своё:
// сессию выдаёт и восстановление, и его предъявление обязано иметь имя в том же
// словаре. Утверждение ключа называется webauthn в обеих ролях — первым
// фактором и вторым: правило судит его по флагам утверждения, а не по роли.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ПАКЕТ НЕ ДЕЛАЕТ — названо, а не подразумевается
//
// Не выпускает сессию, не проверяет ни одного способа (пароль — Ф3, второй
// фактор — Ф12, ключ — Ф7/Ф13), не хранит уровень и не ранжирует ось: единая
// функция ранжирования платформы живёт в фундаменте (`acrlevel.Rank`), и
// второе ранжирование — находка. Порядок строк здесь — сама лестница, а не её
// копия: строка «3» стоит раньше строки «2» потому, что уровень есть наивысшая
// выполненная строка.
package assurance

import "sort"

// Level — уровень уверенности сессии на оси каталога прав.
//
// Значения — только Level1, Level2, Level3: сессии без уровня не бывает (Р1),
// «0» и «не задано» существуют лишь как состояние ОТВЕТА, которое край
// отвергает громко. Нулевое значение типа — не уровень; хранилище сессии
// отвергает его ограничением базы, а не проверкой в коде.
type Level string

const (
	// Level1 — пароль либо код восстановления.
	Level1 Level = "1"
	// Level2 — утверждение ключа доступа либо пароль вместе со вторым фактором.
	Level2 Level = "2"
	// Level3 — утверждение ключа с проверкой пользователя ключом, не
	// допускающим резервного копирования.
	Level3 Level = "3"
)

// String — значение на оси, как его читает каталог прав и край.
func (l Level) String() string { return string(l) }

// Levels — перечень уровней.
type Levels []Level

// Strings — перечень как строки оси, для читателей, говорящих строками
// (страж посадки, самоотчёт старта).
func (ls Levels) Strings() []string {
	if len(ls) == 0 {
		return nil
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.String())
	}
	return out
}

// Method — имя способа предъявления из закрытого словаря Р8.
//
// Поле не экспортировано намеренно: значение вне словаря снаружи пакета не
// собирается. Нулевое значение — безымянно и способом не является: правило его
// не видит, перечень его не содержит.
type Method struct{ name string }

// Словарь. ЕДИНСТВЕННОЕ объявление имён; второе в прод-коде службы — находка
// гейта `internal/check/assurance_method_vocabulary.go`.
var (
	// MethodPassword — пароль, сверенный с проверочным значением.
	MethodPassword = Method{"password"}
	// MethodTOTP — одноразовый код по времени, сверенный с чеканенным.
	MethodTOTP = Method{"totp"}
	// MethodLookupSecret — запасной код, сверенный с чеканенным.
	MethodLookupSecret = Method{"lookup_secret"}
	// MethodWebAuthn — утверждение ключа доступа, сверенное с открытым ключом;
	// флаги утверждения несёт предъявление (KeyAssertion).
	MethodWebAuthn = Method{"webauthn"}
	// MethodRecoveryCode — код восстановления, предъявленный в срок.
	MethodRecoveryCode = Method{"recovery_code"}
)

// Methods — словарь в устойчивом порядке. Новый способ входит сюда И строкой
// правила: способ, заведённый в перечень без строки, доезжал бы до сессии
// безуровневым — на это краснеет сплошная проба по всей таблице.
func Methods() []Method {
	return []Method{MethodPassword, MethodTOTP, MethodLookupSecret, MethodWebAuthn, MethodRecoveryCode}
}

// String — имя способа, как оно идёт в журнал повышения и в хранилище.
func (m Method) String() string { return m.name }

// Presentation — ОДНО успешное предъявление внутри сессии: способ и флаги
// утверждения. Флаги значимы только у ключа и ставятся только его
// конструктором; у прочих способов их нет by construction.
type Presentation struct {
	method         Method
	userVerified   bool
	backupEligible bool
}

// PasswordPresented — пароль сверен с проверочным значением.
func PasswordPresented() Presentation { return Presentation{method: MethodPassword} }

// TOTPPresented — код по времени сверен с чеканенным.
func TOTPPresented() Presentation { return Presentation{method: MethodTOTP} }

// LookupSecretPresented — запасной код сверен с чеканенным.
func LookupSecretPresented() Presentation { return Presentation{method: MethodLookupSecret} }

// RecoveryCodePresented — код восстановления предъявлен в срок.
func RecoveryCodePresented() Presentation { return Presentation{method: MethodRecoveryCode} }

// KeyAssertion — утверждение ключа доступа сверено с открытым ключом.
//
// Флаги — то, что ключ сообщил В ЭТОМ утверждении, а не память о регистрации:
// userVerified — проверка пользователя выполнена; backupEligible — ключ
// допускает резервное копирование (его закрытый материал живёт вне
// устройства). Ключ, выпущенный до появления флагов, сообщает их нулями и
// читается как привязанный к устройству без проверки пользователя — «2».
func KeyAssertion(userVerified, backupEligible bool) Presentation {
	return Presentation{method: MethodWebAuthn, userVerified: userVerified, backupEligible: backupEligible}
}

// Method — способ этого предъявления.
func (p Presentation) Method() Method { return p.method }

// UserVerified — выполнил ли ключ проверку пользователя в этом утверждении.
// У способов, кроме ключа, всегда false.
func (p Presentation) UserVerified() bool { return p.userVerified }

// BackupEligible — допускает ли ключ резервное копирование, по его же слову в
// этом утверждении. У способов, кроме ключа, всегда false.
func (p Presentation) BackupEligible() bool { return p.backupEligible }

// presented — множество предъявленного, над которым читаются условия строк.
type presented []Presentation

func (s presented) has(m Method) bool {
	for _, p := range s {
		if p.method == m {
			return true
		}
	}
	return false
}

func (s presented) hasDeviceBoundVerifiedKey() bool {
	for _, p := range s {
		if p.method == MethodWebAuthn && p.userVerified && !p.backupEligible {
			return true
		}
	}
	return false
}

// row — строка правила: уровень и условие «множество содержит …».
//
// Имя строки — для находки: снятая строка краснеет им на наборе, который она
// покрывала (проба по всей таблице).
type row struct {
	level Level
	name  string
	holds func(presented) bool
}

// rows — ПРАВИЛО Р2 как данные, строки по убыванию уровня. Порядок — лестница.
var rows = []row{
	{Level3, "ключ с проверкой пользователя, не допускающий резервного копирования",
		func(s presented) bool { return s.hasDeviceBoundVerifiedKey() }},
	{Level2, "утверждение ключа доступа (любое)",
		func(s presented) bool { return s.has(MethodWebAuthn) }},
	{Level2, "пароль и второй фактор",
		func(s presented) bool {
			return s.has(MethodPassword) && (s.has(MethodTOTP) || s.has(MethodLookupSecret))
		}},
	{Level1, "пароль",
		func(s presented) bool { return s.has(MethodPassword) }},
	{Level1, "код восстановления",
		func(s presented) bool { return s.has(MethodRecoveryCode) }},
}

// LevelOf — уровень сессии по множеству предъявленного в ней.
//
// ok=false означает «ничего из перечисленного»: сессия не выдаётся. Порядок
// предъявлений не значим — множество; повтор предъявления уровня не меняет.
func LevelOf(presentations []Presentation) (Level, bool) {
	return levelOf(rows, presentations)
}

// levelOf — то же над названной таблицей строк; таблица подаётся параметром,
// чтобы проба могла доказать, что снятая строка краснеет именем набора.
func levelOf(table []row, presentations []Presentation) (Level, bool) {
	s := presented(presentations)
	for _, r := range table {
		if r.holds(s) {
			return r.level, true
		}
	}
	return "", false
}

// PresentableLevels — уровни, которые полоса УМЕЕТ предъявить, если у неё
// провязаны названные способы (Р9). Считается ЭТИМ ЖЕ правилом по всем
// сочетаниям провязанного, ключ — в лучшем исходе флагов; своей таблицы
// «способ → уровень» страж посадки не заводит.
//
// Пустой перечень означает «ни одного»: так у провязанного только второго
// фактора — без первого сессии не бывает.
func PresentableLevels(wired []Method) Levels {
	var known []Method
	for _, m := range Methods() {
		for _, w := range wired {
			if w == m {
				known = append(known, m)
				break
			}
		}
	}
	seen := map[Level]bool{}
	for mask := 1; mask < 1<<len(known); mask++ {
		var ps []Presentation
		for i, m := range known {
			if mask&(1<<i) == 0 {
				continue
			}
			ps = append(ps, bestPresentation(m))
		}
		if l, ok := LevelOf(ps); ok {
			seen[l] = true
		}
	}
	out := make(Levels, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// bestPresentation — предъявление способа в лучшем исходе его флагов: ключ с
// проверкой пользователя, не допускающий резервного копирования.
func bestPresentation(m Method) Presentation {
	if m == MethodWebAuthn {
		return KeyAssertion(true, false)
	}
	return Presentation{method: m}
}
