// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify

// verifier.go — ЕДИНСТВЕННЫЙ файл, которому разрешён проверочный материал
// (приёмка ID-PW-1 §5 PWV-01…07, PWV-11, PWV-14, PWV-15 в части Ф2).
//
// # Почему весь материал живёт в одном файле
//
// Выход у материала один — `domain.LoginVerifier.Reveal`, и его вызывающих
// держит гейт дерева `internal/check` `TestLoginVerifierStaysInside`: разрешение
// даётся ФАЙЛУ с причиной, а не пакету. Оттого разбор, сверка и вычисление
// стоят здесь: вынеси разбор в соседний файл — материал ушёл бы из-под гейта
// строкой, и дальше ничто не мешало бы положить его куда угодно.
//
// Наружу из файла уходят только ЧИСЛА и КОНСТАНТЫ: исход, признак формата,
// параметры стоимости. Соль и тело значения не покидают функции, которая их
// считает, и хранятся здесь ИНДЕКСАМИ в материале, а не подстроками.
//
// # Порядок внутри проверки — несущий, а не стилистический
//
//	ёмкость   →  материал есть?  →  признак формата  →  разбор тела и
//	области допустимости  →  потолок  →  вычисление
//
//   - ёмкость занимается ПЕРВОЙ: иначе полоса «материала нет» её не занимала
//     бы, и под нагрузкой отказ по ёмкости сообщал бы, есть ли у личности
//     пароль (15.4);
//   - разбор идёт РАНЬШЕ сверки с потолком: значение за нижней границей
//     допустимости обязано давать «тело не разбирается», а не «выше потолка», —
//     библиотека на части таких значений падает, а при памяти ниже `8·p` молча
//     считает ИНУЮ функцию (§1.7 приёмки);
//   - потолок сверяется ДО вычисления: параметры стоимости берутся из самого
//     значения, пришедшего из чужого источника, и начатое вычисление — это уже
//     та цена, от которой потолок защищает (14.3);
//   - предъявленный пароль не сравнивается ни с чем, пока значение не разобрано:
//     иначе «совпал» стало бы возможным на неразбираемом теле (05.5).

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Observer — приёмник исходов. У КАЖДОГО исхода свой счётчик: слитые в один,
// повреждение данных и перегрузка читались бы как поток неверных паролей, а
// проверка, не отказавшая ни разу, была бы неотличима от мёртвой.
//
// Клетки заводятся ДО первого события — их набор берётся из [OutcomeNames].
type Observer interface {
	VerificationObserved(outcome Outcome)
}

// Result — исход одной проверки.
//
// Материала не несёт и нести не может: наружу уходит исход, признак формата, по
// которому читали, и параметры стоимости — числа, а не части значения.
type Result struct {
	// Outcome — исход. Единственное, что решает вызывающий.
	Outcome Outcome
	// Format — формат, по которому читали. Пуст, когда признак в перечень не
	// вошёл: называть формат, которого перечень не знает, значило бы выдать
	// догадку за факт.
	Format domain.PasswordHashFormat
	// Params — параметры стоимости разобранного значения. Пусты, когда тело не
	// разобрано.
	Params map[domain.PasswordHashCostParam]uint32
}

// Verifier — проверяющий пароля.
//
// Настройки «что писать» он не принимает ВОВСЕ, и это главное его свойство:
// «как читать» решает хранимое значение (Р1). Прими он формат настройкой —
// смена настройки молча сделала бы нечитаемой уже лежащую популяцию.
type Verifier struct {
	capacity *capacityGate
	observer Observer
}

// New — проверяющий с объявленной ёмкостью и приёмником исходов.
//
// Оба довода обязательны: ёмкость без умолчания (PWV-15), приёмник — потому что
// мягкий проход законен только пока он слышен, а проверяющий без счётчиков
// молчит обо всех шести отказах разом.
func New(capacity int, observer Observer) (*Verifier, error) {
	gate, err := newCapacityGate(capacity)
	if err != nil {
		return nil, err
	}
	if observer == nil {
		return nil, fmt.Errorf("password_verifier.observer: required — " +
			"проверяющий без приёмника исходов молчит обо всех отказах разом")
	}
	return &Verifier{capacity: gate, observer: observer}, nil
}

// WithCapacity исполняет работу, занимая одно место ёмкости; отвечает, удалось
// ли место занять. Нужен полосе входа Ф3 и пробам ёмкости.
func (v *Verifier) WithCapacity(work func()) bool {
	release, ok := v.capacity.acquire()
	if !ok {
		return false
	}
	defer release()
	work()
	return true
}

// Verify — проверка предъявленного пароля против хранимого значения.
func (v *Verifier) Verify(stored domain.LoginVerifier, presented string) Result {
	release, ok := v.capacity.acquire()
	if !ok {
		return v.observed(Result{Outcome: OutcomeCapacityExhausted})
	}
	defer release()

	// Отсутствие материала — ОТДЕЛЬНЫЙ исход, и оно не приводится к пустой
	// строке: сравнение пустого с пустым дало бы «совпал» у человека, пароля не
	// заводившего.
	if stored.IsZero() {
		return v.observed(Result{Outcome: OutcomeMaterialMissing})
	}
	return v.observed(inspectAndCompare(stored.Reveal(), presented, true))
}

// MeetsDeclared — отвечает ли хранимое значение объявленному формату и
// объявленным параметрам (PWV-11, строки 11.2 и 11.4).
//
// «Объявленный формат» и «объявленные параметры» — ОДНО требование: значение
// объявленного формата, у которого хотя бы один параметр ниже объявленного,
// отвечающим не считается, иначе оно осталось бы лежать навсегда.
//
// Значение, которого продукт не читает, отвечает ОТКАЗОМ, а не «да» либо «нет»:
// молчаливое «отвечает» оставило бы его лежать, молчаливое «не отвечает»
// послало бы полосу входа переписывать неразобранное.
func (v *Verifier) MeetsDeclared(stored domain.LoginVerifier, declared Declared) (bool, error) {
	if err := declared.Validate(); err != nil {
		return false, err
	}
	if stored.IsZero() {
		return false, fmt.Errorf("password_verifier: материала нет — отвечать объявленному нечему")
	}
	res := inspectAndCompare(stored.Reveal(), "", false)
	if res.Outcome != OutcomeMatched && res.Outcome != OutcomeMismatched {
		return false, fmt.Errorf("password_verifier: значение не читается (%s) — «отвечает объявленному» неприменимо",
			res.Outcome)
	}
	if res.Format != declared.Format {
		return false, nil
	}
	for param, want := range declared.Params {
		if res.Params[param] < want {
			return false, nil
		}
	}
	return true, nil
}

// observed — исход уходит своему счётчику и возвращается вызывающему. Один
// путь на все исходы: второй оставил бы какой-нибудь из них без счётчика.
func (v *Verifier) observed(res Result) Result {
	v.observer.VerificationObserved(res.Outcome)
	return res
}

// bcryptMarkerPrefix, argon2idMarkerPrefix — признак формата, как он лежит в
// самом значении. Соседние написания bcrypt (`2b`, `2y`) в перечень не входят и
// сюда не добавляются: признак вне перечня — наша ошибка, и она обязана быть
// громкой.
const (
	bcryptMarkerPrefix    = "$2a$"
	argon2idMarkerPrefix  = "$argon2id$"
	argon2idVersionPrefix = "v=19$"
	bcryptValueLen        = 60
	bcryptCostDigits      = 2
)

// inspectAndCompare — разбор значения и, если попросили, сверка с предъявленным
// паролем.
//
// `compare == false` — путь [Verifier.MeetsDeclared]: разбор нужен, вычисление
// нет; исход «не совпал» означает тогда «значение читается».
func inspectAndCompare(material, presented string, compare bool) Result {
	switch {
	case strings.HasPrefix(material, bcryptMarkerPrefix):
		return compareBcrypt(material, presented, compare)
	case strings.HasPrefix(material, argon2idMarkerPrefix):
		return compareArgon2id(material, presented, compare)
	default:
		// Ветки «прочее» у классификатора нет: непокрытый признак получает
		// СВОЙ исход, а не общий отказ и не политику повтора.
		return Result{Outcome: OutcomeFormatNotInRegistry}
	}
}

// compareBcrypt — наследуемый формат.
//
// Разметка: `$2a$<две цифры стоимости>$<53 символа соли и тела>`, ровно 60
// символов. Стоимость разбирается ЗДЕСЬ, а не доверяется библиотеке: сверить её
// с потолком нужно ДО вычисления, а библиотека разбирает и считает одним шагом.
func compareBcrypt(material, presented string, compare bool) Result {
	record, ok := domain.PasswordHashFormatByMarker(string(domain.PasswordHashFormatBcrypt))
	if !ok {
		return Result{Outcome: OutcomeFormatNotInRegistry}
	}
	unreadable := Result{Outcome: OutcomeBodyNotParsable, Format: domain.PasswordHashFormatBcrypt}

	if len(material) != bcryptValueLen {
		return unreadable
	}
	costEnd := len(bcryptMarkerPrefix) + bcryptCostDigits
	if material[costEnd] != '$' {
		return unreadable
	}
	cost64, err := strconv.ParseUint(material[len(bcryptMarkerPrefix):costEnd], 10, 32)
	if err != nil {
		return unreadable
	}
	cost := uint32(cost64)
	if !bcryptBodyIsWellFormed(material[costEnd+1:]) {
		return unreadable
	}

	// Область допустимости формата: за её границей библиотека отказывает, и
	// совпадение на таком значении было бы совпадением с функцией, которой у
	// человека не было.
	if !withinAdmissibility(domain.PasswordHashFormatBcrypt, domain.CostParamBcryptCost, cost) {
		return unreadable
	}

	params := map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: cost}
	if cost > record.Ceiling[domain.CostParamBcryptCost] {
		return Result{Outcome: OutcomeParamsAboveCeiling, Format: domain.PasswordHashFormatBcrypt, Params: params}
	}
	if !compare {
		return Result{Outcome: OutcomeMismatched, Format: domain.PasswordHashFormatBcrypt, Params: params}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(material), []byte(presented)); err != nil {
		return Result{Outcome: OutcomeMismatched, Format: domain.PasswordHashFormatBcrypt, Params: params}
	}
	return Result{Outcome: OutcomeMatched, Format: domain.PasswordHashFormatBcrypt, Params: params}
}

// bcryptBodyIsWellFormed — 53 символа алфавита bcrypt. Проверяется ДО
// вычисления: библиотека на чужом алфавите отвечает отказом, неотличимым от
// «не совпал», и повреждение значения стало бы потоком неверных паролей.
func bcryptBodyIsWellFormed(body string) bool {
	if len(body) != bcryptValueLen-len(bcryptMarkerPrefix)-bcryptCostDigits-1 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '/':
		default:
			return false
		}
	}
	return true
}

// compareArgon2id — объявленный формат.
//
// Разметка PHC: `$argon2id$v=19$m=<КиБ>,t=<проходы>,p=<параллельность>$<соль>$<тело>`.
// Чужая версия разметки, лишние поля и любой параметр за областью допустимости
// дают «тело не разбирается» — без вычисления.
func compareArgon2id(material, presented string, compare bool) Result {
	record, ok := domain.PasswordHashFormatByMarker(string(domain.PasswordHashFormatArgon2id))
	if !ok {
		return Result{Outcome: OutcomeFormatNotInRegistry}
	}
	unreadable := Result{Outcome: OutcomeBodyNotParsable, Format: domain.PasswordHashFormatArgon2id}

	rest := material[len(argon2idMarkerPrefix):]
	if !strings.HasPrefix(rest, argon2idVersionPrefix) {
		// Версия разметки, отличная от 19, — иная функция, а не наша.
		return unreadable
	}
	rest = rest[len(argon2idVersionPrefix):]

	paramsPart, saltAndBody, found := strings.Cut(rest, "$")
	if !found {
		return unreadable
	}
	saltPart, bodyPart, found := strings.Cut(saltAndBody, "$")
	if !found {
		return unreadable
	}
	if strings.Contains(bodyPart, "$") {
		return unreadable
	}

	memory, iterations, parallelism, ok := parseArgon2idParams(paramsPart)
	if !ok {
		return unreadable
	}

	salt, err := base64.RawStdEncoding.DecodeString(saltPart)
	if err != nil || len(salt) == 0 {
		return unreadable
	}
	body, err := base64.RawStdEncoding.DecodeString(bodyPart)
	if err != nil {
		return unreadable
	}

	// Область допустимости — пересечение спецификации и того, что читатель
	// исполняет без искажения. Память ниже `8·p` библиотека не отвергает: она
	// берёт `8·p` блоков, а объявленную память кладёт в начальный хеш, — то
	// есть считает ИНУЮ функцию. Параллельность больше 255 читатель не
	// вмещает: приведённая, она стала бы другим числом, в худшем случае нулём,
	// а на нуле библиотека паникует.
	if !withinAdmissibility(domain.PasswordHashFormatArgon2id, domain.CostParamArgon2Memory, memory) ||
		!withinAdmissibility(domain.PasswordHashFormatArgon2id, domain.CostParamArgon2Iterations, iterations) ||
		!withinAdmissibility(domain.PasswordHashFormatArgon2id, domain.CostParamArgon2Parallelism, parallelism) {
		return unreadable
	}
	if uint64(memory) < 8*uint64(parallelism) {
		return unreadable
	}
	if len(body) < argon2idMinKeyLen {
		// Длина ключа короче четырёх байт: библиотека такое считает, а
		// исполнитель спецификации не производит — совпадение на нём было бы
		// совпадением с функцией, которой у человека не было.
		return unreadable
	}

	params := map[domain.PasswordHashCostParam]uint32{
		domain.CostParamArgon2Memory:      memory,
		domain.CostParamArgon2Iterations:  iterations,
		domain.CostParamArgon2Parallelism: parallelism,
	}
	if memory > record.Ceiling[domain.CostParamArgon2Memory] ||
		iterations > record.Ceiling[domain.CostParamArgon2Iterations] ||
		parallelism > record.Ceiling[domain.CostParamArgon2Parallelism] {
		return Result{Outcome: OutcomeParamsAboveCeiling, Format: domain.PasswordHashFormatArgon2id, Params: params}
	}
	if !compare {
		return Result{Outcome: OutcomeMismatched, Format: domain.PasswordHashFormatArgon2id, Params: params}
	}

	want := argon2.IDKey([]byte(presented), salt, iterations, memory, uint8(parallelism), uint32(len(body)))
	if subtle.ConstantTimeCompare(want, body) != 1 {
		return Result{Outcome: OutcomeMismatched, Format: domain.PasswordHashFormatArgon2id, Params: params}
	}
	return Result{Outcome: OutcomeMatched, Format: domain.PasswordHashFormatArgon2id, Params: params}
}

// argon2idMinKeyLen — нижняя граница длины ключа по RFC 9106 §3.1.
const argon2idMinKeyLen = 4

// parseArgon2idParams — сегмент `m=<…>,t=<…>,p=<…>` ровно в этом составе и
// порядке. Лишнее поле (`keyid`, `data`) значит, что значение считала иная
// функция, и разбираться оно не обязано.
func parseArgon2idParams(part string) (memory, iterations, parallelism uint32, ok bool) {
	fields := strings.Split(part, ",")
	if len(fields) != 3 {
		return 0, 0, 0, false
	}
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(fields[i], prefix) {
			return 0, 0, 0, false
		}
		value, err := strconv.ParseUint(fields[i][len(prefix):], 10, 32)
		if err != nil {
			return 0, 0, 0, false
		}
		switch i {
		case 0:
			memory = uint32(value)
		case 1:
			iterations = uint32(value)
		default:
			parallelism = uint32(value)
		}
	}
	return memory, iterations, parallelism, true
}

// withinAdmissibility — параметр внутри области допустимости своего формата.
// Область объявлена перечнем; второе её объявление здесь разошлось бы с ним
// молча.
func withinAdmissibility(format domain.PasswordHashFormat, param domain.PasswordHashCostParam, value uint32) bool {
	rng, ok := format.Admissibility(param)
	if !ok {
		return false
	}
	return value >= rng.Min && value <= rng.Max
}
