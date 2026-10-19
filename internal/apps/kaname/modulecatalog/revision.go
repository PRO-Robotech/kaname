// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog

// revision.go — редакция манифеста модуля только растёт (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// решения Д2–Д4, Д6, Д7).
//
// ─────────────────────────────────────────────────────────────────────────────
// РЕШАТЕЛЬ ОДИН
//
// Исход сравнения редакций — функция ЧЕТЫРЁХ величин: применённая пара (номер
// `a`, отпечаток `h`) и объявленная пара (`d`, `g`). Решает её ровно одна
// функция — [JudgeRevision]; её зовут и `Plan` (вердикт), и применитель (разбор
// того, что записал оператор сравнения-и-записи). Второй решатель разошёлся бы с
// первым молча: на обычной доставке оба отвечают «применяется».
//
// Запись пары при этом делает НЕ решатель, а ОДИН оператор базы под замком
// каталога (`CatalogWriter.AdvanceRevision`): условие записи выражено в его
// `WHERE`, и решатель здесь только ПЕРЕСЧИТЫВАЕТ, что оператор обязан был
// сделать. Разошлись — отказ `ErrWriteFailed`: значит предикат оператора и
// решатель описывают разное, и молча выбрать одного из них нельзя.
//
// ─────────────────────────────────────────────────────────────────────────────
// МЛАДШАЯ РЕДАКЦИЯ И КОНФЛИКТ — ИСХОД, А НЕ ОШИБКА
//
// На пути старта младшая редакция пропускается, конфликт содержимого
// называется отдельной записью, и применитель при этом возвращает `nil` (Д3):
// пропуск одного модуля не есть отказ пуска. Поэтому исход едет в переписи
// (`Report.Revision`), а в ошибку превращается в ОДНОМ месте и только на полосе
// глагола (`VerbApplier.Apply`): там его получает оператор как
// `FAILED_PRECONDITION` с текстом Д7.

import (
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// Edition — пара «номер редакции, отпечаток содержимого» (Д1, Д9).
//
// Отсутствие пары выражается указателем `nil`, а не нулевым значением: ноль
// редакцией не бывает, и «манифест редакцию не объявил» либо «модуль ни разу не
// применён с редакцией» — законные состояния, отличные от любого номера.
type Edition struct {
	// Revision — номер редакции, не меньше 1.
	Revision int64
	// Digest — отпечаток содержимого, `sha256:` и 64 строчные цифры.
	Digest string
}

// DeclaredEdition — пара, объявленная манифестом; `nil`, если документ ключа
// `revision` не несёт.
//
// Отпечаток берётся только у документа, объявившего номер: отпечаток без
// номера ничего не сравнивает (§3 Д5 приёмки).
func DeclaredEdition(m *manifest.Manifest) *Edition {
	if m == nil {
		return nil
	}
	n, declared := m.Revision()
	if !declared {
		return nil
	}
	return &Edition{Revision: n, Digest: m.Digest()}
}

// RevisionOutcome — исход сравнения объявленной редакции с применённой.
type RevisionOutcome uint8

const (
	// RevisionUnjudged — сравнения не было: применение отвергнуто раньше
	// (актор, вывод строк) либо отчёт собран не применителем. Нулевое значение
	// типа намеренно не означает «применяется».
	RevisionUnjudged RevisionOutcome = iota
	// RevisionFirst — у модуля нет применённой редакции, манифест её объявил:
	// пара записывается.
	RevisionFirst
	// RevisionNewer — объявленная редакция старше применённой: пара
	// записывается.
	RevisionNewer
	// RevisionRepeat — номер и отпечаток равны применённым: идемпотентный
	// повтор, пара не меняется.
	RevisionRepeat
	// RevisionUndeclaredOverUnapplied — документ ключа не несёт, у модуля нет
	// применённой редакции: строки применяются, пара не пишется (переходная
	// ветка Д6, [undeclaredRevisionTransitionS1]).
	RevisionUndeclaredOverUnapplied
	// RevisionStale — объявленная редакция МЛАДШЕ применённой либо не
	// объявлена при применённой (Д6): не пишется ничего.
	RevisionStale
	// RevisionConflict — номер равен применённому, отпечаток иной: не пишется
	// ничего.
	RevisionConflict
)

// String — имя исхода для журнала и переписи.
func (o RevisionOutcome) String() string {
	switch o {
	case RevisionFirst:
		return "first"
	case RevisionNewer:
		return "newer"
	case RevisionRepeat:
		return "repeat"
	case RevisionUndeclaredOverUnapplied:
		return "undeclared_over_unapplied"
	case RevisionStale:
		return "stale"
	case RevisionConflict:
		return "conflict"
	default:
		return "unjudged"
	}
}

// Writes — исход, при котором оператор сравнения-и-записи ОБЯЗАН записать
// пару.
func (o RevisionOutcome) Writes() bool { return o == RevisionFirst || o == RevisionNewer }

// Refused — исход, при котором каталог модуля не меняется вовсе.
func (o RevisionOutcome) Refused() bool { return o == RevisionStale || o == RevisionConflict }

// JudgeRevision — ЕДИНСТВЕННЫЙ решатель исхода (таблица Д2 приёмки).
//
//	a нет,  d есть               → первая редакция, пишется
//	a есть, d < a                → младшая
//	a есть, d = a, g = h         → повтор
//	a есть, d = a, g ≠ h         → конфликт содержимого
//	a есть, d > a                → старшая, пишется
//	d нет (только S1)            → переходная ветка Д6
func JudgeRevision(applied, declared *Edition) RevisionOutcome {
	if declared == nil {
		return undeclaredRevisionTransitionS1(applied)
	}
	switch {
	case applied == nil:
		return RevisionFirst
	case declared.Revision < applied.Revision:
		return RevisionStale
	case declared.Revision > applied.Revision:
		return RevisionNewer
	case declared.Digest == applied.Digest:
		return RevisionRepeat
	default:
		return RevisionConflict
	}
}

// undeclaredRevisionTransitionS1 — ПЕРЕХОДНАЯ ВЕТКА стадии S1 (Д6 приёмки):
// документ без ключа `revision` младше любой объявленной редакции. Модуль с
// применённой редакцией он не перезаписывает никогда; к модулю без неё
// применяется, не сдвигая пары.
//
// Ветка — один именованный символ, чтобы её снятие было проверяемо по дереву.
// Предикат снятия: стадия S2 той же задачи (kaname#865) — загрузчик требует
// ключ (`manifest: revision is required`), и сюда документ без редакции не
// доходит; тогда символ удаляется вместе со своими пробами (865-09, 865-19), а
// применитель отвергает манифест без редакции до транзакции (865-23).
func undeclaredRevisionTransitionS1(applied *Edition) RevisionOutcome {
	if applied == nil {
		return RevisionUndeclaredOverUnapplied
	}
	return RevisionStale
}

// RevisionReport — что сравнение редакций сказало о применении одного модуля.
type RevisionReport struct {
	// Outcome — исход решателя.
	Outcome RevisionOutcome
	// Declared — пара, объявленная манифестом; nil — ключа нет.
	Declared *Edition
	// Previous — применённая пара ДО применения; nil — модуль не применялся с
	// редакцией (или строки модуля не было вовсе).
	Previous *Edition
}

// Applied — применённая пара ПОСЛЕ применения: объявленная, если пара
// записана, иначе прежняя.
func (r RevisionReport) Applied() *Edition {
	if r.Outcome.Writes() {
		return r.Declared
	}
	return r.Previous
}

// RevisionWrite — что сделал оператор сравнения-и-записи.
type RevisionWrite struct {
	// Previous — пара, стоявшая в строке модуля ДО оператора; nil — пусто
	// либо строки не было.
	Previous *Edition
	// RowCreated — оператор ЗАВЁЛ строку модуля (её не было).
	RowCreated bool
	// Written — оператор записал объявленную пару.
	Written bool
}

var (
	// ErrStaleRevision — объявленная редакция младше применённой (либо не
	// объявлена при применённой — переходная ветка S1).
	ErrStaleRevision = errors.New("modulecatalog: manifest revision is older than the applied one")
	// ErrRevisionConflict — номер равен применённому, содержимое иное.
	ErrRevisionConflict = errors.New("modulecatalog: manifest revision is applied with other content")
)

// RevisionRefusal — отказ ГЛАГОЛА по редакции.
//
// Тип, а не обёртка сентинела: `Error()` обязан отдавать РОВНО текст Д7 — он
// часть контракта и сверяется дословным равенством. Обёртка `%w: …` приставила
// бы английский текст сентинела впереди, и приведение транспорта (`applyRefusal`)
// донесло бы его оператору. С сентинелом тип связан методом `Is`.
type RevisionRefusal struct {
	Module   string
	Outcome  RevisionOutcome
	Declared *Edition
	Applied  *Edition
}

// Error — текст Д7.
func (e *RevisionRefusal) Error() string {
	switch {
	case e.Outcome == RevisionConflict && e.Declared != nil && e.Applied != nil:
		return fmt.Sprintf("модуль %s: редакция манифеста %d уже применена с другим содержимым "+
			"(отпечаток манифеста %s, применённый %s); изменение содержимого выражается новой "+
			"редакцией больше %d",
			e.Module, e.Declared.Revision, e.Declared.Digest, e.Applied.Digest, e.Declared.Revision)
	case e.Outcome == RevisionStale && e.Declared == nil && e.Applied != nil:
		return fmt.Sprintf("модуль %s: манифест не объявляет редакцию, а применена редакция %d; "+
			"применяется только редакция не меньше %d",
			e.Module, e.Applied.Revision, e.Applied.Revision)
	case e.Outcome == RevisionStale && e.Declared != nil && e.Applied != nil:
		return fmt.Sprintf("модуль %s: редакция манифеста %d старше применённой %d; "+
			"откат выражается новой редакцией больше %d",
			e.Module, e.Declared.Revision, e.Applied.Revision, e.Applied.Revision)
	default:
		return fmt.Sprintf("модуль %s: применение отвергнуто по редакции (исход %s)", e.Module, e.Outcome)
	}
}

// Is связывает отказ с сентинелом его исхода.
func (e *RevisionRefusal) Is(target error) bool {
	switch e.Outcome {
	case RevisionStale:
		return target == ErrStaleRevision
	case RevisionConflict:
		return target == ErrRevisionConflict
	default:
		return false
	}
}

// refusalOf — отказ глагола по исходу редакции; nil, если исход не отказ.
func refusalOf(module string, r RevisionReport) error {
	if !r.Outcome.Refused() {
		return nil
	}
	return &RevisionRefusal{Module: module, Outcome: r.Outcome, Declared: r.Declared, Applied: r.Previous}
}

// PlanVerdict — вердикт плана с учётом редакции (Д4): исход сравнения
// редакций судится РАНЬШЕ опоры, повторяя порядок отказов `Apply` (сравнение
// пары — первый пишущий оператор транзакции, сверка опоры — перед фиксацией).
// Младшая редакция и конфликт дают свой вердикт при ЛЮБОМ вердикте опоры;
// иначе отдаётся вердикт опоры. Перечни опоры этим не трогаются.
func PlanVerdict(anchor AnchorPlan, revision RevisionOutcome) Verdict {
	switch revision {
	case RevisionStale:
		return VerdictWouldBeRefusedStaleRevision
	case RevisionConflict:
		return VerdictWouldBeRefusedRevisionConflict
	default:
		return anchor.Verdict
	}
}
