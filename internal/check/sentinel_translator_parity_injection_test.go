// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sentinel_translator_parity_injection_test.go — доказательство способности
// гейта упасть И смолчать.
//
// Инъекция подаёт НАСТОЯЩИЙ вход — копию переводчика ровно в том наборе ветвей,
// в каком она лежала на `kaname@5303cebd`: без `ErrAborted`,
// `ErrPermissionDenied` и `ErrUnauthenticated` (kaname#114). Законные близнецы —
// те же формы записи там, где они законны.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// sentinelCanonSrc — канон в форме, достаточной для разбора: девять полос и
// терминальный INTERNAL литералом.
const sentinelCanonSrc = `package shared

func MapRepoErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case stderrors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrAborted):
		return status.Error(codes.Aborted, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, UnavailableMessage)
	case stderrors.Is(err, iamerr.ErrInternal):
		return status.Error(codes.Internal, "internal error")
	}
	return status.Error(codes.Internal, "internal error")
}
`

// sentinelDefectSrc — копия ДО правки: три полосы канона не различаются.
const sentinelDefectSrc = `package sa_keys

func mapPGErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, iamerr.ErrQuotaExceeded) || errors.Is(err, iamerr.ErrQuotaRateExceeded) {
		return shared.MapRepoErr(err)
	}
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	}
	return status.Error(codes.Internal, "internal SA key error")
}
`

// sentinelFixedSrc — она же после правки: набор сошёлся, текст остался СВОИМ.
const sentinelFixedSrc = `package sa_keys

func mapPGErr(err error) error {
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAborted):
		return status.Error(codes.Aborted, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	case errors.Is(err, iamerr.ErrInternal):
		return status.Error(codes.Internal, "internal SA key error")
	}
	return status.Error(codes.Internal, "internal SA key error")
}
`

// sentinelCallSiteSrc — законный близнец: проверка НА МЕСТЕ ВЫЗОВА. Одну полосу
// она разбирает сама, остальное отдаёт канону — терминального INTERNAL с
// литералом у неё нет, и переводчиком она НЕ является. Без этой границы
// находкой стал бы каждый вызывающий, спрашивающий `ErrNotFound`.
const sentinelCallSiteSrc = `package access_binding

func requireRole(ctx context.Context, rd Reader, id string) error {
	_, err := rd.Roles().Get(ctx, id)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return status.Errorf(codes.FailedPrecondition, "Role %s not found", id)
		}
		if stderrors.Is(err, iamerr.ErrUnavailable) {
			return shared.MapRepoErr(err)
		}
		return shared.MapRepoErr(err)
	}
	return nil
}
`

func mustCanon(t *testing.T) check.SentinelTranslator {
	t.Helper()
	ts, census, err := check.ScanSentinelTranslators("internal/apps/kaname/shared/errors.go",
		[]byte(sentinelCanonSrc))
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	if len(ts) != 1 {
		t.Fatalf("канон опознан %d раз(а) вместо одного при переписи %+v — без него гейт "+
			"сверял бы копии с пустым набором", len(ts), census)
	}
	if len(ts[0].Sentinels) != 9 {
		t.Fatalf("у канона прочитано %d полос из девяти: %v", len(ts[0].Sentinels), ts[0].Sentinels)
	}
	return ts[0]
}

// TestSentinelParityGateRedsOnATranslatorMissingLanes — инъекция настоящим
// дефектом.
func TestSentinelParityGateRedsOnATranslatorMissingLanes(t *testing.T) {
	canon := mustCanon(t)
	const rel = "internal/apps/kaname/api/sa_keys/usecases.go"
	copies, census, err := check.ScanSentinelTranslators(rel, []byte(sentinelDefectSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Translators != 1 {
		t.Fatalf("переводчик в инъекции опознан %d раз(а) вместо одного: %+v",
			census.Translators, census)
	}
	findings := sentinelParityFindings(canon, copies)
	if len(findings) != 1 {
		t.Fatalf("копия без трёх полос канона НЕ стала находкой: находок %d при переписи %+v\n"+
			"Гейт, не краснеющий на дефекте, из которого он выведен, не удерживает ничего",
			len(findings), census)
	}
	for _, want := range []string{rel, "ErrAborted", "ErrPermissionDenied", "ErrUnauthenticated"} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %s: %q", want, findings[0])
		}
	}
	// Полосы, которые копия РАЗЛИЧАЕТ, находкой называться не должны — иначе
	// сообщение посылает читателя чинить исправное.
	if strings.Contains(findings[0], "ErrNotFound") {
		t.Errorf("находка называет полосу, которую копия различает: %q", findings[0])
	}
}

// TestSentinelParityGateStaysSilentOnLegalTwins — гейт обязан молчать там, где
// форма законна.
func TestSentinelParityGateStaysSilentOnLegalTwins(t *testing.T) {
	canon := mustCanon(t)

	t.Run("копия с полным набором — молчание", func(t *testing.T) {
		copies, census, err := check.ScanSentinelTranslators(
			"internal/apps/kaname/api/sa_keys/usecases.go", []byte(sentinelFixedSrc))
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if census.Translators != 1 {
			t.Fatalf("переводчик не опознан: %+v", census)
		}
		if f := sentinelParityFindings(canon, copies); len(f) != 0 {
			t.Fatalf("копия с полным набором объявлена находкой: %v", f)
		}
	})

	t.Run("проверка на месте вызова переводчиком НЕ является", func(t *testing.T) {
		copies, census, err := check.ScanSentinelTranslators(
			"internal/apps/kaname/api/access_binding/structural_gates.go",
			[]byte(sentinelCallSiteSrc))
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if census.WithSentinels == 0 {
			t.Fatalf("разбор не увидел sentinel'ов вовсе — граница проверена ни на чём: %+v",
				census)
		}
		if census.Translators != 0 || len(copies) != 0 {
			t.Fatalf("проверка на месте вызова объявлена переводчиком (%d): без этой границы "+
				"находкой стал бы каждый вызывающий, спрашивающий ErrNotFound — %+v",
				census.Translators, census)
		}
	})
}

// TestSentinelScannerKnowsEveryDispatchForm — распознаватель обязан знать ВСЕ
// формы записи предмета. Форма, о которой он не знает, даёт МОЛЧАНИЕ: полоса
// уезжает вне наблюдения, и копия выглядит полной.
func TestSentinelScannerKnowsEveryDispatchForm(t *testing.T) {
	const src = `package p

func translate(err error) error {
	if errors.Is(err, iamerr.ErrNotFound) {
		return status.Error(codes.NotFound, "")
	}
	if goerrors.Is(err, iamerr.ErrAborted) || goerrors.Is(err, iamerr.ErrUnavailable) {
		return status.Error(codes.Aborted, "")
	}
	switch {
	case stderrors.Is(err, iamerr.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, "")
	}
	return status.Error(codes.Internal, "internal error")
}
`
	ts, census, err := check.ScanSentinelTranslators("internal/x/a.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(ts) != 1 {
		t.Fatalf("переводчик не опознан: %+v", census)
	}
	want := []string{"ErrAborted", "ErrNotFound", "ErrPermissionDenied", "ErrUnavailable"}
	got := strings.Join(ts[0].Sentinels, ",")
	if got != strings.Join(want, ",") {
		t.Fatalf("прочитано %q, ожидалось %q — форма, о которой распознаватель не знает, "+
			"даёт МОЛЧАНИЕ: полоса уезжает вне наблюдения, а копия выглядит полной",
			got, strings.Join(want, ","))
	}
	// Псевдоним пакета `errors` безразличен by construction: sentinel опознаётся
	// по АРГУМЕНТУ (`iamerr.Err*`), а не по имени вызываемого пакета. Здесь три
	// разных написания — `errors`, `goerrors`, `stderrors`, — и все прочитаны.
}

// TestSentinelScannerNeedsATerminalInternalLiteral — второй признак переводчика.
// Без него разбор объявил бы переводчиком функцию, отдающую остаток канону.
func TestSentinelScannerNeedsATerminalInternalLiteral(t *testing.T) {
	const delegating = `package p

func translate(err error) error {
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, "")
	case errors.Is(err, iamerr.ErrAborted):
		return status.Error(codes.Aborted, "")
	}
	return shared.MapRepoErr(err)
}
`
	ts, census, err := check.ScanSentinelTranslators("internal/x/a.go", []byte(delegating))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.WithSentinels != 1 {
		t.Fatalf("sentinel'ы не прочитаны — граница проверена ни на чём: %+v", census)
	}
	if len(ts) != 0 {
		t.Fatalf("функция, отдающая остаток канону, объявлена переводчиком: %+v", ts)
	}
}

// TestSentinelWalkExcludesGeneratedAndProbes — отбор гейта. Проверяется ТОТ ЖЕ
// предикат, которым судит гейт.
func TestSentinelWalkExcludesGeneratedAndProbes(t *testing.T) {
	if !sentinelWalkable("internal/apps/kaname/api/sa_keys/usecases.go") {
		t.Fatalf("отбор гейта не берёт прод-файл — тогда осматривать нечего")
	}
	for _, rel := range []string{
		"internal/apps/kaname/api/sa_keys/usecases_test.go",
		"pkg/api/kaname/cloud/iam/v1/sa_key.pb.go",
	} {
		if sentinelWalkable(rel) {
			t.Errorf("отбор гейта берёт %s — предмет там не его", rel)
		}
	}
}

// ── Полоса конца контекста (kaname#383) ─────────────────────────────────────
//
// Конец контекста — не sentinel `iamerr`, а ошибка пакета `context`, и до
// kaname#383 разбор её не читал вовсе: канон различал её бы, а копия без неё
// выглядела полной. Её законные формы — те же, что у sentinel'ов (ветвь switch,
// условие if, дизъюнкция), плюс псевдоним ИМПОРТА пакета `context`: опознаётся
// она по пути импорта, а не по написанию идентификатора.

// sentinelCanonWithContextEndSrc — канон с полосой конца контекста.
const sentinelCanonWithContextEndSrc = `package shared

import (
	"context"
)

func MapRepoErr(err error) error {
	switch {
	case stderrors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, UnavailableMessage)
	case stderrors.Is(err, context.Canceled) || stderrors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.Unavailable, UnavailableMessage)
	case stderrors.Is(err, iamerr.ErrInternal):
		return status.Error(codes.Internal, "internal error")
	}
	return status.Error(codes.Internal, "internal error")
}
`

// sentinelCopyWithoutContextEndSrc — копия, различающая все sentinel'ы канона,
// но не конец контекста: дефект kaname#383 в форме копии.
const sentinelCopyWithoutContextEndSrc = `package sa_keys

func mapPGErr(err error) error {
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	case errors.Is(err, iamerr.ErrInternal):
		return status.Error(codes.Internal, "internal SA key error")
	}
	return status.Error(codes.Internal, "internal SA key error")
}
`

// sentinelCopyWithContextEndAliasedSrc — законный близнец: та же копия с
// полосой конца контекста, пакет `context` импортирован под псевдонимом, а
// полоса записана условием if.
const sentinelCopyWithContextEndAliasedSrc = `package sa_keys

import (
	stdctx "context"
)

func mapPGErr(err error) error {
	if errors.Is(err, stdctx.Canceled) || errors.Is(err, stdctx.DeadlineExceeded) {
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	}
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	case errors.Is(err, iamerr.ErrInternal):
		return status.Error(codes.Internal, "internal SA key error")
	}
	return status.Error(codes.Internal, "internal SA key error")
}
`

func scanOneTranslator(t *testing.T, rel, src string) check.SentinelTranslator {
	t.Helper()
	ts, census, err := check.ScanSentinelTranslators(rel, []byte(src))
	if err != nil {
		t.Fatalf("разбор %s: %v", rel, err)
	}
	if len(ts) != 1 {
		t.Fatalf("переводчик в %s опознан %d раз(а) вместо одного: %+v", rel, len(ts), census)
	}
	return ts[0]
}

// TestSentinelParityGateRedsOnACopyMissingTheContextEndLane — инъекция
// дефектом kaname#383: копия без полосы конца контекста — находка, и находка
// называет обе ошибки контекста.
func TestSentinelParityGateRedsOnACopyMissingTheContextEndLane(t *testing.T) {
	canon := scanOneTranslator(t, "internal/apps/kaname/shared/errors.go", sentinelCanonWithContextEndSrc)
	for _, lane := range []string{"context.Canceled", "context.DeadlineExceeded"} {
		if !canon.Has(lane) {
			t.Fatalf("канон с полосой конца контекста прочитан без %s: %v — полоса вне наблюдения, "+
				"и копия без неё выглядит полной", lane, canon.Sentinels)
		}
	}
	const rel = "internal/apps/kaname/api/sa_keys/usecases.go"
	findings := sentinelParityFindings(canon, []check.SentinelTranslator{scanOneTranslator(t, rel, sentinelCopyWithoutContextEndSrc)})
	if len(findings) != 1 {
		t.Fatalf("копия без полосы конца контекста НЕ стала находкой: %v", findings)
	}
	for _, want := range []string{rel, "context.Canceled", "context.DeadlineExceeded"} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %s: %q", want, findings[0])
		}
	}
	if strings.Contains(findings[0], "ErrNotFound") {
		t.Errorf("находка называет полосу, которую копия различает: %q", findings[0])
	}
}

// TestSentinelParityGateReadsTheContextEndLaneInEveryLegalForm — законный
// близнец: полоса записана условием if под псевдонимом импорта — молчание.
func TestSentinelParityGateReadsTheContextEndLaneInEveryLegalForm(t *testing.T) {
	canon := scanOneTranslator(t, "internal/apps/kaname/shared/errors.go", sentinelCanonWithContextEndSrc)
	cp := scanOneTranslator(t, "internal/apps/kaname/api/sa_keys/usecases.go", sentinelCopyWithContextEndAliasedSrc)
	if f := sentinelParityFindings(canon, []check.SentinelTranslator{cp}); len(f) != 0 {
		t.Fatalf("копия с полосой конца контекста под псевдонимом импорта объявлена находкой: %v "+
			"(прочитано %v)", f, cp.Sentinels)
	}
}

// TestSentinelScannerDoesNotReadAForeignCanceled — граница опознания: поле
// `Canceled` чужого значения — не ошибка пакета `context`, и полосой оно не
// читается. Иначе копия «различала» бы конец контекста, не зная его.
func TestSentinelScannerDoesNotReadAForeignCanceled(t *testing.T) {
	const src = `package p

func translate(err error, st state) error {
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, "")
	case errors.Is(err, iamerr.ErrAborted):
		return status.Error(codes.Aborted, "")
	case errors.Is(err, st.Canceled):
		return status.Error(codes.Unavailable, "")
	}
	return status.Error(codes.Internal, "internal error")
}
`
	tr := scanOneTranslator(t, "internal/x/a.go", src)
	if tr.Has("context.Canceled") {
		t.Fatalf("поле чужого значения прочитано ошибкой пакета context: %v", tr.Sentinels)
	}
}

// TestSentinelScannerNeedsTwoIAMSentinelsEvenWithTheContextLane — признак
// переводчика прежний: два и более sentinel'а `iamerr`. Полосы конца контекста
// в этот счёт не входят — иначе переводчиком стала бы функция, судящая только
// срок и одну полосу.
func TestSentinelScannerNeedsTwoIAMSentinelsEvenWithTheContextLane(t *testing.T) {
	const src = `package p

func onDeadline(err error) error {
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.Unavailable, "")
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, "")
	}
	return status.Error(codes.Internal, "internal error")
}
`
	ts, census, err := check.ScanSentinelTranslators("internal/x/a.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.WithSentinels != 1 {
		t.Fatalf("sentinel'ы не прочитаны — граница проверена ни на чём: %+v", census)
	}
	if len(ts) != 0 {
		t.Fatalf("функция с одним sentinel'ом iamerr объявлена переводчиком: %+v", ts)
	}
}
