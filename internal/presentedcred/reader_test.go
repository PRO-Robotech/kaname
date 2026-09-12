// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reader_test.go — семейства VER, FWD, REV и DENY приёмки KAN-AUTHN-1
// (задача продукта #2077).
//
// Единица наблюдения — АРЕНДАТОР ЧУЖОГО ОБЛАКА: у него нет ни нашего края,
// чтобы передать личность, ни модульного сертификата. Всё, чего он не может
// проверить у себя, наблюдаемым поведением не является — поэтому здесь
// утверждается ровно то, что видит вызывающий: дошёл ли вызов, кем он назван и
// побайтово ли одинаков отказ.
package presentedcred_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

// ── VER — верификация предъявленного ────────────────────────────────────────

// TestKAN_VER_01_GoodTokenNamesTheCaller — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ всего
// семейства. Без него одиннадцать отрицаний ниже зеленели бы на читателе,
// отвергающем вообще всё.
func TestKAN_VER_01_GoodTokenNamesTheCaller(t *testing.T) {
	s := newStand(t)
	p, present, err := s.present(t, s.good(t))
	if err != nil {
		t.Fatalf("годный токен собственной чеканки отвергнут: %v", err)
	}
	if !present {
		t.Fatal("вызов дошёл, но носитель личности пуст — вызывающий не назван")
	}
	// Утверждение о ПРИСУТСТВИИ — сравнением с самим идентификатором, а не с
	// запасным значением: запасное есть общее наблюдаемое двух разных состояний
	// («личности не было» и «системная выставлена явно»), и утверждать им
	// что-либо о носителе нельзя. Вычищенность носителя утверждает признак
	// наличия выше.
	if p.ID != testPrincipalID {
		t.Errorf("вызывающим назван %q, ожидается субъект токена %q — подставная личность "+
			"вместо той, кому токен выдан", p.ID, testPrincipalID)
	}
	if p.Type != "user" || p.DisplayName != testDisplay {
		t.Errorf("состав личности собран не из утверждений токена: %+v", p)
	}
}

// TestKAN_VER_02_ExpiredIsRefused — истёкший токен.
func TestKAN_VER_02_ExpiredIsRefused(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.expiry = s.now.Add(-2 * tokenpolicy.ClockSkew) // ЕДИНСТВЕННЫЙ изменённый факт
	assertRefused(t, s, m.sign(t))
}

// TestKAN_VER_03_SignatureThatDoesNotVerifyIsRefused — идентификатор ключа
// резолвится, подпись этим ключом НЕ СХОДИТСЯ.
//
// С KAN-VER-10 сценарий разведён намеренно: там идентификатор не резолвится и
// до подписи дело не доходит вовсе.
func TestKAN_VER_03_SignatureThatDoesNotVerifyIsRefused(t *testing.T) {
	s := newStand(t)
	// Тот же kid и тот же алгоритм, ДРУГАЯ пара ключей: реестр отдаёт публичную
	// половину первой, подпись положена второй.
	impostor := newKey(t, testKID, domain.SigningAlgES256)
	m := goodMint(impostor, s.now)
	m.kid = testKID
	assertRefused(t, s, m.sign(t))
	if s.keys.err != nil {
		t.Fatal("решение принято не собственным реестром")
	}
}

// TestKAN_VER_04_ForeignAudienceIsRefused — токен нашей чеканки, выданный ДЛЯ
// ДРУГОГО адресата. Ровно тот сценарий, ради которого адресат назван осью 3
// решения: у авторитета отзыва он объявлен отступлением и не проверяется.
func TestKAN_VER_04_ForeignAudienceIsRefused(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.audience = []string{"kaname-registry-token"}
	assertRefused(t, s, m.sign(t))
}

// TestKAN_VER_05_NotYetValidIsRefused — момент начала действия в будущем.
func TestKAN_VER_05_NotYetValidIsRefused(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.notBefore = s.now.Add(2 * tokenpolicy.ClockSkew)
	assertRefused(t, s, m.sign(t))
}

// TestKAN_VER_05_ClockSkewIsThePlatformOne — допуск на расхождение часов ТОТ ЖЕ,
// что у остальных проверяющих продукта: второго значения этой величины не
// заводится.
//
// Обе стороны, иначе утверждение вакуумно: внутри допуска — проход, за
// пределом — отказ.
func TestKAN_VER_05_ClockSkewIsThePlatformOne(t *testing.T) {
	s := newStand(t)

	within := goodMint(s.key, s.now)
	within.notBefore = s.now.Add(tokenpolicy.ClockSkew / 2)
	if _, _, err := s.present(t, within.sign(t)); err != nil {
		t.Errorf("токен внутри допуска платформы (%s) отвергнут: %v", tokenpolicy.ClockSkew, err)
	}

	beyond := goodMint(s.key, s.now)
	beyond.notBefore = s.now.Add(tokenpolicy.ClockSkew + time.Minute)
	assertRefused(t, s, beyond.sign(t))
}

// TestKAN_VER_06_AlgorithmOutsideTheDeclaredListIsRefused — подпись вне
// ОБЪЯВЛЕННОГО УСТАНОВКОЙ перечня.
//
// Один факт здесь — сам перечень: токен в обеих половинах ПОБАЙТОВО ОДИН И ТОТ
// ЖЕ, меняется только то, что объявила установка. Так утверждение говорит
// именно то, ради чего заведено: решение принимается по перечню установки, а не
// по тому, что заявлено в самом токене.
func TestKAN_VER_06_AlgorithmOutsideTheDeclaredListIsRefused(t *testing.T) {
	edKey := newKey(t, "kaname-2026-09-ed", domain.SigningAlgEdDSA)
	m := goodMint(edKey, time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	raw := m.sign(t)

	permissive := newStand(t,
		withAllowedAlgorithms(tokenpolicy.AlgES256, tokenpolicy.AlgEdDSA),
		withExtraPublishedKeys(edKey.published))
	if _, _, err := permissive.present(t, raw); err != nil {
		t.Fatalf("положительный близнец: тот же токен при перечне, который его алгоритм "+
			"содержит, обязан приниматься, иначе отрицание ниже вакуумно: %v", err)
	}

	strict := newStand(t,
		withAllowedAlgorithms(tokenpolicy.AlgES256),
		withExtraPublishedKeys(edKey.published))
	assertRefused(t, strict, raw)
}

// TestKAN_VER_07_ForeignIssuerIsRefused — издателем назван не тот, которым
// установка объявила себя.
func TestKAN_VER_07_ForeignIssuerIsRefused(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.issuer = "https://someone-else.example.test"
	assertRefused(t, s, m.sign(t))
}

// TestKAN_VER_07_UnsetIssuerIsNotAcceptedAsAny — состояния «принимаем издателя,
// которого никто не выбирал» не существует: незаданный издатель отвергается
// ПОСТРОЕНИЕМ читателя, а не молча превращается в «любой наш».
func TestKAN_VER_07_UnsetIssuerIsNotAcceptedAsAny(t *testing.T) {
	_, err := presentedcred.New(presentedcred.Config{
		Audience:          testAudience,
		AllowedAlgorithms: []string{tokenpolicy.AlgES256},
		Keys:              &stubKeys{},
		Revocations:       &stubRevocations{},
	})
	if err == nil {
		t.Fatal("читатель построен без издателя — незаданный издатель означал бы «любой»")
	}
}

// TestKAN_VER_08_ForeignTokenTypeIsRefused — тип, который для публичного
// слушателя не предназначен. Второй предмет оси 3 решения.
//
// ОБЕ формы негодности дают ОДИН исход: «тип не назван» не означает «любой».
func TestKAN_VER_08_ForeignTokenTypeIsRefused(t *testing.T) {
	for name, typ := range map[string]string{
		"чужой тип":     tokenpolicy.TokenTypeClientAssertion,
		"тип не назван": "",
	} {
		t.Run(name, func(t *testing.T) {
			s := newStand(t)
			m := goodMint(s.key, s.now)
			m.typ = typ
			assertRefused(t, s, m.sign(t))
		})
	}
}

// TestKAN_VER_09_HeaderAlgorithmNotBoundToTheKeyIsRefused — алгоритм заголовка
// входит в перечень принимаемых, но НЕ РАВЕН закреплённому за найденным ключом.
//
// Односфактность несущая: «алгоритм допустим» (VER-06) и «алгоритм закреплён за
// ключом» — РАЗНЫЕ отказы. Слить их значило бы вернуть двухфактность.
func TestKAN_VER_09_HeaderAlgorithmNotBoundToTheKeyIsRefused(t *testing.T) {
	s := newStand(t, withAllowedAlgorithms(tokenpolicy.AlgES256, tokenpolicy.AlgEdDSA))
	m := goodMint(s.key, s.now) // ключ реестра закреплён за ES256
	m.headerAlg = tokenpolicy.AlgEdDSA
	assertRefused(t, s, m.sign(t))
}

// TestKAN_VER_10_KeyIDThatDoesNotResolveIsRefused — идентификатор ключа
// называет ключ, которого в собственном реестре нет.
//
// Вторая половина сценария — ФОРМА идентификатора: негодная форма и неизвестный
// идентификатор дают ПОБАЙТОВО РАВНЫЙ отказ. Различимость «мусор» и «не наш»
// сама была бы оракулом.
func TestKAN_VER_10_KeyIDThatDoesNotResolveIsRefused(t *testing.T) {
	s := newStand(t)

	unknown := goodMint(s.key, s.now)
	unknown.kid = "kaname-2026-09-unknown"
	unknownErr := assertRefused(t, s, unknown.sign(t))

	malformed := goodMint(s.key, s.now)
	malformed.kid = "../../etc/passwd\x00"
	malformedErr := assertRefused(t, s, malformed.sign(t))

	assertByteIdentical(t, map[string]error{
		"неизвестный идентификатор":     unknownErr,
		"негодная форма идентификатора": malformedErr,
	})
}

// TestKAN_VER_11_CriticalHeaderNotUnderstoodRefusesTheWholeToken — параметр,
// помеченный обязательным к пониманию и не исполняемый читателем.
//
// Отвергается ВЕСЬ токен, а не игнорируется помеченный параметр: принять его
// значило бы исполнить условие, которого читатель не понял.
func TestKAN_VER_11_CriticalHeaderNotUnderstoodRefusesTheWholeToken(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.crit = []string{"kaname-not-implemented"}
	m.extraHdr = map[string]any{"kaname-not-implemented": "whatever"}
	assertRefused(t, s, m.sign(t))
}

// TestKAN_VER_11_UnderstoodCriticalHeaderSetIsDeclared — перечень параметров,
// которые читатель вправе принять помеченными, ОБЪЯВЛЕН. Пустой перечень
// означает «любой помеченный отвергается» и является решением, а не заготовкой.
func TestKAN_VER_11_UnderstoodCriticalHeaderSetIsDeclared(t *testing.T) {
	// Перечень платформы один; своего у читателя нет by construction —
	// второй разошёлся бы с первым молча.
	if got := tokenpolicy.KnownCriticalHeaders(); len(got) != 0 {
		t.Logf("перечень понимаемых параметров непуст (%v) — сценарий VER-11 обязан "+
			"чеканить параметр ВНЕ него", got)
	}
}

// TestKAN_VER_12_UnknownNonCriticalHeaderIsIgnored — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ
// VER-11, и он обязателен, а не для симметрии: без него читатель, отвергающий
// ЛЮБОЙ незнакомый параметр, проходил бы VER-11 как правильный.
func TestKAN_VER_12_UnknownNonCriticalHeaderIsIgnored(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.extraHdr = map[string]any{"kacho-unknown-but-not-critical": "whatever"}
	p, present, err := s.present(t, m.sign(t))
	if err != nil {
		t.Fatalf("НЕ помеченный обязательным неизвестный параметр обязан игнорироваться: %v", err)
	}
	if !present || p.ID != testPrincipalID {
		t.Errorf("исход обязан совпадать с KAN-VER-01: получено %+v (носитель=%v)", p, present)
	}
}

// TestKAN_VER_NoOutsideAuthorityIsConsulted — решение принято БЕЗ обращения к
// какому-либо внешнему авторитету: реестр ключей собственный.
//
// Наблюдаемо у оператора тем, что читатель построения не имеет ни одного поля
// внешнего источника; здесь — тем, что единственный спрошенный источник ключей
// принадлежит стенду.
func TestKAN_VER_NoOutsideAuthorityIsConsulted(t *testing.T) {
	s := newStand(t)
	if _, _, err := s.present(t, s.good(t)); err != nil {
		t.Fatalf("годный токен отвергнут: %v", err)
	}
	if s.keys.keys == nil {
		t.Fatal("подпись проверена не собственным набором — набор стенда пуст")
	}
}

// ── FWD — прежний путь не отзывается ────────────────────────────────────────

// TestKAN_FWD_01_ForwardedIdentityStillPassesTheReader — переданная личность от
// разрешённого отправителя проходит читателя НЕТРОНУТОЙ, а предъявленное
// удостоверение по-прежнему называет своего вызывающего.
//
// # Здесь стояло отрицание «обе формы разом — отказ». Оно СНЯТО ВМЕСТЕ С ПРЕДМЕТОМ
//
// Ветка отказа была реализацией решения, которое приёмка KAN-AUTHN-1 отозвала
// редакцией 2: полосы делаются взаимоисключающими ПОСТРОЕНИЕМ, а не проверкой —
// край снимает арендаторское удостоверение перед пересылкой за себя, установив
// личность сам. Сочетания двух форм в одном запросе больше не бывает, поэтому у
// отрицания не осталось производителя входа: оно зеленело бы на мире, которого
// нет, и никогда бы не покраснело.
//
// Положительные близнецы того отрицания требование выражали ЖИВОЕ и потому
// остались — под своим именем, а не осиротевшими внутри снятого сценария.
func TestKAN_FWD_01_ForwardedIdentityStillPassesTheReader(t *testing.T) {
	s := newStand(t)
	raw := s.good(t)

	// Полоса предъявленного: годный токен называет своего вызывающего.
	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("годный токен отвергнут: %v", err)
	}

	// Полоса переданной личности: читатель её не касается вовсе.
	forwarded := operations.Principal{Type: "user", ID: "usr-forwarded", DisplayName: "fwd"}
	p, present, err := s.present(t, "", withTrustedForwarded(forwarded))
	if err != nil {
		t.Fatalf("прежний путь отозван: переданная личность без предъявленного токена "+
			"обязана проходить читателя: %v", err)
	}
	if !present || p.ID != forwarded.ID {
		t.Fatalf("читатель подменил переданную личность: %+v (носитель=%v)", p, present)
	}
}

// ── REV — отзыв читается на предъявлении ────────────────────────────────────

// TestKAN_REV_01_RevokedIsRefusedAfterTheCacheWindow — СКВОЗЬ ОБЕ СТОРОНЫ одним
// прогоном: записали отзыв → предъявили тот же токен → отказ.
//
// Две пробы по половине («отзыв записался» и «отвергнутое отвергается») этого
// класса не ловят: каждая зелена о своей половине, а вопрос в том, про один ли
// предмет они говорят.
func TestKAN_REV_01_RevokedIsRefusedAfterTheCacheWindow(t *testing.T) {
	s := newStand(t, withCacheTTL(30*time.Second))
	raw := s.good(t)

	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("исходное предъявление обязано пройти (KAN-VER-01): %v", err)
	}

	s.revs.revoke(testSubject, s.now.Add(time.Minute))
	s.clock.advance(31 * time.Second) // срок кеша истёк; срок токена — НЕТ

	if _, _, err := s.present(t, raw); err == nil {
		t.Fatal("отозванный токен принят после истечения срока кеша — контроль действует " +
			"на выдаче и не действует на предъявлении, а такое состояние не сходится само")
	} else {
		assertSingleRefusal(t, err)
	}
}

// TestKAN_REV_02_NotRevokedKeepsBeingAccepted — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ REV-01,
// отличается ровно отсутствием записи отзыва. Без него «после отзыва
// отвергается» зеленело бы на читателе, отвергающем ВСЁ по истечении кеша.
func TestKAN_REV_02_NotRevokedKeepsBeingAccepted(t *testing.T) {
	s := newStand(t, withCacheTTL(30*time.Second))
	raw := s.good(t)

	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("исходное предъявление обязано пройти: %v", err)
	}
	s.clock.advance(31 * time.Second)
	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("неотозванный токен отвергнут после того же интервала: %v", err)
	}
}

// TestKAN_REV_03_UnavailableAuthorityRefuses — недоступный авторитет отзыва даёт
// ОТКАЗ, а не проход: неполученный ответ не есть «не отозван».
func TestKAN_REV_03_UnavailableAuthorityRefuses(t *testing.T) {
	s := newStand(t)
	s.revs.err = errors.New("хранилище отзывов недоступно")

	_, _, err := s.present(t, s.good(t))
	if err == nil {
		t.Fatal("недоступность авторитета отзыва засчитана как «не отозван» — мягкий проход " +
			"при отказе зависимости")
	}
	assertSingleRefusal(t, err)

	if got := s.reader.Stats(); got.Unavailable == 0 {
		t.Errorf("исход «ответить не смогли» не отличим в измерителях: %+v — оператор не увидит "+
			"разницы между «отказов не было» и «сюда никто не приходил»", got)
	}
}

// TestKAN_REV_04_WindowIsTheCacheTTLNotTheTokenTTL — окно отзыва задаёт СРОК
// КЕША, а не срок удостоверения.
//
// Утверждение решительное намеренно: «вызов ЕЩЁ МОЖЕТ дойти» истинно при любом
// исходе, в том числе на читателе, у которого кеша нет вовсе. Такой читатель
// проходил бы все четыре сценария REV — здесь он ОБЯЗАН краснеть.
func TestKAN_REV_04_WindowIsTheCacheTTLNotTheTokenTTL(t *testing.T) {
	s := newStand(t, withCacheTTL(30*time.Second))
	raw := s.good(t) // срок токена 10 минут — заметно длиннее срока кеша

	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("исходное предъявление обязано пройти: %v", err)
	}
	askedAfterFirst := s.revs.askedTimes()

	s.revs.revoke(testSubject, s.now.Add(time.Minute))

	// Внутри окна: положительный вердикт закеширован, срок кеша не истёк.
	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("вызов внутри объявленного окна кеша обязан ДОХОДИТЬ — это объявленное окно, "+
			"а не дефект; у читателя без кеша здесь отказ: %v", err)
	}
	if s.revs.askedTimes() != askedAfterFirst {
		t.Errorf("внутри окна авторитет спрошен снова (%d → %d) — кеша положительного вердикта "+
			"нет, и окно задаёт не он", askedAfterFirst, s.revs.askedTimes())
	}

	// За окном: тот же токен отвергается.
	s.clock.advance(31 * time.Second)
	if _, _, err := s.present(t, raw); err == nil {
		t.Fatal("после истечения объявленного срока кеша отозванный токен принят")
	}

	// ОТРИЦАТЕЛЬНЫЙ вердикт не кешируется: восстановленный доступ не ждёт
	// истечения записи.
	s.revs.before = nil
	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("восстановленный доступ ждёт истечения записи — отрицательный вердикт "+
			"закеширован: %v", err)
	}
}

// ── DENY — отказы аутентификации неразличимы между собой ────────────────────

// TestKAN_DENY_01_EveryAuthenticationRefusalIsByteIdentical — ЗАКРЫТЫЙ перечень
// из тринадцати причин, и ответы на них ПОБАЙТОВО равны между собой.
//
// Равенство утверждается сравнением БАЙТОВ полного ответа, а не совпадением
// кодов: два отказа с одним кодом и разными приложенными подробностями
// различимы, а на публичной цепочке стоит звено, приписывающее машиночитаемую
// причину отказам по правам.
func TestKAN_DENY_01_EveryAuthenticationRefusalIsByteIdentical(t *testing.T) {
	refusals := map[string]error{}

	// 1 — истёк
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.expiry = s.now.Add(-2 * tokenpolicy.ClockSkew)
	refusals["истёк"] = mustRefuse(t, s, m.sign(t))

	// 2 — подпись не сходится
	s = newStand(t)
	impostor := newKey(t, testKID, domain.SigningAlgES256)
	m = goodMint(impostor, s.now)
	m.kid = testKID
	refusals["подпись не сходится"] = mustRefuse(t, s, m.sign(t))

	// 3 — чужой адресат
	s = newStand(t)
	m = goodMint(s.key, s.now)
	m.audience = []string{"kaname-registry-token"}
	refusals["чужой адресат"] = mustRefuse(t, s, m.sign(t))

	// 4 — время не наступило
	s = newStand(t)
	m = goodMint(s.key, s.now)
	m.notBefore = s.now.Add(tokenpolicy.ClockSkew + time.Minute)
	refusals["время не наступило"] = mustRefuse(t, s, m.sign(t))

	// 5 — подпись вне перечня
	edKey := newKey(t, "kaname-2026-09-ed", domain.SigningAlgEdDSA)
	s = newStand(t, withAllowedAlgorithms(tokenpolicy.AlgES256), withExtraPublishedKeys(edKey.published))
	refusals["подпись вне перечня"] = mustRefuse(t, s, goodMint(edKey, s.now).sign(t))

	// 6 — чужой издатель
	s = newStand(t)
	m = goodMint(s.key, s.now)
	m.issuer = "https://someone-else.example.test"
	refusals["чужой издатель"] = mustRefuse(t, s, m.sign(t))

	// 7 — чужой тип
	s = newStand(t)
	m = goodMint(s.key, s.now)
	m.typ = tokenpolicy.TokenTypeClientAssertion
	refusals["чужой тип"] = mustRefuse(t, s, m.sign(t))

	// 8 — алгоритм не закреплён за ключом
	s = newStand(t, withAllowedAlgorithms(tokenpolicy.AlgES256, tokenpolicy.AlgEdDSA))
	m = goodMint(s.key, s.now)
	m.headerAlg = tokenpolicy.AlgEdDSA
	refusals["алгоритм не закреплён за ключом"] = mustRefuse(t, s, m.sign(t))

	// 9 — идентификатор ключа не резолвится
	s = newStand(t)
	m = goodMint(s.key, s.now)
	m.kid = "kaname-2026-09-unknown"
	refusals["идентификатор ключа не резолвится"] = mustRefuse(t, s, m.sign(t))

	// 10 — помеченный обязательным параметр не исполняется
	s = newStand(t)
	m = goodMint(s.key, s.now)
	m.crit = []string{"kaname-not-implemented"}
	refusals["критический параметр не исполняется"] = mustRefuse(t, s, m.sign(t))

	// 11 — отозван
	s = newStand(t, withCacheTTL(time.Nanosecond))
	raw := s.good(t)
	s.revs.revoke(testSubject, s.now.Add(time.Minute))
	s.clock.advance(time.Second)
	refusals["отозван"] = mustRefuse(t, s, raw)

	// 12 — авторитет отзыва недоступен
	s = newStand(t)
	s.revs.err = errors.New("хранилище отзывов недоступно")
	refusals["авторитет отзыва недоступен"] = mustRefuse(t, s, s.good(t))

	// ЧЕТЫРНАДЦАТОЙ ПРИЧИНОЙ ЗДЕСЬ СТОЯЛО «обе формы разом» — она СНЯТА ВМЕСТЕ
	// С ПРЕДМЕТОМ: край снимает арендаторское удостоверение перед пересылкой за
	// себя, поэтому вход, на котором эта причина срабатывала, больше не
	// производит никто (см. TestKAN_FWD_01_ForwardedIdentityStillPassesTheReader).
	// Перечень оттого стал на строку короче, а не «перестал покрывать»: причина
	// без производителя входа неотличима от причины, которую забыли проверить.

	if len(refusals) != 12 {
		t.Fatalf("перечень причин закрыт и содержит двенадцать строк, собрано %d — отказ, "+
			"не попавший в перечень, неразличимости ничем не обязан", len(refusals))
	}
	assertByteIdentical(t, refusals)
}

// TestKAN_DENY_02_GoodPresentationGivesADifferentOutcome — ПОЛОЖИТЕЛЬНЫЙ
// БЛИЗНЕЦ. Без него «все отказы одинаковы» — тождественная истина на установке,
// которая отвечает одним и тем же на ВСЁ.
func TestKAN_DENY_02_GoodPresentationGivesADifferentOutcome(t *testing.T) {
	s := newStand(t)
	if _, _, err := s.present(t, s.good(t)); err != nil {
		t.Fatalf("исход годного предъявления обязан ОТЛИЧАТЬСЯ от общего отказа: %v", err)
	}
}

// ── POL — согласие с единым перечнем проверок ───────────────────────────────

// TestKAN_POL_01_DeclaredChecksAgreeWithTheSharedPolicy — состав проверок
// читателя сходится с единым перечнем В ОБЕ СТОРОНЫ, и отступлений НЕТ.
func TestKAN_POL_01_DeclaredChecksAgreeWithTheSharedPolicy(t *testing.T) {
	s := newStand(t)

	if dev := s.reader.DeclaredDeviations(); len(dev) != 0 {
		t.Fatalf("читатель публичного слушателя объявил отступления (%v) — адресат и тип "+
			"суть свойства ЭТОЙ поверхности, и отступления здесь быть не может", dev)
	}
	if missing := tokenpolicy.MissingChecksExcept(s.reader.DeclaredChecks(), nil); len(missing) != 0 {
		t.Errorf("читатель не объявляет обязательных проверок: %v", missing)
	}
	// Обратная сторона: объявленного сверх перечня быть не должно — иначе
	// объявление станет вторым местом об одном предмете.
	mandatory := map[tokenpolicy.Check]bool{}
	for _, c := range tokenpolicy.MandatoryChecks() {
		mandatory[c] = true
	}
	for _, c := range s.reader.DeclaredChecks() {
		if !mandatory[c] {
			t.Errorf("читатель объявляет проверку %q, которой нет в едином перечне", c)
		}
	}
	t.Logf("перепись: обязательных проверок %d · объявлено читателем %d · отступлений %d",
		len(tokenpolicy.MandatoryChecks()), len(s.reader.DeclaredChecks()), len(s.reader.DeclaredDeviations()))
}

// ── OPS — что видит оператор ────────────────────────────────────────────────

// TestKAN_OPS_02_OutcomesAreCountedSeparately — измерители считают И выданные, И
// отвергнутые: ноль в одном ряду иначе отвечает сразу на два вопроса.
func TestKAN_OPS_02_OutcomesAreCountedSeparately(t *testing.T) {
	s := newStand(t)

	if _, _, err := s.present(t, s.good(t)); err != nil {
		t.Fatalf("годное предъявление отвергнуто: %v", err)
	}
	m := goodMint(s.key, s.now)
	m.issuer = "https://someone-else.example.test"
	mustRefuse(t, s, m.sign(t))

	got := s.reader.Stats()
	if got.Accepted == 0 || got.Refused == 0 {
		t.Fatalf("исходы не разведены: %+v", got)
	}
	t.Logf("перепись исходов: принято %d · отвергнуто %d · ответить не смогли %d",
		got.Accepted, got.Refused, got.Unavailable)
}

// TestKAN_OPS_02_RefusalNeverNamesTheFailedCheck — НАРУЖУ уходит суждение, и
// только оно: подробность о том, какая проверка не сошлась, наружу не течёт.
func TestKAN_OPS_02_RefusalNeverNamesTheFailedCheck(t *testing.T) {
	s := newStand(t)
	m := goodMint(s.key, s.now)
	m.audience = []string{"kaname-registry-token"}
	err := mustRefuse(t, s, m.sign(t))

	msg := status.Convert(err).Message()
	for _, leak := range []string{
		"audience", "адресат", "kaname-registry-token", testIssuer, testSubject,
		"issuer", "signature", "revoked", "expired", "kid", testKID,
	} {
		if contains(msg, leak) {
			t.Errorf("текст отказа называет %q — предъявитель узнаёт, какая половина неверна: %q", leak, msg)
		}
	}
}

// ── общие утверждения ───────────────────────────────────────────────────────

// withTrustedForwarded оставляет в контексте ровно то состояние, которое
// оставляет за собой БОЕВАЯ пара извлечения личности на разрешённом отправителе.
//
// Состояние собирается ПРОИЗВОДСТВЕННЫМ извлекателем, а не выкладывается руками:
// признак доверия живёт в непубличном ключе контекста, и фикстура, положившая
// туда своё, была бы снисходительнее продукта — она объявляла бы доверенным то,
// что боевой путь доверенным не считает.
func withTrustedForwarded(p operations.Principal) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		ctx = metadata.NewIncomingContext(ctx, mergeMD(ctx, metadata.Pairs(
			grpcsrv.MDKeyPrincipalType, p.Type,
			grpcsrv.MDKeyPrincipalID, p.ID,
			grpcsrv.MDKeyPrincipalDisplay, p.DisplayName,
		)))
		var out context.Context
		_, _ = grpcsrv.UnaryTrustedPrincipalExtract()(ctx, nil, nil,
			func(c context.Context, _ any) (any, error) {
				out = c
				return nil, nil
			})
		return out
	}
}

func mergeMD(ctx context.Context, add metadata.MD) metadata.MD {
	base, _ := metadata.FromIncomingContext(ctx)
	out := base.Copy()
	if out == nil {
		out = metadata.MD{}
	}
	for k, vs := range add {
		for _, v := range vs {
			out.Append(k, v)
		}
	}
	return out
}

// assertRefused требует отказа и возвращает его для сверки на побайтовое
// равенство.
func assertRefused(t *testing.T, s *stand, raw string) error {
	t.Helper()
	_, _, err := s.present(t, raw)
	if err == nil {
		t.Fatal("предъявление принято, ожидался отказ")
	}
	assertSingleRefusal(t, err)
	return err
}

func mustRefuse(t *testing.T, s *stand, raw string) error {
	t.Helper()
	return assertRefused(t, s, raw)
}

// assertSingleRefusal — отказ несёт код аутентификации, единый текст и НИ ОДНОЙ
// приложенной подробности.
func assertSingleRefusal(t *testing.T, err error) {
	t.Helper()
	st := status.Convert(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("код отказа %s, ожидается %s: отказ аутентификации, оформленный кодом отказа "+
			"по правам, получил бы машиночитаемую причину и стал бы различимым",
			st.Code(), codes.Unauthenticated)
	}
	if st.Message() != presentedcred.RefusalMessage {
		t.Errorf("текст отказа %q, ожидается единый %q", st.Message(), presentedcred.RefusalMessage)
	}
	if d := st.Proto().GetDetails(); len(d) != 0 {
		t.Errorf("к отказу приложено %d подробностей — два отказа, равные по тексту, "+
			"различимы по приложенному", len(d))
	}
}

// assertByteIdentical сверяет ответы ПОБАЙТОВО, а не по кодам.
func assertByteIdentical(t *testing.T, refusals map[string]error) {
	t.Helper()
	var (
		refName  string
		refBytes []byte
	)
	for name, err := range refusals {
		raw, mErr := proto.Marshal(status.Convert(err).Proto())
		if mErr != nil {
			t.Fatalf("сериализация ответа %q: %v", name, mErr)
		}
		if refBytes == nil {
			refName, refBytes = name, raw
			continue
		}
		if string(raw) != string(refBytes) {
			t.Errorf("ответы различимы: %q ≠ %q\n  %q: %s\n  %q: %s",
				name, refName, name, status.Convert(refusals[name]).Proto(),
				refName, status.Convert(refusals[refName]).Proto())
		}
	}
	t.Logf("перепись: причин отказа сверено %d · все побайтово равны", len(refusals))
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}

// ── снимок набора ключей ────────────────────────────────────────────────────

// TestPresented_KeyRegistryIsNotAskedOnEveryPresentation — реестр ключей
// спрашивается СНИМКОМ, а не на каждом предъявлении.
//
// Иначе неаутентифицированный вызывающий, шлющий мусор в предъявителе, получает
// усиление один-к-одному в хранилище: запрос стоит обращения к базе ДО того, как
// выяснится, что подпись негодна. Кеш вердикта отзыва от этого не защищает — он
// стоит ниже по потоку и персонален.
//
// Утверждение двустороннее: по истечении срока снимка реестр спрашивается снова,
// иначе снятый ключ принимался бы вечно.
func TestPresented_KeyRegistryIsNotAskedOnEveryPresentation(t *testing.T) {
	s := newStand(t)
	raw := s.good(t)

	for i := 0; i < 5; i++ {
		if _, _, err := s.present(t, raw); err != nil {
			t.Fatalf("предъявление %d отвергнуто: %v", i, err)
		}
	}
	// Мусор в предъявителе — тот же путь, и он тоже не обязан стоить обращения.
	for i := 0; i < 5; i++ {
		_, _, _ = s.present(t, "not-a-token-at-all")
	}
	if got := s.keys.askedTimes(); got != 1 {
		t.Errorf("реестр спрошен %d раз(а) на десять предъявлений — снимка нет, и "+
			"неаутентифицированный вызывающий усиливает нагрузку на хранилище один к одному", got)
	}

	// Обратная сторона: срок снимка истёк — спрашиваем снова.
	s.clock.advance(31 * time.Second)
	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("предъявление после истечения снимка отвергнуто: %v", err)
	}
	if got := s.keys.askedTimes(); got != 2 {
		t.Errorf("после истечения срока снимка реестр спрошен %d раз(а), ожидается 2 — "+
			"снятый из реестра ключ принимался бы вечно", got)
	}
}

// TestPresented_UnknownKeyIDForcesARefreshWithinItsOwnInterval — у обновления
// снимка ДВА повода, и второй не проходит через первый.
//
// Подписант, назвавший ключ, которого в снимке нет, — это ротация. Ждать по ней
// срока снимка значило бы отвергать живой токен всё окно. Пускать её без
// ограничения — сделать неизвестный идентификатор усилителем нагрузки, то есть
// ровно тем, от чего снимок заводится.
func TestPresented_UnknownKeyIDForcesARefreshWithinItsOwnInterval(t *testing.T) {
	s := newStand(t)

	// Снимок взят.
	if _, _, err := s.present(t, s.good(t)); err != nil {
		t.Fatalf("исходное предъявление отвергнуто: %v", err)
	}
	if got := s.keys.askedTimes(); got != 1 {
		t.Fatalf("реестр спрошен %d раз(а), ожидается 1", got)
	}

	// Ротация: в реестре новый ключ, снимок о нём не знает.
	rotated := newKey(t, "kaname-2026-09-b", domain.SigningAlgES256)
	s.keys.set(s.key.published, rotated.published)
	rawRotated := goodMint(rotated, s.now).sign(t)

	if _, _, err := s.present(t, rawRotated); err != nil {
		t.Fatalf("токен, подписанный ПОВЁРНУТЫМ ключом, отвергнут — вынужденного обновления "+
			"снимка нет, и живой токен ждал бы срока снимка: %v", err)
	}
	afterForced := s.keys.askedTimes()
	if afterForced != 2 {
		t.Errorf("вынужденное обновление спросило реестр %d раз(а), ожидается 2", afterForced)
	}

	// Ограничение: поток неизвестных идентификаторов не превращается в поток
	// запросов к хранилищу.
	for i := 0; i < 10; i++ {
		m := goodMint(s.key, s.now)
		m.kid = "kaname-2026-09-unknown"
		assertRefused(t, s, m.sign(t))
	}
	if got := s.keys.askedTimes(); got != afterForced {
		t.Errorf("десять неизвестных идентификаторов подряд спросили реестр ещё %d раз(а) — "+
			"вынужденное обновление не ограничено собственным интервалом, и неизвестный "+
			"идентификатор стал усилителем нагрузки", got-afterForced)
	}
}

// TestPresented_BrokenOwnKeyIsOurFailureNotTheirBadInput — ключ ИЗ НАШЕГО
// реестра, который не разбирается, — НАША поломка, а не негодный вход.
//
// Смешать их значило бы учить оператора смотреть не туда: единственный
// испорченный ключ отверг бы всё, ряд «отвергнуто» рос бы линейно, ряд «ответить
// не смогли» остался бы нулём, и оператор пошёл бы разбираться с клиентами.
func TestPresented_BrokenOwnKeyIsOurFailureNotTheirBadInput(t *testing.T) {
	s := newStand(t)
	raw := s.good(t)

	broken := s.key.published
	broken.PublicKeyPEM = "-----BEGIN PUBLIC KEY-----\nnot base64 at all\n-----END PUBLIC KEY-----"
	s.keys.set(broken)
	s.clock.advance(31 * time.Second) // снимок обновится

	if _, _, err := s.present(t, raw); err == nil {
		t.Fatal("токен принят на нечитаемом ключе")
	} else {
		assertSingleRefusal(t, err)
	}
	got := s.reader.Stats()
	if got.Unavailable == 0 {
		t.Errorf("испорченный ключ СВОЕГО реестра засчитан отказом предъявителя: %+v — "+
			"оператор пойдёт разбираться с клиентами", got)
	}
	if got.Refused != 0 {
		t.Errorf("наша поломка попала в ряд «отвергнуто»: %+v", got)
	}
}

// TestPresented_MoreThanOneCredentialIsRefused — два предъявленных удостоверения
// в одном запросе.
//
// Та же неоднозначность о том, кто звонит, что и две формы личности разом.
// «Побеждает первый» здесь было бы догадкой, и выбирал бы её порядок метаданных.
//
// Положительный близнец рядом: ОДНО удостоверение принимается.
func TestPresented_MoreThanOneCredentialIsRefused(t *testing.T) {
	s := newStand(t)
	raw := s.good(t)

	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("положительный близнец: одно удостоверение обязано приниматься: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		presentedcred.MetadataKey, "Bearer "+raw,
		presentedcred.MetadataKey, "Bearer "+raw,
	))
	final := func(context.Context, any) (any, error) { return nil, nil }
	_, err := s.reader.UnaryOver(nil)(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Get"}, final)
	if err == nil {
		t.Fatal("два предъявленных удостоверения приняты — победил порядок метаданных")
	}
	assertSingleRefusal(t, err)
}
