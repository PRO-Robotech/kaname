// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package refusaltext — ОДНА проба для всех переводчиков отказа службы: текст,
// который получает вызывающий на признаке недоступности, ФИКСИРОВАН и причины
// не несёт.
//
// # Почему помощник, а не копия утверждения у каждого переводчика
//
// Переводчиков в службе несколько, и предмет у них ОДИН. Копия утверждения в
// каждом пакете разошлась бы с остальными на первом же уточнении — ровно тем
// способом, каким разошлись сами переводчики (задача #2464): канонический был
// переведён на фиксированный текст, а копии остались, и расхождение никем не
// решалось. Утверждение живёт в одном месте; вызывающий приносит только свой
// переводчик и своего законного близнеца.
//
// # Проба утверждает СООБЩЕНИЕ, а не код
//
// Проба, сверяющая лишь код ответа, остаётся зелёной при вернувшемся эхе:
// код `UNAVAILABLE` верен в обоих случаях. Именно такая проба и стояла у
// канонического соседа, поэтому расхождение прожило незамеченным.
package refusaltext

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// CauseMarker — синтетическая подробность цепочки: то, что переводчик обязан
// оставить журналу и НИКОГДА не отдать вызывающему.
//
// Значение намеренно НЕПРАВДОПОДОБНО. Правдоподобная строка (адрес узла, имя
// базы) прошла бы за настоящую и в отказе пробы читалась бы как утечка
// свидетельства, а не как её проверка; кроме того, обе рабочие копии этого
// дерева публичны.
const CauseMarker = "PROBE-CAUSE-MARKER-MUST-NOT-REACH-THE-WIRE"

// callerContext — контекст ВЫЗЫВАЮЩЕГО, поставленный впереди отказа.
//
// Форма несущая, а не украшение: пока никто не оборачивал, «опаково by
// construction» и «опаково by design» выглядели одинаково. Обёртка их
// различает — с ней текст цепочки доезжает до провода дословно.
const callerContext = "probe caller context"

// Probe — переводчик под пробой и его ЗАКОННЫЙ БЛИЗНЕЦ.
type Probe struct {
	// Translate — перевод отказа в gRPC-статус: то, что вызывающий увидит.
	Translate func(error) error

	// Positive / PositiveCode / PositiveMessage — отказ, чей текст ОБЯЗАН
	// доехать дословно. Без него отрицание вакуумно: переводчик, отвечающий
	// фиксированным текстом НА ВСЁ, прошёл бы каждое утверждение ниже и при
	// этом перестал бы говорить вызывающему хоть что-нибудь.
	Positive        error
	PositiveCode    codes.Code
	PositiveMessage string
}

// unavailableInputs — законные формы отказа недоступности, какими они приходят
// переводчику. Перечень не «на всякий случай»: каждая форма встречается в
// дереве, и разбор у них разный — голая обёртка признака, обёртка с контекстом
// вызывающего впереди (её имя признака снимается из СЕРЕДИНЫ) и двойная.
func unavailableInputs() []struct {
	name string
	err  error
} {
	base := iamerr.Wrapf(iamerr.ErrUnavailable, "%s", CauseMarker)
	return []struct {
		name string
		err  error
	}{
		{"признак префиксом", base},
		{"контекст вызывающего впереди", fmt.Errorf("%s: %w", callerContext, base)},
		{"две обёртки контекста", fmt.Errorf("%s: %w", callerContext,
			fmt.Errorf("%s: %w", callerContext, base))},
	}
}

// Run — прогоняет утверждение на переданном переводчике.
func (p Probe) Run(t *testing.T) {
	t.Helper()
	if p.Translate == nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: переводчик не назван")
	}

	for _, tc := range unavailableInputs() {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Translate(tc.err)
			if err == nil {
				t.Fatalf("переводчик вернул nil на отказе недоступности")
			}
			st := status.Convert(err)
			if st.Code() != codes.Unavailable {
				t.Fatalf("код отказа %s, ожидался %s", st.Code(), codes.Unavailable)
			}
			if strings.Contains(st.Message(), CauseMarker) {
				t.Errorf("текст отказа несёт ПРИЧИНУ вызывающему: %q\n\n"+
					"Цепочка признака недоступности ведёт к чужому производителю "+
					"(база, сосед, гейт прав), и её текст вызывающему не адресован. "+
					"Умолчание обязано быть фиксированным: %q. "+
					"Подробность остаётся в цепочке и уходит в журнал.",
					st.Message(), shared.UnavailableMessage)
			}
			if strings.Contains(st.Message(), callerContext) {
				t.Errorf("текст отказа несёт КОНТЕКСТ ВЫЗЫВАЮЩЕГО: %q — "+
					"обёртка внутри процесса вызывающему не адресована", st.Message())
			}
			if st.Message() != shared.UnavailableMessage {
				t.Errorf("текст отказа %q, ожидался фиксированный %q",
					st.Message(), shared.UnavailableMessage)
			}
		})
	}

	t.Run("законный близнец: текст, адресованный вызывающему, доезжает дословно", func(t *testing.T) {
		if p.Positive == nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: законный близнец не назван — "+
				"отрицание без него вакуумно: переводчик, отвечающий %q на ВСЁ, "+
				"прошёл бы каждое утверждение выше", shared.UnavailableMessage)
		}
		err := p.Translate(p.Positive)
		if err == nil {
			t.Fatalf("переводчик вернул nil на законном близнеце")
		}
		st := status.Convert(err)
		if st.Code() != p.PositiveCode {
			t.Errorf("код законного близнеца %s, ожидался %s", st.Code(), p.PositiveCode)
		}
		if st.Message() != p.PositiveMessage {
			t.Errorf("текст законного близнеца %q, ожидался %q — "+
				"фиксированный текст поставлен ШИРЕ своего предмета: "+
				"отказ, адресованный вызывающему, потерял то, ради чего он существует",
				st.Message(), p.PositiveMessage)
		}
	})
}
