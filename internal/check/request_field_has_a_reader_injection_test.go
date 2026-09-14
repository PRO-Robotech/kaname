// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// request_field_has_a_reader_injection_test.go — доказательство того, что гейт
// «у поля запроса есть читатель» СПОСОБЕН упасть и способен смолчать.
//
// У каждой оси две стороны: внесённый дефект обязан найтись С КООРДИНАТОЙ, а
// законный близнец — промолчать. Близнец отличается от дефекта РОВНО ОДНИМ
// названным фактом; иначе красное могло прийти от соседа, и ось ничего не
// доказывает.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// judge — один прогон разбора на синтетической паре «контракт × прод-код».
func judge(t *testing.T, proto, goSrc string) check.RequestFieldCensus {
	t.Helper()
	surface, err := check.ProtoSurfaceIn("synthetic.proto", proto)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: разбор контракта: %v", err)
	}
	messages := map[string]bool{}
	for _, u := range surface.Requests {
		messages[u.Message] = true
	}
	if len(messages) == 0 {
		t.Fatalf("фикстура негодна: в синтетическом контракте нет сообщений запроса")
	}
	reads, whole, err := check.RequestFieldReadsIn("synthetic.go", goSrc, messages)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: разбор Go: %v", err)
	}
	return check.JudgeRequestFieldReaders(
		[]check.ProtoSurface{surface}, reads, whole, 1, 1)
}

func names(c check.RequestFieldCensus) string { return strings.Join(c.Findings, "\n") }

// protoOneField — контракт с ОДНИМ полем; всё, что меняется по осям ниже,
// задаётся параметрами, чтобы близнец отличался одним фактом.
func protoOneField(fieldLine, rpcOptions string) string {
	return `syntax = "proto3";
service WidgetService {
  rpc Get (GetWidgetRequest) returns (Widget) {
` + rpcOptions + `  }
}
message GetWidgetRequest {
  ` + fieldLine + `
}
message Widget {
  string id = 1;
}
`
}

const goReadsWidgetID = `package api
func (h *Handler) Get(ctx context.Context, req *iamv1.GetWidgetRequest) (*iamv1.Widget, error) {
	return h.uc.Execute(ctx, req.GetWidgetId())
}
`

const goReadsNothing = `package api
func (h *Handler) Get(ctx context.Context, req *iamv1.GetWidgetRequest) (*iamv1.Widget, error) {
	return h.uc.Execute(ctx)
}
`

// Ось A. Поле без читателя — находка; то же поле с читателем — молчание.
func TestInjection_FieldWithoutAReaderIsFound(t *testing.T) {
	t.Parallel()

	defect := judge(t, protoOneField("string widget_id = 1;", ""), goReadsNothing)
	if len(defect.Findings) != 1 {
		t.Fatalf("внесённый дефект НЕ НАЙДЕН: находок %d, ожидалась 1\n%s",
			len(defect.Findings), names(defect))
	}
	if !strings.Contains(defect.Findings[0], "GetWidgetRequest.widget_id") {
		t.Fatalf("находка не называет координату: %s", defect.Findings[0])
	}
	if !strings.Contains(defect.Findings[0], "synthetic.proto:7") {
		t.Fatalf("находка не называет файл и строку: %s", defect.Findings[0])
	}

	twin := judge(t, protoOneField("string widget_id = 1;", ""), goReadsWidgetID)
	if len(twin.Findings) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %s", names(twin))
	}
	if twin.Fields != 1 {
		t.Fatalf("перепись близнеца неверна: полей %d, ожидалось 1", twin.Fields)
	}
}

// Ось B. Геттер-ТЁЗКА у чужого сообщения читателем не является.
//
// Это довод в пользу разбора узлов вместо поиска имени: `GetWidgetId` объявлен
// и у соседнего сообщения, и предикат по имени засчитал бы его.
func TestInjection_NamesakeGetterOnAnotherMessageIsNotAReader(t *testing.T) {
	t.Parallel()

	const protoTwo = `syntax = "proto3";
service WidgetService {
  rpc Get (GetWidgetRequest) returns (Widget) {}
  rpc Drop (DropWidgetRequest) returns (Widget) {}
}
message GetWidgetRequest {
  string widget_id = 1;
}
message DropWidgetRequest {
  string widget_id = 1;
}
message Widget { string id = 1; }
`
	// читается ТОЛЬКО поле снятия; у чтения — тёзка и ни одного обращения
	const goReadsDropOnly = `package api
func (h *Handler) Drop(ctx context.Context, req *iamv1.DropWidgetRequest) error {
	return h.uc.Execute(ctx, req.GetWidgetId())
}
`
	defect := judge(t, protoTwo, goReadsDropOnly)
	if len(defect.Findings) != 1 {
		t.Fatalf("тёзка засчитан читателем: находок %d, ожидалась 1 "+
			"(GetWidgetRequest.widget_id)\n%s", len(defect.Findings), names(defect))
	}
	if !strings.Contains(defect.Findings[0], "GetWidgetRequest.widget_id") {
		t.Fatalf("найдено не то сообщение: %s", defect.Findings[0])
	}

	const goReadsBoth = `package api
func (h *Handler) Drop(ctx context.Context, req *iamv1.DropWidgetRequest) error {
	return h.uc.Execute(ctx, req.GetWidgetId())
}
func (h *Handler) Get(ctx context.Context, req *iamv1.GetWidgetRequest) error {
	return h.uc.Execute(ctx, req.GetWidgetId())
}
`
	twin := judge(t, protoTwo, goReadsBoth)
	if len(twin.Findings) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %s", names(twin))
	}
}

// Ось C. Одноимённый параметр в двух функциях ОДНОГО файла не смешивает
// прочтения — область видимости на функцию, а не на файл.
//
// Это и был дефект первой редакции разбора: плоская карта на файл оставляла
// последнюю связь, и 230 полей объявлялись мёртвыми при живых читателях.
func TestInjection_SameParameterNameInTwoFunctionsDoesNotMixReads(t *testing.T) {
	t.Parallel()

	const protoTwo = `syntax = "proto3";
service WidgetService {
  rpc Get (GetWidgetRequest) returns (Widget) {}
  rpc List (ListWidgetsRequest) returns (Widget) {}
}
message GetWidgetRequest {
  string widget_id = 1;
}
message ListWidgetsRequest {
  string page_token = 1;
}
message Widget { string id = 1; }
`
	// оба параметра названы `req` — ровно форма обработчиков этого дерева
	const goBothNamedReq = `package api
func (h *Handler) Get(ctx context.Context, req *iamv1.GetWidgetRequest) error {
	return h.uc.Execute(ctx, req.GetWidgetId())
}
func (h *Handler) List(ctx context.Context, req *iamv1.ListWidgetsRequest) error {
	return h.uc.Execute(ctx, req.GetPageToken())
}
`
	twin := judge(t, protoTwo, goBothNamedReq)
	if len(twin.Findings) != 0 {
		t.Fatalf("прочтения смешаны между одноимёнными параметрами: %s", names(twin))
	}

	// дефект: второй обработчик своё поле не читает — находка ровно одна,
	// и это ДОКАЗЫВАЕТ, что первый его не «прикрыл» своим `req`
	const goSecondReadsNothing = `package api
func (h *Handler) Get(ctx context.Context, req *iamv1.GetWidgetRequest) error {
	return h.uc.Execute(ctx, req.GetWidgetId())
}
func (h *Handler) List(ctx context.Context, req *iamv1.ListWidgetsRequest) error {
	return h.uc.Execute(ctx)
}
`
	defect := judge(t, protoTwo, goSecondReadsNothing)
	if len(defect.Findings) != 1 ||
		!strings.Contains(defect.Findings[0], "ListWidgetsRequest.page_token") {
		t.Fatalf("дефект второго обработчика не найден: находок %d\n%s",
			len(defect.Findings), names(defect))
	}
}

// Ось D. Поле, названное `scope_extractor`, читает КРАЙ — находкой не является.
// Близнец отличается одним фактом: у глагола нет объявления области.
func TestInjection_ScopeExtractorFieldIsReadByTheEdge(t *testing.T) {
	t.Parallel()

	const withScope = `    option (corelib.authz.v1.scope_extractor) = {
      object_type:        "project"
      from_request_field: "widget_id"
    };
`
	silent := judge(t, protoOneField("string widget_id = 1;", withScope), goReadsNothing)
	if len(silent.Findings) != 0 {
		t.Fatalf("поле, читаемое краем, объявлено находкой: %s", names(silent))
	}
	if silent.ScopeReadFields != 1 {
		t.Fatalf("перепись не назвала поле области: ScopeReadFields=%d, ожидалась 1",
			silent.ScopeReadFields)
	}

	defect := judge(t, protoOneField("string widget_id = 1;", ""), goReadsNothing)
	if len(defect.Findings) != 1 {
		t.Fatalf("без объявления области поле обязано стать находкой: находок %d\n%s",
			len(defect.Findings), names(defect))
	}
}

// Ось E. Поле `deprecated` выведено из популяции и СОСЧИТАНО.
func TestInjection_DeprecatedFieldIsCountedNotJudged(t *testing.T) {
	t.Parallel()

	silent := judge(t,
		protoOneField("string widget_id = 1 [deprecated = true];", ""), goReadsNothing)
	if len(silent.Findings) != 0 {
		t.Fatalf("поле deprecated объявлено находкой: %s", names(silent))
	}
	if silent.DeprecatedFields != 1 {
		t.Fatalf("перепись не назвала поле deprecated: %d, ожидалось 1",
			silent.DeprecatedFields)
	}

	// один факт различия — снятая пометка
	defect := judge(t, protoOneField("string widget_id = 1;", ""), goReadsNothing)
	if len(defect.Findings) != 1 {
		t.Fatalf("без пометки поле обязано стать находкой: находок %d\n%s",
			len(defect.Findings), names(defect))
	}
}

// Ось F. Запрос, ушедший в вызов ЦЕЛИКОМ, выведен из вердикта и СОСЧИТАН —
// прощение молчаливым не бывает.
func TestInjection_RequestPassedWholeIsCountedNotSilentlyForgiven(t *testing.T) {
	t.Parallel()

	const goPassesWhole = `package api
func (h *Handler) Get(ctx context.Context, req *iamv1.GetWidgetRequest) error {
	return h.uc.Execute(ctx, req)
}
`
	escaped := judge(t, protoOneField("string widget_id = 1;", ""), goPassesWhole)
	if len(escaped.Findings) != 0 {
		t.Fatalf("запрос, ушедший целиком, объявлен находкой: %s", names(escaped))
	}
	if escaped.WholePassed != 1 || escaped.EscapedFields != 1 {
		t.Fatalf("перепись не назвала передачу целиком: сообщений %d, полей %d "+
			"— ожидалось 1 и 1", escaped.WholePassed, escaped.EscapedFields)
	}

	defect := judge(t, protoOneField("string widget_id = 1;", ""), goReadsNothing)
	if len(defect.Findings) != 1 {
		t.Fatalf("без передачи целиком поле обязано стать находкой: находок %d\n%s",
			len(defect.Findings), names(defect))
	}
}

// Ось G. Пустое сообщение, записанное ОДНОЙ строкой, не проглатывает поля
// следующего.
//
// Первая редакция замера разбирала тело до первой закрывающей скобки на своей
// строке и приписывала запросу поля ОТВЕТА: две находки, обе ложные, обе этой
// формы. Ось стережёт возврат.
func TestInjection_OneLineEmptyMessageDoesNotSwallowTheNextOne(t *testing.T) {
	t.Parallel()

	const protoEmptyThenResponse = `syntax = "proto3";
service WidgetService {
  rpc List (ListWidgetsRequest) returns (ListWidgetsResponse) {}
}
message ListWidgetsRequest {}
message ListWidgetsResponse {
  repeated string widgets = 1;
}
`
	c := judge(t, protoEmptyThenResponse, goReadsNothing)
	if len(c.Findings) != 0 {
		t.Fatalf("поля ОТВЕТА приписаны запросу: %s", names(c))
	}
	if c.Fields != 0 {
		t.Fatalf("у пустого сообщения запроса насчитано полей %d, ожидалось 0", c.Fields)
	}
}

// Ось H. Пустой вход даёт ПУСТУЮ перепись, а не зелёный вердикт о дереве.
//
// Судит это сам прогон гейта (он падает на нулевом обходе); здесь доказывается,
// что судья не выдумывает находок и не выдумывает популяции.
func TestInjection_EmptyInputProducesAnEmptyCensus(t *testing.T) {
	t.Parallel()

	c := check.JudgeRequestFieldReaders(nil, nil, nil, 0, 0)
	if c.Fields != 0 || len(c.Findings) != 0 || c.Messages != 0 {
		t.Fatalf("судья на пустом входе выдумал перепись: %s", c.Summary())
	}
}
