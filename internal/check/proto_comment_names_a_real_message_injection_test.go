// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// proto_comment_names_a_real_message_injection_test.go — доказательство
// способности гейта упасть И смолчать.
//
// Инъекция подаёт НАСТОЯЩИЙ вход — тот, из которого гейт и выведен: комментарий
// привязки обещал `Tuple.condition` при том, что сообщения `Tuple` в контрактах
// не было ни одного (kaname#132). Законные близнецы — те же формы записи там,
// где они законны.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// protoInjectionSrc — настоящий дефект дословно.
const protoInjectionSrc = `syntax = "proto3";

message AccessBinding {
  // Conditions on a tuple remain first-class and untouched: the model declares
  // them, and the internal listener carries them on ` + "`Tuple.condition`" + `.
  reserved 9, 14;
}
`

// protoTwinSrc — законные близнецы, каждый своей осью:
//
//	(а) ссылка на СУЩЕСТВУЮЩЕЕ сообщение — молчание;
//	(б) полная форма с именем пакета перед типом — тип берётся последним
//	    сегментом с заглавной, пакет за сообщение не принимается;
//	(в) форма через службу — то же, служба за сообщение не принимается;
//	(г) имя типа БЕЗ обратных кавычек — не координата, а проза;
//	(д) вложенное сообщение `Foo.Bar` — обещания ПОЛЯ в нём нет, и гейт его
//	    не судит: он судит тип, а не поле.
const protoTwinSrc = `syntax = "proto3";

// AccessBinding — ссылка на своё же сообщение: ` + "`AccessBinding.scope_type`" + `.
// Полная форма: ` + "`kaname.cloud.iam.v1.AccessBinding.scope_type`" + `.
// Через службу: ` + "`AuthorizeService.CheckRequest.context`" + `.
// Без кавычек Tuple.condition координатой не является — это проза.
// Вложенное: ` + "`AccessBinding.Nested`" + ` — поля не обещает.
message AccessBinding {
  string scope_type = 1;
}

message CheckRequest {
  string context = 1;
}
`

// protoKnownFromSrc — множество известных типов из того же источника, что читает
// гейт. Собирается ТЕМ ЖЕ разбором: своё множество на стороне пробы осталось бы
// зелёным, когда гейт читает объявления иначе.
func protoKnownFromSrc(srcs ...string) map[string]bool {
	known := map[string]bool{}
	for _, s := range srcs {
		for _, n := range check.ProtoTypeDecls([]byte(s)) {
			known[n] = true
		}
	}
	return known
}

// TestProtoCommentGateRedsOnADanglingMessage — инъекция настоящим дефектом.
func TestProtoCommentGateRedsOnADanglingMessage(t *testing.T) {
	const rel = "proto/kaname/cloud/iam/v1/access_binding.proto"
	refs, census := check.ScanProtoCommentRefs(rel, []byte(protoInjectionSrc))
	if census.Refs == 0 {
		t.Fatalf("перепись инъекции пуста — разбор ничего не прочитал, и его молчание "+
			"сказано ни о чём: %+v", census)
	}
	findings := protoCommentFindings(refs, protoKnownFromSrc(protoInjectionSrc))
	if len(findings) != 1 {
		t.Fatalf("обещание несуществующего сообщения НЕ стало находкой: находок %d при "+
			"переписи %+v\nГейт, не краснеющий на дефекте, из которого он выведен, не "+
			"удерживает ничего", len(findings), census)
	}
	for _, want := range []string{rel, "Tuple.condition", `"Tuple"`} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %s: %q", want, findings[0])
		}
	}
	// Объявление В ТОМ ЖЕ файле прочитано — иначе множество известных типов было
	// бы пустым, и находкой стала бы любая ссылка, включая законную.
	if census.Decls != 1 {
		t.Errorf("объявлений message прочитано %d из одного: %+v", census.Decls, census)
	}
}

// TestProtoCommentGateStaysSilentOnLegalTwins — гейт обязан молчать там, где
// форма законна. Без этого он ловит форму, а не существо.
func TestProtoCommentGateStaysSilentOnLegalTwins(t *testing.T) {
	const rel = "proto/kaname/cloud/iam/v1/access_binding.proto"
	refs, census := check.ScanProtoCommentRefs(rel, []byte(protoTwinSrc))
	if f := protoCommentFindings(refs, protoKnownFromSrc(protoTwinSrc)); len(f) != 0 {
		t.Fatalf("законная ссылка объявлена находкой: %v", f)
	}
	// Ровно три координаты: короткая, полная и через службу. Проза без кавычек и
	// вложенное сообщение координатами НЕ считаются — это границы, названные прямо.
	if census.Refs != 3 {
		t.Fatalf("ссылок прочитано %d, ожидалось три (короткая, полная, через службу): "+
			"проза без кавычек и вложенное `Foo.Bar` координатами не являются — %+v",
			census.Refs, census)
	}
	got := map[string]string{}
	for _, r := range refs {
		got[r.Text] = r.Type
	}
	for text, want := range map[string]string{
		"AccessBinding.scope_type":                     "AccessBinding",
		"kaname.cloud.iam.v1.AccessBinding.scope_type": "AccessBinding",
		"AuthorizeService.CheckRequest.context":        "CheckRequest",
	} {
		if got[text] != want {
			t.Errorf("форма %q разобрана в тип %q, ожидался %q — форма, о которой "+
				"распознаватель не знает, даёт МОЛЧАНИЕ, а не находку", text, got[text], want)
		}
	}
}

// TestProtoCommentGateReadsOnlyComments — координата в КОДЕ контракта ссылкой не
// является: там она объявление, а не обещание.
func TestProtoCommentGateReadsOnlyComments(t *testing.T) {
	const src = "syntax = \"proto3\";\n\n" +
		"message M {\n" +
		"  // `Tuple.condition` — здесь это обещание.\n" +
		"  string s = 1; // хвостовой комментарий отдельной строкой не является\n" +
		"}\n"
	refs, census := check.ScanProtoCommentRefs("proto/x.proto", []byte(src))
	if census.Refs != 1 || len(refs) != 1 {
		t.Fatalf("прочитано %d ссылок из одной: разбор берёт строки, начинающиеся с «//», "+
			"и только их — %+v", census.Refs, census)
	}
	if census.Comments == 0 {
		t.Fatalf("строк комментария прочитано ноль — перепись обязана их называть, иначе "+
			"«ссылок ноль» неотличимо от «комментариев не читали»: %+v", census)
	}
}

// TestProtoCommentWalkTakesContractsOnly — отбор гейта. Проверяется ТОТ ЖЕ
// предикат, которым судит гейт.
func TestProtoCommentWalkTakesContractsOnly(t *testing.T) {
	if !protoCommentWalkable("proto/kaname/cloud/iam/v1/access_binding.proto") {
		t.Fatalf("отбор гейта не берёт контракт — тогда осматривать нечего")
	}
	for _, rel := range []string{
		"proto/kaname/cloud/iam/v1/fga_model.fga",
		"pkg/api/kaname/cloud/iam/v1/access_binding.pb.go",
	} {
		if protoCommentWalkable(rel) {
			t.Errorf("отбор гейта берёт %s — предмет там не его", rel)
		}
	}
}
