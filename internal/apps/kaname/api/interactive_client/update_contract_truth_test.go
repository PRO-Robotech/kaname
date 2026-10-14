// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// update_contract_truth_test.go — kaname#562: контракт Update интерактивного
// клиента говорит о теле то же, что исполняет обработчик.
//
// # ЧТО БЫЛО НЕ ТАК
//
// Комментарий `update_mask` обещал: «immutable fields present in the body are
// silently ignored». Это исход «принято-и-проигнорировано», который тот же файл
// контракта запрещает (NOTE у CreateInteractiveClientRequest), и он к тому же
// невозможен: в UpdateInteractiveClientRequest НЕТ ни одного неизменяемого поля —
// тело физически не может его нести. Неизменяемое называется только маской, и
// маска отвергает его ПО ИМЕНИ (TestUpdate_ImmutableInMask_IsNamedNotGenericallyUnknown).
//
// # ДВА ДЕРЖАТЕЛЯ
//
//   - форма: каждое поле тела, кроме идентификатора и маски, — изменяемое
//     (входит в mutableFields), и ни одно не входит в immutableFields. Пока это
//     так, «молча проигнорировать неизменяемое из тела» нечего. Предикат
//     доказан способным упасть на сообщении ресурса, которое неизменяемые поля
//     несёт (близнец ниже);
//   - слово: комментарий поля `update_mask` в порождённой заглушке (её сверяет с
//     `.proto` цель `make proto-gen-diff`) не обещает исхода «ignored». Разбор —
//     по узлу поля структуры (go/ast), а не поиском по тексту файла.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// bodyFieldsOutsideMutable — поля сообщения, которые тело несёт и которые НЕ
// входят в изменяемый набор Update (идентификатор и маска — не поля тела).
func bodyFieldsOutsideMutable(md protoreflect.MessageDescriptor) (outside, immutable []string, inspected int) {
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		if name == "interactive_client_id" || name == "update_mask" {
			continue
		}
		inspected++
		if !slices.Contains(mutableFields, name) {
			outside = append(outside, name)
		}
		if slices.Contains(immutableFields, name) {
			immutable = append(immutable, name)
		}
	}
	return outside, immutable, inspected
}

// TestUpdateRequest_BodyCarriesOnlyMutableFields — тело Update не может нести
// неизменяемое поле: обещать о нём что-либо, кроме «его нет», нечему.
func TestUpdateRequest_BodyCarriesOnlyMutableFields(t *testing.T) {
	md := (&iamv1.UpdateInteractiveClientRequest{}).ProtoReflect().Descriptor()
	outside, immutable, inspected := bodyFieldsOutsideMutable(md)
	t.Logf("перепись: полей тела %d · вне изменяемого набора %d · неизменяемых %d",
		inspected, len(outside), len(immutable))

	require.Positive(t, inspected, "обход тела пуст — отрицания ниже вакуумны")
	require.Empty(t, outside, "тело Update несёт поле вне изменяемого набора — у него нет исхода в обработчике")
	require.Empty(t, immutable, "тело Update несёт неизменяемое поле — исход «отказ по имени» обязан стоять в обработчике")
	for _, f := range mutableFields {
		require.NotNilf(t, md.Fields().ByName(protoreflect.Name(f)),
			"изменяемое поле %q объявлено набором, но тело его не несёт", f)
	}
}

// TestUpdateRequest_BodyPredicateFiresOnAMessageWithImmutableFields — близнец:
// тот же предикат на сообщении ресурса находит неизменяемые поля. Без него
// пустой результат выше не отличить от предиката, не способного найти ничего.
func TestUpdateRequest_BodyPredicateFiresOnAMessageWithImmutableFields(t *testing.T) {
	md := (&iamv1.InteractiveClient{}).ProtoReflect().Descriptor()
	_, immutable, _ := bodyFieldsOutsideMutable(md)
	require.Contains(t, immutable, "client_id", "предикат не видит неизменяемое поле там, где оно есть")
}

// TestUpdateRequest_MaskCommentDoesNotPromiseIgnoredFields — контракт не обещает
// исхода «принято и проигнорировано» для тела Update.
func TestUpdateRequest_MaskCommentDoesNotPromiseIgnoredFields(t *testing.T) {
	doc := updateMaskFieldDoc(t)
	require.NotEmpty(t, doc, "у поля update_mask нет комментария — нечего сверять")
	require.NotContainsf(t, strings.ToLower(doc), "ignored",
		"комментарий update_mask обещает исход «ignored», запрещённый контрактом "+
			"(принято-и-проигнорировано), а тело неизменяемых полей не несёт вовсе:\n%s", doc)
	require.Containsf(t, doc, "immutable after InteractiveClient.Create",
		"комментарий update_mask не называет отказ по имени для неизменяемого в маске:\n%s", doc)
}

// updateMaskFieldDoc — комментарий поля UpdateMask структуры
// UpdateInteractiveClientRequest в порождённой заглушке.
func updateMaskFieldDoc(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	require.True(t, ok)
	stub := filepath.Join(filepath.Dir(self), "..", "..", "..", "..", "..",
		"pkg", "api", "kaname", "cloud", "iam", "v1", "internal_interactive_client_service.pb.go")
	file, err := parser.ParseFile(token.NewFileSet(), stub, nil, parser.ParseComments)
	require.NoError(t, err)

	var doc string
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "UpdateInteractiveClientRequest" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		require.True(t, ok)
		for _, f := range st.Fields.List {
			for _, name := range f.Names {
				if name.Name == "UpdateMask" {
					found = true
					doc = f.Doc.Text()
				}
			}
		}
		return false
	})
	require.True(t, found, "поле UpdateMask структуры UpdateInteractiveClientRequest не найдено в %s", stub)
	return doc
}
