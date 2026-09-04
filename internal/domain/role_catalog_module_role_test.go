// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// role_catalog_module_role_test.go — замок на то, что публичный контракт роли
// теперь ОБЪЯВЛЯЕТ (задача продукта #1925).
//
// `display_name` и `purpose` — поля КАНОНИЧЕСКОГО каталога и ничьи больше. У
// роли вне каталога отображаемое имя равно идентификатору, а назначение пусто, и
// это сказано в контракте (`proto/kacho/cloud/iam/v1/role.proto`), а не
// подразумевается. Человеческая проза такой роли живёт в `description`: её
// пишет автор модуля в манифесте, и загрузчик требует её наличия
// (`manifest.ErrRoleDescriptionTooShort`).
//
// Замок нужен потому, что до #1925 контракт обещал «friendly catalog label» и
// молчал о ролях модуля — то есть обещал возможность, которой на них нет.
// Стоило бы кому-нибудь «починить» деривацию под прежнее обещание — и роль
// модуля начала бы возвращать выдуманную метку без единого носителя.
package domain

import (
	"strings"
	"testing"
)

// moduleRoleOfTheApplier — роль ровно в той форме, в какой её строит применитель
// манифеста: кластерный ярус, имя дословно из объявления, назначение из
// манифеста. Фикстура повторяет `moduleroles.roleOf`, а не изобретает свою: иначе
// замок утверждал бы о роли, которой в дереве не бывает.
func moduleRoleOfTheApplier(name, description string) Role {
	return Role{
		ID:          SystemRoleID(RoleName(name)),
		ClusterID:   ClusterSingletonID,
		Name:        RoleName(name),
		Description: Description(description),
		IsSystem:    true,
	}
}

// TestCanonicalCatalogLabelsFourNamesAndNoModuleRole — перепись каталога и его
// граница. Печатается объём осмотренного: «ноль находок» обязано быть отличимо
// от «ноль прочитанного».
func TestCanonicalCatalogLabelsFourNamesAndNoModuleRole(t *testing.T) {
	want := map[string]string{
		"view": "Viewer", "edit": "Editor", "admin": "Admin", "owner": "Owner",
	}

	dotted := 0
	for name := range canonicalCatalog {
		if strings.Contains(name, ".") {
			dotted++
		}
	}
	t.Logf("перепись: записей канонического каталога %d, из них с точкой в имени %d",
		len(canonicalCatalog), dotted)

	if len(canonicalCatalog) == 0 {
		t.Fatalf("канонический каталог пуст — замок беспредметен: утверждать «роль ВНЕ " +
			"каталога» не о чем")
	}
	if len(canonicalCatalog) != len(want) {
		t.Fatalf("записей каталога %d, ожидалось %d. Каталог вырос или сжался — значит "+
			"фраза контракта о том, что вне него отображаемое имя равно идентификатору, "+
			"перечисляет уже не тот набор, и её надо править ТЕМ ЖЕ изменением "+
			"(proto/kacho/cloud/iam/v1/role.proto, поля display_name и purpose)",
			len(canonicalCatalog), len(want))
	}
	for name, label := range want {
		got, ok := canonicalCatalog[name]
		if !ok {
			t.Fatalf("каноническое имя %q исчезло из каталога", name)
		}
		if got.displayName != label {
			t.Errorf("метка %q: %q, ожидалось %q", name, got.displayName, label)
		}
		if got.purpose == "" {
			t.Errorf("у канонического имени %q пустое назначение — положительный контроль "+
				"замка исчез, и «пусто у роли модуля» перестало что-либо различать", name)
		}
	}
	// Граница каталога: имя роли модуля точечное by construction
	// (`<модуль>.<ресурс>.<класс>`), и ни одна такая роль каталогом не помечена.
	// Появится — фраза контракта станет неверной, и править её надо здесь же.
	if dotted != 0 {
		t.Fatalf("канонический каталог помечает %d точечных имён — то есть роль модуля. "+
			"Контракт объявляет обратное: вне каталога display_name равен name, а purpose "+
			"пуст. Два места об одном предмете разошлись", dotted)
	}
}

// TestModuleRoleReadsBackItsIdentifierAndCarriesItsProseInDescription — само
// свойство, обе стороны сразу.
func TestModuleRoleReadsBackItsIdentifierAndCarriesItsProseInDescription(t *testing.T) {
	const (
		name  = "vpc.address.admin"
		prose = "Admin Address"
	)
	r := moduleRoleOfTheApplier(name, prose)

	if !r.IsSystemDerived() {
		t.Fatalf("фикстура не системная — она не воспроизводит роль применителя, и замок " +
			"утверждает о роли, которой в дереве не бывает")
	}
	if got := r.DisplayName(); got != name {
		t.Errorf("display_name роли модуля = %q, контракт объявляет %q (равен name)", got, name)
	}
	if got := r.Purpose(); got != "" {
		t.Errorf("purpose роли модуля = %q, контракт объявляет пустое: пустое здесь "+
			"означает «записи в каталоге нет», а не «у роли нет назначения»", got)
	}
	// Носитель прозы — тот, на который контракт и указывает. Без этой половины
	// замок утверждал бы, что у роли модуля человеческого текста нет вовсе.
	if string(r.Description) != prose {
		t.Errorf("description = %q, ожидалось %q — носитель прозы роли модуля не работает, "+
			"и указание контракта на него становится ложным", r.Description, prose)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него оба утверждения выше зеленели бы на
	// деривации, которая возвращает идентификатор и пустоту ВСЕГДА.
	canonical := Role{ID: SystemRoleID("view"), ClusterID: ClusterSingletonID, Name: "view", IsSystem: true}
	if got := canonical.DisplayName(); got != "Viewer" {
		t.Fatalf("КОНТРОЛЬ: каноническая роль отдала %q вместо %q — деривация каталога "+
			"мертва, и отрицания выше сказаны ни о чём", got, "Viewer")
	}
	if canonical.Purpose() == "" {
		t.Fatalf("КОНТРОЛЬ: у канонической роли пустое назначение — отрицание «пусто у " +
			"роли модуля» перестало что-либо различать")
	}
}
