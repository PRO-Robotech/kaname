// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_provider_road_knobs_test.go — ручки дороги обмена к прежнему издателю
// сняты ВСЕМИ написаниями (kaname#494); отказ на них даёт строгость загрузчика
// (замысел NTF-2 З5), а плоская переменная, которой строгость не судит, никуда
// не доезжает.
//
// # Предмет
//
// Дорогу обмена задавали три ручки: издатель поставщика, адрес его
// токен-эндпоинта и якорь хопа к нему. У каждой было два написания — ключ файла
// настройки и переменная окружения (своя, и каноническая форма ключа). Дорога
// снята, и процесс не читает ни одного написания ни одной ручки.
//
// # Исход по написаниям — и почему он утверждается, а не подразумевается
//
// Решение kaname#494 снимало ручки без отказа: на единственной посадке, которую
// поставка предлагает (боевая, своя чеканка обязательна), все три были инертны
// и до снятия. Строгость загрузчика (strict_env.go) с тех пор отвергает ключ
// файла и переменную пространства `__`, которых не знает декодер, — и ключ
// файла и каноническая переменная снятых ручек отвергаются как неизвестные, с
// их именем. Плоскую переменную строгость не судит намеренно (одного
// объявления у плоских имён нет), и она загружается — её значение обязано не
// доехать ни до одного поля. Шапка `retired_settings.go` говорит то же.
//
// # Имя поставщика — из словаря, а не литералом
//
// Имя снимаемого поставщика проба берёт у словаря класса
// (`check.RetiredIssuerName`, `check.RetiredVendorMarks`): выписанное заново, оно
// было бы новой привязкой к поставщику в дереве, которое их снимает.
package config_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/check"
)

// roadMarker — значение, которое кладётся в каждое написание снятых ручек.
// Непохоже ни на одно умолчание: совпадение с ним сделало бы «не доехало»
// тождественно ложным.
const roadMarker = "retired-road-marker-494"

// roadKnob — снятая ручка так, как её знал оператор.
type roadKnob struct {
	fileKey   string // путь ключа в файле настройки
	ownEnv    string // своя переменная, которой ручка подавалась
	canonical string // каноническая переменная, выводимая из ключа
}

// retiredRoadKnobs — три ручки дороги обмена, имена собраны из словаря.
func retiredRoadKnobs() []roadKnob {
	v := check.RetiredIssuerName
	V := strings.ToUpper(v)
	return []roadKnob{
		{"authn." + v + "-issuer", "KANAME_" + V + "_ISSUER", "KANAME_AUTHN__" + V + "_ISSUER"},
		{"authn." + v + "-token-url", "KANAME_" + V + "_TOKEN_URL", "KANAME_AUTHN__" + V + "_TOKEN_URL"},
		{"authn." + v + "-token-ca-file", "KANAME_" + V + "_TOKEN_CA_FILE", "KANAME_AUTHN__" + V + "_TOKEN_CA_FILE"},
	}
}

// settingPathsNamingTheProvider — ЧИСТОЕ ТЕЛО ВЕРДИКТА: пути ключей настройки
// (по тегам mapstructure) и те из них, что несут имя снимаемого поставщика.
// Вынесено ради инъекции: доказать способность упасть можно только подачей
// объявления с таким ключом, а в дереве его быть не должно.
func settingPathsNamingTheProvider(root reflect.Type) (paths, findings []string) {
	var walk func(t reflect.Type, prefix string, depth int)
	walk = func(t reflect.Type, prefix string, depth int) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if depth > 8 || t.Kind() != reflect.Struct {
			return
		}
		for i := range t.NumField() {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("mapstructure"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			path := tag
			if prefix != "" {
				path = prefix + "." + tag
			}
			paths = append(paths, path)
			for _, m := range check.RetiredVendorMarks {
				if strings.Contains(strings.ToLower(path), m) {
					findings = append(findings, path)
					break
				}
			}
			if ft := f.Type; ft.String() != "time.Duration" {
				walk(ft, path, depth+1)
			}
		}
	}
	walk(root, "", 0)
	sort.Strings(findings)
	return paths, findings
}

// TestNoSettingKeyCarriesTheRetiredProviderName — ни один ключ настройки
// процесса не несёт имени снимаемого поставщика.
func TestNoSettingKeyCarriesTheRetiredProviderName(t *testing.T) {
	paths, findings := settingPathsNamingTheProvider(reflect.TypeOf(config.Config{}))
	t.Logf("перепись: ключей настройки осмотрено %d · с именем поставщика %d", len(paths), len(findings))
	if len(paths) < 50 {
		t.Fatalf("осмотрено ключей %d — объявление настройки так не выглядит, вердикт беспредметен", len(paths))
	}
	if len(findings) != 0 {
		t.Fatalf("ключи настройки несут имя снятого поставщика — процесс читает ручку дороги, которой нет: %s",
			strings.Join(findings, ", "))
	}
}

// TestSettingPathJudge_FindsTheVendorKeyAndSparesItsTwin — тело вердикта
// способно упасть и способно смолчать: объявления различаются ОДНИМ тегом.
func TestSettingPathJudge_FindsTheVendorKeyAndSparesItsTwin(t *testing.T) {
	type section struct {
		Issuer string `mapstructure:"issuer"`
	}
	type twin struct {
		AuthN section `mapstructure:"authn"`
	}
	if _, f := settingPathsNamingTheProvider(reflect.TypeOf(twin{})); len(f) != 0 {
		t.Fatalf("законный близнец принят за ключ поставщика: %v", f)
	}
	// ИНЪЕКЦИЯ, ОДИН ФАКТ против близнеца: в той же секции рядом с издателем —
	// ключ с именем поставщика. Тег собирается из словаря, литерала здесь нет.
	withRoad := reflect.StructOf([]reflect.StructField{{
		Name: "AuthN",
		Type: reflect.StructOf([]reflect.StructField{
			{Name: "Issuer", Type: reflect.TypeOf(""), Tag: `mapstructure:"issuer"`},
			{
				Name: "Road", Type: reflect.TypeOf(""),
				Tag: reflect.StructTag(`mapstructure:"` + check.RetiredIssuerName + `-token-url"`),
			},
		}),
		Tag: `mapstructure:"authn"`,
	}})
	_, f := settingPathsNamingTheProvider(withRoad)
	if len(f) != 1 || f[0] != "authn."+check.RetiredIssuerName+"-token-url" {
		t.Fatalf("ключ с именем поставщика не найден либо назван не той координатой: %v", f)
	}
}

// stringsIn — все строковые значения, достижимые из v: поля, указатели,
// срезы, карты. Нужны все, а не печать структуры: значение, спрятанное за
// указателем, печать показала бы адресом.
func stringsIn(v reflect.Value, out *[]string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			stringsIn(v.Elem(), out)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			stringsIn(v.Field(i), out)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			stringsIn(v.Index(i), out)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			stringsIn(k, out)
			stringsIn(v.MapIndex(k), out)
		}
	case reflect.String:
		*out = append(*out, v.String())
	}
}

// TestRetiredProviderRoadKnobsAreRefusedByStrictnessOrReachNoField — ключ файла
// и каноническую переменную каждой снятой ручки загрузка отвергает с их именем;
// плоскую переменную принимает и никуда не доносит. Три подкейса меняют против
// общего пустого профиля ровно одно — написание, которым ручки поданы.
func TestRetiredProviderRoadKnobsAreRefusedByStrictnessOrReachNoField(t *testing.T) {
	t.Run("ключ файла — отказ строгости с путём ключа", func(t *testing.T) {
		var body strings.Builder
		body.WriteString("authn:\n")
		for _, k := range retiredRoadKnobs() {
			body.WriteString("  " + strings.TrimPrefix(k.fileKey, "authn.") + ": \"" + roadMarker + "-file\"\n")
		}
		_, err := config.Load(writeSettingsFile(t, body.String()))
		if err == nil {
			t.Fatal("ключи снятых ручек в файле загружены без отказа — «принято и проигнорировано»")
		}
		named := 0
		for _, k := range retiredRoadKnobs() {
			if !strings.Contains(err.Error(), "`"+k.fileKey+"`") {
				t.Errorf("отказ не называет ключ %q: %v", k.fileKey, err)
				continue
			}
			named++
		}
		t.Logf("перепись: ключей файла подано %d · названо отказом %d", len(retiredRoadKnobs()), named)
	})

	t.Run("каноническая переменная — отказ строгости с именем переменной", func(t *testing.T) {
		for _, k := range retiredRoadKnobs() {
			t.Setenv(k.canonical, roadMarker+"-canonical-env")
		}
		_, err := config.Load("")
		if err == nil {
			t.Fatal("канонические переменные снятых ручек загружены без отказа — «принято и проигнорировано»")
		}
		named := 0
		for _, k := range retiredRoadKnobs() {
			if !strings.Contains(err.Error(), "`"+k.canonical+"`") {
				t.Errorf("отказ не называет переменную %q: %v", k.canonical, err)
				continue
			}
			named++
		}
		t.Logf("перепись: канонических переменных подано %d · названо отказом %d", len(retiredRoadKnobs()), named)
	})

	t.Run("плоская переменная — загружается и никуда не доезжает", func(t *testing.T) {
		written := 0
		for _, k := range retiredRoadKnobs() {
			t.Setenv(k.ownEnv, roadMarker+"-own-env")
			written++
		}
		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("плоская переменная снятой ручки отвергнута — строгость её не судит, отказ пришёл "+
				"от другого: %v", err)
		}
		var values []string
		stringsIn(reflect.ValueOf(cfg), &values)
		reached := 0
		for _, s := range values {
			if strings.Contains(s, roadMarker) {
				reached++
				t.Errorf("значение снятой ручки доехало до настройки: %q", s)
			}
		}
		t.Logf("перепись: плоских переменных подано %d · строковых значений настройки осмотрено %d · доехало %d",
			written, len(values), reached)
		if len(values) == 0 {
			t.Fatal("обход настройки не нашёл ни одной строки — «не доехало» означало бы «не смотрели»")
		}
	})
}
