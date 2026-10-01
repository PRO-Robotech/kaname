// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// strict_env.go — СТРОГАЯ КОНФИГУРАЦИЯ: что считается известным ключом файла и
// известной переменной окружения (замысел NTF-2 З5, приёмка NTF2-48).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ключ, который служба принимает и не читает, — класс «принято и
// проигнорировано»: оператор задаёт снятую ручку, процесс стартует, и ручка
// выглядит настроенной, ничего не делая. Поэтому:
//
//   - ФАЙЛ судится целиком: ключ, которого не знает декодер структуры Config,
//     — отказ старта с полным путём ключа. Декодер настроен `ErrorUnused`
//     (`UnmarshalExact` в Load); полный путь называет суждение ниже, потому что
//     декодер называет лишь родителя и лист порознь;
//   - ОКРУЖЕНИЕ судится ТОЛЬКО в пространстве `__`. Имя с двойным
//     подчёркиванием производит ровно один механизм — вывод viper из пути
//     ключа (SetEnvKeyReplacer в Load), поэтому множество законных имён этого
//     пространства вычислимо из одного объявления, а кластер в нём имён не
//     производит. Плоские имена читают несколько механизмов (flatEnvKnobs,
//     прямые чтения окружения, посадка транспорта `envconfig`, значения ключей
//     `*-env`), и одного объявления у них нет: строгость по неполному перечню
//     отвергла бы каждый профиль. Сужение — решение замысла, а не недоделка.
//
// ─────────────────────────────────────────────────────────────────────────────
// МНОЖЕСТВО — ПРЯМОЙ ВЫВОД
//
// Для каждого ключа, который знает декодер (`mapstructure`-пути структуры
// Config — то же множество, которым судит `UnmarshalExact`), имя =
// EnvNameOfKey(key). Обратного разбора имени нет: `-` и `_` в ключе дают один
// символ, и обратный вывод неоднозначен.
package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// nestedEnvSeparator — разделитель сегментов пути ключа в имени переменной
// (тот же, что в SetEnvKeyReplacer). Кластер его не производит.
const nestedEnvSeparator = "__"

// DecoderKeys — пути ключей, которые знает декодер структуры Config, в
// порядке имени. Это листья: секция — не ключ, ключ — её поле.
func DecoderKeys() []string { return decoderKeysOf(reflect.TypeOf(Config{})) }

// NestedEnvNames — множество законных имён пространства `__`, выведенное из
// ключей декодера правилом EnvNameOfKey, в порядке имени.
func NestedEnvNames() []string {
	keys := DecoderKeys()
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, EnvNameOfKey(k))
	}
	sort.Strings(out)
	return out
}

// decoderKeysOf обходит структуру так же, как её сопоставляет декодер:
// имя — из тега `mapstructure` (до запятой), поле без тега — по имени поля в
// нижнем регистре, `squash` — поля встраиваются без сегмента, `-` и
// неэкспортируемые поля декодер не видит. Указатель разыменовывается;
// вложенная структура даёт сегмент пути; открытая форма (openKeyForms) листом
// не является; всё прочее — лист.
func decoderKeysOf(tp reflect.Type) []string { return walkDecoder(tp).keys }

// openKeyForms — пути полей ОТКРЫТОЙ формы: отображение и интерфейс. Их
// подключи задаёт оператор, а не тип, поэтому множество ключей и имён
// пространства `__` из типа для них не выводится — а строгость (файл,
// окружение, перечень величин документа установки) держится ровно на этом
// выводе. Поддержки таких полей нет намеренно: проба
// TestConfigCarriesNoOpenKeyForm запрещает их в Config, и поле, которому
// нужен оператором заданный набор подключей, объявляется иначе (структурой
// с перечисленными полями либо списком).
func openKeyForms(tp reflect.Type) []string { return walkDecoder(tp).open }

// decoderWalk — исход одного обхода: листья, открытые формы и перепись
// осмотренных полей (объём — отдельно от находок).
type decoderWalk struct {
	keys   []string
	open   []string
	fields int
}

func walkDecoder(tp reflect.Type) decoderWalk {
	var w decoderWalk
	walkDecoderKeys(tp, "", &w)
	sort.Strings(w.keys)
	sort.Strings(w.open)
	return w
}

func walkDecoderKeys(tp reflect.Type, prefix string, w *decoderWalk) {
	for tp.Kind() == reflect.Pointer {
		tp = tp.Elem()
	}
	for i := 0; i < tp.NumField(); i++ {
		f := tp.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("mapstructure"), ",")
		if name == "-" {
			continue
		}
		w.fields++
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if name == "" && hasTagOption(opts, "squash") && ft.Kind() == reflect.Struct {
			walkDecoderKeys(ft, prefix, w)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		switch ft.Kind() {
		case reflect.Struct:
			walkDecoderKeys(ft, path, w)
		case reflect.Map, reflect.Interface:
			w.open = append(w.open, path)
		default:
			w.keys = append(w.keys, path)
		}
	}
}

func hasTagOption(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if strings.TrimSpace(o) == want {
			return true
		}
	}
	return false
}

// unknownNestedEnvNames — имена окружения пространства `__` службы (приставка
// `KANAME_` и хотя бы один `__`), которых нет в множестве known, в порядке
// имени. Пустое значение — тоже объявление: оператор задал имя.
func unknownNestedEnvNames(environ []string, known map[string]struct{}) []string {
	var out []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, EnvPrefix+"_") || !strings.Contains(name, nestedEnvSeparator) {
			continue
		}
		if _, ok := known[name]; ok {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// refuseUnknownNestedEnv — отказ старта на переменной пространства `__`,
// которой не производит ни один ключ декодера. Отказ называет каждое такое
// имя: оператор видит, что именно не читается.
func refuseUnknownNestedEnv(environ []string) error {
	names := NestedEnvNames()
	known := make(map[string]struct{}, len(names))
	for _, n := range names {
		known[n] = struct{}{}
	}
	unknown := unknownNestedEnvNames(environ, known)
	if len(unknown) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(unknown))
	for _, n := range unknown {
		quoted = append(quoted, "unknown configuration variable `"+n+"`")
	}
	return fmt.Errorf("%s: ни один ключ настроек не производит этого имени — "+
		"снимите переменную либо исправьте имя по пути ключа (точка → `__`, дефис → `_`)",
		strings.Join(quoted, "; "))
}

// unknownFileKeys — пути ключей, заданных файлом либо иным слоем viper, которых
// декодер не знает, в порядке имени. Путь, являющийся началом известного
// ключа (секция, заданная не отображением), не неизвестен — о его форме
// скажет декодер.
func unknownFileKeys(settingKeys []string) []string {
	keys := DecoderKeys()
	known := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		known[k] = struct{}{}
	}
	var out []string
	for _, k := range settingKeys {
		if _, ok := known[k]; ok {
			continue
		}
		if isSectionOf(k, keys) {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isSectionOf(path string, keys []string) bool {
	p := path + "."
	for _, k := range keys {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// refuseUnknownFileKeys — отказ старта на ключе вне декодера с полным путём.
func refuseUnknownFileKeys(settingKeys []string) error {
	unknown := unknownFileKeys(settingKeys)
	if len(unknown) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(unknown))
	for _, k := range unknown {
		quoted = append(quoted, "unknown configuration key `"+k+"`")
	}
	return fmt.Errorf("%s: служба этого ключа не читает — снимите его из файла настроек",
		strings.Join(quoted, "; "))
}
