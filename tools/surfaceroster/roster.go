// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package surfaceroster — ПЕРЕЧЕНЬ ПОВЕРХНОСТЕЙ, которые поднимает процесс,
// выведенный из его собственных объявлений.
//
// # Зачем отдельный производитель
//
// О поверхностях службы утверждают ТРИ места: композиционный корень (что
// поднимается), чарт (куда ведёт маршрут) и документ установки (что оператор
// откроет и что защитит). Пока перечень выписан в каждом от руки, расхождение
// между ними молчит by construction: каждое место по отдельности выглядит
// верным. Так и вышло — чарт вёл к двум поверхностям из восьми (задача #2337),
// а документ называл шесть (задача #2341).
//
// Здесь перечень ОДИН, и читают его гейты обоих мест. Разойтись с процессом он
// не может: он и есть процесс, прочитанный разбором.
//
// # Почему разбором, а не импортом
//
// Поверхности объявляются ВНУТРИ функции подъёма (`serve.go`), рядом со своими
// обработчиками, и вынести их оттуда таблицей значило бы завести второе место
// об одном предмете — ровно то, против чего этот пакет написан. Разбор читает
// объявление там, где оно живёт.
//
// Читается УЗЕЛ синтаксического дерева, а не текст: имя поверхности и её
// досягаемость встречаются и в комментариях, и в сообщениях отказа, и поиск по
// подстроке считал бы прозу объявлением.
package surfaceroster

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Surface — одна поверхность, поднимаемая процессом.
type Surface struct {
	// Name — имя, которым процесс называет её сам (журнал, текст отказа).
	Name string
	// Reach — досягаемость: "external" либо "cluster-internal".
	Reach string
	// ReachFromProcess — досягаемость объявлена САМИМ ПРОЦЕССОМ (ось
	// `Surface.Reach`), а не названа здесь.
	//
	// Различать обязательно. У gRPC-ног оси досягаемости не существует вовсе,
	// поэтому их значение ниже — утверждение ЭТОГО пакета. Сверять чужой
	// документ с собственным утверждением значит проверять себя собой: такой
	// гейт краснеет на верном тексте и молчит на неверном ровно тогда, когда
	// ошибётся автор перечня.
	ReachFromProcess bool
	// SettingKey — ключ конфигурации, задающий её адрес.
	SettingKey string
	// DefaultAddr — адрес по умолчанию. Пустой означает «умолчания нет»:
	// поверхность поднимается, только если посадка назвала адрес.
	DefaultAddr string
	// DefaultPort — порт из DefaultAddr. Пустой, если умолчания нет.
	DefaultPort string
	// GRPC — поверхность является gRPC-слушателем.
	GRPC bool
	// PostureAddr — адрес, который объявляет ПОСТАВЛЯЕМЫЙ боевой профиль.
	// Заполняется у поверхностей без умолчания: их поднимает посадка, и вне
	// профиля порт у них не определён ничем.
	PostureAddr string
	// PosturePort — порт из [Surface.PostureAddr].
	PosturePort string
}

// Roster — прочитанный перечень плюс объём осмотренного.
type Roster struct {
	Surfaces []Surface
	// FilesRead — сколько файлов прочитано. «Ноль находок» обязано быть
	// отличимо от «ноль прочитанного».
	FilesRead int
	// DefaultsRead — сколько умолчаний адресов прочитано.
	DefaultsRead int
}

// grpcListeners — два gRPC-слушателя.
//
// Их объявляет НЕ [servicecontract.Surface]: этот тип по своему контракту
// описывает поверхность, которая gRPC НЕ является. Значит перечень поверхностей
// службы шире перечня `Surface`, и молчаливо считать их одним и тем же значило
// бы потерять из виду ровно те две двери, ради которых службу вообще зовут.
//
// Досягаемость названа здесь, потому что назвать её больше негде: у gRPC-ног
// оси `Reach` не существует. Значения — те же, что несёт публичный и внутренний
// слушатель везде в дереве, и разделение по ним держит запрет #6.
//
// Помечены как НЕ объявленные процессом: этим перечнем можно разводить двери по
// объектам Service, но нельзя судить чужой текст — см. [Surface.ReachFromProcess].
var grpcListeners = []Surface{
	{
		Name:       "публичный gRPC",
		Reach:      "external",
		SettingKey: "api-server.endpoint",
		GRPC:       true,
	},
	{
		Name:       "внутренний gRPC",
		Reach:      "cluster-internal",
		SettingKey: "api-server.internal-endpoint",
		GRPC:       true,
	},
}

var (
	// envKeyRe — имя переменной окружения в сообщении оси адреса. Именно оно
	// связывает поверхность с её ключом конфигурации.
	envKeyRe = regexp.MustCompile(`KANAME_[A-Z0-9_]+`)
	// portRe — порт в конце адреса.
	portRe = regexp.MustCompile(`:(\d+)$`)
)

// Read собирает перечень из дерева службы (корень — каталог `services/iam`).
func Read(iamRoot string) (Roster, error) {
	var r Roster

	defaults, n, err := readDefaults(filepath.Join(iamRoot, "internal/apps/kaname/config/defaults.go"))
	if err != nil {
		return r, err
	}
	r.FilesRead++
	r.DefaultsRead = n

	declared, err := readDeclaredSurfaces(filepath.Join(iamRoot, "cmd/kaname/serve.go"))
	if err != nil {
		return r, err
	}
	r.FilesRead++

	posture, err := readPostureAddrs(filepath.Join(iamRoot, "deploy/values.prod.yaml"))
	if err != nil {
		return r, err
	}
	r.FilesRead++

	all := append(append([]Surface{}, grpcListeners...), declared...)
	for i := range all {
		addr := defaults[all[i].SettingKey]
		all[i].DefaultAddr = addr
		if m := portRe.FindStringSubmatch(addr); m != nil {
			all[i].DefaultPort = m[1]
		}
		if p, ok := posture[all[i].SettingKey]; ok {
			all[i].PostureAddr = p
			if m := portRe.FindStringSubmatch(p); m != nil {
				all[i].PosturePort = m[1]
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].SettingKey < all[j].SettingKey })
	r.Surfaces = all

	if len(r.Surfaces) == 0 {
		return r, fmt.Errorf("перечень поверхностей пуст: вердикт был бы о пустоте, а не о дереве")
	}
	return r, nil
}

// readDefaults читает умолчания адресов из таблицы умолчаний службы.
func readDefaults(path string) (map[string]string, int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("таблица умолчаний %s: %w", path, err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetDefault" {
			return true
		}
		key, ok1 := stringLit(call.Args[0])
		val, ok2 := stringLit(call.Args[1])
		if !ok1 || !ok2 {
			return true
		}
		if !strings.HasSuffix(key, "endpoint") {
			return true
		}
		out[key] = val
		return true
	})
	return out, len(out), nil
}

// readDeclaredSurfaces читает объявления поверхностей композиционного корня.
func readDeclaredSurfaces(path string) ([]Surface, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("композиционный корень %s: %w", path, err)
	}
	var out []Surface
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isSurfaceLit(lit) {
			return true
		}
		s := Surface{}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Name":
				if v, ok := stringLit(kv.Value); ok {
					s.Name = v
				}
			case "Reach":
				s.Reach = reachOf(kv.Value)
			case "Addr":
				s.SettingKey = settingKeyOf(kv.Value)
			}
		}
		if s.Name != "" {
			s.ReachFromProcess = true
			out = append(out, s)
		}
		return true
	})
	return out, nil
}

// isSurfaceLit — литерал ровно типа `servicecontract.Surface`.
func isSurfaceLit(lit *ast.CompositeLit) bool {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Surface" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "servicecontract"
}

// reachOf переводит объявленную ось досягаемости в её же написание из журнала.
func reachOf(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch sel.Sel.Name {
	case "ReachExternal":
		return "external"
	case "ReachClusterInternal":
		return "cluster-internal"
	default:
		return ""
	}
}

// settingKeyOf достаёт ключ конфигурации из оси адреса.
//
// Ось несёт сообщение, называющее ПЕРЕМЕННУЮ ОКРУЖЕНИЯ незаданного адреса, — то
// самое, что читает оператор в отказе. Ключ конфигурации выводится из неё по
// правилу связывания випера, а не выписывается рядом: выписанный разошёлся бы с
// сообщением молча, и разошёлся бы именно там, где оператор ищет причину.
func settingKeyOf(e ast.Expr) string {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	for _, a := range call.Args {
		lit, ok := stringLit(a)
		if !ok {
			continue
		}
		if m := envKeyRe.FindString(lit); m != "" {
			return settingKeyFromEnv(m)
		}
	}
	return ""
}

// settingKeyFromEnv — правило связывания: `KANAME_A_B__C` → `a-b.c`.
func settingKeyFromEnv(env string) string {
	body := strings.TrimPrefix(env, "KANAME_")
	segs := strings.Split(body, "__")
	for i, s := range segs {
		segs[i] = strings.ToLower(strings.ReplaceAll(s, "_", "-"))
	}
	return strings.Join(segs, ".")
}

func stringLit(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		l, ok1 := stringLit(v.X)
		r, ok2 := stringLit(v.Y)
		if !ok1 || !ok2 {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// IAMRoot — корень дерева службы относительно каталога пробы.
func IAMRoot(fromDir string) (string, error) {
	abs, err := filepath.Abs(fromDir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "cmd/kaname/serve.go")); err == nil {
			return d, nil
		}
		if d == filepath.Dir(d) {
			return "", fmt.Errorf("корень дерева службы не найден от %s", fromDir)
		}
	}
}

// PostureAddr — адреса, которые объявляет ПОСТАВЛЯЕМЫЙ боевой профиль, по ключу
// конфигурации.
//
// Нужны поверхностям, у которых умолчания адреса нет намеренно: их поднимает
// посадка, и вне профиля их порт не определён ничем.
//
// ЧИТАЮТСЯ, А НЕ ВЫПИСЫВАЮТСЯ. Выписанный порт — второе место об одном предмете:
// профиль сменит адрес, а перечень продолжит называть прежний, и разойдутся они
// молча — ровно тот класс, против которого этот пакет написан.
func readPostureAddrs(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- путь из дерева службы
	if err != nil {
		return nil, fmt.Errorf("боевой профиль %s: %w", path, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("разбор боевого профиля %s: %w", path, err)
	}
	out := map[string]string{}
	var walk func(prefix []string, node any)
	walk = func(prefix []string, node any) {
		switch v := node.(type) {
		case map[string]any:
			for k, sub := range v {
				walk(append(append([]string{}, prefix...), k), sub)
			}
		case string:
			if portRe.MatchString(v) {
				out[settingKeyFromHelmPath(prefix)] = v
			}
		}
	}
	walk(nil, tree)
	return out, nil
}

// settingKeyFromHelmPath — правило связывания ключа профиля с ключом
// конфигурации: `apiServer.restEndpoint` → `api-server.rest-endpoint`.
//
// То же правило, которым их связывает шаблон карты настроек; здесь оно
// применяется к пути, а не переписывается таблицей соответствий.
func settingKeyFromHelmPath(path []string) string {
	segs := make([]string, 0, len(path))
	for _, p := range path {
		segs = append(segs, deCamel(p))
	}
	return strings.Join(segs, ".")
}

// deCamel — `internalRestEndpoint` → `internal-rest-endpoint`.
func deCamel(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
