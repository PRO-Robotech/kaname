package check

import "testing"

// TestProtoFieldOfKnowsMapAndOptional — инъекция в обе стороны по двум формам,
// которых разбор не видел: параметризованный тип и модификатор optional.
func TestProtoFieldOfKnowsMapAndOptional(t *testing.T) {
	for _, c := range []struct {
		line string
		want string // "" = полем не является
	}{
		{"  string name = 1;", "name"},                          // контроль
		{"  repeated string ids = 2;", "ids"},                    // контроль
		{"  map<string, string> labels = 5;", "labels"},          // прежде молчал
		{"  optional int32 max_refs = 3;", "max_refs"},           // прежде молчал
		{"  map<string, Foo> by_id = 7;", "by_id"},               // прежде молчал
		{`  option java_package = "x";`, ""},                     // законный близнец
		{`  option (kacho.api.v1.a) = "b";`, ""},                 // законный близнец
	} {
		got, ok := protoFieldOf(c.line)
		if c.want == "" {
			if ok {
				t.Errorf("%q: опознано полем %q, а это не поле", c.line, got.Name)
			}
			continue
		}
		if !ok {
			t.Errorf("%q: полем НЕ опознано — форма вне наблюдения", c.line)
			continue
		}
		if got.Name != c.want {
			t.Errorf("%q: имя %q, ожидалось %q", c.line, got.Name, c.want)
		}
	}
}
