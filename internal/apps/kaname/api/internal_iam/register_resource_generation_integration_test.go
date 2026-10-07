// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_generation_integration_test.go — приём поколения объекта
// сравнением с головой (приёмка NTF-3, kacho#2918; сценарии NTF3-174 (д), (к),
// (н), NTF3-182; Р30 «Приём поколения — CAS», «Поколение и проекция»,
// редакция 39; Д133, Д134 B2).
//
// # Что судится
//
// Регистрация и снятие объекта применяются, только если поколение строго новее
// головы объекта; голова — максимум применённого, ВКЛЮЧАЯ надгробие снятия.
// Иначе — исход REJECTED_STALE: зеркало, надгробие и кортежи не меняются.
// Поколение обязательно: `0` — INVALID_ARGUMENT по полю `generation`.
//
// # Как проба задаёт поколение
//
// Через отражение дескриптора по ИМЕНИ поля, а не через поле Go-структуры:
// проба собирается и на дереве без поля, и там она падает честным красным с
// текстом «поля generation нет» — отсутствие возможности у испытуемого, а не
// ошибка компиляции, у которой вердикта нет.
//
// # Что наблюдается
//
// Состояние базы службы доступа: строка зеркала (`source_version::text` —
// форма, читаемая при любом типе столбца), голова объекта (колонка
// `generation`, `bigint`) и кортеж `parent` на
// объекте в `relation_fact`. Значение метрики исхода REJECTED_STALE не
// утверждается — имени у неё в приёмке нет (вопрос к приёмке в возврате).
//
// Пропускается под `go test -short`.
package internal_iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
)

// Объект сценариев группы W: том `vol-41` с цепью `[project:prj-1, account:acc-1]`.
// Каждая проба берёт свой id (суффикс), чтобы конкурентный прогон пакета не
// делил объект между пробами.
const (
	genSubject   = "project:prj-1"
	genRelation  = "parent"
	genProjectID = "prj-1"
	genAccountID = "acc-1"
)

func genObject(id string) string { return "storage_volume:" + id }

// setGeneration задаёт поколение запросу по имени поля дескриптора.
func setGeneration(t *testing.T, m proto.Message, g int64) {
	t.Helper()
	r := m.ProtoReflect()
	fd := r.Descriptor().Fields().ByName("generation")
	if fd == nil {
		t.Fatalf("%s: поля `generation` нет — поколение объекта в контракт не заведено, "+
			"приём сравнением с головой выразить нечем (Р30 «Поколение и проекция», NTF3-182)",
			r.Descriptor().FullName())
	}
	if fd.Kind() != protoreflect.Int64Kind || fd.Cardinality() == protoreflect.Repeated {
		t.Fatalf("%s.generation: %s %s, ожидается одиночное int64",
			r.Descriptor().FullName(), fd.Cardinality(), fd.Kind())
	}
	r.Set(fd, protoreflect.ValueOfInt64(g))
}

func regAt(t *testing.T, id string, labels map[string]string, g int64) *iamv1.RegisterResourceRequest {
	t.Helper()
	req := &iamv1.RegisterResourceRequest{
		Tuples:          []*iamv1.RegisteredTuple{{SubjectId: genSubject, Relation: genRelation}},
		Object:          genObject(id),
		Labels:          labels,
		ParentProjectId: genProjectID,
		ParentAccountId: genAccountID,
	}
	if g != 0 {
		setGeneration(t, req, g)
	}
	return req
}

func unregAt(t *testing.T, id string, g int64) *iamv1.UnregisterResourceRequest {
	t.Helper()
	req := &iamv1.UnregisterResourceRequest{
		Object: genObject(id),
	}
	if g != 0 {
		setGeneration(t, req, g)
	}
	return req
}

// genProbe — наблюдатель состояния объекта в базе службы доступа.
type genProbe struct{ pool *pgxpool.Pool }

// mirror — строка зеркала объекта: поколение текстом и метки.
func (p genProbe) mirror(t *testing.T, ctx context.Context, id string) (gen string, labels map[string]string, present bool) {
	t.Helper()
	var raw string
	err := p.pool.QueryRow(ctx,
		`SELECT source_version::text, labels::text FROM kaname.resource_mirror WHERE object_id = $1`, id).
		Scan(&gen, &raw)
	if err == pgx.ErrNoRows {
		return "", nil, false
	}
	require.NoError(t, err, "чтение зеркала %s", id)
	labels = map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(raw), &labels))
	return gen, labels, true
}

// headColumn — колонка поколения головы объекта `generation` таблицы
// kaname.object_head; её отсутствие — красный с текстом, а не ошибка запроса.
func (p genProbe) headColumn(t *testing.T, ctx context.Context) string {
	t.Helper()
	var typ string
	err := p.pool.QueryRow(ctx, `
		SELECT data_type FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'object_head' AND column_name = 'generation'`).Scan(&typ)
	if err == pgx.ErrNoRows {
		t.Fatalf("у kaname.object_head нет колонки generation — головы объекта нет, сравнивать поколение не с чем " +
			"(Р30 «Приём поколения — CAS»)")
	}
	require.NoError(t, err)
	require.Equal(t, "bigint", typ, "kaname.object_head.generation")
	return "generation"
}

// head — поколение головы объекта.
func (p genProbe) head(t *testing.T, ctx context.Context, id string) (int64, bool) {
	t.Helper()
	col := pgx.Identifier{p.headColumn(t, ctx)}.Sanitize()
	var g int64
	err := p.pool.QueryRow(ctx, `SELECT `+col+` FROM kaname.object_head WHERE object_id = $1`, id).Scan(&g)
	if err == pgx.ErrNoRows {
		return 0, false
	}
	require.NoError(t, err, "чтение головы %s", id)
	return g, true
}

// parentFacts — кортежи `parent` на объекте в прямом факте.
func (p genProbe) parentFacts(t *testing.T, ctx context.Context, id string) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'storage_volume' AND object_id = $1 AND relation = $2 AND subject = $3`,
		id, genRelation, genSubject).Scan(&n))
	return n
}

func (p genProbe) requireMirror(t *testing.T, ctx context.Context, id string, wantGen int64, wantLabels map[string]string, why string) {
	t.Helper()
	gen, labels, ok := p.mirror(t, ctx, id)
	require.True(t, ok, "%s: строки зеркала %s нет", why, id)
	require.Equal(t, strconv.FormatInt(wantGen, 10), gen, "%s: поколение зеркала", why)
	require.Equal(t, wantLabels, labels, "%s: метки зеркала", why)
}

func (p genProbe) requireHead(t *testing.T, ctx context.Context, id string, want int64, why string) {
	t.Helper()
	g, ok := p.head(t, ctx, id)
	require.True(t, ok, "%s: головы объекта %s нет", why, id)
	require.Equal(t, want, g, "%s: поколение головы", why)
}

func (p genProbe) requireNoMirror(t *testing.T, ctx context.Context, id, why string) {
	t.Helper()
	gen, _, ok := p.mirror(t, ctx, id)
	require.False(t, ok, "%s: живая строка зеркала %s есть (поколение %s)", why, id, gen)
}

func newGenerationUC(t *testing.T) (*internaliam.RegisterResourceUseCase, genProbe) {
	t.Helper()
	uc, mp := newRegisterUCWithMirror(t)
	return uc, genProbe{pool: mp.pool}
}

var (
	labelsProd  = map[string]string{"env": "prod"}
	labelsEmpty = map[string]string{}
)

// TestRegisterResource_NTF3_174d_GenerationNotNewerThanHeadIsRejectedStale —
// после v1..v3 приходит v2 с метками `{env: prod}`: не новее головы, исход
// REJECTED_STALE, зеркало несёт v3 и `{}`. Близнец по одному факту — v4 с теми
// же метками: применено, зеркало несёт v4 и `{env: prod}`.
func TestRegisterResource_NTF3_174d_GenerationNotNewerThanHeadIsRejectedStale(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	uc, p := newGenerationUC(t)
	const id = "vol-41d"

	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 1)))
	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsEmpty, 2)))
	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsEmpty, 3)))
	p.requireMirror(t, ctx, id, 3, labelsEmpty, "после v1..v3")
	p.requireHead(t, ctx, id, 3, "после v1..v3")

	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 2)),
		"запоздалая доставка — успех вызова: прокси идемпотентен, отказ породил бы вечный повтор")
	p.requireMirror(t, ctx, id, 3, labelsEmpty, "v2 не новее головы v3 — REJECTED_STALE")
	p.requireHead(t, ctx, id, 3, "v2 не новее головы v3 — REJECTED_STALE")

	// Близнец: тот же вход, поколение новее головы.
	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 4)))
	p.requireMirror(t, ctx, id, 4, labelsProd, "близнец: v4 новее головы")
	p.requireHead(t, ctx, id, 4, "близнец: v4 новее головы")
}

// TestRegisterResource_NTF3_174k_TombstoneRefusesAGenerationNotNewerThanIt —
// v1..v3, снятие v4: живой строки зеркала нет, голова (надгробие) — v4, кортеж
// `parent` снят. Затем v3 с `{env: prod}` — не новее надгробия: REJECTED_STALE,
// зеркала нет, кортеж не восстановлен. Близнец по одному факту — поколение v5
// (новее надгробия): применено, зеркало v5, кортеж есть.
func TestRegisterResource_NTF3_174k_TombstoneRefusesAGenerationNotNewerThanIt(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	uc, p := newGenerationUC(t)
	const id = "vol-41k"

	for g, l := range []map[string]string{labelsProd, labelsEmpty, labelsEmpty} {
		require.NoError(t, uc.Register(ctx, regAt(t, id, l, int64(g+1))))
	}
	require.Equal(t, 1, p.parentFacts(t, ctx, id), "положительный контроль: кортеж parent после v1..v3")

	require.NoError(t, uc.Unregister(ctx, unregAt(t, id, 4)))
	p.requireNoMirror(t, ctx, id, "после снятия v4")
	p.requireHead(t, ctx, id, 4, "надгробие снятия v4")
	require.Equal(t, 0, p.parentFacts(t, ctx, id), "после снятия v4 кортеж parent снят")

	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 3)))
	p.requireNoMirror(t, ctx, id, "v3 не новее надгробия v4 — REJECTED_STALE")
	p.requireHead(t, ctx, id, 4, "v3 не новее надгробия v4 — REJECTED_STALE")
	require.Equal(t, 0, p.parentFacts(t, ctx, id), "v3 не новее надгробия v4: кортеж не восстановлен")

	// Близнец: то же, поколение новее надгробия.
	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 5)))
	p.requireMirror(t, ctx, id, 5, labelsProd, "близнец: v5 новее надгробия")
	p.requireHead(t, ctx, id, 5, "близнец: v5 новее надгробия")
	require.Equal(t, 1, p.parentFacts(t, ctx, id), "близнец: v5 новее надгробия — кортеж parent есть")
}

// badRequestField — поле и описание первого нарушения BadRequest отказа.
func badRequestField(err error) (field, desc string) {
	for _, d := range status.Convert(err).Details() {
		if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
			v := br.GetFieldViolations()[0]
			return v.GetField(), v.GetDescription()
		}
	}
	return "", ""
}

// TestRegisterResource_NTF3_174n_GenerationIsRequired — после v1 регистрация
// без поколения (`0`): INVALID_ARGUMENT `generation: required`, зеркало и голова
// несут v1 — применения без поколения нет. То же у снятия. Близнец по одному
// факту — поколение v2: применено.
func TestRegisterResource_NTF3_174n_GenerationIsRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	uc, p := newGenerationUC(t)
	const id = "vol-41n"

	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 1)))

	err := uc.Register(ctx, regAt(t, id, labelsEmpty, 0))
	require.Error(t, err, "регистрация без поколения принята — наследственный путь «пустая версия применяется всегда» жив")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "регистрация без поколения: %v", err)
	field, desc := badRequestField(err)
	require.Equal(t, "generation", field, "поле отказа")
	require.Equal(t, "required", desc, "описание отказа")
	p.requireMirror(t, ctx, id, 1, labelsProd, "регистрация без поколения")
	p.requireHead(t, ctx, id, 1, "регистрация без поколения")

	err = uc.Unregister(ctx, unregAt(t, id, 0))
	require.Error(t, err, "снятие без поколения принято")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "снятие без поколения: %v", err)
	field, desc = badRequestField(err)
	require.Equal(t, "generation", field, "поле отказа снятия")
	require.Equal(t, "required", desc, "описание отказа снятия")
	p.requireMirror(t, ctx, id, 1, labelsProd, "снятие без поколения")

	// Близнец: то же, поколение задано.
	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsEmpty, 2)))
	p.requireMirror(t, ctx, id, 2, labelsEmpty, "близнец: generation = v2")
	p.requireHead(t, ctx, id, 2, "близнец: generation = v2")
}

// TestRegisterResource_NTF3_174_ConcurrentGenerationsConvergeOnTheHighest —
// шестнадцать регистраций одного объекта с поколениями 1..16 в случайном
// порядке, конкурентно, со стартовым барьером: каждая — успех вызова; итог —
// зеркало и голова несут 16 и метки поколения 16. Порядок прихода не решает.
func TestRegisterResource_NTF3_174_ConcurrentGenerationsConvergeOnTheHighest(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	uc, p := newGenerationUC(t)
	const id = "vol-41race"
	const n = 16

	reqs := make([]*iamv1.RegisterResourceRequest, n)
	for i := range reqs {
		g := int64(i + 1)
		reqs[i] = regAt(t, id, map[string]string{"gen": strconv.FormatInt(g, 10)}, g)
	}
	rand.New(rand.NewSource(41)).Shuffle(n, func(i, j int) { reqs[i], reqs[j] = reqs[j], reqs[i] })

	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = uc.Register(ctx, reqs[i])
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "регистрация %d из %d", i+1, n)
	}
	p.requireMirror(t, ctx, id, n, map[string]string{"gen": fmt.Sprint(n)}, "после конкурентных v1..v16")
	p.requireHead(t, ctx, id, n, "после конкурентных v1..v16")
}

// TestRegisterResource_NTF3_174_ConcurrentWithdrawalLeavesTheTombstone —
// регистрации 1..8 и снятие 9 одного объекта конкурентно: итог — живой строки
// зеркала нет, голова 9, кортежа `parent` нет, в каком бы порядке ни пришли
// вызовы (в том числе снятие раньше любой регистрации). Затем регистрация 7 —
// не новее надгробия: зеркала нет.
func TestRegisterResource_NTF3_174_ConcurrentWithdrawalLeavesTheTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	uc, p := newGenerationUC(t)
	const id = "vol-41tomb"

	type call func() error
	withdrawal := unregAt(t, id, 9)
	calls := []call{func() error { return uc.Unregister(ctx, withdrawal) }}
	for g := int64(1); g <= 8; g++ {
		req := regAt(t, id, labelsProd, g)
		calls = append(calls, func() error { return uc.Register(ctx, req) })
	}
	rand.New(rand.NewSource(9)).Shuffle(len(calls), func(i, j int) { calls[i], calls[j] = calls[j], calls[i] })

	start := make(chan struct{})
	errs := make([]error, len(calls))
	var wg sync.WaitGroup
	for i := range calls {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = calls[i]()
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "вызов %d из %d", i+1, len(calls))
	}
	p.requireNoMirror(t, ctx, id, "снятие v9 против регистраций v1..v8")
	p.requireHead(t, ctx, id, 9, "надгробие v9")
	require.Equal(t, 0, p.parentFacts(t, ctx, id), "снятие v9: кортежа parent нет")

	require.NoError(t, uc.Register(ctx, regAt(t, id, labelsProd, 7)))
	p.requireNoMirror(t, ctx, id, "v7 после надгробия v9")
	p.requireHead(t, ctx, id, 9, "v7 после надгробия v9")
}

// TestResourceProjection_NTF3_182_GenerationIsBigintOnlyOnTheObjectSide — в
// поколение `bigint` переведены зеркало, рёбра предков и голова объекта;
// `relation_fact` и `public_read_publication` сохраняют `timestamptz` и свой
// порядок записи и снятия (страж от воскрешения снятого права, NTF3-184).
func TestResourceProjection_NTF3_182_GenerationIsBigintOnlyOnTheObjectSide(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	_, p := newGenerationUC(t)

	colType := func(t *testing.T, table, column string) string {
		t.Helper()
		var typ string
		err := p.pool.QueryRow(ctx, `
			SELECT data_type FROM information_schema.columns
			 WHERE table_schema = 'kaname' AND table_name = $1 AND column_name = $2`, table, column).Scan(&typ)
		if err == pgx.ErrNoRows {
			t.Fatalf("kaname.%s.%s: столбца нет", table, column)
		}
		require.NoError(t, err)
		return typ
	}
	for _, c := range []struct{ table, column, want string }{
		{"resource_mirror", "source_version", "bigint"},
		{"resource_parent_edge", "source_version", "bigint"},
		{"relation_fact", "source_version", "timestamp with time zone"},
		{"public_read_publication", "source_version", "timestamp with time zone"},
	} {
		t.Run(c.table, func(t *testing.T) {
			require.Equal(t, c.want, colType(t, c.table, c.column), "kaname.%s.%s", c.table, c.column)
		})
	}
	t.Run("object_head", func(t *testing.T) {
		t.Logf("колонка поколения головы: %s", p.headColumn(t, ctx))
	})
}
