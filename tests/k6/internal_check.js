// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// internal_check.js — нагрузка на InternalIAMService.Check: точечную проверку
// доступа, которую per-RPC интерсепторы vpc / compute / nlb зовут на КАЖДОМ
// запросе к платформе.
//
// ПОЧЕМУ ИМЕННО ЭТОТ ГЛАГОЛ, А НЕ ПУБЛИЧНЫЙ AuthorizeService.Check.
// Публичный Check стоит за краем, и путь до него включает разбор RS256-токена
// шлюзом, его кэш положительных вердиктов и внутреннюю калитку
// authorizeCaller — до четырёх лишних обращений к хранилищу прав на отказе.
// Замер через край мерил бы край. Внутренний Check объявлен `<exempt>`, его
// пускает только пол проверенного сертификата, и он ровно то, что тратится на
// каждом запросе платформы: поход в хранилище прав и — КОГДА СВЕРКА УСПЕВАЕТ
// ВЗЯТЬ СЛОТ — теневой запрос в свою базу. Складывать эти два расхода как
// постоянные нельзя: выше потолка одновременных сравнений вопрос отбрасывается,
// а не задаётся, и разбор ниже это и говорит.
//
// ЧТО ИМЕННО ОПЛАЧИВАЕТСЯ ОДНИМ ВЫЗОВОМ (важно для истолкования чисел):
//   · 1 HTTP-вызов к хранилищу прав (бюджет 200 мс, до 3 попыток внутри него);
//   · теневой запрос в свою базу — СБОКУ ОТ ПУТИ ОТВЕТА: у него свой срок 10 мс,
//     свой контекст и потолок восьми одновременных сравнений с ОТБРАСЫВАНИЕМ, а не
//     очередью. Ответ вызывающему он не задерживает ни значением, ни задержкой;
//     отброшенный вопрос попадает в исход «не выполнилось» со своей причиной.
// Прогон всё равно снимается вместе с показателями пула — соединение теневой
// запрос берёт, — но «ждём свободное соединение» больше не сидит на пути ответа.
//
// Здесь стояло: теневой запрос «блокирует ответ до 50 мс», а потолок равен
// «100 / среднее время теневого запроса» при `pool_max_conns=100`. Ни срок, ни
// предел пула, ни сам механизм давно не таковы; логика прибора при этом была верна
// — устарел текст. Снято по находке перемера 2026-08-20 (#776): два утверждения
// из трёх — вместе с расхождением #775, третье («плюс теневой запрос» как
// постоянное слагаемое) — выше, потому что читается оно как описание механизма,
// а слово «плюс» и есть то, что механизм перестал делать.
//
// Транспорт: gRPC + mTLS клиентским сертификатом модуля (SPIFFE-SAN), схема
// берётся серверным отражением — грузить .proto с их импортами не требуется.
//
// Запуск (в кластере, см. deploy/load-tests/k6-iam-internal-check.yaml):
//   k6 run -e TARGET_RPS=800 -e DURATION=60s /scripts/internal_check.js
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const ADDR        = __ENV.IAM_ADDR    || 'kacho-iam-internal.kacho.svc:9091';
const TARGET_RPS  = parseInt(__ENV.TARGET_RPS || '200', 10);
const DURATION    = __ENV.DURATION    || '60s';
const ALLOW_RATIO = parseFloat(__ENV.ALLOW_RATIO || '0.9');
const MAX_VUS     = parseInt(__ENV.MAX_VUS || String(Math.max(64, TARGET_RPS)), 10);
const PRE_VUS     = parseInt(__ENV.PRE_VUS || String(Math.min(MAX_VUS, Math.max(32, Math.ceil(TARGET_RPS / 4)))), 10);

const CERT_PATH = __ENV.CERT_PATH || '/certs/tls.crt';
const KEY_PATH  = __ENV.KEY_PATH  || '/certs/tls.key';
const CA_PATH   = __ENV.CA_PATH   || '/certs/ca.crt';

// Фикстура: реальные тройки (субъект, отношение, объект) из хранилища прав
// стенда. Разрешающие взяты как есть; отказ строится ПЕРЕСТАНОВКОЙ — субъект
// одной тройки против объекта другой. Так отказ остаётся well-formed (объект
// существует, тип верен) и оплачивает полный обход, а не короткий отлуп на
// разборе идентификатора.
//
// ПЕРЕСТАНОВКА ПРОВЕРЕНА И ИСТОЧНИКОМ РАСХОЖДЕНИЙ НЕ ЯВЛЯЕТСЯ (замер #775,
// 2026-08-20). Подозрение было обратным: что теневая сверка расходится с движком
// именно на синтетических парах. Развели двумя прогонами на одном стенде —
// `ALLOW_RATIO=1.0` (ни одной перестановки) дал 61.0 % расхождений, `ALLOW_RATIO=0.0`
// (одни перестановки) дал 0.13 %. Расхождение приносят НАСТОЯЩИЕ выдачи, а не
// перестановка; она, наоборот, почти всегда даёт согласное «нет».
//
// Повторить этот развод больше нечем: теневая сверка снята вместе с внешним
// движком (стадия S6), и второй формы, с которой можно разойтись, не существует.
// Замер остаётся историей — отчёт `results/SHADOW-DIVERGENCE-2026-08-20.md`, — а не
// действующей процедурой.
//
// Но сам прибор этого не знал и знать не мог: до этой правки он НЕ ПРОВЕРЯЛ, что
// его отказной вход действительно отказывает. Утверждение «вердикт достоверно
// нет пути» стояло комментарием и не держалось ничем — положительный контроль был
// односторонним (`wrongVerdict` ловит только «разрешающая тройка не разрешила»).
// Обратная сторона — «перестановка оказалась разрешающей» — теперь считается
// (`iam_check_deny_input_allowed`), и доля отказного входа перестала быть
// объявлением: её видно числом в сводке прогона.
const RAW_TUPLES = JSON.parse(open(__ENV.FIXTURE_PATH || '/fixtures/allow_tuples.json'));

// ─────────────────────────────────────────────────────────────────────────────
// СОСТАВ ПОДАЧИ — ПРИБОР ОБЯЗАН НАЗЫВАТЬ, О ЧЁМ ЕГО СПРАШИВАЛИ
//
// Пока состав не назывался, доля расхождений читалась как утверждение обо всём,
// о чём прибор спрашивал, — а спрашивал он не обо всём. Замер 2026-08-20: подача
// несла 273 тройки шести типов и НИ ОДНОГО объекта пяти собственных типов iam,
// поэтому её «0.00 %» стоял рядом с переписью, называвшей 15 085 потерянных
// объектов ровно этих типов. Два прибора мерили разные множества, и это было
// неотличимо от согласия. Ноль, не читавший предмета, — это «ноль прочитанного»,
// поданное как «ноль находок».
//
// Перечень пяти типов живёт ЗДЕСЬ и отдаётся наружу строкой `ФИКСТУРА-СВОИ-ТИПЫ`:
// у него один дом, и оболочка прибора берёт его отсюда, а не держит вторую копию,
// которая разошлась бы молча.
const OWN_IAM_TYPES = [
  'iam_access_binding', 'iam_group', 'iam_role', 'iam_service_account', 'iam_user',
];

// Классы, объявленные ЗАРАНЕЕ и считаемые ОТДЕЛЬНО. Класс печатается всегда,
// даже когда его объектов ноль: класс, всплывающий в общей доле впервые в момент
// расхождения, либо объявит достройку неудачной, либо научит игнорировать долю.
//
// `project_role` — роль с областью «проект». Её `account_id` пуст по ограничению
// схемы (`roles_definition_tier_xor`: ровно один непустой якорь из трёх), а
// отношения `project` у типа `iam_role` в модели прав нет вовсе. Поэтому форма,
// достроенная из схемы, отвечает по ней РАНЬШЕ каскада движка — расхождение по
// этому классу ОЖИДАЕМО и остаётся ожидаемым: догоняет материализация, каскад не
// догонит никогда.
const DECLARED_CLASSES = ['project_role'];

// Тип объекта выводится ОДНИМ выражением на весь прибор — тем же, которым ниже
// строится пул перестановки. Второе выражение разошлось бы с первым молча.
function objectType(object) { return object.split(':')[0]; }

// ─────────────────────────────────────────────────────────────────────────────
// СУЖЕНИЕ ПОДАЧИ — ЧЕМ РАЗВОДЯТСЯ ЗНАМЕНАТЕЛИ
//
// Счётчики сравнителя живут в СЛУЖБЕ и общие на всю подачу: разложить их по типу
// объекта, не трогая службу, нельзя. Поэтому «доля по пяти типам» берётся не
// разбором счётчиков, а ОТДЕЛЬНОЙ рукой: сузили подачу — дельта счётчиков за
// прогон относится ровно к ней и ни к чему больше.
//
// Форма — `only:a,b` либо `not:a,b`; пусто значит «вся подача». Неизвестная форма
// — ЯВНЫЙ отказ, а не молчаливое «подам всё»: сужение, которое не состоялось,
// вернуло бы долю по всей подаче под именем доли по пяти типам.
function selector(spec, name) {
  const raw = (spec || '').replace(/^\s+|\s+$/g, '');
  if (raw === '') return null;
  const i = raw.indexOf(':');
  const mode = i < 0 ? '' : raw.slice(0, i);
  const list = (i < 0 ? '' : raw.slice(i + 1)).split(',')
    .map(function (x) { return x.replace(/^\s+|\s+$/g, ''); })
    .filter(function (x) { return x !== ''; });
  if ((mode !== 'only' && mode !== 'not') || list.length === 0) {
    throw new Error(name + ': ожидается «only:a,b» либо «not:a,b», получено «' + raw + '»');
  }
  return { only: mode === 'only', set: list };
}

const TYPE_SEL  = selector(__ENV.FEED_TYPES, 'FEED_TYPES');
const CLASS_SEL = selector(__ENV.FEED_CLASS, 'FEED_CLASS');

function keepTuple(t) {
  if (TYPE_SEL !== null) {
    const hit = TYPE_SEL.set.indexOf(objectType(t.object)) >= 0;
    if (hit !== TYPE_SEL.only) return false;
  }
  if (CLASS_SEL !== null) {
    const hit = CLASS_SEL.set.indexOf(t['class'] || '') >= 0;
    if (hit !== CLASS_SEL.only) return false;
  }
  return true;
}

const TUPLES = RAW_TUPLES.filter(keepTuple);

// Пустая подача — ТРЕТИЙ исход, а не тихий ноль. Прогон на ней дал бы
// «сравнений 0», неотличимое от «сравнили и не разошлись», то есть ровно тот
// класс, ради которого этот прибор и правится.
if (TUPLES.length === 0) {
  throw new Error('ПОДАЧА ПУСТА после сужения (FEED_TYPES="' + (__ENV.FEED_TYPES || '') +
    '", FEED_CLASS="' + (__ENV.FEED_CLASS || '') + '", всего в фикстуре ' + RAW_TUPLES.length +
    '): мерить нечем, и «ноль расхождений» здесь означало бы «ноль прочитанного»');
}

const COMPOSITION = (function () {
  const byType = {};
  const byClass = {};
  let own = 0;
  for (const c of DECLARED_CLASSES) byClass[c] = 0;
  for (const t of TUPLES) {
    const ty = objectType(t.object);
    byType[ty] = (byType[ty] || 0) + 1;
    const cl = t['class'] || '-';
    byClass[cl] = (byClass[cl] || 0) + 1;
    if (OWN_IAM_TYPES.indexOf(ty) >= 0) own += 1;
  }
  return { byType: byType, byClass: byClass, own: own, total: TUPLES.length };
})();

// Отчёт СТРОКАМИ, а не одним JSON: его читает и человек, и оболочка прибора на
// оболочечном языке, где разбор JSON потребовал бы второго инструмента.
function reportComposition() {
  console.log('ФИКСТУРА-СОСТАВ всего ' + COMPOSITION.total + ' из ' + RAW_TUPLES.length + ' в фикстуре');
  const types = Object.keys(COMPOSITION.byType).sort();
  for (const ty of types) console.log('ФИКСТУРА-ТИП ' + ty + ' ' + COMPOSITION.byType[ty]);
  const classes = Object.keys(COMPOSITION.byClass).sort();
  for (const cl of classes) console.log('ФИКСТУРА-КЛАСС ' + cl + ' ' + COMPOSITION.byClass[cl]);
  console.log('ФИКСТУРА-СВОИ-ТИПЫ ' + OWN_IAM_TYPES.join(','));
  console.log('ФИКСТУРА-СВОИ ' + COMPOSITION.own);
  if (COMPOSITION.own === 0) {
    console.log('ФИКСТУРА-ПРЕДУПРЕЖДЕНИЕ подача не содержит НИ ОДНОГО объекта пяти ' +
      'собственных типов iam (' + OWN_IAM_TYPES.join(', ') + '); доля расхождений, ' +
      'снятая на ней, об этих типах НЕ УТВЕРЖДАЕТ НИЧЕГО');
  }
}

// Режим «только состав»: одна итерация, ни одного обращения к службе. Спрашивать
// состав подачи ценой прогона нельзя — стенд общий.
const COMPOSITION_ONLY = (__ENV.COMPOSITION_ONLY || '') !== '';

// Индекс объектов ПО ТИПУ: отказ строится подстановкой объекта ТОГО ЖЕ типа.
// Кросс-типовая подстановка тоже дала бы «нет пути», но сменила бы стоимость:
// у типов, принадлежащих iam (account/project), путь отказа доплачивает
// структурным чтением в свою базу, у vpc-типов — нет. Смешав типы, мы мерили бы
// не ту работу, которую платит настоящий отказ по этому объекту.
//
// Строится по СУЖЕННОЙ подаче: иначе рука по пяти типам подставляла бы объекты
// чужих типов и мерила бы не свой знаменатель.
const BY_TYPE = {};
for (const t of TUPLES) {
  const ty = objectType(t.object);
  (BY_TYPE[ty] = BY_TYPE[ty] || []).push(t.object);
}

// open() доступен ТОЛЬКО в init-контексте — читаем ключевой материал здесь,
// иначе connect() внутри итерации падает на каждом VU.
const CERT = open(CERT_PATH);
const KEY  = open(KEY_PATH);
const CA   = open(CA_PATH);

const checkLatency = new Trend('iam_check_latency_ms', true);
const allowLatency = new Trend('iam_check_allow_latency_ms', true);
const denyLatency  = new Trend('iam_check_deny_latency_ms', true);
const errRate      = new Rate('iam_check_errors');
// Отказ обязан НАЗЫВАТЬ СЕБЯ. Прежде прибор печатал долю отказов и молчал о их
// природе: «20.89 %» одинаково выглядит и при исчерпании пула службы, и при
// сроке вызова, и при том, что нагрузчик не смог отправить запрос вовсе.
// Разбирая такой отчёт, инженер строит гипотезы вместо чтения — и строит их
// про систему, тогда как отказ мог родиться в приборе.
//
// Счётчик на каждый статус: `iam_check_err_<код>`; отдельно — случай, когда
// ответа нет ВОВСЕ (`res` пуст), потому что это не статус, а его отсутствие,
// и означает оно другое: до службы не дошли.
// Счётчики объявлены ЗАРАНЕЕ и все сразу: k6 разрешает заводить метрику только
// в контексте загрузки, поэтому «создам, когда встретится такой код» —
// невозможно by construction. Кодов gRPC семнадцать (0..16), и объявить их все
// дешевле, чем гадать, какие встретятся: незанятые не печатаются.
const errByStatus = {};
for (let c = 0; c <= 16; c++) {
  errByStatus[String(c)] = new Counter('iam_check_err_status_' + c);
}
const errNoResponse = new Counter('iam_check_err_no_response');
const okCount      = new Counter('iam_check_ok');
const wrongVerdict = new Counter('iam_check_wrong_verdict');
// Три счётчика ниже делают ОТКАЗНОЙ вход наблюдаемым. Без них доля отказа была
// намерением (`ALLOW_RATIO`), а не измеренной величиной, и разойтись с ней могла
// молча — см. `denyInputUnavailable`.
const denyInput            = new Counter('iam_check_deny_input');
const denyInputAllowed     = new Counter('iam_check_deny_input_allowed');
const denyInputUnavailable = new Counter('iam_check_permutation_unavailable');

export const options = COMPOSITION_ONLY ? {
  scenarios: {
    composition: {
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 1,
      maxDuration: '30s',
    },
  },
  // Порогов нет намеренно: в этом режиме не измеряется ничего, и порог,
  // применённый к пустому набору, объявил бы «выдержан» о неснятой величине.
  thresholds: {},
} : {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: TARGET_RPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: PRE_VUS,
      maxVUs: MAX_VUS,
      gracefulStop: '10s',
    },
  },
  // Порог — БЮДЖЕТ ЧТЕНИЯ, а не украшение: прогон, вышедший за него, обязан
  // пометиться отказом, иначе точку насыщения пришлось бы искать глазами.
  thresholds: {
    'iam_check_latency_ms': ['p(99)<30'],
    'iam_check_errors':     ['rate<0.001'],
  },
  summaryTrendStats: ['min', 'avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  noConnectionReuse: false,
};

const client = new grpc.Client();
let connected = false;

// setup() исполняется РОВНО ОДИН раз за прогон — в отличие от init-контекста,
// который k6 исполняет в каждом VU. Состав, напечатанный оттуда, повторился бы
// столько раз, сколько поднято VU.
export function setup() {
  reportComposition();
}

export default function () {
  if (COMPOSITION_ONLY) return;
  if (!connected) {
    client.connect(ADDR, {
      reflect: true,
      tls: { cert: CERT, key: KEY, cacerts: [CA] },
    });
    connected = true;
  }

  const i = Math.floor(Math.random() * TUPLES.length);
  const t = TUPLES[i];
  const wantAllow = Math.random() < ALLOW_RATIO;

  // Отказ: объект берётся у ДРУГОЙ тройки того же типа, поэтому вердикт
  // достоверно «нет пути», а не «неверный идентификатор».
  let object = t.object;
  let isDeny = false;
  if (!wantAllow) {
    const ty = objectType(t.object);
    const pool = BY_TYPE[ty];
    if (pool && pool.length > 1) {
      let cand = t.object;
      for (let k = 0; k < 4 && cand === t.object; k++) {
        cand = pool[Math.floor(Math.random() * pool.length)];
      }
      if (cand !== t.object) { object = cand; isDeny = true; }
    }
  }
  // Перестановка НЕ СОСТОЯЛАСЬ (в пуле типа один объект, либо четыре броска
  // выпали в тот же). Запрос уходит исходной РАЗРЕШАЮЩЕЙ тройкой, то есть
  // фактическая доля отказа ниже объявленной `ALLOW_RATIO`. Прежде этот снос был
  // невидим: вызов просто считался разрешающим, и объявленная доля читалась как
  // измеренная. Теперь он называет себя сам.
  if (!wantAllow && !isDeny) denyInputUnavailable.add(1);
  if (isDeny) denyInput.add(1);

  const started = Date.now();
  const res = client.invoke('kacho.cloud.iam.v1.InternalIAMService/Check', {
    subject_id: t.subject,
    relation: t.relation,
    object: object,
  });
  const ms = Date.now() - started;

  checkLatency.add(ms);
  const ok = res && res.status === grpc.StatusOK;
  errRate.add(!ok);
  if (!ok) {
    if (!res) {
      // Ответа нет вовсе: запрос не ушёл либо соединение оборвалось. Это
      // говорит о ПРИБОРЕ или транспорте, а не о службе, и путать эти два
      // случая нельзя — они чинятся в разных местах.
      errNoResponse.add(1);
    } else {
      const code = String(res.status);
      // Код вне 0..16 означает, что словарь статусов разошёлся с библиотекой —
      // считаем его отдельно, чтобы это было видно, а не потерялось.
      if (errByStatus[code]) { errByStatus[code].add(1); } else { errNoResponse.add(1); }
    }
    return;
  }
  okCount.add(1);

  const allowed = res.message && res.message.allowed === true;
  if (allowed) { allowLatency.add(ms); } else { denyLatency.add(ms); }
  // Положительный контроль: разрешающая тройка ОБЯЗАНА разрешать. Без него
  // прогон остался бы зелёным на стенде, где посев не доехал, и мерил бы
  // сплошной отказ, называя это пропускной способностью.
  if (!isDeny && !allowed) wrongVerdict.add(1);
  // Симметричная половина того же контроля: перестановка, которую движок РАЗРЕШИЛ,
  // отказом не является, и мерить на ней стоимость отказа нельзя. Это не обязано
  // быть нулём — у субъекта законно бывают права на несколько объектов своего
  // типа, — поэтому здесь счётчик, а не порог: порог краснел бы на исправном
  // стенде. Но величина обязана быть ВИДНА, иначе «10 % отказа» остаётся
  // объявлением о входе, которое никто не сверял с исходом.
  if (isDeny && allowed) denyInputAllowed.add(1);
  check(res, { 'grpc OK': (r) => r.status === grpc.StatusOK });
}

export function teardown() {
  client.close();
}
