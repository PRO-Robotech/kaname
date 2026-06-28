// authz_check.js — k6 load test for AuthorizeService.Check
// (latency SLO target: p95 ≤ 30ms under sustained load).
//
// Run:
//   k6 run -e AUTHZ_URL=http://localhost:8080/iam/v1/authorize:check \
//          -e JWT_TOKEN=<dpop-bound-jwt> tests/k6/authz_check.js
//
// Defaults: 1000 RPS sustained for 30min, target p95 ≤ 20ms (Check) and
// p95 ≤ 100ms (ListObjects). Reports failure if SLO breached.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('check_errors');
const checkLatency = new Trend('check_latency_ms', true);
const listLatency = new Trend('list_latency_ms', true);

const AUTHZ_URL  = __ENV.AUTHZ_URL  || 'http://localhost:8080/iam/v1/authorize:check';
const LIST_URL   = __ENV.LIST_URL   || 'http://localhost:8080/iam/v1/authorize:listObjects';
const JWT_TOKEN  = __ENV.JWT_TOKEN  || ''; // empty = no Authorization header
const DURATION   = __ENV.DURATION   || '30m';
const TARGET_RPS = parseInt(__ENV.TARGET_RPS || '1000', 10);

export const options = {
  scenarios: {
    sustained_check: {
      executor: 'constant-arrival-rate',
      rate: TARGET_RPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'doCheck',
    },
    occasional_list: {
      executor: 'constant-arrival-rate',
      rate: Math.max(1, Math.floor(TARGET_RPS / 50)), // 1/50th of Check rate
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 10,
      maxVUs: 50,
      exec: 'doList',
    },
  },
  thresholds: {
    'check_latency_ms': [
      'p(95)<20',
      'p(99)<50',
    ],
    'list_latency_ms': [
      'p(95)<100',
    ],
    'check_errors': ['rate<0.01'],
  },
};

function authHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (JWT_TOKEN) {
    h['Authorization'] = `Bearer ${JWT_TOKEN}`;
  }
  return h;
}

export function doCheck() {
  const subjectIdx = Math.floor(Math.random() * 100);
  const body = JSON.stringify({
    subject: `user:usr_alice_${subjectIdx}`,
    resource: {
      type: 'vpc_network',
      id: `vpcn_test_${subjectIdx % 10}`,
    },
    action: 'vpc.networks.list',
    context: {
      acr_value: '3',
      amr_claims: ['webauthn'],
      mfa_at: Math.floor(Date.now() / 1000) - 60,
      client_ip: '10.0.0.1',
    },
  });
  const res = http.post(AUTHZ_URL, body, { headers: authHeaders() });
  checkLatency.add(res.timings.duration);
  const ok = check(res, {
    'status 200/403': (r) => r.status === 200 || r.status === 403,
    'has decision': (r) => {
      try {
        const j = JSON.parse(r.body);
        return j !== null && (j.allowed === true || j.allowed === false);
      } catch (e) {
        return false;
      }
    },
  });
  if (!ok) errorRate.add(1);
}

export function doList() {
  const subjectIdx = Math.floor(Math.random() * 100);
  const body = JSON.stringify({
    subject: `user:usr_alice_${subjectIdx}`,
    resource_type: 'vpc_network',
    action: 'vpc.networks.list',
    max_results: 100,
  });
  const res = http.post(LIST_URL, body, { headers: authHeaders() });
  listLatency.add(res.timings.duration);
  check(res, {
    'list-status acceptable': (r) => r.status === 200 || r.status === 501, // 501 if ListObjects is gated off
  });
}

export function handleSummary(data) {
  return {
    stdout: JSON.stringify({
      check_p95_ms: data.metrics.check_latency_ms.values['p(95)'],
      check_p99_ms: data.metrics.check_latency_ms.values['p(99)'],
      list_p95_ms: data.metrics.list_latency_ms.values['p(95)'],
      error_rate: data.metrics.check_errors.values.rate,
    }, null, 2),
  };
}
