// 홈캠: 폰 A(카메라) → 폰 B(뷰어)로 WebRTC P2P 영상을 보낸다.
// 보안 흐름:
//  1) 카메라가 처음 켜질 때 추측 불가능한 ID(160비트)와 비밀키(256비트)를 만들고 QR로만 보여 준다.
//  2) 뷰어는 먼저 "데이터 채널만 있는" 연결을 연다(영상 트랙 없음).
//  3) 그 채널에서 챌린지-응답: HMAC-SHA256(비밀키, 카메라 난수|뷰어 난수|양쪽 DTLS 지문). 카메라도 같은 방식으로 자기를 증명.
//     지문이 들어가므로 중개 서버가 가운데 끼어들면(MITM) 검증이 깨진다. 비밀키는 네트워크로 나가지 않는다.
//  4) 통과한 뒤에만, 인증된 채널 안에서 다시 협상해 카메라 영상·소리 트랙을 붙인다.
// 중개 서버는 PeerJS 서버 프로토콜(웹소켓으로 OFFER/ANSWER/CANDIDATE 전달)을 직접 구현해 외부 스크립트가 없다.
'use strict';

/** 앱 버전. 진단 기록·설정에 보여서 두 폰이 같은 버전인지 확인한다(배포 때마다 올림). */
const APP_VERSION = '2026.10.18-10';
const $ = (s) => document.querySelector(s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 화질 단계. 해상도는 'ideal'로 요청해서 기기가 낼 수 있는 만큼 받는다. */
const QUALITY = {
  max: { w: 3840, h: 2160, fps: 30, kbps: 12000 },
  high: { w: 1920, h: 1080, fps: 30, kbps: 6000 },
  mid: { w: 1280, h: 720, fps: 30, kbps: 2500 },
  low: { w: 640, h: 480, fps: 20, kbps: 800 },
};
const STUN = [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun.cloudflare.com:3478' }];
const DEFAULTS = { quality: 'high', maxViewers: '1', audio: true, autoDim: true, turnUrl: '', turnUser: '', turnPass: '', server: '', brokers: '', night: 'auto', nightLevel: 'mid', nightSnap: true };
const KEY_SETTINGS = 'homecam.settings.v2';
const KEY_PAIR = 'homecam.pair.v2'; // 카메라 폰: 내 ID·토큰·비밀키
const KEY_CAMS = 'homecam.cams.v2'; // 뷰어 폰: 등록한 카메라 목록
const AUTH_TIMEOUT = 12000;
const FAIL_LIMIT = 5; const FAIL_WINDOW = 10 * 60000; const BLOCK_MS = 5 * 60000;

// ---------- 작은 도우미 ----------

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
/** 공식 PeerJS 클라이언트 randomToken과 같은 모양(소문자·숫자 11자), 단 암호학적 난수로. */
const rtok = () => [...rand(11)].map((b) => (b % 36).toString(36)).join('');
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64u = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(s);

function readJSON(key, fallback) { try { const v = JSON.parse(localStorage.getItem(key)); return v == null ? fallback : v; } catch { return fallback; } }
function writeJSON(key, v) { try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* 사생활 보호 모드 */ } }

/** 비밀키(raw 32바이트)를 HMAC 키로 가져온다. 내보낼 수 없게(extractable=false). */
const hmacKey = (b64) => crypto.subtle.importKey('raw', unb64u(b64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const hmacSign = async (key, text) => b64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(text))));
async function hmacVerify(key, mac, text) {
  try { return await crypto.subtle.verify('HMAC', key, unb64u(String(mac)), utf8(text)); } catch { return false; }
}
/** SDP 안의 DTLS 인증서 지문(정렬·중복 제거). 인증 문구에 넣어 연결 자체에 묶는다. */
function fpOf(sdp) {
  const set = new Set([...String(sdp || '').matchAll(/^a=fingerprint:(\S+) (\S+)/gm)].map((m) => m[1].toLowerCase() + ' ' + m[2].toUpperCase()));
  return [...set].sort().join(',');
}

// ---------- 설정 ----------

const FIELDS = Object.keys(DEFAULTS);
const loadSettings = () => ({ ...DEFAULTS, ...readJSON(KEY_SETTINGS, {}) });
// 체크박스·입력칸은 id, 선택 버튼(라디오)은 name으로 찾는다
const radios = (k) => [...document.querySelectorAll('input[name="' + k + '"]')];
function fillForm(s) {
  for (const k of FIELDS) {
    const el = $('#' + k);
    if (!el) radios(k).forEach((r) => { r.checked = r.value === String(s[k]); });
    else if (el.type === 'checkbox') el.checked = !!s[k]; else el.value = s[k];
  }
}
function readForm() {
  const s = loadSettings();
  for (const k of FIELDS) {
    const el = $('#' + k);
    if (!el) { const r = radios(k).find((x) => x.checked); if (r) s[k] = r.value; } else s[k] = el.type === 'checkbox' ? el.checked : el.value.trim();
  }
  writeJSON(KEY_SETTINGS, s);
  return s;
}

/** STUN + (있으면) TURN. 모든 미디어를 한 전송로로 묶는다(재협상 때도 같은 DTLS). */
function rtcConfig(s) {
  const iceServers = [...STUN];
  const urls = (s.turnUrl || '').split(',').map((u) => u.trim()).filter(Boolean);
  if (urls.length) iceServers.push({ urls, username: s.turnUser, credential: s.turnPass });
  return { iceServers, bundlePolicy: 'max-bundle' };
}

/** 중개 서버 주소. 기본은 PeerJS 무료 서버. https(wss)만 허용(내 컴퓨터 시험용 localhost 제외). */
function signalBase(s) {
  if (!s.server) return 'wss://0.peerjs.com:443/peerjs?key=peerjs';
  const u = new URL(s.server);
  const local = ['localhost', '127.0.0.1'].includes(u.hostname);
  if (u.protocol !== 'https:' && !local) throw new Error('중개 서버 주소는 https:// 로 시작해야 해요.');
  const port = u.port || (u.protocol === 'https:' ? 443 : 80);
  const path = u.pathname.endsWith('/') ? u.pathname : u.pathname + '/';
  return (u.protocol === 'https:' ? 'wss://' : 'ws://') + u.hostname + ':' + port + path + 'peerjs?key=peerjs';
}

// ---------- 중개(시그널링) 연결: PeerJS 서버 프로토콜 ----------

/**
 * 중개 서버와의 웹소켓. 끊기면 알아서 다시 붙는다.
 * 서버는 {type, src, dst, payload}를 상대에게 그대로 전달만 한다(OPEN, ID-TAKEN, EXPIRE, LEAVE는 서버가 보냄).
 */
class Signal {
  /** fresh=true면 다시 붙을 때마다 새 ID·토큰을 쓴다(뷰어: 서버에 남은 옛 연결과 얽히지 않게). */
  constructor(base, id, token, h, fresh = false) { this.base = base; this.id = id; this.token = token; this.h = h; this.fresh = fresh; this.fails = 0; this.ready = false; this.stopped = false; this.conns = 0; }
  start() { this.stopped = false; this.connect(); }
  connect() {
    clearTimeout(this.rt); clearTimeout(this.ot);
    if (this.fresh && this.conns++) { this.id = 'hv' + hex(rand(16)); this.token = hex(rand(16)); }
    let ws;
    try { ws = new WebSocket(this.base + '&id=' + this.id + '&token=' + this.token + '&version=1.5.5'); } catch (e) { dlog('서버 주소 오류: ' + e.message); return this.retry(); }
    this.ws = ws; const t0 = Date.now();
    dlog('서버 접속 시도 ' + this.base.replace(/^wss?:\/\//, '').split('/')[0] + ' id=' + this.id.slice(0, 6) + '…');
    ws.onopen = () => {
      dlog('웹소켓 열림 (' + (Date.now() - t0) + 'ms)');
      clearInterval(this.hb); this.hb = setInterval(() => this.raw({ type: 'HEARTBEAT' }), 5000);
      // 같은 ID·토큰으로 다시 붙으면 서버(PeerJS)는 OPEN을 다시 보내지 않는다 → 오류가 없으면 등록된 것으로 본다
      this.ot = setTimeout(() => { if (this.ws === ws && !this.ready) { dlog('OPEN 없이 2초 경과 → 이미 등록된 연결로 보고 진행'); this.markReady(); } }, 2000);
    };
    ws.onmessage = (e) => {
      let m; try { m = JSON.parse(e.data); } catch { return; }
      if (!m || typeof m !== 'object') return;
      if (m.type === 'OPEN') { dlog('서버 등록 완료(OPEN)'); this.markReady(); }
      else if (m.type === 'ID-TAKEN') { dlog('ID-TAKEN: 다른 기기가 같은 ID 사용'); this.stop(); if (this.h.taken) this.h.taken(); }
      else if (m.type === 'ERROR') { const msg = (m.payload && m.payload.msg) || '서버 오류'; dlog('서버 ERROR: ' + msg); if (this.h.error) this.h.error(msg); }
      else { if (m.type !== 'CANDIDATE') dlog('받음 ' + m.type + (m.src ? ' ← ' + String(m.src).slice(0, 6) + '…' : '')); this.h.msg(m); }
    };
    ws.onclose = (e) => {
      if (this.ws !== ws) return;
      dlog('웹소켓 닫힘 code=' + e.code + (e.reason ? ' reason=' + e.reason : '') + ' clean=' + e.wasClean + ' (' + Math.round((Date.now() - t0) / 100) / 10 + '초 유지)');
      this.ready = false; this.lastCode = e.code; clearInterval(this.hb); clearTimeout(this.ot);
      if (this.h.down) this.h.down(e.code);
      if (!this.stopped) this.retry();
    };
    ws.onerror = () => dlog('웹소켓 오류 이벤트');
  }
  markReady() { if (this.ready) return; clearTimeout(this.ot); this.ready = true; this.fails = 0; if (this.h.open) this.h.open(); }
  retry() {
    clearTimeout(this.rt);
    const wait = Math.min(30000, 1000 * 2 ** Math.min(this.fails++, 5));
    dlog(Math.round(wait / 1000) + '초 뒤 다시 접속');
    this.rt = setTimeout(() => this.connect(), wait);
  }
  raw(o) { if (this.ws && this.ws.readyState === 1) { this.ws.send(JSON.stringify(o)); return true; } return false; }
  send(type, dst, payload) {
    const ok = this.raw({ type, payload, dst }); // 공식 클라이언트와 같은 순서·모양
    if (type !== 'CANDIDATE') dlog((ok ? '보냄 ' : '보내기 실패(소켓 닫힘) ') + type + ' → ' + String(dst).slice(0, 6) + '… ' + JSON.stringify(payload || {}).length + 'B');
    return ok;
  }
  /** 네트워크가 돌아왔을 때 기다리지 말고 바로 다시 붙기 */
  kick() { if (!this.stopped && (!this.ws || this.ws.readyState > 1)) { this.fails = 0; this.connect(); } }
  stop() { this.stopped = true; this.ready = false; clearTimeout(this.rt); clearTimeout(this.ot); clearInterval(this.hb); const ws = this.ws; this.ws = null; if (ws) ws.close(); }
}

// ---------- 두 번째 중개 길: 공개 MQTT 브로커(설치·가입 없음) ----------
// PeerJS 서버가 특정 망에서 끊길 때를 대비해, 같은 메시지를 공개 MQTT 브로커로도 주고받는다.
// 브로커는 누구나 볼 수 있으므로: 연결 신청(OFFER)엔 열쇠로 만든 서명을 붙이고, 영상 인증은 기존 상호 인증이 그대로 지킨다.
const BROKERS = ['wss://broker.emqx.io:8084/mqtt', 'wss://broker.hivemq.com:8884/mqtt'];
const mqStr = (t) => { const b = utf8(t); return [b.length >> 8, b.length & 255, ...b]; };
const mqTopic = (id) => 'hcam1/' + id;

/** MQTT 3.1.1 최소 클라이언트(연결·구독·발행 QoS0·핑). 받는 함은 inbox 하나. */
class Mqtt {
  constructor(url, inbox) { this.url = url; this.inbox = inbox; this.h = {}; this.fails = 0; this.ready = false; this.stopped = false; this.name = url.replace(/^wss?:\/\//, '').split(/[:/]/)[0]; }
  start() { this.stopped = false; this.connect(); }
  connect() {
    clearTimeout(this.rt);
    let ws;
    try { ws = new WebSocket(this.url, ['mqtt']); } catch (e) { dlog('MQTT 주소 오류: ' + e.message); return this.retry(); }
    ws.binaryType = 'arraybuffer'; this.ws = ws; this.buf = new Uint8Array(0); const t0 = Date.now();
    dlog('MQTT 접속 시도 ' + this.name);
    ws.onopen = () => this.pkt(0x10, [...mqStr('MQTT'), 4, 0x02, 0, 60, ...mqStr('hc' + hex(rand(8)))]);
    ws.onmessage = (e) => { if (this.ws === ws) this.feed(new Uint8Array(e.data)); };
    ws.onclose = (e) => {
      if (this.ws !== ws) return;
      dlog('MQTT 닫힘 ' + this.name + ' code=' + e.code + ' (' + Math.round((Date.now() - t0) / 100) / 10 + '초 유지)');
      this.ready = false; clearInterval(this.hb);
      if (this.h.down) this.h.down(e.code);
      if (!this.stopped) this.retry();
    };
    ws.onerror = () => {};
  }
  /** 받은 바이트를 MQTT 패킷 단위로 잘라 처리한다(한 프레임에 여러 개·반쪽이 와도 됨). */
  feed(chunk) {
    const b = new Uint8Array(this.buf.length + chunk.length); b.set(this.buf); b.set(chunk, this.buf.length);
    let i = 0;
    while (b.length - i >= 2) {
      let len = 0; let mul = 1; let j = i + 1; let byte;
      do { if (j >= b.length) { this.buf = b.slice(i); return; } byte = b[j++]; len += (byte & 127) * mul; mul *= 128; } while (byte & 128);
      if (b.length - j < len) break;
      this.handle(b[i] >> 4, b[i] & 15, b.subarray(j, j + len));
      i = j + len;
    }
    this.buf = b.slice(i);
  }
  handle(type, flags, body) {
    if (type === 2) { // CONNACK
      if (body[1] !== 0) { dlog('MQTT 거절 ' + this.name + ' rc=' + body[1]); return this.ws.close(); }
      this.pkt(0x82, [0, 1, ...mqStr(mqTopic(this.inbox)), 0]);
    } else if (type === 9) { // SUBACK
      dlog('MQTT 준비 ' + this.name);
      clearInterval(this.hb); this.hb = setInterval(() => this.pkt(0xc0, []), 25000);
      this.ready = true; this.fails = 0; if (this.h.open) this.h.open();
    } else if (type === 3) { // PUBLISH
      const tl = (body[0] << 8) | body[1]; const off = 2 + tl + (((flags >> 1) & 3) ? 2 : 0);
      let m; try { m = JSON.parse(new TextDecoder().decode(body.subarray(off))); } catch { return; }
      if (!m || typeof m !== 'object' || typeof m.type !== 'string' || typeof m.src !== 'string') return;
      if (m.type !== 'CANDIDATE') dlog('받음 ' + m.type + ' ← ' + m.src.slice(0, 6) + '… (MQTT ' + this.name + ')');
      if (this.h.msg) this.h.msg(m);
    }
  }
  pkt(head, body) {
    if (!this.ws || this.ws.readyState !== 1) return false;
    const len = []; let n = body.length;
    do { let d = n % 128; n = Math.floor(n / 128); if (n) d |= 128; len.push(d); } while (n);
    this.ws.send(Uint8Array.from([head, ...len, ...body])); return true;
  }
  send(type, dst, payload) {
    if (!this.ready) return false;
    const ok = this.pkt(0x30, [...mqStr(mqTopic(dst)), ...utf8(JSON.stringify({ type, src: this.inbox, payload }))]);
    if (type !== 'CANDIDATE') dlog((ok ? '보냄 ' : '보내기 실패 ') + type + ' → ' + String(dst).slice(0, 6) + '… (MQTT ' + this.name + ')');
    return ok;
  }
  retry() { clearTimeout(this.rt); const wait = Math.min(30000, 1000 * 2 ** Math.min(this.fails++, 5)); this.rt = setTimeout(() => this.connect(), wait); }
  kick() { if (!this.stopped && (!this.ws || this.ws.readyState > 1)) { this.fails = 0; this.connect(); } }
  stop() { this.stopped = true; this.ready = false; clearTimeout(this.rt); clearInterval(this.hb); const ws = this.ws; this.ws = null; if (ws) ws.close(); }
}

/**
 * 여러 중개 길을 하나처럼 쓴다. 보낼 때 via(받은 길)가 있으면 그 길로만, 없으면 열린 길 모두로.
 * 하나라도 열리면 open, 모두 닫히면 down.
 */
class Relay {
  constructor(list, h) {
    this.list = list; this.h = h; this.opened = false;
    for (const t of list) {
      t.h = {
        open: () => { if (!this.opened) { this.opened = true; if (h.open) h.open(); } else if (h.more) h.more(); },
        msg: (m) => { m.via = t; h.msg(m); },
        down: (code) => { if (!this.ready && this.opened) { this.opened = false; if (h.down) h.down(code); } },
        taken: () => { if (h.taken) h.taken(); },
        error: (msg) => { if (h.error) h.error(msg); },
      };
    }
  }
  get ready() { return this.list.some((t) => t.ready); }
  start() { this.list.forEach((t) => t.start()); }
  send(type, dst, payload, via) {
    if (via) return via.send(type, dst, payload);
    let ok = false; for (const t of this.list) if (t.ready) ok = t.send(type, dst, payload) || ok; return ok;
  }
  kick() { this.list.forEach((t) => t.kick()); }
  stop() { this.list.forEach((t) => t.stop()); }
}

/** 설정대로 중개 길 묶음을 만든다. brokers: 비우면 기본 공개 브로커, 'off'면 MQTT 안 씀. */
function makeRelay(s, id, token, fresh, h) {
  const list = [new Signal(signalBase(s), id, token, {}, fresh)];
  const urls = s.brokers === 'off' ? [] : (s.brokers ? s.brokers.split(',').map((u) => u.trim()).filter(Boolean) : BROKERS);
  for (const u of urls) list.push(new Mqtt(u, id));
  return new Relay(list, h);
}

/** ICE 후보 모으기를 잠깐 기다린다 → 후보를 SDP에 담아 한 번에 보내 중개 서버로 가는 메시지를 줄인다. */
function waitIce(pc, ms = 3000) {
  const t0 = Date.now();
  const end = (why) => dlog('ICE 후보 모으기 ' + why + ' (' + (Date.now() - t0) + 'ms) → 담은 후보 ' + candText(pc.localDescription && pc.localDescription.sdp));
  if (pc.iceGatheringState === 'complete') { end('완료'); return Promise.resolve(); }
  return new Promise((res) => {
    const t = setTimeout(() => done('시간 초과'), ms);
    function done(why) { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', chk); end(why); res(); }
    function chk() { if (pc.iceGatheringState === 'complete') done('완료'); }
    pc.addEventListener('icegatheringstatechange', chk);
  });
}

/** SDP(또는 후보 한 줄들) 안의 ICE 후보 종류 세기: host(내 기기)/srflx(공유기 바깥 주소)/relay(TURN 중계). */
function candCount(text) {
  const c = { host: 0, srflx: 0, prflx: 0, relay: 0 };
  for (const m of String(text || '').matchAll(/candidate:\S+ \d+ (\S+) \d+ \S+ \d+ typ (\w+)/g)) c[m[2]] = (c[m[2]] || 0) + 1;
  return c;
}
const candText = (text) => { const c = candCount(text); return 'host ' + c.host + ' · srflx ' + c.srflx + ' · relay ' + c.relay + (c.prflx ? ' · prflx ' + c.prflx : ''); };

/** ICE 진행을 진단 기록에 남긴다: 상태 변화, STUN/TURN 서버 오류, 늦게 온 후보 수, 연결된 경로, 실패 시 원인 힌트. */
function watchIce(pc, who, s, onRoute) {
  const late = { mine: '', theirs: '' };
  const turn = (s.turnUrl || '').split(',').filter((u) => u.trim()).length;
  dlog(who + ' ICE 서버: STUN 2개' + (turn ? ' + TURN ' + turn + '개' : ' (TURN 없음)'));
  pc.addEventListener('icecandidate', (e) => { if (e.candidate && e.candidate.candidate) late.mine += e.candidate.candidate + '\n'; });
  pc.addEventListener('icecandidateerror', (e) => {
    // 701 등은 흔한 일시 오류. TURN 주소·비밀번호가 틀리면 여기서 401 등이 보인다.
    if (e.errorCode === 701 && !/turn/i.test(e.url || '')) return;
    dlog(who + ' ICE 서버 오류 ' + (e.url || '') + ' ' + e.errorCode + ' ' + (e.errorText || ''));
  });
  pc.addEventListener('iceconnectionstatechange', async () => {
    const st = pc.iceConnectionState;
    dlog(who + ' ICE 상태 ' + st);
    if (st === 'connected' || st === 'completed') {
      try {
        const r = await pc.getStats(); let pair = null; const c = {};
        r.forEach((x) => { if (x.type === 'candidate-pair' && (x.selected || x.nominated) && x.state === 'succeeded') pair = x; if (/candidate$/.test(x.type)) c[x.id] = x; });
        if (pair) {
          const l = c[pair.localCandidateId] || {}; const rm = c[pair.remoteCandidateId] || {};
          const relay = l.candidateType === 'relay' || rm.candidateType === 'relay';
          dlog(who + ' 연결 경로: 내 ' + l.candidateType + '(' + (l.relayProtocol || l.protocol) + ') ↔ 상대 ' + rm.candidateType + (relay ? ' · TURN 중계' : ' · 직접'));
          if (onRoute) onRoute(relay);
        }
      } catch { /* 통계 없음 */ }
    } else if (st === 'failed') {
      const mine = candCount((pc.localDescription && pc.localDescription.sdp) + late.mine);
      const theirs = candCount(pc.remoteDescription && pc.remoteDescription.sdp);
      dlog(who + ' 연결 실패 요약: 내 후보 ' + candText((pc.localDescription && pc.localDescription.sdp) + late.mine) + ' / 상대 후보 ' + candText(pc.remoteDescription && pc.remoteDescription.sdp));
      if (!mine.relay && !theirs.relay) dlog(who + ' → 직접 연결이 막힌 망(5G 등)이에요. 설정에 TURN을 넣으면 해결돼요.');
      else dlog(who + ' → TURN 후보는 있는데도 실패: TURN 주소·포트(443/TCP 권장)를 확인하세요.');
    }
  });
  return late;
}

// ---------- 진단 기록(설정 → 진단 보기, 상태 표시 누르기) ----------

const KEY_DIAG = 'homecam.diag.v1';
const diag = readJSON(KEY_DIAG, []);
let diagSave = 0;
/** 최근 이벤트 한 줄 기록. 열쇠·토큰은 절대 넣지 않는다(ID도 앞 6자만). */
function dlog(msg) {
  const d = new Date(); const p = (n, w = 2) => String(n).padStart(w, '0');
  diag.push(p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '.' + p(d.getMilliseconds(), 3) + ' ' + msg);
  if (diag.length > 120) diag.splice(0, diag.length - 120);
  clearTimeout(diagSave); diagSave = setTimeout(() => writeJSON(KEY_DIAG, diag), 300);
  if (!$('#diagSheet').hidden) $('#diagLog').textContent = diagText();
}
const diagText = () => diag.slice(-40).join('\n');
function openDiag() {
  const ua = navigator.userAgent.replace(/^Mozilla\/5\.0 /, '');
  $('#diagLog').textContent = diagText() || '(기록 없음)';
  $('#diagEnv').textContent = '앱 ' + APP_VERSION + ' · 기기: ' + ua.slice(0, 120) + ' · 연결: ' + ((navigator.connection && navigator.connection.effectiveType) || '-') + ' · ' + (navigator.onLine ? '온라인' : '오프라인');
  $('#diagSheet').hidden = false;
}

// ---------- 공통 화면 도우미 ----------

let wakeLock = null;
/** 화면 꺼짐 방지. 지원 안 하는 브라우저는 조용히 넘어간다. */
async function keepAwake(on) {
  try {
    if (on && !wakeLock && 'wakeLock' in navigator && document.visibilityState === 'visible') {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
    } else if (!on && wakeLock) { await wakeLock.release(); wakeLock = null; }
  } catch { /* 배터리 절약 모드 등 */ }
}
let toastTimer;
function toast(msg, ms = 2500) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}
function setStatus(prefix, text, state) {
  $('#' + prefix + 'Status').textContent = text;
  $('#' + prefix + 'Dot').className = 'dot' + (state ? ' ' + state : '');
  if (prefix === 'cam') $('#dimText').textContent = (state === 'ok' ? '● ' : '○ ') + text + ' · 누르면 돌아와요';
}
function show(id) { for (const s of ['home', 'settings', 'vhome', 'vpair', 'cam', 'view']) $('#' + s).hidden = s !== id; window.scrollTo(0, 0); }
/** 아이콘 버튼의 글자만 바꾼다(아이콘은 그대로). */
function setLabel(btn, text) { const n = [...btn.childNodes].reverse().find((x) => x.nodeType === 3 || (x.tagName === 'SPAN' && !x.classList.contains('disc'))); if (n) n.textContent = text; }
const fmtKbps = (k) => (k >= 1000 ? (k / 1000).toFixed(1) + 'Mbps' : Math.round(k) + 'kbps');
const sendJSON = (dc, o) => { if (dc && dc.readyState === 'open') { dc.send(JSON.stringify(o)); return true; } return false; };

/** 연결 하나의 수신/송신 통계(해상도·fps·비트레이트·직접/중계). */
async function readStats(pc, dir, prev) {
  const r = await pc.getStats();
  let v = null; let pair = null; const cands = {};
  r.forEach((x) => {
    if (x.type === (dir === 'in' ? 'inbound-rtp' : 'outbound-rtp') && x.kind === 'video' && (!v || (x.frameWidth || 0) > (v.frameWidth || 0))) v = x;
    if (x.type === 'candidate-pair' && (x.selected || x.nominated) && x.state === 'succeeded') pair = x;
    if (x.type === 'local-candidate' || x.type === 'remote-candidate') cands[x.id] = x;
  });
  const relay = !!pair && [pair.localCandidateId, pair.remoteCandidateId].some((id) => cands[id] && cands[id].candidateType === 'relay');
  if (!v) return { text: '', prev };
  const bytes = dir === 'in' ? v.bytesReceived : v.bytesSent;
  const kbps = prev && v.timestamp > prev.ts ? ((bytes - prev.bytes) * 8) / (v.timestamp - prev.ts) : 0;
  const fps = Math.round(v.framesPerSecond || 0);
  const text = (v.frameWidth ? v.frameWidth + '×' + v.frameHeight : '') + (fps ? ' · ' + fps + 'fps' : '') + (kbps ? ' · ' + fmtKbps(kbps) : '') + (pair ? (relay ? ' · 중계' : ' · 직접') : '');
  return { text, prev: { ts: v.timestamp, bytes } };
}

// =====================================================================
// 카메라(A) 모드
// =====================================================================

const cam = { seen: new Set(), dropped: 0, active: false, s: null, pair: null, hkey: null, sig: null, stream: null, facing: 'environment', sessions: new Map(), fails: [], failTotal: 0, blockedUntil: 0, watch: 0, idle: 0, dimMove: 0, micOn: true, torch: false, battery: null };

/** 카메라 폰의 페어링 정보. 없으면 새로 만든다(난수 ID 160비트 + 비밀키 256비트). */
function loadPair() {
  const p = readJSON(KEY_PAIR, null);
  try {
    if (p && /^hc[0-9a-f]{40}$/.test(p.id) && unb64u(p.key).length === 32) {
      if (!/^[0-9a-z]{6,16}$/.test(p.token)) { p.token = rtok(); writeJSON(KEY_PAIR, p); } // 서버 토큰 모양만 공식 클라이언트와 맞춤(열쇠·ID 그대로)
      return p;
    }
  } catch { /* 깨진 값 */ }
  return newPair();
}
function newPair() { const p = { id: 'hc' + hex(rand(20)), token: rtok(), key: b64u(rand(32)), shown: false }; writeJSON(KEY_PAIR, p); return p; }
const pairCode = (p) => 'HC1.' + p.id + '.' + p.key;
const pairLink = (p) => location.origin + location.pathname + '#pair=' + pairCode(p);

/** 카메라를 연다. 원하는 해상도가 안 되면 단계적으로 낮춘다. */
async function getCamera(facing, q, audio) {
  const tries = [{ width: { ideal: q.w }, height: { ideal: q.h }, frameRate: { ideal: q.fps } }, { width: { ideal: 1280 }, height: { ideal: 720 } }, {}];
  let last;
  for (const v of tries) {
    try {
      return await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: facing }, ...v },
        audio: audio ? { echoCancellation: true, noiseSuppression: true, autoGainControl: true } : false,
      });
    } catch (e) { last = e; if (e.name === 'NotAllowedError' || e.name === 'SecurityError') break; }
  }
  throw last;
}

async function startCamera() {
  dlog('— 카메라 시작 (앱 ' + APP_VERSION + ')');
  const s = readForm();
  if (!checkSecure()) return;
  let base; try { base = signalBase(s); } catch (e) { $('#homeErr').textContent = e.message; return; }
  cam.s = s; cam.active = true; cam.micOn = s.audio;
  show('cam'); setStatus('cam', '카메라 켜는 중…');
  try { await openStream(); } catch (e) { return failHome(e); }
  cam.pair = loadPair();
  cam.hkey = await hmacKey(cam.pair.key);
  keepAwake(true);
  connectCamSignal();
  clearInterval(cam.watch); cam.watch = setInterval(camWatchdog, 10000);
  camStatsLoop();
  bumpIdle();
  if (!cam.pair.shown) { cam.pair.shown = true; writeJSON(KEY_PAIR, cam.pair); openPairSheet(); }
}

function connectCamSignal() {
  if (cam.sig) cam.sig.stop();
  setStatus('cam', '연결 서버에 등록 중…');
  cam.sig = makeRelay(cam.s, cam.pair.id, cam.pair.token, false, {
    open: camStatus, more: camStatus,
    msg: onCamSignal,
    down: (code) => setStatus('cam', '서버와 끊김(' + code + ') · 다시 연결 중…', 'bad'),
    taken: () => setStatus('cam', '이 카메라 ID를 다른 기기가 쓰고 있어요 · 페어링 초기화를 해 주세요', 'bad'),
    error: (msg) => setStatus('cam', '서버 오류: ' + msg, 'bad'),
  });
  cam.sig.start();
}

const authedCount = () => [...cam.sessions.values()].filter((x) => x.authed).length;
const isBlocked = () => Date.now() < cam.blockedUntil;

function camStatus() {
  if (!cam.active) return;
  const max = Number(cam.s.maxViewers) || 1; const n = authedCount();
  const fail = (cam.failTotal ? ' · ⚠ 인증 실패 ' + cam.failTotal + '회' : '') + (cam.dropped ? ' · 무시한 신청 ' + cam.dropped + '건' : '');
  if (isBlocked()) setStatus('cam', '⛔ 인증 실패가 많아 ' + Math.ceil((cam.blockedUntil - Date.now()) / 60000) + '분간 새 연결 차단' + fail, 'bad');
  else if (!cam.sig || !cam.sig.ready) setStatus('cam', '연결 서버에 등록 중…' + fail);
  else if (n) setStatus('cam', '보는 중 ' + n + '/' + max + '명' + fail, 'ok');
  else setStatus('cam', '대기 중 · 등록된 뷰어만 볼 수 있어요' + fail, 'ok');
}

function noteFail() {
  const now = Date.now();
  cam.failTotal++;
  cam.fails = cam.fails.filter((t) => now - t < FAIL_WINDOW); cam.fails.push(now);
  if (cam.fails.length >= FAIL_LIMIT) { cam.blockedUntil = now + BLOCK_MS; cam.fails = []; toast('인증 실패가 반복돼 5분간 새 연결을 막아요', 4000); }
  camStatus();
}

/** 중개 서버로 온 메시지. 처음 연결(데이터 채널만)만 받아 준다. */
async function onCamSignal(m) {
  const p = m.payload || {};
  if (m.type === 'OFFER') {
    if (isBlocked()) { dlog('[카메라] 차단 중이라 연결 신청 무시'); return; }
    if ([...cam.sessions.values()].filter((x) => !x.authed).length >= 3) { dlog('[카메라] 인증 대기 연결이 많아 신청 무시'); return; } // 인증 안 된 연결이 쌓이지 않게
    // 공식 PeerJS 모양: { sdp: {type, sdp}, type: 'data', connectionId, metadata: {ts, tag}, label, reliable, serialization }
    const sid = p.connectionId; const sdp = p.sdp && p.sdp.type === 'offer' ? p.sdp.sdp : null; const md = p.metadata || {};
    if (typeof sid !== 'string' || typeof sdp !== 'string') { cam.dropped++; dlog('[카메라] 모양이 다른 연결 신청 무시(뷰어 앱이 옛 버전일 수 있음)'); return camStatus(); }
    if (cam.sessions.has(sid) || cam.seen.has(sid)) return; // 같은 신청이 다른 길로 또 온 것
    if (/^m=(audio|video)/m.test(sdp)) { dlog('[카메라] 인증 전 영상 협상 시도 무시'); return; } // 인증 전엔 영상·소리 협상 금지
    // 열쇠로 서명한 신청만 받는다(공개 중개 길에서 엿본 사람은 연결 자체를 못 만듦). 같은 신청 재사용·10분 넘은 신청 거부.
    const fresh = typeof md.ts === 'number' && Math.abs(Date.now() - md.ts) < 10 * 60000;
    cam.seen.add(sid); if (cam.seen.size > 300) cam.seen.delete(cam.seen.values().next().value);
    if (!fresh || !(await hmacVerify(cam.hkey, md.tag, offerText(sid, md.ts, sdp)))) { cam.dropped++; dlog('[카메라] 서명이 맞지 않는 연결 신청 무시' + (fresh ? '(열쇠가 다름 → 뷰어 재등록 필요?)' : '(두 폰 시각이 10분 넘게 어긋남)')); camStatus(); return; }
    camSession(m.src, sid, sdp).catch(() => {});
  } else if (m.type === 'CANDIDATE') {
    const ss = cam.sessions.get(p.connectionId);
    if (ss && ss.peer === m.src && p.candidate) addCandidate(ss, p.candidate);
  }
  // EXPIRE·LEAVE(PeerJS 길에서만 옴)로는 끊지 않는다: 다른 길로 답이 갔을 수 있고, 인증 안 된 연결은 12초 뒤 알아서 정리된다.
}

function addCandidate(ss, c) {
  dlog('[카메라] 늦게 온 상대 후보: ' + ((/typ (\w+)/.exec(c.candidate || '') || [])[1] || '?'));
  if (ss.pc.remoteDescription) ss.pc.addIceCandidate(c).catch(() => {}); else ss.pending.push(c);
}

async function camSession(peer, sid, sdp) {
  const pc = new RTCPeerConnection(rtcConfig(cam.s));
  watchIce(pc, '[카메라]', cam.s);
  const dc = pc.createDataChannel('ctl', { negotiated: true, id: 0 });
  dc.binaryType = 'arraybuffer';
  const ss = { sid, peer, pc, dc, authed: false, nonce: '', pending: [], audio: null, ended: false };
  cam.sessions.set(sid, ss);
  ss.timer = setTimeout(() => { if (!ss.authed) endCam(ss); }, AUTH_TIMEOUT);
  pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate && ss.sent && cam.sig) dlog('[카메라] 늦게 나온 내 후보 보냄: ' + ((/typ (\w+)/.exec(e.candidate.candidate) || [])[1] || '?')), cam.sig.send('CANDIDATE', peer, { candidate: e.candidate.toJSON(), type: 'data', connectionId: sid }); }; // 늦게 나온 후보만 따로
  pc.onconnectionstatechange = () => { dlog('[카메라] 연결 상태 ' + pc.connectionState); if (['failed', 'closed'].includes(pc.connectionState)) endCam(ss); else if (pc.connectionState === 'connected' && ss.authed) tuneSenders(pc); };
  pc.ontrack = (e) => {
    if (!ss.authed || e.track.kind !== 'audio') return;
    // 뷰어 목소리(말하기). 처음엔 빈 트랙.
    if (!ss.audio) { ss.audio = new Audio(); ss.audio.autoplay = true; }
    ss.audio.srcObject = new MediaStream([e.track]); ss.audio.play().catch(() => {});
  };
  dc.onopen = () => { ss.nonce = b64u(rand(32)); sendJSON(dc, { t: 'hello', v: 1, n: ss.nonce }); };
  dc.onmessage = (e) => onCamData(ss, e.data).catch(() => endCam(ss));
  dc.onclose = () => endCam(ss);
  dlog('[카메라] 받은 신청의 후보: ' + candText(sdp));
  await pc.setRemoteDescription({ type: 'offer', sdp });
  dlog('연결 요청 받음 ← ' + peer.slice(0, 6) + '…');
  await pc.setLocalDescription(await pc.createAnswer());
  await waitIce(pc);
  ss.sent = true;
  if (cam.sig) cam.sig.send('ANSWER', peer, { sdp: { sdp: pc.localDescription.sdp, type: 'answer' }, type: 'data', connectionId: sid }); // 열린 길 모두로(한 길이 끊겨도 다른 길로 도착)
  ss.pending.splice(0).forEach((c) => pc.addIceCandidate(c).catch(() => {}));
}

function endCam(ss) {
  if (ss.ended) return;
  ss.ended = true; clearTimeout(ss.timer);
  cam.sessions.delete(ss.sid);
  if (ss.audio) ss.audio.srcObject = null;
  try { ss.dc.close(); } catch { /* 이미 닫힘 */ }
  ss.pc.close();
  camStatus();
}

/** 인증 문구. 양쪽 난수와 DTLS 지문을 묶는다(역할 이름이 달라 서로의 응답을 재사용할 수 없음). */
/** 연결 신청 서명 문구(신청 번호·시각·뷰어 DTLS 지문). */
const offerText = (sid, ts, sdp) => 'homecam/1|offer|' + sid + '|' + ts + '|' + fpOf(sdp);
const authText = (role, nC, nV, fpV, fpC) => 'homecam/1|' + role + '|' + nC + '|' + nV + '|' + fpV + '|' + fpC;

async function onCamData(ss, raw) {
  if (typeof raw !== 'string') { if (!ss.authed) endCam(ss); return; }
  let m; try { m = JSON.parse(raw); } catch { return endCam(ss); }
  if (!m || typeof m !== 'object') return;
  const fpV = fpOf(ss.pc.remoteDescription && ss.pc.remoteDescription.sdp);
  const fpC = fpOf(ss.pc.localDescription && ss.pc.localDescription.sdp);
  if (!ss.authed) {
    if (m.t !== 'auth' || !ss.nonce || ss.tried || typeof m.n !== 'string' || m.n.length < 40) return endCam(ss);
    ss.tried = true; // 연결 하나당 한 번만 시도
    const ok = await hmacVerify(cam.hkey, m.mac, authText('viewer', ss.nonce, m.n, fpV, fpC));
    dlog('[카메라] 인증 ' + (ok ? '통과' : '실패'));
    if (!ok) { noteFail(); sendJSON(ss.dc, { t: 'deny', why: 'auth' }); setTimeout(() => endCam(ss), 300); return; }
    if (authedCount() >= (Number(cam.s.maxViewers) || 1)) { dlog('[카메라] 뷰어 수 초과로 거절'); sendJSON(ss.dc, { t: 'deny', why: 'busy' }); setTimeout(() => endCam(ss), 300); return; }
    ss.authed = true; ss.fpV = fpV; clearTimeout(ss.timer);
    sendJSON(ss.dc, { t: 'ok', mac: await hmacSign(cam.hkey, authText('camera', ss.nonce, m.n, fpV, fpC)) });
    toast('새 뷰어가 연결됐어요 (' + authedCount() + '/' + cam.s.maxViewers + ')', 4000);
    camStatus(); sendInfo();
    return;
  }
  // ---- 여기부터는 인증된 뷰어만 ----
  if (m.t === 'sdp' && m.type === 'offer' && typeof m.sdp === 'string') {
    if (fpOf(m.sdp) !== ss.fpV) return endCam(ss); // 전송로(지문)가 바뀌면 거부
    await ss.pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
    await attachTracks(ss.pc);
    await ss.pc.setLocalDescription(await ss.pc.createAnswer());
    sendJSON(ss.dc, { t: 'sdp', type: 'answer', sdp: ss.pc.localDescription.sdp });
    tuneSenders(ss.pc);
  } else if (m.t === 'flip') { cam.facing = cam.facing === 'environment' ? 'user' : 'environment'; await openStream(); }
  else if (m.t === 'quality' && QUALITY[m.q]) { cam.s.quality = m.q; writeJSON(KEY_SETTINGS, cam.s); await openStream(); }
  else if (m.t === 'torch') {
    try { await cam.stream.getVideoTracks()[0].applyConstraints({ advanced: [{ torch: !!m.on }] }); cam.torch = !!m.on; } catch { sendJSON(ss.dc, { t: 'msg', text: '이 카메라는 플래시를 못 켜요' }); }
    sendInfo();
  } else if (m.t === 'photo') await sendPhoto(ss);
  else if (m.t === 'info') sendInfo();
}

/** 뷰어가 만든 트랜시버에 카메라 트랙을 끼운다(영상은 보내기만, 소리는 양방향). */
async function attachTracks(pc) {
  if (!cam.stream) return;
  for (const tr of pc.getTransceivers()) {
    const kind = tr.receiver.track && tr.receiver.track.kind;
    if (kind === 'video') { tr.direction = 'sendonly'; await tr.sender.replaceTrack(cam.stream.getVideoTracks()[0] || null); }
    else if (kind === 'audio') { tr.direction = 'sendrecv'; await tr.sender.replaceTrack(cam.stream.getAudioTracks()[0] || null); }
  }
}

/** 카메라 스트림을 (다시) 열고, 보고 있는 뷰어에게는 트랙만 바꿔 끼운다. */
async function openStream() {
  const q = QUALITY[cam.s.quality] || QUALITY.high;
  if (cam.stream) cam.stream.getTracks().forEach((t) => t.stop());
  const stream = await getCamera(cam.facing, q, cam.s.audio);
  cam.stream = stream; cam.torch = false;
  for (const t of stream.getTracks()) t.addEventListener('ended', onTrackEnded);
  const at = stream.getAudioTracks()[0]; if (at) at.enabled = cam.micOn;
  $('#camVideo').srcObject = stream;
  tuneExposure(stream.getVideoTracks()[0], q);
  $('#camVideo').classList.toggle('mirror', cam.facing === 'user');
  $('#camMic').hidden = !at; $('#camMic').classList.toggle('on', cam.micOn);
  for (const ss of cam.sessions.values()) {
    if (!ss.authed) continue;
    for (const tr of ss.pc.getTransceivers()) {
      if (!tr.currentDirection || !tr.currentDirection.includes('send')) continue;
      const t = stream.getTracks().find((x) => x.kind === tr.receiver.track.kind);
      if (t) await tr.sender.replaceTrack(t).catch(() => {});
    }
    tuneSenders(ss.pc);
  }
  sendInfo();
}

/** 어두운 곳 대비: 되는 기기에서만 연속 자동노출 + 노출보정 약간 +, 프레임이 너무 떨어지지 않게. 안 되면 조용히 넘어감. */
async function tuneExposure(vt, q) {
  if (!vt || !vt.getCapabilities) return dlog('[카메라] 노출 조절: 지원 안 함(getCapabilities 없음)');
  const caps = vt.getCapabilities(); const adv = {};
  if (Array.isArray(caps.exposureMode) && caps.exposureMode.includes('continuous')) adv.exposureMode = 'continuous';
  const ec = caps.exposureCompensation;
  if (ec && ec.max > 0) { const step = ec.step || 0.1; adv.exposureCompensation = Math.min(ec.max, Math.round(0.7 / step) * step); }
  let ok = true;
  if (Object.keys(adv).length) { try { await vt.applyConstraints({ advanced: [adv] }); } catch { ok = false; } }
  let fps = '';
  if (caps.frameRate && caps.frameRate.max >= 15) {
    try { await vt.applyConstraints({ ...vt.getConstraints(), frameRate: { ideal: q.fps, min: 15 } }); fps = ' · 최소 15fps 적용'; } catch { fps = ' · 최소 fps 고정 불가'; }
  }
  dlog('[카메라] 노출 조절: 자동노출 ' + (adv.exposureMode ? '✓' : '✗') + ' · 노출보정 ' + (adv.exposureCompensation !== undefined ? '+' + adv.exposureCompensation.toFixed(1) : '✗') + (ok ? '' : '(적용 실패)') +
    ' · 플래시 ' + (caps.torch ? '✓' : '✗') + ' · fps ' + (caps.frameRate ? Math.round(caps.frameRate.min || 0) + '~' + Math.round(caps.frameRate.max) : '?') + fps);
}

let reopening = false;
async function onTrackEnded() {
  // iOS가 백그라운드에서 카메라를 뺏으면 트랙이 끝난다. 돌아오면 다시 연다.
  if (!cam.active || reopening || document.visibilityState !== 'visible') return;
  reopening = true;
  try { await sleep(800); await openStream(); } catch (e) { setStatus('cam', '카메라를 다시 못 열었어요: ' + e.message, 'bad'); }
  reopening = false;
}

/** 영상 송신에 높은 비트레이트·프레임 상한을 건다. */
function tuneSenders(pc) {
  const q = QUALITY[cam.s.quality] || QUALITY.high;
  for (const sender of pc.getSenders()) {
    if (!sender.track || sender.track.kind !== 'video') continue;
    const p = sender.getParameters();
    if (!p.encodings || !p.encodings.length) continue;
    p.encodings[0].maxBitrate = q.kbps * 1000;
    p.encodings[0].maxFramerate = q.fps;
    // 고화질 단계는 해상도를 지키고(망이 나쁘면 프레임이 준다), 절약 단계는 둘을 섞어 낮춘다
    p.degradationPreference = q.w >= 1920 ? 'maintain-resolution' : 'balanced';
    sender.setParameters(p).catch(() => { delete p.degradationPreference; sender.setParameters(p).catch(() => {}); });
  }
}

function camWatchdog() {
  if (!cam.active) return;
  if (cam.sig) cam.sig.kick();
  if (cam.stream && cam.stream.getVideoTracks().some((t) => t.readyState === 'ended')) onTrackEnded();
  camStatus();
}

/** 카메라 원본 해상도로 한 장 찍어 인증된 채널로 보낸다(16KB 조각). */
async function sendPhoto(ss) {
  const vt = cam.stream && cam.stream.getVideoTracks()[0];
  let src = null; let w = 0; let h = 0;
  if (vt && 'ImageCapture' in window) { try { src = await new ImageCapture(vt).grabFrame(); w = src.width; h = src.height; } catch { src = null; } }
  if (!src) { const v = $('#camVideo'); if (v.videoWidth) { src = v; w = v.videoWidth; h = v.videoHeight; } }
  if (!src) return sendJSON(ss.dc, { t: 'photo', err: 1 });
  const c = document.createElement('canvas'); c.width = w; c.height = h;
  c.getContext('2d').drawImage(src, 0, 0, w, h);
  if (src.close) src.close();
  const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.92));
  if (!blob) return sendJSON(ss.dc, { t: 'photo', err: 1 });
  const buf = await blob.arrayBuffer();
  sendJSON(ss.dc, { t: 'photo', size: buf.byteLength, w, h });
  for (let off = 0; off < buf.byteLength; off += 16384) {
    while (ss.dc.bufferedAmount > 1 << 20) { if (ss.dc.readyState !== 'open') return; await sleep(20); }
    ss.dc.send(buf.slice(off, off + 16384));
  }
}

function sendInfo() {
  if (!cam.stream) return;
  const vt = cam.stream.getVideoTracks()[0];
  const st = vt ? vt.getSettings() : {};
  const caps = vt && vt.getCapabilities ? vt.getCapabilities() : {};
  const info = { t: 'info', v: APP_VERSION, facing: cam.facing, w: st.width, h: st.height, quality: cam.s.quality, torch: !!caps.torch, torchOn: cam.torch };
  if (cam.battery) { info.battery = Math.round(cam.battery.level * 100); info.charging = cam.battery.charging; }
  for (const ss of cam.sessions.values()) if (ss.authed) sendJSON(ss.dc, info);
}
if (navigator.getBattery) navigator.getBattery().then((b) => { cam.battery = b; b.addEventListener('levelchange', sendInfo); b.addEventListener('chargingchange', sendInfo); }).catch(() => {});

async function camStatsLoop() {
  const prevs = new Map();
  while (cam.active) {
    const vt = cam.stream && cam.stream.getVideoTracks()[0];
    const st = vt ? vt.getSettings() : {};
    let text = st.width ? '촬영 ' + st.width + '×' + st.height : '';
    for (const ss of cam.sessions.values()) {
      if (!ss.authed) continue;
      try { const r = await readStats(ss.pc, 'out', prevs.get(ss)); prevs.set(ss, r.prev); if (r.text) text += ' | 송출 ' + r.text; } catch { /* 닫히는 중 */ }
    }
    $('#camStats').textContent = text;
    await sleep(2000);
  }
}

// 페어링 QR
function openPairSheet() {
  QR.draw($('#qr'), pairLink(cam.pair), 6);
  $('#pairText').value = pairCode(cam.pair);
  $('#pairSheet').hidden = false; setDim(false);
}
async function resetPair() {
  if (!confirm('페어링을 초기화할까요?\n지금까지 등록한 뷰어는 모두 못 보게 되고, 새 QR로 다시 등록해야 해요.')) return;
  for (const ss of [...cam.sessions.values()]) endCam(ss);
  cam.pair = newPair(); cam.pair.shown = true; writeJSON(KEY_PAIR, cam.pair);
  cam.hkey = await hmacKey(cam.pair.key);
  cam.fails = []; cam.failTotal = 0; cam.blockedUntil = 0; cam.dropped = 0; cam.seen.clear();
  connectCamSignal();
  openPairSheet();
  toast('새 열쇠를 만들었어요. 뷰어에서 다시 등록하세요.', 4000);
}

// 절전: 검은 화면. 카메라·송출은 그대로 돈다. 글자는 천천히 자리를 옮긴다(번인 방지).
function setDim(on) {
  $('#dim').hidden = !on;
  clearInterval(cam.dimMove);
  if (on) {
    const move = () => { const t = $('#dimText'); t.style.left = 5 + Math.random() * 50 + '%'; t.style.top = 10 + Math.random() * 75 + '%'; };
    move(); cam.dimMove = setInterval(move, 20000);
  }
}
function bumpIdle() {
  clearTimeout(cam.idle);
  if (cam.active && cam.s.autoDim) cam.idle = setTimeout(() => { if ($('#pairSheet').hidden) setDim(true); else bumpIdle(); }, 30000);
}

function stopCamera() {
  cam.active = false;
  clearInterval(cam.watch); clearTimeout(cam.idle);
  for (const ss of [...cam.sessions.values()]) endCam(ss);
  if (cam.sig) { cam.sig.stop(); cam.sig = null; }
  if (cam.stream) { cam.stream.getTracks().forEach((t) => t.stop()); cam.stream = null; }
  $('#pairSheet').hidden = true;
  setDim(false); keepAwake(false); show('home');
}

// =====================================================================
// 뷰어(B) 모드
// =====================================================================

const view = { active: false, s: null, cam: null, hkey: null, sig: null, ss: null, timer: 0, mic: null, info: null, gotVideo: false, photo: null };

/** "HC1.<ID>.<키>"(링크 안에 있어도 됨)를 읽는다. */
function parsePair(text) {
  const m = /HC1\.(hc[0-9a-f]{40})\.([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/.exec(String(text || ''));
  return m ? { id: m[1], key: m[2] } : null;
}
const loadCams = () => readJSON(KEY_CAMS, []).filter((c) => c && parsePair('HC1.' + c.id + '.' + c.key));

function renderCamList() {
  const list = $('#camList'); list.textContent = '';
  const cams = loadCams();
  if (!cams.length) { const p = document.createElement('p'); p.className = 'empty'; p.textContent = '등록한 카메라가 없어요.'; list.append(p); }
  cams.forEach((c, i) => {
    const row = document.createElement('div'); row.className = 'cam-row';
    const go = document.createElement('button'); go.className = 'go';
    const dot = document.createElement('span'); dot.className = 'dotlive';
    go.append(dot, c.label || '카메라 ' + (i + 1));
    go.onclick = () => startViewer(c);
    const del = document.createElement('button'); del.className = 'icon-btn'; del.setAttribute('aria-label', '삭제');
    del.innerHTML = '<svg class="ic"><use href="#i-trash"/></svg>';
    del.onclick = () => { if (confirm('이 카메라 등록을 지울까요?')) { writeJSON(KEY_CAMS, loadCams().filter((x) => x.id !== c.id)); renderCamList(); } };
    row.append(go, del); list.append(row);
  });
}

/** 뷰어 시작: 카메라가 하나면 바로 보기, 없으면 등록, 여럿이면 목록. */
function openViewer() {
  readForm();
  const cams = loadCams();
  if (!cams.length) openPair();
  else if (cams.length === 1) startViewer(cams[0]);
  else { show('vhome'); renderCamList(); }
}
function openPair(code) {
  show('vpair');
  $('#pairCode').value = code || ''; $('#pairErr').textContent = '';
  if (code) $('#pairLabel').focus();
}

function addCamera() {
  const p = parsePair($('#pairCode').value);
  if (!p) { $('#pairErr').textContent = '코드가 올바르지 않아요. 카메라 폰의 QR을 다시 찍어 주세요.'; return; }
  const label = $('#pairLabel').value.trim() || '우리집';
  const entry = { ...p, label };
  writeJSON(KEY_CAMS, [...loadCams().filter((c) => c.id !== p.id), entry]);
  $('#pairCode').value = ''; $('#pairLabel').value = ''; $('#pairErr').textContent = '';
  stopScan(); startViewer(entry); // 등록하자마자 바로 보기
}

let scanStream = null;
/** 앱 안 QR 스캔(BarcodeDetector가 있는 브라우저: 안드로이드 크롬 등). 없으면 폰 기본 카메라 앱으로 찍으면 링크가 열린다. */
async function scanQR() {
  if (scanStream) return stopScan();
  try {
    const det = new BarcodeDetector({ formats: ['qr_code'] });
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } } });
    const v = $('#scanVideo'); v.srcObject = scanStream; $('#scanWrap').hidden = false; await v.play();
    setLabel($('#scanBtn'), '스캔 멈추기');
    const t0 = Date.now();
    while (scanStream && Date.now() - t0 < 60000) {
      const codes = await det.detect(v).catch(() => []);
      const hit = codes.map((c) => parsePair(c.rawValue)).find(Boolean);
      if (hit) { $('#pairCode').value = 'HC1.' + hit.id + '.' + hit.key; toast('QR을 읽었어요'); $('#pairLabel').focus(); break; }
      await sleep(250);
    }
  } catch (e) { toast('스캔을 못 했어요: ' + (e.name || e)); }
  stopScan();
}
function stopScan() {
  if (scanStream) scanStream.getTracks().forEach((t) => t.stop());
  scanStream = null; $('#scanWrap').hidden = true; $('#scanVideo').srcObject = null; setLabel($('#scanBtn'), 'QR 스캔');
}

async function startViewer(entry) {
  dlog('— 뷰어 시작 (앱 ' + APP_VERSION + ')');
  const s = readForm();
  if (!checkSecure()) return;
  let base; try { base = signalBase(s); } catch (e) { toast(e.message, 4000); return; }
  view.s = s; view.cam = entry; view.active = true; view.info = null;
  view.hkey = await hmacKey(entry.key);
  show('view'); setStatus('view', '연결 서버에 접속 중…');
  keepAwake(true);
  view.sig = makeRelay(s, 'hv' + hex(rand(16)), rtok(), false, {
    open: () => dial(),
    more: () => { const ss = view.ss; if (ss && ss.offer && !ss.authed) view.sig.send('OFFER', view.cam.id, ss.offer); }, // 늦게 열린 길로도 같은 신청
    msg: onViewSignal,
    down: (code) => { if (!view.gotVideo) setStatus('view', '서버와 끊김(' + code + ') · 다시 연결 중…', 'bad'); },
    error: (msg) => setStatus('view', '서버 오류: ' + msg, 'bad'),
  });
  view.sig.start();
  viewStatsLoop();
}

function hangup() {
  const ss = view.ss; view.ss = null;
  if (!ss) return;
  clearTimeout(ss.timer); clearTimeout(ss.lost);
  try { ss.dc.close(); } catch { /* 이미 닫힘 */ }
  ss.pc.close();
}

function redial(ms, text) {
  if (!view.active) return;
  if (text) { setStatus('view', text, 'bad'); dlog('[뷰어] ' + text); }
  clearTimeout(view.timer);
  view.timer = setTimeout(() => { if (view.sig && view.sig.ready) dial(); else if (view.sig) view.sig.kick(); }, ms);
}

/** 1단계: 데이터 채널만 있는 연결을 연다. 영상은 인증 뒤에. */
async function dial() {
  if (!view.active) return;
  clearTimeout(view.timer); hangup();
  view.gotVideo = false; $('#viewRoute').hidden = true;
  setStatus('view', '카메라에 연결 중…');
  dlog('[뷰어] 카메라에 연결 시도');
  const camId = view.cam.id; const sid = 'dc_' + rtok(); // 공식 DataConnection ID 모양
  const pc = new RTCPeerConnection(rtcConfig(view.s));
  watchIce(pc, '[뷰어]', view.s, (relay) => { if (view.ss && view.ss.pc === pc) showRoute(relay); });
  const dc = pc.createDataChannel('ctl', { negotiated: true, id: 0 });
  dc.binaryType = 'arraybuffer';
  const ss = { sid, pc, dc, pending: [], authed: false };
  view.ss = ss;
  pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate && ss.sent && view.sig) dlog('[뷰어] 늦게 나온 내 후보 보냄: ' + ((/typ (\w+)/.exec(e.candidate.candidate) || [])[1] || '?')), view.sig.send('CANDIDATE', camId, { candidate: e.candidate.toJSON(), type: 'data', connectionId: sid }); }; // 늦게 나온 후보만 따로
  pc.onconnectionstatechange = () => {
    if (view.ss !== ss) return;
    const st = pc.connectionState;
    dlog('[뷰어] 연결 상태 ' + st);
    if (st === 'failed') redial(3000, '연결 실패 · TURN 설정이 필요할 수 있어요 · 다시 시도');
    else if (st === 'disconnected') {
      setStatus('view', '신호 약함 · 기다리는 중…', 'bad');
      clearTimeout(ss.lost); ss.lost = setTimeout(() => { if (view.ss === ss && pc.connectionState !== 'connected') redial(0); }, 6000);
    } else if (st === 'connected') { clearTimeout(ss.lost); if (view.gotVideo) setStatus('view', '연결됨', 'ok'); }
  };
  dc.onmessage = (e) => onViewData(ss, e.data).catch(() => {});
  dc.onopen = () => dlog('[뷰어] 명령 채널 열림');
  dc.onclose = () => { if (view.ss === ss) dlog('[뷰어] 명령 채널 닫힘'); if (view.ss === ss) redial(1500, '카메라와 끊김 · 다시 연결 중…'); };
  ss.timer = setTimeout(() => { if (view.ss === ss && !ss.authed) redial(1000, '카메라 응답 없음(꺼져 있거나 등록이 바뀌었을 수 있어요) · 다시 시도'); }, 20000);
  await pc.setLocalDescription(await pc.createOffer());
  await waitIce(pc);
  if (view.ss !== ss || !view.sig) return;
  ss.sent = true;
  const sdp = pc.localDescription.sdp; const ts = Date.now();
  const tag = await hmacSign(view.hkey, offerText(sid, ts, sdp));
  if (view.ss !== ss || !view.sig) return;
  ss.offer = { sdp: { sdp, type: 'offer' }, type: 'data', connectionId: sid, metadata: { ts, tag }, label: sid, reliable: true, serialization: 'binary' };
  if (!view.sig.send('OFFER', camId, ss.offer)) redial(1000); // 열린 중개 길 모두로
}

function onViewSignal(m) {
  const ss = view.ss; const p = m.payload || {};
  if (m.src !== view.cam.id) return;
  // PeerJS 길에서만 오는 알림. 다른 길(MQTT)로 답이 올 수 있으니 끊지 않고 안내만(20초 안에 답 없으면 다시 시도).
  if (m.type === 'EXPIRE' || m.type === 'LEAVE') { if (!view.gotVideo) { setStatus('view', '카메라를 찾는 중… (꺼져 있거나 등록이 바뀌었을 수 있어요)', 'bad'); dlog('[뷰어] PeerJS: 카메라 없음(' + m.type + ')'); } return; }
  if (!ss || p.connectionId !== ss.sid) return;
  const sdp = p.sdp && p.sdp.type === 'answer' ? p.sdp.sdp : null;
  if (m.type === 'ANSWER' && typeof sdp === 'string' && !ss.answered) {
    ss.answered = true; // 같은 답이 여러 길로 거의 동시에 오므로 첫 답만(비동기 적용 중 두 번째가 오면 오류가 남)
    if (/^m=(audio|video)/m.test(sdp)) return redial(3000);
    dlog('[뷰어] 받은 답의 후보: ' + candText(sdp));
    ss.pc.setRemoteDescription({ type: 'answer', sdp }).then(() => ss.pending.splice(0).forEach((c) => ss.pc.addIceCandidate(c).catch(() => {}))).catch(() => redial(3000));
  } else if (m.type === 'CANDIDATE' && p.candidate) {
    dlog('[뷰어] 늦게 온 상대 후보: ' + ((/typ (\w+)/.exec(p.candidate.candidate || '') || [])[1] || '?'));
    if (ss.pc.remoteDescription) ss.pc.addIceCandidate(p.candidate).catch(() => {}); else ss.pending.push(p.candidate);
  }
}

async function onViewData(ss, raw) {
  if (view.ss !== ss) return;
  if (typeof raw !== 'string') { if (ss.authed) photoChunk(raw); return; }
  let m; try { m = JSON.parse(raw); } catch { return; }
  if (!m || typeof m !== 'object') return;
  const fpV = fpOf(ss.pc.localDescription && ss.pc.localDescription.sdp);
  const fpC = fpOf(ss.pc.remoteDescription && ss.pc.remoteDescription.sdp);
  if (m.t === 'hello' && typeof m.n === 'string' && m.n.length >= 40 && !ss.nV) {
    ss.nC = m.n; ss.nV = b64u(rand(32)); dlog('[뷰어] 카메라 문제 받음 → 답 보냄');
    sendJSON(ss.dc, { t: 'auth', n: ss.nV, mac: await hmacSign(view.hkey, authText('viewer', ss.nC, ss.nV, fpV, fpC)) });
  } else if (m.t === 'ok' && ss.nV && !ss.authed) {
    // 카메라도 같은 열쇠를 가졌는지 확인(가짜 카메라·중간자 차단)
    if (!(await hmacVerify(view.hkey, m.mac, authText('camera', ss.nC, ss.nV, fpV, fpC)))) { hangup(); return redial(15000, '카메라 확인 실패(위조 의심) · 잠시 뒤 다시 시도'); }
    ss.authed = true; clearTimeout(ss.timer); dlog('[뷰어] 서로 인증 완료 → 영상 요청');
    await startMedia(ss);
  } else if (m.t === 'deny') {
    dlog('[뷰어] 거절됨: ' + m.why);
    hangup();
    if (m.why === 'auth') { clearTimeout(view.timer); setStatus('view', '등록이 무효예요. 카메라에서 페어링을 초기화했다면 다시 등록하세요.', 'bad'); }
    else if (m.why === 'busy') redial(10000, '다른 뷰어가 보는 중이에요 · 잠시 뒤 다시 시도');
    else redial(30000, '카메라가 잠시 새 연결을 막고 있어요');
  } else if (!ss.authed) {
    /* 인증 전 다른 메시지는 무시 */
  } else if (m.t === 'sdp' && m.type === 'answer' && typeof m.sdp === 'string') {
    await ss.pc.setRemoteDescription({ type: 'answer', sdp: m.sdp });
  } else if (m.t === 'info') {
    if (m.v !== APP_VERSION && (!view.info || view.info.v !== m.v)) { dlog('[뷰어] 카메라 앱 버전이 달라요: ' + (m.v || '옛 버전')); toast('카메라 폰 앱이 다른 버전이에요. 카메라 폰에서 앱을 껐다 켜 주세요.', 5000); }
    view.info = m;
    $('#vTorch').hidden = !m.torch; $('#vTorch').classList.toggle('on', !!m.torchOn);
    $('#viewVideo').classList.toggle('mirror', m.facing === 'user'); $('#nightCanvas').classList.toggle('mirror', m.facing === 'user');
  } else if (m.t === 'photo') {
    const timer = view.photo && view.photo.timer;
    if (m.err || !(m.size > 0) || m.size > 30e6) { clearTimeout(timer); view.photo = null; framePhoto(); }
    else view.photo = { size: m.size, w: m.w, h: m.h, got: 0, parts: [], timer };
  } else if (m.t === 'msg' && typeof m.text === 'string') toast(m.text);
}

/** 2단계(인증 뒤): 영상 받기·소리 주고받기 트랜시버를 만들고, 인증된 채널로 다시 협상한다. */
async function startMedia(ss) {
  const pc = ss.pc;
  const vt = pc.addTransceiver('video', { direction: 'recvonly' });
  const at = pc.addTransceiver('audio', { direction: 'sendrecv' });
  if (view.mic) await at.sender.replaceTrack(view.mic);
  ss.audioTr = at;
  const v = $('#viewVideo');
  v.srcObject = new MediaStream([vt.receiver.track, at.receiver.track]);
  v.onloadeddata = () => {
    if (view.ss !== ss) return;
    view.gotVideo = true; setStatus('view', '연결됨', 'ok'); wakeHud(); dlog('[뷰어] 영상 수신 시작');
    startNight();
    v.play().catch(() => { v.muted = true; v.play().catch(() => {}); soundBtn(); });
    soundBtn();
  };
  v.play().catch(() => {});
  await pc.setLocalDescription(await pc.createOffer());
  sendJSON(ss.dc, { t: 'sdp', type: 'offer', sdp: pc.localDescription.sdp });
  setStatus('view', '인증됨 · 영상 받는 중…');
}

const cmd = (m) => { const ss = view.ss; if (ss && ss.authed && sendJSON(ss.dc, m)) return true; toast('카메라와 아직 연결 안 됐어요'); return false; };

async function viewStatsLoop() {
  let prev = null;
  while (view.active) {
    let text = '';
    const ss = view.ss;
    if (ss && ss.authed) { try { const r = await readStats(ss.pc, 'in', prev); prev = r.prev; text = r.text.replace(/ · (직접|중계)$/, ''); } catch { /* 닫히는 중 */ } } // 경로는 옆 배지에
    const i = view.info;
    if (i && i.battery != null) text += ' · 🔋' + i.battery + '%' + (i.charging ? '⚡' : '');
    $('#viewStats').textContent = text;
    await sleep(2000);
  }
}

/** 야간 보정 시작(영상이 들어올 때마다). 보정 중이면 달 배지를 보여 준다. */
function startNight() {
  let was = false;
  Night.start($('#viewVideo'), $('#nightCanvas'), () => ({ mode: view.s.night, level: view.s.nightLevel }), (on, b, L) => {
    $('#nightBadge').hidden = !on;
    if (on !== was) { was = on; dlog('[뷰어] 야간 보정 ' + (on ? '켜짐' : '꺼짐') + ' (밝기 ' + Math.round(L * 100) + '%, 세기 ' + Math.round(b * 100) + '%)'); }
  });
}

/** 연결 경로 표시: 직접 / 중계(TURN). */
function showRoute(relay) {
  const r = $('#viewRoute'); r.hidden = false;
  r.textContent = relay ? '중계(TURN)' : '직접';
  r.className = 'route ' + (relay ? 'relay' : 'direct');
}

const isStandalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const fsElement = () => document.fullscreenElement || document.webkitFullscreenElement;
/** 전체화면: Fullscreen API가 되면 그것으로, 안 되는 곳(아이폰 Safari)은 버튼·상단을 숨기는 몰입 모드 + 홈 화면 추가 안내. */
async function toggleFull() {
  const v = $('#view');
  const canFs = document.fullscreenEnabled || document.webkitFullscreenEnabled;
  if (canFs) {
    try {
      if (fsElement()) await (document.exitFullscreen || document.webkitExitFullscreen).call(document);
      else await (v.requestFullscreen || v.webkitRequestFullscreen).call(v, { navigationUI: 'hide' });
    } catch { /* 사용자가 막음 */ }
  } else {
    const on = v.classList.toggle('immersive');
    if (on && !isStandalone()) toast('홈 화면에 추가해서 열면 주소창 없이 꽉 차요 · 다시 두 번 누르면 돌아와요', 4000);
    else if (on) toast('두 번 누르면 버튼이 돌아와요', 1800);
  }
  fullLabel();
}
function fullLabel() { const on = !!fsElement() || $('#view').classList.contains('immersive'); setLabel($('#vFull'), on ? '나가기' : '전체화면'); }

function soundBtn() { const v = $('#viewVideo'); setLabel($('#vSound'), v.muted ? '소리 꺼짐' : '소리 켬'); $('#vSound').classList.toggle('on', !v.muted); }

// 뷰어 컨트롤: 영상이 나오면 4초 뒤 숨고, 화면을 누르면 다시 나온다
let hudTimer = 0;
function wakeHud() {
  $('#view').classList.remove('idle'); clearTimeout(hudTimer);
  if (view.gotVideo) hudTimer = setTimeout(() => { if ($('#photo').hidden) $('#view').classList.add('idle'); }, 4000);
}

async function toggleTalk() {
  try {
    if (!view.mic) {
      const s = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
      view.mic = s.getAudioTracks()[0];
    } else { view.mic.stop(); view.mic = null; }
  } catch (e) { return toast('마이크를 못 켰어요: ' + e.name); }
  const ss = view.ss;
  if (ss && ss.audioTr) await ss.audioTr.sender.replaceTrack(view.mic).catch(() => {});
  $('#vTalk').classList.toggle('on', !!view.mic);
  setLabel($('#vTalk'), view.mic ? '말하는 중' : '말하기');
}

/** 사진: 카메라 폰에 원본을 요청하고, 늦으면 받은 화면을 캡처한다. */
function takePhoto() {
  if (view.photo) return;
  if (!cmd({ t: 'photo' })) return framePhoto();
  toast('찍는 중…', 1500);
  view.photo = { timer: setTimeout(() => { view.photo = null; framePhoto(); }, 10000) };
}
function photoChunk(buf) {
  const ph = view.photo; if (!ph || !ph.size) return;
  ph.parts.push(buf); ph.got += buf.byteLength;
  if (ph.got >= ph.size) {
    clearTimeout(ph.timer); view.photo = null;
    const blob = new Blob(ph.parts, { type: 'image/jpeg' });
    if (view.s.nightSnap && Night.active) Night.enhanceBlob(blob).then((e) => showPhoto(e || blob, ph.w, ph.h, '카메라 원본' + (e ? ' · 야간 보정' : '')));
    else showPhoto(blob, ph.w, ph.h, '카메라 원본');
  }
}
function framePhoto() {
  const v = $('#viewVideo');
  if (!v.videoWidth) return toast('아직 영상이 없어요');
  const nc = view.s.nightSnap ? Night.frameCanvas() : null; // 야간 보정 중이면 보이는 그대로(보정본)
  const c = document.createElement('canvas'); c.width = nc ? nc.width : v.videoWidth; c.height = nc ? nc.height : v.videoHeight;
  c.getContext('2d').drawImage(nc || v, 0, 0);
  c.toBlob((b) => b && showPhoto(b, c.width, c.height, '받은 화면' + (nc ? ' · 야간 보정' : '')), 'image/jpeg', 0.92);
}
let photoUrl = '';
function showPhoto(blob, w, h, kind) {
  if (photoUrl) URL.revokeObjectURL(photoUrl);
  photoUrl = URL.createObjectURL(blob);
  const d = new Date(); const p = (n) => String(n).padStart(2, '0');
  const fname = 'homecam-' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()) + '.jpg';
  $('#photoImg').src = photoUrl;
  $('#photoSave').href = photoUrl; $('#photoSave').download = fname;
  $('#photoInfo').textContent = kind + ' · ' + w + '×' + h + ' · ' + Math.round(blob.size / 1024) + 'KB · 아이폰은 사진을 길게 눌러 저장해도 돼요';
  const file = new File([blob], fname, { type: 'image/jpeg' });
  const canShare = navigator.canShare && navigator.canShare({ files: [file] });
  $('#photoShare').hidden = !canShare;
  $('#photoShare').onclick = () => navigator.share({ files: [file] }).catch(() => {});
  $('#toast').hidden = true;
  $('#photo').hidden = false;
}

function stopViewer() {
  view.active = false;
  clearTimeout(view.timer); hangup();
  if (view.sig) { view.sig.stop(); view.sig = null; }
  if (view.mic) { view.mic.stop(); view.mic = null; }
  Night.stop();
  $('#viewVideo').srcObject = null;
  $('#vTalk').classList.remove('on'); setLabel($('#vTalk'), '말하기');
  clearTimeout(hudTimer); $('#view').classList.remove('idle');
  $('#view').classList.remove('immersive'); $('#viewRoute').hidden = true; if (fsElement()) (document.exitFullscreen || document.webkitExitFullscreen).call(document).catch(() => {});
  keepAwake(false); show('vhome'); renderCamList();
}

// ---------- 첫 화면 ----------

function checkSecure() {
  if (!window.isSecureContext || !navigator.mediaDevices || !crypto.subtle) { $('#homeErr').textContent = 'https 주소로 열어야 해요 (README 참고).'; return false; }
  $('#homeErr').textContent = ''; return true;
}
function failHome(e) {
  if (cam.active) stopCamera();
  const name = e && e.name;
  $('#homeErr').textContent = name === 'NotAllowedError' ? '카메라·마이크 권한을 허용해 주세요 (브라우저 설정 → 사이트 권한).'
    : name === 'NotFoundError' ? '카메라를 찾지 못했어요.' : (e && e.message) || String(e);
}

/** QR을 폰 기본 카메라로 찍어 열린 링크(#pair=…)면 등록 화면을 띄운다. 주소창에서는 바로 지운다. */
function takePairFromLink() {
  if (!location.hash.startsWith('#pair=')) return;
  const p = parsePair(decodeURIComponent(location.hash));
  history.replaceState(null, '', location.pathname + location.search);
  if (!p) return;
  openPair('HC1.' + p.id + '.' + p.key);
  toast('QR을 읽었어요 · 이름을 정하고 등록하세요', 4000);
}

function init() {
  // https 전용(내 컴퓨터 시험 주소만 예외)
  if (location.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(location.hostname)) { location.replace('https://' + location.host + location.pathname + location.search + location.hash); return; }
  fillForm(loadSettings());
  $('#goCam').onclick = startCamera;
  $('#goView').onclick = openViewer;
  $('#goSettings').onclick = () => show('settings');
  $('#setBack').onclick = () => { readForm(); show('home'); };
  $('#vBack').onclick = () => show('home');
  $('#goPair').onclick = () => openPair();
  $('#pairBack').onclick = () => { stopScan(); if (loadCams().length) { show('vhome'); renderCamList(); } else show('home'); };
  $('#pairAdd').onclick = addCamera;
  $('#scanBtn').hidden = !('BarcodeDetector' in window);
  $('#scanBtn').onclick = scanQR;

  $('#camStop').onclick = stopCamera;
  $('#camPair').onclick = openPairSheet;
  $('#pairClose').onclick = $('#pairDone').onclick = () => { $('#pairSheet').hidden = true; bumpIdle(); };
  $('#pairReset').onclick = resetPair;
  $('#pairCopy').onclick = () => navigator.clipboard.writeText($('#pairText').value).then(() => toast('복사했어요. 내 뷰어 폰에만 붙여 넣으세요.')).catch(() => toast('복사 실패 · 글자를 길게 눌러 복사하세요'));
  $('#camDimBtn').onclick = (e) => { e.stopPropagation(); setDim(true); };
  $('#camFlip').onclick = async () => { cam.facing = cam.facing === 'environment' ? 'user' : 'environment'; try { await openStream(); } catch (e) { toast('전환 실패: ' + e.name); } };
  $('#camMic').onclick = () => {
    cam.micOn = !cam.micOn;
    cam.stream.getAudioTracks().forEach((t) => { t.enabled = cam.micOn; });
    $('#camMic').classList.toggle('on', cam.micOn); toast(cam.micOn ? '집 안 소리 보내는 중' : '집 안 소리 끔');
  };
  $('#dim').onclick = () => { setDim(false); bumpIdle(); };
  document.addEventListener('pointerdown', () => { if (cam.active) bumpIdle(); });

  $('#vStop').onclick = stopViewer;
  $('#vSound').onclick = () => { const v = $('#viewVideo'); v.muted = !v.muted; v.play().catch(() => {}); soundBtn(); };
  $('#vTalk').onclick = toggleTalk;
  $('#vPhoto').onclick = takePhoto;
  $('#vFlip').onclick = () => cmd({ t: 'flip' });
  $('#vTorch').onclick = () => cmd({ t: 'torch', on: !(view.info && view.info.torchOn) });
  $('#vFit').onclick = () => { const c = $('#viewVideo').classList.toggle('contain'); $('#nightCanvas').classList.toggle('contain', c); setLabel($('#vFit'), c ? '채우기' : '맞춤'); toast(c ? '잘림 없이 전체 보기' : '화면 꽉 채우기', 1200); };
  $('#vFull').onclick = toggleFull;
  // 한 번 누르면 버튼 보이기/숨기기, 두 번 빠르게 누르면 전체화면
  let tapT = 0;
  $('#viewVideo').onclick = () => {
    if (tapT) { clearTimeout(tapT); tapT = 0; toggleFull(); return; }
    tapT = setTimeout(() => { tapT = 0; if ($('#view').classList.contains('idle')) wakeHud(); else { clearTimeout(hudTimer); $('#view').classList.add('idle'); } }, 260);
  };
  document.addEventListener('fullscreenchange', fullLabel); document.addEventListener('webkitfullscreenchange', fullLabel);
  $('#view').querySelector('.hud.bottom').addEventListener('pointerdown', wakeHud);
  $('#photoClose').onclick = () => { $('#photo').hidden = true; };

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return;
    if (cam.active) { keepAwake(true); camWatchdog(); }
    if (view.active) { keepAwake(true); if (view.sig) view.sig.kick(); if (!view.gotVideo) redial(0); }
  });
  window.addEventListener('online', () => { if (cam.active) camWatchdog(); if (view.active) { if (view.sig) view.sig.kick(); if (!view.gotVideo) redial(500); } });
  // 앱을 닫을 때 중개 서버 연결을 바로 끊어 상대가 빨리 알게 한다
  window.addEventListener('pagehide', () => { if (cam.sig) cam.sig.stop(); if (view.sig) view.sig.stop(); });

  $('#goDiag').onclick = openDiag;
  $('#appVer').textContent = '앱 버전 ' + APP_VERSION + ' · 두 폰이 같아야 해요';
  $('#camStatus').parentElement.onclick = openDiag;
  $('#viewStatus').parentElement.onclick = (e) => { e.stopPropagation(); openDiag(); };
  $('#diagClose').onclick = () => { $('#diagSheet').hidden = true; };
  $('#diagCopy').onclick = () => navigator.clipboard.writeText($('#diagEnv').textContent + '\n' + diagText()).then(() => toast('복사했어요')).catch(() => toast('길게 눌러 복사하거나 화면을 캡처하세요'));
  $('#diagClear').onclick = () => { diag.length = 0; writeJSON(KEY_DIAG, diag); $('#diagLog').textContent = '(기록 없음)'; };

  takePairFromLink();
  window.addEventListener('hashchange', takePairFromLink);
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
}
init();
