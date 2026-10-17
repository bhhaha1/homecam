// QR 코드 그리기(외부 라이브러리 없이). 바이트 모드, 오류 정정 M, 버전 1~10(최대 213바이트).
// 알고리즘은 ISO/IEC 18004 표준대로: 데이터 → RS 오류정정 → 블록 섞기 → 배치 → 마스크 → 형식·버전 정보.
'use strict';

const QR = (() => {
  // 버전별 [전체 코드워드 수, 블록당 EC 코드워드 수, 블록 수] (오류 정정 M)
  const TABLE = [null, [26, 10, 1], [44, 16, 1], [70, 26, 1], [100, 18, 2], [134, 24, 2], [172, 16, 4], [196, 18, 4], [242, 22, 4], [292, 22, 5], [346, 26, 5]];
  const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

  // GF(256) 곱셈 (원시 다항식 0x11D)
  function gmul(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; }
    return z & 0xff;
  }
  function rsDivisor(deg) {
    const r = new Array(deg).fill(0); r[deg - 1] = 1; let root = 1;
    for (let i = 0; i < deg; i++) {
      for (let j = 0; j < r.length; j++) { r[j] = gmul(r[j], root); if (j + 1 < r.length) r[j] ^= r[j + 1]; }
      root = gmul(root, 0x02);
    }
    return r;
  }
  function rsRemainder(data, div) {
    const r = div.map(() => 0);
    for (const b of data) {
      const f = b ^ r.shift(); r.push(0);
      div.forEach((c, i) => { r[i] ^= gmul(c, f); });
    }
    return r;
  }

  /** 텍스트(UTF-8)를 QR 모듈 격자로 만든다. */
  function encode(text) {
    const bytes = [...new TextEncoder().encode(text)];
    let ver = 1;
    for (; ver <= 10; ver++) {
      const [total, ec, nb] = TABLE[ver];
      const capBits = (total - ec * nb) * 8;
      if (4 + (ver < 10 ? 8 : 16) + bytes.length * 8 <= capBits) break;
    }
    if (ver > 10) throw new Error('QR에 넣기엔 너무 길어요');
    const [total, ecLen, numBlocks] = TABLE[ver];
    const dataCap = total - ecLen * numBlocks;

    // 1) 비트열: 모드(0100) + 길이 + 데이터 + 종결자 + 채움
    const bits = [];
    const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
    put(4, 4); put(bytes.length, ver < 10 ? 8 : 16); bytes.forEach((b) => put(b, 8));
    put(0, Math.min(4, dataCap * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));
    for (let p = 0; data.length < dataCap; p ^= 1) data.push(p ? 0x11 : 0xec);

    // 2) 블록별 RS 오류정정 후 섞기
    const shortLen = Math.floor(total / numBlocks);
    const numShort = numBlocks - (total % numBlocks);
    const div = rsDivisor(ecLen);
    const blocks = [];
    for (let i = 0, k = 0; i < numBlocks; i++) {
      const d = data.slice(k, k + shortLen - ecLen + (i < numShort ? 0 : 1)); k += d.length;
      const e = rsRemainder(d, div);
      if (i < numShort) d.push(0);
      blocks.push(d.concat(e));
    }
    const cw = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach((b, j) => { if (i !== shortLen - ecLen || j >= numShort) cw.push(b[i]); });
    }

    // 3) 기능 패턴
    const size = ver * 4 + 17;
    const mod = Array.from({ length: size }, () => new Array(size).fill(false));
    const fn = Array.from({ length: size }, () => new Array(size).fill(false));
    const set = (x, y, v) => { mod[y][x] = v; fn[y][x] = true; };
    for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    const finder = (cx, cy) => {
      for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx; const y = cy + dy; const d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
    };
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
    const al = ALIGN[ver]; const last = al.length - 1;
    al.forEach((ay, i) => al.forEach((ax, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }));
    const drawFormat = (mask) => {
      const d = (0 << 3) | mask; // M = 00
      let r = d; for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
      const b = ((d << 10) | r) ^ 0x5412; const bit = (i) => ((b >>> i) & 1) === 1;
      for (let i = 0; i <= 5; i++) set(8, i, bit(i));
      set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
      for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
      set(8, size - 8, true);
    };
    drawFormat(0); // 자리 예약
    if (ver >= 7) {
      let r = ver; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
      const b = (ver << 12) | r;
      for (let i = 0; i < 18; i++) { const v = ((b >>> i) & 1) === 1; const a = size - 11 + (i % 3); const c = Math.floor(i / 3); set(a, c, v); set(c, a, v); }
    }

    // 4) 데이터 지그재그 배치
    let n = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
        const x = right - j; const up = ((right + 1) & 2) === 0; const y = up ? size - 1 - vert : vert;
        if (!fn[y][x] && n < cw.length * 8) { mod[y][x] = ((cw[n >>> 3] >>> (7 - (n & 7))) & 1) === 1; n++; }
      }
    }

    // 5) 마스크 8개 중 벌점이 가장 낮은 것
    const MASKS = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
      (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
      (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0];
    const applyMask = (m) => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && MASKS[m](x, y)) mod[y][x] = !mod[y][x]; };
    const penalty = () => {
      let p = 0; let dark = 0;
      for (let y = 0; y < size; y++) {
        let rx = 1; let ry = 1;
        for (let x = 0; x < size; x++) {
          if (mod[y][x]) dark++;
          if (x > 0) {
            if (mod[y][x] === mod[y][x - 1]) { rx++; if (rx === 5) p += 3; else if (rx > 5) p++; } else rx = 1;
            if (mod[x][y] === mod[x - 1][y]) { ry++; if (ry === 5) p += 3; else if (ry > 5) p++; } else ry = 1;
          }
          if (x > 0 && y > 0 && mod[y][x] === mod[y][x - 1] && mod[y][x] === mod[y - 1][x] && mod[y][x] === mod[y - 1][x - 1]) p += 3;
        }
      }
      return p + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
    };
    let best = 0; let bestP = Infinity;
    for (let m = 0; m < 8; m++) {
      applyMask(m); drawFormat(m); const p = penalty(); if (p < bestP) { bestP = p; best = m; } applyMask(m);
    }
    applyMask(best); drawFormat(best);
    return { size, version: ver, get: (x, y) => mod[y][x] };
  }

  /** 캔버스에 그린다(여백 4칸 포함, 흰 바탕). */
  function draw(canvas, text, px = 6) {
    const q = encode(text); const s = (q.size + 8) * px;
    canvas.width = canvas.height = s;
    const g = canvas.getContext('2d');
    g.fillStyle = '#fff'; g.fillRect(0, 0, s, s); g.fillStyle = '#000';
    for (let y = 0; y < q.size; y++) for (let x = 0; x < q.size; x++) if (q.get(x, y)) g.fillRect((x + 4) * px, (y + 4) * px, px, px);
    return q;
  }
  return { encode, draw };
})();
