// 야간 보정(뷰어 폰에서만 처리 — 카메라 폰 부담 없음).
// 0.5초마다 받은 영상의 평균 밝기를 64×36으로 재서, 어두우면 밝기(이득)·감마·약한 대비를 부드럽게 올린다.
// 화면 출력은 WebGL 셰이더(움직임이 적은 곳만 직전 프레임과 살짝 섞어 노이즈를 줄임). WebGL이 없으면 CSS 필터로 대신한다.
'use strict';

const Night = (() => {
  /** 세기별 최대 보정치: lin=밝기 배수, gam=감마(어두운 곳을 더 끌어올림), dn=노이즈 줄이기(직전 프레임 섞는 최대 비율). */
  const LEVELS = { low: { lin: 1.8, gam: 1.4, dn: 0.25 }, mid: { lin: 2.6, gam: 1.7, dn: 0.35 }, high: { lin: 3.6, gam: 2.1, dn: 0.45 } };
  const ON_BELOW = 0.25; const OFF_ABOVE = 0.34; // 자동: 이보다 어두우면 켜고, 이보다 밝아지면 끈다(깜빡임 방지 간격)

  const VS = 'attribute vec2 p; varying vec2 uv; void main(){ uv = p * 0.5 + 0.5; gl_Position = vec4(p, 0.0, 1.0); }';
  // 강한 야간(str=1): 정지한 곳은 직전 결과에 계속 쌓아(지수 누적, 약 1/(1-wmax)장 평균) 노이즈를 줄이고,
  // 주변 3×3 블록 평균이 달라진 곳(움직임)은 바로 누적을 끊는다. glob은 화면 전체가 크게 바뀔 때 누적을 약하게.
  const FS = [
    'precision mediump float;',
    'varying vec2 uv; uniform sampler2D cur; uniform sampler2D prev;',
    'uniform float lin; uniform float gam; uniform float con; uniform float dn;',
    'uniform float str; uniform float wmax; uniform float glob; uniform vec2 texel;',
    'vec3 enh(vec2 q){ vec3 e = pow(clamp(texture2D(cur, q).rgb * lin, 0.0, 1.0), vec3(1.0 / gam)); return clamp((e - 0.5) * con + 0.5, 0.0, 1.0); }',
    'void main(){',
    '  vec3 e = enh(uv);',
    '  vec3 p = texture2D(prev, uv).rgb;',
    '  float w;',
    '  if (str > 0.5) {',
    '    vec3 ac = vec3(0.0); vec3 ap = vec3(0.0);',
    '    for (int i = -1; i <= 1; i++) for (int j = -1; j <= 1; j++) { vec2 o = vec2(float(i), float(j)) * texel * 6.0; ac += enh(uv + o); ap += texture2D(prev, uv + o).rgb; }',
    '    float m = abs(dot(ac - ap, vec3(0.2126, 0.7152, 0.0722))) / 9.0;',  // 밝기 차이만 봐서 색 노이즈에 덜 흔들림
    '    w = wmax * glob * (1.0 - smoothstep(0.03, 0.08, m));',
    '  } else {',
    '    w = dn * (1.0 - smoothstep(0.05, 0.15, distance(e, p)));', // 움직인 곳은 섞지 않아 번지지 않게
    '  }',
    '  gl_FragColor = vec4(mix(e, p, w), 1.0);',
    '}',
  ].join('\n');

  /** 캔버스 하나에 보정 셰이더를 준비한다. 실패하면 null(→ CSS 필터로 대체). */
  function makeGL(canvas, keep) {
    const gl = canvas.getContext('webgl', { preserveDrawingBuffer: keep, premultipliedAlpha: false, antialias: false });
    if (!gl) return null;
    const sh = (type, src) => { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null; };
    const vs = sh(gl.VERTEX_SHADER, VS); const fs = sh(gl.FRAGMENT_SHADER, FS);
    if (!vs || !fs) return null;
    const pr = gl.createProgram(); gl.attachShader(pr, vs); gl.attachShader(pr, fs); gl.linkProgram(pr);
    if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) return null;
    gl.useProgram(pr);
    const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(pr, 'p'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const tex = () => { const t = gl.createTexture(); gl.bindTexture(gl.TEXTURE_2D, t); for (const [k, v] of [[gl.TEXTURE_MIN_FILTER, gl.LINEAR], [gl.TEXTURE_MAG_FILTER, gl.LINEAR], [gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE], [gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE]]) gl.texParameteri(gl.TEXTURE_2D, k, v); return t; };
    const cur = tex(); const prev = tex();
    gl.uniform1i(gl.getUniformLocation(pr, 'cur'), 0); gl.uniform1i(gl.getUniformLocation(pr, 'prev'), 1);
    const u = (n) => gl.getUniformLocation(pr, n);
    const U = { lin: u('lin'), gam: u('gam'), con: u('con'), dn: u('dn'), str: u('str'), wmax: u('wmax'), glob: u('glob'), texel: u('texel') };
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
    let w = 0; let h = 0; let fresh = true;
    return {
      /** source(영상·이미지)를 보정해 그린다. temporal=false면 노이즈 줄이기 없이 한 장만. */
      draw(source, sw, sh2, k, temporal) {
        if (sw !== w || sh2 !== h) {
          w = canvas.width = sw; h = canvas.height = sh2; gl.viewport(0, 0, w, h);
          gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, prev);
          gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, w, h, 0, gl.RGB, gl.UNSIGNED_BYTE, null);
          fresh = true;
        }
        gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, cur);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, gl.RGB, gl.UNSIGNED_BYTE, source);
        gl.uniform1f(U.lin, k.lin); gl.uniform1f(U.gam, k.gam); gl.uniform1f(U.con, k.con);
        gl.uniform1f(U.dn, temporal && !fresh ? k.dn : 0);
        gl.uniform1f(U.str, temporal && !fresh && k.str ? 1 : 0); gl.uniform1f(U.wmax, k.wmax || 0); gl.uniform1f(U.glob, k.glob == null ? 1 : k.glob); gl.uniform2f(U.texel, 1 / w, 1 / h);
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
        if (temporal) { gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, prev); gl.copyTexSubImage2D(gl.TEXTURE_2D, 0, 0, 0, 0, 0, w, h); fresh = false; }
      },
    };
  }

  /** 보정 세기 b(0~1)와 단계로 실제 값 계산. */
  function params(b, level, strong, glob) {
    const L = LEVELS[level] || LEVELS.mid;
    // 강한 야간은 노이즈가 줄어드는 만큼 더 밝게(밝기 배수 +30%), 최근 약 10장 누적(wmax 0.9)
    const lin = 1 + b * (L.lin - 1) * (strong ? 1.3 : 1);
    return { lin, gam: 1 + b * (L.gam - 1), con: 1 + 0.12 * b, dn: L.dn * Math.min(1, b * 1.5), str: !!strong, wmax: 0.9, glob: glob == null ? 1 : glob };
  }

  const st = { glob: 1, prevY: null, lastDraw: 0, b: 0, active: false, inLuma: 0, timer: 0, loop: 0, gl: null, glFailed: false, video: null, canvas: null, opts: null, onState: null, sample: null };

  /** 64×36으로 줄여 평균 밝기(0~1)를 잰다. */
  function luma(src) {
    if (!st.sample) { st.sample = document.createElement('canvas'); st.sample.width = 64; st.sample.height = 36; }
    const g = st.sample.getContext('2d', { willReadFrequently: true });
    g.drawImage(src, 0, 0, 64, 36);
    const d = g.getImageData(0, 0, 64, 36).data; let s = 0;
    const y = new Float32Array(d.length / 4);
    for (let i = 0; i < d.length; i += 4) { y[i / 4] = 0.2126 * d[i] + 0.7152 * d[i + 1] + 0.0722 * d[i + 2]; s += y[i / 4]; }
    luma.last = y;
    return s / (d.length / 4) / 255;
  }

  function tick() {
    const v = st.video; const o = st.opts();
    if (!v || !v.videoWidth) return;
    let L; try { L = luma(v); } catch { return; }
    st.inLuma = L;
    // 화면 전체 움직임(0.5초 전과 평균 차이)이 크면 누적을 약하게
    const y = luma.last;
    if (st.prevY && y) { let m = 0; for (let i = 0; i < y.length; i++) m += Math.abs(y[i] - st.prevY[i]); m /= y.length * 255 * Math.max(0.05, L * 4); const g = 1 - Math.min(1, Math.max(0, (m - 0.15) / 0.35)); st.glob += (g - st.glob) * 0.5; }
    st.prevY = y;
    let bd = 0;
    if (o.mode !== 'off') {
      if (o.mode === 'auto') { if (!st.active && L < ON_BELOW) st.active = true; else if (st.active && L > OFF_ABOVE) st.active = false; }
      const want = Math.max(0, Math.min(1, (OFF_ABOVE - L) / 0.30));
      bd = o.mode === 'on' ? Math.max(want, 0.6) : st.active ? Math.max(want, 0.15) : 0;
    }
    st.b += (bd - st.b) * 0.3; // 지수 이동평균 → 1~2초에 걸쳐 부드럽게
    if (bd === 0 && st.b < 0.02) st.b = 0;
    render();
    if (st.onState) st.onState(st.b > 0.05, st.b, L);
  }

  /** 보정이 필요하면 캔버스(WebGL) 또는 CSS 필터로 보여 주고, 아니면 원본 영상 그대로. */
  function render() {
    const v = st.video; const c = st.canvas;
    const on = st.b > 0;
    if (on && !st.gl && !st.glFailed) { st.gl = makeGL(c, true); if (!st.gl) st.glFailed = true; }
    if (on && st.gl) {
      c.hidden = false; v.style.opacity = '0'; v.style.filter = '';
      if (!st.loop) frame();
    } else {
      stopLoop(); c.hidden = true; v.style.opacity = '';
      if (on) { const k = params(st.b, st.opts().level, false); v.style.filter = 'brightness(' + (k.lin * 0.85).toFixed(2) + ') contrast(' + k.con.toFixed(2) + ')'; } // WebGL 없을 때
      else v.style.filter = '';
    }
  }
  function frame() {
    const v = st.video;
    if (!(st.b > 0) || !st.gl) { st.loop = 0; return; }
    const o = st.opts(); const now = performance.now();
    // 처리 상한: 15fps 제한이면 그 사이 프레임은 건너뜀(발열·배터리)
    if (v.videoWidth && !(o.fps15 && now - st.lastDraw < 1000 / 15 - 4)) {
      st.lastDraw = now;
      // 처리 해상도: 보통 가로 최대 1920, 강한 야간은 1280(블록 비교가 무거워서)
      const s = Math.min(1, (o.strong ? 1280 : 1920) / v.videoWidth);
      try { st.gl.draw(v, Math.round(v.videoWidth * s), Math.round(v.videoHeight * s), params(st.b, o.level, o.strong, st.glob), true); } catch { /* 프레임 없음 */ }
    }
    st.loop = v.requestVideoFrameCallback ? v.requestVideoFrameCallback(frame) : requestAnimationFrame(frame);
    st.loopRvfc = !!v.requestVideoFrameCallback;
  }
  function stopLoop() {
    if (!st.loop) return;
    if (st.loopRvfc && st.video.cancelVideoFrameCallback) st.video.cancelVideoFrameCallback(st.loop); else cancelAnimationFrame(st.loop);
    st.loop = 0;
  }

  return {
    /** 영상 받기 시작 때 호출. opts()는 { mode: 'auto'|'on'|'off', level: 'low'|'mid'|'high' }를 돌려준다. */
    start(video, canvas, opts, onState) {
      this.stop();
      Object.assign(st, { video, canvas, opts, onState, b: 0, active: false });
      st.timer = setInterval(tick, 500); tick();
    },
    stop() {
      clearInterval(st.timer); st.timer = 0; stopLoop(); st.b = 0; st.active = false;
      if (st.canvas) st.canvas.hidden = true;
      if (st.video) { st.video.style.opacity = ''; st.video.style.filter = ''; }
      if (st.onState) st.onState(false, 0, st.inLuma);
    },
    /** 설정을 바꾼 뒤 바로 다시 판단. */
    refresh() { if (st.timer) tick(); },
    get active() { return st.b > 0.05; },
    get state() { return { b: st.b, inLuma: st.inLuma, gl: !!st.gl, auto: st.active, glob: st.glob }; },
    /** 지금 화면에 보이는(보정된) 영상의 평균 밝기 — 검사용. */
    outLuma() { return st.b > 0 && st.gl && !st.canvas.hidden ? luma(st.canvas) : luma(st.video); },
    /** 지금 보이는 보정 화면을 그대로 담은 캔버스(사진 저장용). 보정 중이 아니면 null. */
    frameCanvas() { return st.b > 0 && st.gl && !st.canvas.hidden ? st.canvas : null; },
    /** 사진 한 장(카메라 원본)에 지금과 같은 보정을 적용해 JPEG Blob으로. 실패하면 null. */
    async enhanceBlob(blob) {
      if (!(st.b > 0.05)) return null;
      try {
        const bmp = await createImageBitmap(blob);
        const c = document.createElement('canvas'); const g = makeGL(c, true);
        if (!g) return null;
        g.draw(bmp, bmp.width, bmp.height, params(st.b, st.opts().level, st.opts().strong), false);
        return await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.92));
      } catch { return null; }
    },
  };
})();
