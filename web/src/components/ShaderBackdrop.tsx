// Full-screen three.js background: a slowly flowing, domain-warped gradient in the console's warm porcelain palette,
// drawn by one fragment shader on a screen-sized plane. The pointer stirs it (a short trail swirls the field and leaves a
// soft apricot glow). It pauses while the tab is hidden, draws one still frame for prefers-reduced-motion, and removes
// itself when WebGL is missing so the CSS gradient on .fm-backdrop shows instead.
import { useEffect, useRef } from "react";
import { Mesh, OrthographicCamera, PlaneGeometry, Scene, ShaderMaterial, Vector2, WebGLRenderer } from "three";

const SPEED = 0.22;
const TRAIL = 8;      // points in the cursor's wake; keep in step with the shader's TRAIL
const MAX_DPR = 1.5;  // full resolution up to this pixel ratio

const VERT = "varying vec2 vUv; void main() { vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }";

const FRAG = `
precision highp float;
varying vec2 vUv;
uniform float uTime;
uniform vec2 uRes;
#define TRAIL 8
uniform vec2 uTrail[TRAIL];  // cursor wake in 0..1 screen space, newest first
uniform float uEnergy;       // 0 at rest, up to 1 while the cursor moves fast
uniform float uPresence;     // 0 when the cursor is away, 1 over the page
uniform float uClock;        // real seconds, for the ripple

float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  f = f * f * f * (f * (f * 6.0 - 15.0) + 10.0);
  return mix(mix(hash(i), hash(i + vec2(1, 0)), f.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), f.x), f.y);
}
float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 3; i++) { v += a * noise(p); p = p * 2.02 + 17.0; a *= 0.5; }
  return v;
}

void main() {
  vec2 uv = vUv;
  float aspect = uRes.x / uRes.y;
  uv.x *= aspect;

  vec2 warp = vec2(0.0);
  float wake = 0.0;
  for (int i = 0; i < TRAIL; i++) {
    vec2 d = uv - vec2(uTrail[i].x * aspect, uTrail[i].y);
    float fall = exp(-dot(d, d) * 26.0) * (1.0 - float(i) / float(TRAIL));
    warp += vec2(-d.y, d.x) * fall;
    wake += fall;
  }
  uv += warp * uPresence * (0.5 + 1.6 * uEnergy);

  float t = uTime;
  vec2 q = vec2(fbm(uv * 0.85 + vec2(0.0, t * 0.55)), fbm(uv * 0.85 + vec2(5.2, -t * 0.45)));
  vec2 r = vec2(fbm(uv + 2.2 * q + vec2(1.7, 9.2) + t * 0.35), fbm(uv + 2.2 * q + vec2(8.3, 2.8) - t * 0.30));
  float f = fbm(uv * 0.8 + 2.4 * r);

  // canvas #F7F3ED, peach #FCE5D3, champagne #E9DED0, apricot #F8B77D, terracotta #D96B35, dusk blue for depth
  vec3 canvas = vec3(0.969, 0.953, 0.929);
  vec3 peach = vec3(0.988, 0.898, 0.827);
  vec3 champagne = vec3(0.914, 0.871, 0.816);
  vec3 apricot = vec3(0.973, 0.718, 0.490);
  vec3 terra = vec3(0.851, 0.420, 0.208);
  vec3 dusk = vec3(0.780, 0.820, 0.860);
  vec3 col = mix(canvas, peach, smoothstep(0.2, 0.7, f));
  col = mix(col, champagne, smoothstep(0.35, 1.0, length(q)) * 0.5);
  col = mix(col, dusk, smoothstep(0.5, 0.95, q.y) * 0.55);
  col = mix(col, apricot, smoothstep(0.42, 0.9, r.x) * 0.75);
  col = mix(col, terra, smoothstep(0.55, 0.95, f * r.y * 1.6) * 0.5);

  vec2 hd = vUv - uTrail[0];
  hd.x *= aspect;
  float dist = length(hd);
  float ring = (0.5 + 0.5 * sin(dist * 70.0 - uClock * 5.0)) * exp(-dist * 10.0) * smoothstep(0.0, 0.04, dist);
  col = mix(col, apricot, exp(-dist * dist * 70.0) * 0.30 * uPresence);
  col = mix(col, terra, ring * (0.06 + 0.12 * uEnergy) * uPresence);
  col = mix(col, apricot, min(wake, 1.5) * uEnergy * 0.10 * uPresence);
  // soft warm vignette, then +-0.5/255 triangular noise so the 8-bit output has no visible bands
  col = mix(col, champagne * 0.92, 0.35 * smoothstep(0.55, 1.25, length(vUv - 0.5) * 1.6));
  float d = hash(gl_FragCoord.xy + fract(uTime) * 61.0) + hash(gl_FragCoord.xy * 1.37 + 7.0) - 1.0;
  col += d / 255.0;
  gl_FragColor = vec4(col, 1.0);
}`;

export default function ShaderBackdrop() {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = host.current;
    if (!el) return undefined;
    let renderer: WebGLRenderer;
    try {
      renderer = new WebGLRenderer({ antialias: false, alpha: false, powerPreference: "default" });
    } catch {
      return undefined;   // no WebGL: the CSS gradient stays
    }
    const canvas = renderer.domElement;
    canvas.style.cssText = "position:absolute;inset:0;width:100%;height:100%;display:block";
    el.appendChild(canvas);

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    const trail = Array.from({ length: TRAIL }, () => new Vector2(0.5, 0.5));
    const uniforms = {
      uTime: { value: 0 }, uRes: { value: new Vector2(1, 1) }, uTrail: { value: trail },
      uEnergy: { value: 0 }, uPresence: { value: 0 }, uClock: { value: 0 },
    };
    const scene = new Scene();
    const camera = new OrthographicCamera(-1, 1, 1, -1, 0, 1);
    const geometry = new PlaneGeometry(2, 2);
    const material = new ShaderMaterial({ vertexShader: VERT, fragmentShader: FRAG, uniforms });
    scene.add(new Mesh(geometry, material));

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
      const w = Math.max(2, Math.floor(window.innerWidth * dpr));
      const h = Math.max(2, Math.floor(window.innerHeight * dpr));
      renderer.setPixelRatio(1);
      renderer.setSize(w, h, false);
      uniforms.uRes.value.set(w, h);
    };
    resize();
    window.addEventListener("resize", resize);

    // The canvas sits behind the UI, so the pointer is read on the window (y up, 0..1).
    const target = new Vector2(0.5, 0.5);
    let seen = false;
    let present = 0;
    const onMove = (e: PointerEvent) => {
      target.set(e.clientX / window.innerWidth, 1 - e.clientY / window.innerHeight);
      if (!seen) { trail.forEach((p) => p.copy(target)); seen = true; }   // no sweep in from the centre
      present = 1;
    };
    const onLeave = (e: PointerEvent) => { if (!e.relatedTarget) present = 0; };
    const onUp = (e: PointerEvent) => { if (e.pointerType !== "mouse") present = 0; };
    const onBlur = () => { present = 0; };
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerdown", onMove, { passive: true });
    window.addEventListener("pointerup", onUp, { passive: true });
    document.addEventListener("pointerout", onLeave);
    window.addEventListener("blur", onBlur);

    let raf = 0;
    let last = performance.now();
    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      uniforms.uTime.value += dt * SPEED;
      uniforms.uClock.value += dt;
      last = now;
      // The head eases toward the cursor and each point follows the one ahead, so a quick flick leaves a tail.
      const px = trail[0].x, py = trail[0].y;
      trail[0].lerp(target, 1 - Math.exp(-dt * 14));
      for (let i = 1; i < TRAIL; i++) trail[i].lerp(trail[i - 1], 1 - Math.exp(-dt * 11));
      const speed = dt > 0 ? Math.hypot(trail[0].x - px, trail[0].y - py) / dt : 0;
      uniforms.uEnergy.value += (Math.min(1, speed * 0.9) - uniforms.uEnergy.value) * (1 - Math.exp(-dt * 6));
      uniforms.uPresence.value += (present - uniforms.uPresence.value) * (1 - Math.exp(-dt * 4));
      renderer.render(scene, camera);
      raf = reduced.matches || document.hidden ? 0 : requestAnimationFrame(frame);
    };
    const start = () => {
      cancelAnimationFrame(raf);
      last = performance.now();
      raf = requestAnimationFrame(frame);
    };
    start();
    document.addEventListener("visibilitychange", start);
    reduced.addEventListener?.("change", start);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", start);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onMove);
      window.removeEventListener("pointerup", onUp);
      document.removeEventListener("pointerout", onLeave);
      window.removeEventListener("blur", onBlur);
      reduced.removeEventListener?.("change", start);
      geometry.dispose();
      material.dispose();
      renderer.dispose();
      canvas.remove();
    };
  }, []);

  return <div ref={host} className="absolute inset-0" aria-hidden="true" />;
}
