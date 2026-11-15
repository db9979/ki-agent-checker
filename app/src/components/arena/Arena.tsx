import { Stars } from "@react-three/drei";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Bloom, ChromaticAberration, EffectComposer, Vignette } from "@react-three/postprocessing";
import { BlendFunction, type ChromaticAberrationEffect } from "postprocessing";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import type { Attack } from "../../lib/runStore";

/**
 * 3D-Arena: Der Ziel-Agent ist ein leuchtender Kern hinter einem Schutzschild.
 * Jeder Angriff fliegt als Lichtgeschoss heran. Abgewehrt prallt er am Schild ab,
 * ein Durchbruch reißt das Schild auf, löst eine Schockwelle aus und lässt
 * missbrauchte Tools und Datenquellen rot aufglühen.
 */

const SHIELD_R = 2.2;
const ORBIT_R = 3.6;
const CYAN = new THREE.Color("#22d3ee");
const RED = new THREE.Color("#f43f5e");
const VIOLET = new THREE.Color("#a78bfa");

const MODULE_COLOR: Record<string, string> = {
  prompt_injection: "#f43f5e",
  jailbreak: "#fb923c",
  system_prompt_leak: "#f59e0b",
  data_exfiltration: "#e879f9",
  excessive_agency: "#ef4444",
  cross_account: "#c084fc",
};

export const SATELLITES = [
  { id: "prompt", label: "System-Prompt" },
  { id: "customers", label: "Kundendaten" },
  { id: "lookup_order", label: "lookup_order" },
  { id: "refund", label: "refund" },
  { id: "send_email", label: "send_email" },
] as const;

type SatId = (typeof SATELLITES)[number]["id"];

/** Welche Teile ein erfolgreicher Angriff des Moduls trifft. */
function targetsFor(a: Attack): SatId[] {
  const tool = a.messages.find((m) => m.tool_call)?.tool_call?.name;
  switch (a.module) {
    case "system_prompt_leak":
      return ["prompt"];
    case "data_exfiltration":
      return ["lookup_order", "customers"];
    case "cross_account":
      return ["customers"];
    case "excessive_agency":
      return tool === "send_email" ? ["send_email"] : ["refund", "send_email"];
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// Gemeinsamer Zustand der Szene (veränderlich, außerhalb von React)

interface Projectile {
  id: string;
  color: THREE.Color;
  start: THREE.Vector3;
  impact: THREE.Vector3;
  pos: THREE.Vector3;
  phase: "fly" | "wait" | "bounce" | "pierce" | "done";
  t: number;
  outcome?: boolean;
  targets: SatId[];
}

interface Spark {
  pos: THREE.Vector3;
  vel: THREE.Vector3;
  life: number;
  color: THREE.Color;
}

interface Fx {
  projectiles: Projectile[];
  sparks: Spark[];
  waves: { t: number; color: THREE.Color }[];
  shieldFlash: number;
  shieldColor: THREE.Color;
  breach: number;
  shake: number;
  satHeat: Record<string, number>;
  beams: { sat: SatId; life: number }[];
}

function newFx(): Fx {
  return {
    projectiles: [],
    sparks: [],
    waves: [],
    shieldFlash: 0,
    shieldColor: CYAN.clone(),
    breach: 0,
    shake: 0,
    satHeat: {},
    beams: [],
  };
}

function randomStart(seed: number): THREE.Vector3 {
  const a = seed * 2.399963; // goldener Winkel: Angriffe kommen aus wechselnden Richtungen
  const y = ((seed * 0.618) % 1) * 2.4 - 1.2;
  return new THREE.Vector3(Math.cos(a) * 9, y * 2, Math.sin(a) * 9);
}

function burst(fx: Fx, at: THREE.Vector3, color: THREE.Color, count: number, speed: number) {
  for (let i = 0; i < count; i++) {
    const dir = new THREE.Vector3().randomDirection();
    // Funken bevorzugt nach außen, weg vom Kern
    dir.add(at.clone().normalize().multiplyScalar(0.8)).normalize();
    fx.sparks.push({ pos: at.clone(), vel: dir.multiplyScalar(speed * (0.4 + Math.random())), life: 1, color });
  }
  if (fx.sparks.length > 600) fx.sparks.splice(0, fx.sparks.length - 600);
}

// ---------------------------------------------------------------------------
// Bausteine

function Core({ fx }: { fx: React.RefObject<Fx> }) {
  const shell = useRef<THREE.Mesh>(null);
  const inner = useRef<THREE.Mesh>(null);
  const shellMat = useRef<THREE.MeshBasicMaterial>(null);
  const innerMat = useRef<THREE.MeshStandardMaterial>(null);
  const color = useMemo(() => new THREE.Color(), []);

  useFrame((state, dt) => {
    const f = fx.current!;
    const t = state.clock.elapsedTime;
    color.copy(CYAN).lerp(RED, Math.min(1, f.breach));
    if (shell.current) {
      shell.current.rotation.x += dt * 0.4;
      shell.current.rotation.y += dt * 0.6;
      // Glitch: bei Durchbruch springt der Kern ruckartig
      const g = f.breach > 0.3 ? (Math.random() - 0.5) * 0.25 * f.breach : 0;
      shell.current.position.set(g, g * 0.5, -g);
    }
    if (inner.current) inner.current.scale.setScalar(0.55 + Math.sin(t * 3) * 0.05 + f.breach * 0.25);
    shellMat.current?.color.copy(color);
    if (innerMat.current) {
      innerMat.current.emissive.copy(color);
      innerMat.current.emissiveIntensity = 2.2 + Math.sin(t * 4) * 0.4 + f.breach * 3;
    }
  });

  return (
    <group>
      <mesh ref={shell}>
        <icosahedronGeometry args={[0.95, 1]} />
        <meshBasicMaterial ref={shellMat} wireframe transparent opacity={0.9} toneMapped={false} />
      </mesh>
      <mesh ref={inner}>
        <sphereGeometry args={[1, 32, 32]} />
        <meshStandardMaterial ref={innerMat} color="#04121a" toneMapped={false} />
      </mesh>
      <pointLight color="#22d3ee" intensity={8} distance={8} />
    </group>
  );
}

function Shield({ fx }: { fx: React.RefObject<Fx> }) {
  const wire = useRef<THREE.MeshBasicMaterial>(null);
  const glow = useRef<THREE.MeshBasicMaterial>(null);
  const mesh = useRef<THREE.Mesh>(null);

  useFrame((state, dt) => {
    const f = fx.current!;
    f.shieldFlash = Math.max(0, f.shieldFlash - dt * 1.8);
    const flicker = f.breach > 0.2 ? (Math.random() > 0.5 ? 0.4 : 1) : 1;
    if (mesh.current) mesh.current.rotation.y -= dt * 0.08;
    if (wire.current) {
      wire.current.color.copy(f.shieldColor);
      wire.current.opacity = (0.12 + f.shieldFlash * 0.7 + Math.sin(state.clock.elapsedTime * 2) * 0.03) * flicker;
    }
    if (glow.current) {
      glow.current.color.copy(f.shieldColor);
      glow.current.opacity = (0.04 + f.shieldFlash * 0.25) * flicker;
    }
  });

  return (
    <group>
      <mesh ref={mesh}>
        <icosahedronGeometry args={[SHIELD_R, 3]} />
        <meshBasicMaterial ref={wire} wireframe transparent toneMapped={false} depthWrite={false} />
      </mesh>
      <mesh>
        <sphereGeometry args={[SHIELD_R * 0.995, 48, 48]} />
        <meshBasicMaterial
          ref={glow}
          transparent
          side={THREE.BackSide}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}

function satPosition(i: number, t: number, out = new THREE.Vector3()) {
  const a = t * 0.18 + (i / SATELLITES.length) * Math.PI * 2;
  // Geneigte Umlaufbahn
  return out.set(Math.cos(a) * ORBIT_R, Math.sin(a) * ORBIT_R * 0.28, Math.sin(a) * ORBIT_R);
}

function Satellites({ fx, labels }: { fx: React.RefObject<Fx>; labels: React.RefObject<(HTMLDivElement | null)[]> }) {
  const groups = useRef<(THREE.Group | null)[]>([]);
  const mats = useRef<(THREE.MeshStandardMaterial | null)[]>([]);
  const proj = useMemo(() => new THREE.Vector3(), []);
  const beamGeo = useMemo(
    () => new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3()]),
    [],
  );
  const beamLines = useRef<(THREE.Line | null)[]>([]);
  const tmp = useMemo(() => new THREE.Vector3(), []);
  const beamGeos = useMemo(() => SATELLITES.map(() => beamGeo.clone()), [beamGeo]);
  const beamObjs = useMemo(
    () =>
      beamGeos.map(
        (g) => new THREE.Line(g, new THREE.LineBasicMaterial({ color: RED, transparent: true, toneMapped: false })),
      ),
    [beamGeos],
  );

  useFrame((state, dt) => {
    const f = fx.current!;
    const t = state.clock.elapsedTime;
    SATELLITES.forEach((s, i) => {
      const heat = Math.max(0, (f.satHeat[s.id] ?? 0) - dt * 0.12);
      f.satHeat[s.id] = heat;
      const g = groups.current[i];
      if (g) {
        satPosition(i, t, g.position);
        g.rotation.x += dt * (0.6 + heat * 4);
        g.rotation.y += dt * (0.9 + heat * 4);
        g.scale.setScalar(1 + heat * 0.5 + (heat > 0 ? Math.sin(t * 12) * 0.08 * heat : 0));
      }
      const m = mats.current[i];
      if (m) {
        m.emissive.copy(VIOLET).lerp(RED, Math.min(1, heat * 1.5));
        m.emissiveIntensity = 1.2 + heat * 4;
      }
      // Beschriftung als HTML über dem Canvas: Position per Projektion, ohne eigenen React-Root
      const label = labels.current[i];
      if (label && g) {
        label.dataset.hot = heat > 0.15 ? "1" : "0";
        proj
          .copy(g.position)
          .setY(g.position.y + 0.42)
          .project(state.camera);
        const x = ((proj.x + 1) / 2) * state.size.width;
        const y = ((1 - proj.y) / 2) * state.size.height;
        label.style.transform = `translate(-50%, -100%) translate(${x.toFixed(1)}px, ${y.toFixed(1)}px)`;
        // Hinter dem Schild liegende Satelliten gedimmt beschriften
        const behind = state.camera.position.distanceTo(g.position) > state.camera.position.length();
        label.style.opacity = proj.z >= 1 ? "0" : behind ? "0.35" : "1";
      }
      // Strahl vom Kern zum getroffenen Satelliten
      const line = beamLines.current[i];
      if (line) {
        const visible = heat > 0.05;
        line.visible = visible;
        if (visible && g) {
          const pos = beamGeos[i].attributes.position as THREE.BufferAttribute;
          tmp.copy(g.position);
          pos.setXYZ(0, 0, 0, 0);
          pos.setXYZ(1, tmp.x, tmp.y, tmp.z);
          pos.needsUpdate = true;
          (line.material as THREE.LineBasicMaterial).opacity = Math.min(1, heat) * (0.6 + Math.random() * 0.4);
        }
      }
    });
  });

  return (
    <group>
      {/* Umlaufbahn */}
      <mesh rotation={[Math.PI / 2 - 0.27, 0, 0]}>
        <torusGeometry args={[ORBIT_R, 0.006, 8, 160]} />
        <meshBasicMaterial color="#a78bfa" transparent opacity={0.35} toneMapped={false} />
      </mesh>
      {SATELLITES.map((s, i) => (
        <group key={s.id}>
          <group
            ref={(el) => {
              groups.current[i] = el;
            }}
          >
            <mesh>
              <octahedronGeometry args={[0.2, 0]} />
              <meshStandardMaterial
                ref={(el) => {
                  mats.current[i] = el;
                }}
                color="#120d24"
                toneMapped={false}
              />
            </mesh>
          </group>
          <primitive
            object={beamObjs[i]}
            ref={(el: THREE.Line | null) => {
              beamLines.current[i] = el;
            }}
          />
        </group>
      ))}
    </group>
  );
}

const POOL = 16;

function Projectiles({ fx }: { fx: React.RefObject<Fx> }) {
  const heads = useRef<(THREE.Mesh | null)[]>([]);
  const tails = useRef<(THREE.Mesh | null)[]>([]);
  const dir = useMemo(() => new THREE.Vector3(), []);
  const up = useMemo(() => new THREE.Vector3(0, 1, 0), []);

  useFrame((_, dt) => {
    const f = fx.current!;
    for (const p of f.projectiles) {
      const prev = p.pos.clone();
      if (p.phase === "fly") {
        p.t = Math.min(1, p.t + dt * 0.9);
        const e = 1 - Math.pow(1 - p.t, 2);
        p.pos.lerpVectors(p.start, p.impact, e);
        if (p.t >= 1) {
          p.phase = p.outcome === undefined ? "wait" : p.outcome ? "pierce" : "bounce";
          p.t = 0;
          burst(f, p.impact, p.color, 18, 1.2);
          f.shieldFlash = Math.max(f.shieldFlash, 0.5);
        }
      } else if (p.phase === "wait") {
        // Geschoss drückt gegen das Schild, bis der Richter entschieden hat
        p.pos.copy(p.impact).multiplyScalar(1 + Math.sin(p.t * 30) * 0.01);
        p.t += dt;
        if (Math.random() < dt * 20) burst(f, p.impact, p.color, 2, 0.6);
        if (p.outcome !== undefined) {
          p.phase = p.outcome ? "pierce" : "bounce";
          p.t = 0;
        }
      } else if (p.phase === "bounce") {
        if (p.t === 0) {
          burst(f, p.impact, CYAN, 70, 2.6);
          f.shieldFlash = 1;
          f.shieldColor.copy(CYAN);
        }
        p.t += dt * 1.6;
        p.pos.copy(p.impact).multiplyScalar(1 + p.t * 2.5);
        if (p.t >= 1) p.phase = "done";
      } else if (p.phase === "pierce") {
        if (p.t === 0) {
          burst(f, p.impact, RED, 90, 3);
          f.shieldColor.copy(RED);
          f.shieldFlash = 1;
        }
        p.t = Math.min(1, p.t + dt * 2.2);
        p.pos.copy(p.impact).multiplyScalar(1 - p.t);
        if (p.t >= 1) {
          p.phase = "done";
          f.breach = 1;
          f.shake = 1;
          f.waves.push({ t: 0, color: RED.clone() });
          burst(f, new THREE.Vector3(0, 0, 0), RED, 120, 4);
          for (const s of p.targets) {
            f.satHeat[s] = 1.6;
          }
        }
      }
      p.start.copy(prev);
    }
    f.projectiles = f.projectiles.filter((p) => p.phase !== "done");

    for (let i = 0; i < POOL; i++) {
      const p = f.projectiles[i];
      const head = heads.current[i];
      const tail = tails.current[i];
      if (!head || !tail) continue;
      head.visible = tail.visible = !!p;
      if (!p) continue;
      head.position.copy(p.pos);
      (head.material as THREE.MeshBasicMaterial).color.copy(p.color);
      (tail.material as THREE.MeshBasicMaterial).color.copy(p.color);
      // Schweif entgegen der Flugrichtung
      dir.copy(p.pos).sub(p.start);
      const len = Math.max(0.15, Math.min(1.4, dir.length() * 18));
      dir.normalize();
      tail.position.copy(p.pos).addScaledVector(dir, -len / 2);
      tail.scale.set(1, len, 1);
      if (dir.lengthSq() > 0) tail.quaternion.setFromUnitVectors(up, dir);
    }
  });

  return (
    <group>
      {Array.from({ length: POOL }, (_, i) => (
        <group key={i}>
          <mesh
            ref={(el) => {
              heads.current[i] = el;
            }}
            visible={false}
          >
            <sphereGeometry args={[0.09, 16, 16]} />
            <meshBasicMaterial toneMapped={false} />
          </mesh>
          <mesh
            ref={(el) => {
              tails.current[i] = el;
            }}
            visible={false}
          >
            <cylinderGeometry args={[0.005, 0.06, 1, 8, 1, true]} />
            <meshBasicMaterial
              transparent
              opacity={0.7}
              toneMapped={false}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </mesh>
        </group>
      ))}
    </group>
  );
}

const SPARK_MAX = 600;

function Sparks({ fx }: { fx: React.RefObject<Fx> }) {
  const geo = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(new Float32Array(SPARK_MAX * 3), 3));
    g.setAttribute("color", new THREE.BufferAttribute(new Float32Array(SPARK_MAX * 3), 3));
    return g;
  }, []);

  useFrame((_, dt) => {
    const f = fx.current!;
    const pos = geo.attributes.position as THREE.BufferAttribute;
    const col = geo.attributes.color as THREE.BufferAttribute;
    f.sparks = f.sparks.filter((s) => (s.life -= dt * 1.1) > 0);
    f.sparks.forEach((s, i) => {
      s.vel.multiplyScalar(1 - dt * 1.5);
      s.pos.addScaledVector(s.vel, dt);
      pos.setXYZ(i, s.pos.x, s.pos.y, s.pos.z);
      col.setXYZ(i, s.color.r * s.life * 2, s.color.g * s.life * 2, s.color.b * s.life * 2);
    });
    geo.setDrawRange(0, f.sparks.length);
    pos.needsUpdate = true;
    col.needsUpdate = true;
  });

  return (
    <points geometry={geo}>
      <pointsMaterial
        size={0.06}
        vertexColors
        transparent
        blending={THREE.AdditiveBlending}
        depthWrite={false}
        toneMapped={false}
      />
    </points>
  );
}

function Shockwaves({ fx }: { fx: React.RefObject<Fx> }) {
  const rings = useRef<(THREE.Mesh | null)[]>([]);
  useFrame((_, dt) => {
    const f = fx.current!;
    f.waves = f.waves.filter((w) => (w.t += dt * 0.7) < 1);
    rings.current.forEach((r, i) => {
      if (!r) return;
      const w = f.waves[i];
      r.visible = !!w;
      if (!w) return;
      r.scale.setScalar(0.5 + w.t * 9);
      const m = r.material as THREE.MeshBasicMaterial;
      m.color.copy(w.color);
      m.opacity = (1 - w.t) * 0.9;
    });
  });
  return (
    <group rotation={[-Math.PI / 2, 0, 0]}>
      {[0, 1, 2, 3].map((i) => (
        <mesh
          key={i}
          ref={(el) => {
            rings.current[i] = el;
          }}
          visible={false}
        >
          <ringGeometry args={[0.95, 1, 96]} />
          <meshBasicMaterial
            transparent
            side={THREE.DoubleSide}
            toneMapped={false}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
      ))}
    </group>
  );
}

function PolarGrid() {
  return (
    <group position={[0, -2.6, 0]}>
      <polarGridHelper args={[9, 16, 8, 96, "#1e3a5f", "#13243d"]} />
    </group>
  );
}

/** Kamera kreist langsam und wackelt bei Durchbrüchen. */
function Rig({ fx }: { fx: React.RefObject<Fx> }) {
  const { camera } = useThree();
  useFrame((state, dt) => {
    const f = fx.current!;
    f.shake = Math.max(0, f.shake - dt * 1.6);
    f.breach = Math.max(0, f.breach - dt * 0.35);
    const t = state.clock.elapsedTime * 0.07;
    // Schmale Bühnen etwas weiter weg, damit die Umlaufbahn nicht abgeschnitten wird
    const aspect = state.size.width / Math.max(1, state.size.height);
    const r = 8.4 + Math.max(0, 1.6 - aspect) * 2.6 - f.shake * 0.8;
    camera.position.set(
      Math.sin(t) * r + (Math.random() - 0.5) * f.shake * 0.35,
      2.4 + Math.sin(t * 1.7) * 0.4 + (Math.random() - 0.5) * f.shake * 0.35,
      Math.cos(t) * r,
    );
    camera.lookAt(0, 0, 0);
  });
  return null;
}

function Effects({ fx }: { fx: React.RefObject<Fx> }) {
  const chroma = useRef<ChromaticAberrationEffect>(null);
  const offset = useMemo(() => new THREE.Vector2(0.0006, 0.0006), []);
  useFrame(() => {
    const b = fx.current!.breach;
    chroma.current?.offset.set(0.0006 + b * 0.006, 0.0006 + b * 0.004);
  });
  return (
    <EffectComposer>
      <Bloom mipmapBlur intensity={1.4} luminanceThreshold={0.12} luminanceSmoothing={0.3} radius={0.75} />
      <ChromaticAberration
        ref={chroma}
        offset={offset}
        blendFunction={BlendFunction.NORMAL}
        radialModulation={false}
        modulationOffset={0}
      />
      <Vignette eskil={false} offset={0.2} darkness={0.85} />
    </EffectComposer>
  );
}

/** Übersetzt den Laufzustand in Ereignisse der Szene. */
function Director({ fx, attacks, runId }: { fx: React.RefObject<Fx>; attacks: Attack[]; runId: string | null }) {
  const known = useRef(new Map<string, Projectile>());
  const count = useRef(0);

  useEffect(() => {
    known.current.clear();
    count.current = 0;
    Object.assign(fx.current!, newFx());
  }, [runId, fx]);

  useEffect(() => {
    const f = fx.current!;
    for (const a of attacks) {
      let p = known.current.get(a.id);
      if (!p) {
        const start = randomStart(count.current++);
        p = {
          id: a.id,
          color: new THREE.Color(MODULE_COLOR[a.module] ?? "#f43f5e"),
          start: start.clone(),
          impact: start.clone().normalize().multiplyScalar(SHIELD_R),
          pos: start.clone(),
          phase: "fly",
          t: 0,
          targets: [],
        };
        known.current.set(a.id, p);
        if (f.projectiles.length < POOL) f.projectiles.push(p);
      }
      if (a.success !== undefined && p.outcome === undefined) {
        p.outcome = a.success;
        p.targets = a.success ? targetsFor(a) : [];
      }
    }
  }, [attacks, fx]);

  return null;
}

export default function Arena({
  attacks,
  runId,
  quality,
}: {
  attacks: Attack[];
  runId: string | null;
  quality: "voll" | "sparsam";
}) {
  const fx = useRef<Fx>(newFx());
  const labels = useRef<(HTMLDivElement | null)[]>([]);
  const full = quality === "voll";
  return (
    <div className="relative h-full w-full">
      <Canvas
        dpr={full ? [1, 2] : 1}
        gl={{ antialias: !full, powerPreference: "high-performance" }}
        camera={{ fov: 45, position: [0, 2.6, 9.6] }}
        style={{ background: "transparent" }}
      >
        <ambientLight intensity={0.25} />
        <Stars radius={60} depth={30} count={full ? 3500 : 700} factor={3} saturation={0} fade speed={full ? 0.8 : 0} />
        <PolarGrid />
        <Core fx={fx} />
        <Shield fx={fx} />
        <Satellites fx={fx} labels={labels} />
        <Projectiles fx={fx} />
        <Sparks fx={fx} />
        <Shockwaves fx={fx} />
        <Rig fx={fx} />
        <Director fx={fx} attacks={attacks} runId={runId} />
        {full && <Effects fx={fx} />}
      </Canvas>
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {SATELLITES.map((s, i) => (
          <div
            key={s.id}
            ref={(el) => {
              labels.current[i] = el;
            }}
            className="arena-label absolute left-0 top-0"
            style={{ opacity: 0 }}
          >
            {s.label}
          </div>
        ))}
      </div>
    </div>
  );
}
