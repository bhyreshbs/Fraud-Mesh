// Risk over time (PRD §11.1): explanation parts[].running_p vs ts, shaded bands at 0.20 / 0.50 / 0.80, dots by detector.
import { CartesianGrid, Line, LineChart, ReferenceArea, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DetectorId, Explanation } from "../types/contracts";
import { DETECTOR } from "../lib/labels";
import { istTime } from "../lib/format";

type Pt = { t: number; p: number; label: string; detector: DetectorId | null; kind: string };

export function RiskChart({ ex, height = 260 }: { ex: Explanation | undefined; height?: number }) {
  const data: Pt[] = (ex?.parts ?? []).filter((p) => p.ts && p.kind !== "prior")
    .map((p) => ({ t: new Date(p.ts!).getTime(), p: p.running_p, label: p.label, detector: p.detector ?? null, kind: p.kind }));
  const used = [...new Set(data.map((d) => d.detector).filter(Boolean))] as DetectorId[];

  return (
    <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
      <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
        <span className="font-headline-sm text-headline-sm">Risk over time</span>
        <div className="flex items-center gap-3 flex-wrap justify-end">
          {used.map((d) => (
            <span key={d} className="flex items-center gap-1 text-body-xs text-on-surface-variant">
              <span className="w-2 h-2 rounded-full" style={{ background: DETECTOR[d].color }} />{DETECTOR[d].label}
            </span>
          ))}
        </div>
      </div>
      <div className="p-2" data-testid="risk-chart">
        {data.length === 0 ? (
          <div className="h-[200px] flex items-center justify-center text-body-sm text-on-surface-variant">No scored evidence yet.</div>
        ) : (
          <ResponsiveContainer width="100%" height={height}>
            <LineChart data={data} margin={{ top: 10, right: 24, bottom: 4, left: 0 }}>
              <ReferenceArea y1={0} y2={0.2} fill="#ECFDF3" fillOpacity={0.7} />
              <ReferenceArea y1={0.2} y2={0.5} fill="#FBEFD6" fillOpacity={0.7} />
              <ReferenceArea y1={0.5} y2={0.8} fill="#FCE5D3" fillOpacity={0.7} />
              <ReferenceArea y1={0.8} y2={1} fill="#FBE6E2" fillOpacity={0.8} />
              {[0.2, 0.5, 0.8].map((y) => <ReferenceLine key={y} y={y} stroke="#DDC9B8" strokeDasharray="3 3" />)}
              <CartesianGrid stroke="#E6D9CA" vertical={false} />
              <XAxis dataKey="t" type="number" scale="time" domain={["dataMin", "dataMax"]} tickFormatter={(t) => istTime(new Date(t).toISOString())}
                tick={{ fontSize: 11, fontFamily: "JetBrains Mono" }} stroke="#8A7268" />
              <YAxis domain={[0, 1]} ticks={[0, 0.2, 0.5, 0.8, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} width={44}
                tick={{ fontSize: 11 }} stroke="#8A7268" />
              <Tooltip labelFormatter={(t) => istTime(new Date(t as number).toISOString(), true) + " IST"}
                formatter={(v: number, _n, item) => [`${(v * 100).toFixed(1)}%`, (item.payload as Pt).label]}
                contentStyle={{ fontSize: 12, borderRadius: 4, borderColor: "#D1D5DB" }} />
              <Line type="stepAfter" dataKey="p" stroke="#D96B35" strokeWidth={2} isAnimationActive={false}
                dot={(props) => {
                  const pt = props.payload as Pt;
                  const fill = pt.detector ? DETECTOR[pt.detector].color : "#D96B35";
                  return <circle key={`${props.cx}-${props.cy}-${pt.label}`} cx={props.cx} cy={props.cy} r={pt.kind === "evidence" ? 5 : 3.5}
                    fill={pt.kind === "evidence" ? fill : "#fff"} stroke={fill} strokeWidth={2} />;
                }} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}
