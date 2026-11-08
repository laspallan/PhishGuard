import { Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { useApi } from "@/shared/api/client";
import { DataState, DataTable } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface ExperimentResult {
  experiment: string;
  round: number | null;
  seed: number;
  arm: string;
  eval_set: string;
  k: number | null;
  metrics: { f1?: number; recall?: number; fpr?: number };
}

const ARMS = [
  { arm: "A", label: "A: static", color: "var(--series-1)" },
  { arm: "B", label: "B: fresh feed", color: "var(--series-2)" },
  { arm: "C", label: "C: fresh feed + simulation", color: "var(--series-3)" },
];

export function meanF1ByRound(runs: ExperimentResult[]) {
  const chosen = runs.filter((r) => r.experiment === "rq3" && r.eval_set === "fresh_feed" && r.round !== null);
  const rounds = [...new Set(chosen.map((r) => r.round as number))].sort((a, b) => a - b);
  return rounds.map((round) => {
    const row: Record<string, number> = { round };
    for (const { arm } of ARMS) {
      const values = chosen
        .filter((r) => r.round === round && r.arm === arm)
        .map((r) => r.metrics.f1)
        .filter((f1): f1 is number => typeof f1 === "number");
      if (values.length) row[arm] = values.reduce((sum, f1) => sum + f1, 0) / values.length;
    }
    return row;
  });
}

export function ExperimentsPage() {
  const state = useApi<ExperimentResult[]>("/admin/experiments");

  return (
    <>
      <PageHeader title="Experiments" description="RQ3 rounds: mean F1 over the seeds on the next month's fresh data." />
      <DataState
        state={state}
        isEmpty={(runs) => runs.length === 0}
        emptyMessage="No experiment results yet. RQ3 rounds run after ethics approval."
      >
        {(runs) => {
          const rows = meanF1ByRound(runs);
          return (
            <div className="space-y-6">
              <figure>
                <figcaption className="mb-2 font-medium">Mean F1 per round</figcaption>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={rows} margin={{ right: 16 }}>
                    <XAxis dataKey="round" allowDecimals={false} tickLine={false} />
                    <YAxis domain={["auto", "auto"]} tickLine={false} axisLine={false} width={48} />
                    <Tooltip />
                    <Legend formatter={(value) => <span className="text-slate-900">{value}</span>} />
                    {ARMS.map(({ arm, label, color }) => (
                      <Line key={arm} dataKey={arm} name={label} stroke={color} strokeWidth={2} dot={{ r: 4 }} />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              </figure>
              <DataTable
                caption="Mean F1 per round"
                headers={["Round", ...ARMS.map(({ label }) => label)]}
                rows={rows.map((row) => [
                  row.round,
                  ...ARMS.map(({ arm }) => (row[arm] === undefined ? "–" : row[arm].toFixed(4))),
                ])}
              />
            </div>
          );
        }}
      </DataState>
    </>
  );
}
