import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { useApi } from "@/shared/api/client";
import { DataState, DataTable, Stat } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface Overview {
  total_scans: number;
  by_decision: Record<string, number>;
  by_modality: Record<string, number>;
  median_latency_ms: number | null;
  p95_latency_ms: number | null;
}

function latency(value: number | null): string {
  return value === null ? "–" : `${Math.round(value)} ms`;
}

export function OverviewPage() {
  const state = useApi<Overview>("/admin/overview");

  return (
    <>
      <PageHeader title="Overview" description="Scans, the block / warn / allow split and latency." />
      <DataState
        state={state}
        isEmpty={(data) => data.total_scans === 0}
        emptyMessage="No scans saved yet."
      >
        {(data) => {
          const bars = ["block", "warn", "allow"].map((decision) => ({
            decision,
            scans: data.by_decision[decision] ?? 0,
          }));
          return (
            <div className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-3">
                <Stat label="Scans" value={data.total_scans.toLocaleString()} />
                <Stat label="Median latency" value={latency(data.median_latency_ms)} />
                <Stat label="95th percentile latency" value={latency(data.p95_latency_ms)} />
              </div>
              <figure>
                <figcaption className="mb-2 font-medium">Scans by verdict</figcaption>
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={bars} layout="vertical" margin={{ right: 48 }}>
                    <XAxis type="number" hide />
                    <YAxis type="category" dataKey="decision" axisLine={false} tickLine={false} />
                    <Tooltip cursor={{ fillOpacity: 0.08 }} />
                    <Bar dataKey="scans" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={24}>
                      <LabelList dataKey="scans" position="right" fill="currentColor" />
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </figure>
              <DataTable
                caption="Scans by type"
                headers={["Type", "Scans"]}
                rows={Object.entries(data.by_modality)}
              />
            </div>
          );
        }}
      </DataState>
    </>
  );
}
