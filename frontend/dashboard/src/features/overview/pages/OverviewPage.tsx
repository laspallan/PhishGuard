import { useApi } from "@/shared/api/client";
import { DataState, DataTable, HeroStat, Stat } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";
import { SegmentedBar } from "@/shared/components/SegmentedBar";

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
          const total = data.total_scans;
          const count = (decision: string) => data.by_decision[decision] ?? 0;
          const share = (n: number) => (total > 0 ? `${Math.round((n / total) * 100)}% of scans` : "–");
          return (
            <div className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <HeroStat
                  label="Total scans"
                  value={total.toLocaleString()}
                  hint="URL and email scans saved"
                />
                <Stat
                  tone="critical"
                  label="Blocked"
                  value={count("block").toLocaleString()}
                  hint={share(count("block"))}
                />
                <Stat
                  tone="warning"
                  label="Warned"
                  value={count("warn").toLocaleString()}
                  hint={share(count("warn"))}
                />
                <Stat
                  tone="good"
                  label="Allowed"
                  value={count("allow").toLocaleString()}
                  hint={share(count("allow"))}
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <Stat
                  label="Median latency"
                  value={latency(data.median_latency_ms)}
                  hint="typical time to a verdict"
                />
                <Stat
                  label="95th percentile latency"
                  value={latency(data.p95_latency_ms)}
                  hint="slowest 5% of scans"
                />
              </div>

              <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                <SegmentedBar
                  caption="Verdict split"
                  segments={[
                    { label: "Blocked", value: count("block"), color: "var(--status-critical)" },
                    {
                      label: "Warned",
                      value: count("warn"),
                      color: "var(--status-warning)",
                      textOnFill: "#0b0b0b",
                    },
                    { label: "Allowed", value: count("allow"), color: "var(--status-good)" },
                  ]}
                />
              </div>

              <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                <DataTable
                  caption="Scans by type"
                  headers={["Type", "Scans"]}
                  rows={Object.entries(data.by_modality)}
                />
              </div>
            </div>
          );
        }}
      </DataState>
    </>
  );
}
