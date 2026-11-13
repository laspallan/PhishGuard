import { useApi } from "@/shared/api/client";
import { DataState, DataTable, Stat } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";
import { SegmentedBar } from "@/shared/components/SegmentedBar";

interface RecentScan {
  created_at: string;
  sample_type: string;
  target: string | null;
  decision: string;
  score: number;
  latency_ms: number | null;
}

function median(values: number[]): string {
  if (values.length === 0) return "–";
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const value = sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
  return `${Math.round(value)} ms`;
}

export function DetectionsPage() {
  const state = useApi<RecentScan[]>("/admin/scans?limit=100");

  return (
    <>
      <PageHeader title="Detections" description="The latest scans. Emails show only the sender domain." />
      <DataState state={state} isEmpty={(rows) => rows.length === 0} emptyMessage="No scans saved yet.">
        {(rows) => {
          const count = (decision: string) => rows.filter((scan) => scan.decision === decision).length;
          const share = (n: number) => `${Math.round((n / rows.length) * 100)}% of the ${rows.length} shown`;
          const latencies = rows
            .map((scan) => scan.latency_ms)
            .filter((value): value is number => value !== null);
          return (
            <div className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
                <Stat label="Median latency" value={median(latencies)} hint="of the scans shown" />
              </div>

              <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                <SegmentedBar
                  caption={`Verdict split (latest ${rows.length} scans)`}
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
                  caption={`Latest ${rows.length} scans`}
                  headers={["Time", "Type", "URL or sender domain", "Verdict", "Score", "Latency (ms)"]}
                  rows={rows.map((scan) => [
                    new Date(scan.created_at).toLocaleString(),
                    scan.sample_type,
                    scan.target ?? "–",
                    scan.decision,
                    scan.score.toFixed(3),
                    scan.latency_ms ?? "–",
                  ])}
                />
              </div>
            </div>
          );
        }}
      </DataState>
    </>
  );
}
