import { useApi } from "@/shared/api/client";
import { DataState, DataTable } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface RecentScan {
  created_at: string;
  sample_type: string;
  target: string | null;
  decision: string;
  score: number;
  latency_ms: number | null;
}

export function DetectionsPage() {
  const state = useApi<RecentScan[]>("/admin/scans?limit=100");

  return (
    <>
      <PageHeader title="Detections" description="The latest scans. Emails show only the sender domain." />
      <DataState state={state} isEmpty={(rows) => rows.length === 0} emptyMessage="No scans saved yet.">
        {(rows) => (
          <DataTable
            caption="Latest 100 scans"
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
        )}
      </DataState>
    </>
  );
}
