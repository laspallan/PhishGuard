import { useApi } from "@/shared/api/client";
import { DataState, Stat } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface Status {
  threat_intel_configured: boolean;
}

export function ThreatIntelPage() {
  const state = useApi<Status>("/admin/status");

  return (
    <>
      <PageHeader title="Threat Intel" description="VirusTotal and AlienVault OTX, used for ti_score (RQ2)." />
      <DataState state={state}>
        {(data) => (
          <div className="grid gap-4 sm:grid-cols-2">
            <Stat label="API keys" value={data.threat_intel_configured ? "Configured" : "Not configured"} />
            <Stat label="ti_score in verdicts" value="Not used yet: RQ2 decides whether it helps" />
          </div>
        )}
      </DataState>
    </>
  );
}
