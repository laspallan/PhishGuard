import { useApi } from "@/shared/api/client";
import { DataState, Stat } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface Status {
  warn_threshold: number;
  block_threshold: number;
  features_count: number;
  models_loaded: boolean;
  simulations_allowed: boolean;
}

export function SettingsPage() {
  const state = useApi<Status>("/admin/status");

  return (
    <>
      <PageHeader title="Settings" description="Current configuration, read-only. Changes are made in the server's .env file." />
      <DataState state={state}>
        {(data) => (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Stat label="Warn at" value={data.warn_threshold.toFixed(2)} />
            <Stat label="Block at" value={data.block_threshold.toFixed(2)} />
            <Stat label="Features" value={String(data.features_count)} />
            <Stat label="Models" value={data.models_loaded ? "Registered" : "None registered"} />
            <Stat label="Simulations" value={data.simulations_allowed ? "Allowed" : "Locked: no ethics approval set"} />
          </div>
        )}
      </DataState>
    </>
  );
}
