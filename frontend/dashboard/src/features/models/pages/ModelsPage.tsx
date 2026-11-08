import { useApi } from "@/shared/api/client";
import { DataState, DataTable } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface ModelList {
  models: { name: string; modality: string; version: string | null; metrics: { oof_log_loss: number } | null }[];
}

interface ResultRow {
  model: string;
  n: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  ci95: { f1: [number, number]; fpr: [number, number] };
}

function number(value: number | null | undefined): string {
  return value === null || value === undefined || Number.isNaN(value) ? "–" : value.toFixed(4);
}

export function ModelsPage() {
  const models = useApi<ModelList>("/models");
  const results = useApi<Record<string, ResultRow[]>>("/admin/results");

  return (
    <>
      <PageHeader
        title="Models"
        description="Registered versions and development results (5-fold CV). These are not the final test results."
      />
      <div className="space-y-8">
        <DataState state={models} isEmpty={(data) => data.models.length === 0} emptyMessage="No models registered yet.">
          {(data) => (
            <DataTable
              caption="Registered versions"
              headers={["Version", "Type", "Modality", "Out-of-fold log loss"]}
              rows={data.models.map((model) => [
                model.version ?? "–",
                model.name,
                model.modality,
                number(model.metrics?.oof_log_loss),
              ])}
            />
          )}
        </DataState>
        <DataState
          state={results}
          isEmpty={(data) => Object.keys(data).length === 0}
          emptyMessage="No development report yet. Run: python -m phishguard_ml report"
        >
          {(data) =>
            Object.entries(data).map(([key, rows]) => (
              <DataTable
                key={key}
                caption={key}
                headers={["Model", "n", "Precision", "Recall", "F1 [95% CI]", "FPR [95% CI]"]}
                rows={rows.map((row) => [
                  row.model,
                  row.n,
                  number(row.precision),
                  number(row.recall),
                  `${number(row.f1)} [${number(row.ci95.f1[0])}, ${number(row.ci95.f1[1])}]`,
                  `${number(row.fpr)} [${number(row.ci95.fpr[0])}, ${number(row.ci95.fpr[1])}]`,
                ])}
              />
            ))
          }
        </DataState>
      </div>
    </>
  );
}
