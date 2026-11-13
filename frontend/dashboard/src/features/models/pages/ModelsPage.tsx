import { useApi } from "@/shared/api/client";
import { DataState, DataTable, HeroStat, Stat } from "@/shared/components/DataState";
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
          {(data) => {
            const urls = data.models.filter((model) => model.modality === "url").length;
            const emails = data.models.filter((model) => model.modality === "email").length;
            let best: { version: string | null; name: string; loss: number } | null = null;
            for (const model of data.models) {
              const loss = model.metrics?.oof_log_loss;
              if (typeof loss === "number" && (best === null || loss < best.loss)) {
                best = { version: model.version, name: model.name, loss };
              }
            }
            const types = [...new Set(data.models.map((model) => model.name))];
            return (
              <div className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-3">
                  <HeroStat
                    label="Registered models"
                    value={String(data.models.length)}
                    hint={`${urls} URL · ${emails} email`}
                  />
                  <Stat
                    label="Best out-of-fold log loss"
                    value={best ? best.loss.toFixed(4) : "–"}
                    hint={best?.version ?? "no metrics yet"}
                  />
                  <Stat label="Model types" value={String(types.length)} hint={types.join(", ")} />
                </div>
                <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
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
                </div>
              </div>
            );
          }}
        </DataState>
        <DataState
          state={results}
          isEmpty={(data) => Object.keys(data).length === 0}
          emptyMessage="No development report yet. Run: python -m phishguard_ml report"
        >
          {(data) => (
            <div className="space-y-6">
              {Object.entries(data).map(([key, rows]) => (
                <div key={key} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <DataTable
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
                </div>
              ))}
            </div>
          )}
        </DataState>
      </div>
    </>
  );
}
