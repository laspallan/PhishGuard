import { useApi } from "@/shared/api/client";
import { DataState, DataTable } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface CampaignSummary {
  name: string;
  status: string;
  fictional_org: string;
  template_split: string;
  participants_by_event: Record<string, number>;
}

function rate(part: number, whole: number): string {
  return whole === 0 ? "–" : `${part} (${Math.round((part / whole) * 100)}%)`;
}

export function CampaignsPage() {
  const state = useApi<CampaignSummary[]>("/admin/campaigns");

  return (
    <>
      <PageHeader
        title="Campaigns"
        description="Simulation totals for consenting participants. No individual's actions are shown."
      />
      <DataState
        state={state}
        isEmpty={(rows) => rows.length === 0}
        emptyMessage="No campaigns. Simulations need university ethics approval first."
      >
        {(rows) => (
          <DataTable
            caption="Participants per campaign"
            headers={["Campaign", "Organisation (fictional)", "Status", "Template set", "Sent", "Clicked", "Submitted", "Reported"]}
            rows={rows.map((campaign) => {
              const events = campaign.participants_by_event;
              const sent = events.sent ?? 0;
              return [
                campaign.name,
                campaign.fictional_org,
                campaign.status,
                campaign.template_split,
                sent,
                rate(events.clicked ?? 0, sent),
                rate(events.submitted ?? 0, sent),
                rate(events.reported ?? 0, sent),
              ];
            })}
          />
        )}
      </DataState>
    </>
  );
}
