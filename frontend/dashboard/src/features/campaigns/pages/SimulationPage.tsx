// Managing simulations: templates, participants, campaigns. Every safety rule (ethics approval,
// fictional organisation, consent, withdrawal) is enforced by the API; this page only shows the
// API's reason when it refuses. Participants appear by code only: no email address comes back.
import { type FormEvent, type ReactNode, useState } from "react";

import { apiPost, explainRefusal, useApi } from "@/shared/api/client";
import { DataState, DataTable } from "@/shared/components/DataState";
import { PageHeader } from "@/shared/components/PageHeader";

interface Template {
  id: string;
  name: string;
  fictional_org: string;
  attack_category: string;
  split: string;
}

interface Participant {
  id: string;
  participant_code: string;
  consent_form_version: string;
  consent_given_at: string;
  withdrawn: boolean;
}

interface Campaign {
  id: string;
  name: string;
  template_name: string;
  status: string;
  launched_at: string | null;
  completed_at: string | null;
}

interface SyncResult {
  saved: number;
  already_saved: number;
  unknown_address: number;
  withdrawn: number;
}

const CATEGORIES = ["credential_harvest", "brand_impersonation", "malware", "spear", "unknown"];
const BASE = "/admin/simulation";
const input = "mt-1 block w-full rounded border border-slate-300 px-2 py-1 text-sm";
const button = "rounded border border-slate-400 px-3 py-1 text-sm hover:bg-slate-100 disabled:opacity-50";

type Outcome = { ok: boolean; text: string } | null;

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-sm">
      {label}
      {children}
    </label>
  );
}

function Message({ outcome }: { outcome: Outcome }) {
  if (!outcome) return null;
  return (
    <p role={outcome.ok ? "status" : "alert"} className="mt-2 rounded border border-slate-300 p-2 text-sm">
      {outcome.text}
    </p>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="mb-3 text-lg font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function day(value: string | null): string {
  return value ? value.slice(0, 10) : "–";
}

// Runs one POST and reports the result; the caller reloads its lists on success.
function useAction(onDone: () => void) {
  const [outcome, setOutcome] = useState<Outcome>(null);
  const [busy, setBusy] = useState(false);

  async function run(path: string, body: unknown, success: (answer: unknown) => string) {
    setBusy(true);
    setOutcome(null);
    try {
      const answer = await apiPost<unknown>(path, body);
      setOutcome({ ok: true, text: success(answer) });
      onDone();
      return true;
    } catch (error) {
      setOutcome({ ok: false, text: explainRefusal(error) });
      return false;
    } finally {
      setBusy(false);
    }
  }

  return { outcome, busy, run };
}

function TemplateForm({ onDone }: { onDone: () => void }) {
  const { outcome, busy, run } = useAction(onDone);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body = Object.fromEntries(
      ["name", "subject", "html", "text", "fictional_org", "attack_category", "split"].map((k) => [k, String(data.get(k) ?? "")]),
    );
    if (await run(`${BASE}/templates`, body, () => "Template saved in PhishGuard and GoPhish.")) form.reset();
  }

  return (
    <form onSubmit={submit} className="grid gap-3 rounded border border-slate-200 p-4 sm:grid-cols-2" aria-label="New template">
      <Field label="Name">
        <input name="name" required maxLength={100} className={input} />
      </Field>
      <Field label="Organisation (fictional, never a real brand)">
        <input name="fictional_org" required maxLength={100} className={input} />
      </Field>
      <Field label="Subject">
        <input name="subject" required className={input} />
      </Field>
      <Field label="Category">
        <select name="attack_category" className={input} defaultValue="credential_harvest">
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Template set">
        <select name="split" className={input} defaultValue="train">
          <option value="train">train</option>
          <option value="holdout">holdout</option>
        </select>
      </Field>
      <div className="sm:col-span-2">
        <Field label="HTML body (put {{.URL}} where the link goes)">
          <textarea name="html" required rows={5} className={`${input} font-mono`} />
        </Field>
      </div>
      <div className="sm:col-span-2">
        <Field label="Plain-text body (optional)">
          <textarea name="text" rows={3} className={`${input} font-mono`} />
        </Field>
      </div>
      <div className="sm:col-span-2">
        <button type="submit" disabled={busy} className={button}>
          Save template
        </button>
        <Message outcome={outcome} />
      </div>
    </form>
  );
}

function ParticipantForm({ onDone }: { onDone: () => void }) {
  const { outcome, busy, run } = useAction(onDone);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const consentDay = String(data.get("consent_given_at") ?? "");
    const body = {
      email: String(data.get("email") ?? "").trim(),
      participant_code: String(data.get("participant_code") ?? "").trim(),
      consent_form_version: String(data.get("consent_form_version") ?? "").trim(),
      consent_given_at: `${consentDay}T00:00:00Z`,
    };
    if (await run(`${BASE}/participants`, body, () => `Participant ${body.participant_code} registered.`)) form.reset();
  }

  return (
    <form onSubmit={submit} className="grid gap-3 rounded border border-slate-200 p-4 sm:grid-cols-2" aria-label="New participant">
      <p className="text-sm text-slate-600 sm:col-span-2">
        Only people who signed the consent form. The address is stored encrypted and is never shown again.
      </p>
      <Field label="Email address">
        <input name="email" type="email" required maxLength={254} autoComplete="off" className={input} />
      </Field>
      <Field label="Participant code">
        <input name="participant_code" required maxLength={32} className={input} />
      </Field>
      <Field label="Consent form version">
        <input name="consent_form_version" required maxLength={32} className={input} />
      </Field>
      <Field label="Consent given on">
        <input name="consent_given_at" type="date" required className={input} />
      </Field>
      <div className="sm:col-span-2">
        <button type="submit" disabled={busy} className={button}>
          Register participant
        </button>
        <Message outcome={outcome} />
      </div>
    </form>
  );
}

function Participants({ rows, onDone }: { rows: Participant[]; onDone: () => void }) {
  const { outcome, busy, run } = useAction(onDone);

  function withdraw(person: Participant) {
    if (!window.confirm(`Withdraw ${person.participant_code}? Their consent ends now and cannot be restored here.`)) return;
    void run(`${BASE}/participants/${person.id}/withdraw`, undefined, () => `${person.participant_code} withdrawn.`);
  }

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-sm">
          <caption className="mb-2 text-left font-medium">Registered participants</caption>
          <thead>
            <tr className="border-b border-slate-300">
              {["Code", "Consent form", "Consent given", "Status", ""].map((h) => (
                <th key={h} scope="col" className="px-2 py-1 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.id} className="border-b border-slate-100">
                <td className="px-2 py-1">{p.participant_code}</td>
                <td className="px-2 py-1">{p.consent_form_version}</td>
                <td className="px-2 py-1 tabular-nums">{day(p.consent_given_at)}</td>
                <td className="px-2 py-1">{p.withdrawn ? "Withdrawn" : "Active"}</td>
                <td className="px-2 py-1">
                  {!p.withdrawn && (
                    <button type="button" disabled={busy} onClick={() => withdraw(p)} className={button}>
                      Withdraw
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Message outcome={outcome} />
    </>
  );
}

function CampaignForm({ templates, onDone }: { templates: Template[]; onDone: () => void }) {
  const { outcome, busy, run } = useAction(onDone);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body = { name: String(data.get("name") ?? "").trim(), template_id: String(data.get("template_id") ?? "") };
    if (await run(`${BASE}/campaigns`, body, () => `Campaign ${body.name} created as a draft.`)) form.reset();
  }

  if (templates.length === 0) return <p className="text-sm text-slate-600">Save a template first.</p>;
  return (
    <form onSubmit={submit} className="grid gap-3 rounded border border-slate-200 p-4 sm:grid-cols-2" aria-label="New campaign">
      <Field label="Campaign name">
        <input name="name" required maxLength={100} className={input} />
      </Field>
      <Field label="Template">
        <select name="template_id" required className={input}>
          {templates.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} ({t.fictional_org}, {t.split})
            </option>
          ))}
        </select>
      </Field>
      <div className="sm:col-span-2">
        <button type="submit" disabled={busy} className={button}>
          Create draft
        </button>
        <Message outcome={outcome} />
      </div>
    </form>
  );
}

function LaunchForm({ campaign, people, allowed, onDone }: { campaign: Campaign; people: Participant[]; allowed: boolean; onDone: () => void }) {
  const { outcome, busy, run } = useAction(onDone);
  const active = people.filter((p) => !p.withdrawn);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const ids = data.getAll("participant").map(String);
    if (ids.length === 0) return;
    if (!window.confirm(`Send "${campaign.name}" to ${ids.length} consenting participant(s)? This sends real emails.`)) return;
    await run(
      `${BASE}/campaigns/${campaign.id}/launch`,
      { participant_ids: ids, smtp: String(data.get("smtp") ?? ""), url: String(data.get("url") ?? "") },
      () => `${campaign.name} launched.`,
    );
  }

  return (
    <form onSubmit={submit} className="mt-2 grid gap-3 rounded border border-slate-200 p-4 sm:grid-cols-2" aria-label={`Launch ${campaign.name}`}>
      <fieldset className="sm:col-span-2">
        <legend className="text-sm">Participants (active only)</legend>
        {active.length === 0 ? (
          <p className="text-sm text-slate-600">No active participants.</p>
        ) : (
          <div className="mt-1 flex flex-wrap gap-3">
            {active.map((p) => (
              <label key={p.id} className="flex items-center gap-1 text-sm">
                <input type="checkbox" name="participant" value={p.id} />
                {p.participant_code}
              </label>
            ))}
          </div>
        )}
      </fieldset>
      <Field label="GoPhish sending profile">
        <input name="smtp" required className={input} />
      </Field>
      <Field label="Landing page address (GoPhish)">
        <input name="url" type="url" required className={input} />
      </Field>
      <div className="sm:col-span-2">
        <button type="submit" disabled={busy || !allowed || active.length === 0} className={button}>
          Launch
        </button>
        {!allowed && <p className="mt-1 text-sm text-slate-600">Locked until the ethics approval reference is set.</p>}
        <Message outcome={outcome} />
      </div>
    </form>
  );
}

function CampaignActions({ campaign, onDone }: { campaign: Campaign; onDone: () => void }) {
  const { outcome, busy, run } = useAction(onDone);
  const sync = () =>
    void run(`${BASE}/campaigns/${campaign.id}/sync`, undefined, (answer) => {
      const r = answer as SyncResult;
      return `${r.saved} new events saved (${r.already_saved} already saved, ${r.withdrawn} from withdrawn participants dropped).`;
    });
  const complete = () => {
    if (!window.confirm(`Complete "${campaign.name}"? GoPhish stops tracking it.`)) return;
    void run(`${BASE}/campaigns/${campaign.id}/complete`, undefined, () => `${campaign.name} completed.`);
  };

  return (
    <div className="mt-2">
      <div className="flex gap-2">
        <button type="button" disabled={busy} onClick={sync} className={button}>
          Fetch events
        </button>
        {campaign.status === "running" && (
          <button type="button" disabled={busy} onClick={complete} className={button}>
            Complete
          </button>
        )}
      </div>
      <Message outcome={outcome} />
    </div>
  );
}

export function SimulationPage() {
  const [version, setVersion] = useState(0);
  const reload = () => setVersion((v) => v + 1);
  const status = useApi<{ simulations_allowed: boolean }>("/admin/status", version);
  const templates = useApi<Template[]>(`${BASE}/templates`, version);
  const people = useApi<Participant[]>(`${BASE}/participants`, version);
  const campaigns = useApi<Campaign[]>(`${BASE}/campaigns`, version);
  const allowed = status.data?.simulations_allowed === true;

  return (
    <>
      <PageHeader
        title="Simulation"
        description="Templates, consenting participants and campaigns. Only fictional organisations; nothing can be sent before ethics approval."
      />
      {status.data && !allowed && (
        <p role="note" className="rounded border border-slate-300 p-3 text-sm">
          Simulations are locked: no ethics approval reference is set. You can prepare templates, participants and drafts.
        </p>
      )}

      <Section title="Templates">
        <DataState state={templates} isEmpty={(rows) => rows.length === 0} emptyMessage="No templates yet.">
          {(rows) => (
            <DataTable
              caption="Saved templates"
              headers={["Name", "Organisation (fictional)", "Category", "Set"]}
              rows={rows.map((t) => [t.name, t.fictional_org, t.attack_category, t.split])}
            />
          )}
        </DataState>
        <div className="mt-3">
          <TemplateForm onDone={reload} />
        </div>
      </Section>

      <Section title="Participants">
        <DataState state={people} isEmpty={(rows) => rows.length === 0} emptyMessage="No participants registered.">
          {(rows) => <Participants rows={rows} onDone={reload} />}
        </DataState>
        <div className="mt-3">
          <ParticipantForm onDone={reload} />
        </div>
      </Section>

      <Section title="Campaigns">
        <DataState state={campaigns} isEmpty={(rows) => rows.length === 0} emptyMessage="No campaigns yet.">
          {(rows) => (
            <ul className="space-y-4">
              {rows.map((c) => (
                <li key={c.id} className="rounded border border-slate-200 p-4">
                  <p className="text-sm">
                    <span className="font-medium">{c.name}</span> · {c.template_name} · {c.status} · launched {day(c.launched_at)} · completed{" "}
                    {day(c.completed_at)}
                  </p>
                  {c.status === "draft" ? (
                    <LaunchForm campaign={c} people={people.data ?? []} allowed={allowed} onDone={reload} />
                  ) : (
                    <CampaignActions campaign={c} onDone={reload} />
                  )}
                </li>
              ))}
            </ul>
          )}
        </DataState>
        <div className="mt-3">
          {templates.data && <CampaignForm templates={templates.data} onDone={reload} />}
        </div>
      </Section>
    </>
  );
}
