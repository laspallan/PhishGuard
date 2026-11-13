import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { loadApiKey } from "@/shared/api/client";

import { LoginPage } from "./auth";
import { CampaignsPage, SimulationPage } from "./campaigns";
import { DetectionsPage } from "./detections";
import { ExperimentsPage } from "./experiments";
import { meanF1ByRound } from "./experiments/pages/ExperimentsPage";
import { OverviewPage } from "./overview";
import { SettingsPage } from "./settings";

function answer(body: unknown, status = 200) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status })));
}

beforeEach(() => sessionStorage.clear());
afterEach(() => vi.unstubAllGlobals());

describe("pages", () => {
  it("say so when the key is wrong instead of showing numbers", async () => {
    answer({}, 401);
    render(<OverviewPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("API key");
  });

  it("say so when the API is down", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    render(<DetectionsPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("cannot be reached");
  });

  it("do not invent numbers for an empty database", async () => {
    answer({ total_scans: 0, by_decision: {}, by_modality: {}, median_latency_ms: null, p95_latency_ms: null });
    render(<OverviewPage />);
    expect(await screen.findByText("No scans saved yet.")).toBeInTheDocument();
  });

  it("show the scan counts", async () => {
    answer({
      total_scans: 1234,
      by_decision: { block: 4, warn: 30, allow: 1200 },
      by_modality: { url: 1000, email: 234 },
      median_latency_ms: 120.4,
      p95_latency_ms: 900,
    });
    render(<OverviewPage />);
    expect(await screen.findByText("900 ms")).toBeInTheDocument();
    expect(screen.getByText("email")).toBeInTheDocument();
  });

  it("show campaign rates from totals", async () => {
    answer([
      {
        name: "Round 1",
        status: "completed",
        fictional_org: "Northwind",
        template_split: "train",
        participants_by_event: { sent: 20, clicked: 5, submitted: 1 },
      },
    ]);
    render(<CampaignsPage />);
    expect(await screen.findByText("5 (25%)")).toBeInTheDocument();
    expect(screen.getByText("1 (5%)")).toBeInTheDocument();
  });

  it("explain that simulations are locked without approval", async () => {
    answer({
      warn_threshold: 0.6,
      block_threshold: 0.9,
      features_count: 140,
      models_loaded: false,
      simulations_allowed: false,
    });
    render(<SettingsPage />);
    expect(await screen.findByText(/no ethics approval/)).toBeInTheDocument();
  });

  it("explain why RQ3 has no results yet", async () => {
    answer([]);
    render(<ExperimentsPage />);
    expect(await screen.findByText(/after ethics approval/)).toBeInTheDocument();
  });
});

describe("simulation page", () => {
  const answers: Record<string, unknown> = {
    "/admin/status": { simulations_allowed: false },
    "/admin/simulation/templates": [
      { id: "t1", name: "library-expiry", fictional_org: "Kestrelmoor Institute", attack_category: "credential_harvest", split: "train" },
    ],
    "/admin/simulation/participants": [
      { id: "p1", participant_code: "P1", consent_form_version: "1.0", consent_given_at: "2026-11-08T00:00:00Z", withdrawn: false },
    ],
    "/admin/simulation/campaigns": [
      { id: "c1", name: "Round 1", template_name: "library-expiry", status: "draft", launched_at: null, completed_at: null },
    ],
  };

  function routed(post?: (url: string, init: RequestInit) => Response) {
    const mock = vi.fn((url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      if (init.method === "POST" && post) return Promise.resolve(post(path, init));
      return Promise.resolve(new Response(JSON.stringify(answers[path] ?? []), { status: 200 }));
    });
    vi.stubGlobal("fetch", mock);
    return mock;
  }

  it("lists by code and keeps launch locked without approval", async () => {
    routed();
    render(<SimulationPage />);
    expect(await screen.findByText(/Simulations are locked/)).toBeInTheDocument();
    expect(await screen.findByText("Kestrelmoor Institute")).toBeInTheDocument();
    expect(screen.getAllByText("P1").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Launch" })).toBeDisabled();
  });

  it("shows the API's reason when it refuses a template", async () => {
    const mock = routed(() => new Response(JSON.stringify({ detail: "PayPal is a real brand" }), { status: 422 }));
    const user = userEvent.setup();
    render(<SimulationPage />);
    const form = await screen.findByRole("form", { name: "New template" });
    const within = (label: string) => form.querySelector(`[name="${label}"]`) as HTMLInputElement;
    await user.type(within("name"), "x");
    await user.type(within("fictional_org"), "PayPal");
    await user.type(within("subject"), "s");
    await user.type(within("html"), "<p>hi</p>");
    await user.click(screen.getByRole("button", { name: "Save template" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("PayPal is a real brand");
    const post = mock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({ fictional_org: "PayPal", split: "train" });
  });

  it("offers Delete only for a withdrawn participant, and asks first", async () => {
    const withdrawn = { ...(answers["/admin/simulation/participants"] as object[])[0], withdrawn: true };
    const saved = answers["/admin/simulation/participants"];
    answers["/admin/simulation/participants"] = [withdrawn];
    const mock = routed(() => new Response(JSON.stringify({ deleted: true, gophish_groups_changed: 1, gophish_campaigns_still_holding_results: 0 }), { status: 200 }));
    vi.stubGlobal("confirm", vi.fn().mockReturnValue(true));
    const user = userEvent.setup();
    render(<SimulationPage />);
    expect(screen.queryByRole("button", { name: "Withdraw" })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    const post = mock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(String(post?.[0])).toContain("/admin/simulation/participants/p1/delete");
    expect(await screen.findByRole("status")).toHaveTextContent("P1 deleted.");
    answers["/admin/simulation/participants"] = saved;
  });

  it("asks before withdrawing and posts nothing if cancelled", async () => {
    const mock = routed(() => new Response(JSON.stringify({ id: "p1", status: "withdrawn" }), { status: 200 }));
    vi.stubGlobal("confirm", vi.fn().mockReturnValue(false));
    const user = userEvent.setup();
    render(<SimulationPage />);
    await user.click(await screen.findByRole("button", { name: "Withdraw" }));
    expect(mock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });
});

describe("meanF1ByRound", () => {
  const run = (round: number, arm: string, f1: number, seed: number, eval_set = "fresh_feed") => ({
    experiment: "rq3",
    round,
    seed,
    arm,
    eval_set,
    k: 0,
    metrics: { f1 },
  });

  it("averages the seeds and keeps only the fresh data", () => {
    const rows = meanF1ByRound([
      run(2, "A", 0.8, 42),
      run(1, "C", 0.9, 42),
      run(1, "C", 0.7, 43),
      run(1, "C", 0.1, 42, "sim_holdout"),
    ]);
    expect(rows.map((row) => row.round)).toEqual([1, 2]);
    expect(rows[0].C).toBeCloseTo(0.8);
    expect(rows[1].A).toBeCloseTo(0.8);
  });
});

describe("sign-in", () => {
  it("keeps the key for this tab and goes to the overview", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );
    await user.type(screen.getByLabelText("API key"), "secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(loadApiKey()).toBe("secret");
  });

  it("drops spaces and a pasted .env prefix around the key", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );
    await user.type(screen.getByLabelText("API key"), "  PHISHGUARD_API_KEY=secret ");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(loadApiKey()).toBe("secret");
  });
});
