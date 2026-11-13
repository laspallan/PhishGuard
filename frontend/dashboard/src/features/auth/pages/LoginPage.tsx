import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";

import { saveApiKey } from "@/shared/api/client";
import { PageHeader } from "@/shared/components/PageHeader";

export function LoginPage() {
  const [key, setKey] = useState("");
  const navigate = useNavigate();

  function submit(event: FormEvent) {
    event.preventDefault();
    // Pasting often brings a space or line break, or the whole .env line; keep only the key.
    saveApiKey(key.trim().replace(/^PHISHGUARD_API_KEY=/, "").trim());
    navigate("/");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-50 p-6">
      <div className="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="mb-6 flex items-center gap-2">
          <span
            aria-hidden
            className="inline-block h-8 w-8 rounded-lg"
            style={{ backgroundColor: "var(--series-1)" }}
          />
          <span className="text-lg font-semibold text-slate-900">PhishGuard</span>
        </div>
        <PageHeader
          title="Sign in"
          description="Enter the API key. It is kept only in this browser tab."
        />
        <form onSubmit={submit} className="space-y-4">
          <label className="block text-sm font-medium text-slate-700">
            API key
            <input
              type="password"
              autoComplete="off"
              required
              value={key}
              onChange={(event) => setKey(event.target.value)}
              className="mt-1 block w-full rounded-lg border border-slate-300 p-2 focus:border-slate-500 focus:ring-2 focus:ring-slate-200 focus:outline-none"
            />
          </label>
          <button
            type="submit"
            className="w-full rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
          >
            Sign in
          </button>
        </form>
      </div>
    </main>
  );
}
