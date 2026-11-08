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
    <main className="mx-auto max-w-md p-6">
      <PageHeader title="Sign in" description="Enter the API key. It is kept only in this browser tab." />
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-sm font-medium">
          API key
          <input
            type="password"
            autoComplete="off"
            required
            value={key}
            onChange={(event) => setKey(event.target.value)}
            className="mt-1 block w-full rounded border border-slate-300 p-2"
          />
        </label>
        <button type="submit" className="rounded bg-slate-800 px-4 py-2 text-sm text-white">
          Sign in
        </button>
      </form>
    </main>
  );
}
