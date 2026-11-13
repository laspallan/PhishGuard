import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { saveApiKey } from "@/shared/api/client";

import App, { menu } from "./App";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("no API in tests")));
  saveApiKey("test-key"); // signed in: the dashboard is behind the sign-in gate
});
afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("App", () => {
  it("shows every visible menu item in the sidebar, and no hidden one", () => {
    renderAt("/");
    const nav = screen.getByRole("navigation", { name: "Main menu" });

    for (const item of menu.filter((i) => !i.hidden)) {
      expect(nav).toHaveTextContent(item.label);
    }
    for (const item of menu.filter((i) => i.hidden)) {
      expect(
        screen.queryByRole("link", { name: item.label }),
      ).not.toBeInTheDocument();
    }
  });

  it("opens each visible feature page from its menu link", async () => {
    const user = userEvent.setup();
    renderAt("/");

    for (const item of menu.filter((i) => !i.hidden)) {
      await user.click(screen.getByRole("link", { name: item.label }));
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(item.label);
    }
  });

  it("still serves a hidden page by its route", () => {
    for (const item of menu.filter((i) => i.hidden)) {
      const view = renderAt(item.path);
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(item.label);
      view.unmount();
    }
  });

  it("serves the login page outside the main layout", () => {
    renderAt("/login");

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Sign in");
    expect(screen.queryByRole("navigation", { name: "Main menu" })).not.toBeInTheDocument();
  });

  it("sends a signed-out visitor to the sign-in page", () => {
    sessionStorage.clear();
    renderAt("/");

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Sign in");
    expect(screen.queryByRole("navigation", { name: "Main menu" })).not.toBeInTheDocument();
  });
});
