import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import App, { menu } from "./App";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("App", () => {
  it("shows every menu item in the sidebar", () => {
    renderAt("/");
    const nav = screen.getByRole("navigation", { name: "Main menu" });

    for (const item of menu) {
      expect(nav).toHaveTextContent(item.label);
    }
  });

  it("opens each feature page from its menu link", async () => {
    const user = userEvent.setup();
    renderAt("/");

    for (const item of menu) {
      await user.click(screen.getByRole("link", { name: item.label }));
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(item.label);
    }
  });

  it("serves the login page outside the main layout", () => {
    renderAt("/login");

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Sign in");
    expect(screen.queryByRole("navigation", { name: "Main menu" })).not.toBeInTheDocument();
  });
});
