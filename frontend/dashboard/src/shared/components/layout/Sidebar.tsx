import { NavLink, useNavigate } from "react-router-dom";

import { clearApiKey } from "@/shared/api/client";
import type { MenuItem } from "@/shared/types/navigation";

interface SidebarProps {
  menu: MenuItem[];
}

export function Sidebar({ menu }: SidebarProps) {
  const navigate = useNavigate();

  function signOut() {
    clearApiKey();
    navigate("/login");
  }

  return (
    <nav
      aria-label="Main menu"
      className="flex shrink-0 flex-col border-b border-slate-200 bg-white p-4 md:w-56 md:border-r md:border-b-0"
    >
      <div className="mb-3 flex items-center gap-2 md:mb-6">
        <span
          aria-hidden
          className="inline-block h-6 w-6 rounded-md"
          style={{ backgroundColor: "var(--series-1)" }}
        />
        <span className="text-lg font-semibold text-slate-900">PhishGuard</span>
      </div>
      <ul className="flex flex-wrap gap-1 md:block md:space-y-1">
        {menu.filter((item) => !item.hidden).map((item) => (
          <li key={item.path}>
            <NavLink
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm ${
                  isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                }`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
      <button
        type="button"
        onClick={signOut}
        className="mt-3 rounded-lg px-3 py-2 text-left text-sm text-slate-500 hover:bg-slate-100 hover:text-slate-800 md:mt-auto"
      >
        Sign out
      </button>
    </nav>
  );
}
