import { NavLink } from "react-router-dom";

import type { MenuItem } from "@/shared/types/navigation";

interface SidebarProps {
  menu: MenuItem[];
}

export function Sidebar({ menu }: SidebarProps) {
  return (
    <nav
      aria-label="Main menu"
      className="shrink-0 border-b border-slate-200 bg-white p-4 md:w-56 md:border-r md:border-b-0"
    >
      <p className="mb-3 text-lg font-semibold md:mb-6">PhishGuard</p>
      <ul className="flex flex-wrap gap-1 md:block md:space-y-1">
        {menu.map((item) => (
          <li key={item.path}>
            <NavLink
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `block rounded px-3 py-2 text-sm ${
                  isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                }`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
