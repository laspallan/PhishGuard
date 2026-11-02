import { Outlet } from "react-router-dom";

import type { MenuItem } from "@/shared/types/navigation";

import { Sidebar } from "./Sidebar";

interface AppLayoutProps {
  menu: MenuItem[];
}

export function AppLayout({ menu }: AppLayoutProps) {
  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <Sidebar menu={menu} />
      <main className="flex-1 p-6">
        <Outlet />
      </main>
    </div>
  );
}
