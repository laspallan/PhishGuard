import { Outlet } from "react-router-dom";

import type { MenuItem } from "@/shared/types/navigation";

import { Sidebar } from "./Sidebar";

interface AppLayoutProps {
  menu: MenuItem[];
}

export function AppLayout({ menu }: AppLayoutProps) {
  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-900 md:flex-row">
      <Sidebar menu={menu} />
      <main className="min-w-0 flex-1 p-4 md:p-6">
        <Outlet />
      </main>
    </div>
  );
}
