// The menu is defined here, not in shared/, because shared code must never import features.
import { Route, Routes } from "react-router-dom";

import { LoginPage } from "@/features/auth";
import { CampaignsPage, SimulationPage } from "@/features/campaigns";
import { DetectionsPage } from "@/features/detections";
import { ExperimentsPage } from "@/features/experiments";
import { ModelsPage } from "@/features/models";
import { OverviewPage } from "@/features/overview";
import { SettingsPage } from "@/features/settings";
import { ThreatIntelPage } from "@/features/threat-intel";
import { AppLayout } from "@/shared/components/layout/AppLayout";
import { RequireAuth } from "@/shared/components/layout/RequireAuth";
import type { MenuItem } from "@/shared/types/navigation";

export const menu: MenuItem[] = [
  { path: "/", label: "Overview", element: <OverviewPage /> },
  { path: "/detections", label: "Detections", element: <DetectionsPage /> },
  // Hidden until they carry live data: Campaigns fills after Round 1, Experiments after RQ3.
  // Routes stay reachable; they are only left out of the sidebar (see MenuItem.hidden).
  { path: "/campaigns", label: "Campaigns", element: <CampaignsPage />, hidden: true },
  { path: "/simulation", label: "Simulation", element: <SimulationPage /> },
  { path: "/models", label: "Models", element: <ModelsPage /> },
  { path: "/experiments", label: "Experiments", element: <ExperimentsPage />, hidden: true },
  { path: "/threat-intel", label: "Threat Intel", element: <ThreatIntelPage /> },
  { path: "/settings", label: "Settings", element: <SettingsPage /> },
];

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppLayout menu={menu} />}>
          {menu.map((item) => (
            <Route key={item.path} path={item.path} element={item.element} />
          ))}
        </Route>
      </Route>
    </Routes>
  );
}
