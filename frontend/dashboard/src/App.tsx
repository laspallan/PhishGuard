// The menu is defined here, not in shared/, because shared code must never import features.
import { Route, Routes } from "react-router-dom";

import { LoginPage } from "@/features/auth";
import { CampaignsPage } from "@/features/campaigns";
import { DetectionsPage } from "@/features/detections";
import { ExperimentsPage } from "@/features/experiments";
import { ModelsPage } from "@/features/models";
import { OverviewPage } from "@/features/overview";
import { SettingsPage } from "@/features/settings";
import { ThreatIntelPage } from "@/features/threat-intel";
import { AppLayout } from "@/shared/components/layout/AppLayout";
import type { MenuItem } from "@/shared/types/navigation";

export const menu: MenuItem[] = [
  { path: "/", label: "Overview", element: <OverviewPage /> },
  { path: "/detections", label: "Detections", element: <DetectionsPage /> },
  { path: "/campaigns", label: "Campaigns", element: <CampaignsPage /> },
  { path: "/models", label: "Models", element: <ModelsPage /> },
  { path: "/experiments", label: "Experiments", element: <ExperimentsPage /> },
  { path: "/threat-intel", label: "Threat Intel", element: <ThreatIntelPage /> },
  { path: "/settings", label: "Settings", element: <SettingsPage /> },
];

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<AppLayout menu={menu} />}>
        {menu.map((item) => (
          <Route key={item.path} path={item.path} element={item.element} />
        ))}
      </Route>
    </Routes>
  );
}
