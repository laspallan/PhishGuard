import { Navigate, Outlet } from "react-router-dom";

import { loadApiKey } from "@/shared/api/client";

// The dashboard is behind the sign-in page: with no API key in this tab, every in-app route sends
// the visitor to /login. After they sign in, LoginPage navigates back to the overview.
export function RequireAuth() {
  return loadApiKey() ? <Outlet /> : <Navigate to="/login" replace />;
}
