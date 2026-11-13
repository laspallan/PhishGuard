import type { ReactElement } from "react";

export interface MenuItem {
  path: string;
  label: string;
  element: ReactElement;
  /** Keep the route but leave it out of the sidebar (a page with no live data yet). */
  hidden?: boolean;
}
