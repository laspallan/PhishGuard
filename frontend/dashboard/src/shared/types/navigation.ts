import type { ReactElement } from "react";

export interface MenuItem {
  path: string;
  label: string;
  element: ReactElement;
}
