# PhishGuard dashboard

React + Vite + TypeScript + Tailwind admin dashboard. Pages are built in Phase 8; Phase 0
provides the structure, the menu and one placeholder page per menu item.

## Structure (feature-based)

```
src/
  main.tsx  App.tsx        entry point; App.tsx defines the menu and routes
  features/                one folder per menu item
    overview/ detections/ campaigns/ models/ experiments/ threat-intel/ settings/ auth/
  shared/                  everything used by more than one feature
    components/  api/  hooks/  utils/  types/
```

Inside a feature folder:

```
features/<name>/
  pages/       the page the menu opens
  components/  components used only by this feature
  api/         backend calls for this feature (through shared/api/client.ts)
  hooks/
  types.ts
  index.ts     the only file other code imports from
```

Folders are added inside a feature when it first needs them.

**Import rule:** a feature may import from `shared/`, never from another feature, and
`shared/` never imports a feature. `src/structure.test.ts` fails if this rule is broken.

**Adding a menu item:** create `features/<name>/pages/<Name>Page.tsx` and
`features/<name>/index.ts`, then add one line to `menu` in `App.tsx`.

## Run (PowerShell, from `frontend/dashboard/`)

```powershell
npm install
Copy-Item .env.example .env.local
npm run dev        # http://localhost:5173
npm test           # vitest
npm run typecheck
npm run build
```
