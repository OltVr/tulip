import { BrowserRouter, Routes, Route, Outlet } from "react-router-dom";
import { lazy, Suspense } from "react";
import { useHotkeys } from 'react-hotkeys-hook';

import "./App.css";
import { Header } from "./components/Header";
import { FlowList } from "./components/FlowList";

const TriageView = lazy(() =>
  import("./pages/TriageView").then((module) => ({ default: module.TriageView }))
);
const Home = lazy(() =>
  import("./pages/Home").then((module) => ({ default: module.Home }))
);
const FlowView = lazy(() =>
  import("./pages/FlowView").then((module) => ({ default: module.FlowView }))
);
const DiffView = lazy(() =>
  import("./pages/DiffView").then((module) => ({ default: module.DiffView }))
);
const Corrie = lazy(() =>
  import("./components/Corrie").then((module) => ({ default: module.Corrie }))
);

function App() {
  useHotkeys('esc', () => (document.activeElement as HTMLElement).blur(), {enableOnFormTags: true});
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Suspense><TriageView /></Suspense>} />
          <Route path="help" element={<Suspense><Home /></Suspense>} />
          <Route
            path="flow/:id"
            element={
              <Suspense>
                <FlowView />
              </Suspense>
            }
          />
          <Route
            path="diff/:id"
            element={
              <Suspense>
                <DiffView />
              </Suspense>
            }
          />
          <Route
            path="corrie/"
            element={
              <Suspense>
                <Corrie />
              </Suspense>
            }
          />
        </Route>
        <Route path="*" element={<PageNotFound />} />
      </Routes>
    </BrowserRouter>
  );
}

function Layout() {
  return (
    <div className="grid-container">
      <header className="header-area">
        <div className="header">
          <Header></Header>
        </div>
      </header>
      <aside className="flow-list-area">
        <Suspense>
          <FlowList></FlowList>
        </Suspense>
      </aside>
      <main className="flow-details-area">
        <Outlet />
      </main>
      <footer className="footer-area"></footer>
    </div>
  );
}


function PageNotFound() {
  return (
    <div>
      <h2>404 Page not found</h2>
    </div>
  );
}

export default App;
