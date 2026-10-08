import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./components/Shell";
import { useAuth } from "./lib/auth";
import { Login } from "./screens/Login";
import { CasePage } from "./screens/CasePage";
import { Detectors } from "./screens/Detectors";
import { Metrics } from "./screens/Metrics";
import { Placeholder } from "./screens/Placeholder";
import { Queue } from "./screens/Queue";
import { SystemStatus } from "./screens/SystemStatus";

function Protected({ crumb, children }: { crumb: string; children: ReactNode }) {
  const { session, ready } = useAuth();
  const location = useLocation();
  if (!ready) return <div className="p-8 text-on-surface-variant">Restoring session…</div>;
  if (!session) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Shell crumb={crumb}>{children}</Shell>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/queue" element={<Protected crumb="Case queue"><Queue /></Protected>} />
      <Route path="/cases/:id" element={<Protected crumb="Case investigation"><CasePage /></Protected>} />
      <Route path="/detectors" element={<Protected crumb="Detectors"><Detectors /></Protected>} />
      <Route path="/metrics" element={<Protected crumb="Metrics and simulator"><Metrics /></Protected>} />
      <Route path="/demo" element={<Protected crumb="Demo control">
        <Placeholder title="Demo control" phase="D1-P5 (scenario picker, speed, Run, Reset)" /></Protected>} />
      <Route path="/status" element={<Protected crumb="System status"><SystemStatus /></Protected>} />
      <Route path="*" element={<Navigate to="/queue" replace />} />
    </Routes>
  );
}
