import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./components/Shell";
import { useAuth } from "./lib/auth";
import { Login } from "./screens/Login";
import { CasePage } from "./screens/CasePage";
import { Demo } from "./screens/Demo";
import { Detectors } from "./screens/Detectors";
import { Metrics } from "./screens/Metrics";
import { Twin } from "./screens/Twin";
import { Queue } from "./screens/Queue";
import { SystemStatus } from "./screens/SystemStatus";
import { Overview } from "./screens/Overview";
import { Investigations } from "./screens/Investigations";
import { Settings } from "./screens/Settings";

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
      <Route path="/overview" element={<Protected crumb="Overview"><Overview /></Protected>} />
      <Route path="/queue" element={<Protected crumb="Case Queue"><Queue /></Protected>} />
      <Route path="/investigations" element={<Protected crumb="Investigations"><Investigations /></Protected>} />
      <Route path="/investigations/:id" element={<Protected crumb="Investigations"><Investigations /></Protected>} />
      <Route path="/cases/:id" element={<Protected crumb="Case workbench"><CasePage /></Protected>} />
      <Route path="/detectors" element={<Protected crumb="Detection Engine"><Detectors /></Protected>} />
      <Route path="/metrics" element={<Protected crumb="Metrics & Analytics"><Metrics /></Protected>} />
      <Route path="/twin" element={<Protected crumb="Digital Twin"><Twin /></Protected>} />
      <Route path="/demo" element={<Protected crumb="Demo Simulator"><Demo /></Protected>} />
      <Route path="/status" element={<Protected crumb="System Health"><SystemStatus /></Protected>} />
      <Route path="/settings" element={<Protected crumb="Settings"><Settings /></Protected>} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
