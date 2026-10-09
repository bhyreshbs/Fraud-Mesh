// Fixed layer behind every screen. three.js is only fetched with this lazy chunk; the CSS gradient on .fm-backdrop
// shows until the shader is ready, and stays if WebGL is unavailable.
import { lazy, Suspense } from "react";

const ShaderBackdrop = lazy(() => import("./ShaderBackdrop"));

export function Backdrop() {
  return (
    <div className="fm-backdrop" aria-hidden="true" data-testid="backdrop">
      <Suspense fallback={null}><ShaderBackdrop /></Suspense>
    </div>
  );
}
