// NammaBank — fictional demo bank (PRD §11.2). Scaffold only: identity switcher, screens and phones arrive in D1-P3.
import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";

function App() {
  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-white border border-border-default rounded-lg p-7">
        <div className="flex items-center gap-2 mb-4">
          <span className="material-symbols-outlined text-brand">account_balance</span>
          <span className="font-semibold text-[18px]">NammaBank</span>
          <span className="ml-auto text-[11px] px-2 py-0.5 rounded-lg bg-surface-container text-on-surface-variant">FICTIONAL DEMO</span>
        </div>
        <p className="text-[13px] text-text-secondary">
          The demo bank app (login, security, KYC, payees, transfer, OTP modal) and the two simulated phones
          (<span className="font-mono">/phone/attacker</span>, <span className="font-mono">/phone/priya</span>) are built in phase D1-P3.
        </p>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
