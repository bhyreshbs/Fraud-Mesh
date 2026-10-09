// NammaBank — fictional demo bank (PRD §11.2, port 5174): bank app + /phone/attacker + /phone/priya.
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { IdentityProvider } from "./lib/identity";
import { Home, Kyc, Login, Payees, Security, Transfer } from "./screens/Bank";
import { AttackerPhone, PriyaPhone } from "./screens/Phones";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <IdentityProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/home" element={<Home />} />
          <Route path="/security" element={<Security />} />
          <Route path="/kyc" element={<Kyc />} />
          <Route path="/payees" element={<Payees />} />
          <Route path="/transfer" element={<Transfer />} />
          <Route path="/phone/attacker" element={<AttackerPhone />} />
          <Route path="/phone/priya" element={<PriyaPhone />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    </IdentityProvider>
  </React.StrictMode>,
);
