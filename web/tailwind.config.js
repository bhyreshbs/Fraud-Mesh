// Theme copied from the Stitch export (Stitch FM Design/code/*.html, tailwind-config) plus the DESIGN.md risk tokens.
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        error: "#ba1a1a", "error-container": "#ffdad6", "on-secondary": "#ffffff", "secondary-fixed": "#dce2f7",
        "on-secondary-fixed-variant": "#404758", "surface-container-lowest": "#ffffff", "on-error": "#ffffff",
        "on-surface-variant": "#434653", "surface-container-highest": "#d9e3f4", tertiary: "#7a2f00", secondary: "#575e70",
        "on-background": "#121c28", "surface-container": "#e5eeff", "primary-fixed": "#dbe1ff", outline: "#737685",
        primary: "#003fa4", "surface-dim": "#d1dbec", background: "#f8f9ff", "on-tertiary-fixed": "#351000", surface: "#f8f9ff",
        "tertiary-container": "#a04000", "on-secondary-container": "#5c6274", "surface-container-low": "#eef4ff",
        "primary-container": "#2457c5", "surface-container-high": "#dfe9fa", "on-secondary-fixed": "#141b2b",
        "on-primary-fixed": "#001849", "surface-variant": "#d9e3f4", "tertiary-fixed": "#ffdbcc", "on-error-container": "#93000a",
        "on-surface": "#121c28", "on-tertiary-fixed-variant": "#7b2f00", "inverse-on-surface": "#eaf1ff",
        "secondary-container": "#d9dff5", "secondary-fixed-dim": "#c0c6db", "surface-bright": "#f8f9ff",
        "primary-fixed-dim": "#b3c5ff", "surface-tint": "#2457c5", "outline-variant": "#c3c6d5", "inverse-primary": "#b3c5ff",
        "on-tertiary": "#ffffff", "tertiary-fixed-dim": "#ffb694", "on-primary-container": "#ccd7ff",
        "on-tertiary-container": "#ffcdb7", "inverse-surface": "#27313e", "on-primary-fixed-variant": "#003fa5", "on-primary": "#ffffff",
        // DESIGN.md: canvas, borders, text tiers, brand, risk severities
        canvas: "#F5F6F8", "border-default": "#E2E5E9", "slate-rail": "#111827",
        "text-primary": "#111827", "text-secondary": "#4B5563", "text-tertiary": "#6B7280",
        brand: { DEFAULT: "#2457C5", hover: "#1D46A0", pressed: "#163782" },
        risk: {
          critical: "#B42318", "critical-fill": "#FEF3F2", "critical-border": "#FECDCA",
          high: "#B54708", "high-fill": "#FFF4E5", "high-border": "#FEDF89",
          medium: "#946200", "medium-fill": "#FEF7E0", "medium-border": "#FCEEAA",
          low: "#1E6B45", "low-fill": "#ECFDF3", "low-border": "#A6F4C5",
        },
      },
      borderRadius: { DEFAULT: "0.125rem", lg: "0.25rem", xl: "0.5rem", full: "0.75rem" },
      spacing: {
        "space-xs": "0.25rem", "gutter-compact": "0.5rem", "space-sm": "0.5rem", "space-xl": "2rem", "margin-panel": "1rem",
        "space-base": "1rem", "space-md": "0.75rem", "space-2xs": "0.125rem", gutter: "1rem", margin: "1.5rem", "space-lg": "1.5rem",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"], mono: ["JetBrains Mono", "ui-monospace", "monospace"],
        "code-sm": ["JetBrains Mono", "monospace"], "headline-xl": ["Inter"], "body-xs": ["Inter"], "code-xs": ["JetBrains Mono", "monospace"],
        "body-sm": ["Inter"], "headline-lg": ["Inter"], "body-md": ["Inter"], "headline-md": ["Inter"], "tabular-metric": ["Inter"],
        "label-caps": ["Inter"], "label-md": ["Inter"], "headline-sm": ["Inter"],
      },
      fontSize: {
        "code-sm": ["12px", { lineHeight: "16px", letterSpacing: "-0.01em", fontWeight: "400" }],
        "headline-xl": ["24px", { lineHeight: "32px", letterSpacing: "-0.02em", fontWeight: "600" }],
        "body-xs": ["12px", { lineHeight: "16px", letterSpacing: "0em", fontWeight: "400" }],
        "code-xs": ["11px", { lineHeight: "14px", letterSpacing: "0em", fontWeight: "400" }],
        "body-sm": ["13px", { lineHeight: "18px", letterSpacing: "0em", fontWeight: "400" }],
        "headline-lg": ["20px", { lineHeight: "28px", letterSpacing: "-0.015em", fontWeight: "600" }],
        "body-md": ["14px", { lineHeight: "20px", letterSpacing: "0em", fontWeight: "400" }],
        "headline-md": ["16px", { lineHeight: "24px", letterSpacing: "-0.01em", fontWeight: "600" }],
        "tabular-metric": ["14px", { lineHeight: "20px", letterSpacing: "0em", fontWeight: "500" }],
        "label-caps": ["11px", { lineHeight: "16px", letterSpacing: "0.04em", fontWeight: "600" }],
        "label-md": ["12px", { lineHeight: "16px", letterSpacing: "0.01em", fontWeight: "500" }],
        "headline-sm": ["14px", { lineHeight: "20px", letterSpacing: "-0.005em", fontWeight: "600" }],
      },
    },
  },
  plugins: [],
};
