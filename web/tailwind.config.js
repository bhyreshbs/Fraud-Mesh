// Theme: Stitch "Warm Neumorphic Glass" (stitch_fraudmesh_enterprise_intelligence_platform/warm_neumorphic_glass/DESIGN.md
// and the tailwind-config of its code.html screens). Token names are unchanged from the first Stitch theme, so every
// screen picks up the warm porcelain palette; risk tokens follow DESIGN.md "Threat & Risk Classification".
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // surfaces: warm ivory canvas -> porcelain cards -> champagne wells
        background: "#F7F3ED", surface: "#F7F3ED", "surface-bright": "#FFF8F4", "surface-dim": "#E8D7C7",
        "surface-container-lowest": "#FFFEFC", "surface-container-low": "#FBF4EC", "surface-container": "#F3E9DD",
        "surface-container-high": "#EEE2D4", "surface-container-highest": "#E9DED0", "surface-variant": "#F1E0CF",
        // text
        "on-surface": "#292622", "on-background": "#292622", "on-surface-variant": "#756D64",
        "inverse-surface": "#382F24", "inverse-on-surface": "#FFEEDE",
        // lines
        outline: "#A1988D", "outline-variant": "#E6D9CA",
        // brand: burnt orange actions, terracotta pressed
        primary: "#A94D29", "primary-container": "#D96B35", "on-primary": "#FFFEFC", "on-primary-container": "#FFFBFF",
        "primary-fixed": "#FCE5D3", "primary-fixed-dim": "#F8B77D", "on-primary-fixed": "#5A2408", "on-primary-fixed-variant": "#7C2E00",
        "inverse-primary": "#FFB596", "surface-tint": "#D96B35",
        secondary: "#984800", "on-secondary": "#FFFFFF", "secondary-container": "#FCE5D3", "on-secondary-container": "#6B3100",
        "secondary-fixed": "#FFDBC7", "secondary-fixed-dim": "#FFB689", "on-secondary-fixed": "#311300", "on-secondary-fixed-variant": "#733500",
        tertiary: "#7F5300", "on-tertiary": "#FFFFFF", "tertiary-container": "#A06900", "on-tertiary-container": "#FFFBFF",
        "tertiary-fixed": "#FFDDB3", "tertiary-fixed-dim": "#FFB951", "on-tertiary-fixed": "#291800", "on-tertiary-fixed-variant": "#633F00",
        error: "#BA1A1A", "on-error": "#FFFFFF", "error-container": "#FFDAD6", "on-error-container": "#93000A",
        // DESIGN.md named tokens
        canvas: "#F7F3ED", "border-default": "#E6D9CA", "slate-rail": "#292622",
        "text-primary": "#292622", "text-secondary": "#756D64", "text-tertiary": "#A1988D",
        brand: { DEFAULT: "#D96B35", hover: "#F28B42", pressed: "#A94D29", apricot: "#F8B77D", peach: "#FCE5D3" },
        porcelain: "#FFFEFC", cream: "#F1E9DF", champagne: "#E9DED0", taupe: "#B8A99A",
        risk: {
          critical: "#D03B29", "critical-fill": "#FBE6E2", "critical-border": "#F2BFB6",
          high: "#C25A26", "high-fill": "#FCE5D3", "high-border": "#F8B77D",
          medium: "#A8700F", "medium-fill": "#FBEFD6", "medium-border": "#EFD196",
          low: "#3A8A5B", "low-fill": "#E3F1E8", "low-border": "#B5D9C3",
          info: "#5C7080",
        },
      },
      borderRadius: { DEFAULT: "0.5rem", lg: "0.875rem", xl: "1.25rem", "2xl": "1.5rem", full: "9999px" },
      boxShadow: {
        porcelain: "6px 6px 16px rgba(184, 169, 154, 0.22), -6px -6px 16px rgba(255, 255, 255, 0.9)",
        "porcelain-sm": "3px 3px 10px rgba(184, 169, 154, 0.18), -3px -3px 10px rgba(255, 255, 255, 0.95)",
        float: "10px 10px 28px rgba(184, 169, 154, 0.35), -10px -10px 24px rgba(255, 255, 255, 0.95)",
        sunken: "inset 2px 2px 5px rgba(184, 169, 154, 0.28), inset -2px -2px 5px rgba(255, 255, 255, 0.9)",
        "btn-primary": "4px 4px 10px rgba(169, 77, 41, 0.35), -2px -2px 6px rgba(255, 255, 255, 0.8)",
        glass: "inset 0 1px 1px rgba(255, 255, 255, 0.9), 0 8px 24px rgba(184, 169, 154, 0.2)",
      },
      spacing: {
        "space-xs": "0.25rem", "gutter-compact": "0.5rem", "space-sm": "0.5rem", "space-xl": "2.5rem", "margin-panel": "1rem",
        "space-base": "1.5rem", "space-md": "1rem", "space-2xs": "0.125rem", gutter: "1.5rem", margin: "2rem", "space-lg": "1.5rem",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"], mono: ["JetBrains Mono", "ui-monospace", "monospace"],
        "code-sm": ["JetBrains Mono", "monospace"], "headline-xl": ["Inter"], "body-xs": ["Inter"], "code-xs": ["JetBrains Mono", "monospace"],
        "body-sm": ["Inter"], "headline-lg": ["Inter"], "body-md": ["Inter"], "headline-md": ["Inter"], "tabular-metric": ["Inter"],
        "label-caps": ["JetBrains Mono", "monospace"], "label-md": ["Inter"], "headline-sm": ["Inter"],
      },
      fontSize: {
        "display-lg": ["40px", { lineHeight: "46px", letterSpacing: "-0.03em", fontWeight: "600" }],
        "code-sm": ["12.5px", { lineHeight: "17px", letterSpacing: "-0.005em", fontWeight: "500" }],
        "headline-xl": ["32px", { lineHeight: "40px", letterSpacing: "-0.025em", fontWeight: "600" }],
        "body-xs": ["12px", { lineHeight: "17px", letterSpacing: "0.005em", fontWeight: "400" }],
        "code-xs": ["11px", { lineHeight: "15px", letterSpacing: "0.02em", fontWeight: "500" }],
        "body-sm": ["13px", { lineHeight: "20px", letterSpacing: "0.005em", fontWeight: "400" }],
        "headline-lg": ["24px", { lineHeight: "32px", letterSpacing: "-0.02em", fontWeight: "600" }],
        "body-md": ["15px", { lineHeight: "24px", letterSpacing: "0em", fontWeight: "400" }],
        "headline-md": ["18px", { lineHeight: "26px", letterSpacing: "-0.015em", fontWeight: "600" }],
        "tabular-metric": ["14px", { lineHeight: "20px", letterSpacing: "0em", fontWeight: "500" }],
        "label-caps": ["11px", { lineHeight: "16px", letterSpacing: "0.08em", fontWeight: "500" }],
        "label-md": ["12.5px", { lineHeight: "16px", letterSpacing: "0.01em", fontWeight: "500" }],
        "headline-sm": ["15px", { lineHeight: "22px", letterSpacing: "-0.01em", fontWeight: "600" }],
      },
    },
  },
  plugins: [],
};
