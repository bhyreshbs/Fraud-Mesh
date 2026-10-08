// Display helpers. Rounding happens only in the UI (PRD §4): money is integer paise, times are shown in IST.
const inrFmt = new Intl.NumberFormat("en-IN", { maximumFractionDigits: 0 });

export const inr = (paise: number) => "₹" + inrFmt.format(Math.round(paise / 100));

export const pct = (p: number, digits = 1) => (p * 100).toFixed(digits) + "%";

export const istTime = (iso: string, seconds = false) =>
  new Date(iso).toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit",
    second: seconds ? "2-digit" : undefined, hour12: false });

export const istDateTime = (iso: string | Date) =>
  new Date(iso).toLocaleString("en-GB", { timeZone: "Asia/Kolkata", day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) + " IST";

/** Entity tokens are shown by kind + last 6 chars, e.g. "cust …9b4wd1". */
export const shortToken = (token: string | null | undefined) => {
  if (!token) return "—";
  const [kind, rest = ""] = token.split(":");
  return `${kind} …${rest.slice(-6)}`;
};

export const shortCaseId = (id: string) => id.replace(/^case_/, "").slice(0, 8).toUpperCase();

export const titleCase = (s: string) => s.toLowerCase().replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
