export type Theme = "dark" | "light";

const storageKey = "ravenx.appearance";
const THEME_META_COLOR: Record<Theme, string> = {
  dark: "#0d1014",
  light: "#f6f7f9",
};

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (meta) meta.content = THEME_META_COLOR[theme];
}

export function initializeTheme() {
  let theme: Theme = "dark";
  try {
    if (localStorage.getItem(storageKey) === "light") theme = "light";
  } catch {
    // Storage may be disabled in a private browser.
  }
  applyTheme(theme);
}

export function setTheme(theme: Theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(storageKey, theme);
  } catch {
    // Keep the preference for this page lifetime.
  }
}
