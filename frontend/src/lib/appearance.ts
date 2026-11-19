export type Theme = "dark" | "light";

const storageKey = "ravenx.appearance";

export function initializeTheme() {
  let theme: Theme = "dark";
  try {
    if (localStorage.getItem(storageKey) === "light") theme = "light";
  } catch {
    // Storage may be disabled in a private browser.
  }
  document.documentElement.dataset.theme = theme;
}

export function setTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(storageKey, theme);
  } catch {
    // Keep the preference for this page lifetime.
  }
}
