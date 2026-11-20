import { useEffectEvent, useLayoutEffect, useRef } from "react";

const focusableSelector = [
  "a[href]", "button", "input:not([type=hidden])", "select", "textarea",
  "details > summary:first-of-type", "[tabindex]", "[contenteditable=true]",
].join(", ");

const dialogs: HTMLElement[] = [];
let restoreBackground: (() => void) | undefined;

function activeDialog() {
  return dialogs.at(-1);
}

function updateBackground() {
  restoreBackground?.();
  const covered: Element[] = [];

  for (let branch: Element | undefined | null = activeDialog(); branch?.parentElement; branch = branch.parentElement) {
    if (branch === document.body) break;
    for (const sibling of branch.parentElement.children) {
      if (sibling !== branch && !sibling.hasAttribute("inert")) {
        sibling.setAttribute("inert", "");
        covered.push(sibling);
      }
    }
  }

  restoreBackground = () => covered.forEach((element) => element.removeAttribute("inert"));
}

function focusStops(dialog: HTMLElement) {
  return Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector)).filter((element) =>
    !element.matches(":disabled") && !element.closest("[inert], [hidden]") &&
    element.getClientRects().length > 0 && getComputedStyle(element).visibility === "visible" &&
    // A details summary is tabbable even on browsers where its tabIndex is -1.
    (element.tabIndex >= 0 || element.matches("summary:not([tabindex])")),
  );
}

export function useDialogFocus<T extends HTMLElement>(open: boolean, onClose: () => void) {
  const ref = useRef<T>(null);
  const close = useEffectEvent(onClose);

  useLayoutEffect(() => {
    const dialog = ref.current;
    if (!open || !dialog) return;

    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialog.inert = false;
    dialogs.push(dialog);
    updateBackground();

    const focusStart = () => (focusStops(dialog)[0] ?? dialog).focus({ preventScroll: true });
    const keepFocusInside = (event: FocusEvent) => {
      if (activeDialog() === dialog && event.target instanceof Node && !dialog.contains(event.target)) {
        focusStart();
      }
    };
    const handleKey = (event: KeyboardEvent) => {
      if (activeDialog() !== dialog || event.defaultPrevented) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        close();
      } else if (event.key === "Tab") {
        const stops = focusStops(dialog);
        const first = stops[0];
        const last = stops.at(-1);
        const current = document.activeElement;
        if (!first || current === dialog || !dialog.contains(current) ||
            (event.shiftKey ? current === first : current === last)) {
          event.preventDefault();
          (event.shiftKey ? last ?? dialog : first ?? dialog).focus();
        }
      }
    };
    document.addEventListener("keydown", handleKey);
    document.addEventListener("focusin", keepFocusInside);
    focusStart();

    return () => {
      document.removeEventListener("keydown", handleKey);
      document.removeEventListener("focusin", keepFocusInside);
      const wasActive = activeDialog() === dialog;
      dialogs.splice(dialogs.indexOf(dialog), 1);
      updateBackground();
      // Framer Motion keeps the closing dialog mounted during its exit animation.
      dialog.inert = true;
      if (!wasActive) return;
      const next = activeDialog();
      if (opener?.isConnected && (!next || next.contains(opener))) {
        opener.focus({ preventScroll: true });
      } else if (next) {
        (focusStops(next)[0] ?? next).focus({ preventScroll: true });
      }
    };
  }, [open]);

  return ref;
}
