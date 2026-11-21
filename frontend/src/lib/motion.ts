/**
 * Centralized motion language for the RAVEN-X enterprise console.
 *
 * Design rules:
 * - Brief, directional, interruptible transitions using compositor-friendly
 *   `transform` and `opacity` properties only.
 * - Critically-damped spring tuning (`SPRING_PILL`) reserved for isolated
 *   `layoutId` selection pills so transitions settle briskly without distracting bounce.
 * - Explicit reduced-motion variants replace every spatial transform (`x`, `y`, `scale`)
 *   with a calm opacity cross-fade, paired with root `<MotionConfig reducedMotion="user">`.
 * - Never combine CSS `transition: transform` with Framer Motion transforms on the same node.
 */
import type { Transition, Variants } from "framer-motion";

export const EASE_OUT = [0.22, 1, 0.36, 1] as const;
export const EASE_EXIT = [0.4, 0, 1, 1] as const;

export const MOTION_DURATION = {
  instant: 0.09,
  fast: 0.14,
  normal: 0.18,
  sheet: 0.21,
} as const;

/** Critically-damped spring target for isolated selection indicators (nav/tabs). */
export const SPRING_PILL: Transition = {
  type: "spring",
  stiffness: 520,
  damping: 42,
  mass: 0.85,
};

export const SCRIM_TRANSITION: Transition = {
  duration: MOTION_DURATION.fast,
  ease: EASE_OUT,
};

export function pageVariants(reduced: boolean | null): Variants {
  if (reduced) {
    return {
      initial: { opacity: 0 },
      animate: { opacity: 1, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
      exit: { opacity: 0, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
    };
  }
  return {
    initial: { opacity: 0, y: 6 },
    animate: { opacity: 1, y: 0, transition: { duration: MOTION_DURATION.normal, ease: EASE_OUT } },
    exit: { opacity: 0, y: -4, transition: { duration: MOTION_DURATION.instant, ease: EASE_EXIT } },
  };
}

export function drawerVariants(reduced: boolean | null): Variants {
  if (reduced) {
    return {
      initial: { opacity: 0 },
      animate: { opacity: 1, transition: { duration: MOTION_DURATION.fast, ease: "linear" } },
      exit: { opacity: 0, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
    };
  }
  return {
    initial: { opacity: 0, x: 28 },
    animate: { opacity: 1, x: 0, transition: { duration: MOTION_DURATION.sheet, ease: EASE_OUT } },
    exit: { opacity: 0, x: 24, transition: { duration: MOTION_DURATION.fast, ease: EASE_EXIT } },
  };
}

export function modalVariants(reduced: boolean | null): Variants {
  if (reduced) {
    return {
      initial: { opacity: 0 },
      animate: { opacity: 1, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
      exit: { opacity: 0, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
    };
  }
  return {
    initial: { opacity: 0, scale: 0.975, y: -6 },
    animate: { opacity: 1, scale: 1, y: 0, transition: { duration: MOTION_DURATION.normal, ease: EASE_OUT } },
    exit: { opacity: 0, scale: 0.985, y: -3, transition: { duration: MOTION_DURATION.instant, ease: EASE_EXIT } },
  };
}

export function paletteVariants(reduced: boolean | null): Variants {
  if (reduced) {
    return {
      initial: { opacity: 0 },
      animate: { opacity: 1, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
      exit: { opacity: 0, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
    };
  }
  return {
    initial: { opacity: 0, scale: 0.98, y: -8 },
    animate: { opacity: 1, scale: 1, y: 0, transition: { duration: MOTION_DURATION.fast, ease: EASE_OUT } },
    exit: { opacity: 0, scale: 0.985, y: -4, transition: { duration: MOTION_DURATION.instant, ease: EASE_EXIT } },
  };
}

export function toastVariants(reduced: boolean | null): Variants {
  if (reduced) {
    return {
      initial: { opacity: 0 },
      animate: { opacity: 1, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
      exit: { opacity: 0, transition: { duration: MOTION_DURATION.instant, ease: "linear" } },
    };
  }
  return {
    initial: { opacity: 0, y: 10 },
    animate: { opacity: 1, y: 0, transition: { duration: MOTION_DURATION.normal, ease: EASE_OUT } },
    exit: { opacity: 0, y: 8, transition: { duration: MOTION_DURATION.fast, ease: EASE_EXIT } },
  };
}
