import { Moon, Sun, SwatchBook } from "lucide-react";
import { useState } from "react";
import { setTheme, type Theme } from "../lib/appearance";
import { Panel } from "./ui";

export function Appearance() {
  const [theme, select] = useState<Theme>(() =>
    document.documentElement.dataset.theme === "light" ? "light" : "dark",
  );

  return (
    <Panel title="Appearance" icon={<SwatchBook size={17} />}>
      <div className="appearance-row">
        <div>
          <h3>Interface theme</h3>
          <p className="panel-note">Saved in this browser and applied across the workspace.</p>
        </div>
        <fieldset className="theme-switch" data-value={theme}>
          <legend className="sr-only">Interface theme</legend>
          {(["dark", "light"] as const).map((value) => (
            <label key={value}>
              <input type="radio" name="theme" value={value} checked={theme === value}
                onChange={() => { setTheme(value); select(value); }} />
              {value === "dark" ? <Moon size={16} /> : <Sun size={16} />}
              {value === "dark" ? "Dark" : "Light"}
            </label>
          ))}
        </fieldset>
      </div>
    </Panel>
  );
}
