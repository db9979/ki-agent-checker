/** Selbst-Update der Desktop-App über den Tauri-Updater (signierte Pakete aus dem GitHub-Release). */
import type { Update } from "@tauri-apps/plugin-updater";

export const isDesktop = () => "__TAURI_INTERNALS__" in window;

/** Liefert das Update, wenn die App sich selbst aktualisieren kann; sonst null (dann Download-Hinweis). */
export async function findSelfUpdate(): Promise<Update | null> {
  if (!isDesktop()) return null;
  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    return await check();
  } catch {
    return null; // z. B. kein signiertes Paket für dieses System
  }
}

/** Lädt, beendet die Engine, installiert und startet neu. onProgress bekommt 0..1 (oder null, wenn unbekannt). */
export async function installUpdate(update: Update, onProgress: (p: number | null) => void): Promise<void> {
  let total = 0;
  let done = 0;
  await update.download((e) => {
    if (e.event === "Started") total = e.data.contentLength ?? 0;
    if (e.event === "Progress") {
      done += e.data.chunkLength;
      onProgress(total ? done / total : null);
    }
  });
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("stop_engine");
  await update.install(); // Windows beendet die App hier selbst
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
