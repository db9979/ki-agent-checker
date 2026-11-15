/** Öffnet eine Adresse im Standardbrowser (in der Desktop-App über das Shell-Plugin). */
export async function openLink(url: string): Promise<void> {
  if (!/^https?:\/\//.test(url)) return;
  if ("__TAURI_INTERNALS__" in window) {
    const { open } = await import("@tauri-apps/plugin-shell");
    await open(url);
  } else {
    window.open(url, "_blank", "noopener");
  }
}
