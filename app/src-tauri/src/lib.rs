//! Desktop-Hülle: startet die Python-Engine als Sidecar und gibt der
//! Oberfläche Adresse und Zugriffstoken.

use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, RunEvent, State};
use tauri_plugin_shell::process::CommandChild;

#[derive(Clone, Serialize)]
struct EngineInfo {
    url: String,
    token: Option<String>,
}

#[derive(Default)]
struct Engine {
    info: Mutex<Option<EngineInfo>>,
    child: Mutex<Option<CommandChild>>,
}

#[tauri::command]
fn engine_info(engine: State<'_, Engine>) -> Result<EngineInfo, String> {
    engine
        .info
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "Engine wurde nicht gestartet".into())
}

/// Entwicklung: Engine läuft separat (`npm run dev:engine`), ohne Token.
#[cfg(debug_assertions)]
fn start_engine(_app: &tauri::AppHandle) -> Result<(EngineInfo, Option<CommandChild>), String> {
    let url = std::env::var("KAC_ENGINE_URL").unwrap_or_else(|_| "http://127.0.0.1:8765".into());
    Ok((EngineInfo { url, token: None }, None))
}

/// Release: mitgeliefertes Engine-Binary auf freiem Port mit zufälligem Token starten.
#[cfg(not(debug_assertions))]
fn start_engine(app: &tauri::AppHandle) -> Result<(EngineInfo, Option<CommandChild>), String> {
    use tauri_plugin_shell::ShellExt;

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(|e| e.to_string())?
        .port();
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;

    let (_events, child) = app
        .shell()
        .sidecar("kac-engine")
        .map_err(|e| e.to_string())?
        .args([
            "serve".to_string(),
            "--port".to_string(),
            port.to_string(),
            "--data-dir".to_string(),
            data_dir.to_string_lossy().into_owned(),
            "--exit-on-stdin-close".to_string(),
        ])
        // Token über die Umgebung statt Kommandozeile, damit es nicht in Prozesslisten steht
        .env("KAC_ENGINE_TOKEN", &token)
        .spawn()
        .map_err(|e| e.to_string())?;

    Ok((
        EngineInfo {
            url: format!("http://127.0.0.1:{port}"),
            token: Some(token),
        },
        Some(child),
    ))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Engine::default())
        .invoke_handler(tauri::generate_handler![engine_info])
        .setup(|app| {
            let (info, child) = start_engine(app.handle())?;
            let engine = app.state::<Engine>();
            *engine.info.lock().unwrap() = Some(info);
            *engine.child.lock().unwrap() = child;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Fehler beim Start der App");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(child) = handle.state::<Engine>().child.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
    });
}
