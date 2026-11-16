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
    /// Letzte Ausgaben des Sidecars, damit Startfehler in der Oberfläche sichtbar sind
    log: std::sync::Arc<Mutex<Vec<String>>>,
}

#[tauri::command]
fn engine_log(engine: State<'_, Engine>) -> Vec<String> {
    engine.log.lock().map(|l| l.clone()).unwrap_or_default()
}

/// Beendet die Engine vor der Installation eines Updates, damit der Installer
/// (vor allem unter Windows) ihre Datei ersetzen kann.
#[tauri::command]
fn stop_engine(engine: State<'_, Engine>) {
    if let Some(child) = engine.child.lock().ok().and_then(|mut c| c.take()) {
        let _ = child.kill();
    }
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
fn start_engine(
    _app: &tauri::AppHandle,
    _log: std::sync::Arc<Mutex<Vec<String>>>,
) -> Result<(EngineInfo, Option<CommandChild>), String> {
    let url = std::env::var("KAC_ENGINE_URL").unwrap_or_else(|_| "http://127.0.0.1:8765".into());
    Ok((EngineInfo { url, token: None }, None))
}

/// Release: mitgeliefertes Engine-Binary auf freiem Port mit zufälligem Token starten.
#[cfg(not(debug_assertions))]
fn start_engine(
    app: &tauri::AppHandle,
    log: std::sync::Arc<Mutex<Vec<String>>>,
) -> Result<(EngineInfo, Option<CommandChild>), String> {
    use tauri_plugin_shell::{process::CommandEvent, ShellExt};

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(|e| e.to_string())?
        .port();
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;

    let (mut events, child) = app
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

    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            let line = match event {
                CommandEvent::Stdout(b) | CommandEvent::Stderr(b) => {
                    String::from_utf8_lossy(&b).trim_end().to_string()
                }
                CommandEvent::Error(e) => format!("Fehler: {e}"),
                CommandEvent::Terminated(p) => {
                    format!("Engine beendet (Code {:?}, Signal {:?})", p.code, p.signal)
                }
                _ => continue,
            };
            if let Ok(mut l) = log.lock() {
                l.push(line);
                let len = l.len();
                if len > 200 {
                    l.drain(..len - 200);
                }
            }
        }
    });

    Ok((
        EngineInfo {
            url: format!("http://127.0.0.1:{port}"),
            token: Some(token),
        },
        Some(child),
    ))
}

/// Auf kleinen Bildschirmen (z. B. uConsole mit 1280×720) maximiert starten,
/// statt ein 1440×900-Fenster über den Rand ragen zu lassen.
fn fit_small_screens(app: &tauri::App) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    if let Ok(Some(monitor)) = window.current_monitor() {
        let size = monitor.size().to_logical::<f64>(monitor.scale_factor());
        if size.width < 1500.0 || size.height < 960.0 {
            let _ = window.maximize();
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(Engine::default())
        .invoke_handler(tauri::generate_handler![engine_info, engine_log, stop_engine])
        .setup(|app| {
            let engine = app.state::<Engine>();
            let (info, child) = start_engine(app.handle(), engine.log.clone())?;
            *engine.info.lock().unwrap() = Some(info);
            *engine.child.lock().unwrap() = child;
            fit_small_screens(app);
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
