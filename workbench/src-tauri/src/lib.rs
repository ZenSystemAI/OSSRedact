// OSSRedact desktop shell (Tauri v2).
//
// This wraps the EXISTING Vite frontend (built into ../dist) as a tray-resident native app -- the
// "firewall console" that lives in the system tray (the standard tray-app pattern): minimize-to-tray, autostart
// on login, a small window you pop open to inspect the firewall.
//
// What this shell does NOT do: it does not embed or run the Python egress daemon. The daemon is a
// SEPARATE long-lived service (systemd unit / the existing deploy units). This app merely CONNECTS to
// it over loopback. The webview is told where the daemon lives by injecting `window.__OSSREDACT_DAEMON__`
// (read by workbench/src/lib/daemon.ts::daemonBase) via a window initialization script -- so the
// bundled frontend talks to the local egress without any code change in the frontend.

use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::WebviewWindowBuilder,
    AppHandle, Manager, WindowEvent,
};
use tauri_plugin_autostart::MacosLauncher;

/// Loopback base for the always-on egress daemon's control API (allowlist / live-activity SSE /
/// healthz). Injected into the webview so the bundled frontend (daemon.ts) talks to the local egress.
/// The egress daemon binds this port as a separate service; the shell only connects.
const DAEMON_BASE: &str = "http://127.0.0.1:8011";

/// Label of the main app window. Must match the window `label` declared in tauri.conf.json (the
/// window is built FROM that config in setup(), so its sizing/title live in one place).
const MAIN_WINDOW: &str = "main";

// Tray menu item ids. Matched in the on_menu_event handler below.
const MENU_SHOW: &str = "show";
const MENU_HIDE: &str = "hide";
const MENU_STATUS: &str = "status";
const MENU_QUIT: &str = "quit";

/// The webview initialization script. It runs after the global object is created but BEFORE the
/// HTML document is parsed (and thus before the frontend's own scripts), so
/// `window.__OSSREDACT_DAEMON__` is defined by the time daemon.ts::daemonBase() reads it.
/// daemonBase() trims a trailing slash and prefixes it onto `/api/*` and `/healthz`, so the
/// console issues requests to e.g. http://127.0.0.1:8011/api/allowlist.
fn daemon_init_script() -> String {
    // {DAEMON_BASE:?} emits a JSON/JS string literal (quoted, escaped) -- safe to embed in JS.
    format!("window.__OSSREDACT_DAEMON__ = {DAEMON_BASE:?};")
}

/// Show + focus the main window (the window already exists -- just hidden -- so this only reveals it).
fn show_main(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN_WINDOW) {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

/// Hide the main window to the tray (the firewall console stays resident in the background).
fn hide_main(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN_WINDOW) {
        let _ = win.hide();
    }
}

// ---------------------------------------------------------------------------------------------------
// TODO(daemon-supervision): hook point for managing the egress daemon lifecycle from the shell.
//
// Today the daemon is a SEPARATE long-lived service (systemd / the deploy units) and this app only
// CONNECTS to it (see DAEMON_BASE). When we later want the tray app to optionally supervise the
// daemon (spawn it if absent, poll /healthz, restart on crash, surface status in the tray label),
// implement it here. Deliberately NOT implemented now -- no process spawning happens in this build.
//
// Sketch of the eventual shape (do NOT wire up yet):
//   - ensure_daemon_running(app): if `GET {DAEMON_BASE}/healthz` fails, start the configured daemon
//     command (a tauri_plugin_shell sidecar or a system service handle) and wait for it to answer.
//   - watch_daemon_health(app): background task polling /healthz on an interval, updating the tray
//     "Firewall: <status>" label (Healthy / Unreachable) and optionally restarting on repeated failure.
//   - stop_daemon_on_quit(): only if the shell OWNS the process (it does not, in the service model).
//
// Until this is implemented, the daemon must already be running for the console tabs to populate;
// the frontend (daemon.ts) already degrades gracefully when the daemon is unreachable.
#[allow(dead_code)]
fn supervise_daemon_todo(_app: &AppHandle) {
    // Intentionally empty. See the TODO above.
}
// ---------------------------------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Single-instance MUST be the first plugin registered: on a second launch it fires this
        // callback in the ALREADY-RUNNING instance (then the new process exits), so we focus the
        // existing window instead of opening a duplicate.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app);
        }))
        // Autostart: launch on login. Registered disabled by default so first run does not silently
        // add a login item; the Settings UI can enable it via the autostart JS/Rust API. The
        // MacosLauncher argument is required by the plugin signature; the trailing args are the CLI
        // args passed to the binary when auto-launched (none needed -- it starts hidden to tray).
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![]),
        ))
        .setup(|app| {
            // --- Main window ------------------------------------------------------------------
            // Build the window FROM its tauri.conf.json definition (sizing/title/visible live there),
            // then attach the daemon-base init script. The config sets `"create": false` so Tauri does
            // NOT auto-create this window -- we create it here so we can inject
            // `window.__OSSREDACT_DAEMON__` before the frontend scripts run. The config also sets
            // `"visible": false`, so it starts hidden to the tray; the tray/menu reveals it.
            let win_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|w| w.label == MAIN_WINDOW)
                .expect("main window must be declared in tauri.conf.json")
                .clone();
            WebviewWindowBuilder::from_config(app, &win_config)?
                .initialization_script(daemon_init_script())
                .build()?;

            // --- Tray menu --------------------------------------------------------------------
            // A static "Firewall: <status>" label (disabled -- it is informational, not clickable).
            // The daemon-supervision TODO above is where this would be made live.
            let show_i = MenuItem::with_id(app, MENU_SHOW, "Show Console", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, MENU_HIDE, "Hide to Tray", true, None::<&str>)?;
            let status_i =
                MenuItem::with_id(app, MENU_STATUS, "Firewall: resident", false, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, MENU_QUIT, "Quit", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;

            let menu = Menu::with_items(app, &[&status_i, &sep, &show_i, &hide_i, &sep, &quit_i])?;

            // --- Tray icon --------------------------------------------------------------------
            // Decode the bundled 32x32 PNG at runtime (image-png feature) so the tray has an icon
            // even before any window paints. Falls back to the app's default window icon if present.
            let tray_icon = tray_image().or_else(|| app.default_window_icon().cloned());

            let mut tray = TrayIconBuilder::with_id("main")
                .tooltip("OSSRedact -- firewall resident")
                // macOS only: render the tray PNG as a monochrome template so it adapts to light/dark
                // menu bars (the icon set should be a single-color silhouette -- see icons/README).
                .icon_as_template(true)
                .menu(&menu)
                // Keep the menu on right-click; left-click is wired below to toggle the window
                // (the familiar tray behaviour: click the icon to pop the console open).
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    MENU_SHOW => show_main(app),
                    MENU_HIDE => hide_main(app),
                    MENU_QUIT => {
                        // Real exit (distinct from close-to-tray): tear the whole app down.
                        app.exit(0);
                    }
                    // MENU_STATUS is disabled/informational -- no action.
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Left-click (button up) toggles the console window.
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window(MAIN_WINDOW) {
                            match win.is_visible() {
                                Ok(true) => {
                                    let _ = win.hide();
                                }
                                _ => show_main(app),
                            }
                        }
                    }
                });

            if let Some(icon) = tray_icon {
                tray = tray.icon(icon);
            }
            tray.build(app)?;

            // Where daemon supervision will hook in later (currently a no-op stub).
            supervise_daemon_todo(app.handle());

            Ok(())
        })
        // --- Close-to-tray ----------------------------------------------------------------------
        // Intercept the window close request and HIDE instead of exiting, so the firewall console
        // stays resident in the tray. Only the tray "Quit" item (app.exit) actually terminates.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == MAIN_WINDOW {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running the OSSRedact tray application");
}

/// Decode the bundled tray PNG (icons/32x32.png) into a runtime `Image`. include_bytes! resolves
/// relative to THIS source file (src-tauri/src/lib.rs), climbing one dir to src-tauri/icons/. The
/// icon set is required for a real build (see icons/README); if the file is missing this fails to
/// compile, which is the desired loud failure.
fn tray_image() -> Option<Image<'static>> {
    const TRAY_PNG: &[u8] = include_bytes!("../icons/32x32.png");
    Image::from_bytes(TRAY_PNG).ok()
}
