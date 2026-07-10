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
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

/// Loopback base for the always-on egress daemon's control API (allowlist / live-activity SSE /
/// healthz). Injected into the webview so the bundled frontend (daemon.ts) talks to the local egress.
/// The egress daemon binds this port as a separate service; the shell only connects.
/// This is the DEFAULT only: the operator can override it at runtime via the OSSREDACT_DAEMON env var
/// (e.g. point a packaged app at an off-device gate without rebuilding), and can also set/clear the
/// address inside the console's "Gate connection" panel (which persists in the webview and wins over this).
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
    // Runtime override (OSSREDACT_DAEMON) lets a packaged app target an off-device gate without a rebuild;
    // otherwise the loopback default. The in-console "Gate connection" override still wins over this (daemon.ts
    // checks its persisted value first). {base:?} emits a quoted/escaped JS string literal -- safe to embed.
    let base = std::env::var("OSSREDACT_DAEMON")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DAEMON_BASE.to_string());
    format!("window.__OSSREDACT_DAEMON__ = {base:?};")
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
// Firewall control commands (invoked from the console UI). The point-and-click on/off + routing that the
// service-model app previously left to the CLI. All LOCAL + loopback: `systemctl --user` manages the two
// user services (NO sudo), and the routing toggle flips ANTHROPIC_BASE_URL in ~/.claude/settings.json.
// ---------------------------------------------------------------------------------------------------
const FW_SERVICES: [&str; 2] = ["ossredact-gate-cpu.service", "ossredact-egress.service"];
const ROUTE_BASE: &str = "http://127.0.0.1:8011";
const ROUTE_KEY: &str = "ANTHROPIC_BASE_URL";
const ROUTE_DISABLED_KEY: &str = "_ANTHROPIC_BASE_URL_DISABLED_GATE_DEBUG";
// When ANTHROPIC_BASE_URL points at anything other than api.anthropic.com, Claude Code treats the
// endpoint as "not first-party" and pessimistically caps the context window at 200k -- even for models
// that are natively 1M. The visible cost is the context bar reading ~5x high (it glows red /
// auto-compacts near 140k of real tokens instead of ~700k). The firewall forwards every request
// verbatim to the real Anthropic API, so the 1M window genuinely applies.
//
// _CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL does NOT fix this (probe-verified on CC 2.1.197,
// 2026-07-01: gated /context still read 97k/200k with it set). It only patches the host check;
// the window sizing also requires the provider classification to be first-party, and a custom
// base URL fails that leg regardless. The key is kept solely so enable/disable scrub it from
// installs that wrote it while it was believed to work.
//
// What DOES work is the `[1m]` model-id suffix (e.g. `claude-fable-5[1m]`): the suffix check runs
// before any provider gating, so the bar reads against 1M, and CC sends the matching 1M context
// beta upstream (accepted through the proxy; probe-verified end-to-end, /context read 97k/1m and
// the request returned 200 with a prompt-cache hit). On a direct first-party connection CC strips
// the suffix itself, so leaving it on the model permanently is safe in both modes -- which is why
// enable adds it and disable leaves it alone.
const ASSUME_FIRST_PARTY_KEY: &str = "_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL";
// Models safe to suffix with [1m]: native-1M families per the CC model registry (fable-5, opus-4-8)
// plus sonnet-5 (native 1M per its release notes) and the aliases CC resolves through the same
// suffix-aware path. Anything else (haiku, explicit dated ids, unknown strings) is left untouched --
// wrongly suffixing a non-1M model is worse than a mis-sized bar.
const ONE_M_MODELS: [&str; 7] = [
    "fable",
    "opus",
    "sonnet",
    "opusplan",
    "claude-fable-5",
    "claude-opus-4-8",
    "claude-sonnet-5",
];

/// Translate a raw `systemctl --user` failure into actionable guidance. The common non-obvious case is a
/// missing user session bus (`Failed to connect to bus` / `Failed to connect to user scope bus`): the app was
/// launched outside an active `systemd --user` session (SSH without lingering, some autostart/kiosk contexts),
/// so the point-and-click toggle cannot reach the user manager. Surface what to do instead of the bare dbus error.
fn friendly_systemctl_err(stderr: &str) -> String {
    let s = stderr.trim();
    let low = s.to_lowercase();
    if low.contains("connect to bus") || low.contains("scope bus") || low.contains("dbus") {
        return format!(
            "No systemd user session available, so the firewall can't be toggled from here.\n\
             Start it from a normal desktop login, or run `loginctl enable-linger {}` once so the user \
             services can run without an active session. (raw: {})",
            std::env::var("USER").unwrap_or_else(|_| "<user>".to_string()),
            s
        );
    }
    if s.is_empty() {
        "systemctl --user failed with no output (is the user service manager running?)".to_string()
    } else {
        s.to_string()
    }
}

/// Ensure `home/.ossredact` exists as a directory so egress units with an optional
/// ReadWritePaths map can write on first start. Idempotent when already a directory;
/// fails closed if the path exists as a non-directory.
fn ensure_ossredact_dir(home: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let dir = home.join(".ossredact");
    if dir.exists() {
        if !dir.is_dir() {
            return Err(format!(
                "{} exists and is not a directory",
                dir.display()
            ));
        }
    } else {
        #[cfg(unix)]
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("create {}: {e}", dir.display()))?;

        #[cfg(not(unix))]
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }

    #[cfg(unix)]
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("set permissions on {}: {e}", dir.display()))?;

    Ok(dir)
}

/// "active" iff BOTH user services report active, else "inactive".
fn firewall_status_str() -> String {
    for svc in FW_SERVICES {
        let active = std::process::Command::new("systemctl")
            .args(["--user", "is-active", svc])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
        if !active {
            return "inactive".to_string();
        }
    }
    "active".to_string()
}

/// Start / stop / restart the two OSSRedact user services, or report status. Returns the resulting status
/// string ("active" | "inactive"). No sudo -- these are `systemctl --user` services.
#[tauri::command]
fn firewall_control(action: String) -> Result<String, String> {
    match action.as_str() {
        "start" | "restart" => {
            let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
            ensure_ossredact_dir(std::path::Path::new(&home))?;
            let out = std::process::Command::new("systemctl")
                .arg("--user")
                .arg(&action)
                .args(FW_SERVICES)
                .output()
                .map_err(|e| format!("systemctl --user {action}: {e}"))?;
            if out.status.success() {
                Ok(firewall_status_str())
            } else {
                Err(friendly_systemctl_err(&String::from_utf8_lossy(&out.stderr)))
            }
        }
        "stop" => {
            let out = std::process::Command::new("systemctl")
                .arg("--user")
                .arg("stop")
                .args(FW_SERVICES)
                .output()
                .map_err(|e| format!("systemctl --user stop: {e}"))?;
            if out.status.success() {
                Ok(firewall_status_str())
            } else {
                Err(friendly_systemctl_err(&String::from_utf8_lossy(&out.stderr)))
            }
        }
        "status" => Ok(firewall_status_str()),
        other => Err(format!("unknown firewall action: {other}")),
    }
}

fn claude_settings_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(std::path::PathBuf::from(home)
        .join(".claude")
        .join("settings.json"))
}

/// Toggle whether Claude Code routes through the firewall, by flipping ANTHROPIC_BASE_URL in
/// ~/.claude/settings.json's `env` block. "get" reports current state; "enable"/"disable" set it and return
/// the new state (true = routing on). Applies to NEW Claude Code sessions.
#[tauri::command]
fn routing_config(action: String) -> Result<bool, String> {
    routing_config_impl(action)
}

fn routing_config_impl(action: String) -> Result<bool, String> {
    let path = claude_settings_path()?;
    // A fresh user has no ~/.claude/settings.json yet. Treat an absent file as "{}" (start from an
    // empty object) and create it (plus the ~/.claude/ dir) on write below; a MALFORMED file that
    // exists still surfaces a parse error so silent corruption is never masked.
    let txt = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "{}".to_string(),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let mut v: serde_json::Value =
        serde_json::from_str(&txt).map_err(|e| format!("parse settings.json: {e}"))?;

    if action == "get" {
        let on = v
            .get("env")
            .and_then(|e| e.as_object())
            .map(|e| e.contains_key(ROUTE_KEY))
            .unwrap_or(false);
        return Ok(on);
    }
    if action != "enable" && action != "disable" {
        return Err(format!("unknown routing action: {action}"));
    }

    if !v.get("env").map(|e| e.is_object()).unwrap_or(false) {
        v.as_object_mut()
            .ok_or("settings.json is not a JSON object")?
            .insert("env".to_string(), serde_json::json!({}));
    }
    let env = v
        .get_mut("env")
        .and_then(|e| e.as_object_mut())
        .ok_or("settings.json env is not an object")?;

    if action == "enable" {
        env.remove(ROUTE_DISABLED_KEY);
        env.insert(
            ROUTE_KEY.to_string(),
            serde_json::Value::String(ROUTE_BASE.to_string()),
        );
        // Scrub the flag written by older builds -- it never affected the window (see const note).
        env.remove(ASSUME_FIRST_PARTY_KEY);
    } else {
        env.remove(ROUTE_KEY);
        env.remove(ASSUME_FIRST_PARTY_KEY);
        // keep a disabled marker so the prior intent stays visible / easily re-enabled
        env.insert(
            ROUTE_DISABLED_KEY.to_string(),
            serde_json::Value::String(ROUTE_BASE.to_string()),
        );
    }

    if action == "enable" {
        // Keep the context bar / auto-compact sized to the true 1M window through the proxy: append
        // [1m] to the configured model when it is a known native-1M id/alias. CC strips the suffix
        // on direct first-party connections, so disable intentionally leaves it in place.
        if let Some(model) = v.get("model").and_then(|m| m.as_str()) {
            let trimmed = model.trim();
            if !trimmed.to_lowercase().ends_with("[1m]")
                && ONE_M_MODELS.contains(&trimmed.to_lowercase().as_str())
            {
                let suffixed = format!("{trimmed}[1m]");
                v.as_object_mut()
                    .ok_or("settings.json is not a JSON object")?
                    .insert("model".to_string(), serde_json::Value::String(suffixed));
            }
        }
    }

    let pretty = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    // create_dir_all is idempotent: no-op when ~/.claude/ already exists, creates it (and any
    // missing ancestors) for the fresh-user absent-file path so the write does not fail.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, pretty + "\n").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(action == "enable")
}

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
        // Console-invoked firewall controls (point-and-click on/off + routing).
        .invoke_handler(tauri::generate_handler![firewall_control, routing_config])
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Guard that restores `HOME` when dropped so a test cannot leak a fake HOME into the process.
    /// All routing tests live in ONE test fn so the process-global HOME never races across parallel
    /// tests (no `serial_test` dependency).
    struct HomeGuard(Option<String>);
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn fake_home(tag: &str) -> (std::path::PathBuf, HomeGuard) {
        let dir = std::env::temp_dir()
            .join(format!("ossredact-routing-test-{}-{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp home");
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", &dir);
        (dir, HomeGuard(prev))
    }

    fn settings_path(home: &std::path::Path) -> std::path::PathBuf {
        home.join(".claude").join("settings.json")
    }

    fn read_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(path).expect("read settings"))
            .expect("parse settings")
    }

    /// Per-test temporary home that removes its synthetic fixture even when an assertion fails.
    #[cfg(unix)]
    struct TempHome(std::path::PathBuf);

    #[cfg(unix)]
    impl TempHome {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ossredact-dir-permissions-test-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create synthetic home root");
            Self(path)
        }
    }

    #[cfg(unix)]
    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn unix_mode(path: &std::path::Path) -> u32 {
        fs::metadata(path)
            .expect("read directory metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn routing_config_round_trip_and_siblings_preserved() {
        // --- Absent file: enable creates it; disable writes the marker; get reflects each state ---
        let (home, _guard) = fake_home("absent");
        let path = settings_path(&home);
        assert!(!path.exists(), "precondition: no settings.json yet");

        assert!(routing_config_impl("enable".into()).unwrap(), "enable returns true");
        assert!(path.exists(), "enable created the file (and ~/.claude/)");
        assert!(
            routing_config_impl("get".into()).unwrap(),
            "get reports routing on after enable"
        );
        let v = read_json(&path);
        assert_eq!(
            v["env"][ROUTE_KEY].as_str(),
            Some(ROUTE_BASE),
            "enable wrote ANTHROPIC_BASE_URL = ROUTE_BASE"
        );
        assert!(
            !v["env"].as_object().unwrap().contains_key(ASSUME_FIRST_PARTY_KEY),
            "enable does NOT write the assume-first-party flag (probe-verified inert on CC 2.1.197)"
        );
        assert!(
            !v["env"].as_object().unwrap().contains_key(ROUTE_DISABLED_KEY),
            "enable removed the disabled marker"
        );

        assert!(!routing_config_impl("disable".into()).unwrap(), "disable returns false");
        assert!(
            !routing_config_impl("get".into()).unwrap(),
            "get reports routing off after disable"
        );
        let v = read_json(&path);
        assert!(
            !v["env"].as_object().unwrap().contains_key(ROUTE_KEY),
            "disable removed ANTHROPIC_BASE_URL"
        );
        assert!(
            !v["env"].as_object().unwrap().contains_key(ASSUME_FIRST_PARTY_KEY),
            "disable removed the assume-first-party flag (un-routed CC is first-party on its own)"
        );
        assert_eq!(
            v["env"][ROUTE_DISABLED_KEY].as_str(),
            Some(ROUTE_BASE),
            "disable wrote the _ANTHROPIC_BASE_URL_DISABLED_GATE_DEBUG marker"
        );
        let _ = fs::remove_dir_all(&home);

        // --- Pre-existing sibling keys survive with order preserved (serde_json preserve_order) ---
        let (home2, _guard2) = fake_home("siblings");
        let path2 = settings_path(&home2);
        fs::create_dir_all(path2.parent().unwrap()).unwrap();
        // theme before env before notes -> a stable, non-trivial order to preserve on rewrite.
        fs::write(&path2, r#"{"theme":"dark","env":{"FOO":"bar"},"notes":"keep-me"}"#).unwrap();
        assert!(routing_config_impl("enable".into()).unwrap());
        let v2 = read_json(&path2);
        let top: Vec<&str> = v2.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(top, vec!["theme", "env", "notes"], "top-level key order preserved");
        assert_eq!(v2["theme"].as_str(), Some("dark"), "sibling key survives");
        assert_eq!(v2["notes"].as_str(), Some("keep-me"), "sibling key survives");
        assert_eq!(v2["env"]["FOO"].as_str(), Some("bar"), "pre-existing env key survives");
        assert_eq!(v2["env"][ROUTE_KEY].as_str(), Some(ROUTE_BASE), "route key added");
        let _ = fs::remove_dir_all(&home2);

        // --- A malformed file that EXISTS still surfaces a parse error (absent-file path does not mask it) ---
        let (home3, _guard3) = fake_home("malformed");
        let path3 = settings_path(&home3);
        fs::create_dir_all(path3.parent().unwrap()).unwrap();
        fs::write(&path3, "{not json").unwrap();
        let err = routing_config_impl("get".into()).unwrap_err();
        assert!(
            err.contains("parse settings.json"),
            "malformed file surfaces parse error: {err}"
        );
        let _ = fs::remove_dir_all(&home3);

        // --- Known native-1M model gets [1m] appended on enable; disable leaves it alone ---
        let (home, _guard) = fake_home("model-1m");
        let path = settings_path(&home);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            format!(
                r#"{{"model":"claude-fable-5","env":{{"{ASSUME_FIRST_PARTY_KEY}":"stale"}}}}"#
            ),
        )
        .unwrap();
        assert!(routing_config_impl("enable".into()).unwrap());
        let v = read_json(&path);
        assert_eq!(
            v["model"].as_str(),
            Some("claude-fable-5[1m]"),
            "enable appended [1m] so the context bar reads the true 1M window through the proxy"
        );
        assert!(
            !v["env"].as_object().unwrap().contains_key(ASSUME_FIRST_PARTY_KEY),
            "enable scrubbed the stale assume-first-party flag from an older install"
        );
        assert!(!routing_config_impl("disable".into()).unwrap());
        let v = read_json(&path);
        assert_eq!(
            v["model"].as_str(),
            Some("claude-fable-5[1m]"),
            "disable leaves the suffix (CC strips it itself on direct first-party connections)"
        );
        let _ = fs::remove_dir_all(&home);

        // --- Already-suffixed stays as-is; unknown model and absent model are never touched ---
        let (home2, _guard2) = fake_home("model-other");
        let path2 = settings_path(&home2);
        fs::create_dir_all(path2.parent().unwrap()).unwrap();
        fs::write(&path2, r#"{"model":"claude-fable-5[1m]"}"#).unwrap();
        assert!(routing_config_impl("enable".into()).unwrap());
        assert_eq!(
            read_json(&path2)["model"].as_str(),
            Some("claude-fable-5[1m]"),
            "already-suffixed model unchanged (no [1m][1m])"
        );
        fs::write(&path2, r#"{"model":"claude-haiku-4-5-20251001"}"#).unwrap();
        assert!(routing_config_impl("enable".into()).unwrap());
        assert_eq!(
            read_json(&path2)["model"].as_str(),
            Some("claude-haiku-4-5-20251001"),
            "non-1M / unknown model left untouched"
        );
        fs::write(&path2, r#"{}"#).unwrap();
        assert!(routing_config_impl("enable".into()).unwrap());
        assert!(
            !read_json(&path2).as_object().unwrap().contains_key("model"),
            "absent model key is not invented"
        );
        let _ = fs::remove_dir_all(&home2);
    }

    /// Fixed user-unit basenames the desktop control plane is allowed to manage.
    /// Keep this locked to the approved pair so a rename cannot silently drift from
    /// the documented `~/.config/systemd/user/` units without a test failure.
    #[test]
    fn firewall_user_service_basenames_are_fixed() {
        assert_eq!(
            FW_SERVICES,
            [
                "ossredact-gate-cpu.service",
                "ossredact-egress.service",
            ],
            "desktop firewall control must target only the approved user-unit basenames"
        );
        assert_eq!(FW_SERVICES.len(), 2, "exactly two user services are controlled");
    }

    /// Action classification for unknown verbs is pure (no systemctl spawn). Valid
    /// start/stop/restart/status paths still require a live user manager and stay
    /// outside this suite.
    #[test]
    fn firewall_control_rejects_unknown_actions() {
        for action in ["", "enable", "Start", "START", "reload", "statuss", "bogus"] {
            let err = firewall_control(action.to_string()).expect_err(action);
            assert_eq!(
                err,
                format!("unknown firewall action: {action}"),
                "unexpected classification for action {action:?}"
            );
        }
    }

    /// Pure stderr mapping for missing user-session bus; no live manager required.
    #[test]
    fn friendly_systemctl_err_maps_user_bus_failures() {
        let bus = friendly_systemctl_err("Failed to connect to bus: No such file or directory");
        assert!(
            bus.contains("No systemd user session available"),
            "bus failure should explain missing user session: {bus}"
        );
        assert!(
            bus.contains("loginctl enable-linger"),
            "bus failure should name the linger remediation: {bus}"
        );

        let scope = friendly_systemctl_err("Failed to connect to user scope bus");
        assert!(
            scope.contains("No systemd user session available"),
            "scope-bus failure should map the same way: {scope}"
        );

        let empty = friendly_systemctl_err("   ");
        assert!(
            empty.contains("systemctl --user failed with no output"),
            "empty stderr should surface a generic manager-missing hint: {empty}"
        );

        let passthrough = friendly_systemctl_err("Unit not found.");
        assert_eq!(
            passthrough, "Unit not found.",
            "non-bus errors pass through trimmed raw text"
        );
    }

    /// The egress units keep local state here, so a newly created directory must be private
    /// regardless of the caller's umask.
    #[cfg(unix)]
    #[test]
    fn ensure_ossredact_dir_creates_private_directory() {
        let home = TempHome::new("create");
        let dir = home.0.join(".ossredact");

        ensure_ossredact_dir(&home.0).expect("create missing .ossredact");

        assert_eq!(
            unix_mode(&dir),
            0o700,
            "first creation must give .ossredact owner-only permissions"
        );
    }

    /// A directory made permissive by an earlier release must be tightened on the next call.
    #[cfg(unix)]
    #[test]
    fn ensure_ossredact_dir_repairs_existing_directory_permissions() {
        let home = TempHome::new("repair");
        let dir = home.0.join(".ossredact");
        fs::create_dir(&dir).expect("create synthetic pre-existing .ossredact");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
            .expect("make synthetic directory world-readable");
        assert_eq!(
            unix_mode(&dir),
            0o755,
            "precondition: synthetic directory starts world-readable"
        );

        ensure_ossredact_dir(&home.0).expect("repair existing .ossredact permissions");

        assert_eq!(
            unix_mode(&dir),
            0o700,
            "existing .ossredact directory must be tightened to owner-only permissions"
        );
    }

    /// `ensure_ossredact_dir(home)` must create `home/.ossredact` as a directory when absent,
    /// remain a no-op when it already is a directory, and reject a preexisting non-directory
    /// at that path. Pure filesystem seam: no systemctl, explicit home root for testability.
    #[test]
    fn ensure_ossredact_dir_creates_idempotently_and_rejects_file() {
        let root = std::env::temp_dir().join(format!(
            "ossredact-dir-test-{}-{}",
            std::process::id(),
            "create"
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp home root");

        let expected = root.join(".ossredact");
        assert!(!expected.exists(), "precondition: path absent");

        let created = ensure_ossredact_dir(&root).expect("create missing .ossredact");
        assert_eq!(created, expected, "helper returns the .ossredact path under home");
        assert!(
            expected.is_dir(),
            "first call must create .ossredact as a directory"
        );

        let again = ensure_ossredact_dir(&root).expect("idempotent when already a directory");
        assert_eq!(again, expected, "second call returns the same path");
        assert!(
            expected.is_dir(),
            "second call must leave an existing directory intact"
        );

        let _ = fs::remove_dir_all(&root);

        // Non-directory occupant must fail closed (do not replace a file with a directory).
        let root2 = std::env::temp_dir().join(format!(
            "ossredact-dir-test-{}-{}",
            std::process::id(),
            "file-block"
        ));
        let _ = fs::remove_dir_all(&root2);
        fs::create_dir_all(&root2).expect("create temp home root for file case");
        let blocked = root2.join(".ossredact");
        fs::write(&blocked, b"not-a-directory").expect("plant file at .ossredact");
        assert!(blocked.is_file(), "precondition: path is a regular file");

        let err = ensure_ossredact_dir(&root2).expect_err("file at path must error");
        assert!(
            blocked.is_file(),
            "rejecting a file must not remove or replace it"
        );
        assert!(
            err.contains(".ossredact") || err.to_lowercase().contains("not a directory") || err.to_lowercase().contains("directory"),
            "error should name the path or that it is not a directory: {err}"
        );

        let _ = fs::remove_dir_all(&root2);
    }
}
