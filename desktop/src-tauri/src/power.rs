//! Keeping the machine awake through a long audit, and knowing when it is on
//! battery.
//!
//! An every-page batch runs for hours. A laptop that idles to sleep at hour
//! two kills it (resumable, but the night is gone), and a laptop on battery
//! measures slower than the same laptop on mains: the OS throttles the CPU,
//! and Lighthouse's own benchmark drifts with it. So a batch holds a
//! keep-awake assertion for as long as it runs, and the composer warns before
//! a long batch starts on battery.
//!
//! Each platform's native mechanism, no extra crate:
//! - **Windows**: `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)`
//!   on the audit thread. The state belongs to the thread, so the guard must
//!   be created and dropped on the thread that runs the batch, which is how
//!   the audit command uses it.
//! - **macOS**: `caffeinate -i -w <pid>`, the system's own idle-sleep
//!   assertion (an IOPMAssertion), tied to this process so it cannot outlive
//!   a crash.
//! - **Linux**: `systemd-inhibit --what=idle:sleep`, where systemd exists,
//!   around a command that exits with this process.
//!
//! None of these stop a closed laptop lid from sleeping the machine on
//! battery; that is the OS honouring an explicit user action, and the batch
//! is resumable for exactly that reason.

/// Holds the keep-awake assertion until dropped. Best effort: where the
/// platform mechanism is unavailable the guard does nothing, and the batch
/// runs exactly as it would have.
pub struct KeepAwake {
    #[cfg(not(windows))]
    child: Option<std::process::Child>,
}

impl KeepAwake {
    pub fn acquire(reason: &str) -> Self {
        #[cfg(windows)]
        {
            let _ = reason;
            use windows_sys::Win32::System::Power::{
                SetThreadExecutionState, ES_CONTINUOUS, ES_SYSTEM_REQUIRED,
            };
            // SAFETY: a plain Win32 call with flag arguments; it touches only
            // this thread's execution state.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
            }
            KeepAwake {}
        }
        #[cfg(target_os = "macos")]
        {
            let _ = reason;
            let child = std::process::Command::new("/usr/bin/caffeinate")
                .args(["-i", "-w", &std::process::id().to_string()])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
            KeepAwake { child }
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            // The inhibited command waits on SLAP's own pid, so the lock
            // cannot outlive a crash (the macOS `caffeinate -w` equivalent).
            let pid = std::process::id().to_string();
            let child = std::process::Command::new("systemd-inhibit")
                .args([
                    "--what=idle:sleep",
                    "--who=SLAP",
                    &format!("--why={reason}"),
                    "--mode=block",
                    "tail",
                    "--pid",
                    &pid,
                    "-f",
                    "/dev/null",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
            KeepAwake { child }
        }
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Power::{SetThreadExecutionState, ES_CONTINUOUS};
            // SAFETY: as above; ES_CONTINUOUS alone clears the requirement.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
        #[cfg(not(windows))]
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `Some(true)` on battery, `Some(false)` on mains (or a desktop with no
/// battery), `None` when the platform will not say.
pub fn on_battery() -> Option<bool> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        // SAFETY: GetSystemPowerStatus fills the struct we pass it.
        let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
            return None;
        }
        // BatteryFlag 128: no system battery. ACLineStatus 0 offline, 1 online.
        if status.BatteryFlag == 128 {
            return Some(false);
        }
        match status.ACLineStatus {
            0 => Some(true),
            1 => Some(false),
            _ => None,
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/pmset")
            .args(["-g", "batt"])
            .output()
            .ok()?;
        parse_pmset(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux_on_battery(std::path::Path::new("/sys/class/power_supply"))
    }
}

/// `pmset -g batt` prints "Now drawing from 'Battery Power'" or "'AC Power'".
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_pmset(text: &str) -> Option<bool> {
    let first = text.lines().next()?;
    if first.contains("'Battery Power'") {
        Some(true)
    } else if first.contains("'AC Power'") || first.contains("'UPS Power'") {
        Some(false)
    } else {
        None
    }
}

/// Mains online means not on battery; a battery with no mains online means
/// on battery; a machine with neither (a desktop, a VM) is on mains.
#[cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code))]
fn linux_on_battery(root: &std::path::Path) -> Option<bool> {
    let entries = std::fs::read_dir(root).ok()?;
    let (mut mains_online, mut has_battery, mut has_mains) = (false, false, false);
    for entry in entries.flatten() {
        let path = entry.path();
        let kind = std::fs::read_to_string(path.join("type")).unwrap_or_default();
        match kind.trim() {
            "Mains" => {
                has_mains = true;
                if std::fs::read_to_string(path.join("online")).unwrap_or_default().trim() == "1" {
                    mains_online = true;
                }
            }
            "Battery" => has_battery = true,
            _ => {}
        }
    }
    if mains_online || !has_battery {
        Some(false)
    } else if has_mains || has_battery {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmset_output_is_read_from_its_first_line() {
        assert_eq!(
            parse_pmset("Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1) 81%; discharging"),
            Some(true)
        );
        assert_eq!(parse_pmset("Now drawing from 'AC Power'\n"), Some(false));
        assert_eq!(parse_pmset(""), None);
    }

    #[test]
    fn linux_power_supplies_decide_battery_or_mains() {
        let dir = tempfile::tempdir().unwrap();
        let supply = |name: &str, kind: &str, online: Option<&str>| {
            let p = dir.path().join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("type"), kind).unwrap();
            if let Some(o) = online {
                std::fs::write(p.join("online"), o).unwrap();
            }
        };
        // A desktop: nothing at all, so mains.
        assert_eq!(linux_on_battery(dir.path()), Some(false));
        supply("BAT0", "Battery\n", None);
        supply("AC", "Mains\n", Some("0\n"));
        assert_eq!(linux_on_battery(dir.path()), Some(true));
        std::fs::write(dir.path().join("AC").join("online"), "1\n").unwrap();
        assert_eq!(linux_on_battery(dir.path()), Some(false));
    }
}
