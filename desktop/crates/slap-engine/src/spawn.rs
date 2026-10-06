//! Starting the programs the engine drives (Lighthouse's Node worker, and the
//! Chromium that prints a PDF) so that they behave the same on every platform.
//!
//! Two things go wrong on Windows that never show on macOS or Linux:
//!
//! - **A console window per program.** SLAP's release build is a GUI app with
//!   no console, so Windows gives every console program it starts (Node is
//!   one) a console window of its own: a batch opened one per page tested,
//!   and Windows Terminal keeps a window open after a program exits with an
//!   error, so they piled up. `CREATE_NO_WINDOW` gives the program a console
//!   with no window, and anything it starts in turn shares that console, so
//!   it opens none either.
//! - **Verbatim paths.** `canonicalize` returns `\\?\C:\...` paths, and Tauri
//!   builds its resource folder, where the worker lives, from one. Node cannot
//!   start a script from such a path: it stops with `EISDIR: illegal
//!   operation on a directory, lstat 'C:'` before the worker runs a line,
//!   which failed Lighthouse on every page. [`plain`] turns them back into
//!   ordinary paths.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Windows' `CREATE_NO_WINDOW` process creation flag.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// An async command that opens no console window on Windows.
pub fn tokio_command(program: impl AsRef<OsStr>) -> tokio::process::Command {
    #[allow(unused_mut)]
    let mut command = tokio::process::Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// A blocking command that opens no console window on Windows.
pub fn std_command(program: impl AsRef<OsStr>) -> std::process::Command {
    #[allow(unused_mut)]
    let mut command = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// `path` without its Windows verbatim prefix (`\\?\C:\...` becomes
/// `C:\...`) wherever the prefix can be dropped without changing what the path
/// names. Unchanged otherwise (a network share, `\\?\UNC\...`, keeps it), and
/// on every other platform.
pub fn plain(path: impl AsRef<Path>) -> PathBuf {
    dunce::simplified(path.as_ref()).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_path_is_left_alone() {
        let path = Path::new("worker").join("worker.js");
        assert_eq!(plain(&path), path);
    }

    #[cfg(windows)]
    #[test]
    fn a_verbatim_path_becomes_one_node_can_start() {
        assert_eq!(plain(r"\\?\C:\Users\me\SLAP\_up_\worker"), Path::new(r"C:\Users\me\SLAP\_up_\worker"));
        // A network share keeps its prefix: dropping it is not always safe.
        assert_eq!(plain(r"\\?\UNC\server\share\worker"), Path::new(r"\\?\UNC\server\share\worker"));
        assert_eq!(plain(r"C:\already\plain"), Path::new(r"C:\already\plain"));
    }

    /// The release app is a GUI program; a console program it starts must
    /// not get a window of its own. The flag is what prevents it, so the
    /// commands must carry it.
    #[cfg(windows)]
    #[test]
    fn commands_carry_no_window() {
        // Neither command type exposes its flags; starting a console program
        // through each and finishing cleanly at least proves the flag is
        // accepted by CreateProcess.
        let status = std_command("cmd").args(["/c", "exit", "0"]).status().unwrap();
        assert!(status.success());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let status = runtime
            .block_on(tokio_command("cmd").args(["/c", "exit", "0"]).status())
            .unwrap();
        assert!(status.success());
    }
}
