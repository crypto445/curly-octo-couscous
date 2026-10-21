use anyhow::{Context, Result};
use clap::Subcommand;
use gitlawb_core::did::DidDocument;
use gitlawb_core::identity::Keypair;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Generate a new Ed25519 keypair and DID
    New {
        /// Output directory for key files (default: ~/.gitlawb)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite existing keys if present
        #[arg(long)]
        force: bool,
    },
    /// Print your current DID
    Show {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Export your DID document as JSON
    Export {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Sign a message with your private key and print base64url signature
    Sign {
        message: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Back up your identity key to a secure location
    Backup {
        /// Destination path for the backup file (default: ./identity.pem.bak)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Restore your identity key from a backup file
    Restore {
        /// Path to the backup PEM file
        src: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite existing identity without prompting
        #[arg(long)]
        force: bool,
    },
}

pub async fn run(cmd: IdentityCmd) -> Result<()> {
    match cmd {
        IdentityCmd::New { dir, force } => cmd_new(dir, force).await,
        IdentityCmd::Show { dir } => cmd_show(dir).await,
        IdentityCmd::Export { dir } => cmd_export(dir).await,
        IdentityCmd::Sign { message, dir } => cmd_sign(message, dir).await,
        IdentityCmd::Backup { out, dir } => cmd_backup(out, dir).await,
        IdentityCmd::Restore { src, dir, force } => cmd_restore(src, dir, force).await,
    }
}

fn gitlawb_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d);
    }
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".gitlawb"))
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("identity.pem")
}

fn load_keypair(dir: Option<PathBuf>) -> Result<Keypair> {
    load_keypair_from_dir(dir.as_deref())
}

/// Load keypair from an optional directory override.
/// Used by other modules (register, repo, mcp).
///
/// When `GITLAWB_PROXY_DID` is set, the keypair presents that DID instead of
/// the one its local key derives (proxy mode): every signed request then names
/// the real agent DID, and the trusted proxy re-signs with the real private
/// key. Without the variable, behavior is unchanged.
pub fn load_keypair_from_dir(dir: Option<&std::path::Path>) -> Result<Keypair> {
    let base = if let Some(d) = dir {
        d.to_path_buf()
    } else {
        dirs::home_dir()
            .context("could not determine home directory")?
            .join(".gitlawb")
    };
    let path = key_path(&base);
    let pem = fs::read_to_string(&path).with_context(|| {
        format!(
            "no identity found at {}\nRun `gl identity new` to create one",
            path.display()
        )
    })?;
    let keypair = Keypair::from_pem(&pem).context("failed to load keypair from PEM")?;
    Ok(gitlawb_core::identity::apply_proxy_did_from_env(keypair)?)
}

/// Warn when the identity presents a DID its local key does not back. Commands
/// that cryptographically depend on the local PEM (`identity sign`,
/// `identity export`) cannot produce real-identity output in proxy mode.
fn warn_proxy_identity(keypair: &Keypair) {
    if keypair.public_did_override().is_some() {
        eprintln!(
            "warning: {} is set: the local key backs {} ({}), so this command's \
             output will not verify as the presented DID",
            gitlawb_core::identity::PROXY_DID_ENV,
            keypair.local_did(),
            keypair.did(),
        );
    }
}

async fn cmd_new(dir: Option<PathBuf>, force: bool) -> Result<()> {
    cmd_new_with_reader(dir, force, &mut std::io::stdin().lock()).await
}

async fn cmd_new_with_reader(
    dir: Option<PathBuf>,
    force: bool,
    reader: &mut impl std::io::BufRead,
) -> Result<()> {
    let dir = gitlawb_dir(dir)?;
    let path = key_path(&dir);

    if path.exists() {
        if force {
            eprint!(
                "warning: --force specified. Overwriting existing identity at {}.\nThis will permanently destroy your current DID. Continue? [y/N] ",
                path.display()
            );
        } else {
            eprint!(
                "identity already exists at {}.\nThis will permanently replace your current DID. Continue? [y/N] ",
                path.display()
            );
        }
        let mut input = String::new();
        reader.read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let keypair = Keypair::generate();
    let pem = keypair.to_pem()?;

    // Write with restricted permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&path, pem.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, pem.as_bytes())?;
    }

    let did = keypair.did();
    println!("✓ Generated new identity");
    println!("  DID:  {did}");
    println!("  Key:  {}", path.display());
    println!();
    println!("  Your DID is your identity on the gitlawb network.");
    println!("  Keep your key file safe — it cannot be recovered if lost.");

    Ok(())
}

async fn cmd_show(dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair(dir)?;
    println!("{}", keypair.did());
    Ok(())
}

async fn cmd_export(dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair(dir)?;
    warn_proxy_identity(&keypair);
    let did = keypair.did();
    let vk = keypair.verifying_key();
    let doc = DidDocument::new(did, &vk);
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

async fn cmd_sign(message: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair(dir)?;
    warn_proxy_identity(&keypair);
    let sig = keypair.sign_b64(message.as_bytes());
    println!("{sig}");
    Ok(())
}

async fn cmd_backup(out: Option<PathBuf>, dir: Option<PathBuf>) -> Result<()> {
    let base = gitlawb_dir(dir)?;
    let src = key_path(&base);

    let pem = fs::read_to_string(&src).with_context(|| {
        format!(
            "no identity found at {} — run `gl identity new` first",
            src.display()
        )
    })?;

    // Verify it loads before copying
    let keypair = Keypair::from_pem(&pem).context("identity.pem is corrupted")?;

    let dest = out.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_default()
            .join("identity.pem.bak")
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&dest, pem.as_bytes())?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&dest, pem.as_bytes())?;
    }

    println!("✓ Identity backed up");
    println!("  DID:  {}", keypair.did());
    println!("  From: {}", src.display());
    println!("  To:   {}", dest.display());
    println!();
    println!("  Store this file somewhere safe — a password manager, encrypted drive,");
    println!("  or offline backup. Anyone with this file controls your DID.");
    Ok(())
}

async fn cmd_restore(src: PathBuf, dir: Option<PathBuf>, force: bool) -> Result<()> {
    cmd_restore_with_reader(src, dir, force, &mut std::io::stdin().lock()).await
}

async fn cmd_restore_with_reader(
    src: PathBuf,
    dir: Option<PathBuf>,
    force: bool,
    reader: &mut impl std::io::BufRead,
) -> Result<()> {
    let pem = fs::read_to_string(&src)
        .with_context(|| format!("could not read backup file {}", src.display()))?;

    // Verify it's a valid keypair before writing anything
    let keypair = Keypair::from_pem(&pem).context("backup file is not a valid identity PEM")?;

    let base = gitlawb_dir(dir)?;
    let dest = key_path(&base);

    if dest.exists() {
        if force {
            eprint!(
                "warning: --force specified. Overwriting existing identity at {}.\nThis will permanently destroy your current DID. Continue? [y/N] ",
                dest.display()
            );
        } else {
            eprint!(
                "identity already exists at {}.\nRestoring will permanently replace your current DID. Continue? [y/N] ",
                dest.display()
            );
        }
        let mut input = String::new();
        reader.read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    fs::create_dir_all(&base)
        .with_context(|| format!("failed to create directory {}", base.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&dest, pem.as_bytes())?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&dest, pem.as_bytes())?;
    }

    println!("✓ Identity restored");
    println!("  DID:  {}", keypair.did());
    println!("  From: {}", src.display());
    println!("  To:   {}", dest.display());
    Ok(())
}

/// Serialize process-global `GITLAWB_PROXY_DID` access for tests across this
/// crate's modules (identity, issue, …): env-touching tests never race.
#[cfg(test)]
pub(crate) mod test_env {
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    static PROXY_DID_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A well-formed stand-in for the agent's real DID.
    pub(crate) const REAL_DID: &str = "did:key:z6MkgKE7i43aWhq2ntFx5o7e2tXrSZFay1nY4KZAuyj5WofL";

    /// Set or clear `GITLAWB_PROXY_DID` for the guard's lifetime, restoring the
    /// previous value on drop.
    pub(crate) struct ProxyDidEnv {
        _lock: MutexGuard<'static, ()>,
        prev: Option<OsString>,
    }

    impl ProxyDidEnv {
        pub(crate) fn set(value: Option<&str>) -> Self {
            let lock = PROXY_DID_ENV_LOCK.lock().unwrap();
            let prev = std::env::var_os("GITLAWB_PROXY_DID");
            match value {
                Some(v) => std::env::set_var("GITLAWB_PROXY_DID", v),
                None => std::env::remove_var("GITLAWB_PROXY_DID"),
            }
            ProxyDidEnv { _lock: lock, prev }
        }
    }

    impl Drop for ProxyDidEnv {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("GITLAWB_PROXY_DID", v),
                None => std::env::remove_var("GITLAWB_PROXY_DID"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cmd_new_creates_pem() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        assert!(dir.path().join("identity.pem").exists());
    }

    #[tokio::test]
    async fn test_cmd_new_force_overwrites_on_confirm() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let pem1 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        // Simulate user typing "y" at the --force prompt
        let mut reader = std::io::Cursor::new(b"y\n");
        cmd_new_with_reader(Some(dir.path().to_path_buf()), true, &mut reader)
            .await
            .unwrap();
        let pem2 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        assert_ne!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_cmd_new_force_aborts_on_n() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let pem1 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        // Simulate user typing "n" — should abort even with --force
        let mut reader = std::io::Cursor::new(b"n\n");
        cmd_new_with_reader(Some(dir.path().to_path_buf()), true, &mut reader)
            .await
            .unwrap();
        let pem2 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        assert_eq!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_cmd_new_no_force_aborts_on_n() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let pem1 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        let mut reader = std::io::Cursor::new(b"n\n");
        cmd_new_with_reader(Some(dir.path().to_path_buf()), false, &mut reader)
            .await
            .unwrap();
        let pem2 = std::fs::read_to_string(dir.path().join("identity.pem")).unwrap();
        assert_eq!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_cmd_show_succeeds() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_show(Some(dir.path().to_path_buf())).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_export_produces_did_document() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_export(Some(dir.path().to_path_buf())).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_sign_succeeds() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_sign("hello gitlawb".to_string(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }

    #[test]
    fn test_load_keypair_missing_returns_error() {
        let dir = TempDir::new().unwrap();
        let result = load_keypair_from_dir(Some(dir.path()));
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("no identity found") || msg.contains("identity.pem"));
    }

    #[tokio::test]
    async fn test_pem_roundtrip() {
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();
        // Loading the keypair back should succeed and produce a valid DID
        let kp = load_keypair_from_dir(Some(dir.path())).unwrap();
        let did = kp.did().to_string();
        assert!(did.starts_with("did:key:"));
    }

    #[tokio::test]
    async fn test_cmd_restore_success() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        // Create an identity and back it up
        cmd_new(Some(src_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let backup_path = src_dir.path().join("identity.pem.bak");
        cmd_backup(
            Some(backup_path.clone()),
            Some(src_dir.path().to_path_buf()),
        )
        .await
        .unwrap();

        // Restore to a fresh directory
        cmd_restore(backup_path, Some(dst_dir.path().to_path_buf()), false)
            .await
            .unwrap();

        // The restored DID should match the original
        let orig = load_keypair_from_dir(Some(src_dir.path())).unwrap();
        let restored = load_keypair_from_dir(Some(dst_dir.path())).unwrap();
        assert_eq!(orig.did(), restored.did());
    }

    #[tokio::test]
    async fn test_cmd_restore_invalid_pem_fails() {
        let dir = TempDir::new().unwrap();
        let bad_pem = dir.path().join("bad.pem");
        std::fs::write(&bad_pem, b"this is not a valid PEM file").unwrap();

        let err = cmd_restore(bad_pem, Some(dir.path().to_path_buf()), false).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("valid identity PEM"));
    }

    #[tokio::test]
    async fn test_cmd_restore_missing_file_fails() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist.pem");

        let err = cmd_restore(missing, Some(dir.path().to_path_buf()), false).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("backup file"));
    }

    #[tokio::test]
    async fn test_cmd_restore_force_overwrites_on_confirm() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        cmd_new(Some(src_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_new(Some(dst_dir.path().to_path_buf()), false)
            .await
            .unwrap();

        let backup = src_dir.path().join("identity.pem.bak");
        cmd_backup(Some(backup.clone()), Some(src_dir.path().to_path_buf()))
            .await
            .unwrap();

        // Simulate user typing "y" at the --force prompt
        let mut reader = std::io::Cursor::new(b"y\n");
        cmd_restore_with_reader(
            backup,
            Some(dst_dir.path().to_path_buf()),
            true,
            &mut reader,
        )
        .await
        .unwrap();

        let src_kp = load_keypair_from_dir(Some(src_dir.path())).unwrap();
        let dst_kp = load_keypair_from_dir(Some(dst_dir.path())).unwrap();
        assert_eq!(src_kp.did(), dst_kp.did());
    }

    #[tokio::test]
    async fn test_cmd_restore_force_aborts_on_n() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        cmd_new(Some(src_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        cmd_new(Some(dst_dir.path().to_path_buf()), false)
            .await
            .unwrap();
        let original_did = load_keypair_from_dir(Some(dst_dir.path())).unwrap().did();

        let backup = src_dir.path().join("identity.pem.bak");
        cmd_backup(Some(backup.clone()), Some(src_dir.path().to_path_buf()))
            .await
            .unwrap();

        // Simulate user typing "n" — should abort
        let mut reader = std::io::Cursor::new(b"n\n");
        cmd_restore_with_reader(
            backup,
            Some(dst_dir.path().to_path_buf()),
            true,
            &mut reader,
        )
        .await
        .unwrap();

        let dst_kp = load_keypair_from_dir(Some(dst_dir.path())).unwrap();
        assert_eq!(original_did, dst_kp.did());
    }

    // ── GITLAWB_PROXY_DID (proxy mode) ──────────────────────────────────

    use crate::identity::test_env::{ProxyDidEnv, REAL_DID};

    #[tokio::test]
    async fn load_keypair_applies_proxy_did_env() {
        let _env = ProxyDidEnv::set(Some(REAL_DID));
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();

        let kp = load_keypair_from_dir(Some(dir.path())).unwrap();
        assert_eq!(kp.did().to_string(), REAL_DID);
        assert_ne!(
            kp.local_did().to_string(),
            REAL_DID,
            "the presented DID must differ from the local key's DID"
        );
    }

    #[tokio::test]
    async fn load_keypair_without_proxy_did_env_is_unchanged() {
        let _env = ProxyDidEnv::set(None);
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();

        let kp = load_keypair_from_dir(Some(dir.path())).unwrap();
        assert_eq!(kp.did(), kp.local_did());
        assert_eq!(kp.public_did_override(), None);
    }

    #[tokio::test]
    async fn load_keypair_with_invalid_proxy_did_env_errors() {
        let _env = ProxyDidEnv::set(Some("not-a-did"));
        let dir = TempDir::new().unwrap();
        cmd_new(Some(dir.path().to_path_buf()), false)
            .await
            .unwrap();

        let err = load_keypair_from_dir(Some(dir.path()))
            .err()
            .expect("expected the invalid GITLAWB_PROXY_DID to fail the load");
        assert!(
            err.to_string().contains("GITLAWB_PROXY_DID"),
            "the error must name the offending variable, got: {err}"
        );
    }
}
