use std::fmt::Write as FmtWrite;
use tokio::process::Command;

pub struct NftConfig<'a> {
    pub family: &'a str,
    pub table:  &'a str,
    pub set4:   &'a str,
    pub set6:   &'a str,
    pub ip4:    &'a [String],
    pub ip6:    &'a [String],
    pub chunk4: usize,
    pub chunk6: usize,
}

pub async fn apply(cfg: &NftConfig<'_>) -> anyhow::Result<()> {
    // Ensure the table exists
    let check = Command::new("nft")
        .args(["list", "table", cfg.family, cfg.table])
        .output()
        .await?;
    if !check.status.success() {
        anyhow::bail!(
            "nft table does not exist: {} {}",
            cfg.family, cfg.table
        );
    }

    // Ensure sets exist (idempotent)
    if cfg.set4 != "-" {
        let _ = Command::new("nft")
            .args([
                "add", "set", cfg.family, cfg.table, cfg.set4,
                "{ type ipv4_addr; flags interval; }",
            ])
            .status()
            .await;
    }
    if cfg.set6 != "-" {
        let _ = Command::new("nft")
            .args([
                "add", "set", cfg.family, cfg.table, cfg.set6,
                "{ type ipv6_addr; flags interval; }",
            ])
            .status()
            .await;
    }

    let cmds = build_commands(cfg);

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(cmds.as_bytes()).await?;
    }

    let status = child.wait().await?;
    if !status.success() {
        anyhow::bail!("nft -f - failed with status {status}");
    }
    Ok(())
}

fn build_commands(cfg: &NftConfig<'_>) -> String {
    let mut s = String::new();
    if cfg.set4 != "-" {
        emit_set(&mut s, cfg.family, cfg.table, cfg.set4, cfg.ip4, cfg.chunk4);
    }
    if cfg.set6 != "-" {
        emit_set(&mut s, cfg.family, cfg.table, cfg.set6, cfg.ip6, cfg.chunk6);
    }
    s
}

fn emit_set(
    out: &mut String,
    family: &str,
    table: &str,
    set: &str,
    ips: &[String],
    chunk: usize,
) {
    writeln!(out, "flush set {family} {table} {set}").unwrap();
    for chunk_ips in ips.chunks(chunk) {
        let elements = chunk_ips.join(", ");
        writeln!(out, "add element {family} {table} {set} {{ {elements} }}").unwrap();
    }
}
