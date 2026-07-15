mod args;
mod classify;
mod nft;
mod parse;
mod resolve;
mod source;

use anyhow::{anyhow, bail, Context};
use clap::Parser;

use args::Args;
use classify::{classify, dedup_sorted};
use nft::{apply, NftConfig};
use parse::{parse, Format};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.set4 == "-" && args.set6 == "-" {
        bail!("both IPv4 and IPv6 sets are disabled");
    }

    let default_fmt = Format::parse(&args.default_format)
        .ok_or_else(|| anyhow!("unknown format: {}", args.default_format))?;

    // Fetch and parse all sources (in parallel for multiple URLs)
    let mut fetch_tasks = tokio::task::JoinSet::new();
    for spec in &args.sources {
        let (fmt, src) = split_spec(spec, default_fmt)?;
        let src: String = src.to_string();
        fetch_tasks.spawn(async move {
            let content = source::fetch(&src).await
                .with_context(|| format!("failed to fetch: {src}"))?;
            anyhow::Ok(parse(fmt, &content))
        });
    }

    let mut all_candidates: Vec<String> = Vec::new();
    while let Some(res) = fetch_tasks.join_next().await {
        all_candidates.extend(res??);
    }

    // Classify into domains, IPv4, IPv6
    let mut classified = classify(&all_candidates);
    dedup_sorted(&mut classified.domains);
    dedup_sorted(&mut classified.ip4);
    dedup_sorted(&mut classified.ip6);

    let domain_count = classified.domains.len();
    let source_count = args.sources.len();

    if let Some(ref path) = args.domains_out {
        tokio::fs::write(path, classified.domains.join("\n") + "\n").await
            .with_context(|| format!("failed to write domains to {path}") )?;
    }

    // Resolve domains in parallel
    if !args.no_resolve && !classified.domains.is_empty() {
        let resolved = resolve::resolve_all(&classified.domains, &args.resolver).await;
        classified.ip4.extend(resolved.ip4);
        classified.ip6.extend(resolved.ip6);
        dedup_sorted(&mut classified.ip4);
        dedup_sorted(&mut classified.ip6);
    }

    // Apply to nftables
    apply(&NftConfig {
        family: &args.family,
        table:  &args.table,
        set4:   &args.set4,
        set6:   &args.set6,
        ip4:    &classified.ip4,
        ip6:    &classified.ip6,
        chunk4: 400,
        chunk6: 200,
    }).await?;

    eprintln!("Updated nft sets in {} {}", args.family, args.table);
    if args.set4 != "-" {
        eprintln!("IPv4 set {}: {} elements", args.set4, classified.ip4.len());
    }
    if args.set6 != "-" {
        eprintln!("IPv6 set {}: {} elements", args.set6, classified.ip6.len());
    }
    eprintln!("Domains parsed: {domain_count} from {source_count} source(s)");

    Ok(())
}

fn split_spec(spec: &str, default_fmt: Format) -> anyhow::Result<(Format, &str)> {
    if let Some(eq) = spec.find('=') {
        let prefix = &spec[..eq];
        if let Some(fmt) = Format::parse(prefix) {
            return Ok((fmt, &spec[eq+1..]));
        }
    }
    Ok((default_fmt, spec))
}
