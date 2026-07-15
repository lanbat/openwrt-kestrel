use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "nft-resolve",
    about = "Resolve domain blocklists into nftables sets",
    override_usage = "nft-resolve -4 SET4 -6 SET6 [OPTIONS] [FORMAT=]SOURCE..."
)]
pub struct Args {
    /// IPv4 nft set name, or - to skip
    #[arg(short = '4', value_name = "SET")]
    pub set4: String,

    /// IPv6 nft set name, or - to skip
    #[arg(short = '6', value_name = "SET")]
    pub set6: String,

    /// nft family
    #[arg(short = 'F', default_value = "inet", value_name = "FAMILY")]
    pub family: String,

    /// nft table
    #[arg(short = 'T', default_value = "fw4", value_name = "TABLE")]
    pub table: String,

    /// DNS resolver IP
    #[arg(short = 'R', default_value = "127.0.0.1", value_name = "IP")]
    pub resolver: String,

    /// Default format for bare SOURCE arguments
    #[arg(short = 'f', default_value = "auto", value_name = "FORMAT")]
    pub default_format: String,

    /// Do not resolve domains; only load direct IP/CIDR entries
    #[arg(short = 'n', long = "no-resolve")]
    pub no_resolve: bool,

    /// Write normalised domains to FILE as well
    #[arg(short = 'd', long = "domains-out", value_name = "FILE")]
    pub domains_out: Option<String>,

    /// Sources: [FORMAT=]SOURCE (https://..., /path/file, -)
    #[arg(value_name = "SOURCE", required = true)]
    pub sources: Vec<String>,
}
