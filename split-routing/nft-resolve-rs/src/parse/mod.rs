mod auto;
mod hosts;
mod adblock;
mod url;
mod dnsmasq;
mod rpz;
mod unbound;
mod ipset;
mod clash;
mod oneper;

pub use auto::parse_auto;
pub use hosts::parse_hosts;
pub use adblock::parse_adblock;
pub use url::parse_url;
pub use dnsmasq::parse_dnsmasq;
pub use rpz::parse_rpz;
pub use unbound::parse_unbound;
pub use ipset::parse_ipset;
pub use clash::parse_clash;
pub use oneper::parse_oneper;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Auto,
    Domain,
    Hosts,
    Adblock,
    Url,
    Dnsmasq,
    Rpz,
    Unbound,
    Ipset,
    Clash,
    Ip,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto"                              => Some(Self::Auto),
            "domain" | "domains"               => Some(Self::Domain),
            "hosts"  | "host"                  => Some(Self::Hosts),
            "adblock"| "abp" | "ublock"        => Some(Self::Adblock),
            "url"    | "urls" | "tracker" | "trackers" => Some(Self::Url),
            "dnsmasq"                          => Some(Self::Dnsmasq),
            "rpz"                              => Some(Self::Rpz),
            "unbound"                          => Some(Self::Unbound),
            "ipset"                            => Some(Self::Ipset),
            "clash"  | "surge"                 => Some(Self::Clash),
            "ip"     | "ips" | "cidr"          => Some(Self::Ip),
            _                                  => None,
        }
    }
}

pub fn parse(fmt: Format, content: &str) -> Vec<String> {
    match fmt {
        Format::Auto    => parse_auto(content),
        Format::Domain  => parse_oneper(content),
        Format::Hosts   => parse_hosts(content),
        Format::Adblock => parse_adblock(content),
        Format::Url     => parse_url(content),
        Format::Dnsmasq => parse_dnsmasq(content),
        Format::Rpz     => parse_rpz(content),
        Format::Unbound => parse_unbound(content),
        Format::Ipset   => parse_ipset(content),
        Format::Clash   => parse_clash(content),
        Format::Ip      => parse_oneper(content),
    }
}

// Shared helpers used by multiple parsers

pub fn trim_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None    => line,
    }
}

pub fn strip_crlf(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}
