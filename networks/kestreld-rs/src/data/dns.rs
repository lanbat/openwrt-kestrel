use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::task::JoinSet;

use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

#[derive(Default, Clone)]
pub struct DnsCache {
    /// ip → hostname
    pub map: HashMap<String, String>,
}

impl DnsCache {
    pub fn lookup(&self, ip: &str) -> Option<&str> {
        self.map.get(ip).map(|s| s.as_str())
    }
}

pub async fn resolve_all(ips: &[String], resolver_ip: &str) -> DnsCache {
    let resolver = build_resolver(resolver_ip);
    let mut set: JoinSet<(String, Option<String>)> = JoinSet::new();

    for ip in ips {
        let resolver = resolver.clone();
        let ip = ip.clone();
        set.spawn(async move {
            let name = reverse_lookup(&resolver, &ip).await;
            (ip, name)
        });
    }

    let mut map = HashMap::new();
    while let Some(Ok((ip, name))) = set.join_next().await {
        if let Some(name) = name {
            map.insert(ip, name);
        }
    }

    DnsCache { map }
}

async fn reverse_lookup(resolver: &TokioAsyncResolver, ip: &str) -> Option<String> {
    let addr = IpAddr::from_str(ip).ok()?;
    let result = resolver.reverse_lookup(addr).await.ok()?;
    result
        .iter()
        .next()
        .map(|name| name.to_string().trim_end_matches('.').to_string())
}

fn build_resolver(resolver_ip: &str) -> Arc<TokioAsyncResolver> {
    let ip: std::net::IpAddr = resolver_ip.parse().unwrap_or([1, 1, 1, 1].into());
    let socket = SocketAddr::new(ip, 53);
    let ns = NameServerConfig {
        socket_addr: socket,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    };
    let mut config = ResolverConfig::new();
    config.add_name_server(ns);
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(2);
    opts.attempts = 1;
    Arc::new(TokioAsyncResolver::tokio(config, opts))
}
