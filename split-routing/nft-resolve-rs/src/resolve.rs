use std::net::{IpAddr, SocketAddr};
use hickory_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol},
};
use tokio::task::JoinSet;

pub struct ResolveResults {
    pub ip4: Vec<String>,
    pub ip6: Vec<String>,
}

pub async fn resolve_all(domains: &[String], resolver_ip: &str) -> ResolveResults {
    let resolver = build_resolver(resolver_ip);

    let mut set: JoinSet<(Vec<String>, Vec<String>)> = JoinSet::new();

    for domain in domains {
        let resolver = resolver.clone();
        let domain = domain.clone();
        set.spawn(async move {
            resolve_one(&resolver, &domain).await
        });
    }

    let mut ip4 = Vec::new();
    let mut ip6 = Vec::new();

    while let Some(res) = set.join_next().await {
        match res {
            Ok((v4, v6)) => {
                ip4.extend(v4);
                ip6.extend(v6);
            }
            Err(_) => {} // task panicked; skip
        }
    }

    ResolveResults { ip4, ip6 }
}

async fn resolve_one(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    if let Ok(resp) = resolver.ipv4_lookup(domain).await {
        v4.extend(resp.iter().map(|r| r.to_string()));
    }
    if let Ok(resp) = resolver.ipv6_lookup(domain).await {
        v6.extend(resp.iter().map(|r| r.to_string()));
    }

    (v4, v6)
}

fn build_resolver(resolver_ip: &str) -> TokioAsyncResolver {
    let addr: IpAddr = resolver_ip
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let socket = SocketAddr::new(addr, 53);

    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: socket,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });

    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(3);
    opts.attempts = 2;

    TokioAsyncResolver::tokio(config, opts)
}
