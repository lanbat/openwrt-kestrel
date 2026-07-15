pub async fn fetch(src: &str) -> anyhow::Result<String> {
    if src == "-" {
        use tokio::io::AsyncReadExt;
        let mut buf = String::new();
        tokio::io::stdin().read_to_string(&mut buf).await?;
        return Ok(buf);
    }
    if src.starts_with("http://") || src.starts_with("https://") {
        let body = reqwest::get(src).await?.error_for_status()?.text().await?;
        return Ok(body);
    }
    Ok(tokio::fs::read_to_string(src).await?)
}
