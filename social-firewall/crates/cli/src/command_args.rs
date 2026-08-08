use anyhow::Result;

pub(crate) fn split(input: &str) -> Result<Vec<String>> {
    Ok(shell_words::split(input)?)
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn preserves_quoted_arguments_for_all_command_adapters() {
        assert_eq!(
            split("vote --note \"known tracker\"").unwrap(),
            vec!["vote", "--note", "known tracker"]
        );
    }
}
