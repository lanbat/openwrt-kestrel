//! Detail page for a single plugin (`/cgi-bin/plugin_info?name=<name>`),
//! linked from a plugin-contributed note on the device page (see
//! `plugins::Action::Annotate`). Reads `{plugins::PLUGINS_DIR}/{name}.info`
//! — the daemon writes one whenever a plugin is discovered (`RustPlugin`s)
//! or self-reports one via an `Info` line (external plugins); this route
//! itself never talks to the live `PluginManager`, which only exists
//! inside the long-running daemon process, not this one-shot CGI request.

use axum::{extract::Query, response::Html};
use askama::Template;
use serde::Deserialize;

use crate::data::files;
use crate::plugins;

#[derive(Template)]
#[template(path = "plugin_info.html")]
struct PluginInfoTmpl {
    name: String,
    kind: String,
    version: String,
    maintainer: String,
    website: String,
    description: String,
    known: bool,
}

#[derive(Deserialize)]
pub struct PluginInfoQuery {
    pub name: Option<String>,
}

pub async fn get(Query(params): Query<PluginInfoQuery>) -> Html<String> {
    let name = params.name.as_deref().unwrap_or("");
    if !files::is_valid_plugin_name(name) {
        return Html("<h1>Invalid plugin name</h1>".into());
    }

    let info = plugins::read_plugin_info(std::path::Path::new(plugins::PLUGINS_DIR), name).await;
    let tmpl = match info {
        Some(i) => PluginInfoTmpl {
            name: name.to_string(),
            kind: if i.kind == "rust" { "Compiled-in (ships with kestreld)".to_string() } else { "External script".to_string() },
            version: i.version,
            maintainer: if i.maintainer.is_empty() { "kestreld".to_string() } else { i.maintainer },
            website: i.website,
            description: if i.description.is_empty() {
                "This plugin hasn't reported a description of itself.".to_string()
            } else {
                i.description
            },
            known: true,
        },
        None => PluginInfoTmpl {
            name: name.to_string(),
            kind: String::new(),
            version: String::new(),
            maintainer: String::new(),
            website: String::new(),
            description: "No information is on record for this plugin yet — it may not have run since the daemon last started, or it hasn't sent an `info` line describing itself.".to_string(),
            known: false,
        },
    };

    Html(tmpl.render().unwrap_or_default())
}
