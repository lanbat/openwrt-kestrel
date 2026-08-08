//! CGI entry point for the interactive party-line chat.

use crate::auth;
use anyhow::Result;
use domain_types::GroupId;
use state_store::StateStore;
use std::io::Write;
use std::path::Path;

const DB_PATH: &str = "/etc/kestrel/social-firewall/social-firewall.sqlite";
const CHAT_OUT_DIR: &str = "/etc/kestrel/social-firewall/chat-out";
const FONT_DATA: &[u8] = include_bytes!("../assets/FixedsysExcelsiorNerdFont-Regular.ttf");
const COMMAND_ASSIST_SCRIPT: &str = r#"<script>(function(){var input=document.querySelector('input[name=input]'),assist=document.getElementById('command-assist');if(!input||!assist)return;var title=document.getElementById('command-assist-title'),detail=document.getElementById('command-assist-detail'),matchesNode=document.getElementById('command-assist-matches');var docs=[{name:'/nick',args:'[name]',desc:'Set or clear your local nickname.'},{name:'/join',args:'<group>',desc:'Join or select a group by name or ID.'},{name:'/list',args:'',desc:'List available groups.'},{name:'/names',args:'',desc:'Show users in the current group.'},{name:'/topic',args:'[text]',desc:'Show or change the current group topic.'},{name:'/msg',args:'<group> <message>',desc:'Send a message to a group.'},{name:'/me',args:'<action>',desc:'Send an IRC-style action message.'},{name:'/history',args:'',desc:'Show recent messages in the current group.'},{name:'/help',args:'[command]',desc:'Show command help.'},{name:'/groups',args:'',desc:'List your groups.'},{name:'/follows',args:'',desc:'List followed identities.'},{name:'/say',args:'<message>',desc:'Send a message to the current group.'},{name:'/log',args:'',desc:'Show the current group transcript.'}];var history=[],historyIndex=-1,lastQuery='',completionIndex=0;function token(){return input.value.trim().split(/\s+/)[0].toLowerCase()}function update(){var value=input.value,t=token();if(value.charAt(0)!=='/'||!t){assist.hidden=true;return}var found=docs.filter(function(d){return d.name.indexOf(t)===0}),exact=docs.find(function(d){return d.name===t});assist.hidden=false;title.textContent=exact?(exact.name+' '+exact.args):(found.length?found.map(function(d){return d.name}).join('   '):'unknown command');detail.textContent=exact?exact.desc:'Press Tab to complete, or keep typing to narrow commands.';matchesNode.textContent=found.length?'matches: '+found.map(function(d){return d.name+' '+d.args}).join('  |  '):'No matching command'}input.addEventListener('input',function(){lastQuery='';completionIndex=0;update()});input.addEventListener('focus',update);input.addEventListener('keydown',function(e){if(e.key==='Escape'){assist.hidden=true;return}if(e.key==='Tab'&&input.value.charAt(0)==='/'){var t=token(),found=docs.filter(function(d){return d.name.indexOf(t)===0});if(found.length){e.preventDefault();if(t!==lastQuery){completionIndex=0;lastQuery=t}input.value=found[completionIndex++%found.length].name+' ';update();return}}if(e.key==='Enter'&&input.value.trim()){history.push(input.value);historyIndex=history.length}if((e.key==='ArrowUp'||e.key==='ArrowDown')&&history.length){e.preventDefault();historyIndex+=e.key==='ArrowUp'?-1:1;historyIndex=Math.max(0,Math.min(history.length,historyIndex));input.value=historyIndex===history.length?'':history[historyIndex];update()}});update()})();</script>"#;
const COMMAND_ASSIST_DOC_SCRIPT: &str = r#"<script>(function(){var i=document.querySelector('input[name=input]'),d=document.getElementById('command-assist-detail'),m=document.getElementById('command-assist-matches');if(!i||!d||!m)return;var docs={'/topic':'Show or change the current group topic.','/nick':'Set or clear your local nickname.','/join':'Join or select a group by name or ID.','/msg':'Send a message to a group.','/me':'Send an IRC-style action message.','/say':'Send a message to the current group.'};i.addEventListener('input',function(){var t=i.value.trim().split(/\s+/)[0].toLowerCase();var out=Object.keys(docs).filter(function(k){return k.indexOf(t)===0}).map(function(k){return k+': '+docs[k]});if(out.length&&t!==out[0].split(':')[0])d.textContent=out.join('  |  ');});})();</script>"#;

const COMMAND_EXAMPLES_SCRIPT: &str = r#"<script>(function(){var i=document.querySelector('input[name=input]'),d=document.getElementById('command-assist-detail');if(!i||!d)return;var examples={'/topic':'example: /topic trusted routers','/nick':'example: /nick living-room','/join':'example: /join GROUP_ID','/msg':'example: /msg alice hello','/me':'example: /me reviews the new policy','/say':'example: /say hello everyone','/mode':'examples: /mode +m, /mode -m, /mode +v USER'};i.addEventListener('input',function(){var t=i.value.trim().split(/\s+/)[0].toLowerCase();if(examples[t])d.textContent=d.textContent.replace(/\s+example[s]?:.*$/i,'')+'  '+examples[t];});})();</script>"#;
const STYLE: &str = "*{box-sizing:border-box}html{background:#008080}body{margin:10px auto;max-width:980px;background:#c0c0c0;color:#000;font-family:Tahoma,Arial,sans-serif;font-size:12px;border:2px solid #fff;border-right-color:#404040;border-bottom-color:#404040;box-shadow:1px 1px 0 #000;padding:3px}h1{margin:0;padding:4px 7px;background:#000080;color:#fff;font-size:13px;font-weight:bold;letter-spacing:.2px;border:1px solid #00005c}.note{margin:3px 2px 5px;padding:2px 5px;color:#000;font-size:11px;background:#d4d0c8;border:1px solid #808080;border-right-color:#fff;border-bottom-color:#fff}nav{display:flex;flex-wrap:wrap;gap:2px;margin:0 2px 4px}nav a{display:inline-block;padding:3px 8px;background:#d4d0c8;color:#000080;text-decoration:none;border:1px solid #fff;border-right-color:#404040;border-bottom-color:#404040;font-weight:bold}nav a:hover{background:#000080;color:#fff}pre.timeline{min-height:280px;margin:0 2px;padding:7px;background:#fff;color:#000;border:2px solid #404040;border-right-color:#fff;border-bottom-color:#fff;overflow:auto;white-space:pre-wrap;word-break:break-word;font-family:\"Fixedsys Excelsior 3.01\",\"Fixedsys Unicode\",\"Lucida Console\",\"Courier New\",monospace;font-size:14px;line-height:1.35}form{display:flex;gap:4px;margin:5px 2px 2px;padding:4px;background:#d4d0c8;border:1px solid #fff;border-right-color:#808080;border-bottom-color:#808080}input[type=text]{min-width:0;flex:1;background:#fff;color:#000;border:2px solid #404040;border-right-color:#fff;border-bottom-color:#fff;font-family:\"Fixedsys Excelsior 3.01\",\"Fixedsys Unicode\",Tahoma,Arial,sans-serif;font-size:13px;padding:4px 5px}button{background:#d4d0c8;color:#000;border:1px solid #fff;border-right-color:#404040;border-bottom-color:#404040;padding:3px 14px;font-family:Tahoma,Arial,sans-serif;font-size:12px;font-weight:bold}button:active{border-color:#404040;border-right-color:#fff;border-bottom-color:#fff;padding-top:4px;padding-left:15px}.error{margin:4px 2px;color:#800000;background:#fff;white-space:pre-wrap;border:1px solid #800000;padding:5px;font-family:\"Fixedsys Excelsior 3.01\",\"Fixedsys Unicode\",\"Lucida Console\",monospace}@media(max-width:600px){body{margin:0;border-width:1px}pre.timeline{min-height:220px;font-size:13px}form{align-items:stretch}button{padding-left:9px;padding-right:9px}}";

const POLICY_STYLE: &str = "*{box-sizing:border-box}:root{color-scheme:light}body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:1rem;color:#111;background:#fff}h1{font-size:1.4rem;margin:.5rem 0 .15rem}h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:#888;border-bottom:1px solid #e0e0e0;padding-bottom:.3rem;margin:1.75rem 0 .6rem}.sub,.note{color:#666;font-size:.88rem}.global-nav{display:flex;flex-wrap:wrap;gap:.7rem;padding-bottom:1rem;border-bottom:1px solid #e5e5e5}.global-nav a{color:#1976d2;text-decoration:none}.global-nav a:hover{text-decoration:underline}.card{background:#f5f5f5;border-radius:8px;padding:.8rem 1rem;margin:.5rem 0;border:1px solid #ececec}.policy-card{display:flex;gap:.7rem;align-items:baseline}.policy-card code{font-size:.76rem;color:#555;word-break:break-all}.badge{font-size:.72rem;font-weight:700;color:#1b5e20;background:#e8f5e9;padding:.18rem .45rem;border-radius:999px;white-space:nowrap}.empty{padding:1rem;color:#777;background:#fafafa;border:1px dashed #ccc;border-radius:8px}form{display:grid;gap:.7rem;background:#f5f5f5;border-radius:8px;padding:1rem;border:1px solid #ececec}label{display:grid;gap:.25rem;font-size:.85rem;color:#555}input,textarea,select{font:inherit;padding:.55rem;border:1px solid #ccc;border-radius:5px;background:#fff;color:#111}button{justify-self:start;background:#1976d2;color:#fff;border:0;border-radius:5px;padding:.55rem .9rem;font-weight:600;cursor:pointer}.notice,.error{padding:.7rem .9rem;border-radius:6px;margin:.7rem 0}.notice{color:#1b5e20;background:#e8f5e9}.error{color:#b71c1c;background:#ffebee}";

fn db_path() -> std::path::PathBuf {
    std::env::var_os("SF_DB_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(DB_PATH).to_path_buf())
}

fn chat_out_dir() -> String {
    std::env::var("SF_CHAT_OUT_DIR").unwrap_or_else(|_| CHAT_OUT_DIR.to_string())
}

pub fn is_cgi() -> bool {
    std::env::var("REQUEST_METHOD").is_ok()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn global_nav() -> &'static str {
    "<nav class=\"global-nav\"><a href=\"/cgi-bin/status\">Router dashboard</a><a href=\"/cgi-bin/sf-groups\">Groups</a><a href=\"/cgi-bin/sf-policies\">Social policies</a><a href=\"/cgi-bin/sf-fingerprint\">Fingerprints</a><a href=\"/cgi-bin/sf-profiles\">Profiles</a><a href=\"/cgi-bin/sf-routes\">Routes</a><a href=\"/cgi-bin/sf-partyline\">Partyline</a></nav>"
}

const PARTYLINE_STYLE: &str = "body.partyline{background:#111827!important;color:#d8dee9!important;border:0!important;box-shadow:none!important;padding:0!important}body.partyline h1{background:#172554!important;border:0!important;color:#e0e7ff!important;padding:.65rem 1rem!important;font-size:1rem!important}body.partyline .note{background:#1f2937!important;border:0!important;color:#93c5fd!important;padding:.45rem .8rem!important}body.partyline nav{background:#111827!important;border:0!important;padding:.35rem .6rem!important}body.partyline nav a{background:#1e293b!important;border:1px solid #334155!important;color:#bfdbfe!important;padding:.35rem .65rem!important}body.partyline nav a:hover{background:#2563eb!important;color:#fff!important}body.partyline .chat-tabs,body.partyline .group-browser,body.partyline .nick-list{background:#172033!important;color:#cbd5e1!important;border-color:#334155!important}body.partyline .chat-tabs button,body.partyline form button{background:#2563eb!important;color:#fff!important;border:1px solid #60a5fa!important}body.partyline .topic{background:#172033!important;color:#bfdbfe!important;border-color:#334155!important}body.partyline pre.timeline{background:#05070b!important;color:#d1d5db!important;border-color:#334155!important;box-shadow:inset 0 0 18px #000!important}body.partyline form{background:#172033!important;border-color:#334155!important}body.partyline input{background:#0f172a!important;color:#f8fafc!important;border-color:#475569!important}body.partyline #command-assist{background:#172033!important;color:#bfdbfe!important;border-color:#475569!important}body.partyline .global-nav{background:#111827!important}.party-event{color:#fbbf24!important}.party-join{color:#86efac!important}.party-leave{color:#fca5a5!important}.party-vote{color:#93c5fd!important}body.partyline .nick-list b{background:#1d4ed8!important;color:#eff6ff!important}body.partyline .nick-list li{color:#cbd5e1!important}";
const PARTYLINE_POLISH: &str = r#"
body.partyline { font-family: system-ui, sans-serif !important; }
body.partyline h1 { letter-spacing: .08em; }
body.partyline .note { border-left: 3px solid #38bdf8 !important; }
body.partyline .chat-tabs { display: flex; gap: .45rem; padding: .45rem .6rem !important; }
body.partyline .chat-tabs button { border-radius: 4px; cursor: pointer; font-weight: 700; }
body.partyline .group-browser { border-radius: 4px; color: #94a3b8 !important; }
body.partyline .party-workspace { height: calc(100vh - 250px) !important; max-height: none !important; min-height: 360px; }
body.partyline #group-panel { display: flex; flex-direction: column; }
body.partyline .topic { border-radius: 4px; font-family: "Fixedsys Excelsior 3.01", monospace !important; }
body.partyline pre.timeline { flex: 1; min-height: 0 !important; border-radius: 5px; font-family: "Fixedsys Excelsior 3.01", monospace !important; font-size: clamp(13px, 1.15vw, 16px) !important; line-height: 1.45 !important; }
body.partyline .nick-list { border-radius: 5px; width: 220px !important; }
body.partyline .composer { align-items: center; border-radius: 5px; margin-top: .6rem; }
body.partyline .composer input { border-radius: 4px; min-height: 38px; }
body.partyline .composer button { border-radius: 4px; min-height: 38px; cursor: pointer; }
body.partyline #command-assist { border-radius: 4px; font-family: "Fixedsys Excelsior 3.01", monospace !important; }
@media (max-width: 700px) {
  body.partyline .party-workspace { height: calc(100vh - 315px) !important; }
  body.partyline .nick-list { display: none; }
  body.partyline .composer { flex-wrap: wrap; }
  body.partyline .composer input { flex-basis: 100%; }
}
"#;

fn policy_cards(output: &str) -> String {
    let cards = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| format!("<article class=\"card policy-card\"><span class=\"badge\">signed collection</span><code>{}</code></article>", escape_html(line)))
        .collect::<String>();
    if cards.is_empty() {
        "<div class=\"empty\"><strong>No shared policies yet.</strong><br>Publish or ingest a signed collection, then review it before selecting a local profile.</div>".into()
    } else {
        cards
    }
}

fn unified_page(title: &str, body: &str) -> String {
    let page = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title><style>{POLICY_STYLE}</style></head><body>{}{body}</body></html>",
        global_nav()
    );
    page
        .replace("<title>social-firewall chat</title>", "<title>partyline</title>")
        .replace("<h1>social-firewall chat</h1>", "<h1>partyline</h1>")
        .replace(
            "<nav><a href=\"/cgi-bin/status\">Router dashboard</a><a href=\"/cgi-bin/sf-policies\">Social policies</a><a href=\"/cgi-bin/sf-fingerprint\">Fingerprints</a><a href=\"/cgi-bin/sf-profiles\">Profiles</a><a href=\"/cgi-bin/sf-routes\">Routes</a><a href=\"/cgi-bin/sf-chat\">Group chat</a></nav>",
            global_nav(),
        )
}

fn render_page(
    store: &StateStore,
    group_id: GroupId,
    timeline: &str,
    result: Option<(bool, String)>,
) -> String {
    let topic = store
        .get_group(group_id)
        .ok()
        .flatten()
        .map(|group| escape_html(&group.description))
        .unwrap_or_else(|| "no topic".to_string());
    let self_user = store
        .get_self_identity()
        .ok()
        .flatten()
        .map(|(user, _)| user);
    let mut group_browser = String::new();
    if let Ok(groups) = store.list_groups() {
        for group in groups {
            let name = escape_html(&group.name);
            let group_ref = crate::group::group_id_str(group.group_id);
            let link = format!("<a href=\"?group={group_ref}\">{name}</a>");
            let is_member = self_user
                .as_ref()
                .map(|user| group.is_member(user))
                .unwrap_or(false);
            if is_member {
                group_browser.push_str(&format!("<span>{link} <small>(joined)</small></span>"));
            } else {
                group_browser.push_str(&format!(
                    "<span>{link} <form method=\"POST\" action=\"?group={group_ref}\" style=\"display:inline\"><input type=\"hidden\" name=\"input\" value=\"/join {group_ref}\"><button type=\"submit\">join</button></form></span>"
                ));
            }
        }
    }
    let mut nick_list = String::new();
    if let Ok(Some(group)) = store.get_group(group_id) {
        let mut members = Vec::new();
        for member in group
            .owners
            .iter()
            .chain(&group.admins)
            .chain(&group.voting_members)
            .chain(&group.non_voting_members)
        {
            if !members.contains(member) {
                members.push(*member);
            }
        }
        for member in members {
            let identity = crate::group::irc_identity(store, &member)
                .unwrap_or_else(|_| crate::tunnel::user_id_str(&member));
            nick_list.push_str(&format!(
                "<li style=\"padding:2px 4px;white-space:nowrap\">{}</li>",
                escape_html(&identity)
            ));
        }
    }
    let nick_panel = format!(
        "<aside class=\"nick-list\" style=\"width:220px;min-width:170px;overflow:auto;background:#fff;border:2px solid #404040;border-right-color:#fff;border-bottom-color:#fff;padding:4px 0\"><b style=\"display:block;padding:2px 6px;background:#000080;color:#fff\">users</b><ul style=\"list-style:none;margin:4px 0;padding:0\">{nick_list}</ul></aside>"
    );
    let has_result = result.is_some();
    let command_tab = if has_result {
        "<button type=\"button\" onclick=\"showChatPanel('command-panel')\">command response</button>"
    } else {
        ""
    };
    let page = render_page_html(store, group_id, timeline, result)
        .replace("<body>", "<body class=\"partyline\" style=\"width:100vw;max-width:none;min-height:100vh;margin:0\">")
        .replace("</head>", &format!("<style>{PARTYLINE_STYLE}{PARTYLINE_POLISH}</style></head>"))
        .replace(
            "</nav>",
            &format!(
                "</nav><div class=\"chat-tabs\" style=\"margin:0 2px 4px;padding:3px;background:#d4d0c8\"><button type=\"button\" onclick=\"showChatPanel('group-panel')\">group</button>{command_tab}</div><section class=\"group-browser\" style=\"margin:0 2px 4px;padding:4px 7px;background:#d4d0c8;border:1px solid #fff;border-right-color:#808080;border-bottom-color:#808080\"><b>groups:</b> {group_browser}</section>"
            ),
        )
        .replace(
        "<pre class=\"timeline\">",
        &format!(
            "<div class=\"party-workspace\" style=\"display:flex;gap:4px;align-items:stretch;height:calc(100vh - 250px);max-height:620px\"><div id=\"group-panel\" style=\"min-width:0;flex:1\"><p class=\"topic\" style=\"margin:0 2px 4px;padding:4px 7px;background:#ffffe1;color:#000080;border:1px solid #808080;border-right-color:#fff;border-bottom-color:#fff;font-family:\\\"Fixedsys Excelsior 3.01\\\",monospace;font-weight:600\"><b>topic:</b> {topic}</p><pre class=\"timeline\" style=\"height:calc(100% - 35px);max-height:none;overflow-y:auto\">"
        ),
    );
    let page = if has_result {
        page.replace(
            "<pre id=\"command-panel\"",
            "</pre></div>{nick_panel}</div><pre id=\"command-panel\"",
        )
    } else {
        page.replace(
            "</pre></div><form",
            &format!("</pre></div>{nick_panel}</div></div><form class=\"composer\""),
        )
    };
    let page = page.replace(
        "<form method=\"POST\"",
        "<form class=\"composer\" method=\"POST\"",
    );
    let page = page.replace(
        r#"font-family:\"Fixedsys Excelsior 3.01\",monospace"#,
        "font-family:'Fixedsys Excelsior 3.01',monospace",
    );
    let page = page.replace(
        "</body>",
        &format!(
            "<script>function showChatPanel(id) {{ document.getElementById('group-panel').style.display = id === 'group-panel' ? 'block' : 'none'; var command = document.getElementById('command-panel'); if (command) command.style.display = id === 'command-panel' ? 'block' : 'none'; }}</script>{COMMAND_ASSIST_SCRIPT}{COMMAND_ASSIST_DOC_SCRIPT}{COMMAND_EXAMPLES_SCRIPT}</body>"
        ),
    );
    page
}

fn render_page_html(
    store: &StateStore,
    group_id: GroupId,
    timeline: &str,
    result: Option<(bool, String)>,
) -> String {
    let nav = store
        .list_groups()
        .unwrap_or_default()
        .iter()
        .map(|group| {
            format!(
                "<a href=\"?group={}\">{}</a>",
                crate::group::group_id_str(group.group_id),
                escape_html(&group.name)
            )
        })
        .collect::<String>();
    let result = result
        .map(|(success, output)| {
            format!(
                "<pre id=\"command-panel\" style=\"display:none;max-height:calc(100vh - 250px);overflow:auto\"{}>{}</pre>",
                if success { "" } else { " class=\"error\"" },
                escape_html(&output)
            )
        })
        .unwrap_or_default();
    let group = crate::group::group_id_str(group_id);
    let page = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>social-firewall chat</title><style>@font-face{{font-family:\"Fixedsys Excelsior 3.01\";src:url(\"/cgi-bin/sf-chat-font\") format(\"truetype\");font-weight:400;font-style:normal;font-display:swap}}{STYLE}</style></head><body><h1>social-firewall chat</h1><p class=\"note\">party-line chat - refreshes automatically while idle</p><nav><a href=\"/cgi-bin/status\">Router dashboard</a><a href=\"/cgi-bin/sf-policies\">Social policies</a><a href=\"/cgi-bin/sf-fingerprint\">Fingerprints</a><a href=\"/cgi-bin/sf-profiles\">Profiles</a><a href=\"/cgi-bin/sf-routes\">Routes</a><a href=\"/cgi-bin/sf-chat\">Group chat</a></nav><nav>{nav}</nav><pre class=\"timeline\">{}</pre>{result}<form method=\"POST\" action=\"?group={group}\"><input type=\"hidden\" name=\"group\" value=\"{group}\"><input type=\"text\" name=\"input\" placeholder=\"message, or /command --flags\" autofocus><button type=\"submit\">send</button><button type=\"button\" onclick=\"window.location.reload()\">refresh</button></form><div id=\"command-assist\" hidden style=\"margin:0 2px 4px;padding:4px 6px;background:#ffffe1;color:#000080;border:1px solid #808080;font-family:'Fixedsys Excelsior 3.01',monospace\"><b id=\"command-assist-title\"></b><span id=\"command-assist-detail\" style=\"margin-left:8px;color:#000\"></span><div id=\"command-assist-matches\" style=\"margin-top:2px;color:#606060\"></div></div><script>setInterval(function() {{ var input=document.querySelector('input[name=input]'); if (document.activeElement === input || input.value.length > 0) return; window.location.reload(); }}, 3000);</script></body></html>",
        render_timeline_html(timeline)
    );
    page
        .replace("<title>social-firewall chat</title>", "<title>partyline</title>")
        .replace("<h1>social-firewall chat</h1>", "<h1>partyline</h1>")
        .replace(
            "<nav><a href=\"/cgi-bin/status\">Router dashboard</a><a href=\"/cgi-bin/sf-policies\">Social policies</a><a href=\"/cgi-bin/sf-fingerprint\">Fingerprints</a><a href=\"/cgi-bin/sf-profiles\">Profiles</a><a href=\"/cgi-bin/sf-routes\">Routes</a><a href=\"/cgi-bin/sf-chat\">Group chat</a></nav>",
            global_nav(),
        )
}

fn render_timeline_html(timeline: &str) -> String {
    timeline
        .lines()
        .map(|line| {
            let color = if line.contains("has joined") {
                "#55ff55"
            } else if line.contains("has left") {
                "#ff5555"
            } else if line.contains("voted ") {
                "#55aaff"
            } else if line.starts_with("Error:") || line.contains("could not") {
                "#ff5555"
            } else if line.starts_with("no party-line")
                || line.starts_with("group ")
                || line.starts_with("topic:")
            {
                "#aaaaaa"
            } else {
                "#f0f0f0"
            };
            format!("<span style=\"color:{color}\">{}</span>", escape_html(line))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct ChatQuery {
    group: Option<String>,
    notice: Option<String>,
    success: Option<bool>,
}

pub fn run_cgi() {
    if std::env::var("SCRIPT_NAME").as_deref() != Ok("/cgi-bin/sf-chat-font") && auth::required() {
        match auth::current() {
            Ok(Some(_user)) => {}
            Ok(None) => return print!("{}", auth::reject_response("missing identity headers")),
            Err(reason) => return print!("{}", auth::reject_response(reason)),
        }
    }
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    if method != "GET"
        && method != "HEAD"
        && std::env::var("SCRIPT_NAME").as_deref() != Ok("/cgi-bin/sf-chat-font")
    {
        if let Err(failure) = auth::authorize_mutation() {
            return match failure {
                auth::AuthFailure::MissingIdentity => {
                    print!("{}", auth::reject_response("missing identity headers"))
                }
                auth::AuthFailure::InvalidIdentity(reason) => {
                    print!("{}", auth::reject_response(reason))
                }
                auth::AuthFailure::MissingEntitlement(entitlement) => {
                    print!(
                        "{}",
                        auth::forbidden_response(&format!("missing {entitlement}"))
                    )
                }
            };
        }
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-chat-font") {
        print!("Status: 200 OK\r\nContent-Type: font/ttf\r\nCache-Control: public, max-age=31536000, immutable\r\nContent-Length: {}\r\n\r\n", FONT_DATA.len());
        let _ = std::io::stdout().write_all(FONT_DATA);
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-groups") {
        run_groups_cgi();
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-policies") {
        run_policy_cgi();
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-policy-vote") {
        run_policy_vote_cgi();
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-policy-explain") {
        run_policy_explain_cgi();
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-fingerprint") {
        run_fingerprint_cgi();
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-profiles") {
        run_profiles_cgi();
        return;
    }
    if std::env::var("SCRIPT_NAME").as_deref() == Ok("/cgi-bin/sf-routes") {
        run_routes_cgi();
        return;
    }
    let db_path = db_path();
    let store = match StateStore::open(&db_path) {
        Ok(store) => store,
        Err(error) => {
            print!("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nfailed to open state store: {error}");
            return;
        }
    };
    let query = std::env::var("QUERY_STRING").unwrap_or_default();
    let query: ChatQuery = serde_urlencoded::from_str(&query).unwrap_or_default();
    let group_id = match resolve_group(&store, query.group.as_deref()) {
        Ok(group_id) => group_id,
        Err(error) => {
            print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n{error}");
            return;
        }
    };
    match std::env::var("REQUEST_METHOD").unwrap_or_default().as_str() {
        "GET" => {
            let group = crate::group::group_id_str(group_id);
            let timeline = run_sf_subprocess(&["list-party-line", "--group", &group]);
            let success = query.success.unwrap_or(false);
            let result = query.notice.map(|notice| (success, notice));
            let html = render_page(&store, group_id, &timeline.output, result);
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
        }
        "POST" => handle_post(group_id),
        _ => print!(
            "Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nmethod not allowed"
        ),
    }
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct PolicyQuery {
    notice: Option<String>,
    success: Option<bool>,
}

#[derive(serde::Deserialize)]
struct PolicyForm {
    policy_id: String,
    name: String,
    description: String,
    categories: Option<String>,
    entries: String,
}

fn run_policy_cgi() {
    let query: PolicyQuery =
        serde_urlencoded::from_str(&std::env::var("QUERY_STRING").unwrap_or_default())
            .unwrap_or_default();
    match std::env::var("REQUEST_METHOD").unwrap_or_default().as_str() {
        "GET" => {
            let result = run_sf_subprocess(&["list-policies"]);
            let notice = query
                .notice
                .map(|message| {
                    format!(
                        "<div class=\"{}\">{}</div>",
                        if query.success.unwrap_or(false) {
                            "notice"
                        } else {
                            "error"
                        },
                        escape_html(&message)
                    )
                })
                .unwrap_or_default();
            let cards = policy_cards(&result.output);
            let html = format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Shared policies</title><style>{POLICY_STYLE}</style></head><body>{}<h1>Shared policies</h1><p class=\"sub\">Signed collections from trusted routers. Review provenance and effects before selecting a local profile.</p>{}<h2>Available collections</h2>{}<h2>Publish a collection</h2><form method=\"POST\"><label>Policy ID <input name=\"policy_id\" required pattern=\"[0-9a-fA-F]{{64}}\"></label><label>Name <input name=\"name\" required></label><label>Description <input name=\"description\" required></label><label>Categories <input name=\"categories\" placeholder=\"privacy,dns\"></label><label>Entries JSON <textarea name=\"entries\" required rows=\"10\">[{{&quot;target_kind&quot;:&quot;domain&quot;,&quot;target_value&quot;:&quot;example.com&quot;,&quot;action&quot;:&quot;dns_block&quot;,&quot;reason_code&quot;:&quot;tracker&quot;}}]</textarea></label><button type=\"submit\">Publish signed collection</button></form><p class=\"note\"><a href=\"/cgi-bin/sf-profiles\">Choose a local profile</a> · <a href=\"/cgi-bin/sf-routes\">Review route effects</a> · <a href=\"/cgi-bin/sf-chat\">Discuss in group chat</a></p></body></html>", global_nav(), notice, cards);
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
        }
        "POST" => {
            let body = read_stdin_body();
            let form: PolicyForm = match serde_urlencoded::from_str(&body) {
                Ok(form) => form,
                Err(error) => {
                    print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\ninvalid policy form: {error}");
                    return;
                }
            };
            let path =
                std::env::temp_dir().join(format!("sf-policy-{}-entries.json", std::process::id()));
            if let Err(error) = std::fs::write(&path, &form.entries) {
                redirect_policy_result(false, format!("could not write entries: {error}"));
                return;
            }
            let categories = form.categories.unwrap_or_default();
            let mut args = vec![
                "publish-policy".to_string(),
                "--policy-id".into(),
                form.policy_id,
                "--name".into(),
                form.name,
                "--description".into(),
                form.description,
                "--entries-file".into(),
                path.display().to_string(),
            ];
            for category in categories
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                args.push("--category".into());
                args.push(category.into());
            }
            let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let result = run_sf_subprocess(&refs);
            let _ = std::fs::remove_file(path);
            redirect_policy_result(result.success, result.output);
        }
        _ => print!(
            "Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nmethod not allowed"
        ),
    }
}

fn redirect_policy_result(success: bool, notice: String) {
    let query = serde_urlencoded::to_string(PolicyQuery {
        notice: Some(notice),
        success: Some(success),
    })
    .unwrap_or_default();
    print!("Status: 303 See Other\r\nLocation: ?{query}\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n");
}

#[derive(serde::Deserialize)]
struct PolicyVoteForm {
    policy_id: String,
    entry_id: String,
    group: String,
    stance: String,
    reason_code: String,
    note: Option<String>,
}

fn run_policy_vote_cgi() {
    match std::env::var("REQUEST_METHOD").unwrap_or_default().as_str() {
        "GET" => {
            let html = unified_page("Vote on policy", "<h1>Vote on policy entry</h1><p class=\"sub\">Votes are signed by this router and scoped to a group.</p><form method=\"POST\"><label>Policy ID <input name=\"policy_id\" required></label><label>Entry ID <input name=\"entry_id\" required></label><label>Group <input name=\"group\" required></label><label>Stance <select name=\"stance\"><option>allow</option><option selected>deny</option><option>ask</option></select></label><label>Reason <input name=\"reason_code\" value=\"other\" required></label><label>Note <input name=\"note\"></label><button type=\"submit\">Cast vote</button></form>");
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
        }
        "POST" => {
            let form: PolicyVoteForm = match serde_urlencoded::from_str(&read_stdin_body()) {
                Ok(form) => form,
                Err(error) => {
                    print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\ninvalid vote form: {error}");
                    return;
                }
            };
            let mut args = vec![
                "vote-policy-entry",
                "--policy-id",
                &form.policy_id,
                "--entry-id",
                &form.entry_id,
                "--group",
                &form.group,
                "--stance",
                &form.stance,
                "--reason-code",
                &form.reason_code,
            ];
            if let Some(note) = form.note.as_deref() {
                args.extend(["--note", note]);
            }
            let result = run_sf_subprocess(&args);
            redirect_policy_result(result.success, result.output);
        }
        _ => print!(
            "Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nmethod not allowed"
        ),
    }
}

#[derive(serde::Deserialize, Default)]
struct PolicyExplainQuery {
    policy_id: Option<String>,
    entry_id: Option<String>,
    group: Option<String>,
}

fn run_policy_explain_cgi() {
    let query: PolicyExplainQuery =
        serde_urlencoded::from_str(&std::env::var("QUERY_STRING").unwrap_or_default())
            .unwrap_or_default();
    let output = match (
        query.policy_id.as_deref(),
        query.entry_id.as_deref(),
        query.group.as_deref(),
    ) {
        (Some(policy_id), Some(entry_id), Some(group)) => {
            run_sf_subprocess(&[
                "explain-policy-entry",
                "--policy-id",
                policy_id,
                "--entry-id",
                entry_id,
                "--group",
                group,
            ])
            .output
        }
        _ => "Provide policy_id, entry_id, and group in the query string.".into(),
    };
    let html = unified_page("Policy explanation", &format!("<h1>Policy explanation</h1><div class=\"card\"><pre>{}</pre></div><p class=\"note\"><a href=\"/cgi-bin/sf-policy-vote\">Vote on an entry</a></p>", escape_html(&output)));
    print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
}

#[derive(serde::Deserialize, Default)]
struct FingerprintQuery {
    group: Option<String>,
    fingerprint_id: Option<String>,
    revision: Option<u64>,
}

#[derive(serde::Deserialize)]
struct FingerprintCommentForm {
    group: String,
    fingerprint_id: String,
    revision: u64,
    body: String,
}

fn run_fingerprint_cgi() {
    let query: FingerprintQuery =
        serde_urlencoded::from_str(&std::env::var("QUERY_STRING").unwrap_or_default())
            .unwrap_or_default();
    match std::env::var("REQUEST_METHOD").unwrap_or_default().as_str() {
        "GET" => {
            let output = match (
                query.group.as_deref(),
                query.fingerprint_id.as_deref(),
                query.revision,
            ) {
                (Some(group), Some(fingerprint_id), Some(revision)) => {
                    run_sf_subprocess(&[
                        "list-fingerprint",
                        "--group",
                        group,
                        "--fingerprint-id",
                        fingerprint_id,
                        "--revision",
                        &revision.to_string(),
                    ])
                    .output
                }
                _ => "Provide group, fingerprint_id, and revision to inspect a fingerprint.".into(),
            };
            let html = format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>group fingerprint</title><style>{STYLE}</style></head><body>{}<h1>group fingerprint</h1><p class=\"note\">Compare privacy-filtered observations from trusted routers. A shared fingerprint is evidence, not a proven device identity.</p><pre>{}</pre><h2>comment</h2><form method=\"POST\"><input name=\"group\" placeholder=\"group ID\" required><input name=\"fingerprint_id\" placeholder=\"fingerprint ID\" required><input name=\"revision\" type=\"number\" min=\"0\" required><textarea name=\"body\" maxlength=\"4096\" required></textarea><button type=\"submit\">comment</button></form></body></html>", global_nav(), escape_html(&output));
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
        }
        "POST" => {
            let form: FingerprintCommentForm = match serde_urlencoded::from_str(&read_stdin_body())
            {
                Ok(form) => form,
                Err(error) => {
                    print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\ninvalid fingerprint comment: {error}");
                    return;
                }
            };
            let result = run_sf_subprocess(&[
                "publish-fingerprint-comment",
                "--group",
                &form.group,
                "--fingerprint-id",
                &form.fingerprint_id,
                "--revision",
                &form.revision.to_string(),
                "--body",
                &form.body,
            ]);
            redirect_policy_result(result.success, result.output);
        }
        _ => print!(
            "Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nmethod not allowed"
        ),
    }
}

#[derive(serde::Deserialize)]
struct ProfileForm {
    operation: String,
    name: Option<String>,
    description: Option<String>,
    profile_id: Option<String>,
    policy_id: Option<String>,
}

fn run_groups_cgi() {
    if std::env::var("REQUEST_METHOD").unwrap_or_default() != "GET" {
        print!("Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nGET required");
        return;
    }
    let store = match StateStore::open(&db_path()) {
        Ok(store) => store,
        Err(error) => {
            print!("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nfailed to open state store: {error}");
            return;
        }
    };
    let groups = store.list_groups().unwrap_or_default();
    let cards = groups
        .iter()
        .map(|group| {
            let id = crate::group::group_id_str(group.group_id);
            format!(
                "<article class=\"card\"><h2>{}</h2><p class=\"sub\">{}</p><p><a class=\"button\" href=\"/cgi-bin/sf-partyline?group={id}\">Open partyline</a> <a href=\"/cgi-bin/sf-fingerprint?group={id}\">Evidence</a></p></article>",
                escape_html(&group.name),
                escape_html(&group.description),
            )
        })
        .collect::<String>();
    let body = if cards.is_empty() {
        "<div class=\"empty\"><strong>No groups yet.</strong><br>Create or ingest a group before opening partyline.</div>".to_string()
    } else {
        cards
    };
    let html = unified_page(
        "Groups",
        &format!("<h1>Groups</h1><p class=\"sub\">Choose a group to open its IRC-style partyline and shared evidence.</p>{body}"),
    );
    print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
}

fn run_profiles_cgi() {
    match std::env::var("REQUEST_METHOD").unwrap_or_default().as_str() {
        "GET" => {
            let result = run_sf_subprocess(&["list-profiles"]);
            let effects = run_sf_subprocess(&["list-profile-effects"]);
            let html = format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>policy profiles</title><style>{STYLE}</style></head><body>{}<h1>policy profiles</h1><p class=\"note\">Select which advertised policy collections are active locally.</p><pre>{}</pre><h2>selected effects</h2><pre>{}</pre><h2>create profile</h2><form method=\"POST\"><input type=\"hidden\" name=\"operation\" value=\"create\"><input name=\"name\" placeholder=\"Privacy\" required><input name=\"description\" placeholder=\"description\"><button type=\"submit\">create</button></form><h2>select profile</h2><form method=\"POST\"><input type=\"hidden\" name=\"operation\" value=\"select\"><input name=\"profile_id\" placeholder=\"profile ID\" required><button type=\"submit\">select</button></form><h2>add collection</h2><form method=\"POST\"><input type=\"hidden\" name=\"operation\" value=\"add\"><input name=\"profile_id\" placeholder=\"profile ID\" required><input name=\"policy_id\" placeholder=\"policy ID\" required><button type=\"submit\">add</button></form></body></html>", global_nav(), escape_html(&result.output), escape_html(&effects.output));
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
        }
        "POST" => {
            let form: ProfileForm = match serde_urlencoded::from_str(&read_stdin_body()) {
                Ok(form) => form,
                Err(error) => {
                    print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\ninvalid profile form: {error}");
                    return;
                }
            };
            let mut args = Vec::new();
            match form.operation.as_str() {
                "create" => {
                    args.extend([
                        "create-profile".into(),
                        "--name".into(),
                        form.name.unwrap_or_default(),
                        "--description".into(),
                        form.description.unwrap_or_default(),
                    ]);
                }
                "select" => {
                    args.extend([
                        "select-profile".into(),
                        "--profile-id".into(),
                        form.profile_id.unwrap_or_default(),
                    ]);
                }
                "add" => {
                    args.extend([
                        "add-profile-policy".into(),
                        "--profile-id".into(),
                        form.profile_id.unwrap_or_default(),
                        "--policy-id".into(),
                        form.policy_id.unwrap_or_default(),
                    ]);
                }
                _ => {
                    redirect_policy_result(false, "unknown profile operation".into());
                    return;
                }
            }
            let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let result = run_sf_subprocess(&refs);
            redirect_policy_result(result.success, result.output);
        }
        _ => print!(
            "Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nmethod not allowed"
        ),
    }
}

fn run_routes_cgi() {
    if std::env::var("REQUEST_METHOD").unwrap_or_default() != "GET" {
        print!("Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nGET required");
        return;
    }
    let profiles = run_sf_subprocess(&["list-route-profiles"]);
    let effects = run_sf_subprocess(&["preview-routes"]);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>route profiles</title><style>{STYLE}</style></head><body>{}<h1>route profiles</h1><p class=\"note\">Only locally registered interfaces and tables are eligible. Route and VPN mutation remains disabled until its materializer is installed.</p><pre>{}</pre><h2>policy effects</h2><pre>{}</pre></body></html>",
        global_nav(), escape_html(&profiles.output), escape_html(&effects.output)
    );
    print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
}

fn resolve_group(store: &StateStore, requested: Option<&str>) -> Result<GroupId> {
    match requested {
        Some(group) => crate::group::parse_group_id(group),
        None => {
            let (_, pubkey) = store
                .get_self_identity()?
                .ok_or_else(|| anyhow::anyhow!("no identity yet - run init-identity first"))?;
            Ok(crate::group::self_group_id(&pubkey))
        }
    }
}

struct SubprocessOutput {
    success: bool,
    output: String,
}

fn run_sf_subprocess(args: &[&str]) -> SubprocessOutput {
    let executable = std::env::var_os("SF_EXECUTABLE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| Path::new("/usr/bin/sf").to_path_buf());
    match std::process::Command::new(executable)
        .arg("--db")
        .arg(db_path())
        .args(args)
        // The CGI entry point is selected from REQUEST_METHOD. Remove the
        // inherited CGI environment so the child runs the requested CLI
        // command instead of recursively entering this handler.
        .env_remove("REQUEST_METHOD")
        .env_remove("QUERY_STRING")
        .env_remove("CONTENT_LENGTH")
        .env_remove("CONTENT_TYPE")
        .output()
    {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            SubprocessOutput {
                success: output.status.success(),
                output: text,
            }
        }
        Err(error) => SubprocessOutput {
            success: false,
            output: format!("failed to invoke sf: {error}"),
        },
    }
}

fn build_argv(input: &str, current_group_hex: &str) -> Result<Vec<String>> {
    if let Some(command) = input.strip_prefix('/') {
        let words = crate::command_args::split(command)?;
        if words.is_empty() {
            return Ok(vec!["--help".into()]);
        }
        let shortcut = match words[0].as_str() {
            "help" => Some(vec!["chat-help".into()]),
            "groups" | "list" | "names" => Some(vec!["list-groups".into()]),
            "follows" => Some(vec!["list-follows".into()]),
            "history" | "log" => Some(vec![
                "list-party-line".into(),
                "--group".into(),
                current_group_hex.into(),
            ]),
            "topic" if words.len() > 1 => Some(vec![
                "announce-topic".into(),
                "--group".into(),
                current_group_hex.into(),
                "--topic".into(),
                words[1..].join(" "),
            ]),
            "topic" => Some(vec![
                "list-party-line".into(),
                "--group".into(),
                current_group_hex.into(),
            ]),
            "mode" if words.get(1).map(String::as_str) == Some("+m") => Some(vec![
                "announce-mode".into(),
                "--group".into(),
                current_group_hex.into(),
                "--moderated".into(),
                "true".into(),
            ]),
            "mode" if words.get(1).map(String::as_str) == Some("-m") => Some(vec![
                "announce-mode".into(),
                "--group".into(),
                current_group_hex.into(),
                "--moderated".into(),
                "false".into(),
            ]),
            "mode" if words.len() == 3 && (words[1] == "+v" || words[1] == "-v") => Some(vec![
                "announce-voice".into(),
                "--group".into(),
                current_group_hex.into(),
                "--user".into(),
                words[2].clone(),
                "--voiced".into(),
                (words[1] == "+v").to_string(),
            ]),
            "say" | "msg" => Some(vec![
                "publish-party-line".into(),
                "--group".into(),
                current_group_hex.into(),
                "--body".into(),
                words[1..].join(" "),
            ]),
            "me" => Some(vec![
                "publish-party-line".into(),
                "--group".into(),
                current_group_hex.into(),
                "--body".into(),
                format!("* {}", words[1..].join(" ")),
            ]),
            "nick" => Some(if words.len() > 1 {
                vec![
                    "announce-nick".into(),
                    "--group".into(),
                    current_group_hex.into(),
                    "--name".into(),
                    words[1..].join(" "),
                ]
            } else {
                vec![
                    "announce-nick".into(),
                    "--group".into(),
                    current_group_hex.into(),
                ]
            }),
            "join" if words.len() == 2 => Some(vec![
                "request-group-join".into(),
                "--group".into(),
                words[1].clone(),
            ]),
            _ => None,
        };
        Ok(shortcut.unwrap_or(words))
    } else {
        Ok(vec![
            "publish-party-line".into(),
            "--group".into(),
            current_group_hex.into(),
            "--body".into(),
            input.into(),
            "--out-dir".into(),
            chat_out_dir(),
        ])
    }
}

#[derive(serde::Deserialize)]
struct ChatForm {
    input: String,
}

fn handle_post(group_id: GroupId) {
    let body = read_stdin_body();
    let form: ChatForm = match serde_urlencoded::from_str(&body) {
        Ok(form) => form,
        Err(error) => {
            print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\ninvalid form body: {error}");
            return;
        }
    };
    let group = crate::group::group_id_str(group_id);
    let argv = match build_argv(&form.input, &group) {
        Ok(argv) => argv,
        Err(error) => {
            redirect_with_result(group_id, false, format!("could not parse: {error}"));
            return;
        }
    };
    let args = argv.iter().map(String::as_str).collect::<Vec<_>>();
    let result = run_sf_subprocess(&args);
    redirect_with_result(group_id, result.success, result.output);
}

fn redirect_with_result(group_id: GroupId, success: bool, notice: String) {
    let query = serde_urlencoded::to_string(ChatQuery {
        group: Some(crate::group::group_id_str(group_id)),
        notice: Some(notice),
        success: Some(success),
    })
    .unwrap_or_else(|_| format!("group={}", crate::group::group_id_str(group_id)));
    print!(
        "Status: 303 See Other\r\nLocation: ?{query}\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n"
    );
}

fn read_stdin_body() -> String {
    use std::io::Read;
    let length = std::env::var("CONTENT_LENGTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let mut bytes = Vec::new();
    match length {
        Some(length) => {
            bytes.resize(length, 0);
            if std::io::stdin().read_exact(&mut bytes).is_err() {
                bytes.clear();
            }
        }
        None => {
            let _ = std::io::stdin().read_to_end(&mut bytes);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{FederationId, Hash32, PublicKeyBytes, UserId};

    fn store_with_self() -> (StateStore, GroupId) {
        let store = StateStore::open_in_memory().unwrap();
        let user = UserId {
            federation: FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        };
        let pubkey = PublicKeyBytes([1; 32]);
        store
            .set_self_identity(user, pubkey, &[4; 32], None)
            .unwrap();
        crate::group::create_self_group(&store, user, &pubkey).unwrap();
        (store, crate::group::self_group_id(&pubkey))
    }

    #[test]
    fn render_page_includes_navigation_and_timeline() {
        let (store, group) = store_with_self();
        let html = render_page(&store, group, "alice has joined", None);
        assert!(html.contains("self"));
        assert!(html.contains("/cgi-bin/status"));
        assert!(html.contains("/cgi-bin/sf-groups"));
        assert!(html.contains("/cgi-bin/sf-profiles"));
        assert!(html.contains("/cgi-bin/sf-routes"));
        assert!(html.contains("partyline"));
        assert!(html.contains("groups:"));
        assert!(html.contains("topic:"));
        assert!(html.contains("height:calc(100vh - 250px)"));
        assert!(html.contains("alice has joined"));
        assert!(html.contains("method=\"POST\""));
        assert!(html.contains("command-assist"));
        assert!(html.contains("Set or clear your local nickname."));
        assert!(html.contains("Press Tab to complete"));
    }

    #[test]
    fn render_page_escapes_group_name_and_timeline() {
        let (store, group) = store_with_self();
        let html = render_page(&store, group, "<script>alert(1)</script>", None);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn build_argv_routes_commands_and_messages() {
        assert_eq!(
            build_argv("/list-groups", "deadbeef").unwrap(),
            vec!["list-groups"]
        );
        assert_eq!(
            build_argv(
                "/publish-party-line --group abc --body \"hello world\"",
                "deadbeef"
            )
            .unwrap(),
            vec![
                "publish-party-line",
                "--group",
                "abc",
                "--body",
                "hello world"
            ]
        );
        assert_eq!(
            build_argv("/say hello world", "deadbeef").unwrap(),
            vec![
                "publish-party-line",
                "--group",
                "deadbeef",
                "--body",
                "hello world"
            ]
        );
        assert_eq!(
            build_argv("/history", "deadbeef").unwrap(),
            vec!["list-party-line", "--group", "deadbeef"]
        );
        assert_eq!(
            build_argv("/groups", "deadbeef").unwrap(),
            vec!["list-groups"]
        );
        assert_eq!(
            build_argv("/nick alice", "deadbeef").unwrap(),
            vec!["announce-nick", "--group", "deadbeef", "--name", "alice"]
        );
        assert_eq!(
            build_argv("/topic trusted routers", "deadbeef").unwrap(),
            vec![
                "announce-topic",
                "--group",
                "deadbeef",
                "--topic",
                "trusted routers"
            ]
        );
        assert_eq!(
            build_argv("/mode +m", "deadbeef").unwrap(),
            vec![
                "announce-mode",
                "--group",
                "deadbeef",
                "--moderated",
                "true"
            ]
        );
        let group = "ab".repeat(32);
        assert_eq!(
            build_argv("hello everyone", &group).unwrap(),
            vec![
                "publish-party-line".to_string(),
                "--group".to_string(),
                group,
                "--body".to_string(),
                "hello everyone".to_string(),
                "--out-dir".to_string(),
                CHAT_OUT_DIR.to_string()
            ]
        );
        assert!(build_argv("/publish-party-line --body \"unterminated", "abc").is_err());
    }
}
