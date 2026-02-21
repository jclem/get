mod input_parser;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::engine::{ArgValueCompleter, CompletionCandidate};
use clap_complete::{CompleteEnv, Shell};
use input_parser::{parse_input, ParsedHeader};
use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::{as_24_bit_terminal_escaped, LinesWithEndings};

const DEFAULT_PROFILE: &str = "default";

#[derive(Parser)]
#[command(name = "get")]
#[command(version, about = "A simple HTTP GET CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Show request and response headers.
    #[arg(short, long)]
    verbose: bool,

    /// Print detailed request and redirect debugging information.
    #[arg(long)]
    debug: bool,

    /// Do not print the response body.
    #[arg(short = 'B', long)]
    no_body: bool,

    /// Skip all session persistence.
    #[arg(short = 'S', long)]
    no_session: bool,

    /// Use a named session profile.
    #[arg(short = 'p', long, global = true)]
    profile: Option<String>,

    /// Show the request and exit without sending it.
    #[arg(long)]
    dry_run: bool,

    /// Stream the response body as it is received.
    #[arg(short, long)]
    stream: bool,

    /// Send request body as form data instead of JSON.
    #[arg(long)]
    form: bool,

    /// Maximum number of redirects to follow. Set to 0 to disable redirects.
    #[arg(long, default_value_t = 16)]
    max_redirects: usize,

    /// HTTP method to use.
    #[arg(short = 'X', long)]
    method: Option<String>,

    /// The full URL to request.
    url: Option<String>,

    /// Additional request inputs (Header:Value, name==value, path=value, path:=json).
    inputs: Vec<String>,
}

#[derive(Subcommand, Clone, Debug)]
enum Commands {
    /// Generate shell completion scripts.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Option<Shell>,
    },

    /// Manage get configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Manage session profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },

    /// Manage session persistence.
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
}

#[derive(Subcommand, Clone, Debug)]
enum ConfigCommands {
    /// Open the config file in $EDITOR.
    Edit,
}

#[derive(Subcommand, Clone, Debug)]
enum ProfileCommands {
    /// List available session profiles.
    #[command(alias = "ls")]
    List,

    /// Show all profiles and their sessions as a tree.
    Tree,

    /// Remove the selected profile.
    #[command(alias = "rm")]
    Remove {
        /// Name of the profile to remove.
        #[arg(
            add = ArgValueCompleter::new(complete_profile_name),
            value_name = "PROFILE"
        )]
        profile: String,
    },
}

#[derive(Subcommand, Clone, Debug)]
enum SessionCommands {
    /// List saved session files.
    #[command(alias = "ls")]
    List,

    /// Edit a saved session file.
    Edit {
        /// Name of the session file (without .toml).
        #[arg(
            add = ArgValueCompleter::new(complete_session_name),
            value_name = "SESSION"
        )]
        session: String,
    },

    /// Delete a saved session file.
    #[command(alias = "rm")]
    Delete {
        /// Name of the session file (without .toml).
        #[arg(
            add = ArgValueCompleter::new(complete_session_name),
            value_name = "SESSION"
        )]
        session: String,
    },

    /// Show a saved session file.
    Show {
        /// Name of the session file (without .toml).
        #[arg(
            add = ArgValueCompleter::new(complete_session_name),
            value_name = "SESSION"
        )]
        session: String,
    },

    /// Switch the active session profile.
    Switch {
        /// Profile name to switch to.
        #[arg(
            add = ArgValueCompleter::new(complete_profile_name),
            value_name = "PROFILE"
        )]
        profile: String,
    },

    /// Clear saved headers from a session file.
    Clear {
        /// Name of the session file (without .toml).
        #[arg(
            add = ArgValueCompleter::new(complete_session_name),
            value_name = "SESSION"
        )]
        session: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("get: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    if run_dynamic_completion_from_env()? {
        return Ok(());
    }

    let cli = Cli::parse();

    if let Some(command) = cli.command {
        let active_profile = active_profile(cli.profile.as_deref())?;
        return run_command(command, &active_profile);
    }

    let url = cli.url.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing URL argument (or run `get completions [shell]`)",
        )
    })?;

    let redirect_policy = if cli.debug {
        let max_redirects = cli.max_redirects;
        Policy::custom(move |attempt| {
            let hop = attempt.previous().len();
            let from = attempt
                .previous()
                .last()
                .map(|url| url.to_string())
                .unwrap_or_else(|| "<initial request>".to_string());
            let to = attempt.url();
            eprintln!(
                "\x1b[1;90m[debug]\x1b[0m \x1b[90mredirect #{hop}: {from} -> {to} ({})\x1b[0m",
                attempt.status()
            );

            if max_redirects == 0 {
                attempt.stop()
            } else {
                Policy::limited(max_redirects).redirect(attempt)
            }
        })
    } else if cli.max_redirects == 0 {
        Policy::none()
    } else {
        Policy::limited(cli.max_redirects)
    };

    let client = Client::builder().redirect(redirect_policy).build()?;
    let mut url = parse_target_url(url)?;
    let parsed_input = parse_input(&cli.inputs)?;
    let host_for_session = url
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL is missing a host"))?;
    let active_profile = active_profile(cli.profile.as_deref())?;
    let loaded_session_headers =
        load_session_headers(&host_for_session, cli.no_session, &active_profile)?;
    let session_headers = if cli.no_session {
        BTreeSet::new()
    } else {
        load_session_header_names()?
    };
    let mut tracked_session_headers = session_headers.clone();
    tracked_session_headers.extend(loaded_session_headers.keys().cloned());
    let session_updates = collect_session_headers(&parsed_input.headers, &tracked_session_headers);
    let session_updates = changed_session_headers(&session_updates, &loaded_session_headers);
    let cli_header_names = collect_header_names(&parsed_input.headers);

    if !parsed_input.query_params.is_empty() {
        let mut query_pairs = url.query_pairs_mut();
        for query in &parsed_input.query_params {
            query_pairs.append_pair(&query.name, &query.value);
        }
    }

    let host = host_header_value(&url)?;

    let method_name = cli.method.as_deref().unwrap_or_else(|| {
        if parsed_input.body.is_some() {
            "POST"
        } else {
            "GET"
        }
    });
    let method = reqwest::Method::from_bytes(method_name.as_bytes())?;
    let mut request_builder = client
        .request(method, url.clone())
        .header(ACCEPT, "*/*")
        .header(USER_AGENT, format!("get/{}", env!("CARGO_PKG_VERSION")));

    for (name, value) in &loaded_session_headers {
        if cli_header_names.contains(name) {
            continue;
        }
        let (name, value) = parse_header(name, value)?;
        request_builder = request_builder.header(name, value);
    }

    for header in &parsed_input.headers {
        let (name, value) = parse_header(&header.name, &header.value)?;
        request_builder = request_builder.header(name, value);
    }

    if let Some(body) = parsed_input.body.as_ref() {
        if cli.form {
            request_builder = request_builder.form(&body_to_form_fields(body));
        } else {
            request_builder = request_builder.json(body);
        }
    }

    let request = request_builder.build()?;

    let mut stderr = io::stderr();
    let show_headers = cli.verbose || cli.debug || cli.dry_run;

    if show_headers {
        let path_and_query = request
            .url()
            .query()
            .map(|query| format!("{}?{query}", request.url().path()))
            .unwrap_or_else(|| request.url().path().to_string());

        writeln!(
            stderr,
            "> {} {path_and_query} {}",
            request.method(),
            http_version(request.version())
        )?;
        for (name, value) in request.headers() {
            writeln!(
                stderr,
                "> {}: {}",
                name,
                value.to_str().unwrap_or("<binary>")
            )?;
        }
        writeln!(stderr, "> host: {host}")?;
        writeln!(stderr, ">")?;

        if let Some(body) = request.body() {
            if let Some(bytes) = body.as_bytes() {
                write_prefixed_request_body(&mut stderr, bytes)?;
            } else {
                writeln!(stderr, "> <binary request body>")?;
            }
        }
    }

    let highlight_body = should_highlight_body();
    let mut stdout = io::stdout().lock();

    if cli.dry_run {
        return Ok(());
    }

    let mut response = client.execute(request)?;
    persist_session_headers(
        &host_for_session,
        &session_updates,
        cli.no_session,
        &active_profile,
    )?;
    if show_headers {
        writeln!(
            stderr,
            "< {} {}",
            http_version(response.version()),
            response.status()
        )?;
        for (name, value) in response.headers() {
            writeln!(
                stderr,
                "< {}: {}",
                name,
                value.to_str().unwrap_or("<binary>")
            )?;
        }
        writeln!(stderr, "<")?;
    }

    let response_content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if !cli.no_body {
        if cli.stream {
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let bytes = response.read(&mut buffer)?;
                if bytes == 0 {
                    break;
                }
                stdout.write_all(&buffer[..bytes])?;
                stdout.flush()?;
            }
        } else if highlight_body
            && response_content_type
                .as_deref()
                .and_then(syntax_token_for_content_type)
                .is_some()
        {
            let mut body = Vec::new();
            response.read_to_end(&mut body)?;
            if let Some(highlighted) = highlight_body_text(&body, response_content_type.as_deref())
            {
                stdout.write_all(highlighted.as_bytes())?;
            } else {
                stdout.write_all(&body)?;
            }
        } else {
            io::copy(&mut response, &mut stdout)?;
        }
        stdout.flush()?;
    }

    Ok(())
}

fn run_command(command: Commands, profile: &str) -> Result<(), Box<dyn Error>> {
    match command {
        Commands::Completions { shell } => {
            let shell = match shell.or_else(detect_shell_from_env) {
                Some(shell) => shell,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "could not detect shell from $SHELL; pass one explicitly (bash, elvish, fish, powershell, zsh)",
                    )
                    .into())
                }
            };

            write_dynamic_completion_registration(shell)?;
            Ok(())
        }
        Commands::Config { command } => run_config_command(command),
        Commands::Profile { command } => run_profile_command(command),
        Commands::Session { command } => run_session_command(profile, command),
    }
}

fn run_config_command(command: ConfigCommands) -> Result<(), Box<dyn Error>> {
    match command {
        ConfigCommands::Edit => edit_config(),
    }
}

fn run_profile_command(command: ProfileCommands) -> Result<(), Box<dyn Error>> {
    match command {
        ProfileCommands::List => list_profiles(),
        ProfileCommands::Tree => print_profile_tree(),
        ProfileCommands::Remove { profile } => remove_profile(&profile),
    }
}

fn list_profiles() -> Result<(), Box<dyn Error>> {
    for name in list_profile_names()? {
        println!("{name}");
    }
    Ok(())
}

fn print_profile_tree() -> Result<(), Box<dyn Error>> {
    let profiles = list_profile_names()?;
    for (profile_i, profile) in profiles.iter().enumerate() {
        let is_last_profile = profile_i + 1 == profiles.len();
        let profile_indent = if is_last_profile {
            "└─ "
        } else {
            "├─ "
        };
        println!("{profile_indent}{profile}");

        let sessions = list_session_names(profile)?;
        for (session_i, session) in sessions.iter().enumerate() {
            let connector = if session_i + 1 == sessions.len() {
                "└─ "
            } else {
                "├─ "
            };
            let child_indent = if is_last_profile { "   " } else { "│  " };
            println!("{child_indent}{connector}{session}");
        }
    }
    Ok(())
}

fn list_profile_names() -> Result<Vec<String>, Box<dyn Error>> {
    let base = profiles_root().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine profile directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    read_profile_names_in_dir(&base)
}

fn read_profile_names_in_dir(profile_dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let entries = match fs::read_dir(profile_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        names.push(name);
    }

    names.sort_unstable();
    Ok(names)
}

fn remove_profile(profile: &str) -> Result<(), Box<dyn Error>> {
    let base = profile_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine profile directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    if !base.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "profile does not exist").into());
    }
    fs::remove_dir_all(base)?;
    Ok(())
}

fn switch_profile(profile: &str) -> Result<(), Box<dyn Error>> {
    let profile = normalize_profile_name(profile)?;
    write_active_profile(&profile)?;
    let base = profile_state_dir(&profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine profile directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    fs::create_dir_all(base)?;
    Ok(())
}

fn clear_session(session: String, profile: &str) -> Result<(), Box<dyn Error>> {
    let name = normalize_session_name(&session)?;
    let base = session_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine session directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    let path = base.join(format!("{name}.toml"));
    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "session does not exist").into());
    }

    let mut value = match fs::read_to_string(&path) {
        Ok(content) => toml::from_str::<toml::Value>(&content)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "session does not exist").into())
        }
        Err(error) => return Err(error.into()),
    };

    let table = value
        .as_table_mut()
        .ok_or_else(|| io::Error::other("session file is not a TOML table"))?;
    table.insert(
        "headers".to_string(),
        toml::Value::Table(toml::map::Map::new()),
    );

    fs::write(path, toml::to_string_pretty(&value)?)?;
    Ok(())
}

fn run_session_command(profile: &str, command: SessionCommands) -> Result<(), Box<dyn Error>> {
    match command {
        SessionCommands::List => list_sessions(profile),
        SessionCommands::Edit { session } => edit_session(session, profile),
        SessionCommands::Delete { session } => delete_session(session, profile),
        SessionCommands::Show { session } => show_session(session, profile),
        SessionCommands::Switch { profile: target } => switch_profile(&target),
        SessionCommands::Clear { session } => clear_session(session, profile),
    }
}

fn edit_session(session: String, profile: &str) -> Result<(), Box<dyn Error>> {
    let name = normalize_session_name(&session)?;
    let base = session_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine session directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    edit_file(base.join(format!("{name}.toml")))
}

fn delete_session(session: String, profile: &str) -> Result<(), Box<dyn Error>> {
    let name = normalize_session_name(&session)?;
    let base = session_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine session directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    let path = base.join(format!("{name}.toml"));
    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "session does not exist").into());
    }
    fs::remove_file(path)?;
    Ok(())
}

fn show_session(session: String, profile: &str) -> Result<(), Box<dyn Error>> {
    let name = normalize_session_name(&session)?;
    let base = session_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine session directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    let path = base.join(format!("{name}.toml"));
    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "session does not exist").into());
    }

    let contents = fs::read_to_string(&path)?;
    let mut stdout = io::stdout();

    if should_highlight_body() {
        if let Some(highlighted) = highlight_file_text(path.as_path(), contents.as_bytes()) {
            stdout.write_all(highlighted.as_bytes())?;
        } else {
            stdout.write_all(contents.as_bytes())?;
        }
    } else {
        stdout.write_all(contents.as_bytes())?;
    }
    stdout.flush()?;

    Ok(())
}

fn list_sessions(profile: &str) -> Result<(), Box<dyn Error>> {
    for name in list_session_names(profile)? {
        println!("{name}");
    }
    Ok(())
}

fn list_session_names(profile: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let base = session_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine session directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    read_session_names_in_dir(&base)
}

fn read_session_names_in_dir(session_dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let entries = match fs::read_dir(session_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }

        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        names.push(name.to_string());
    }

    names.sort_unstable();
    Ok(names)
}

fn session_candidates(profile: &str) -> Vec<String> {
    let base = match session_state_dir(profile) {
        Some(base) => base,
        None => return Vec::new(),
    };

    read_session_names_in_dir(&base).unwrap_or_default()
}

fn complete_session_name(current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    let mut candidates = Vec::new();
    let profile = default_profile().unwrap_or_else(|_| DEFAULT_PROFILE.to_string());

    for name in session_candidates(&profile) {
        if name.starts_with(current.as_ref()) {
            candidates.push(CompletionCandidate::new(name));
        }
    }

    candidates
}

fn normalize_session_name(raw: &str) -> Result<&str, Box<dyn Error>> {
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "session name is empty").into());
    }

    if normalized.contains('/') || normalized.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session name cannot contain path separators",
        )
        .into());
    }

    let normalized = normalized.strip_suffix(".toml").unwrap_or(normalized);
    if normalized.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "session name is empty").into());
    }

    Ok(normalized)
}

fn normalize_profile_name(raw: &str) -> Result<&str, Box<dyn Error>> {
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "profile name is empty").into());
    }

    if normalized.contains('/') || normalized.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "profile name cannot contain path separators",
        )
        .into());
    }

    Ok(normalized)
}

fn profile_candidates() -> Vec<String> {
    let base = match profiles_root() {
        Some(base) => base,
        None => return Vec::new(),
    };

    read_profile_names_in_dir(&base).unwrap_or_default()
}

fn complete_profile_name(current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    let mut candidates = Vec::new();

    for name in profile_candidates() {
        if name.starts_with(current.as_ref()) {
            candidates.push(CompletionCandidate::new(name));
        }
    }

    candidates
}

fn edit_file(path: PathBuf) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        fs::File::create(&path)?;
    }

    let editor = std::env::var("EDITOR")
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "$EDITOR is not set"))?;
    let mut parts = editor.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "$EDITOR is empty"))?;

    let mut command = std::process::Command::new(program);
    command.args(parts).arg(path);
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("editor exited with status {status}")).into());
    }

    Ok(())
}

fn edit_config() -> Result<(), Box<dyn Error>> {
    let path = config_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine config path (XDG_CONFIG_HOME or HOME required)",
        )
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        fs::File::create(&path)?;
    }

    edit_file(path)
}

fn run_dynamic_completion_from_env() -> Result<bool, Box<dyn Error>> {
    let current_dir = std::env::current_dir().ok();
    let completed = CompleteEnv::with_factory(|| Cli::command())
        .bin("get")
        .completer("get")
        .try_complete(std::env::args_os(), current_dir.as_deref())?;
    Ok(completed)
}

fn detect_shell_from_env() -> Option<Shell> {
    let path = std::env::var("SHELL").ok()?;
    let shell = std::path::Path::new(&path).file_name()?.to_str()?;

    match shell {
        "bash" => Some(Shell::Bash),
        "elvish" => Some(Shell::Elvish),
        "fish" => Some(Shell::Fish),
        "pwsh" | "powershell" => Some(Shell::PowerShell),
        "zsh" => Some(Shell::Zsh),
        _ => None,
    }
}

fn write_dynamic_completion_registration(shell: Shell) -> Result<(), Box<dyn Error>> {
    let current_dir = std::env::current_dir().ok();
    std::env::set_var("COMPLETE", shell_name(shell)?);
    let completed = CompleteEnv::with_factory(|| Cli::command())
        .bin("get")
        .completer("get")
        .try_complete([std::ffi::OsString::from("get")], current_dir.as_deref())?;
    if !completed {
        return Err(io::Error::other("failed to generate completion registration").into());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(rename = "session-headers", default)]
    session_headers: Vec<String>,
}

fn load_session_header_names() -> Result<BTreeSet<String>, Box<dyn Error>> {
    load_session_header_names_from_path(config_path())
}

fn load_session_header_names_from_path(
    path: Option<PathBuf>,
) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let path = match path {
        Some(path) => path,
        None => return Ok(BTreeSet::new()),
    };

    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error.into()),
    };

    let config: Config = toml::from_str(&content)?;
    Ok(config
        .session_headers
        .into_iter()
        .map(|name| name.to_ascii_lowercase())
        .collect())
}

fn collect_session_headers(
    headers: &[ParsedHeader],
    configured: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if configured.contains(&name) {
            result.insert(name, header.value.clone());
        }
    }
    result
}

fn collect_header_names(headers: &[ParsedHeader]) -> BTreeSet<String> {
    headers
        .iter()
        .map(|header| header.name.to_ascii_lowercase())
        .collect()
}

fn changed_session_headers(
    updates: &BTreeMap<String, String>,
    existing: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut changed = BTreeMap::new();
    for (name, value) in updates {
        if existing.get(name) != Some(value) {
            changed.insert(name.clone(), value.clone());
        }
    }
    changed
}

fn load_session_headers(
    host: &str,
    no_session: bool,
    profile: &str,
) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    if no_session {
        return Ok(BTreeMap::new());
    }

    let path = session_path(host, profile)?;
    load_session_headers_from_path(&path)
}

fn load_session_headers_from_path(path: &Path) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error.into()),
    };

    let value = toml::from_str::<toml::Value>(&content)?;
    let table = value
        .as_table()
        .ok_or_else(|| io::Error::other("session file is not a TOML table"))?;

    let Some(headers) = table.get("headers") else {
        return Ok(BTreeMap::new());
    };
    let headers = headers.as_table().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "`headers` is not a TOML table")
    })?;

    let mut loaded = BTreeMap::new();
    for (name, value) in headers {
        let value = value.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("`headers.{name}` is not a string"),
            )
        })?;
        loaded.insert(name.to_ascii_lowercase(), value.to_string());
    }

    Ok(loaded)
}

fn persist_session_headers(
    host: &str,
    updates: &BTreeMap<String, String>,
    no_session: bool,
    profile: &str,
) -> Result<(), Box<dyn Error>> {
    if no_session || updates.is_empty() {
        return Ok(());
    }

    let path = session_path(host, profile)?;
    persist_session_headers_to_path(&path, updates)
}

fn persist_session_headers_to_path(
    path: &Path,
    updates: &BTreeMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    if updates.is_empty() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut value = match fs::read_to_string(path) {
        Ok(content) => toml::from_str::<toml::Value>(&content)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            toml::Value::Table(toml::map::Map::new())
        }
        Err(error) => return Err(error.into()),
    };

    let table = value
        .as_table_mut()
        .ok_or_else(|| io::Error::other("session file is not a TOML table"))?;
    let headers = table
        .entry("headers".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));

    let headers = headers.as_table_mut().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "`headers` is not a TOML table")
    })?;

    for (name, value) in updates {
        headers.insert(name.clone(), toml::Value::String(value.clone()));
    }

    fs::write(path, toml::to_string_pretty(&value)?)?;
    Ok(())
}

fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("get").join("config.toml"))
}

fn state_root() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state"))
        })?;
    Some(base.join("get"))
}

fn state_file_path() -> Option<PathBuf> {
    Some(state_root()?.join("state.toml"))
}

fn profiles_root() -> Option<PathBuf> {
    Some(state_root()?.join("profiles"))
}

fn profile_state_dir(profile: &str) -> Option<PathBuf> {
    Some(profiles_root()?.join(profile))
}

fn session_state_dir(profile: &str) -> Option<PathBuf> {
    Some(profile_state_dir(profile)?.join("sessions"))
}

fn default_profile() -> Result<String, Box<dyn Error>> {
    let path = state_file_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine state directory (XDG_STATE_HOME or HOME required)",
        )
    })?;

    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DEFAULT_PROFILE.to_string())
        }
        Err(error) => return Err(error.into()),
    };

    let value = toml::from_str::<toml::Value>(&contents)?;
    let profile = value
        .get("default-profile")
        .and_then(toml::Value::as_str)
        .unwrap_or(DEFAULT_PROFILE);

    Ok(normalize_profile_name(profile)?.to_string())
}

fn write_active_profile(profile: &str) -> Result<(), Box<dyn Error>> {
    let profile = normalize_profile_name(profile)?;
    let path = state_file_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine state directory (XDG_STATE_HOME or HOME required)",
        )
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut value = toml::map::Map::new();
    value.insert(
        "default-profile".to_string(),
        toml::Value::String(profile.to_string()),
    );
    fs::write(path, toml::to_string_pretty(&toml::Value::Table(value))?)?;
    Ok(())
}

fn active_profile(cli_profile: Option<&str>) -> Result<String, Box<dyn Error>> {
    match cli_profile {
        Some(profile) => Ok(normalize_profile_name(profile)?.to_string()),
        None => default_profile(),
    }
}

fn session_path(host: &str, profile: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = session_state_dir(profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine session directory (XDG_STATE_HOME or HOME required)",
        )
    })?;
    let host = sanitize_host_path_component(host);
    Ok(base.join(format!("{host}.toml")))
}

fn sanitize_host_path_component(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn shell_name(shell: Shell) -> Result<&'static str, io::Error> {
    match shell {
        Shell::Bash => Ok("bash"),
        Shell::Elvish => Ok("elvish"),
        Shell::Fish => Ok("fish"),
        Shell::PowerShell => Ok("powershell"),
        Shell::Zsh => Ok("zsh"),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported shell for dynamic completions",
        )),
    }
}

fn parse_target_url(raw: &str) -> Result<Url, Box<dyn Error>> {
    if raw.contains("://") {
        return Url::parse(raw).map_err(|error| error.into());
    }

    let host = host_for_default_scheme(raw)?;
    let scheme = if is_local_host(host.as_deref()) {
        "http"
    } else {
        "https"
    };

    Url::parse(&format!("{scheme}://{raw}")).map_err(|error| error.into())
}

fn parse_header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), Box<dyn Error>> {
    if name.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "header name is empty").into());
    }

    let name = HeaderName::from_bytes(name.as_bytes())?;
    let value = HeaderValue::from_str(value)?;
    Ok((name, value))
}

fn body_to_form_fields(body: &Value) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    append_form_fields(None, body, &mut fields);
    fields
}

fn append_form_fields(prefix: Option<&str>, value: &Value, fields: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let next_key = match prefix {
                    Some(prefix) => format!("{prefix}[{key}]"),
                    None => key.clone(),
                };
                append_form_fields(Some(&next_key), value, fields);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let next_key = match prefix {
                    Some(prefix) => format!("{prefix}[{index}]"),
                    None => index.to_string(),
                };
                append_form_fields(Some(&next_key), value, fields);
            }
        }
        Value::Null => {
            if let Some(prefix) = prefix {
                fields.push((prefix.to_string(), "null".to_string()));
            }
        }
        Value::Bool(boolean) => {
            if let Some(prefix) = prefix {
                fields.push((prefix.to_string(), boolean.to_string()));
            }
        }
        Value::Number(number) => {
            if let Some(prefix) = prefix {
                fields.push((prefix.to_string(), number.to_string()));
            }
        }
        Value::String(string) => {
            if let Some(prefix) = prefix {
                fields.push((prefix.to_string(), string.clone()));
            }
        }
    }
}

fn should_highlight_body() -> bool {
    if !io::stdout().is_terminal() {
        return false;
    }

    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    !matches!(
        std::env::var("TERM"),
        Ok(term) if term.eq_ignore_ascii_case("dumb")
    )
}

fn highlight_body_text(body: &[u8], content_type: Option<&str>) -> Option<String> {
    let syntax_token = syntax_token_for_content_type(content_type?)?;
    let source = std::str::from_utf8(body).ok()?;
    let syntax_set = syntax_set();
    let syntax = syntax_set
        .find_syntax_by_token(syntax_token)
        .or_else(|| syntax_set.find_syntax_by_extension(syntax_token))?;
    let mut highlighter = HighlightLines::new(syntax, theme());
    let mut output = String::new();

    for line in LinesWithEndings::from(source) {
        let ranges = highlighter.highlight_line(line, syntax_set).ok()?;
        output.push_str(&as_24_bit_terminal_escaped(&ranges, false));
    }

    Some(output)
}

fn highlight_file_text(path: &Path, body: &[u8]) -> Option<String> {
    let source = std::str::from_utf8(body).ok()?;
    let syntax_set = syntax_set();
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let syntax = syntax_set
        .find_syntax_for_file(path)
        .ok()
        .flatten()
        .or_else(|| syntax_set.find_syntax_by_name("TOML"))
        .or_else(|| syntax_set.find_syntax_by_extension("toml"))
        .or_else(|| {
            if extension.eq_ignore_ascii_case("toml") {
                syntax_set.find_syntax_by_name("JSON")
            } else {
                None
            }
        })?;
    let mut highlighter = HighlightLines::new(syntax, theme());
    let mut output = String::new();

    for line in LinesWithEndings::from(source) {
        let ranges = highlighter.highlight_line(line, syntax_set).ok()?;
        output.push_str(&as_24_bit_terminal_escaped(&ranges, false));
    }

    Some(output)
}

fn syntax_token_for_content_type(content_type: &str) -> Option<&'static str> {
    let media_type = content_type.split(';').next()?.trim().to_ascii_lowercase();
    let (type_name, subtype) = media_type.split_once('/')?;

    if let Some((_, suffix)) = subtype.rsplit_once('+') {
        match suffix {
            "json" => return Some("json"),
            "xml" => return Some("xml"),
            _ => {}
        }
    }

    match (type_name, subtype) {
        ("text", "html") => Some("html"),
        ("text", "css") => Some("css"),
        ("text", "markdown") => Some("markdown"),
        ("text", "javascript") => Some("javascript"),
        ("text", "ecmascript") => Some("javascript"),
        ("text", "xml") => Some("xml"),
        ("text", "json") => Some("json"),
        ("application", "json") => Some("json"),
        ("application", "javascript") => Some("javascript"),
        ("application", "x-javascript") => Some("javascript"),
        ("application", "xml") => Some("xml"),
        ("application", "yaml") => Some("yaml"),
        ("application", "x-yaml") => Some("yaml"),
        ("application", "toml") => Some("toml"),
        ("application", "typescript") => Some("typescript"),
        ("text", "typescript") => Some("typescript"),
        _ => None,
    }
}

fn syntax_set() -> &'static SyntaxSet {
    static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
    SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines)
}

fn theme() -> &'static Theme {
    static THEME: OnceLock<Theme> = OnceLock::new();
    THEME.get_or_init(|| {
        let themes = ThemeSet::load_defaults();
        themes
            .themes
            .get("base16-ocean.dark")
            .cloned()
            .or_else(|| themes.themes.values().next().cloned())
            .expect("syntect returned no built-in themes")
    })
}

fn host_for_default_scheme(raw: &str) -> Result<Option<String>, Box<dyn Error>> {
    let with_scheme = format!("https://{raw}");
    let parsed = Url::parse(&with_scheme)?;
    Ok(parsed.host_str().map(|host| host.to_string()))
}

fn is_local_host(host: Option<&str>) -> bool {
    let host = match host {
        Some(host) => host,
        None => return false,
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(ip) => match ip {
            IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local(),
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unique_local() || ipv6.is_unicast_link_local()
            }
        },
        Err(_) => false,
    }
}

fn host_header_value(url: &Url) -> Result<String, Box<dyn Error>> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL is missing a host"))?;
    let value = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    Ok(value)
}

fn http_version(version: reqwest::Version) -> &'static str {
    match version {
        reqwest::Version::HTTP_09 => "HTTP/0.9",
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2.0",
        reqwest::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

fn write_prefixed_request_body(stderr: &mut io::Stderr, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }

    if let Ok(body) = std::str::from_utf8(bytes) {
        for line in body.lines() {
            writeln!(stderr, "> {line}")?;
        }
        if body.ends_with('\n') {
            writeln!(stderr, ">")?;
        }
    } else {
        writeln!(stderr, "> <binary request body>")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        body_to_form_fields, changed_session_headers, collect_header_names,
        collect_session_headers, complete_session_name, load_session_header_names_from_path,
        load_session_headers_from_path, persist_session_headers, persist_session_headers_to_path,
        read_profile_names_in_dir, read_session_names_in_dir, sanitize_host_path_component,
        syntax_token_for_content_type, Cli, Commands, ConfigCommands, ParsedHeader,
        ProfileCommands, SessionCommands, DEFAULT_PROFILE,
    };
    use clap::{CommandFactory, Parser};
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        env, fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use toml;

    #[test]
    fn syntax_token_matches_common_content_types() {
        assert_eq!(
            syntax_token_for_content_type("application/json"),
            Some("json")
        );
        assert_eq!(
            syntax_token_for_content_type("application/problem+json"),
            Some("json")
        );
        assert_eq!(
            syntax_token_for_content_type("text/html; charset=utf-8"),
            Some("html")
        );
        assert_eq!(
            syntax_token_for_content_type("application/javascript"),
            Some("javascript")
        );
        assert_eq!(
            syntax_token_for_content_type("application/xml"),
            Some("xml")
        );
    }

    #[test]
    fn syntax_token_skips_plain_and_binary_content_types() {
        assert_eq!(syntax_token_for_content_type("text/plain"), None);
        assert_eq!(
            syntax_token_for_content_type("application/octet-stream"),
            None
        );
    }

    #[test]
    fn body_to_form_fields_flattens_nested_json() {
        let body = json!({
            "title": "hello world",
            "meta": {"enabled": true, "count": 2}
        });
        let fields = body_to_form_fields(&body);

        assert_eq!(
            fields,
            vec![
                ("meta[count]".to_string(), "2".to_string()),
                ("meta[enabled]".to_string(), "true".to_string()),
                ("title".to_string(), "hello world".to_string()),
            ]
        );
    }

    #[test]
    fn body_to_form_fields_flattens_arrays() {
        let body = json!({
            "tags": ["rust", "cli"]
        });
        let fields = body_to_form_fields(&body);

        assert_eq!(
            fields,
            vec![
                ("tags[0]".to_string(), "rust".to_string()),
                ("tags[1]".to_string(), "cli".to_string()),
            ]
        );
    }

    #[test]
    fn help_includes_no_session_flag() {
        let mut buffer = Vec::new();
        Cli::command().write_long_help(&mut buffer).unwrap();
        let help = String::from_utf8(buffer).unwrap();

        assert!(help.contains("-S"));
        assert!(help.contains("--no-session"));
        assert!(help.contains("-p"));
        assert!(help.contains("--profile"));
    }

    #[test]
    fn parses_profile_long_flag() {
        let cli = Cli::try_parse_from(["get", "--profile", "work", "session", "list"])
            .expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
    }

    #[test]
    fn parses_profile_short_flag() {
        let cli = Cli::try_parse_from(["get", "-p", "work", "session", "list"]).expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
    }

    #[test]
    fn parses_profile_long_flag_after_subcommand() {
        let cli = Cli::try_parse_from(["get", "session", "list", "--profile", "work"])
            .expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_short_flag_after_subcommand() {
        let cli = Cli::try_parse_from(["get", "session", "list", "-p", "work"]).expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn session_help_includes_profile_flag() {
        let error = Cli::command()
            .try_get_matches_from(["get", "session", "--help"])
            .expect_err("expected clap help");
        let help = error.to_string();

        assert!(help.contains("-p"));
        assert!(help.contains("--profile"));
    }

    #[test]
    fn config_help_includes_profile_flag() {
        let error = Cli::command()
            .try_get_matches_from(["get", "config", "--help"])
            .expect_err("expected clap help");
        let help = error.to_string();

        assert!(help.contains("-p"));
        assert!(help.contains("--profile"));
    }

    #[test]
    fn profile_help_includes_profile_flag() {
        let error = Cli::command()
            .try_get_matches_from(["get", "profile", "--help"])
            .expect_err("expected clap help");
        let help = error.to_string();

        assert!(help.contains("-p"));
        assert!(help.contains("--profile"));
    }

    #[test]
    fn parses_profile_long_flag_after_config_subcommand() {
        let cli =
            Cli::try_parse_from(["get", "config", "edit", "--profile", "work"]).expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
        match cli.command {
            Some(Commands::Config {
                command: ConfigCommands::Edit,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_long_flag_after_profile_subcommand() {
        let cli = Cli::try_parse_from(["get", "profile", "list", "--profile", "work"])
            .expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
        match cli.command {
            Some(Commands::Profile {
                command: ProfileCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_long_flag_after_url() {
        let cli = Cli::try_parse_from(["get", "https://example.com", "--profile", "work"])
            .expect("parse cli");
        assert_eq!(cli.profile.as_deref(), Some("work"));
        assert_eq!(cli.url.as_deref(), Some("https://example.com"));
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_config_edit_subcommand() {
        let cli = Cli::try_parse_from(["get", "config", "edit"]).expect("parse cli");
        match cli.command {
            Some(Commands::Config {
                command: ConfigCommands::Edit,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_list_subcommand() {
        let cli = Cli::try_parse_from(["get", "profile", "list"]).expect("parse cli");
        match cli.command {
            Some(Commands::Profile {
                command: ProfileCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_ls_alias() {
        let cli = Cli::try_parse_from(["get", "profile", "ls"]).expect("parse cli");
        match cli.command {
            Some(Commands::Profile {
                command: ProfileCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_remove_subcommand() {
        let cli = Cli::try_parse_from(["get", "profile", "remove", "work"]).expect("parse cli");
        match cli.command {
            Some(Commands::Profile {
                command: ProfileCommands::Remove { profile },
            }) => assert_eq!(profile, "work"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_rm_alias() {
        let cli = Cli::try_parse_from(["get", "profile", "rm", "work"]).expect("parse cli");
        match cli.command {
            Some(Commands::Profile {
                command: ProfileCommands::Remove { profile },
            }) => assert_eq!(profile, "work"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_profile_tree_subcommand() {
        let cli = Cli::try_parse_from(["get", "profile", "tree"]).expect("parse cli");
        match cli.command {
            Some(Commands::Profile {
                command: ProfileCommands::Tree,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_list_subcommand() {
        let cli = Cli::try_parse_from(["get", "session", "list"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_ls_alias() {
        let cli = Cli::try_parse_from(["get", "session", "ls"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::List,
            }) => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_edit_subcommand() {
        let cli =
            Cli::try_parse_from(["get", "session", "edit", "api.github.com"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::Edit { session },
            }) => assert_eq!(session, "api.github.com"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_delete_subcommand() {
        let cli =
            Cli::try_parse_from(["get", "session", "delete", "api.github.com"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::Delete { session },
            }) => assert_eq!(session, "api.github.com"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_rm_alias() {
        let cli =
            Cli::try_parse_from(["get", "session", "rm", "api.github.com"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::Delete { session },
            }) => assert_eq!(session, "api.github.com"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_show_subcommand() {
        let cli =
            Cli::try_parse_from(["get", "session", "show", "api.github.com"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::Show { session },
            }) => assert_eq!(session, "api.github.com"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_switch_subcommand() {
        let cli = Cli::try_parse_from(["get", "session", "switch", "work"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::Switch { profile },
            }) => assert_eq!(profile, "work"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_session_clear_subcommand() {
        let cli =
            Cli::try_parse_from(["get", "session", "clear", "api.github.com"]).expect("parse cli");
        match cli.command {
            Some(Commands::Session {
                command: SessionCommands::Clear { session },
            }) => assert_eq!(session, "api.github.com"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn session_edit_completes_existing_sessions() {
        let suggestions = complete_session_name(std::ffi::OsStr::new("foo"));
        for suggestion in suggestions {
            assert!(suggestion.get_value().to_string_lossy().starts_with("foo"));
        }
    }

    #[test]
    fn collects_session_headers_case_insensitively() {
        let headers = vec![
            ParsedHeader {
                name: "Authorization".to_string(),
                value: "Bearer abc".to_string(),
            },
            ParsedHeader {
                name: "x-other".to_string(),
                value: "ignore".to_string(),
            },
        ];

        let configured = BTreeSet::from_iter(vec!["authorization".to_string()]);
        let updates = collect_session_headers(&headers, &configured);

        assert_eq!(
            updates.get("authorization"),
            Some(&"Bearer abc".to_string())
        );
        assert_eq!(updates.len(), 1);
    }

    #[test]
    fn collects_header_names_case_insensitively() {
        let headers = vec![
            ParsedHeader {
                name: "Authorization".to_string(),
                value: "Bearer abc".to_string(),
            },
            ParsedHeader {
                name: "authorization".to_string(),
                value: "Bearer def".to_string(),
            },
        ];

        let names = collect_header_names(&headers);
        assert_eq!(
            names,
            BTreeSet::from_iter(vec!["authorization".to_string()])
        );
    }

    #[test]
    fn keeps_only_changed_session_headers() {
        let mut updates = BTreeMap::new();
        updates.insert("authorization".to_string(), "new".to_string());
        updates.insert("x-api-key".to_string(), "key".to_string());

        let mut existing = BTreeMap::new();
        existing.insert("authorization".to_string(), "old".to_string());
        existing.insert("x-api-key".to_string(), "key".to_string());

        let changed = changed_session_headers(&updates, &existing);
        assert_eq!(
            changed,
            BTreeMap::from_iter(vec![("authorization".to_string(), "new".to_string())])
        );
    }

    #[test]
    fn config_parses_session_headers_case_insensitively() {
        let path = temp_path("config-parse");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"session-headers = ["Authorization", "x-api-key"]"#).unwrap();

        let names = load_session_header_names_from_path(Some(path)).unwrap();
        assert!(names.contains("authorization"));
        assert!(names.contains("x-api-key"));
    }

    #[test]
    fn missing_session_config_returns_empty_set() {
        let names = load_session_header_names_from_path(None).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn persist_session_headers_sanitizes_host_and_merges_headers_table() {
        let path = temp_path("session-merge");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "other = \"keep\"\n[headers]\nauthorization = \"old\"\n",
        )
        .unwrap();

        let mut updates = BTreeMap::new();
        updates.insert("authorization".to_string(), "new".to_string());
        updates.insert("x-api-key".to_string(), "key".to_string());

        persist_session_headers_to_path(&path, &updates).unwrap();

        let stored = fs::read_to_string(&path).unwrap();
        let value = toml::from_str::<toml::Value>(&stored).unwrap();
        let headers = value.get("headers").unwrap().as_table().unwrap();
        assert_eq!(
            headers.get("authorization").unwrap().as_str().unwrap(),
            "new"
        );
        assert_eq!(headers.get("x-api-key").unwrap().as_str().unwrap(), "key");
        assert_eq!(value.get("other").unwrap().as_str().unwrap(), "keep");
    }

    #[test]
    fn load_session_headers_reads_and_normalizes_keys() {
        let path = temp_path("session-read");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "[headers]\nAuthorization = \"Bearer abc\"\nX-Api-Key = \"k\"\n",
        )
        .unwrap();

        let loaded = load_session_headers_from_path(&path).unwrap();
        assert_eq!(
            loaded,
            BTreeMap::from_iter(vec![
                ("authorization".to_string(), "Bearer abc".to_string()),
                ("x-api-key".to_string(), "k".to_string()),
            ])
        );
    }

    #[test]
    fn host_with_port_is_stored_safely() {
        assert_eq!(
            sanitize_host_path_component("api.github.com:443"),
            "api.github.com_443"
        );
    }

    #[test]
    fn session_list_ignores_non_toml_entries_and_sorts() {
        let stem = "session-list-sort-test";
        let base = temp_path(stem);
        fs::create_dir_all(&base).unwrap();

        fs::write(base.join("zeta.toml"), "").unwrap();
        fs::write(base.join("alpha.toml"), "").unwrap();
        fs::write(base.join("readme.txt"), "").unwrap();
        fs::create_dir(base.join("nested")).unwrap();

        let names = read_session_names_in_dir(&base).unwrap();
        assert_eq!(names, vec!["alpha".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn profile_list_ignores_non_directories_and_sorts() {
        let stem = "profile-list-sort-test";
        let base = temp_path(stem);
        fs::create_dir_all(&base).unwrap();

        fs::create_dir_all(base.join("zeta")).unwrap();
        fs::create_dir_all(base.join("alpha")).unwrap();
        fs::write(base.join("readme.txt"), "").unwrap();
        fs::write(base.join("nested.txt"), "").unwrap();

        let names = read_profile_names_in_dir(&base).unwrap();
        assert_eq!(names, vec!["alpha".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn no_session_skips_persisting_headers() {
        persist_session_headers(
            "api.github.com",
            &{
                let mut updates = BTreeMap::new();
                updates.insert("authorization".to_string(), "skip".to_string());
                updates
            },
            true,
            DEFAULT_PROFILE,
        )
        .unwrap();
    }

    fn temp_path(stem: &str) -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("get-session-test-{stem}-{id}"))
    }
}
