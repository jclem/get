use clap::Parser;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Url;
use std::error::Error;
use std::io::{self, IsTerminal, Read, Write};
use std::net::IpAddr;
use std::sync::OnceLock;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::{as_24_bit_terminal_escaped, LinesWithEndings};

#[derive(Parser)]
#[command(name = "get")]
#[command(version, about = "A simple HTTP GET CLI")]
struct Cli {
    /// Show request and response headers.
    #[arg(short, long)]
    verbose: bool,

    /// Print detailed request and redirect debugging information.
    #[arg(short, long)]
    debug: bool,

    /// Do not print the response body.
    #[arg(short = 'B', long)]
    no_body: bool,

    /// Show the request and exit without sending it.
    #[arg(long)]
    dry_run: bool,

    /// Stream the response body as it is received.
    #[arg(short, long)]
    stream: bool,

    /// Maximum number of redirects to follow. Set to 0 to disable redirects.
    #[arg(long, default_value_t = 16)]
    max_redirects: usize,

    /// HTTP method to use.
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// The full URL to request.
    url: String,
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
    let cli = Cli::parse();
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
    let url = parse_target_url(&cli.url)?;
    let host = host_header_value(&url)?;

    let method = reqwest::Method::from_bytes(cli.method.as_bytes())?;
    let request = client
        .request(method, url)
        .header(ACCEPT, "*/*")
        .header(USER_AGENT, format!("get/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

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
    }

    let highlight_body = should_highlight_body();
    let mut stdout = io::stdout().lock();

    if cli.dry_run {
        return Ok(());
    }

    let mut response = client.execute(request)?;
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

fn should_highlight_body() -> bool {
    if !io::stdout().is_terminal() {
        return false;
    }

    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    match std::env::var("TERM") {
        Ok(term) if term.eq_ignore_ascii_case("dumb") => false,
        _ => true,
    }
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

#[cfg(test)]
mod tests {
    use super::syntax_token_for_content_type;

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
}
