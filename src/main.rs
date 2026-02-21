use clap::Parser;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Url;
use std::error::Error;
use std::io::{self, Write};
use std::net::IpAddr;

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

    /// Maximum number of redirects to follow. Set to 0 to disable redirects.
    #[arg(long, default_value_t = 16)]
    max_redirects: usize,

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

    let request = client
        .get(url)
        .header(ACCEPT, "*/*")
        .header(USER_AGENT, format!("get/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let mut stderr = io::stderr();
    let show_headers = cli.verbose || cli.debug;

    if show_headers {
        let path_and_query = request
            .url()
            .query()
            .map(|query| format!("{}?{query}", request.url().path()))
            .unwrap_or_else(|| request.url().path().to_string());

        writeln!(
            stderr,
            "> GET {path_and_query} {}",
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

    let mut stdout = io::stdout().lock();

    if !cli.no_body {
        io::copy(&mut response, &mut stdout)?;
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
