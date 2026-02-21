use clap::Parser;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Url;
use std::error::Error;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "get")]
#[command(version, about = "A simple HTTP GET CLI")]
struct Cli {
    /// Show request and response headers.
    #[arg(short, long)]
    verbose: bool,

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
    let client = Client::builder().redirect(Policy::none()).build()?;
    let url = Url::parse(&cli.url)?;
    let host = host_header_value(&url)?;

    let request = client
        .get(url)
        .header(ACCEPT, "*/*")
        .header(USER_AGENT, format!("get/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let mut stderr = io::stderr().lock();
    if cli.verbose {
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
            writeln!(stderr, "> {}: {}", name, value.to_str().unwrap_or("<binary>"))?;
        }
        writeln!(stderr, "> host: {host}")?;
        writeln!(stderr, ">")?;
    }

    let mut response = client.execute(request)?;
    if cli.verbose {
        writeln!(
            stderr,
            "< {} {}",
            http_version(response.version()),
            response.status()
        )?;
        for (name, value) in response.headers() {
            writeln!(stderr, "< {}: {}", name, value.to_str().unwrap_or("<binary>"))?;
        }
        writeln!(stderr, "<")?;
    }

    let mut stdout = io::stdout().lock();

    io::copy(&mut response, &mut stdout)?;
    stdout.flush()?;

    Ok(())
}

fn host_header_value(url: &Url) -> Result<String, Box<dyn Error>> {
    let host = url.host_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "URL is missing a host")
    })?;
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
