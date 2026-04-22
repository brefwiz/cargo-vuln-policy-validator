mod adapters;
mod application;
mod domain;
mod ports;
use adapters::file_repo::FileRepo;
use adapters::stdout_reporter::StdoutReporter;
use application::validate::ValidateUseCase;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(false) // cleaner output
        .init();
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let repo = FileRepo;
    let reporter = StdoutReporter;

    let usecase = ValidateUseCase { repo, reporter };

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: validator audit.toml deny.toml exceptions.yaml");
        std::process::exit(2);
    }
    info!("Running policy report");
    usecase.run(&args[1], &args[2], &args[3])
}
