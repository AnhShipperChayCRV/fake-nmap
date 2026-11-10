#[macro_use]
mod cli;
mod osdetect;
mod output;
mod rawscan;
mod scan;
mod services;
mod targets;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = cli::parse(&args);

    if cfg.help || cfg.targets.is_empty() {
        print!("{}", cli::usage());
        if !cfg.help {
            std::process::exit(1);
        }
        return;
    }

    let report = scan::run(&cfg);
    output::emit(&cfg, &report);
}