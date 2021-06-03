use std::io;
fn main() {
    let top_dispatcher = fern::Dispatch::new()
        .level(log::LevelFilter::Debug)
        .chain(fern::Dispatch::new().chain(io::stdout()));
    top_dispatcher.apply().expect("failed to init logging");
    mullvad_daemon::resolver::run_resolver()
}
