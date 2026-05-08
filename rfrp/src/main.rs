mod rfrp_init;

use rfrp_main::rfrp_main;
use rfrp_main::RfrpErrorCode;
use rfrp_init::init_logging;

fn main() {
    init_logging();

    match rfrp_main() {
        RfrpErrorCode::RfrpOk => println!("Rfrp exited successfully"),
        _ => println!("Rfrp execution failed"),
    }
}
