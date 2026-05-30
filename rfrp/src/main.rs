mod rfrp_init;

use rfrp_init::init_logging;
use rfrp_main::rfrp_main;

fn main() {
    init_logging();
    rfrp_main();
}
