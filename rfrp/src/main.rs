mod rfrp_init;

use rfrp_main::rfrp_main;
use rfrp_init::init_logging;

fn main() {
    init_logging();
    rfrp_main();
}
