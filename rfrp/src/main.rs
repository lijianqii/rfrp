use rfrp_main::rfrp_main;
use rfrp_main::RfrpErrorCode;

fn main() {
    match rfrp_main() {
        RfrpErrorCode::RfrpOk => println!("Rfrp exited successfully"),
        _ => println!("Rfrp execution failed"),
    }
}
