use std::{
    net::{SocketAddr, TcpStream},
    str::FromStr as _,
    thread,
    time::Duration,
};

use clap::Parser;
use p0f_rs::P0f;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // This default ip is for tcpbin.com
    #[arg(short, long, default_value = "45.79.112.203:4242")]
    address: String,

    #[arg(short, long)]
    socket: String,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let address = SocketAddr::from_str(&args.address)?;

    let mut p0f: P0f = P0f::new(args.socket)?;
    let _ = TcpStream::connect(&address)?;

    thread::sleep(Duration::from_secs(1));
    let response = p0f.query(address.ip())?.unwrap();
    println!("{:#?}", response);

    Ok(())
}
