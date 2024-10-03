use std::{
    net::{SocketAddr, TcpListener},
    str::FromStr as _,
    thread,
    time::Duration,
};

use clap::Parser;
use p0f_rs::P0f;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:6666")]
    address: String,

    #[arg(short, long)]
    socket: String,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let mut p0f: P0f = P0f::new(args.socket)?;
    let listener = TcpListener::bind(SocketAddr::from_str(&args.address)?)?;

    println!("waiting for connection");
    let (_, addr) = listener.accept()?;
    println!("connection from {}", addr);

    thread::sleep(Duration::from_secs(1));
    let response = p0f.query(addr.ip())?.unwrap();
    println!("{:#?}", response);

    Ok(())
}
