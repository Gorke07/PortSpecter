#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    for target in std::env::args().skip(1) {
        let ip = target.parse()?;
        match portspecter_probe::query_mac(ip, None, std::time::Duration::from_millis(1500)).await?
        {
            Some(mac) => println!(
                "{ip}: {} (NetBIOS NBSTAT)",
                mac.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
            ),
            None => println!("{ip}: no valid NetBIOS MAC response"),
        }
    }
    Ok(())
}
