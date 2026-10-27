use portspecter_domain::VendorDatabase;

/// Read-only diagnostic. It reads local route/neighbor tables without sending probe packets.
fn main() -> anyhow::Result<()> {
    let vendors =
        VendorDatabase::from_json(include_bytes!("../../../assets/data/mac-vendors.json"))?;
    let snapshot = portspecter_platform::mac_snapshot(&vendors)?;
    for target in std::env::args().skip(1) {
        let ip = target.parse()?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"ip":ip,"mac":snapshot.get(&ip),"route":portspecter_platform::route_to(ip,None).ok()})
            )?
        );
    }
    Ok(())
}
