use epicauth::EpicAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    let stats = app.fetch_stats().await?;
    println!("Application Stats:");
    println!("  Version: {}", stats.app_ver);
    println!("  Total Users: {}", stats.num_users);
    println!("  Online Users: {}", stats.online_users);
    println!("  Active Keys: {}", stats.num_keys);
    println!("  Customer Panel: {}", stats.customer_panel);

    Ok(())
}
