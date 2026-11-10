use epicauth::EpicAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    // Remote global variable
    let welcome_msg = app.var("welcome_text").await?;
    println!("Server variable: {welcome_msg}");

    // Download protected asset
    let file_bytes = app.file("asset_123").await?;
    println!("Downloaded {} bytes securely", file_bytes.len());

    // Send security audit log
    app.log("User accessed sensitive module").await?;

    Ok(())
}
