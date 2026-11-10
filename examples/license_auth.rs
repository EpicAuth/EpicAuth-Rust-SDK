use epicauth::{EpicAuth, LicenseOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    println!("Initializing application...");
    app.init().await?;

    let license_key =
        std::env::var("EPICAUTH_LICENSE").unwrap_or_else(|_| "DEMO-LICENSE-KEY".into());
    println!("Authenticating license: {license_key}");

    match app.license(LicenseOptions::new(license_key)).await {
        Ok(()) => {
            if let Some(user) = &app.user_data {
                println!("Successfully logged in!");
                println!("Username: {}", user.username);
                println!("HWID: {}", user.hwid);
                println!("IP: {}", user.ip);
                println!("Subscription: {}", user.subscription);
                println!("Expires: {}", user.expires);
            }
        }
        Err(err) => {
            eprintln!("Authentication failed: {err}");
        }
    }

    Ok(())
}
