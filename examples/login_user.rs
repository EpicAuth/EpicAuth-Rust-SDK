use epicauth::{EpicAuth, LoginOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    let mut options = LoginOptions::new("username", "password");
    options.code = Some("123456".into()); // Optional 2FA code

    match app.login(options).await {
        Ok(()) => {
            if let Some(user) = &app.user_data {
                println!("Welcome back, {}!", user.username);
                println!("Level: {:?}", user.subscriptions.first().map(|s| &s.level));
            }
        }
        Err(err) => {
            eprintln!("Login failed: {err}");
        }
    }

    Ok(())
}
