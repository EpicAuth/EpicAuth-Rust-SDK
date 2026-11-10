use epicauth::{EpicAuth, LicenseOptions};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize EpicAuth ONCE during application startup
    let mut app = EpicAuth::builder()
        .name("YourApplication")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    println!("Initializing session...");
    app.init().await?;

    // Authenticate (e.g., with a license key)
    let license_key = "XXXX-XXXX-XXXX-XXXX";
    println!("Authenticating license key...");
    app.license(LicenseOptions::new(license_key)).await?;

    // 2. Wrap the authenticated instance in Arc<Mutex<...>>
    // This allows sharing across asynchronous tasks, threads, and UI handlers
    let shared_client = Arc::new(Mutex::new(app));

    // 3. Spawn a background task using a clone of the Arc handle
    let worker_handle = {
        let task_client = Arc::clone(&shared_client);
        tokio::spawn(async move {
            println!("[Worker Task] Waiting for lock...");
            let mut client = task_client.lock().await;

            // Perform periodic check or fetch remote variables
            match client.check().await {
                Ok(true) => println!("[Worker Task] Session is valid!"),
                Ok(false) => eprintln!("[Worker Task] Session is invalid!"),
                Err(err) => eprintln!("[Worker Task] Check error: {err}"),
            }
        })
    };

    // 4. Concurrently access from the main thread / another subsystem
    {
        let client = shared_client.lock().await;
        if let Some(user) = &client.user_data {
            println!("[Main Thread] Active User: {}", user.username);
            println!("[Main Thread] Subscription: {}", user.subscription);
        }
    }

    worker_handle.await?;
    println!("Completed successfully.");

    Ok(())
}
