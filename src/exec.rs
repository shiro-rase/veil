use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub struct RemoteExecutor;

impl RemoteExecutor {
    pub async fn execute(command_str: &str, timeout_secs: u64) -> Result<ExecResult> {
        let execution = async {
            let output = Command::new("sh")
                .arg("-c")
                .arg(command_str)
                .output()
                .await?;

            let exit_code = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            Ok::<ExecResult, anyhow::Error>(ExecResult {
                exit_code,
                stdout,
                stderr,
            })
        };

        match timeout(Duration::from_secs(timeout_secs), execution).await {
            Ok(res) => res,
            Err(_) => Ok(ExecResult {
                exit_code: 124,
                stdout: String::new(),
                stderr: "Execution timed out".to_string(),
            }),
        }
    }
}
