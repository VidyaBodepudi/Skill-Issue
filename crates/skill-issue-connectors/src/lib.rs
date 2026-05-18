use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_github_signature(secret: &str, body: &[u8], signature_header: &str) -> Result<()> {
    let signature_hex = signature_header
        .strip_prefix("sha256=")
        .ok_or_else(|| anyhow!("GitHub signature must start with sha256="))?;
    let signature = decode_hex(signature_hex)?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .context("failed to initialize GitHub webhook HMAC")?;
    mac.update(body);
    mac.verify_slice(&signature)
        .map_err(|_| anyhow!("GitHub webhook signature verification failed"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(anyhow!("hex value has odd length"));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hex = std::str::from_utf8(chunk).context("hex signature contains invalid utf8")?;
            u8::from_str_radix(hex, 16).context("hex signature contains invalid byte")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_signature() {
        let result = verify_github_signature(
            "secret",
            b"{}",
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
    }
}
