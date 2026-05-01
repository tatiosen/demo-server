use anyhow::{bail, Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_bytes::ByteBuf;

fn hex_to_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    let clean = value.trim().trim_start_matches("0x").to_lowercase();
    if clean.len() % 2 != 0 || !clean.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("{field} must be an even-length hex string");
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for index in (0..clean.len()).step_by(2) {
        let pair = &clean[index..index + 2];
        bytes.push(
            u8::from_str_radix(pair, 16)
                .with_context(|| format!("invalid {field} byte: {pair}"))?,
        );
    }
    Ok(bytes)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        bail!("usage: nsm-attestor <nonce_hex> [public_key_base64] [user_data_hex]");
    }

    let nonce = hex_to_bytes(&args[1], "nonce_hex")?;
    let public_key = if args.len() >= 3 && !args[2].is_empty() {
        Some(
            BASE64_STANDARD
                .decode(args[2].trim())
                .context("public_key_base64 is invalid")?,
        )
    } else {
        None
    };
    let user_data = if args.len() >= 4 && !args[3].is_empty() {
        Some(hex_to_bytes(&args[3], "user_data_hex")?)
    } else {
        None
    };

    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        bail!("Could not open /dev/nsm");
    }

    let response = nsm_process_request(
        nsm_fd,
        Request::Attestation {
            user_data: user_data.map(ByteBuf::from),
            nonce: Some(ByteBuf::from(nonce)),
            public_key: public_key.map(ByteBuf::from),
        },
    );
    nsm_exit(nsm_fd);

    match response {
        Response::Attestation { document } => {
            println!("{}", BASE64_STANDARD.encode(document));
            Ok(())
        }
        Response::Error(code) => bail!("NSM returned error: {code:?}"),
        other => bail!("Unexpected NSM response: {other:?}"),
    }
}
