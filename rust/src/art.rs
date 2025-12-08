//! Android Runtime (ART) integration
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::process::{Command, Stdio};

/// Gets the precompiled offset of the given method (which should be present in the given file on device)
pub(crate) fn get_method_offset_from_oatdump(
    oat_file: &str,
    method_signature: &str,
) -> Result<Option<i32>> {
    let output = Command::new("oatdump")
        .arg(format!("--oat-file={oat_file}"))
        .arg("--dump-method-and-offset-as-json")
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("could not execute oatdump: {e}"))?;
    let output =
        output.wait_with_output().map_err(|e| anyhow!("could not get output from oatdump: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)
            .map_err(|e| anyhow!("oatdump failed, error parsing stderr: {e}"))?;
        return Err(anyhow!("error from oatdump: {}", stderr));
    }

    let lines = String::from_utf8(output.stdout)
        .map_err(|e| anyhow!("could not read oatdump stdout: {e}"))?;
    let lines = lines.lines();
    for line in lines {
        let json: Value =
            serde_json::from_str(line).map_err(|e| anyhow!("error parsing oatdump json: {}", e))?;
        let method =
            json["method"].as_str().map(|s| s.to_string()).ok_or(anyhow!("bad json method"))?;
        if method == method_signature {
            let offset =
                json["offset"].as_str().map(|s| s.to_string()).ok_or(anyhow!("bad json offset"))?;
            let offset = i32::from_str_radix(offset.trim_start_matches("0x"), 16)
                .map_err(|e| anyhow!("could not parse offset {}: {}", offset, e))?;
            return Ok(Some(offset));
        }
    }

    Ok(None)
}
