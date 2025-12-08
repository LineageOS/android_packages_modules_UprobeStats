//! Client for UprobeStatsService
use anyhow::{Context, Result};
use binder::{get_interface, Strong};
use std::sync::LazyLock;
use uprobestats_service_aidl::aidl::com::android::os::uprobestats::IUprobeStatsService::IUprobeStatsService;

const UPROBE_STATS_SERVICE_NAME: &str = "uprobestats_service";

pub(crate) fn get_uprobestats_service() -> Result<Strong<dyn IUprobeStatsService>> {
    let service =
        get_interface(UPROBE_STATS_SERVICE_NAME).context("Failed to get uprobestats service")?;
    Ok(service)
}

pub(crate) static UPROBESTATS_SERVICE: LazyLock<Result<Strong<dyn IUprobeStatsService>>> =
    LazyLock::new(get_uprobestats_service);
