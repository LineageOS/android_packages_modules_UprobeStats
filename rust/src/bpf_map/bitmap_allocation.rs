use super::OnItem;
use crate::config_resolver::ResolvedTask;
use anyhow::Result;
use log::debug;
use statslog_uprobestats::android_graphics_bitmap_allocated;
use uprobestats_bpf_bindgen::BitmapAllocation;

// SAFETY: `BitmapAllocation` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for BitmapAllocation {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
        debug!("BitmapAllocation: {:?}", self);
        android_graphics_bitmap_allocated::stats_write(
            task.uid,
            self.width.try_into()?,
            self.height.try_into()?,
        )?;
        Ok(())
    }
}
