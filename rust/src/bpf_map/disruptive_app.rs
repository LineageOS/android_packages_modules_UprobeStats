use super::{bytes_as_str, OnItem};
use crate::config_resolver::ResolvedTask;
use anyhow::Result;
use log::debug;
use statslog_uprobestats::{
    bind_service_locked_with_bal_flags_reported, set_component_enabled_setting_reported,
};
use std::ffi::c_long;
use uprobestats_bpf_bindgen::{BindServiceLocked, ComponentEnabledSetting};

const COMPONENT_ENABLED_STATE_DISABLED: i32 = 2; // PackageManager#COMPONENT_ENABLED_STATE_DISABLED (all values greater than or equal to are disabled states)

// SAFETY: `ComponentEnabledSetting` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for ComponentEnabledSetting {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_ComponentEnabledSetting_output_buf";
    fn on_item(&self, _task: &ResolvedTask) -> Result<()> {
        let package_name = bytes_as_str(&self.package_name)?;
        let class_name = bytes_as_str(&self.class_name)?;
        let new_state = self.new_state;
        let calling_package_name = bytes_as_str(&self.calling_package_name)?;
        debug!("ComponentEnabledSetting: package_name={:?}, class_name={:?}, new_state={:?}, calling_package_name={:?}", package_name, class_name, new_state, calling_package_name);
        if new_state < COMPONENT_ENABLED_STATE_DISABLED {
            // < PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
            return Ok(());
        }
        set_component_enabled_setting_reported::stats_write(
            package_name,
            class_name,
            new_state,
            calling_package_name,
        )?;
        Ok(())
    }
}

const BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS: c_long = 0x00100000; // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS

// SAFETY: `BindServiceLocked` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for BindServiceLocked {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_BindServiceLocked_output_buf";
    fn on_item(&self, _task: &ResolvedTask) -> Result<()> {
        let intent_package = bytes_as_str(&self.intent_package)?;
        let intent_action = bytes_as_str(&self.intent_action)?;
        let intent_component_name_package = bytes_as_str(&self.intent_component_name_package)?;
        let intent_component_name_class = bytes_as_str(&self.intent_component_name_class)?;
        let flags = self.bind_flags;
        let calling_package = bytes_as_str(&self.calling_package)?;
        let has_bal_flag = (self.bind_flags & BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS) != 0;
        debug!(
            "BindServiceLocked: intent_package={:?}, intent_action={:?}, intent_component_name_package={:?}, intent_component_name_class={:?} flags={:?}, calling_package={:?}, has_bal_flag={}",
            intent_package, intent_action, intent_component_name_package, intent_component_name_class, flags, calling_package, has_bal_flag
        );
        if has_bal_flag {
            bind_service_locked_with_bal_flags_reported::stats_write(
                intent_package,
                flags as _,
                calling_package,
            )?;
        }
        Ok(())
    }
}
