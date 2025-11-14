use super::{bytes_as_str, OnItem};
use crate::config_resolver::ResolvedTask;
use anyhow::{anyhow, Result};
use log::debug;
use protobuf::MessageField;
use statssocket::AStatsEvent;
use uprobestats_bpf_bindgen::{
    SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
};

// SAFETY: `SetUidTempAllowlistStateRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for SetUidTempAllowlistStateRecord {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ProcessManagement_output_buf";
    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
        debug!("SetUidTempAllowlistStateRecord: {:?}", self);

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        debug!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        debug!("attempting to write atom id: {}", atom_id);
        let mut event = AStatsEvent::new(atom_id.try_into()?);

        event.write_int32(self.uid.try_into()?);
        event.write_bool(self.onAllowlist);

        event.write();
        debug!("successfully wrote atom id: {}", atom_id);

        Ok(())
    }
}

// SAFETY: `UpdateDeviceIdleTempAllowlistRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for UpdateDeviceIdleTempAllowlistRecord {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
        debug!("UpdateDeviceIdleTempAllowlistRecord: {:?}", self);

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        debug!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        debug!("attempting to write atom id: {}", atom_id);
        let mut event = AStatsEvent::new(atom_id.try_into()?);

        event.write_int32(self.changing_uid);
        event.write_bool(self.adding);
        event.write_int64(self.duration_ms as _);
        event.write_int32(self.type_);
        event.write_int32(self.reason_code);
        event.write_string(bytes_as_str(&self.reason)?)?;
        event.write_int32(self.calling_uid);

        event.write();
        debug!("successfully wrote atom id: {}", atom_id);

        Ok(())
    }
}
