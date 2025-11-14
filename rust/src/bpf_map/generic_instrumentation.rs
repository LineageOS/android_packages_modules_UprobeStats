use super::{OnItem, JAVA_ARGUMENT_REGISTER_OFFSET};
use crate::config_resolver::ResolvedTask;
use anyhow::{anyhow, Result};
use log::debug;
use protobuf::MessageField;
use statssocket::AStatsEvent;
use uprobestats_bpf_bindgen::{CallResult, CallTimestamp};

// SAFETY: `CallTimestamp` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for CallTimestamp {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_timestamp_buf";
    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
        debug!("CallTimestamp - event: {}, timestamp_ns: {}", self.event, self.timestampNs,);

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        debug!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        debug!("attempting to write atom id: {}", atom_id);
        let mut event = AStatsEvent::new(atom_id.try_into()?);
        event.write_int32(self.event.try_into()?);
        event.write_int64(self.timestampNs.try_into()?);
        event.write();
        debug!("successfully wrote atom id: {}", atom_id);
        Ok(())
    }
}

// SAFETY: `CallResult` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl OnItem for CallResult {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_detail_buf";
    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
        debug!("CallResult - register: pc = {}", self.pc,);
        for i in 0..10 {
            debug!("CallResult - register: {} = {}", i, self.regs[i],);
        }

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        debug!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        debug!("attempting to write atom id: {}", atom_id);
        let mut event = AStatsEvent::new(atom_id.try_into()?);

        for primitive_argument_position in &statsd_logging_config.primitive_argument_positions {
            let register_index: usize =
                (JAVA_ARGUMENT_REGISTER_OFFSET + primitive_argument_position).try_into()?;
            let primitive_argument: i32 = self.regs[register_index].try_into()?;
            debug!(
                "writing primitive_argument: {} from position: {}",
                primitive_argument, primitive_argument_position
            );
            event.write_int32(primitive_argument);
        }

        event.write();
        debug!("successfully wrote atom id: {}", atom_id);

        Ok(())
    }
}
