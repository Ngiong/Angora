use super::*;
use angora_common::defs;
use std::{fs,io::prelude::*};

impl Drop for Depot {
    fn drop(&mut self) {
        info!("dump constraints and chart..");
        let dir = self.dirs.inputs_dir.parent().unwrap();

        let mut log_q = fs::File::create(dir.join(defs::COND_QUEUE_FILE)).unwrap();
        writeln!(
            log_q,
            "cmpid, context, order, belong, priority, op, condition, is_desirable, offsets, state, total offset len, fuzz_times, fuzz_type, input_len, extended_size, extended_size_rel, func_rel_score, belongs"
        )
        .unwrap();
        
        let q = self.queue.lock().unwrap();

        for (cond, p) in q.iter() {
            if !cond.base.is_afl() {
                let mut offsets = vec![];
                for off in &cond.offsets {
                    offsets.push(format!("{}-{}", off.begin, off.end));
                }

                writeln!(
                    log_q,
                    "{}, {}, {}, {}, {}, {}, {}, {:x}, {:x}, {}, {}, {:?}, {}, {}, {}, {}, {}, {}, {}",
                    cond.base.cmpid,
                    cond.base.context,
                    cond.base.order,
                    cond.base.belong,
                    p,
                    cond.base.op,
                    cond.base.condition,
                    cond.base.arg1,
                    cond.base.arg2,
                    cond.is_desirable,
                    offsets.join("&"),
                    cond.state,
                    cond.get_offset_len(),
                    cond.get_fuzz_type(),
                    cond.belong_len,
                    cond.ext_offset_size,
                    cond.ext_offset_size_rel,
                    cond.func_rel_score,
                    cond.belongs,
                )
                .unwrap();
            }
        }
    }
}
