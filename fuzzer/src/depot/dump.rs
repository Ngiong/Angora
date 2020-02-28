use super::*;
use angora_common::defs;
use std::{fs,fs::OpenOptions, io::prelude::*};

impl Drop for Depot {
    fn drop(&mut self) {
        info!("dump constraints and chart..");
        let dir = self.dirs.inputs_dir.parent().unwrap();

        let mut log_q = fs::File::create(dir.join(defs::COND_QUEUE_FILE)).unwrap();
        writeln!(
            log_q,
            "cmpid, context, order, belong, priority, op, condition, is_desirable, offsets, state"
        )
        .unwrap();
        
        let cpath = self.dirs.crashes_dir.as_path().parent().unwrap().join("conds.csv");
        let mut cond_file = OpenOptions::new().write(true).create(true)
                               .open(cpath).expect("Can't open conds.csv");
        if let Err(_) = writeln!(cond_file,
              "cmpid,context,belong,condition,state,# of offsets,total offset len,fuzz_times,priority,fuzz_type,extended_size, extended_size_rel1, extended_size_rel2, extended_size_rel3")
          {eprintln!("can't write conds.csv")}

        let q = self.queue.lock().unwrap();

        for (cond, p) in q.iter() {
            if !cond.base.is_afl() {
                let mut offsets = vec![];
                for off in &cond.offsets {
                    offsets.push(format!("{}-{}", off.begin, off.end));
                }

                writeln!(
                    log_q,
                    "{}, {}, {}, {}, {}, {}, {}, {:x}, {:x}, {}, {}, {:?}",
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
                )
                .unwrap();
            }
  
            let condinfo = format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{}",cond.base.cmpid,cond.base.context,cond.base.belong,
                                   cond.base.condition,cond.state,cond.offsets.len(),cond.get_offset_len(),
                                   cond.fuzz_times,p,cond.get_fuzz_type(),cond.ext_offset_size,cond.ext_offset_size_rel1,
                                   cond.ext_offset_size_rel2,cond.ext_offset_size_rel3);
            if let Err(_) = writeln!(cond_file, "{}", condinfo) {eprintln!("can't write conds.csv");}
        }
    }
}
