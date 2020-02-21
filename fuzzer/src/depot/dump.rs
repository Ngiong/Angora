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
            "cmpid, context, order, belong, priority, op, condition, is_desirable, offsets, state, belongs"
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
                    "{}, {}, {}, {}, {}, {}, {}, {:x}, {:x}, {}, {}, {:?}, {}",
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
                    cond.dump_belongs(),
                )
                .unwrap();
            }
        }
        let cpath = self.dirs.crashes_dir.as_path().parent().unwrap().join("conds.csv");
        let mut cond_file = OpenOptions::new().write(true).create(true)
                               .open(cpath).expect("Can't open conds.csv");
        if let Err(_) = writeln!(cond_file,
              "cmpid,context,belong,condition,state,# of offsets,total offset len,#belongs,fuzz_times,priority,extended_size, extended_size_rel1, extended_size_rel2, extended_size_rel3")
          {eprintln!("can't write conds.csv")}
        
        let q = match self.queue.lock() {Ok (g) => g, Err(p) => {p.into_inner()}};
        let iter = q.iter();
        for (i, p) in iter {
          let condinfo = format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{}",i.base.cmpid,i.base.context,i.base.belong,
                                   i.base.condition,i.state,i.offsets.len(),i.get_offset_len(),
                                   i.belongs.len(),i.fuzz_times,p,i.ext_offset_size,i.ext_offset_size_rel1,i.ext_offset_size_rel2,i.ext_offset_size_rel3);
          if let Err(_) = writeln!(cond_file, "{}", condinfo) {eprintln!("can't write conds.csv");}
        }
    }
}
