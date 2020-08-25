use super::*;
use std::cmp;

pub struct DetFuzz<'a> {
    handler: SearchHandler<'a>,
    program_opts: Vec<String>,
}

impl<'a> DetFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>, program_opts: &Vec<String>) -> Self {
        Self {
            handler,
            program_opts: program_opts.clone(),
        }
    }
    pub fn bitflip1(&mut self) {
        debug!("detministic steps");
        let mut input = self.handler.get_f_input();
        let n = cmp::min(input.val_len() << 3, config::MAX_SEARCH_EXEC_NUM);
        for i in 0..n {
            if self.handler.cond.is_done() {
                break;
            }
            input.bitflip(i);
            self.handler.execute_cond(&input, &self.program_opts);
            input.bitflip(i);
        }
    }

    pub fn dict_based_program_opt(&mut self) {
        let po_dict = self.handler.executor.cmd.option_vec.clone();

        // Stage-1: Overwriting program option
        self.deterministic_overwrite_program_opts(&po_dict);
        // Stage-2: Insert program option
        self.deterministic_insert_program_opts(&po_dict);
        // Stage-3: Delete program option
        if config::MUTATE_PROGRAM_OPT_ALLOW_DELETE {
            self.deterministic_delete_program_opts();
        }
    }

    pub fn deterministic_overwrite_program_opts(&mut self, po_dict: &Vec<String>) {
        let mut input = self.handler.get_f_input();

        let mut po_buf= self.program_opts.clone();
        let po_buf_len = po_buf.len();
        for i in 0..po_buf_len {
            let tmp = po_buf[i].clone();
            for new_opt in po_dict {
                po_buf[i] = new_opt.clone();
                self.handler.execute_cond(&input, &po_buf);
            }
            po_buf[i] = tmp;
        }
    }

    pub fn deterministic_insert_program_opts(&mut self, po_dict: &Vec<String>) {
        let mut input = self.handler.get_f_input();

        let mut program_opts= self.program_opts.clone();
        let mut po_buf = Vec::new();
        po_buf.push(String::new());
        po_buf.append(&mut program_opts);

        let po_buf_len = po_buf.len();
        for i in 0..po_buf_len {
            for new_opt in po_dict {
                po_buf[i] = new_opt.clone();
                self.handler.execute_cond(&input, &po_buf);
            }
            if i < po_buf_len - 1 {
                po_buf[i] = po_buf[i+1].clone();
            }
        }
    }

    pub fn deterministic_delete_program_opts(&mut self) {
        let mut program_opts= self.program_opts.clone();
        let mut input = self.handler.get_f_input();

        if !program_opts.is_empty() {
            let mut po_buf: Vec<String> = program_opts.drain(1..).collect();
            let mut tmp_elmt = program_opts[0].clone();

            self.handler.execute_cond(&input, &po_buf);

            let po_buf_len = po_buf.len();
            for i in 0..po_buf_len {
                let tmp = po_buf[i].clone();
                po_buf[i] = tmp_elmt;
                tmp_elmt = tmp;
                self.handler.execute_cond(&input, &po_buf);
            }
        }
    }

    pub fn run(&mut self) {
        self.bitflip1();
        if config::MUTATE_PROGRAM_OPT_DETERMINISTIC {
            self.dict_based_program_opt();
        }
    }
}
