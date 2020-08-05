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

    pub fn run(&mut self) {
        self.bitflip1();
    }
}
