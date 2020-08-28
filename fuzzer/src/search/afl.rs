// Modify input randomly like AFL.
// All the byte offsets in the input is the input.
// Random pick offsets, then flip, add/sub ..
// And GE algorithm.

use super::*;
use rand::{self, distributions::Uniform, Rng};
use std::collections::HashSet;

static IDX_TO_SIZE: [usize; 4] = [1, 2, 4, 8];

pub struct AFLFuzz<'a> {
    handler: SearchHandler<'a>,
    run_ratio: usize,
    program_opts: Vec<String>,
}

impl<'a> AFLFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>, program_opts: &Vec<String>) -> Self {
        // FIXME:
        let edge_num = handler.cond.base.arg1 as usize;
        let avg_edge_num = handler.executor.local_stats.avg_edge_num.get() as usize;
        let run_ratio = if edge_num * 3 < avg_edge_num {
            2
        } else if edge_num < avg_edge_num {
            3
        } else {
            5
        };

        Self { handler, run_ratio, program_opts: program_opts.clone() }
    }

    pub fn run(&mut self) {
        if self.handler.cond.is_first_time() {
            self.afl_len();
        }

        self.handler.max_times = (config::MAX_SPLICE_TIMES * self.run_ratio).into();
        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            if !self.splice() {
                break;
            }
        }

        let max_stacking = if self.handler.buf.len() <= 16 {
            64
        } else {
            256
        };

        let program_option_additional_choice = if config::MUTATE_PROGRAM_OPT_HAVOC {
            2 + if config::MUTATE_PROGRAM_OPT_ALLOW_DELETE { 1 } else { 0 }
        } else {
            0
        };

        let max_choice = if config::ENABLE_MICRO_RANDOM_LEN_AND_PROGRAM_OPT_HAVOC_MUTATION {
            8 + program_option_additional_choice
        } else {
            6
        };

        let choice_range = Uniform::new(0, max_choice);

        self.handler.max_times += (config::MAX_HAVOC_FLIP_TIMES * self.run_ratio).into();
        self.handler.skip = false;

        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            let mut buf = self.handler.buf.clone();
            self.havoc_flip(&mut buf, max_stacking, choice_range);

            // let mutated_program_opts = self.mutate_prog_opt(max_stacking, choice_range);
            // self.handler.execute(&buf, &mutated_program_opts);
            self.handler.execute(&buf, &self.program_opts);
        }
    }

    fn mutate_prog_opt(
        &mut self,
        max_stacking: usize,
        choice_range: Uniform<u32>
    ) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let program_opts = self.program_opts.clone();
        let should_mutate = rng.gen_bool(config::MUTATE_PROGRAM_OPT_CHANCE);
        if !should_mutate {
            return program_opts;
        }

        let result = if config::CH_MUTATE_PROGRAM_OPT_USING_DICT { // grammar-based mutation
            self.dict_based_program_opt_mutation()

        } else { // byte mutation
            let mut program_opts_bytes: Vec<u8> = program_opts.join(" ").into_bytes();
            if program_opts_bytes.is_empty() {
                program_opts_bytes = Vec::from(" ");
            }
            self.havoc_flip(&mut program_opts_bytes, max_stacking, choice_range);
            match String::from_utf8(program_opts_bytes) {
                Ok(str) => vec![str],
                Err(_) => {
                    program_opts
                },
            }
        };
        result
    }

    fn dict_based_program_opt_mutation(
        &mut self,
    ) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let program_opts = &self.program_opts;
        let program_opts_dict = &self.handler.executor.cmd.option_vec;

        let dict_sample_size = rng.gen_range(0, program_opts_dict.len());
        let dict_sample = program_opts_dict.iter().choose_multiple(&mut rng, dict_sample_size);

        let mut deduplicate_set = HashSet::new();
        for i in program_opts {
            deduplicate_set.insert(i);
        }
        for i in dict_sample {
            deduplicate_set.insert(i);
        }

        let final_program_opt_size = rng.gen_range(0, config::CH_DICT_BASED_MAX_PROG_OPTS);
        let final_program_opt = deduplicate_set.iter().choose_multiple(&mut rng, final_program_opt_size);
        let mut final_program_opt: Vec<String> = final_program_opt.iter()
            .map(|&&s| s.clone())
            .collect();
        final_program_opt.shuffle(&mut rng);
        final_program_opt
    }

    fn locate_diffs(buf1: &Vec<u8>, buf2: &Vec<u8>, len: usize) -> (Option<usize>, Option<usize>) {
        let mut first_loc = None;
        let mut last_loc = None;

        for i in 0..len {
            if buf1[i] != buf2[i] {
                if first_loc.is_none() {
                    first_loc = Some(i);
                }
                last_loc = Some(i);
            }
        }

        (first_loc, last_loc)
    }

    fn splice_two_vec(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Option<Vec<u8>> {
        let len = std::cmp::min(buf1.len(), buf2.len());
        if len < 2 {
            return None;
        }
        let (f_loc, l_loc) = Self::locate_diffs(buf1, buf2, len);
        if f_loc.is_none() || l_loc.is_none() {
            return None;
        }
        let f_loc = f_loc.unwrap();
        let l_loc = l_loc.unwrap();
        if f_loc == l_loc {
            return None;
        }

        let split_at = f_loc + rand::random::<usize>() % (l_loc - f_loc);
        Some([&buf1[..split_at], &buf2[split_at..]].concat())
    }

    // GE algorithm
    fn splice(&mut self) -> bool {
        let buf1 = self.handler.buf.clone();
        let buf2 = self.handler.executor.random_input_buf();
        if let Some(new_buf) = Self::splice_two_vec(&buf1, &buf2) {
            self.handler.execute(&new_buf, &self.program_opts);
            true
        } else {
            false
        }
    }

    // TODO both endian?
    fn havoc_flip(&mut self, buf: &mut Vec<u8>, max_stacking: usize, choice_range: Uniform<u32>) {
        let mut rng = rand::thread_rng();
        let mut byte_len = buf.len() as u32;
        let use_stacking = 1 + rng.gen_range(0, max_stacking);

        for _ in 0..use_stacking {
            match rng.sample(choice_range) {
                0 | 1 => {
                    // flip bit
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let bit_idx: u32 = rng.gen_range(0, 8);
                    buf[byte_idx as usize] ^= 128 >> bit_idx;
                },
                2 | 3 => {
                    //add or sub
                    let n: u32 = rng.gen_range(0, 3);
                    let size = IDX_TO_SIZE[n as usize];
                    if byte_len > size as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len - size as u32);
                        let v: u32 = rng.gen_range(0, config::MUTATE_ARITH_MAX);
                        let direction: bool = rng.gen();
                        mut_input::update_val_in_buf(
                            buf,
                            false,
                            byte_idx as usize,
                            size,
                            direction,
                            v as u64,
                        );
                    }
                },
                4 => {
                    // set interesting value
                    let n: u32 = rng.gen_range(0, 3);
                    let size = IDX_TO_SIZE[n as usize];
                    if byte_len > size as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len - size as u32);
                        let vals = get_interesting_bytes(size);
                        let wh = rng.gen_range(0, vals.len() as u32);
                        mut_input::set_val_in_buf(buf, byte_idx as usize, size, vals[wh as usize]);
                    }
                },
                5 => {
                    // random byte
                    let byte_idx: u32 = rng.gen_range(0, byte_len);
                    let val: u8 = rng.gen();
                    buf[byte_idx as usize] = val;
                },
                6 => {
                    // delete bytes
                    let remove_len: u32 = rng.gen_range(1, 5);
                    if byte_len > remove_len {
                        byte_len -= remove_len;
                        //assert!(byte_len > 0);
                        let byte_idx: u32 = rng.gen_range(0, byte_len);
                        for _ in 0..remove_len {
                            buf.remove(byte_idx as usize);
                        }
                    }
                },
                7 => {
                    // insert bytes
                    let add_len = rng.gen_range(1, 5);
                    let new_len = byte_len + add_len;
                    if new_len < config::MAX_INPUT_LEN as u32 {
                        let byte_idx: u32 = rng.gen_range(0, byte_len);
                        byte_len = new_len;
                        for i in 0..add_len {
                            buf.insert((byte_idx + i) as usize, rng.gen());
                        }
                    }
                },
                8 => {
                    // overwrite program option
                    let program_opts_dict = &self.handler.executor.cmd.option_vec;

                    let new_po_idx = rng.gen_range(0, program_opts_dict.len());
                    let new_opt = program_opts_dict[new_po_idx].clone();

                    if self.program_opts.is_empty() { // do insert
                        self.program_opts.push(new_opt);
                    } else {
                        let loc_idx = rng.gen_range(0, self.program_opts.len());
                        self.program_opts[loc_idx] = new_opt;
                    }
                },
                9 => {
                    // insert program option
                    let program_opts_dict = &self.handler.executor.cmd.option_vec;

                    let new_po_idx = rng.gen_range(0, program_opts_dict.len());
                    let new_opt = program_opts_dict[new_po_idx].clone();

                    if self.program_opts.is_empty() {
                        self.program_opts.push(new_opt);
                    } else {
                        let loc_idx = rng.gen_range(0, self.program_opts.len() + 1);
                        self.program_opts.insert(loc_idx, new_opt);
                    }
                },
                10 => {
                    // delete program option
                    if self.program_opts.is_empty() {
                        // do nothing
                    } else {
                        let loc_idx = rng.gen_range(0, self.program_opts.len());
                        self.program_opts.remove(loc_idx);
                    }
                }
                _ => {},
            }
        }
    }

    fn random_len(&mut self) {
        let len = self.handler.buf.len();
        if len > config::MAX_INPUT_LEN {
            return;
        }

        // let step = std::cmp::max( len / config::INFLATE_MAX_ITER_NUM + 1, 5);
        let orig_len = self.handler.buf.len();
        let mut rng = rand::thread_rng();

        let mut buf = self.handler.buf.clone();
        for _ in 0..config::RANDOM_LEN_NUM {
            let step = rng.gen::<usize>() % orig_len + 1;
            let mut v = vec![0u8; step];
            rng.fill_bytes(&mut v);
            buf.append(&mut v);
            if buf.len() < config::MAX_INPUT_LEN {
                self.handler.execute(&buf, &self.program_opts);
            } else {
                break;
            }
        }
    }

    fn add_small_len(&mut self) {
        let len = self.handler.buf.len();
        if len > config::MAX_INPUT_LEN {
            return;
        }

        let mut rng = rand::thread_rng();
        let mut buf = self.handler.buf.clone();
        let mut step = 1;
        for _ in 0..4 {
            let mut v = vec![0u8; step];
            rng.fill_bytes(&mut v);
            buf.append(&mut v);
            step = step * 2;
            if buf.len() < config::MAX_INPUT_LEN {
                self.handler.execute(&buf, &self.program_opts);
            } else {
                break;
            }
        }
    }

    fn afl_len(&mut self) {
        if config::ENABLE_RANDOM_LEN {
            self.random_len();
        } else {
            self.add_small_len();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_locate_diffs() {
        let buf1: Vec<u8> = vec![1, 2, 3, 4, 5];
        let buf2: Vec<u8> = vec![1, 2, 3, 4, 5];
        let len = std::cmp::min(buf1.len(), buf2.len());
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert!(f_loc.is_none());
        assert!(l_loc.is_none());
        let buf2: Vec<u8> = vec![0, 2, 3, 4, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(0));
        assert_eq!(l_loc, Some(0));
        let buf2: Vec<u8> = vec![1, 2, 0, 0, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(2));
        assert_eq!(l_loc, Some(3));
        let buf2: Vec<u8> = vec![0, 2, 0, 4, 5];
        let (f_loc, l_loc) = AFLFuzz::locate_diffs(&buf1, &buf2, len);
        assert_eq!(f_loc, Some(0));
        assert_eq!(l_loc, Some(2));
    }

    #[test]
    fn test_splice() {
        let buf1: Vec<u8> = vec![1, 2, 3, 4, 5];
        let buf2: Vec<u8> = vec![1, 2, 2, 2, 5, 6];

        let new_vec = AFLFuzz::splice_two_vec(&buf1, &buf2).unwrap();
        println!("{:?}", new_vec);
        // split at index 2 or 3
        assert!(new_vec == vec![1, 2, 2, 4, 5, 6] || new_vec == vec![1, 2, 2, 2, 5, 6]);
    }
}
