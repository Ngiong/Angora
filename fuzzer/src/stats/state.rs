use super::*;
use crate::cond_stmt::{CondState, CondStmt};
use serde_derive::Serialize;

#[derive(Clone, Default, Serialize)]
struct PendingCounter {
    pub pending: Counter,
    pub done: Counter,
}

impl PendingCounter {
    pub fn count(&mut self, done: bool) {
        if done {
            self.done.count();
        } else {
            self.pending.count();
        }
    }
}

impl fmt::Display for PendingCounter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}d - {}p", self.done, self.pending)
    }
}

#[derive(Default, Serialize)]
pub struct StateStats {
    //normal: PendingCounter,
    first_offset : PendingCounter,
    second_offset : PendingCounter,
    merged_offset : PendingCounter,
    normal_end: PendingCounter,
    det: PendingCounter,
    one_byte: PendingCounter,
    unsolvable: PendingCounter,
    timeout: PendingCounter,
    func : PendingCounter,
    func_rel : PendingCounter,
}

impl StateStats {
    pub fn count(&mut self, cond: &CondStmt) {
        let is_done = cond.is_done();
        match cond.state {
            CondState::Offset => {
              self.first_offset.count(is_done);
            },
            CondState::OffsetOpt => {
              self.second_offset.count(is_done);
            },
            CondState::OffsetAll => {
              self.merged_offset.count(is_done);
            },
        //    CondState::Offset | CondState::OffsetOpt | CondState::OffsetAll => {
        //        self.normal.count(is_done);
        //    },
            CondState::OffsetAllEnd => {
                self.normal_end.count(is_done);
            },
            CondState::OneByte => {
                self.one_byte.count(is_done);
            },
            CondState::Unsolvable => {
                self.unsolvable.count(is_done);
            },
            CondState::Deterministic => {
                self.det.count(is_done);
            },
            CondState::Timeout => {
                self.timeout.count(is_done);
            },
            CondState::OffsetFunc => {
               self.func.count(is_done);
            },
            CondState::OffsetRelFunc => {
               self.func_rel.count(is_done);
            }
        }
    }
  pub fn mini_state_log(&self) -> String {
   let res :String = format!( "{}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p, {}d/{}p",
              self.one_byte.done.0, self.one_byte.pending.0,
              self.first_offset.done.0, self.first_offset.pending.0,
              self.second_offset.done.0,self.second_offset.pending.0,
              self.merged_offset.done.0,self.merged_offset.pending.0,
              self.det.done.0, self.det.pending.0,
              self.timeout.done.0, self.timeout.pending.0,
              self.unsolvable.done.0, self.unsolvable.pending.0,
              self.func.done.0, self.func.pending.0, self.func_rel.done.0, self.func_rel.pending.0,
              self.normal_end.done.0, self.normal_end.pending.0 );
   res
  }
}

impl fmt::Display for StateStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            r#"           |     FIRST: {},   SECOND: {},   MERGED: {}
           |    NORMAL: ,   NORMAL_END: {},   ONE_BYTE: {}
           |       DET: {},    TIMEOUT: {},     UNSOLVABLE: {}
           |     FUNC : {},  FUNC_REL : {}"#,
            self.first_offset, self.second_offset, self.merged_offset, self.normal_end, self.one_byte, self.det, self.timeout, self.unsolvable, self.func, self.func_rel
        )
    }
}
