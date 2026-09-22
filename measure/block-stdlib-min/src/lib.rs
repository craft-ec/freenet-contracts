//! MEASUREMENT ONLY: `block-min`'s rule (blake3(state) == params; update refuses; empty summary / delta) written
//! the ordinary way, through freenet-stdlib's `#[contract]`. The size of THIS is the stdlib's floor; the gap to
//! `block/` is block's own logic, and the gap to `block-min` is the stdlib. Not wired, not released.
use freenet_stdlib::prelude::*;

pub struct Block;

#[contract]
impl ContractInterface for Block {
    fn validate_state(p: Parameters<'static>, s: State<'static>, _: RelatedContracts<'static>) -> Result<ValidateResult, ContractError> {
        let (p, s) = (p.as_ref(), s.as_ref());
        Ok(if p.len() == 32 && !s.is_empty() && blake3::hash(s).as_bytes()[..] == p[..] { ValidateResult::Valid } else { ValidateResult::Invalid })
    }
    fn update_state(_: Parameters<'static>, _: State<'static>, _: Vec<UpdateData<'static>>) -> Result<UpdateModification<'static>, ContractError> {
        Err(ContractError::InvalidUpdate)
    }
    fn summarize_state(_: Parameters<'static>, _: State<'static>) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(Vec::new()))
    }
    fn get_state_delta(_: Parameters<'static>, _: State<'static>, _: StateSummary<'static>) -> Result<StateDelta<'static>, ContractError> {
        Ok(StateDelta::from(Vec::new()))
    }
}
