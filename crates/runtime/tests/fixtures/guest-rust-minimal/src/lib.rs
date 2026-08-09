wit_bindgen::generate!({
    path: "wit",
    world: "advance-host",
});

use advance::runtime::types::{
    ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct MinimalAgent;

impl MessageDrivenGuest for MinimalAgent {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(vec![0xAD, 0x11, 0xCE, 0x01])
    }

    fn handle_message(msg: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        let mut new_state = state;
        new_state.extend_from_slice(&msg.payload);
        Ok(ActionResult {
            new_state,
            actions: vec![],
        })
    }
}

impl RunnableGuest for MinimalAgent {
    fn run(config: ComponentConfig) -> Result<RunResult, String> {
        // Slice AB — conditional branches on `config.config_data` for
        // execution-budget integration tests (T53/T54/T55).
        //
        // Default (None or unrecognized payload) preserves the pre-Slice-AB
        // behavior so existing AC-03 happy-path tests (T43/T44/T45) pass
        // unchanged.
        if let Some(data) = &config.config_data {
            if let Some(n_str) = core::str::from_utf8(data).ok().and_then(|s| s.strip_prefix("grow:")) {
                if let Ok(n) = n_str.parse::<u32>() {
                    // `memory_grow` is a WASM intrinsic returning `usize`; grow
                    // failures return `usize::MAX` (= -1 as i32). Under the
                    // Slice AB host-installed limiter cap, grows exceeding the
                    // cap return -1 without trap.
                    let prev = core::arch::wasm32::memory_grow(0, n as usize);
                    return Ok(RunResult {
                        status: RunStatus::Completed,
                        output: Some((prev as i32).to_le_bytes().to_vec()),
                    });
                }
            }
            if data.as_slice() == b"loop" {
                // Infinite loop — Slice AB T55 exercises cooperative yield via
                // the host-installed `epoch_deadline_async_yield_and_update` +
                // OS-thread ticker. `core::hint::spin_loop` hints the CPU to
                // favor a low-power spin, not required for correctness.
                loop {
                    core::hint::spin_loop();
                }
            }
        }
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(vec![0xAD, 0x11, 0xCE, 0x02]),
        })
    }
}

export!(MinimalAgent with_types_in crate);
