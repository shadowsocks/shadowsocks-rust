// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.

//! Packet window
//!
//! https://github.com/WireGuard/wireguard-go/blob/master/replay/replay.go

const BLOCK_BIT_LOG: u64 = 6; // 1<<6 == 64 bits
const BLOCK_BITS: u64 = 1 << BLOCK_BIT_LOG; // must be power of 2
const RING_BLOCKS: u64 = 1 << 7; // must be power of 2
const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS;
const BLOCK_MASK: u64 = RING_BLOCKS - 1;
const BIT_MASK: u64 = BLOCK_BITS - 1;

/// Packet window for checking `packet_id` is in the sliding window
#[derive(Debug, Clone)]
pub struct PacketWindowFilter {
    last_packet_id: u64,
    packet_ring: [u64; RING_BLOCKS as usize],
}

impl Default for PacketWindowFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketWindowFilter {
    /// Create an empty filter
    pub fn new() -> Self {
        Self {
            last_packet_id: 0,
            packet_ring: [0u64; RING_BLOCKS as usize],
        }
    }

    /// Reset filter to the initial state
    pub fn reset(&mut self) {
        self.last_packet_id = 0;
        self.packet_ring[0] = 0;
    }

    /// Check and remember the `packet_id`
    ///
    /// Overlimit `packet_id >= limit` are always rejected
    pub fn validate_packet_id(&mut self, packet_id: u64, limit: u64) -> bool {
        if packet_id >= limit {
            return false;
        }

        let mut index_block = packet_id >> BLOCK_BIT_LOG;
        if packet_id > self.last_packet_id {
            // Move the window forward

            let current = self.last_packet_id >> BLOCK_BIT_LOG;
            let mut diff = index_block - current;
            if diff > RING_BLOCKS {
                // Clear the whole filter
                diff = RING_BLOCKS;
            }
            for d in 1..=diff {
                let i = current + d;
                self.packet_ring[(i & BLOCK_MASK) as usize] = 0;
            }
            self.last_packet_id = packet_id;
        } else if self.last_packet_id - packet_id > WINDOW_SIZE {
            // Behind the current window
            return false;
        }

        // Check and set bit
        index_block &= BLOCK_MASK;
        let index_bit = packet_id & BIT_MASK;
        let old = self.packet_ring[index_block as usize];
        let new = old | (1 << index_bit);
        self.packet_ring[index_block as usize] = new;
        old != new
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::cell::RefCell;

    #[test]
    fn test_packet_window() {
        const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1u64 << 13);

        let filter = RefCell::new(PacketWindowFilter::new());

        let test_number = RefCell::new(0);
        #[allow(non_snake_case)]
        let T = |n: u64, expected: bool| {
            *(test_number.borrow_mut()) += 1;
            if filter.borrow_mut().validate_packet_id(n, REJECT_AFTER_MESSAGES) != expected {
                panic!("Test {} failed, {} {}", test_number.borrow(), n, expected);
            }
        };

        const T_LIM: u64 = WINDOW_SIZE + 1;

        T(0, true); // 1
        T(1, true); // 2
        T(1, false); // 3
        T(9, true); // 4
        T(8, true); // 5
        T(7, true); // 6
        T(7, false); // 7
        T(T_LIM, true); // 8
        T(T_LIM - 1, true); // 9
        T(T_LIM - 1, false); // 10
        T(T_LIM - 2, true); // 11
        T(2, true); // 12
        T(2, false); // 13
        T(T_LIM + 16, true); // 14
        T(3, false); // 15
        T(T_LIM + 16, false); // 16
        T(T_LIM * 4, true); // 17
        T(T_LIM * 4 - (T_LIM - 1), true); // 18
        T(10, false); // 19
        T(T_LIM * 4 - T_LIM, false); // 20
        T(T_LIM * 4 - (T_LIM + 1), false); // 21
        T(T_LIM * 4 - (T_LIM - 2), true); // 22
        T(T_LIM * 4 + 1 - T_LIM, false); // 23
        T(0, false); // 24
        T(REJECT_AFTER_MESSAGES, false); // 25
        T(REJECT_AFTER_MESSAGES - 1, true); // 26
        T(REJECT_AFTER_MESSAGES, false); // 27
        T(REJECT_AFTER_MESSAGES - 1, false); // 28
        T(REJECT_AFTER_MESSAGES - 2, true); // 29
        T(REJECT_AFTER_MESSAGES + 1, false); // 30
        T(REJECT_AFTER_MESSAGES + 2, false); // 31
        T(REJECT_AFTER_MESSAGES - 2, false); // 32
        T(REJECT_AFTER_MESSAGES - 3, true); // 33
        T(0, false); // 34

        println!("Bulk test 1");
        filter.borrow_mut().reset();
        *(test_number.borrow_mut()) = 0;
        for i in 1..=WINDOW_SIZE {
            T(i, true);
        }
        T(0, true);
        T(0, false);

        println!("Bulk test 2");
        filter.borrow_mut().reset();
        *(test_number.borrow_mut()) = 0;
        for i in 2..=WINDOW_SIZE + 1 {
            T(i, true);
        }
        T(1, true);
        T(0, false);

        println!("Bulk test 3");
        filter.borrow_mut().reset();
        *(test_number.borrow_mut()) = 0;
        for i in (1..=WINDOW_SIZE + 1).rev() {
            T(i, true);
        }

        println!("Bulk test 4");
        filter.borrow_mut().reset();
        *(test_number.borrow_mut()) = 0;
        for i in (2..=WINDOW_SIZE + 2).rev() {
            T(i, true);
        }
        T(0, false);

        println!("Bulk test 5");
        filter.borrow_mut().reset();
        *(test_number.borrow_mut()) = 0;
        for i in (1..=WINDOW_SIZE).rev() {
            T(i, true);
        }
        T(WINDOW_SIZE + 1, true);
        T(0, false);

        println!("Bulk test 6");
        filter.borrow_mut().reset();
        *(test_number.borrow_mut()) = 0;
        for i in (1..=WINDOW_SIZE).rev() {
            T(i, true);
        }
        T(0, true);
        T(WINDOW_SIZE + 1, true);
    }
}
