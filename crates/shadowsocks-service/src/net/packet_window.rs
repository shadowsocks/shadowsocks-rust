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

impl PacketWindowFilter {
    /// Create an empty filter
    pub fn new() -> PacketWindowFilter {
        PacketWindowFilter {
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
            for i in current + 1..current + diff {
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
