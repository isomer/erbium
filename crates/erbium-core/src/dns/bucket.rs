/*   Copyright 2023 Perry Lorier
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Token Bucket implementation
 */

/* The token bucket holds a timestamp of when the bucket last had 0 tokens remaining in it.
 * The current contents of the bucket can be calculated by taking how long ago that was, and
 * calculating how many tokens would have been deposited in the bucket since then.  Updating
 * the bucket to deplete some tokens is handled similarly.
 */

type TokenCount = u32;
pub type RealTimeClock = std::time::SystemTime;

pub trait Clock: Send + Sync + 'static {
    fn now() -> u32;
}

impl Clock for RealTimeClock {
    fn now() -> u32 {
        RealTimeClock::now()
            .duration_since(RealTimeClock::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }
}

pub struct GenericTokenBucket(TokenCount);

impl GenericTokenBucket {
    const MAX_TOKENS: u32 = 100;
    const TOKENS_PER_SECOND: u32 = 2;

    pub const fn new() -> Self {
        Self(0)
    }

    // If the bucket is currently "over full", then cap it at the maximum fullness.
    fn get_tokens_with_time(&self, now: u32) -> TokenCount {
        std::cmp::max(self.0, now - Self::MAX_TOKENS / Self::TOKENS_PER_SECOND)
    }

    fn get_tokens<T: Clock>(&mut self) -> TokenCount {
        self.get_tokens_with_time(T::now())
    }

    pub fn check<T: Clock>(&self, tokens: u32) -> bool {
        let now = T::now();
        let cur_tokens = self.get_tokens_with_time(now);
        let avail_tokens = (now as i64 - cur_tokens as i64) * (Self::TOKENS_PER_SECOND as i64);
        /*
                println!(
                    "cur_tokens={} now={} (now-cur_tokens)={} tokens_requested={} tokens_avail={}",
                    cur_tokens,
                    now,
                    now as i64 - cur_tokens as i64,
                    tokens,
                    avail_tokens
                );
        */
        tokens as i64 <= avail_tokens
    }

    // Remove some tokens
    pub fn deplete<T: Clock>(&mut self, tokens: u32) {
        self.0 = self.get_tokens::<T>()
            + (tokens + Self::TOKENS_PER_SECOND - 1) / Self::TOKENS_PER_SECOND;
    }

    // Add some tokens (independent of the passage of time)
    #[allow(dead_code)]
    pub fn refill<T: Clock>(&mut self, tokens: u32) {
        self.0 = self.get_tokens::<T>()
            - (tokens + Self::TOKENS_PER_SECOND - 1) / Self::TOKENS_PER_SECOND;
    }

    // Empty a bucket, ie: make the bucket has no available tokens.
    #[allow(dead_code)]
    pub fn empty<T: Clock>(&mut self) {
        self.0 = T::now();
    }
}

impl Default for GenericTokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

#[test]
fn test_tokens() {
    let mut bucket = GenericTokenBucket::new();
    bucket.empty::<RealTimeClock>();
    bucket.refill::<RealTimeClock>(20);
    assert_eq!(bucket.check::<RealTimeClock>(10), true);
    bucket.deplete::<RealTimeClock>(40);
    assert_eq!(bucket.check::<RealTimeClock>(10), false);
}
