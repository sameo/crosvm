// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::ptr;
use std::time::Duration;

use libc::{self, CLOCK_MONOTONIC, TFD_CLOEXEC, timerfd_create, timerfd_settime};

use {Result, errno_result};

/// A safe wrapper around a Linux timerfd (man 2 timerfd_create).
pub struct TimerFd(File);

impl TimerFd {
    /// Creates a new timerfd.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new() -> Result<TimerFd> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }

        // Safe because we uniquely own the file descriptor.
        Ok(TimerFd(unsafe { File::from_raw_fd(ret) } ))
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        // Safe because we are zero-initializing a struct with only primitive member fields.
        let mut spec: libc::itimerspec = unsafe { mem::zeroed() };
        spec.it_value.tv_sec = dur.as_secs() as libc::time_t;
        spec.it_value.tv_nsec = dur.subsec_nanos() as libc::c_long;

        if let Some(int) = interval {
            spec.it_interval.tv_sec = int.as_secs() as libc::time_t;
            spec.it_interval.tv_nsec = int.subsec_nanos() as libc::c_long;
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_settime(self.as_raw_fd(), 0, &spec, ptr::null_mut()) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }

    /// Waits until the timer expires.  The return value represents the number of times the timer
    /// has expired since the last time `wait` was called.  If the timer has not yet expired once
    /// this call will block until it does.
    pub fn wait(&mut self) -> Result<u64> {
        let mut count = 0u64;

        // Safe because this will only modify |buf| and we check the return value.
        let ret = unsafe {
            libc::read(self.as_raw_fd(),
                       &mut count as *mut _ as *mut libc::c_void,
                       mem::size_of_val(&count))
        };
        if ret < 0 {
            return errno_result();
        }

        // The bytes in the buffer are guaranteed to be in native byte-order so we don't need to
        // use from_le or from_be.
        Ok(count)
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        // Safe because we are zero-initializing a struct with only primitive member fields.
        let spec: libc::itimerspec = unsafe { mem::zeroed() };

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_settime(self.as_raw_fd(),  0, &spec, ptr::null_mut()) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }
}

impl AsRawFd for TimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for TimerFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        TimerFd(File::from_raw_fd(fd))
    }
}

impl IntoRawFd for TimerFd {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    #[test]
    fn one_shot() {
        let mut tfd = TimerFd::new().expect("failed to create timerfd");

        let dur = Duration::from_millis(200);
        let now = Instant::now();
        tfd.reset(dur.clone(), None).expect("failed to arm timer");

        let count = tfd.wait().expect("unable to wait for timer");

        assert_eq!(count, 1);
        assert!(now.elapsed() >= dur);
    }

    #[test]
    fn repeating() {
        let mut tfd = TimerFd::new().expect("failed to create timerfd");

        let dur = Duration::from_millis(200);
        let interval = Duration::from_millis(100);
        tfd.reset(dur.clone(), Some(interval)).expect("failed to arm timer");

        sleep(dur * 3);

        let count = tfd.wait().expect("unable to wait for timer");
        assert!(count >= 5, "count = {}", count);
    }
}