// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

const NOBODY: libc::gid_t = 65534;

pub fn drop_privileges() -> std::io::Result<()> {

    unsafe {
        if libc::setgid(NOBODY) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid(NOBODY as libc::uid_t) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
