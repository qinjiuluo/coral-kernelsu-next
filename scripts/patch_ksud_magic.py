#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ksud_magic 私有化补丁: init_event.rs 的 TEMP_DIR tmpfs 挂载后设 PRIVATE."""
import sys

KSUN = sys.argv[1] if len(sys.argv) > 1 else 'ksun'
NL = chr(10)

p = f'{KSUN}/userspace/ksud_magic/src/init_event.rs'
s = open(p, encoding='utf-8').read()

old = (
    '        if let Err(e) = mount(KSU_MOUNT_SOURCE, TEMP_DIR, "tmpfs", MountFlags::empty(), "") {'
    + NL
    + '            warn!("do temp dir mount failed: {e}");'
    + NL
    + '        }'
    + NL
)
assert s.count(old) == 1, f'tmpfs block count={s.count(old)}'
new = (
    '        if let Err(e) = mount(KSU_MOUNT_SOURCE, TEMP_DIR, "tmpfs", MountFlags::empty(), "") {'
    + NL
    + '            warn!("do temp dir mount failed: {e}");'
    + NL
    + '        } else {'
    + NL
    + '            // stealth: keep ksu tmpfs out of shared peer groups (mount gap detection)'
    + NL
    + '            unsafe {'
    + NL
    + '                let _ = libc::mount(std::ptr::null(), TEMP_DIR.as_ptr() as *const i8,'
    + ' std::ptr::null(), libc::MS_PRIVATE as usize, std::ptr::null());'
    + NL
    + '            }'
    + NL
    + '        }'
    + NL
)
s = s.replace(old, new, 1)

# 确保 import 有 mount_change / MountPropagationFlags
head = s.split('fn ')[0]
if 'mount_change' not in head:
    # 在 use 块补 import (找 rustix fs import 行)
    import re
    m = re.search(r'use rustix::\{[^;]*fs::\{([^}]*)\}[^;]*\};', head)
    if m and 'mount_change' not in m.group(1):
        s = s.replace(m.group(0),
                      m.group(0).replace('MountFlags,', 'MountFlags, mount_change, MountPropagationFlags,'), 1)
    elif 'use rustix::fs::' in head:
        s = s.replace('use rustix::fs::',
                      'use rustix::fs::{mount_change, MountPropagationFlags};\nuse rustix::fs::', 1)
    else:
        # 加全新 import
        s = s.replace('use crate::defs::',
                      'use rustix::fs::{mount_change, MountPropagationFlags};\nuse crate::defs::', 1)

open(p, 'w', encoding='utf-8', newline='').write(s)
print('ksud_magic patched: TEMP_DIR tmpfs PRIVATE')
