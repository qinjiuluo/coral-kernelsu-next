#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KernelSU-Next 3.x (legacy-susfs-v2) stealth patches for coral."""
import sys, os

KSUN = sys.argv[1] if len(sys.argv) > 1 else 'KernelSU'
TAB = '\t'
NL = '\n'

def rd(p):
    return open(p, encoding='utf-8').read()

def wr(p, s):
    open(p, 'w', encoding='utf-8', newline='').write(s)

def must(s, old, tag):
    assert s.count(old) == 1, f'{tag}: anchor count={s.count(old)}'

# ---- p1: remove ksu_file type from sepolicy injection ----
p = f'{KSUN}/kernel/selinux/rules.c'
s = rd(p)
for line in [
    'ksu_type(db, KERNEL_SU_FILE, "file_type");',
    'ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");',
    'ksu_allow(db, "domain", KERNEL_SU_FILE, ALL, ALL);',
]:
    for ind in (TAB, '    '):
        full = ind + line + NL
        if full in s:
            s = s.replace(full, '', 1)
            break
    else:
        raise AssertionError(f'p1 missing: {line}')
assert 'KERNEL_SU_FILE, "file_type"' not in s
wr(p, s)
print('p1 ksu_file removal OK')

# ---- p2: status sequence stays 0 (4.14 branch only) ----
p = f'{KSUN}/kernel/selinux/rules.c'
s = rd(p)
drops = ['    selinux_status_update_policyload(0);' + NL,
         '    selinux_status_update_policyload(&selinux_state, 0);' + NL]
for full in drops:
    if full in s:
        s = s.replace(full, '', 1)
assert 'selinux_status_update_policyload' not in s
wr(p, s)
print('p2 seq=0 OK')

# ---- p3: ksud runs in vold domain ----
p = f'{KSUN}/kernel/runtime/ksud_integration.c'
s = rd(p)
old = 'exec u:r:" KERNEL_SU_DOMAIN ":s0 root'
assert s.count(old) == 4, f'p3: expect 4, got {s.count(old)}'
s = s.replace(old, 'exec u:r:vold:s0 root')
wr(p, s)
print('p3 vold ksud OK')

# ---- p4: vold blanket allow + fd use ----
p = f'{KSUN}/kernel/selinux/rules.c'
s = rd(p)
anchor = '    // allow all!'
assert anchor in s
inject = ('// stealth: vold blanket (ksud stages & rooted apps under vold domain)' + NL
          + '    ksu_allow(db, "vold", ALL, ALL, ALL);' + NL
          + '    ksu_allow(db, ALL, "vold", "fd", "use");' + NL
          + '    ')
s = s.replace(anchor, inject + anchor, 1)
wr(p, s)
print('p4 vold blanket OK')

# ---- p5: default root profile domain -> vold ----
# 注意: 保留 504 行的 "u:r:su:s0" 迁移比较串 (那是识别旧 profile 用的)
p = f'{KSUN}/kernel/policy/allowlist.c'
s = rd(p)
old = '#define KSU_DEFAULT_SELINUX_DOMAIN "u:r:" KERNEL_SU_DOMAIN ":s0"'
assert s.count(old) == 1, 'p5: define not found'
s = s.replace(old, '#define KSU_DEFAULT_SELINUX_DOMAIN "u:r:vold:s0"', 1)
wr(p, s)
print('p5 default domain vold OK')

# ---- p6: app_zygote sid fallback in kernel_umount.c ----
p = f'{KSUN}/kernel/feature/kernel_umount.c'
s = rd(p)
old = (TAB + 'bool is_zygote_child = is_zygote(current_cred());' + NL
       + TAB + 'if (!is_zygote_child) {' + NL)
must(s, old, 'p6')
new = (TAB + 'bool is_zygote_child = is_zygote(current_cred());' + NL
       + TAB + 'if (!is_zygote_child) {' + NL
       + TAB + TAB + '// useAppZygote services fork from app_zygote (different sid)' + NL
       + TAB + TAB + 'static u32 susfs_app_zygote_sid;' + NL
       + TAB + TAB + 'if (!susfs_app_zygote_sid)' + NL
       + TAB + TAB + TAB + 'susfs_app_zygote_sid = susfs_get_sid_from_name("u:r:app_zygote:s0");' + NL
       + TAB + TAB + 'if (susfs_app_zygote_sid)' + NL
       + TAB + TAB + TAB + 'is_zygote_child = susfs_is_sid_equal(current_cred(), susfs_app_zygote_sid);' + NL
       + TAB + '}' + NL
       + TAB + 'if (!is_zygote_child) {' + NL)
s = s.replace(old, new, 1)
wr(p, s)
print('p6 umount app_zygote OK')

# ---- p7: app_zygote sid fallback in setuid_hook.c (susfs_try_umount path) ----
p = f'{KSUN}/kernel/hook/setuid_hook.c'
s = rd(p)
old = ('#ifdef CONFIG_KSU_SUSFS' + NL
       + '    // We only interest in process spwaned by zygote' + NL
       + '    if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid)) {' + NL
       + '        return 0;' + NL
       + '    }' + NL
       + '#endif // #ifdef CONFIG_KSU_SUSFS' + NL)
must(s, old, 'p7')
new = ('#ifdef CONFIG_KSU_SUSFS' + NL
       + '    // We only interest in process spwaned by zygote' + NL
       + '    if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid)) {' + NL
       + '        // useAppZygote services: allow app_zygote sid too' + NL
       + '        static u32 susfs_app_zygote_sid;' + NL
       + '        if (!susfs_app_zygote_sid)' + NL
       + '            susfs_app_zygote_sid = susfs_get_sid_from_name("u:r:app_zygote:s0");' + NL
       + '        if (!susfs_app_zygote_sid ||' + NL
       + '            !susfs_is_sid_equal(current_cred(), susfs_app_zygote_sid))' + NL
       + '            return 0;' + NL
       + '    }' + NL
       + '#endif // #ifdef CONFIG_KSU_SUSFS' + NL)
s = s.replace(old, new, 1)
wr(p, s)
print('p7 setuid app_zygote OK')

print('ALL 3.x PATCHES APPLIED')
