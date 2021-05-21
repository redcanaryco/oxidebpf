/// Packs the kernel version into an u32
pub fn get_kernel_version() -> u32 {
    let utsname = nix::sys::utsname::uname();
    let mut release = utsname.release().to_string();
    // The release information comes in the format "major.minor.patch-extra".
    // We must first strip the "extra".
    if let Some(extra_idx) = release.find(|c: char| !(c.is_digit(10) || c == '.')) {
        release.replace_range(extra_idx.., "");
    }
    let mut split = release.split('.').flat_map(str::parse);
    (split.next().unwrap_or(0) << 16)
        + (split.next().unwrap_or(0) << 8)
        + split.next().unwrap_or(0)
}
