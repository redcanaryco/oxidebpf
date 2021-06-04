fn kernel_str_to_u32(release: &str) -> u32 {
    let mut release = release.to_string();
    // The release information comes in the format "major.minor.patch-extra".
    // We must first strip the "extra".
    if let Some(extra_idx) = release.find(|c: char| !(c.is_digit(10) || c == '.')) {
        release.replace_range(extra_idx.., "");
    }
    let mut split = release.split('.').flat_map(str::parse);
    (split.next().unwrap_or(0) << 16) + (split.next().unwrap_or(0) << 8) + split.next().unwrap_or(0)
}

/// Packs the kernel version into an u32
pub(crate) fn get_kernel_version() -> u32 {
    let utsname = nix::sys::utsname::uname();
    let mut release = utsname.release();
    kernel_str_to_u32(release)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version_parsing() {
        assert_eq!(kernel_str_to_u32("4.4.1"), 0x040401);
        assert_eq!(kernel_str_to_u32("4.4"), 0x040400);
        assert_eq!(kernel_str_to_u32("5.0.0-1234"), 0x050000);
    }
}
