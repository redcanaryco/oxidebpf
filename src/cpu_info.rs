use slog::info;

use crate::{OxidebpfError, LOGGER};

pub fn online() -> Result<Vec<i32>, OxidebpfError> {
    let cpu_string = std::fs::read_to_string("/sys/devices/system/cpu/online").map_err(|e| {
        info!(
            LOGGER.0,
            "cpu_info::online(); could not read /sys/devices/system/cpu/online; error: {:?}", e
        );
        OxidebpfError::FileIOError
    })?;

    process_cpu_string(&cpu_string)
}

pub fn max_possible_index() -> Result<usize, OxidebpfError> {
    let cpu_string = std::fs::read_to_string("/sys/devices/system/cpu/possible").map_err(
        |e| {
            info!(
                LOGGER.0,
                "cpu_info::max_possible_index(); could not read /sys/devices/system/cpu/possible; error: {:?}", e
            );
            OxidebpfError::FileIOError
        },
    )?;

    max_index(&cpu_string)
}

fn max_index(cpu_string: &str) -> Result<usize, OxidebpfError> {
    let last = cpu_string
        .split(',')
        .last()
        .ok_or(OxidebpfError::CpuOnlineFormatError)?;

    let last_index = match last.split_once('-') {
        None => last,
        Some((_, b)) => b,
    };

    last_index
        .parse()
        .map_err(|_| OxidebpfError::CpuOnlineFormatError)
}

fn process_cpu_string(cpu_string: &str) -> Result<Vec<i32>, OxidebpfError> {
    let mut cpus = vec![];

    for sublist in cpu_string.trim().split(',') {
        if sublist.contains('-') {
            let pair: Vec<&str> = sublist.split('-').collect();
            if pair.len() != 2 {
                info!(
                    LOGGER.0,
                    "process_cpu_string(); cpu online formatting error: {}", cpu_string
                );
                return Err(OxidebpfError::CpuOnlineFormatError);
            }

            // we checked the length above so indexing is OK
            let from: i32 = pair[0].parse().map_err(|e| {
                info!(
                    LOGGER.0,
                    "process_cpu_string(); cpu online i32 parse error; pair: {:?}; error: {:?}",
                    pair,
                    e
                );
                OxidebpfError::CpuOnlineFormatError
            })?;
            let to: i32 = pair[1].parse().map_err(|e| {
                info!(
                    LOGGER.0,
                    "process_cpu_string(); cpu online i32 parse error; pair: {:?}; error: {:?}",
                    pair,
                    e
                );
                OxidebpfError::CpuOnlineFormatError
            })?;

            cpus.extend(from..=to)
        } else {
            cpus.push(sublist.trim().parse().map_err(|e| {
                info!(
                    LOGGER.0,
                    "process_cpu_string(); sublist number parsing error; sublist: {:?}; error: {:?}", sublist, e
                );
                OxidebpfError::NumberParserError
            })?);
        }
    }

    Ok(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_range() {
        let result = max_index("0-127").expect("did not parse cpu_string");
        assert_eq!(result, 127);
    }

    #[test]
    fn single_number() {
        let result = max_index("4").expect("did not parse cpu_string");
        assert_eq!(result, 4);
    }

    #[test]
    fn combination() {
        let result = max_index("0,3-5,8").expect("did not parse cpu_string");
        assert_eq!(result, 8);
    }

    #[test]
    fn test_cpu_formatter() {
        assert_eq!(vec![0], process_cpu_string("0").unwrap());
        assert_eq!(vec![0, 1, 2], process_cpu_string("0-2").unwrap());
        assert_eq!(vec![0, 3, 4, 5, 8], process_cpu_string("0,3-5,8").unwrap());
    }
}
