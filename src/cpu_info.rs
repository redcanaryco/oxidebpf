use slog::info;

use crate::{OxidebpfError, LOGGER};

pub fn online() -> Result<Vec<i32>, OxidebpfError> {
    let cpu_string = String::from_utf8(std::fs::read("/sys/devices/system/cpu/online").map_err(
        |e| {
            info!(
                LOGGER.0,
                "get_cpus(); could not read /sys/devices/system/cpu/online; error: {:?}", e
            );
            OxidebpfError::FileIOError
        },
    )?)
    .map_err(|e| {
        info!(
            LOGGER.0,
            "get_cpus(); utf8 string conversion error while getting cpus; error: {:?}", e
        );
        OxidebpfError::Utf8StringConversionError
    })?;
    process_cpu_string(cpu_string)
}

pub fn possible_count() -> Result<usize, OxidebpfError> {
    let cpu_string = std::fs::read_to_string("/sys/devices/system/cpu/possible").map_err(
        |e| {
            info!(
                LOGGER.0,
                "get_possible_cpu_count(); could not read /sys/devices/system/cpu/possible; error: {:?}", e
            );
            OxidebpfError::FileIOError
        },
    )?;

    todo!()
}

fn process_cpu_string(cpu_string: String) -> Result<Vec<i32>, OxidebpfError> {
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