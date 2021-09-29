use crate::blflash::Error;
use crate::blflash::{connection::Connection, elf::RomSegment};
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use serialport::SerialPort;
use sha2::{Digest, Sha256};
use std::thread::sleep;
use std::{
    io::{Cursor, Read},
    time::{Duration, Instant},
};

fn get_bar(len: u64) -> ProgressBar {
    let bar = ProgressBar::new(len);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("  {wide_bar} {bytes}/{total_bytes} {bytes_per_sec} {eta}  ")
            .progress_chars("#>-"),
    );
    bar
}

pub struct Flasher {
    connection: Connection,
    boot_info: protocol::BootInfo,
}

impl Flasher {
    pub fn connect(serial: Box<dyn SerialPort>, initial_speed: u32) -> Result<Self, Error> {
        let mut flasher = Flasher {
            connection: Connection::new(serial),
            boot_info: protocol::BootInfo::default(),
        };
        flasher.connection.set_baud(initial_speed)?;
        flasher.start_connection()?;
        flasher.connection.set_timeout(Duration::from_secs(10))?;

        Ok(flasher)
    }

    pub fn boot_info(&self) -> &protocol::BootInfo {
        &self.boot_info
    }

    pub fn load_segments<'a>(
        &'a mut self,
        force: bool,
        segments: impl Iterator<Item = RomSegment<'a>>,
    ) -> Result<(), Error> {
        //        self.load_eflash_loader()?;

        for segment in segments {
            let local_hash = Sha256::digest(&segment.data[0..segment.size() as usize]);

            // skip segment if the contents are matched
            if !force {
                let sha256 = self
                    .eflash_loader()
                    .sha256_read(segment.addr, segment.size())?;
                if sha256 == &local_hash[..] {
                    log::info!(
                        "Skip segment addr: {:x} size: {} sha256 matches",
                        segment.addr,
                        segment.size()
                    );
                    continue;
                }
            }

            log::info!(
                "Erase flash addr: {:x} size: {}",
                segment.addr,
                segment.size()
            );
            self.eflash_loader()
                .flash_erase(segment.addr, segment.addr + segment.size())?;

            let mut reader = Cursor::new(&segment.data);
            let mut cur = segment.addr;

            let start = Instant::now();
            log::info!("Program flash... {:x}", local_hash);
            let pb = get_bar(segment.size() as u64);
            loop {
                let size = self.eflash_loader().flash_program(cur, &mut reader)?;
                // log::trace!("program {:x} {:x}", cur, size);
                cur += size;
                pb.inc(size as u64);
                if size == 0 {
                    break;
                }
            }
            pb.finish_and_clear();
            let elapsed = start.elapsed();
            log::info!(
                "Program done {:?} {}/s",
                elapsed,
                HumanBytes((segment.size() as f64 / elapsed.as_millis() as f64 * 1000.0) as u64)
            );

            let sha256 = self
                .eflash_loader()
                .sha256_read(segment.addr, segment.size())?;
            if sha256 != &local_hash[..] {
                log::warn!(
                    "sha256 not match: {} != {}",
                    hex::encode(sha256),
                    hex::encode(local_hash)
                );
            }
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), Error> {
        Ok(self.connection.reset()?)
    }

    fn eflash_loader(&mut self) -> EflashLoader {
        EflashLoader(&mut self.connection)
    }

    fn handshake(&mut self) -> Result<(), Error> {
        self.connection
            .with_timeout(Duration::from_millis(200), |connection| {
                let len = connection.calc_duration_length(Duration::from_millis(5));
                log::trace!("5ms send count {}", len);
                let data: Vec<u8> = std::iter::repeat(0x55u8).take(len).collect();
                let start = Instant::now();
                connection.write_all(&data)?;
                connection.flush()?;
                log::trace!("handshake sent elapsed {:?}", start.elapsed());
                sleep(Duration::from_millis(200));

                for _ in 0..5 {
                    if connection.read_response(0).is_ok() {
                        return Ok(());
                    }
                }

                Err(Error::Timeout)
            })
    }

    fn start_connection(&mut self) -> Result<(), Error> {
        log::info!("Start connection...");
        self.connection.reset_to_flash()?;
        for i in 1..=10 {
            self.connection.flush()?;
            if self.handshake().is_ok() {
                log::info!("Connection Succeed");
                return Ok(());
            } else {
                log::debug!("Retry {}", i);
            }
        }
        Err(Error::ConnectionFailed)
    }
}

pub struct EflashLoader<'a>(&'a mut Connection);

impl<'a> EflashLoader<'a> {
    pub fn sha256_read(&mut self, addr: u32, len: u32) -> Result<[u8; 32], Error> {
        Ok(self.0.command(protocol::Sha256Read { addr, len })?.digest)
    }

    pub fn flash_program(&mut self, addr: u32, reader: &mut impl Read) -> Result<u32, Error> {
        let mut data = vec![0u8; 4000];
        let size = reader.read(&mut data)?;
        if size == 0 {
            return Ok(0);
        }
        data.truncate(size);

        self.0.command(protocol::FlashProgram { addr, data })?;

        Ok(size as u32)
    }

    pub fn flash_erase(&mut self, start: u32, end: u32) -> Result<(), Error> {
        self.0.command(protocol::FlashErase { start, end })?;

        Ok(())
    }
}

mod protocol {
    use crate::blflash::connection::{Command, Response};
    use deku::prelude::*;

    #[derive(Debug, DekuWrite, Default)]
    pub struct CheckImage {}
    impl_command!(0x19, CheckImage);

    #[derive(Debug, DekuWrite, Default)]
    pub struct RunImage {}
    impl_command!(0x1a, RunImage);

    #[derive(Debug, DekuWrite, Default)]
    pub struct BootInfoReq {}
    #[derive(Debug, DekuRead, Default)]
    pub struct BootInfo {
        pub len: u16,
        pub bootrom_version: u32,
        pub otp_info: [u8; 16],
    }
    impl_command!(0x10, BootInfoReq, BootInfo);

    #[derive(Debug, DekuWrite, Default)]
    pub struct LoadBootHeader {
        // length must be 176
        pub boot_header: Vec<u8>,
    }
    impl_command!(0x11, LoadBootHeader);

    #[derive(Debug, DekuWrite, Default)]
    pub struct LoadSegmentHeaderReq {
        // length must be 16
        pub segment_header: Vec<u8>,
    }
    #[derive(Debug, DekuRead)]
    pub struct LoadSegmentHeader {
        pub len: u16,
        #[deku(count = "len")]
        pub data: Vec<u8>,
    }
    impl_command!(0x17, LoadSegmentHeaderReq, LoadSegmentHeader);

    #[derive(Debug, DekuWrite, Default)]
    pub struct LoadSegmentData {
        pub segment_data: Vec<u8>,
    }
    impl_command!(0x18, LoadSegmentData);

    #[derive(Debug, DekuWrite, Default)]
    pub struct FlashErase {
        pub start: u32,
        pub end: u32,
    }
    impl_command!(0x30, FlashErase);

    #[derive(Debug, DekuWrite, Default)]
    pub struct FlashProgram {
        pub addr: u32,
        pub data: Vec<u8>,
    }
    impl_command!(0x31, FlashProgram);

    #[derive(Debug, DekuWrite, Default)]
    pub struct FlashRead {
        pub addr: u32,
        pub size: u32,
    }
    #[derive(Debug, DekuRead)]
    pub struct FlashReadResp {
        pub len: u16,
        #[deku(count = "len")]
        pub data: Vec<u8>,
    }
    impl_command!(0x32, FlashRead, FlashReadResp);

    #[derive(Debug, DekuWrite, Default)]
    pub struct Sha256Read {
        pub addr: u32,
        pub len: u32,
    }

    #[derive(Debug, DekuRead)]
    #[deku(magic = b"\x20\x00")]
    pub struct Sha256ReadResp {
        pub digest: [u8; 32],
    }
    impl_command!(0x3d, Sha256Read, Sha256ReadResp);
}
