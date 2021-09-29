use std::{
    io::BufReader,
    thread::sleep,
    time::{Duration, Instant},
};

use byteorder::ReadBytesExt;
use clap::{App, Arg};
use env_logger::Env;
use probe_rs::{Error, MemoryInterface, Probe};

use crate::blflash::{Boot2Opt, Connection, FlashOpt};

mod blflash;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("blash=trace"))
        .format_timestamp(None)
        .init();

    match run() {
        Ok(_) => (),
        Err(err) => {
            log::error!("Error: {}", err);
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("blash")
        .version("1.0.2")
        .author("Bjoern Quentin")
        .about("Zero Touch BL602 Flasher")
        .arg(
            Arg::with_name("port")
                .long("port")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("baud")
                .long("baud")
                .default_value("2000000")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("monitor-baud")
                .long("monitor-baud")
                .default_value("115200")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("no-monitor")
                .long("no-monitor")
                .required(false),
        )
        .arg(Arg::with_name("file").last(true).required(true))
        .get_matches();

    let ports = serialport::available_ports().expect("No ports found!");

    let port_from_env = std::env::var("BLASH_PORT").ok();
    let port = if ports.len() == 1 && !matches.is_present("port") && port_from_env.is_none() {
        ports[0].port_name.to_string()
    } else {
        match matches.value_of("port") {
            Some(port) => port.to_string(),
            None => {
                if port_from_env.is_some() {
                    port_from_env.unwrap()
                } else {
                    return Err("No port specified or found".into());
                }
            }
        }
    };

    let baud = matches.value_of("baud").unwrap().parse().unwrap();
    let monitor_baud = matches.value_of("monitor-baud").unwrap().parse().unwrap();

    let no_monitor = matches.is_present("no-monitor");

    let file = matches.value_of("file").unwrap();

    // Get a list of all available debug probes.
    let probes = Probe::list_all();

    // Use the first probe found.
    let probe = probes
        .get(0)
        .ok_or(Error::UnableToOpenProbe("No probe was found"))?
        .open()?;

    let mut session = probe.attach("Riscv")?;

    // Select a core.
    let mut core = session.core(0)?;

    let regs = core.registers();
    let pc = regs.program_counter();

    // Halt the attached core.
    core.halt(std::time::Duration::from_millis(10))?;

    core.reset().ok();
    let t1 = core
        .registers()
        .registers()
        .find(|r| r.name() == "x6")
        .unwrap();
    // set MSTATUS = 0x80000000
    // 0:   30001373                csrrw   t1,mstatus,zero
    core.write_8(0x22010000, &[0x73, 0x13, 0x00, 0x30])?;
    core.write_core_reg(t1.into(), 0x80000000)?;
    core.write_core_reg(pc.into(), 0x22010000)?;
    core.step()?;

    let mut eflash_loader = [0u32; 29072 / 4];
    let loader = &LOADER[(176 + 16)..];
    for (index, word) in eflash_loader.iter_mut().enumerate() {
        let index = index * 4;
        *word = loader[index] as u32
            + ((loader[index + 1] as u32) << 8)
            + ((loader[index + 2] as u32) << 16)
            + ((loader[index + 3] as u32) << 24);
    }

    log::trace!("Downloading eflasher");
    let t1 = Instant::now();
    core.write_32(0x22010000, &eflash_loader).unwrap(); // skip boot header + segment header
    let t2 = Instant::now();
    log::trace!("Downloaded in {:?}", (t2 - t1));

    // RESET THE CORE AND RUN
    core.reset().ok(); // this errors but we ignore it!
    core.write_core_reg(pc.into(), 0x22010000)?;
    core.run()?;
    sleep(Duration::from_millis(100));

    let opt = FlashOpt {
        conn: Connection {
            port: port.clone(),
            baud_rate: baud,
        },
        image: file.into(),
        force: false,
        boot: Boot2Opt {
            partition_cfg: None,
            boot_header_cfg: None,
            dtb: None,
            without_boot2: false,
        },
    };
    blflash::flash(opt).unwrap();

    // done flashing ...

    // RESET
    core.halt(std::time::Duration::from_millis(100))?;
    core.reset().ok(); // this errors but we ignore it!
    core.write_core_reg(pc.into(), 0x21000000)?;
    core.run()?;

    if no_monitor {
        return Ok(());
    }

    // connect serial port
    log::info!("start serial monitor");
    let mut port = serialport::new(port, monitor_baud)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .flow_control(serialport::FlowControl::None)
        .open()?;
    port.set_timeout(Duration::from_millis(10)).unwrap();

    let canceled = std::sync::Arc::new(std::sync::Mutex::new(false));

    let canceled_clone = canceled.clone();
    ctrlc::set_handler(move || {
        *canceled_clone.lock().unwrap() = true;
    })
    .expect("Error setting Ctrl-C handler");

    let mut br = BufReader::new(port);
    loop {
        if *canceled.lock().unwrap() {
            break;
        }

        let x = br.read_u8();
        match x {
            Ok(x) => print!("{}", x as char),
            Err(_) => {}
        }
    }

    Ok(())
}

static LOADER: &[u8; 29264] = include_bytes!("../bin/eflash_loader_40m.bin");
