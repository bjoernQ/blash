use std::{
    borrow::{Borrow, Cow},
    io::{self, BufReader, Write},
    thread::sleep,
    time::{Duration, Instant},
};

use addr2line::{
    fallible_iterator::FallibleIterator,
    gimli::{BaseAddresses, DebugFrame, UninitializedUnwindContext, UnwindSection},
    object::{File, Object, ObjectSection},
    Context,
};
use byteorder::ReadBytesExt;
use clap::{App, Arg};
use env_logger::Env;
use probe_rs::{Core, Error, MemoryInterface, Probe};
use probe_rs_rtt::ScanRegion;

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
        .version("1.0.3")
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
        .arg(Arg::with_name("rtt").long("rtt").required(false))
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

    let memory_map = session.target().memory_map.clone();

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

    let canceled = std::sync::Arc::new(std::sync::Mutex::new(false));

    let canceled_clone = canceled.clone();
    ctrlc::set_handler(move || {
        *canceled_clone.lock().unwrap() = true;
    })
    .expect("Error setting Ctrl-C handler");

    if matches.is_present("rtt") {
        let elf_data = std::fs::read(file)?;
        let elf_file = goblin::elf::Elf::parse(&elf_data)?;

        let mut rtt_address: Option<u32> = None;
        let mut bt_trigger: Option<u32> = None;

        for sym in elf_file.syms.iter() {
            if sym.st_name != 0 {
                let name = sym.st_name;
                let name = elf_file.strtab.get_at(name).unwrap();
                if name == "_SEGGER_RTT" {
                    rtt_address = Some(sym.st_value as u32);
                }
                if name == "_BLASH_BACKTRACE_TRIGGER" {
                    bt_trigger = Some(sym.st_value as u32);
                }
            }

            if rtt_address.is_some() && bt_trigger.is_some() {
                break;
            }
        }

        sleep(Duration::from_millis(500));
        let scan_region = ScanRegion::Exact(rtt_address.ok_or("No RTT block found")?);
        let mut rtt = probe_rs_rtt::Rtt::attach_region(&mut core, &memory_map, &scan_region)?;

        let channel = rtt.up_channels().iter().next().unwrap();
        let mut buf = [0u8; 1024];

        loop {
            sleep(Duration::from_millis(10));

            // halting the core shouldn't be necessary
            // but sometimes we read garbage without
            let read = channel.read(&mut core, &mut buf)?;

            if read > 0 {
                let to_print = String::from_utf8_lossy(&buf[..read]);
                print!("{}", to_print);
                io::stdout().flush().ok();
            }

            if *canceled.lock().unwrap() {
                println!("\n\nBacktrace on break");
                backtrace(elf_data, None, None, core);
                break;
            }

            if let Some(bt_trigger_address) = bt_trigger {
                let mut data = [0u32; 3];
                core.read_32(bt_trigger_address, &mut data[..])?;
                if data[0] != 0 {
                    println!("\n\nBacktrace");
                    if data[1] != 0 {
                        backtrace(elf_data, Some(data[1]), Some(data[2]), core);
                    } else {
                        backtrace(elf_data, None, None, core);
                    }
                    break;
                }
            }
        }

        return Ok(());
    }

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

    let mut br = BufReader::new(port);
    loop {
        if *canceled.lock().unwrap() {
            break;
        }

        let x = br.read_u8();
        match x {
            Ok(x) => {
                print!("{}", x as char);
                io::stdout().flush().ok();
            }
            Err(_) => {}
        }
    }

    Ok(())
}

fn backtrace(elf_data: Vec<u8>, mepc: Option<u32>, exception_sp: Option<u32>, mut core: Core) {
    core.halt(Duration::from_millis(100)).unwrap();
    let regs = core.registers();
    let pc = regs.program_counter();
    let sp = regs.stack_pointer();

    let mut pc = core.read_core_reg(pc).unwrap();
    let mut sp = core.read_core_reg(sp).unwrap();

    let elf = File::parse(&elf_data[..]).unwrap();
    let bytes = elf
        .section_by_name(".debug_frame")
        .map(|section| section.data())
        .transpose()
        .unwrap()
        .unwrap();

    let mut debug_frame = addr2line::gimli::DebugFrame::new(bytes, addr2line::gimli::LittleEndian);
    debug_frame.set_address_size(32);

    let context = Context::new(&elf).unwrap();

    if let Some(mepc) = mepc {
        // backtrace from the exception's origin
        pc = mepc;
        sp = exception_sp.unwrap();
    }

    // This context is reusable, which cuts down on heap allocations.
    let mut ctx = UninitializedUnwindContext::new();
    let bases = BaseAddresses::default();

    loop {
        let (new_pc, new_sp) =
            backtrace_step(&context, &debug_frame, &mut core, pc, sp, &mut ctx, &bases);
        pc = new_pc;
        sp = new_sp;

        if pc < 0x23000000 {
            break;
        }
    }
}

fn backtrace_step<T, T2>(
    context: &Context<T>,
    debug_frame: &DebugFrame<T2>,
    core: &mut Core,
    pc: u32,
    sp: u32,
    unwind_context: &mut UninitializedUnwindContext<T2>,
    bases: &BaseAddresses,
) -> (u32, u32)
where
    T: addr2line::gimli::Reader,
    T2: addr2line::gimli::Reader,
{
    let address = pc as u64;
    let r = context.find_frames(address).unwrap();

    for x in r.iterator() {
        let x = x.unwrap();

        let loc = x.location.unwrap();
        let file = loc.file.unwrap();
        let line = loc.line.unwrap();

        let func = x.function.unwrap();
        let name = func.raw_name().unwrap();
        let language = func.language;

        let function_name = addr2line::demangle_auto(Cow::from(name), language);
        let func_name: &str = function_name.borrow();

        println!("{} {}:{}", func_name, file, line);
    }

    let unwind_info = debug_frame.unwind_info_for_address(
        bases,
        unwind_context,
        address,
        DebugFrame::cie_from_offset,
    );

    match unwind_info {
        Ok(unwind_info) => {
            let offset = match unwind_info.cfa() {
                addr2line::gimli::CfaRule::RegisterAndOffset {
                    register: _,
                    offset,
                } => offset,
                addr2line::gimli::CfaRule::Expression(_) => panic!("Cannot unwind on expression"),
            };

            let new_sp = sp + *offset as u32;

            let mut mem = [0; 2];
            core.read_32(new_sp - 8, &mut mem[..]).unwrap();

            // now mem[1] is the return address
            (mem[1], new_sp)
        }
        Err(_) => {
            println!(
                "No more unwind info found. Consider compiling the target with `-Z build-std=core`"
            );
            (0, 0)
        }
    }
}

static LOADER: &[u8; 29264] = include_bytes!("../bin/eflash_loader_40m.bin");
