// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use boringtun::device::drop_privileges::drop_privileges;
use boringtun::device::{DeviceConfig, DeviceHandle, DEFAULT_PROBE_REPLY_BYTES_PER_SEC};
use boringtun::noise::amnezia::{AmneziaConfig, AmneziaImitation, AmneziaImitationProtocol};
use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, Command};
use daemonize::{Daemonize, Outcome};
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use tracing::Level;

fn check_tun_name(v: &str) -> Result<String, String> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    {
        if boringtun::device::tun::parse_utun_name(v).is_ok() {
            Ok(v.to_owned())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(v.to_owned())
    }
}

fn main() {
    let matches = Command::new("boringtun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vlad Krasnov <vlad@cloudflare.com>")
        .args(&[
            Arg::new("INTERFACE_NAME")
                .required(true)
                .value_parser(check_tun_name)
                .help("The name of the created interface"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .action(ArgAction::SetTrue)
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .value_parser(PossibleValuesParser::new([
                    "error", "info", "debug", "trace",
                ]))
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .help("File descriptor for the user API")
                .default_value("-1"),
            Arg::new("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::new("log")
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .action(ArgAction::SetTrue)
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .action(ArgAction::SetTrue)
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .action(ArgAction::SetTrue)
                .help("Disable using multiple queues for the tunnel interface"),
            // Protocol imitation has no UAPI key: `awg showconf` drops keys it
            // does not know, so a value set over the UAPI would not survive a
            // round trip. It is therefore startup-only, and these are the only
            // way to reach it from the binary.
            // The value list comes from `AmneziaImitationProtocol::ALL`, not a
            // literal: a variant added to the enum without a name here would
            // otherwise be unreachable, and a name here without an enum arm used
            // to fall through a `_ =>` catch-all to "no imitation" — an operator
            // asking for camouflage and silently getting none.
            Arg::new("imitate-protocol")
                .long("imitate-protocol")
                .env("WG_IMITATE_PROTOCOL")
                .value_parser(PossibleValuesParser::new(
                    AmneziaImitationProtocol::ALL.map(|p| p.as_str()),
                ))
                .help("Protocol to imitate: shapes outbound cover traffic, and selects which probes the listen port answers")
                .default_value(AmneziaImitationProtocol::None.as_str()),
            Arg::new("imitate-domain")
                .long("imitate-domain")
                .env("WG_IMITATE_DOMAIN")
                .help("Hostname to use in imitated DNS/SIP/QUIC cover traffic (a random one is generated when omitted)"),
            // `value_parser` rather than a hand-rolled `.parse().expect(...)`:
            // clap then rejects a bad value inside `get_matches()`, which runs
            // *before* the daemonize fork. Parsed afterwards, a panic would land
            // in a child whose stderr is already /dev/null and whose log file
            // says "started successfully", leaving the operator with no clue
            // which flag was wrong.
            //
            // No `default_value`: the default is the library constant, and
            // restating it here as a string would be a second copy to drift.
            // Absence means "the library default", resolved below.
            Arg::new("probe-reply-rate")
                .long("probe-reply-rate")
                .env("WG_PROBE_REPLY_RATE")
                .value_parser(clap::value_parser!(u32))
                .help(format!(
                    "Aggregate ceiling, in bytes per second, on replies to unauthenticated probes; \
                     0 answers nothing [default: {} when --imitate-protocol is set, otherwise off]",
                    DEFAULT_PROBE_REPLY_BYTES_PER_SEC
                )),
        ])
        .get_matches();

    let background = !matches.get_flag("foreground");
    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = matches
        .get_one::<String>("uapi-fd")
        .unwrap()
        .parse()
        .expect("Invalid uapi-fd value");
    let tun_fd: isize = matches
        .get_one::<String>("tun-fd")
        .unwrap()
        .parse()
        .expect("Invalid tun-fd value");
    let mut tun_name = matches
        .get_one::<String>("INTERFACE_NAME")
        .unwrap()
        .as_str();
    if tun_fd >= 0 {
        tun_name = matches.get_one::<String>("tun-fd").unwrap().as_str();
    }
    let n_threads: usize = matches
        .get_one::<String>("threads")
        .unwrap()
        .parse()
        .expect("Invalid threads value");
    let log_level: Level = matches
        .get_one::<String>("verbosity")
        .unwrap()
        .parse()
        .expect("Invalid verbosity value");

    // Resolved here, beside every other argument conversion and *before* the
    // daemonize fork below. Anything that can reject a value has to run while
    // stderr is still the operator's terminal.
    let imitate: AmneziaImitationProtocol = matches
        .get_one::<String>("imitate-protocol")
        .unwrap()
        .parse()
        // Unreachable: clap's value_parser accepts only the names `FromStr`
        // knows, because both come from `AmneziaImitationProtocol::ALL`.
        .expect("clap accepted an imitation protocol that FromStr rejects");
    let imitate_domain = matches.get_one::<String>("imitate-domain").cloned();
    let probe_reply_rate: u32 = match matches.get_one::<u32>("probe-reply-rate") {
        Some(&rate) => rate,
        // Answering probes is what makes an imitated service credible, so it is
        // on by default once a protocol is named — but a device that imitates
        // nothing stays byte-for-byte silent to unauthenticated sources, which
        // is what it did before this flag existed.
        None if imitate == AmneziaImitationProtocol::None => 0,
        None => DEFAULT_PROBE_REPLY_BYTES_PER_SEC,
    };

    // A rate without a protocol builds a responder that answers nothing:
    // `probe_reply::reply_to` returns before it classifies anything when the
    // imitation protocol is `none`. Refused rather than accepted for the same
    // reason `--imitate-domain` is below -- an operator who asked for a service
    // to be answerable and silently got silence has no way to find out but a
    // packet capture. `--probe-reply-rate 0` stays legal everywhere: that is
    // the spelling for "answer nothing", and it means the same thing here.
    if probe_reply_rate > 0 && imitate == AmneziaImitationProtocol::None {
        eprintln!(
            "--probe-reply-rate {} has no effect without --imitate-protocol; \
             the listen port only answers probes for the service it imitates",
            probe_reply_rate
        );
        exit(1);
    }

    // A domain that reaches `AmneziaImitation::new` and fails its validation is
    // dropped, and a *random* one is generated at emit time instead. Silently
    // camouflaging as a name the operator never chose is worse than refusing to
    // start, and a packet capture is the only other way to notice.
    if let Some(domain) = imitate_domain.as_deref() {
        if !imitate.uses_domain() {
            eprintln!(
                "--imitate-domain is not used by --imitate-protocol {}; \
                 only dns, sip and quic carry a hostname",
                imitate.as_str()
            );
            exit(1);
        }
        let checked = AmneziaImitation::new(imitate, imitate_domain.clone(), Default::default());
        if checked.domain().is_none() {
            eprintln!(
                "--imitate-domain {:?} is not a valid host for --imitate-protocol {}",
                domain,
                imitate.as_str()
            );
            exit(1);
        }
    }

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if background {
        let log = matches.get_one::<String>("log").unwrap();

        let log_file =
            File::create(log).unwrap_or_else(|_| panic!("Could not create log file {}", log));

        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

        _guard = guard;

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        let daemonize = Daemonize::new().working_directory("/tmp");

        match daemonize.execute() {
            Outcome::Parent(Ok(_)) => {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("BoringTun started successfully");
                    exit(0);
                } else {
                    eprintln!("BoringTun failed to start");
                    exit(1);
                }
            }
            Outcome::Parent(Err(e)) => {
                eprintln!("BoringTun failed to fork: {e}");
                exit(1);
            }
            Outcome::Child(Ok(_)) => tracing::info!("BoringTun started successfully"),
            Outcome::Child(Err(e)) => {
                tracing::error!(error = ?e);
                exit(1);
            }
        }
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }

    let config = DeviceConfig {
        n_threads,
        #[cfg(target_os = "linux")]
        uapi_fd,
        use_connected_socket: !matches.get_flag("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.get_flag("disable-multi-queue"),
        // S/H/J parameters arrive over the UAPI (`awg setconf`), so the device
        // starts as plain WireGuard on those. Protocol imitation has no UAPI
        // key and can only be set here; `api.rs` preserves it across `set=1`.
        amnezia: AmneziaConfig::default().with_protocol_imitation(imitate, imitate_domain),
        // 0 disables rather than meaning "a budget of nothing", so an operator
        // who wants silence gets it without a second flag.
        probe_reply_bytes_per_sec: (probe_reply_rate > 0).then_some(probe_reply_rate),
        // `..default()` for the rest, so a future field does not break this.
        ..Default::default()
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            tracing::error!(message = "Failed to initialize tunnel", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.get_flag("disable-drop-privileges") {
        if let Err(error) = drop_privileges() {
            tracing::error!(?error, "Failed to drop privileges");
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    tracing::info!("BoringTun started successfully");

    device_handle.wait();
}
