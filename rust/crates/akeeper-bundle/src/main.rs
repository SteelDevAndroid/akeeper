//! `akeeper-bundle keygen <seed>` · `pubkey <seed>` · `build [options] --out <bundle>` · `verify <bundle> <clé hex>…`

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use akeeper_bundle::{
    SEED_LEN, Sources, build, parse_hex_key, public_key_hex, signing_key, verify,
};

const USAGE: &str = "\
usage :
  akeeper-bundle keygen <seed>        crée une graine Ed25519 (0600) et affiche la clé publique
  akeeper-bundle pubkey <seed>        affiche la clé publique d'une graine
  akeeper-bundle build --seed <f> --key-id <0|1> --version <n> --out <f>
        [--created <s unix>] [--ads <f>] [--malware <f>] [--phishing <f>]
        [--doh <f>] [--doh-ips <f>] [--notice <f>]
  akeeper-bundle verify <bundle> <clé 0 hex> [<clé 1 hex>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (command, rest) = args.split_first().ok_or(USAGE)?;
    match command.as_str() {
        "keygen" => {
            let path = rest.first().ok_or(USAGE)?;
            let mut seed = [0u8; SEED_LEN];
            getrandom::fill(&mut seed).map_err(|e| format!("aléa indisponible : {e}"))?;
            // create_new : ne jamais écraser une clé existante ; 0600 : graine lisible du seul propriétaire.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .and_then(|mut f| f.write_all(&seed))
                .map_err(|e| format!("{path} : {e}"))?;
            println!("{}", public_key_hex(&signing_key(&seed)));
            Ok(())
        }
        "pubkey" => {
            let seed = read_seed(rest.first().ok_or(USAGE)?)?;
            println!("{}", public_key_hex(&signing_key(&seed)));
            Ok(())
        }
        "build" => build_command(rest),
        "verify" => {
            let (path, keys) = rest.split_first().ok_or(USAGE)?;
            let keys = keys
                .iter()
                .map(|k| parse_hex_key(k).ok_or_else(|| format!("clé publique invalide : {k}")))
                .collect::<Result<Vec<_>, _>>()?;
            let bytes = fs::read(path).map_err(|e| format!("{path} : {e}"))?;
            let version = verify(&bytes, &keys).map_err(|e| format!("bundle refusé : {e:?}"))?;
            println!("signature valide, version {version}");
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn build_command(args: &[String]) -> Result<(), String> {
    let mut seed = None;
    let mut key_id = None;
    let mut version = None;
    let mut out = None;
    let mut created = None;
    let mut sources = Sources::default();
    let mut pairs = args.chunks_exact(2);
    for pair in &mut pairs {
        let [flag, value] = pair else {
            return Err(USAGE.into());
        };
        let text = || fs::read_to_string(value).map_err(|e| format!("{value} : {e}"));
        match flag.as_str() {
            "--seed" => seed = Some(read_seed(value)?),
            "--key-id" => key_id = Some(value.parse::<u8>().map_err(|_| USAGE)?),
            "--version" => version = Some(value.parse::<u64>().map_err(|_| USAGE)?),
            "--created" => created = Some(value.parse::<u64>().map_err(|_| USAGE)?),
            "--out" => out = Some(value.clone()),
            "--ads" => sources.ads = Some(text()?),
            "--malware" => sources.malware = Some(text()?),
            "--phishing" => sources.phishing = Some(text()?),
            "--doh" => sources.doh = Some(text()?),
            "--doh-ips" => sources.doh_ips = Some(text()?),
            "--notice" => sources.notice = Some(text()?),
            _ => return Err(USAGE.into()),
        }
    }
    if !pairs.remainder().is_empty() {
        return Err(USAGE.into());
    }
    let (Some(seed), Some(key_id), Some(version), Some(out)) = (seed, key_id, version, out) else {
        return Err(USAGE.into());
    };
    let created = match created {
        Some(c) => c,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    };
    let bytes = build(&signing_key(&seed), key_id, version, created, &sources)
        .map_err(|e| format!("construction impossible : {e:?}"))?;
    fs::write(&out, &bytes).map_err(|e| format!("{out} : {e}"))?;
    println!(
        "{out} : {} octets, version {version}, clé {key_id}",
        bytes.len()
    );
    Ok(())
}

fn read_seed(path: &str) -> Result<[u8; SEED_LEN], String> {
    fs::read(path)
        .map_err(|e| format!("{path} : {e}"))?
        .try_into()
        .map_err(|_| format!("{path} : graine de {SEED_LEN} octets attendue"))
}
