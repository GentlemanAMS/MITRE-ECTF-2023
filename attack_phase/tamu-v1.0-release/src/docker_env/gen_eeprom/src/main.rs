use blake2::digest::generic_array::GenericArray;
use blake2::digest::typenum::U32;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use clap::{Args, Parser, Subcommand};
use color_eyre::eyre::{ensure, Result};
use eeprom_layout::{car::CarLayout, fob::FobLayout, Hashed, Primitive, PrivKey, PubKey};
use goblin::elf::Elf;
use p256::ecdsa::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

fn parse_pin(s: &str) -> Result<u32> {
    ensure!(s.len() == 6, "pin must have 6 digits");
    Ok(u32::from_str_radix(s, 16)?)
}

#[derive(Args, Debug, Clone)]
pub struct SharedArgs {
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    secrets: PathBuf,
    #[arg(long)]
    elf: PathBuf,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Cmd {
    UnpairedFob {
        #[command(flatten)]
        shared: SharedArgs,
    },
    PairedFob {
        #[command(flatten)]
        shared: SharedArgs,
        #[arg(long)]
        car_id: u32,
        #[arg(long, value_parser = parse_pin)]
        pair_pin: u32,
    },
    Car {
        #[command(flatten)]
        shared: SharedArgs,
    },
    Secrets {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Debug, Parser)]
#[clap(rename_all = "kebab")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

pub type Hash = GenericArray<u8, U32>;
fn oneshot_hash(xs: &[u8]) -> Hash {
    let mut h = Blake2s256::new();
    h.update(xs);
    h.finalize()
}

fn compute_text_hash(elf: &PathBuf) -> Result<Hash> {
    let elf_bytes = std::fs::read(elf)?;
    let elf = Elf::parse(&elf_bytes)?;
    let text_header = &elf.program_headers[1];
    ensure!(text_header.p_vaddr == 0x8000, "start of .text section");
    let file_range = text_header.file_range();
    let text = &elf_bytes[file_range];
    Ok(oneshot_hash(text))
}

fn write_keypair(secrets_dir: &PathBuf, name: &str) -> Result<()> {
    let private = SigningKey::random(&mut rand::thread_rng());
    let public = VerifyingKey::from(&private);
    let private_path = secrets_dir.join(format!("{name}_key"));
    let public_path = secrets_dir.join(format!("{name}_key.pub"));

    std::fs::write(private_path, private.to_bytes())?;
    std::fs::write(public_path, public.to_encoded_point(false))?;
    Ok(())
}

fn gen_secrets(secrets_dir: &PathBuf) -> Result<()> {
    let _ = std::fs::create_dir(&secrets_dir);
    write_keypair(&secrets_dir, "paired")?;
    write_keypair(&secrets_dir, "car_auth")?;
    write_keypair(&secrets_dir, "package")?;
    write_keypair(&secrets_dir, "manufacturer")?;

    let fob_sym_key = ChaCha20Poly1305::generate_key(&mut rand::thread_rng());
    std::fs::write(secrets_dir.join("fob_sym_key"), fob_sym_key)?;
    Ok(())
}

fn read_arr<const N: usize>(path: impl AsRef<Path>) -> Result<[u8; N]> {
    let mut b = std::fs::read(path)?;
    ensure!(b.len() <= N, "must fit in {N} bytes");
    b.resize(N, 0);
    Ok(b.try_into().unwrap())
}

fn gen_car(s: &SharedArgs) -> Result<CarLayout> {
    use eeprom_layout::car::*;
    let paired_pubkey = PairedPubKey(PubKey(read_arr(s.secrets.join("paired_key.pub"))?));
    let car_auth_privkey = CarAuthPrivKey(PrivKey(read_arr(s.secrets.join("car_auth_key"))?));
    Ok(CarLayout {
        before_pad: BeforePad {
            text_hash: TextHash(compute_text_hash(&s.elf)?),
            paired_pubkey: Hashed::new(paired_pubkey),
            car_auth_privkey: Hashed::new(car_auth_privkey),
            seed: Hashed::new(CarSeed(rand::random())),
        },
        _pad: [0; PAD],
        feature3: Feature3::zeroed(),
        feature2: Feature2::zeroed(),
        feature1: Feature1::zeroed(),
        unlock: Unlock::zeroed(),
    })
}

fn gen_unpaired_fob(s: &SharedArgs) -> Result<FobLayout> {
    use eeprom_layout::fob::*;
    let manufacturer_pubkey = ManufacturerPubKey(PubKey(read_arr(s.secrets.join("manufacturer_key.pub"))?));
    let manufacturer_privkey = ManufacturerPrivKey(PrivKey(read_arr(s.secrets.join("manufacturer_key"))?));
    let package_pubkey = PackagePubKey(PubKey(read_arr(s.secrets.join("package_key.pub"))?));
    let fob_symmetric = FobSymmetric(read_arr(s.secrets.join("fob_sym_key"))?);
    Ok(FobLayout {
        text_hash: TextHash(compute_text_hash(&s.elf)?),
        seed: Hashed::new(FobSeed(rand::random())),
        manufacturer_pubkey: Hashed::new(manufacturer_pubkey),
        manufacturer_privkey: Hashed::new(manufacturer_privkey),
        package_pubkey: Hashed::new(package_pubkey),
        fob_symmetric: Hashed::new(fob_symmetric),
        feature_flags: Hashed::new(FeatureFlags([false; 4])),
        timeout: Hashed::new(Timeout(0)),
        // explicitly do not initialize
        car_auth_pubkey: Hashed::new(CarAuthPubKey::zeroed()),
        paired_privkey: Hashed::new(PairedPrivKey::zeroed()),
        pin_hash: PinHash::zeroed(),
        car_id: Hashed::new(CarId::zeroed()),
    })
}

fn main() -> Result<()> {
    color_eyre::install()?;
    match Cli::parse().cmd {
        Cmd::Car { shared } => {
            let layout = gen_car(&shared)?;
            std::fs::write(&shared.output, layout.as_bytes())?;
        }
        Cmd::UnpairedFob { shared } => {
            let layout = gen_unpaired_fob(&shared)?;
            std::fs::write(&shared.output, layout.as_bytes())?;
        }
        Cmd::PairedFob {
            shared,
            car_id,
            pair_pin,
        } => {
            use eeprom_layout::fob::*;
            let mut layout = gen_unpaired_fob(&shared)?;
            let car_auth_pubkey = CarAuthPubKey(PubKey(read_arr(shared.secrets.join("car_auth_key.pub"))?));
            let paired_privkey = PairedPrivKey(PrivKey(read_arr(shared.secrets.join("paired_key"))?));
            layout.car_auth_pubkey = Hashed::new(car_auth_pubkey);
            layout.paired_privkey = Hashed::new(paired_privkey);
            layout.pin_hash = PinHash(oneshot_hash(&pair_pin.to_le_bytes()));
            layout.car_id = Hashed::new(CarId(car_id));
            std::fs::write(&shared.output, layout.as_bytes())?;
        }
        Cmd::Secrets { output } => {
            gen_secrets(&output)?;
        }
    }
    Ok(())
}
