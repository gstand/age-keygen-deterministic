use std::io::{stdin, BufRead, IsTerminal};

use argon2::{self, Config, ThreadMode, Variant, Version};
use bech32::{self, Bech32, Hrp};
use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop};
use secure_string::SecureString;
use sha2::Sha256;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    about,
    author,
    version
)]
struct Opt {
    #[arg(default_value = "0", short, long)]
    /// optional u64 offset for index of keys
    offset: u64,
    #[arg(default_value = "1", short, long)]
    /// optional number of secret keys which should be created
    count: u64,
    #[arg(short, long)]
    /// disables the seperator comments prefixed to generated key(s)
    no_seperators: bool,
    #[arg(default_value = "Enter a passphrase", short, long)]
    /// prompt to use for passphrase prompt; useful in scripting scenarios
    prompt: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct AgeKeyGenerator {
    master_key: Vec<u8>,
}

impl AgeKeyGenerator {
    fn new(passphrase: SecureString) -> Self {
        // I explicitly hardcoded the Argon2 parameters here, because Config::default() might change in future.
        let salt = b"age-keygen-deterministic-hardcoded-salt";
        let config = Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 65536,
            time_cost: 10,
            lanes: 2,
            thread_mode: ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 64,
        };
        AgeKeyGenerator {
            master_key: argon2::hash_raw(passphrase.unsecure().as_bytes(), salt, &config).unwrap(),
        }
    }

    fn get_key(self: &Self, index: u64) -> SecureString {
        // now derive keys by calculating HMAC_SHA256(master, i) with varying values of i
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.master_key).unwrap();
        hmac.update(&index.to_be_bytes());
        let mut key = hmac.finalize().into_bytes();
        let ret = SecureString::from(bech32::encode::<Bech32>(Hrp::parse("AGE-SECRET-KEY-").unwrap(), &key).unwrap().to_uppercase());
        for byte in &mut key {
            *byte = 0;
        }
        ret
    }
}

fn main() {
    let opt = Opt::parse();
    let (offset, count) = (opt.offset, opt.count);
    let offset_end = offset
        .checked_add(count);

    if let None = offset_end {
        eprintln!("Integer overflow occured when adding count {count} to offset {offset}; please reduce your values to be within the bounds of a u64.");
        std::process::exit(1); // no sensitive data initialized before this call so no destructors need to be called.
    }

    let offset_end = offset_end.unwrap(); // infalliable

    let mut stdin = stdin().lock();
    let passphrase: SecureString;
    
    if stdin.is_terminal() {
        passphrase = SecureString::from(rpassword::prompt_password(format!("{}: ", opt.prompt)).unwrap_or("".into()));
    } else {
        passphrase = SecureString::from({
            let mut s = String::new();
            let res = BufRead::read_line(&mut stdin, &mut s);
            if let Err(_) = res {
                "".into()
            } else {
                s
            }
        });
    }
        
    if passphrase.unsecure().len() < 16 {
        eprintln!("Passphrase must be at least 16 characters.");
        drop(passphrase);
        std::process::exit(1);
    }

    let agk = AgeKeyGenerator::new(passphrase);
    for i in offset..offset_end {
        if !opt.no_seperators {
            println!("# secret key {:} below", i);
        }
        println!("{:}", agk.get_key(i).unsecure());
    }
}

#[cfg(test)]
mod tests {
    use secure_string::SecureString;

    use crate::AgeKeyGenerator;
    #[test]
    fn test_key_generation() {
        let agk = AgeKeyGenerator::new(SecureString::from("example-passphrase-do-not-use!".to_string()));
        assert_eq!(
            agk.get_key(0).unsecure(),
            "AGE-SECRET-KEY-1VZ3CREDN87LLHYDVS6FK36EZEVWNZGGFFSWZDN7DL0J04WG723MQCZUS9Q"
        );
        // test some more, out-of-order
        assert_eq!(
            agk.get_key(4).unsecure(),
            "AGE-SECRET-KEY-1FMPVFDE9WD8CSTNS4J3QRNQ5VRTFE8973FVJ2JANT56HEPZTKA4SQZZ84R"
        );
        assert_eq!(
            agk.get_key(2).unsecure(),
            "AGE-SECRET-KEY-1RSWAHJR48AWPN6HHTVVGXN7X3X0YWWA7TM7H22T7TF35EZPPVHHQ7WYGRZ"
        );
        assert_eq!(
            agk.get_key(3).unsecure(),
            "AGE-SECRET-KEY-144T9ZKX0HK6CMMGYEN6WPN82Q4K9LVR376NUJF33HKVAQ70TXMHSPV96MY"
        );
    }
}
