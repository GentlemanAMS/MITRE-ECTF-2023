use blake2::{Blake2s256, Digest};
use eeprom_layout::Primitive;
use p256::ecdsa::{
    signature::{Signature, Signer, Verifier},
    SigningKey, VerifyingKey,
};
use pared_core::crypto::{jitter, Challenge};
use pared_core::error::Result;
use pared_core::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

pub trait Challenger {
    fn auth(&self, p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()>;
}

pub trait Responder {
    fn auth(&self, p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()>;

    fn auth_with_data(&self, p: &mut Peripherals, r: &mut ChaChaRng, buf: &[u8]) -> Result<()>;
}


pub struct TwoWay {
    signer: SigningKey,
    verifier: VerifyingKey,
}

impl TwoWay {
    pub fn new(signer: SigningKey, verifier: VerifyingKey) -> Self {
        Self { signer, verifier }
    }
}

impl Challenger for TwoWay {
    fn auth(&self, p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
        let mut chal = Challenge::new(r, &self.signer);
        p.uart_board.write_all(chal.as_bytes());
        p.uart_board
            .ready_nonblocking_read_exact(chal.as_bytes_mut())?;
        jitter(r);
        Ok(self.verifier.verify(&chal.nonce, &chal.signature)?)
    }
}

impl Responder for TwoWay {
    fn auth(&self, p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
        let mut chal = Challenge::zeroed();
        p.uart_board
            .ready_nonblocking_read_exact(chal.as_bytes_mut())?;

        jitter(r);
        self.verifier.verify(&chal.nonce, &chal.signature)?;

        chal.signature = self.signer.sign(&chal.nonce);
        p.uart_board.write_all(chal.as_bytes());

        Ok(())
    }

    fn auth_with_data(&self, p: &mut Peripherals, r: &mut ChaChaRng, buf: &[u8]) -> Result<()> {
        let mut chal = Challenge::zeroed();
        p.uart_board.flush();
        p.uart_board
            .ready_nonblocking_read_exact(chal.as_bytes_mut())?;

        jitter(r);
        self.verifier.verify(&chal.nonce, &chal.signature)?;

        let hash = {
            let mut hasher = Blake2s256::new();
            hasher.update(buf);
            hasher.update(&chal.nonce);
            hasher.finalize()
        };

        p.uart_board.ready_write_all(buf)?;
        p.uart_board.write_all(&hash);
        p.uart_board.write_all(self.signer.sign(&hash).as_bytes());
        Ok(())
    }
}
