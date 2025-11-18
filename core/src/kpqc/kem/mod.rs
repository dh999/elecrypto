//! KPQC Key Encapsulation Mechanisms (KEM)

mod ntruplus;
mod smaug;
mod tiger;
mod paloma;

pub use ntruplus::{ntruplus_keypair, ntruplus_encapsulate, ntruplus_decapsulate};
pub use smaug::{smaug_keypair, smaug_encapsulate, smaug_decapsulate};
pub use tiger::{tiger_keypair, tiger_encapsulate, tiger_decapsulate};
pub use paloma::{paloma_keypair, paloma_encapsulate, paloma_decapsulate};
