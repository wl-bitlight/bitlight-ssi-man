use std::{borrow::Cow, str::FromStr};

use ssi::{Algo, Chain, EncryptedSecret, Ssi, SsiCert, SsiPair, SsiSecret, Uid};
use thiserror::Error;

mod ffi;
mod memory;
#[cfg(feature = "sqlite")]
mod schema;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use crate::memory::SsiMemoryStore;
#[cfg(feature = "sqlite")]
pub use crate::sqlite::SsiSqliteStore;

static DEFAULT_EMPTY_PASSWORD: &str = "";

#[derive(Debug, Error)]
pub enum Error {
    #[cfg(feature = "sqlite")]
    #[error("diesel error: {0}")]
    Diesel(#[from] diesel::result::Error),
    #[cfg(feature = "sqlite")]
    #[error("diesel migration error: {0}")]
    DieselMigration(String),
    #[error("ssi encrypted secret reveal error: {0}")]
    SecretReveal(#[from] ssi::RevealError),
    #[error("ssi signer error: {0}")]
    Signer(#[from] ssi::SignerError),
    #[cfg(feature = "sqlite")]
    #[error("sqlite error: {0}")]
    SqliteConnection(#[from] diesel::ConnectionError),
    #[error("ssi cert parse error: {0}")]
    SsiCertParse(#[from] ssi::CertParseError),
    #[error("ssi parse error: {0}")]
    SsiParse(#[from] ssi::SsiParseError),
    #[error("ssi verify text error: {0}")]
    VerifyText(#[from] ssi::VerifyError),
    #[error("ssi uid parse error: {0}")]
    UidParse(#[from] ssi::UidParseError),
    #[error("ssi unknown error: {0}")]
    UnknownIdentity(String),
}

impl Eq for Error {}

impl PartialEq<Self> for Error {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

pub trait SsiStore {
    fn insert(&mut self, identity: String, ssi: Ssi, secret: EncryptedSecret) -> Result<(), Error>;
    fn get(&mut self, identity: &str) -> Result<Cow<(Ssi, EncryptedSecret)>, Error>;
    fn remove(&mut self, identity: &str) -> Result<bool, Error>;
    fn paginated_identities(
        &mut self,
        page: usize,
        per_page: usize,
    ) -> Result<(Vec<Cow<'_, String>>, usize), Error>;
    fn all_identities(&mut self) -> Result<Vec<Cow<'_, String>>, Error>;
}

#[repr(C)]
pub struct SsiMan {
    store: Box<dyn SsiStore>,
}

impl Default for SsiMan {
    fn default() -> Self {
        Self::with_memory()
    }
}

impl SsiMan {
    #[no_mangle]
    pub fn with_memory() -> Self {
        Self {
            store: Box::new(SsiMemoryStore::default()),
        }
    }
}

#[cfg(feature = "sqlite")]
impl SsiMan {
    pub fn with_sqlite(path: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            store: Box::new(SsiSqliteStore::new(path)?),
        })
    }
}

impl SsiMan {
    pub fn new_ssi(
        &mut self,
        identity: impl ToString,
        email: impl AsRef<str>,
        optional_passwd: Option<&str>,
    ) -> Result<String, Error> {
        let uid = Uid::from_str(&format!(
            "{} <mailto:{}>",
            identity.to_string(),
            email.as_ref()
        ))?;
        let secret = SsiSecret::new(Algo::Ed25519, Chain::Bitcoin);
        let ssi = Ssi::new(vec![uid].into_iter().collect(), None, &secret);
        let ssi_string = ssi.to_string();
        self.store
            .insert(
                identity.to_string(),
                ssi,
                secret.conceal(optional_passwd.unwrap_or(DEFAULT_EMPTY_PASSWORD)),
            )
            .map(|_| ssi_string)
    }

    pub fn sign(
        &mut self,
        ssi: impl AsRef<str>,
        message: impl AsRef<[u8]>,
        passwd: Option<&str>,
    ) -> Result<String, Error> {
        let cow = self.store.get(ssi.as_ref())?;
        let secret = cow.1.reveal(passwd.unwrap_or(DEFAULT_EMPTY_PASSWORD))?;
        if secret.to_public() != cow.0.pk {
            return Err(Error::Signer(ssi::SignerError::WrongPassword));
        }
        let signer = SsiPair::new(cow.0.to_owned(), secret);
        let ssi_cert = signer.sign(message.as_ref());
        Ok(format!("{ssi_cert:#}"))
    }

    pub fn remove(&mut self, identity: &str) -> Result<bool, Error> {
        self.store.remove(identity)
    }

    pub fn paginated_identities(
        &mut self,
        page: usize,
        per_page: usize,
    ) -> Result<(Vec<Cow<'_, String>>, usize), Error> {
        self.store.paginated_identities(page, per_page)
    }

    pub fn all_identities(&mut self) -> Result<Vec<Cow<'_, String>>, Error> {
        self.store.all_identities()
    }
}

pub fn ssi_cert_verify_text(ssi_cert: &str, text: &str) -> Result<(), Error> {
    let ssi_cert = SsiCert::from_str(ssi_cert)?;
    Ok(ssi_cert.verify_text(text)?)
}
