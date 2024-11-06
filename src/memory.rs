use std::{borrow::Cow, collections::HashMap};

use ssi::{EncryptedSecret, Ssi};

use crate::{Error, SsiStore};
#[derive(Default)]
pub struct SsiMemoryStore {
    records: HashMap<String, (Ssi, EncryptedSecret)>,
}

impl SsiStore for SsiMemoryStore {
    fn insert(&mut self, identity: String, ssi: Ssi, secret: EncryptedSecret) -> Result<(), Error> {
        self.records.insert(identity, (ssi, secret));
        Ok(())
    }

    fn get(&mut self, identity: &str) -> Result<Cow<(Ssi, EncryptedSecret)>, Error> {
        self.records
            .get(identity)
            .ok_or(Error::UnknownIdentity(identity.to_string()))
            .map(Cow::Borrowed)
    }

    fn remove(&mut self, identity: &str) -> Result<bool, Error> {
        Ok(self.records.remove(identity).is_some())
    }

    fn paginated_identities(
        &mut self,
        page: usize,
        per_page: usize,
    ) -> Result<(Vec<Cow<'_, String>>, usize), Error> {
        Ok((
            self.records
                .keys()
                .skip((page - 1) * per_page)
                .take(per_page)
                .map(Cow::Borrowed)
                .collect(),
            self.records.len(),
        ))
    }

    fn all_identities(&mut self) -> Result<Vec<Cow<'_, String>>, Error> {
        Ok(self.records.keys().map(Cow::Borrowed).collect())
    }
}

// #[cfg(test)]
// mod tests {
//     use std::str::FromStr;
//
//     use crate::{ssi_cert_verify_text, SsiMan};
//
//     use super::*;
//
//     #[test]
//     fn ssi_memory_store_should_ok() {
//         let identity = String::from("Luna");
//         let mut ssi_man = SsiMan::with_memory();
//         let ssi = ssi_man
//             .new_ssi(&identity, "luna@bitlightlabs.com", None)
//             .unwrap();
//         assert!(Ssi::from_str(&ssi).is_ok());
//         let message = "have a good day!";
//         let ssi_cert = ssi_man.sign(&identity, message, None).unwrap();
//         ssi_cert_verify_text(&ssi_cert, message).unwrap();
//         assert_eq!(
//             ssi_man.paginated_identities(1, 10),
//             Ok((vec![Cow::Borrowed(&identity)], 1))
//         );
//         assert_eq!(ssi_man.paginated_identities(2, 10), Ok((vec![], 1)));
//         assert_eq!(ssi_man.all_identities(), Ok(vec![Cow::Borrowed(&identity)]));
//         assert!(ssi_man.remove(&identity).unwrap());
//         assert_eq!(ssi_man.all_identities(), Ok(vec![]));
//     }
// }
