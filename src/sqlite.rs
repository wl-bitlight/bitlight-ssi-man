use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

use diesel::{
    deserialize::{FromSql, FromSqlRow},
    dsl::count_star,
    expression::AsExpression,
    prelude::*,
    serialize::{IsNull, Output, ToSql},
    sql_types::Text,
    sqlite::{Sqlite, SqliteValue},
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
use ssi::{EncryptedSecret, Ssi};

use crate::{Error, SsiStore};

const DIESEL_MIGRATIONS: EmbeddedMigrations = diesel_migrations::embed_migrations!("./migrations");

#[derive(AsExpression, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct SqliteTextWrapper<T: Display + FromStr + 'static>(T);

impl<T> From<T> for SqliteTextWrapper<T>
where
    T: Display + FromStr + 'static,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> SqliteTextWrapper<T>
where
    T: Display + FromStr + 'static,
{
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Debug for SqliteTextWrapper<T>
where
    T: Display + FromStr + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> ToSql<Text, Sqlite> for SqliteTextWrapper<T>
where
    T: Display + FromStr + 'static,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> diesel::serialize::Result {
        out.set_value(self.0.to_string());
        Ok(IsNull::No)
    }
}

impl<T> FromSql<Text, Sqlite> for SqliteTextWrapper<T>
where
    T: Display + FromStr + 'static,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    fn from_sql(value: SqliteValue) -> diesel::deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(value)?;
        T::from_str(&text)
            .map_err(Into::into)
            .map(SqliteTextWrapper)
    }
}

#[derive(Insertable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::ssi_secrets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct SsiSecret {
    id: String,
    ssi: SqliteTextWrapper<Ssi>,
    secret: SqliteTextWrapper<EncryptedSecret>,
}
pub struct SsiSqliteStore {
    connection: SqliteConnection,
}

impl SsiSqliteStore {
    pub fn new(db_path: impl AsRef<str>) -> Result<Self, Error> {
        let mut connection = SqliteConnection::establish(db_path.as_ref())?;
        connection
            .run_pending_migrations(DIESEL_MIGRATIONS)
            .map_err(|err| Error::DieselMigration(err.to_string()))?;
        Ok(Self { connection })
    }
}

impl SsiStore for SsiSqliteStore {
    fn insert(&mut self, id: String, ssi: Ssi, secret: EncryptedSecret) -> Result<(), Error> {
        use crate::schema::ssi_secrets::dsl;

        diesel::insert_into(dsl::ssi_secrets)
            .values(&SsiSecret {
                id,
                ssi: ssi.into(),
                secret: secret.into(),
            })
            .execute(&mut self.connection)
            .map_err(Into::into)
            .map(drop)
    }

    fn get(&mut self, id: &str) -> Result<Cow<(Ssi, EncryptedSecret)>, Error> {
        use crate::schema::ssi_secrets::dsl;
        dsl::ssi_secrets
            .filter(dsl::id.eq(id))
            .get_result::<SsiSecret>(&mut self.connection)
            .map_err(Into::into)
            .map(|record| Cow::Owned((record.ssi.into_inner(), record.secret.into_inner())))
    }

    fn remove(&mut self, id: &str) -> Result<bool, Error> {
        use crate::schema::ssi_secrets::dsl;
        diesel::delete(dsl::ssi_secrets.filter(dsl::id.eq(id)))
            .execute(&mut self.connection)
            .map_err(Into::into)
            .map(|row| row == 1)
    }

    fn paginated_identities(
        &mut self,
        page: usize,
        per_page: usize,
    ) -> Result<(Vec<Cow<'_, String>>, usize), Error> {
        use crate::schema::ssi_secrets::dsl;
        self.connection.transaction(|conn| {
            let total = dsl::ssi_secrets
                .select(count_star())
                .get_result::<i64>(conn)?;
            let records = dsl::ssi_secrets
                .select(SsiSecret::as_select())
                .offset(((page - 1) * per_page) as i64)
                .limit(per_page as i64)
                .load(conn)
                .map(|records| records.into_iter().map(|ssi| Cow::Owned(ssi.id)).collect())?;

            let total_pages = (total as f64 / per_page as f64).ceil() as usize;
            Ok((records, total_pages))
        })
    }

    fn all_identities(&mut self) -> Result<Vec<Cow<'_, String>>, Error> {
        use crate::schema::ssi_secrets::dsl;
        dsl::ssi_secrets
            .select(SsiSecret::as_select())
            .load(&mut self.connection)
            .map_err(Into::into)
            .map(|records| records.into_iter().map(|ssi| Cow::Owned(ssi.id)).collect())
    }
}

// #[cfg(test)]
// mod tests {
//     use time::OffsetDateTime;
//
//     use crate::{ssi_cert_verify_text, SsiMan};
//
//     use super::*;
//
//     const TEST_IDENTITY: &str = "Luna";
//
//     #[test]
//     fn ssi_sqlite_store_should_ok() {
//         let mut ssi_man = SsiMan::with_sqlite(
//             std::env::temp_dir()
//                 .join(format!(
//                     "ssi_man_{}_sqlite.db",
//                     OffsetDateTime::now_utc().unix_timestamp()
//                 ))
//                 .to_string_lossy(),
//         )
//         .unwrap();
//         let ssi = ssi_man
//             .new_ssi(TEST_IDENTITY, "luna@bitlightlabs.com", None)
//             .unwrap();
//         assert!(Ssi::from_str(&ssi).is_ok());
//         let message = "have a good day!";
//         let ssi_cert = ssi_man.sign(TEST_IDENTITY, message, None).unwrap();
//         ssi_cert_verify_text(&ssi_cert, message).unwrap();
//         assert_eq!(
//             ssi_man.paginated_identities(1, 10),
//             Ok((vec![Cow::Owned(TEST_IDENTITY.to_string())], 1))
//         );
//
//         assert_eq!(ssi_man.paginated_identities(2, 10), Ok((vec![], 1)));
//         assert_eq!(
//             ssi_man.all_identities(),
//             Ok(vec![Cow::Owned(TEST_IDENTITY.to_string())])
//         );
//         assert!(ssi_man.remove(TEST_IDENTITY).unwrap());
//         assert_eq!(ssi_man.all_identities(), Ok(vec![]));
//     }
// }
