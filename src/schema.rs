// @generated automatically by Diesel CLI.

diesel::table! {
    ssi_secrets (id) {
        id -> Text,
        ssi -> Text,
        secret -> Text,
    }
}
