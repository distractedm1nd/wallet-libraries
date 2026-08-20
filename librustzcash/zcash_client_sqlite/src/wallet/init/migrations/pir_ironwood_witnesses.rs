use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::ironwood_received_notes;
use crate::wallet::init::WalletMigrationError;

/// Adds storage for PIR-provided Ironwood witnesses.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x497e5dfc_632e_4ac4_be9e_decd8e480bbd);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_received_notes::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Adds storage for PIR-provided Ironwood witnesses."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE pir_ironwood_witnesses (
                note_id INTEGER PRIMARY KEY
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                position INTEGER NOT NULL,
                anchor_height INTEGER NOT NULL,
                anchor_root BLOB NOT NULL CHECK (length(anchor_root) = 32),
                auth_path BLOB NOT NULL CHECK (length(auth_path) = 1024)
            );",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
