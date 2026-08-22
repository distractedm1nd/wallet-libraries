use orchard::{
    note::ExtractedNoteCommitment,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
};
use rusqlite::{Connection, named_params};
use zcash_client_backend::wallet::ReceivedNote;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight},
};

use crate::{
    PirIronwoodNote, PirIronwoodWitness, ReceivedNoteId, error::SqliteClientError,
    wallet::orchard::to_received_note,
};

pub(crate) fn anchor_exists(
    conn: &Connection,
    anchor_height: BlockHeight,
) -> Result<bool, SqliteClientError> {
    let table_exists: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'pir_ironwood_witnesses'
         )",
        [],
        |row| row.get(0),
    )?;
    if !table_exists {
        return Ok(false);
    }

    conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM pir_ironwood_witnesses WHERE anchor_height = :anchor_height
         )",
        named_params![":anchor_height": u32::from(anchor_height)],
        |row| row.get(0),
    )
    .map_err(SqliteClientError::from)
}

pub(crate) fn anchor_height(conn: &Connection) -> Result<Option<BlockHeight>, SqliteClientError> {
    let table_exists: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'pir_ironwood_witnesses'
         )",
        [],
        |row| row.get(0),
    )?;
    if !table_exists {
        return Ok(None);
    }

    conn.query_row(
        "SELECT MAX(anchor_height) FROM pir_ironwood_witnesses",
        [],
        |row| row.get::<_, Option<u32>>(0),
    )
    .map(|height| height.map(BlockHeight::from_u32))
    .map_err(SqliteClientError::from)
}

pub(crate) fn stored_witness(
    conn: &Connection,
    txid: &TxId,
    output_index: u32,
    anchor_height: BlockHeight,
) -> Result<Option<(Anchor, MerklePath)>, SqliteClientError> {
    let result = conn.query_row_and_then(
        "SELECT witness.position, witness.anchor_root, witness.auth_path
         FROM pir_ironwood_witnesses witness
         JOIN ironwood_received_notes note ON note.id = witness.note_id
         JOIN transactions tx ON tx.id_tx = note.transaction_id
         WHERE tx.txid = :txid
           AND note.action_index = :output_index
           AND witness.anchor_height = :anchor_height",
        named_params![
            ":txid": txid.as_ref(),
            ":output_index": output_index,
            ":anchor_height": u32::from(anchor_height),
        ],
        |row| {
            let position = u32::try_from(row.get::<_, u64>("position")?).map_err(|_| {
                SqliteClientError::CorruptedData(
                    "PIR Ironwood witness position exceeds the tree".into(),
                )
            })?;
            let anchor_root = row.get::<_, [u8; 32]>("anchor_root")?;
            let anchor = Option::from(Anchor::from_bytes(anchor_root)).ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "PIR Ironwood witness has a non-canonical anchor".into(),
                )
            })?;
            let auth_path = row.get::<_, Vec<u8>>("auth_path")?;
            if auth_path.len() != orchard::NOTE_COMMITMENT_TREE_DEPTH * 32 {
                return Err(SqliteClientError::CorruptedData(
                    "PIR Ironwood witness path has the wrong length".into(),
                ));
            }
            let path = auth_path
                .chunks_exact(32)
                .map(|chunk| {
                    MerkleHashOrchard::from_bytes(chunk.try_into().expect("chunk length is 32"))
                        .into_option()
                        .ok_or_else(|| {
                            SqliteClientError::CorruptedData(
                                "PIR Ironwood witness has a non-canonical path".into(),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .expect("path length was checked");
            Ok((anchor, MerklePath::from_parts(position, path)))
        },
    );
    match result {
        Ok(witness) => Ok(Some(witness)),
        Err(SqliteClientError::DbError(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn note_by_id<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    note_id: ReceivedNoteId,
) -> Result<Option<ReceivedNote<ReceivedNoteId, orchard::note::Note>>, SqliteClientError> {
    let ReceivedNoteId(pool, id) = note_id;
    if pool != ShieldedPool::Ironwood {
        return Ok(None);
    }
    let result = conn.query_row_and_then(
        "SELECT
             rn.id, t.txid, rn.action_index,
             rn.diversifier, rn.value, rn.rho, rn.rseed, rn.note_version,
             rn.commitment_tree_position, accounts.ufvk, rn.recipient_key_scope,
             t.mined_height, NULL AS max_shielding_input_height
         FROM ironwood_received_notes rn
         JOIN accounts ON accounts.id = rn.account_id
         JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE rn.id = :id",
        named_params![":id": id],
        |row| to_received_note(params, ShieldedPool::Ironwood, row),
    );
    match result {
        Ok(note) => Ok(note),
        Err(SqliteClientError::DbError(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn known_unspent_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
) -> Result<Vec<PirIronwoodNote>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT
             rn.id, t.txid, rn.action_index,
             rn.diversifier, rn.value, rn.rho, rn.rseed, rn.note_version,
             rn.commitment_tree_position, accounts.ufvk, rn.recipient_key_scope,
             t.mined_height, NULL AS max_shielding_input_height, rn.nf
         FROM ironwood_received_notes rn
         JOIN accounts ON accounts.id = rn.account_id
         JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE t.mined_height IS NOT NULL
           AND rn.nf IS NOT NULL
           AND rn.commitment_tree_position IS NOT NULL
           AND NOT EXISTS (
               SELECT 1
               FROM ironwood_received_note_spends spend
               WHERE spend.ironwood_received_note_id = rn.id
           )
         ORDER BY rn.commitment_tree_position",
    )?;
    let rows = stmt.query_and_then([], |row| {
        let note = to_received_note(params, ShieldedPool::Ironwood, row)?.ok_or_else(|| {
            SqliteClientError::CorruptedData("Ironwood note lacks spending metadata".into())
        })?;
        let nullifier = row.get("nf")?;
        let mined_height = note.mined_height().ok_or_else(|| {
            SqliteClientError::CorruptedData("mined Ironwood note lacks a height".into())
        })?;
        Ok(PirIronwoodNote {
            note_id: *note.internal_note_id(),
            nullifier,
            commitment: ExtractedNoteCommitment::from(note.note().commitment()).to_bytes(),
            position: note.note_commitment_tree_position(),
            mined_height,
            value: note.note_value()?,
        })
    })?;
    rows.collect()
}

pub(crate) fn replace_witnesses<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    anchor_height: BlockHeight,
    anchor_root: [u8; 32],
    witnesses: &[PirIronwoodWitness],
) -> Result<(), SqliteClientError> {
    let anchor = Option::from(Anchor::from_bytes(anchor_root)).ok_or_else(|| {
        SqliteClientError::PirWitnessInvalid("anchor root is not canonical".into())
    })?;
    let mut rows = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        let note = note_by_id(conn, params, witness.note_id)?.ok_or_else(|| {
            SqliteClientError::PirWitnessInvalid(format!(
                "{} is not an Ironwood note in this wallet",
                witness.note_id
            ))
        })?;
        if note.note_commitment_tree_position() != witness.position {
            return Err(SqliteClientError::PirWitnessInvalid(format!(
                "position does not match {}",
                witness.note_id
            )));
        }
        let path = witness
            .siblings
            .iter()
            .map(|hash| {
                Option::from(MerkleHashOrchard::from_bytes(hash)).ok_or_else(|| {
                    SqliteClientError::PirWitnessInvalid(
                        "path contains a non-canonical hash".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("witness paths have the Ironwood tree depth");
        let position = u32::try_from(u64::from(witness.position)).map_err(|_| {
            SqliteClientError::PirWitnessInvalid("position exceeds the Ironwood tree".into())
        })?;
        let merkle_path = MerklePath::from_parts(position, path);
        let commitment = ExtractedNoteCommitment::from(note.note().commitment());
        if merkle_path.root(commitment) != anchor {
            return Err(SqliteClientError::PirWitnessInvalid(format!(
                "path for {} does not produce the supplied anchor",
                witness.note_id
            )));
        }
        rows.push((
            witness.note_id.1,
            u64::from(witness.position),
            witness.siblings,
        ));
    }

    write_rows(conn, anchor_height, anchor_root, &rows)
}

fn write_rows(
    conn: &rusqlite::Transaction,
    anchor_height: BlockHeight,
    anchor_root: [u8; 32],
    rows: &[(i64, u64, [[u8; 32]; orchard::NOTE_COMMITMENT_TREE_DEPTH])],
) -> Result<(), SqliteClientError> {
    conn.execute("DELETE FROM pir_ironwood_witnesses", [])?;
    for (note_id, position, siblings) in rows {
        let auth_path: Vec<_> = siblings
            .iter()
            .flat_map(|hash| hash.iter().copied())
            .collect();
        conn.execute(
            "INSERT INTO pir_ironwood_witnesses
                (note_id, position, anchor_height, anchor_root, auth_path)
             VALUES (:note_id, :position, :anchor_height, :anchor_root, :auth_path)",
            named_params![
                ":note_id": *note_id,
                ":position": *position,
                ":anchor_height": u32::from(anchor_height),
                ":anchor_root": anchor_root,
                ":auth_path": auth_path,
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use orchard::tree::{Anchor, MerkleHashOrchard};
    use rusqlite::Connection;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::consensus::BlockHeight;

    #[test]
    fn failed_replacement_rolls_back_every_write() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE ironwood_received_notes (id INTEGER PRIMARY KEY);
             CREATE TABLE pir_ironwood_witnesses (
                 note_id INTEGER PRIMARY KEY REFERENCES ironwood_received_notes(id),
                 position INTEGER NOT NULL,
                 anchor_height INTEGER NOT NULL,
                 anchor_root BLOB NOT NULL CHECK (length(anchor_root) = 32),
                 auth_path BLOB NOT NULL CHECK (length(auth_path) = 1024)
             );
             INSERT INTO ironwood_received_notes (id) VALUES (1);
             INSERT INTO pir_ironwood_witnesses
                 (note_id, position, anchor_height, anchor_root, auth_path)
             VALUES (1, 0, 1, zeroblob(32), zeroblob(1024));",
        )
        .unwrap();

        let rows = vec![(1, 0, [[0; 32]; 32]), (2, 1, [[0; 32]; 32])];
        let tx = conn.transaction().unwrap();
        assert!(super::write_rows(&tx, BlockHeight::from_u32(2), [0; 32], &rows,).is_err());
        drop(tx);

        let anchor_height: u32 = conn
            .query_row(
                "SELECT anchor_height FROM pir_ironwood_witnesses WHERE note_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(anchor_height, 1);
    }

    #[test]
    fn reads_stored_witness() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL
             );
             CREATE TABLE pir_ironwood_witnesses (
                 note_id INTEGER PRIMARY KEY,
                 position INTEGER NOT NULL,
                 anchor_height INTEGER NOT NULL,
                 anchor_root BLOB NOT NULL,
                 auth_path BLOB NOT NULL
             );",
        )
        .unwrap();
        let txid = TxId::from_bytes([1; 32]);
        conn.execute(
            "INSERT INTO transactions (id_tx, txid) VALUES (1, ?)",
            [txid.as_ref()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ironwood_received_notes (id, transaction_id, action_index)
             VALUES (1, 1, 2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pir_ironwood_witnesses
                 (note_id, position, anchor_height, anchor_root, auth_path)
             VALUES (1, 3, 4, zeroblob(32), zeroblob(1024))",
            [],
        )
        .unwrap();

        let actual = super::stored_witness(&conn, &txid, 2, BlockHeight::from_u32(4))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::anchor_height(&conn).unwrap(),
            Some(BlockHeight::from_u32(4))
        );
        let zero_hash = MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
        assert_eq!(actual.0, Anchor::from_bytes([0; 32]).unwrap());
        assert_eq!(actual.1.position(), 3);
        assert_eq!(actual.1.auth_path(), [zero_hash; 32]);
    }
}
