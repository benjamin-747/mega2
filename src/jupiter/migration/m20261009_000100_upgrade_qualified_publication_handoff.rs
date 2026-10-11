//! Forward-roll the qualified family to the publication-handoff serving revision.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        super::qualified_native_runtime_upgrade::upgrade_publication_handoff(manager).await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Forward-only: no inverse exists, and a silent `Ok` would report a rollback that never
        // happened. Recovery is a forward fix on top of the last landed family.
        Err(DbErr::Custom(
            "publication handoff forward migration is irreversible".to_owned(),
        ))
    }

    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }
}
