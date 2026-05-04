pub mod encrypted_log_repository;
pub mod key_envelope_repository;
pub mod key_repository;

pub type RepositoryError = Box<dyn std::error::Error + Send + Sync>;
