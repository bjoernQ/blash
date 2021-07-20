pub mod bl602;
pub use crate::blflash::elf::{CodeSegment, FirmwareImage, RomSegment};
use crate::blflash::image::{BootHeaderCfg, PartitionCfg};
use crate::blflash::Error;
pub use bl602::Bl602;

pub trait Chip {
    fn target(&self) -> &'static str;
    fn get_eflash_loader(&self) -> &[u8];
    fn get_flash_segment<'a>(&self, code_segment: CodeSegment<'a>) -> Option<RomSegment<'a>>;
    fn with_boot2(
        &self,
        partition_cfg: PartitionCfg,
        bootheader_cfg: BootHeaderCfg,
        ro_params: Vec<u8>,
        bin: &[u8],
    ) -> Result<Vec<RomSegment>, Error>;
}
