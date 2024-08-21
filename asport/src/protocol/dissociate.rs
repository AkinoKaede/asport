/// Command `Dissociate`
///
/// ```plain
/// +----------+
/// | ASSOC_ID |
/// +----------+
/// |    2     |
/// +----------+
/// ```
///
/// where:
///
/// - `ASSOC_ID` - UDP froward session ID
#[derive(Clone, Debug)]
pub struct Dissociate {
    assoc_id: u16,
}

impl Dissociate {
    const TYPE_CODE: u8 = 0x04;

    /// Creates a new `Dissociate` command
    pub const fn new(assoc_id: u16) -> Self {
        Self { assoc_id }
    }

    /// Returns the UDP forward session ID
    pub fn assoc_id(&self) -> u16 {
        self.assoc_id
    }

    /// Returns the command type code
    pub const fn type_code() -> u8 {
        Self::TYPE_CODE
    }

    /// Returns the serialized length of the command
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        2
    }
}

impl From<Dissociate> for (u16,) {
    fn from(dissoc: Dissociate) -> Self {
        (dissoc.assoc_id,)
    }
}
