use ectf::security::constant_time;

#[derive(Clone, Copy)]
pub struct FeatureMessage {
    msg: [u8; 0x40],
}

impl IntoIterator for FeatureMessage {
    type Item = u8;
    type IntoIter = <[u8; 0x40] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.msg.into_iter()
    }
}

impl PartialEq for FeatureMessage {
    fn eq(&self, other: &Self) -> bool {
        constant_time::bytes_equal(&self.msg, &other.msg)
    }
}
