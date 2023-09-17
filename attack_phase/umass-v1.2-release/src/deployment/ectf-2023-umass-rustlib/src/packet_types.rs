use crate::NUM_FEATURES;
use crate::FEATURE_SIG_PUBKEY;

use core::num::NonZeroU8;

use heapless::Vec;

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
pub const SIGNATURE_SIZE: usize = 64;

// SAFETY: all of these are nonzero
pub(crate) const READY_MAGIC:    NonZeroU8 = unsafe{NonZeroU8::new_unchecked(0x54)};
pub(crate) const _PAIR_MAGIC:    NonZeroU8 = unsafe{NonZeroU8::new_unchecked(0x55)};
pub(crate) const UNLOCK_MAGIC:   NonZeroU8 = unsafe{NonZeroU8::new_unchecked(0x56)};
pub(crate) const START_MAGIC:    NonZeroU8 = unsafe{NonZeroU8::new_unchecked(0x57)};
pub(crate) const SCRAMISH_SUCCESS_MAGIC: NonZeroU8 = unsafe{NonZeroU8::new_unchecked(0x80)};
pub(crate) const SCRAMISH_FAIL_MAGIC: NonZeroU8 = unsafe{NonZeroU8::new_unchecked(0x81)};

pub(crate) trait PacketCore<const N: usize> {
    const SIZE: usize = N;
    fn serialize(&self) -> [u8; N];
    fn deserialize(data: [u8; N]) -> Self;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EnablePacket {
    signature: [u8; SIGNATURE_SIZE],
    car_id: u32,
    feature: u8,
}
impl EnablePacket {
    #[inline(always)]
    pub fn car_id(&self) -> u32 {
        self.car_id
    }
    #[inline(always)]
    pub fn signed_feature(&self) -> SignedFeature {
        SignedFeature { signature: self.signature, feature: self.feature }
    }
    fn serialize_without_signature(&self) -> [u8; 5] {
        let mut retval = [0x0; 5];
        retval[0..4].copy_from_slice(&self.car_id.to_le_bytes());
        retval[4] = self.feature;
        retval
    }
    pub fn verify_signature(&self) -> bool {
        // We encoded the key in SEC1 format in the build process so this should always work
        let pk_obj = VerifyingKey::from_sec1_bytes(FEATURE_SIG_PUBKEY).unwrap();
        let sig_obj = match Signature::try_from(self.signature.as_slice()) {
            Ok(sig) => sig,
            Err(_) => { return false; },
        };
        pk_obj.verify(&self.serialize_without_signature(), &sig_obj).is_ok()
    }
}
impl PacketCore<{ SIGNATURE_SIZE+4+1 }> for EnablePacket {
    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut retval = [0x0; Self::SIZE];
        retval[..SIGNATURE_SIZE].copy_from_slice(&self.signature);
        retval[SIGNATURE_SIZE..SIGNATURE_SIZE+4].copy_from_slice(&self.car_id.to_le_bytes());
        retval[SIGNATURE_SIZE+4] = self.feature;
        retval
    }
    fn deserialize(buf: [u8; Self::SIZE]) -> Self {
        EnablePacket {
            signature: buf[..SIGNATURE_SIZE].try_into().unwrap(),
            car_id : u32::from_le_bytes(buf[SIGNATURE_SIZE..SIGNATURE_SIZE+4].try_into().unwrap()),
            feature : buf[SIGNATURE_SIZE+4]
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedFeature {
    signature: [u8; SIGNATURE_SIZE],
    feature: u8
}
impl SignedFeature {
    // Only used for tests
    #[allow(unused)]
    pub fn new(signature: [u8; SIGNATURE_SIZE], feature: u8) -> Self {
        Self{signature, feature}
    }
    #[inline(always)]
    pub fn feature(&self) -> u8 {
        self.feature
    }
}
impl PacketCore<{ SIGNATURE_SIZE+1 }> for SignedFeature {
    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut retval = [0x00; Self::SIZE];
        retval[..SIGNATURE_SIZE].copy_from_slice(&self.signature);
        retval[SIGNATURE_SIZE] = self.feature;
        retval
    }

    fn deserialize(data: [u8; Self::SIZE]) -> Self {
        Self {
            signature: data[..SIGNATURE_SIZE].try_into().unwrap(),
            feature: data[SIGNATURE_SIZE]
        }
    }
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct FeatureData {
    features: Vec<SignedFeature, NUM_FEATURES>,
}
impl FeatureData {
    #[inline(always)]
    pub fn features(&self) -> &[SignedFeature] {
        &self.features
    }
    /// Inserts a signed feature, checking the signature if car_id is given
    pub fn insert_signed_feature(&mut self, car_id: Option<u32>, signed_feature: SignedFeature) -> bool {
        // Check if the feature list is full.
        if self.features.len() >= NUM_FEATURES {
            // Too many features; do not enable any more.
            return false;
        }
        // Check feature list to see if the feature has already been enabled.
        for existing_feature in self.features.iter() {
            if existing_feature.feature == signed_feature.feature {
                // Feature enabled already.
                return false;
            }
        }

        if let Some(car_id) = car_id {
            // Construct data that would have been signed, and check signature
            let mut signed_data = [0x0; 5];
            signed_data[0..4].copy_from_slice(&car_id.to_le_bytes());
            signed_data[4] = signed_feature.feature;
    
            // We encoded the key in SEC1 format in the build process so this should always work
            let pk_obj = VerifyingKey::from_sec1_bytes(FEATURE_SIG_PUBKEY).unwrap();
            let sig_obj = match Signature::try_from(signed_feature.signature.as_slice()) {
                Ok(sig) => sig,
                Err(_) => { return false; },
            };

            let sig_ok = pk_obj.verify(&signed_data, &sig_obj).is_ok();
            if sig_ok {
                // We already checked above that we have space to insert feature
                self.features.push(signed_feature).unwrap();
            }
            sig_ok
        } else {
            // We already checked above that we have space to insert feature
            self.features.push(signed_feature).unwrap();
            true
        }
    }
    /// Drops incorrectly signed features from the Vec
    pub fn verify_signatures(&mut self, car_id: u32) -> Result<(), NonZeroU8> {
        let mut features_to_drop: Vec<usize, NUM_FEATURES> = Vec::new();

        // We encoded the key in SEC1 format in the build process so this should always work
        let pk_obj = VerifyingKey::from_sec1_bytes(FEATURE_SIG_PUBKEY).unwrap();
        for (i,signed_feature) in self.features.iter().enumerate() {
            let mut signed_data = [0x0; 5];
            signed_data[0..4].copy_from_slice(&car_id.to_le_bytes());
            signed_data[4] = signed_feature.feature;

            // features_to_drop vec has enough space for dropping all features
            let sig_obj = match Signature::try_from(signed_feature.signature.as_slice()) {
                Ok(sig) => sig,
                Err(_) => {
                    features_to_drop.push(i).unwrap();
                    continue;
                },
            };

            if pk_obj.verify(&signed_data, &sig_obj).is_err() {
                features_to_drop.push(i).unwrap();
            }
        }

        let bad_sig_count = features_to_drop.len();
        // Remove in reverse order to preserve indices
        for i in features_to_drop.iter().rev() {
            self.features.remove(*i);
        }
        match bad_sig_count {
            0 => Ok(()),
            val => Err(NonZeroU8::new(val.try_into().unwrap()).unwrap())
        }
    }
}
impl PacketCore<{ 1+(SignedFeature::SIZE)*NUM_FEATURES }> for FeatureData {
    fn serialize(&self) -> [u8; Self::SIZE] {
        // We push a predetermined set of fixed-size [u8]'s into a Vec with exactly the right size
        let mut retval: Vec<_, {Self::SIZE}> = Vec::new();
        retval.push(self.features.len().try_into().unwrap()).unwrap();
        // Add features to vec, then pad out the rest
        for feature in self.features.iter() {
            retval.extend_from_slice(&feature.serialize()).unwrap();
        }
        while retval.len() < Self::SIZE {
            retval.extend([0xFF; SignedFeature::SIZE]);
        }
        assert_eq!(retval.len(), Self::SIZE);
        retval.as_slice().try_into().unwrap()
    }
    fn deserialize(arr: [u8; Self::SIZE]) -> Self {
        let mut len = arr[0];
        if usize::from(len) > NUM_FEATURES {
            // This includes the 0xFF case of uninitialized flash
            len = 0;
        }
        let mut feature_vec = Vec::new();
        for i in 0..len {
            let offset = (SignedFeature::SIZE)*(i as usize) + 1;
            let signed_feature = SignedFeature::deserialize(arr[offset..offset+SIGNATURE_SIZE+1].try_into().unwrap());
            feature_vec.push(signed_feature).unwrap();
        }
        Self {
            features: feature_vec
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use heapless::Vec;

    extern crate std;
    #[test]
    fn verify_enable_packet_roundtrip() {
        let orig_packet = EnablePacket{signature: [0x00; SIGNATURE_SIZE], car_id: 1, feature: 1};
        let serialized = orig_packet.serialize();

        let ret_packet = EnablePacket::deserialize(serialized);
        assert_eq!(orig_packet, ret_packet);

        let mut serialized_copy = serialized.clone();
        serialized_copy[EnablePacket::SIZE-1] = 0xFF;
        let mod_packet = EnablePacket::deserialize(serialized_copy);
        assert_ne!(orig_packet, mod_packet);
    }
    #[test]
    fn verify_feature_data_roundtrip() {
        let mut feature_vec = Vec::<_, NUM_FEATURES>::new();
        for i in 0..NUM_FEATURES {
            feature_vec.push(SignedFeature::new([0x10; SIGNATURE_SIZE], i as u8)).unwrap();
        }
        let orig_packet = FeatureData{features: feature_vec};
        let serialized = orig_packet.serialize();

        let ret_packet = FeatureData::deserialize(serialized);
        assert_eq!(orig_packet, ret_packet);

        let mut serialized_copy = serialized.clone();
        serialized_copy[FeatureData::SIZE-1] = 0xFF;
        let mod_packet = FeatureData::deserialize(serialized_copy);
        assert_ne!(orig_packet, mod_packet);
    }
}
