ERROR_DICT = {
	0x1000: 'comms::Error::InvalidNonce',
	0x1001: 'comms::Error::PinError',
	0x1002: 'comms::Error::InvalidMessageIDError',
	0x1003: 'comms::Error::InvalidSignature',
	0x1004: 'comms::Error::CryptoError',
	0x1005: 'comms::Error::MalformedMessageError',
    
	0x3000: 'fob::FeatureEnableError::NoSlotAvailable',
	0x3001: 'fob::FeatureEnableError::InvalidCarID',
	0x3002: 'fob::FeatureEnableError::AlreadyEnabled',
	0x3003: 'fob::FeatureEnableError::InvalidSignature',

    0x4000: 'fob::PairingError::MalformedPIN',
    0x4001: 'fob::PairingError::IncorrectPIN',
    0x4002: 'fob::PairingError::FobNotPaired',
    0x4003: 'fob::PairingError::FobAlreadyPaired',
    
	0x5000: 'car::UnlockError::IncorrectPassword',
	0x5002: 'car::UnlockError::IncorrectCarID',
    
	0x6000: 'car::StartError::IncorrectCarID',
    
	0x7000: 'fob::StartError::ProtocolFailure',
    
	0xDEAC: 'comms::io::Error::InvalidAcknowledgement',
	0xDEAD: 'comms::io::Error::TimedOut',
}

def translate_error(code: int) -> str:
    return ERROR_DICT.get(code) or f'0x{code:X}'