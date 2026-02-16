use std::str::FromStr;

use crate::crypto::CryptoError;

#[derive(Clone, Copy, Debug)]
pub enum HandshakePattern {
    NN,
    NK,
    NX,
    KK,
    KN,
    KX,
    XN,
    XK,
    XX,
    IN,
    IK,
    IX,
}

impl HandshakePattern {
    pub(crate) fn handshake_desc(&self) -> &'static HandshakePatternDesc {
        match self {
            HandshakePattern::NN => &NN_HANDSHAKE,
            HandshakePattern::NK => &NK_HANDSHAKE,
            HandshakePattern::NX => &NX_HANDSHAKE,
            HandshakePattern::KK => &KK_HANDSHAKE,
            HandshakePattern::KN => &KN_HANDSHAKE,
            HandshakePattern::KX => &KX_HANDSHAKE,
            HandshakePattern::XN => &XN_HANDSHAKE,
            HandshakePattern::XK => &XK_HANDSHAKE,
            HandshakePattern::XX => &XX_HANDSHAKE,
            HandshakePattern::IN => &IN_HANDSHAKE,
            HandshakePattern::IK => &IK_HANDSHAKE,
            HandshakePattern::IX => &IX_HANDSHAKE,
        }
    }

    pub fn name(&self) -> &'static str {
        self.handshake_desc().name
    }

    
    /// Returns true if this handshake authenticates with long-term keys
    /// for the (initiator, responder).
    pub fn is_authenticating(self) -> (bool, bool) {
        let init_auth = match self {
            HandshakePattern::NN |
            HandshakePattern::NK |
            HandshakePattern::NX => false,
            _ => true,
        };
        let resp_auth = match self {
            HandshakePattern::NN |
            HandshakePattern::KN |
            HandshakePattern::XN |
            HandshakePattern::IN => false,
            _ => true,
        };
        (init_auth, resp_auth)
    }
}

pub(crate) const ALL_HANDSHAKE_PATTERNS: &'static [HandshakePattern] = &[
    HandshakePattern::NN, HandshakePattern::NK, HandshakePattern::NX,
    HandshakePattern::KN, HandshakePattern::KK, HandshakePattern::KX,
    HandshakePattern::XN, HandshakePattern::XK, HandshakePattern::XX,
    HandshakePattern::IN, HandshakePattern::IK, HandshakePattern::IX,
];

#[derive(Clone, Copy, Debug)]
pub enum HandshakeModifier {
    /// Hybrid Forward Security
    /// 
    /// See:
    /// https://github.com/noiseprotocol/noise_hfs_spec/blob/master/output/noise_hfs.pdf
    Hfs,

    /// Pre-shared Symmetric Key
    /// 
    /// See:
    /// https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys
    Psk (PskPosition),
}

#[derive(Clone, Copy, Debug)]
pub enum PskPosition {
    Psk0,
    Psk1,
    Psk2,
    Psk3,
    Psk4,
}

#[derive(Copy, Clone, Default)]
struct Modifiers {
    modifier_bits: u8,
}

impl Modifiers {
    const PSK_0_BIT: u8 = 0x01;
    const PSK_1_BIT: u8 = 0x02;
    const PSK_2_BIT: u8 = 0x04;
    const PSK_3_BIT: u8 = 0x08;
    const PSK_4_BIT: u8 = 0x10;
    const HFS_BIT:   u8 = 0x20;
    const PSK_ANY:   u8 = 0x1F;

    fn bit(modifier: HandshakeModifier) -> u8 {
        match modifier {
            HandshakeModifier::Hfs => Self::HFS_BIT,
            HandshakeModifier::Psk(PskPosition::Psk0) => Self::PSK_0_BIT,
            HandshakeModifier::Psk(PskPosition::Psk1) => Self::PSK_1_BIT,
            HandshakeModifier::Psk(PskPosition::Psk2) => Self::PSK_2_BIT,
            HandshakeModifier::Psk(PskPosition::Psk3) => Self::PSK_3_BIT,
            HandshakeModifier::Psk(PskPosition::Psk4) => Self::PSK_4_BIT,
        }
    }

    pub fn add(&mut self, modifier: HandshakeModifier) {
        self.modifier_bits |= Self::bit(modifier);
    }

    pub fn has(&self, modifier: HandshakeModifier) -> bool {
        let bit = Self::bit(modifier);
        self.modifier_bits & bit == bit
    }

    pub fn has_psk(&self) -> bool {
        self.modifier_bits & Self::PSK_ANY != 0
    }
}

impl FromStr for Modifiers {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // todo, psk/hfs
        if s == "" {
            Ok(Self::default())
        } else if s == "psk" {
            let mut this = Self::default();
            this.add(HandshakeModifier::Psk(PskPosition::Psk1));
            Ok(this)
        } else {
            Err(CryptoError::UnsupportedProtocol)
        }
    }
}

#[derive(Copy, Clone)]
pub struct HandshakeParams {
    pattern: HandshakePattern,
    modifiers: Modifiers,
}

impl HandshakeParams {
    pub fn pattern(&self) -> HandshakePattern {
        self.pattern
    }

    pub fn has_modifier_hfs(&self) -> bool {
        self.modifiers.has(HandshakeModifier::Hfs)
    }

    /// Returns true if the handshake has a PSK at `position` or in any
    /// position if `None`.
    pub fn has_modifier_psk(&self, position: Option<PskPosition>) -> bool {
        match position {
            Some(p) => self.modifiers.has(HandshakeModifier::Psk(p)),
            None => self.modifiers.has_psk()
        }
    }

    fn message_iter(&self) -> impl Iterator<Item = &'static [Token]> {
        let modifiers = self.modifiers;
        let messages = self.pattern.handshake_desc().messages;
        messages
            .iter()
            .copied()
            // Filter out messages with no active tokens.
            .filter(move |tokens| {
                for token in tokens.iter() {
                    if token.used_with_modifiers(modifiers) {
                        return true;
                    }
                }
                false
            })

    }

    pub(crate) fn message_count(&self) -> usize {
        self.message_iter().count()
    }
    
    pub(crate) fn message_token_iter(&self, pattern_pos: usize) -> Result<impl Iterator<Item = Token>, CryptoError> {
        let modifiers = self.modifiers;
        self.message_iter()
            .nth(pattern_pos)
            .ok_or(CryptoError::Internal)
            .map(move |message_tokens| message_tokens.iter().copied().filter(move |token| token.used_with_modifiers(modifiers)))
    }
}

impl FromStr for HandshakeParams {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let modifiers_start_at = s.find(|c| {
            match c {
                'A'..='Z' => false,
                '0'..='9' => false,
                _ => true,
            }
        }).unwrap_or(s.len());

        let handshake_pattern_s = &s[0..modifiers_start_at];
        let handshake_modifiers_s = &s[modifiers_start_at..];

        let pattern =
            ALL_HANDSHAKE_PATTERNS
            .iter()
            .find(|pattern| pattern.handshake_desc().name == handshake_pattern_s)
            .ok_or(CryptoError::InvalidProtocol)?
            .to_owned();

        Ok(Self {
            pattern,
            modifiers: handshake_modifiers_s.parse()?,
        })
    }
}

/// Parse a Noise protocol name into `(HandshakeParams, diffie_hellman: &str, aead: &str, hash: &str)`.
pub(crate) fn parse_protocol_name(protocol_name: &str) -> Result<(HandshakeParams, &str, &str, &str), CryptoError> {
    let mut split = protocol_name.split('_');
    let prefix = split.next().ok_or(CryptoError::InvalidProtocol)?;
    if prefix != "Noise" {
        return Err(CryptoError::InvalidProtocol);
    }
    let handshake = split.next().ok_or(CryptoError::InvalidProtocol)?;
    let diffie_hellman = split.next().ok_or(CryptoError::InvalidProtocol)?;
    let cipher = split.next().ok_or(CryptoError::InvalidProtocol)?;
    let hash = split.next().ok_or(CryptoError::InvalidProtocol)?;
    if split.next().is_some() {
        return Err(CryptoError::InvalidProtocol);
    }

    Ok((handshake.parse()?, diffie_hellman, cipher, hash))
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Token {
    E,
    S,
    DhEE,
    DhES,
    DhSE,
    DhSS,
    Psk (PskPosition),
}

impl Token {
    pub(self) fn used_with_modifiers(self, modifiers: Modifiers) -> bool {
        match self {
            Token::Psk(pos) => modifiers.has(HandshakeModifier::Psk(pos)),
            _ => true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PreMessageTokens {
    Empty,
    S,
}

pub(crate) struct HandshakePatternDesc {
    pub name: &'static str,
    pub pre_message_init: PreMessageTokens,
    pub pre_message_resp: PreMessageTokens,
    pub messages: &'static [&'static [Token]],
}

const NN_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "NN",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::Psk(PskPosition::Psk2)],
    ],
};

const NK_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "NK",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::S,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::DhES, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::Psk(PskPosition::Psk2)],
    ],
};

const NX_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "NX",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::S, Token::DhES, Token::Psk(PskPosition::Psk2)],
    ],
};

const KN_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "KN",
    pre_message_init: PreMessageTokens::S,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::DhSE, Token::Psk(PskPosition::Psk2)],
    ],
};

const KK_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "KK",
    pre_message_init: PreMessageTokens::S,
    pre_message_resp: PreMessageTokens::S,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::DhES, Token::DhSS, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::DhSE, Token::Psk(PskPosition::Psk2)],
    ],
};

const KX_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "KX",
    pre_message_init: PreMessageTokens::S,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::DhSE, Token::S, Token::DhES, Token::Psk(PskPosition::Psk2)],
    ],
};

const XN_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "XN",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::Psk(PskPosition::Psk2)],
        &[Token::S, Token::DhSE, Token::Psk(PskPosition::Psk3)]
    ],
};

const XK_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "XK",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::S,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::DhES, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::Psk(PskPosition::Psk2)],
        &[Token::S, Token::DhSE, Token::Psk(PskPosition::Psk3)]
    ],
};

const XX_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "XX",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::S, Token::DhES, Token::Psk(PskPosition::Psk2)],
        &[Token::S, Token::DhSE, Token::Psk(PskPosition::Psk3)]
    ],
};


const IN_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "IN",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::S, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::DhSE, Token::Psk(PskPosition::Psk2)],
    ],
};

const IK_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "IK",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::S,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::DhES, Token::S, Token::DhSS, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::DhSE, Token::Psk(PskPosition::Psk2)],
    ],
};

const IX_HANDSHAKE: HandshakePatternDesc = HandshakePatternDesc {
    name: "IX",
    pre_message_init: PreMessageTokens::Empty,
    pre_message_resp: PreMessageTokens::Empty,
    messages: &[
        &[Token::Psk(PskPosition::Psk0), Token::E, Token::S, Token::Psk(PskPosition::Psk1)],
        &[Token::E, Token::DhEE, Token::DhSE, Token::S, Token::DhES, Token::Psk(PskPosition::Psk2)],
    ],
};
