use super::Encoding;
use crate::NcrError;

/// The mc256 encoding, made by Sharp5s.
///
/// See [No Chat Reports](https://github.com/HKS-HNS/No-Chat-Reports/commit/45327294178fd131732892647fa0e9949aca5cb1).
#[derive(Clone, Copy, Debug)]
pub struct Mc256Encoding;

impl Encoding for Mc256Encoding {
    fn encode(self, text: &[u8]) -> String {
        let mut output = String::new();

        for ch in text {
            output.push(MC256_ENCODE[*ch as usize]);
        }

        output
    }

    fn decode(self, text: &str) -> Result<Vec<u8>, NcrError> {
        let mut output = Vec::new();

        for ch in text.chars() {
            let new_ch = MC256_DECODE.get(&ch).ok_or(NcrError::DecodeError)?;

            output.push(*new_ch as u8);
        }

        Ok(output)
    }
}

#[rustfmt::skip]
const MC256_ENCODE: [char; 256] = [
    '⅛', '⅜', '⅝', '⅞', '⅓', '⅔', '✉', '☂', '☔', '☄', '⛄', '☃', '⚐', '✎', '❣', '♤',
    '♧', '♡', '♢', '⛈', 'ª', 'º', '¬', '«', '»', '░', '▒', '▓', '∅', '∈', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '√', 'ⁿ', '²', '¡', '‰', '\u{AD}', '·', '₴',
    '≠', '×', 'Φ', 'Ψ', 'ι', 'κ', 'λ', 'ο', 'π', 'τ', 'υ', 'φ', 'Я', 'а', 'б', 'в',
    'г', 'д', 'е', 'ж', 'з', 'и', 'к', 'л', 'м', 'н', 'о', 'п', 'р', 'с', 'т', 'у',
    'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я', 'є', 'ѕ', 'і', 'ј',
    '„', '…', '⁊', '←', '↑', '→', '↓', '⇄', '＋', 'Ə', 'ə', 'ɛ', 'ɪ', 'Ү', 'ү', 'Ө',
    'ө', 'ʻ', 'ˌ', ';', 'ĸ', '⁰', '¹', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹', '⁺', '⁻',
    '⁼', '⁽', '⁾', 'ⁱ', '™', '⧈', '⚔', '☠', 'ᴀ', 'ʙ', 'ᴄ', 'ᴅ', 'ᴇ', 'ꜰ', 'ɢ', 'ʜ',
    'ᴊ', 'ᴋ', 'ʟ', 'ᴍ', 'ɴ', 'ᴏ', 'ᴘ', 'ꞯ', 'ʀ', 'ꜱ', 'ᴛ', 'ᴜ', 'ᴠ', 'ᴡ', 'ʏ', 'ᴢ',
    '¢', '¤', '¥', '©', '®', 'µ', '¶', '¼', '½', '¾', '·', '‐', '‚', '†', '‡', '•',
    '‱', '′', '″', '‴', '‵', '‶', '‷', '‹', '›', '※', '‼', '⁂', '⁉', '⁎', '⁑', '⁒',
    '⁗', '℗', '−', '∓', '∞', '☀', '☁', '☈', 'Є', '☲', '☵', '☽', '♀', '♂', '⚥', '♠',
    '♣', '♥', '♦', '♩', '♪', '♫', '♬', '♭', '♮', '♯', '⚀', '⚁', '⚂', '⚃', '⚄', '⚅',
    'ʬ', '⚡', '⛏', '✔', '❄', '❌', '❤', '⭐', '△', '▷', '▽', '◁', '◆', '◇', '○', '◎',
    '☆', '★', '✘', '⸸', '▲', '▶', '▼', '◀', '●', '◦', '◘', '⚓', 'ᛩ', 'ᛪ', '☺', '☻',
];

// Post-expanded macros:

#[rustfmt::skip]
const MC256_DECODE: phf::Map<char, u32> = phf::Map {
    key: 12913932095322966823u64,
    disps: &[
        (0u32, 37u32),  (0u32, 0u32),  (0u32, 136u32),  (0u32, 13u32),
        (1u32, 1u32),  (2u32, 102u32),  (1u32, 11u32),  (0u32, 37u32),
        (0u32, 2u32),  (0u32, 105u32),  (0u32, 2u32),  (0u32, 158u32),
        (0u32, 88u32),  (0u32, 4u32),  (0u32, 116u32),  (1u32, 122u32),
        (0u32, 0u32),  (0u32, 6u32),  (1u32, 122u32),  (0u32, 202u32),
        (4u32, 82u32),  (0u32, 126u32),  (0u32, 10u32),  (0u32, 114u32),
        (0u32, 66u32),  (0u32, 24u32),  (0u32, 71u32),  (0u32, 64u32),
        (0u32, 7u32),  (0u32, 0u32),  (17u32, 170u32),  (0u32, 1u32),
        (0u32, 29u32),  (0u32, 195u32),  (2u32, 97u32),  (1u32, 12u32),
        (0u32, 0u32),  (1u32, 35u32),  (0u32, 74u32),  (0u32, 0u32),
        (1u32, 179u32),  (0u32, 10u32),  (7u32, 200u32),  (0u32, 5u32),
        (0u32, 23u32),  (0u32, 40u32),  (8u32, 59u32),  (4u32, 203u32),
        (3u32, 97u32),  (0u32, 80u32),  (0u32, 96u32),  (3u32, 231u32),
    ],
    entries: &[
        ('ʻ', 113), ('ш', 84), ('✔', 227), ('φ', 59), ('«', 23), ('ο', 55), ('¡', 43), ('ᴢ', 159),
        ('▲', 244), ('☁', 198), ('у', 79), ('Φ', 50), ('‼', 186), ('ᴏ', 149), ('⚂', 220), ('♧', 16),
        ('ɴ', 148), ('♮', 216), ('ᛪ', 253), ('‶', 181), ('ѕ', 93), ('™', 132), ('·', 170), ('о', 74),
        ('≤', 33), ('½', 168), ('⌡', 35), ('\u{AD}', 45), ('⅛', 0), ('ʬ', 224), ('ж', 67), ('∓', 195),
        ('≠', 48), ('‡', 174), ('ᴛ', 154), ('−', 194), ('д', 65), ('ᴘ', 150), ('⭐', 231), ('♬', 214),
        ('ᴍ', 147), ('❤', 230), ('¼', 167), ('ᴋ', 145), ('♥', 209), ('г', 64), ('ᴇ', 140), ('ᴡ', 157),
        ('☵', 202), ('⁷', 123), ('ª', 20), ('♤', 15), ('＋', 104), ('▒', 26), ('ᛩ', 252), ('●', 248),
        ('ь', 88), ('≥', 32), ('✎', 13), ('░', 25), ('❄', 228), ('×', 49), ('ц', 82), ('ф', 80),
        ('⚀', 218), ('⁽', 129), ('⛄', 10), ('ꜰ', 141), ('⁊', 98), ('я', 91), ('•', 175), ('☲', 201),
        ('♡', 17), ('υ', 58), ('→', 101), ('♂', 205), ('⁰', 117), ('‹', 183), ('п', 75), ('‷', 182),
        ('‵', 180), ('☔', 8), ('∅', 28), ('ι', 52), ('ⁱ', 131), ('◁', 235), ('☠', 135), ('¢', 160),
        ('♀', 204), ('☀', 197), ('☺', 254), ('❌', 229), ('ы', 87), ('↓', 102), ('ᴄ', 138), ('◆', 236),
        ('µ', 165), ('‴', 179), ('⅓', 4), ('○', 238), ('⁗', 192), ('♠', 207), ('√', 40), ('⧈', 133),
        ('н', 73), ('ɪ', 108), ('а', 61), ('ɛ', 107), ('ᴠ', 156), ('☄', 9), ('⁑', 190), ('л', 71),
        ('э', 89), ('♩', 211), ('»', 24), ('м', 72), ('⚅', 223), ('⁎', 189), ('т', 78), ('∞', 196),
        ('‐', 171), ('б', 62), ('х', 81), ('ᴅ', 139), ('☽', 203), ('Ψ', 51), ('⸸', 243), ('☈', 199),
        ('♪', 212), ('⅝', 2), ('‚', 172), ('❣', 14), ('◀', 247), ('π', 56), ('⚐', 12), ('з', 68),
        ('†', 173), ('⁹', 125), ('₴', 47), ('≡', 30), ('Ө', 111), (';', 115), ('★', 241), ('±', 31),
        ('κ', 53), ('⅜', 1), ('ʟ', 146), ('↑', 100), ('⚁', 219), ('⅞', 3), ('▼', 246), ('⅔', 5),
        ('♭', 215), ('ʙ', 137), ('△', 232), ('÷', 36), ('⁺', 126), ('ĸ', 116), ('²', 42), ('ꜱ', 153),
        ('∙', 39), ('⚓', 251), ('¶', 166), ('℗', 193), ('º', 21), ('і', 94), ('◦', 249), ('ъ', 86),
        ('ᴊ', 144), ('є', 92), ('р', 76), ('≈', 37), ('ю', 90), ('¬', 22), ('⁻', 127), ('◎', 239),
        ('←', 99), ('※', 185), ('ʀ', 152), ('ᴀ', 136), ('▓', 27), ('∈', 29), ('☻', 255), ('♦', 210),
        ('♣', 208), ('▽', 234), ('и', 69), ('⁼', 128), ('⁒', 191), ('⁴', 120), ('′', 177), ('τ', 57),
        ('⁾', 130), ('ə', 106), ('♢', 18), ('✘', 242), ('³', 119), ('¤', 161), ('Ə', 105), ('⚃', 221),
        ('„', 96), ('¥', 162), ('е', 66), ('ɢ', 142), ('с', 77), ('⁸', 124), ('Ү', 109), ('ꞯ', 151),
        ('©', 163), ('ү', 110), ('⁂', 187), ('▷', 233), ('Є', 200), ('☂', 7), ('⁵', 121), ('›', 184),
        ('ʜ', 143), ('◘', 250), ('¹', 118), ('ᴜ', 155), ('⇄', 103), ('″', 178), ('♫', 213), ('⁶', 122),
        ('⁉', 188), ('Я', 60), ('ʏ', 158), ('ч', 83), ('щ', 85), ('♯', 217), ('⛏', 226), ('¾', 169),
        ('☆', 240), ('в', 63), ('…', 97), ('⚄', 222), ('λ', 54), ('·', 46), ('✉', 6), ('ј', 95),
        ('ⁿ', 41), ('°', 38), ('‱', 176), ('☃', 11), ('⚔', 134), ('⚥', 206), ('▶', 245), ('‰', 44),
        ('ˌ', 114), ('⌠', 34), ('⛈', 19), ('ө', 112), ('⚡', 225), ('◇', 237), ('®', 164), ('к', 70),
    ],
};

// Pre-expanded macros:
// phf = { version = "0.11.1", features = ["macros"] }

// const MC256_DECODE: phf::Map<char, u32> = phf_map! {
//     '⅛' => 0, '⅜' => 1, '⅝' => 2, '⅞' => 3, '⅓' => 4, '⅔' => 5, '✉' => 6, '☂' => 7, '☔' => 8, '☄' => 9,
//     '⛄' => 10, '☃' => 11, '⚐' => 12, '✎' => 13, '❣' => 14, '♤' => 15, '♧' => 16, '♡' => 17, '♢' => 18, '⛈' => 19,
//     'ª' => 20, 'º' => 21, '¬' => 22, '«' => 23, '»' => 24, '░' => 25, '▒' => 26, '▓' => 27, '∅' => 28, '∈' => 29,
//     '≡' => 30, '±' => 31, '≥' => 32, '≤' => 33, '⌠' => 34, '⌡' => 35, '÷' => 36, '≈' => 37, '°' => 38, '∙' => 39,
//     '√' => 40, 'ⁿ' => 41, '²' => 42, '¡' => 43, '‰' => 44, '­' => 45, '·' => 46, '₴' => 47, '≠' => 48, '×' => 49,
//     'Φ' => 50, 'Ψ' => 51, 'ι' => 52, 'κ' => 53, 'λ' => 54, 'ο' => 55, 'π' => 56, 'τ' => 57, 'υ' => 58, 'φ' => 59,
//     'Я' => 60, 'а' => 61, 'б' => 62, 'в' => 63, 'г' => 64, 'д' => 65, 'е' => 66, 'ж' => 67, 'з' => 68, 'и' => 69,
//     'к' => 70, 'л' => 71, 'м' => 72, 'н' => 73, 'о' => 74, 'п' => 75, 'р' => 76, 'с' => 77, 'т' => 78, 'у' => 79,
//     'ф' => 80, 'х' => 81, 'ц' => 82, 'ч' => 83, 'ш' => 84, 'щ' => 85, 'ъ' => 86, 'ы' => 87, 'ь' => 88, 'э' => 89,
//     'ю' => 90, 'я' => 91, 'є' => 92, 'ѕ' => 93, 'і' => 94, 'ј' => 95, '„' => 96, '…' => 97, '⁊' => 98, '←' => 99,
//     '↑' => 100, '→' => 101, '↓' => 102, '⇄' => 103, '＋' => 104, 'Ə' => 105, 'ə' => 106, 'ɛ' => 107, 'ɪ' => 108, 'Ү' => 109,
//     'ү' => 110, 'Ө' => 111, 'ө' => 112, 'ʻ' => 113, 'ˌ' => 114, ';' => 115, 'ĸ' => 116, '⁰' => 117, '¹' => 118, '³' => 119,
//     '⁴' => 120, '⁵' => 121, '⁶' => 122, '⁷' => 123, '⁸' => 124, '⁹' => 125, '⁺' => 126, '⁻' => 127, '⁼' => 128, '⁽' => 129,
//     '⁾' => 130, 'ⁱ' => 131, '™' => 132, '⧈' => 133, '⚔' => 134, '☠' => 135, 'ᴀ' => 136, 'ʙ' => 137, 'ᴄ' => 138, 'ᴅ' => 139,
//     'ᴇ' => 140, 'ꜰ' => 141, 'ɢ' => 142, 'ʜ' => 143, 'ᴊ' => 144, 'ᴋ' => 145, 'ʟ' => 146, 'ᴍ' => 147, 'ɴ' => 148, 'ᴏ' => 149,
//     'ᴘ' => 150, 'ꞯ' => 151, 'ʀ' => 152, 'ꜱ' => 153, 'ᴛ' => 154, 'ᴜ' => 155, 'ᴠ' => 156, 'ᴡ' => 157, 'ʏ' => 158, 'ᴢ' => 159,
//     '¢' => 160, '¤' => 161, '¥' => 162, '©' => 163, '®' => 164, 'µ' => 165, '¶' => 166, '¼' => 167, '½' => 168, '¾' => 169,
//     '·' => 170, '‐' => 171, '‚' => 172, '†' => 173, '‡' => 174, '•' => 175, '‱' => 176, '′' => 177, '″' => 178, '‴' => 179,
//     '‵' => 180, '‶' => 181, '‷' => 182, '‹' => 183, '›' => 184, '※' => 185, '‼' => 186, '⁂' => 187, '⁉' => 188, '⁎' => 189,
//     '⁑' => 190, '⁒' => 191, '⁗' => 192, '℗' => 193, '−' => 194, '∓' => 195, '∞' => 196, '☀' => 197, '☁' => 198, '☈' => 199,
//     'Є' => 200, '☲' => 201, '☵' => 202, '☽' => 203, '♀' => 204, '♂' => 205, '⚥' => 206, '♠' => 207, '♣' => 208, '♥' => 209,
//     '♦' => 210, '♩' => 211, '♪' => 212, '♫' => 213, '♬' => 214, '♭' => 215, '♮' => 216, '♯' => 217, '⚀' => 218, '⚁' => 219,
//     '⚂' => 220, '⚃' => 221, '⚄' => 222, '⚅' => 223, 'ʬ' => 224, '⚡' => 225, '⛏' => 226, '✔' => 227, '❄' => 228, '❌' => 229,
//     '❤' => 230, '⭐' => 231, '△' => 232, '▷' => 233, '▽' => 234, '◁' => 235, '◆' => 236, '◇' => 237, '○' => 238, '◎' => 239,
//     '☆' => 240, '★' => 241, '✘' => 242, '⸸' => 243, '▲' => 244, '▶' => 245, '▼' => 246, '◀' => 247, '●' => 248, '◦' => 249,
//     '◘' => 250, '⚓' => 251, 'ᛩ' => 252, 'ᛪ' => 253, '☺' => 254, '☻' => 255,
// };
