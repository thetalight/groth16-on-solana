use crate::Groth16VerifyingKeyPrepared;

pub const VERIFIER_KEY: Groth16VerifyingKeyPrepared = Groth16VerifyingKeyPrepared {
    vk_alpha_g1: [
        12, 131, 7, 68, 183, 107, 59, 74, 204, 114, 251, 232, 67, 238, 169, 85, 171, 255, 21, 199,
        151, 182, 8, 109, 48, 37, 60, 133, 40, 22, 188, 138, 21, 17, 197, 111, 253, 87, 214, 141,
        122, 38, 9, 245, 131, 142, 75, 98, 10, 91, 231, 45, 244, 143, 225, 132, 122, 242, 205, 170,
        92, 40, 113, 195,
    ],
    vk_beta_g2: [
        9, 149, 216, 90, 85, 144, 144, 1, 41, 218, 169, 45, 170, 127, 82, 207, 53, 250, 127, 242,
        68, 186, 133, 112, 217, 172, 197, 144, 28, 52, 171, 203, 25, 5, 52, 16, 150, 203, 247, 41,
        72, 227, 230, 12, 172, 213, 90, 208, 26, 172, 137, 21, 11, 91, 25, 190, 246, 46, 170, 166,
        20, 137, 220, 99, 175, 227, 223, 244, 209, 18, 129, 127, 44, 193, 25, 170, 117, 162, 126,
        10, 169, 36, 184, 225, 228, 21, 3, 71, 51, 222, 47, 32, 107, 166, 153, 217, 46, 247, 226,
        109, 2, 129, 46, 173, 179, 245, 177, 74, 180, 55, 194, 198, 3, 247, 116, 160, 104, 80, 39,
        166, 235, 235, 83, 1, 201, 101, 68, 107,
    ],
    vk_gamma_g2: [
        7, 176, 200, 104, 168, 47, 116, 33, 191, 174, 88, 193, 186, 153, 42, 238, 126, 12, 221, 84,
        189, 26, 91, 140, 82, 31, 16, 165, 129, 233, 223, 97, 1, 247, 20, 125, 217, 23, 245, 1, 69,
        255, 21, 247, 36, 202, 58, 27, 24, 66, 27, 52, 203, 44, 174, 44, 171, 127, 225, 20, 180,
        170, 69, 84, 159, 177, 246, 177, 207, 139, 114, 136, 218, 118, 171, 77, 121, 172, 221, 47,
        139, 51, 162, 223, 129, 155, 243, 240, 220, 215, 228, 28, 60, 250, 218, 96, 26, 16, 13,
        153, 165, 75, 127, 211, 244, 58, 89, 42, 221, 165, 122, 231, 48, 52, 109, 171, 13, 113, 89,
        242, 58, 51, 73, 238, 154, 37, 169, 236,
    ],
    vk_delta_g2: [
        37, 231, 66, 210, 150, 193, 99, 233, 112, 115, 132, 62, 89, 46, 127, 187, 230, 144, 58,
        182, 97, 212, 9, 53, 162, 64, 116, 253, 57, 83, 215, 17, 24, 8, 146, 35, 84, 120, 231, 132,
        224, 93, 42, 79, 183, 212, 210, 10, 24, 164, 211, 29, 185, 212, 11, 230, 231, 86, 200, 255,
        103, 168, 31, 193, 9, 42, 1, 87, 210, 178, 137, 55, 249, 8, 170, 164, 250, 155, 67, 196,
        253, 50, 33, 114, 61, 138, 254, 72, 71, 30, 230, 95, 169, 1, 4, 158, 0, 129, 20, 214, 237,
        244, 65, 213, 241, 107, 45, 204, 123, 108, 82, 35, 102, 159, 56, 140, 92, 27, 162, 224,
        177, 184, 154, 233, 38, 191, 178, 181,
    ],
    vk_ic: [
        [
            17, 50, 247, 232, 13, 133, 87, 249, 69, 178, 142, 166, 125, 36, 68, 195, 244, 193, 231,
            162, 46, 87, 196, 2, 136, 184, 131, 247, 177, 69, 162, 127, 155, 16, 99, 6, 167, 248,
            83, 66, 251, 206, 119, 164, 109, 39, 110, 214, 5, 34, 158, 39, 156, 141, 206, 95, 178,
            120, 183, 184, 221, 184, 182, 195,
        ],
        [
            25, 86, 152, 249, 156, 49, 182, 196, 200, 47, 95, 74, 151, 131, 212, 120, 40, 181, 39,
            224, 232, 213, 72, 89, 126, 8, 183, 103, 26, 111, 223, 153, 17, 237, 77, 112, 64, 212,
            155, 14, 53, 12, 30, 180, 141, 88, 120, 17, 253, 63, 241, 239, 45, 121, 188, 229, 211,
            40, 67, 53, 115, 167, 53, 237,
        ],
    ],
};
