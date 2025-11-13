// decompress.cpp    (no zlib, no tinfl, no sudo required)
//
// Supports: uncompressed RBZ1 native container produced by the python function above.
// Optional: PNG if stb_image.h is present (you can omit stb_image.h and PNG support).
//
// Provides:
//   bool decompress_to_rgb(const unsigned char* data, size_t size,
//                          int& out_w, int& out_h, std::vector<unsigned char>& out_rgb);
//
// Also contains a small CLI main() for testing:
//   ./decompress input.rbz output.bmp
//
// Compile:
//   g++ -O2 -std=c++17 decompress.cpp -o decompress
//

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

static inline uint32_t read_le_u32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Try native RBZ1 uncompressed reader
bool try_decompress_native_RBZ1_uncompressed(const unsigned char* data, size_t size,
                                             int& out_w, int& out_h,
                                             std::vector<unsigned char>& out_rgb)
{
    // header: 4 + 4 + 4 +1 +1 +2 +4 +4 = 24 bytes
    if (size < 24) return false;
    if (std::memcmp(data, "RBZ1", 4) != 0) return false;

    const unsigned char* p = data + 4;
    uint32_t w = read_le_u32(p); p += 4;
    uint32_t h = read_le_u32(p); p += 4;
    unsigned ver = p[0]; p += 1;
    unsigned ch  = p[0]; p += 1;
    p += 2; // reserved
    uint32_t ulen = read_le_u32(p); p += 4;
    uint32_t clen = read_le_u32(p); p += 4;

    // This implementation expects uncompressed payload when clen == 0
    if (ver != 1 || ch != 3) return false;
    const unsigned char* payload = p;
    size_t payload_len = size - (p - data);

    if (clen != 0) {
        // We do not support compressed RBZ in this build (no zlib). Fail gracefully.
        return false;
    }

    if (payload_len < (size_t)ulen) return false; // truncated
    size_t n = (size_t)w * (size_t)h;
    if (ulen != n * 3) return false;

    // payload layout: [R-plane][G-plane][B-plane]
    const unsigned char* R = payload;
    const unsigned char* G = payload + n;
    const unsigned char* B = payload + 2 * n;

    out_w = (int)w;
    out_h = (int)h;
    out_rgb.resize(n * 3);
    for (size_t i = 0; i < n; ++i) {
        out_rgb[3*i + 0] = R[i];
        out_rgb[3*i + 1] = G[i];
        out_rgb[3*i + 2] = B[i];
    }
    return true;
}

#ifdef HAVE_STB_IMAGE
// If you want PNG fallback, compile with -DHAVE_STB_IMAGE and place stb_image.h next to this file.
// Example: g++ -O2 -std=c++17 -DHAVE_STB_IMAGE decompress.cpp -o decompress
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#include "stb_image.h"

bool try_decompress_png(const unsigned char* data, size_t size,
                        int& out_w, int& out_h, std::vector<unsigned char>& out_rgb)
{
    int w=0,h=0,ch=0;
    unsigned char* img = stbi_load_from_memory(data, (int)size, &w, &h, &ch, 3);
    if (!img) return false;
    out_w = w; out_h = h;
    out_rgb.assign(img, img + (size_t)w * (size_t)h * 3);
    stbi_image_free(img);
    return true;
}
#endif

bool decompress_to_rgb(const unsigned char* data, size_t size,
                       int& out_w, int& out_h, std::vector<unsigned char>& out_rgb)
{
    if (try_decompress_native_RBZ1_uncompressed(data, size, out_w, out_h, out_rgb)) return true;
#ifdef HAVE_STB_IMAGE
    if (try_decompress_png(data, size, out_w, out_h, out_rgb)) return true;
#endif
    return false;
}

// Write a 24-bit BMP (bottom-up, padded rows)
std::vector<unsigned char> encode_bmp_24(const unsigned char* rgb, int w, int h)
{
    int row_stride_rgb = w * 3;
    int pad = (4 - (row_stride_rgb % 4)) & 3;
    int row_stride_bmp = row_stride_rgb + pad;
    int pixel_bytes = row_stride_bmp * h;
    int filesize = 54 + pixel_bytes;
    std::vector<unsigned char> out(filesize, 0);

    out[0] = 'B'; out[1] = 'M';
    out[2] = (unsigned char)(filesize      );
    out[3] = (unsigned char)(filesize >> 8 );
    out[4] = (unsigned char)(filesize >> 16);
    out[5] = (unsigned char)(filesize >> 24);
    out[10] = 54;

    out[14] = 40; // info header size
    out[18] = (unsigned char)( w       );
    out[19] = (unsigned char)((w >> 8) );
    out[20] = (unsigned char)((w >> 16));
    out[21] = (unsigned char)((w >> 24));
    out[22] = (unsigned char)( h       );
    out[23] = (unsigned char)((h >> 8) );
    out[24] = (unsigned char)((h >> 16));
    out[25] = (unsigned char)((h >> 24));
    out[26] = 1;  // planes
    out[28] = 24; // bpp

    unsigned char* dst = out.data() + 54;
    for (int y = 0; y < h; ++y) {
        const unsigned char* src = rgb + (size_t)(h - 1 - y) * row_stride_rgb;
        for (int x = 0; x < w; ++x) {
            dst[0] = src[3*x + 2]; // B
            dst[1] = src[3*x + 1]; // G
            dst[2] = src[3*x + 0]; // R
            dst += 3;
        }
        for (int p = 0; p < pad; ++p) *dst++ = 0;
    }
    return out;
}

// --------- Small CLI main for testing ----------
int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " input.(rbz|png) output.bmp\n";
        return 1;
    }
    std::ifstream ifs(argv[1], std::ios::binary);
    if (!ifs) { std::cerr << "Open failed: " << argv[1] << "\n"; return 2; }
    std::vector<unsigned char> filebytes((std::istreambuf_iterator<char>(ifs)), {});
    ifs.close();

    int w=0,h=0;
    std::vector<unsigned char> rgb;
    if (!decompress_to_rgb(filebytes.data(), filebytes.size(), w, h, rgb)) {
        std::cerr << "Decompress failed or unsupported format. If input is compressed RBZ, use uncompressed RBZ.\n";
        return 3;
    }

    std::vector<unsigned char> bmp = encode_bmp_24(rgb.data(), w, h);
    std::ofstream ofs(argv[2], std::ios::binary);
    ofs.write((char*)bmp.data(), bmp.size());
    ofs.close();
    std::cout << "Wrote " << argv[2] << " (" << w << "x" << h << ")\n";
    return 0;
}
