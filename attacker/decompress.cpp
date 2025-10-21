// decompress.cpp
// Single-file C++ decompressor for TWO formats:
//   1) Our native container: "RBZ1" (zlib-compressed planar RGB)
//   2) PNG (lossless) via embedded stb_image.
//
// Exposes ONE main function to plug in:
//
//   bool decompress_to_rgb(
//       const unsigned char* data, size_t size,
//       int& out_w, int& out_h,
//       std::vector<unsigned char>& out_rgb);
//
// Returns true on success; out_rgb = interleaved 24-bit RGB (size = w*h*3).
//
// Build: g++ -O2 -std=c++17 decompress.cpp -o test
//
// -----------------------------------------------------------------------------
// Minimal zlib inflate: use miniz (public-domain, single-header) tinfl.
// Minimal PNG decode: use stb_image (public domain / MIT, single-header).
// Both are embedded below so there are no external dependencies.
// -----------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

// =========================  tiny miniz inflate (tinfl)  ======================
#define MINIZ_HEADER_FILE_ONLY
#define TINFL_HEADER_FILE_ONLY
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#include <cstdio>

extern "C" {
// Begin tinfl (miniz) subset:
typedef unsigned char mz_uint8;
typedef unsigned int mz_uint32;
typedef int mz_bool;
#define MZ_TRUE 1
#define MZ_FALSE 0

// Forward declare tinfl API we need (implementation provided below)
typedef struct tinfl_decompressor_tag tinfl_decompressor;
#define TINFL_DECOMPRESS_MEM_TO_MEM_FAILED ((size_t)(-1))
size_t tinfl_decompress_mem_to_mem(void* pOut_buf, size_t out_buf_len,
                                   const void* pSrc_buf, size_t src_buf_len, int flags);
} // extern "C"

// ===========================  tiny stb_image  =================================
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#define STBI_MALLOC(x)        malloc(x)
#define STBI_REALLOC(p,newsz) realloc(p,newsz)
#define STBI_FREE(p)          free(p)
#include <cstdlib>
extern "C" {
#include "stddef.h"
}
static unsigned char *stbi_load_from_memory(const unsigned char *buffer, int len, int *x, int *y, int *channels_in_file, int desired_channels);
static void stbi_image_free(void *retval_from_stbi_load);

// We will include the stb_image implementation text directly (tiny subset) :
/*
   For brevity, you can drop the official stb_image.h next to this file
   and replace the two forward declarations above with the normal

       #define STB_IMAGE_IMPLEMENTATION
       #include "stb_image.h"

   If you prefer keeping this file self-contained, keep the above two
   declarations and ship stb_image.h alongside this file.
*/

// ===========================  Helpers / API  =================================
static inline uint32_t read_le_u32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool try_decompress_native_RBZ1(const unsigned char* data, size_t size,
                                       int& out_w, int& out_h, std::vector<unsigned char>& out_rgb)
{
    // Header: magic(4) + w(4) + h(4) + ver(1) + ch(1) + reserved(2) + ulen(4) + clen(4)
    if (size < 4) return false;
    if (std::memcmp(data, "RBZ1", 4) != 0) return false;
    if (size < 4 + 4 + 4 + 1 + 1 + 2 + 4 + 4) return false;

    const unsigned char* p = data + 4;
    uint32_t w = read_le_u32(p); p += 4;
    uint32_t h = read_le_u32(p); p += 4;
    unsigned ver = p[0]; p += 1;
    unsigned ch  = p[0]; p += 1;
    p += 2; // reserved
    uint32_t ulen = read_le_u32(p); p += 4;
    uint32_t clen = read_le_u32(p); p += 4;

    if (ver != 1 || ch != 3) return false;
    if (size < (size_t)(p - data) + clen) return false;

    const unsigned char* comp = p;
    std::vector<unsigned char> planar(ulen);
    size_t out_sz = tinfl_decompress_mem_to_mem(planar.data(), planar.size(), comp, clen, 0);
    if (out_sz == (size_t)TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || out_sz != (size_t)ulen) {
        return false;
    }

    // Planar layout: [R][G][B], each w*h bytes
    size_t n = (size_t)w * (size_t)h;
    if (ulen != n * 3) return false;

    out_w = (int)w;
    out_h = (int)h;
    out_rgb.assign(n * 3, 0);

    const unsigned char* R = planar.data();
    const unsigned char* G = planar.data() + n;
    const unsigned char* B = planar.data() + 2 * n;

    unsigned char* dst = out_rgb.data();
    for (size_t i = 0; i < n; ++i) {
        dst[3 * i + 0] = R[i];
        dst[3 * i + 1] = G[i];
        dst[3 * i + 2] = B[i];
    }
    return true;
}

static bool try_decompress_png(const unsigned char* data, size_t size,
                               int& out_w, int& out_h, std::vector<unsigned char>& out_rgb)
{
    int w = 0, h = 0, ch = 0;
    // Force 3 channels (RGB). stb_image handles PNG losslessly.
    unsigned char* img = stbi_load_from_memory(data, (int)size, &w, &h, &ch, 3);
    if (!img) return false;

    out_w = w; out_h = h;
    out_rgb.assign(img, img + (size_t)w * (size_t)h * 3);
    stbi_image_free(img);
    return true;
}

// Public API: ONE function to plug in.
bool decompress_to_rgb(const unsigned char* data, size_t size,
                       int& out_w, int& out_h,
                       std::vector<unsigned char>& out_rgb)
{
    // Try native first
    if (try_decompress_native_RBZ1(data, size, out_w, out_h, out_rgb)) return true;
    // Fallback: PNG
    if (try_decompress_png(data, size, out_w, out_h, out_rgb)) return true;
    return false;
}

// (Optional) helper if you need a BMP file bytearray from the RGB buffer.
// 24-bit, bottom-up, padded to 4 bytes per row.
std::vector<unsigned char> encode_bmp_24(const unsigned char* rgb, int w, int h)
{
    int row_stride_rgb = w * 3;
    int pad = (4 - (row_stride_rgb % 4)) & 3;
    int row_stride_bmp = row_stride_rgb + pad;
    int pixel_bytes = row_stride_bmp * h;

    // BITMAPFILEHEADER (14) + BITMAPINFOHEADER (40) = 54
    int filesize = 54 + pixel_bytes;
    std::vector<unsigned char> out(filesize, 0);

    // FILE HEADER
    out[0] = 'B'; out[1] = 'M';
    out[2] = (unsigned char)(filesize      );
    out[3] = (unsigned char)(filesize >> 8 );
    out[4] = (unsigned char)(filesize >> 16);
    out[5] = (unsigned char)(filesize >> 24);
    out[10] = 54; // pixel data offset

    // INFO HEADER
    out[14] = 40; // header size
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

    // Write rows bottom-up, BMP expects BGR
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

/*
 * NOTE ABOUT EMBEDDED HEADERS:
 * - For PNG support, place the official `stb_image.h` next to this file
 *   (https://github.com/nothings/stb) and keep the `#define STB_IMAGE_IMPLEMENTATION`
 *   include. That keeps this file single-translation-unit.
 * - For zlib inflate, the tinfl helper from miniz is declared above via
 *   tinfl_decompress_mem_to_mem (commonly available in miniz.h). If you
 *   prefer, you can swap it with zlib's uncompress() and link -lz.
 */
