#include "../devices/pvg_texture_copy.h"
#include <assert.h>
#include <stdio.h>

static uint64_t rng = 0x817dc9574bb1cc43ULL;
static uint64_t next(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static bool span_oracle(uint64_t w, uint64_t h, uint64_t bpp, uint64_t off, uint64_t row, uint64_t length) {
    __uint128_t visible = (__uint128_t)w * bpp;
    return w && h && bpp && row && off <= length && visible <= row &&
           (__uint128_t)(h - 1) * row + visible <= length - off;
}

int main(void) {
    /* Synthetic inputs from the affected size/format classes, no user pixels. */
    assert(hv_pvg_texture_copy_layout(12, 3, 8, 0, 96, 288));
    assert(hv_pvg_texture_copy_layout(12, 3, 8, 32, 96, 16384));
    assert(hv_pvg_texture_copy_layout(38, 26, 4, 0, 160, 16384));
    assert(hv_pvg_texture_copy_layout(19, 14, 4, 0, 96, 16384));
    assert(hv_pvg_texture_copy_layout(3, 56, 4, 0, 32, 16384));
    assert(hv_pvg_texture_copy_layout(160, 7, 2, 0, 352, 16384));
    /* No padding is needed after the last visible pixel of a copy. */
    assert(hv_pvg_texture_copy_layout(3, 2, 4, 16, 32, 60));
    assert(!hv_pvg_texture_copy_layout(3, 2, 4, 16, 32, 59));
    assert(!hv_pvg_texture_copy_layout(12, 3, 8, 0, 80, 16384));
    assert(!hv_pvg_texture_copy_layout(12, 3, 8, 4, 96, 16384));
    assert(!hv_pvg_texture_copy_layout(3, 2, 4, 0, 20, 16384));
    assert(!hv_pvg_texture_copy_layout(0, 2, 4, 0, 32, 16384));
    assert(!hv_pvg_texture_copy_layout(3, 0, 4, 0, 32, 16384));
    assert(!hv_pvg_texture_copy_layout(3, 2, 0, 0, 32, 16384));
    assert(!hv_pvg_texture_copy_layout(3, 2, 4, 0, 0, 16384));
    assert(!hv_pvg_texture_copy_layout(UINT64_MAX, 2, 8, 0, 96, UINT64_MAX));
    assert(!hv_pvg_texture_copy_layout(12, UINT64_MAX, 8, 0, 96, UINT64_MAX));
    assert(!hv_pvg_texture_copy_layout(12, 3, 8, UINT64_MAX - 7, 96, UINT64_MAX));
    assert(!hv_pvg_texture_copy_layout(1, 1, 1, 0, UINT64_MAX, 1));
    assert(!hv_pvg_texture_copy_layout(1, 1, 4, 0, 8193 * 4, 4));
    assert(!hv_pvg_texture_copy_layout(8193, 1, 4, 0, 8193 * 4, 8193 * 4));
    assert(!hv_pvg_texture_copy_layout(1, 8193, 4, 0, 16, 8193 * 16));
    assert(hv_pvg_texture_copy_layout(512, 512, 4, 0, 2048, 1 << 20));
    assert(!hv_pvg_texture_copy_layout(512, 513, 4, 0, 2048, 2 << 20));

    uint32_t a[] = {0x80001, 0x80005}, b[] = {0x90001, 0x80005}, second[] = {0x80005};
    assert(hv_pvg_copy_spans_overlap(a, 2, 16, 96, a, 2, 32, 96));
    assert(!hv_pvg_copy_spans_overlap(a, 2, 0, 32, a, 2, 32, 96));
    assert(!hv_pvg_copy_spans_overlap(a, 2, 0, 96, b, 2, 0, 96));
    assert(hv_pvg_copy_spans_overlap(a, 2, 16384, 96, b, 2, 16384, 96));
    assert(hv_pvg_copy_spans_overlap(a, 2, 16370, 32, second, 1, 0, 16));
    assert(!hv_pvg_copy_spans_overlap(a, 2, 16370, 14, second, 1, 0, 16));
    assert(hv_pvg_copy_spans_overlap(a, 2, UINT64_MAX, 96, b, 2, 0, 96));
    uint32_t task_pages[] = {0x20001}, different_pages[] = {0x30000};
    assert(hv_pvg_copy_span_overlaps_buffer(a, 2, 16384, 96, task_pages, 1));
    assert(!hv_pvg_copy_span_overlaps_buffer(a, 2, 0, 96, task_pages, 1));
    assert(!hv_pvg_copy_span_overlaps_buffer(a, 2, 16384, 96, different_pages, 1));

    /* Compare the division-based production span check to wider arithmetic. */
    for (int i = 0; i < 100000; i++) {
        uint64_t w = next(), h = next(), bpp = next() % 17;
        uint64_t off = next(), row = next(), length = next();
        if (i & 1) { w %= 128; h %= 128; off %= 128; row %= 2048; length %= 32768; }
        assert(hv_pvg_texture_span_fits(w, h, bpp, off, row, length) == span_oracle(w, h, bpp, off, row, length));
    }
    puts("PASS: texture copy layout, bounds, alignment, 1 MiB cap, physical alias spans and 100000 overflow cases");
    return 0;
}
