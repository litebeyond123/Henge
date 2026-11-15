#import "../devices/pvg_texture_copy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void complete(id<MTLCommandBuffer> cb) {
    assert(cb);
    [cb commit];
    [cb waitUntilCompleted];
    if (cb.status != MTLCommandBufferStatusCompleted || cb.error) {
        fprintf(stderr, "FAIL: Metal copy command (status %lu): %s\n", (unsigned long)cb.status,
                cb.error ? cb.error.description.UTF8String : "no Metal error description");
        exit(1);
    }
}

static void pixels(uint8_t *bytes, NSUInteger offset, NSUInteger row, NSUInteger width, NSUInteger height,
                   NSUInteger bpp, unsigned seed) {
    for (NSUInteger y = 0; y < height; y++)
        for (NSUInteger x = 0; x < width; x++) {
            uint8_t *p = bytes + offset + y * row + x * bpp;
            if (bpp == 8) {
                /* Finite half floats, varying across every row and column. */
                uint16_t h[4] = {0x3000 + ((x + seed) & 255), 0x3400 + ((y + seed) & 255), 0x3800, 0x3c00};
                memcpy(p, h, sizeof h);
            } else for (NSUInteger c = 0; c < bpp; c++) p[c] = (uint8_t)(x * 13 + y * 7 + c * 29 + seed);
        }
}

static void check_bytes(id<MTLBuffer> buffer, NSData *expected, const char *what) {
    const uint8_t *actual = buffer.contents, *want = expected.bytes;
    for (NSUInteger i = 0; i < expected.length; i++)
        if (actual[i] != want[i]) {
            fprintf(stderr, "FAIL: %s at byte %lu: got %u expected %u\n", what, (unsigned long)i, actual[i], want[i]);
            exit(1);
        }
}

static void roundtrip(id<MTLDevice> device, id<MTLCommandQueue> queue, MTLPixelFormat format,
                      NSUInteger w, NSUInteger h, NSUInteger offset, NSUInteger row) {
    @autoreleasepool {
        NSUInteger bpp = hv_pvg_pixel_bytes(format), length = offset + row * h + 64;
        id<MTLBuffer> source = [device newBufferWithLength:length options:MTLResourceStorageModeShared];
        id<MTLBuffer> readback = [device newBufferWithLength:length options:MTLResourceStorageModeShared];
        assert(source && readback);
        memset(source.contents, 0xa5, length);
        memset(readback.contents, 0xcc, length);
        pixels(source.contents, offset, row, w, h, bpp, 1);
        NSMutableData *expected = [NSMutableData dataWithLength:length];
        memset(expected.mutableBytes, 0xcc, length);
        pixels(expected.mutableBytes, offset, row, w, h, bpp, 1);
        MTLTextureDescriptor *t = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:format width:w height:h mipmapped:NO];
        t.usage = MTLTextureUsageShaderRead | MTLTextureUsageRenderTarget;
        id<MTLTexture> canonical = hv_pvg_texture_copy_create(device, t, source, offset, row);
        assert(canonical);
        id<MTLTexture> a = hv_pvg_texture_copy_view(canonical, t);
        MTLTextureDescriptor *read = [t copy];
        read.usage = MTLTextureUsageShaderRead;
        id<MTLTexture> b = hv_pvg_texture_copy_view(canonical, read);
        assert(a && b);

        /* Use the production create/blit/view helpers, preserving all padding. */
        id<MTLCommandBuffer> cb = [queue commandBuffer];
        assert(cb);
        id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
        assert(blit);
        hv_pvg_texture_copy_encode(blit, canonical, source, offset, row, NO);
        hv_pvg_texture_copy_encode(blit, b, readback, offset, row, YES);
        [blit endEncoding];
        complete(cb);
        check_bytes(readback, expected, "initial upload through a view");

        /* One command buffer, two encoders: a render through view A must be
           visible through view B before any writeback to guest memory. */
        cb = [queue commandBuffer];
        assert(cb);
        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
        pass.colorAttachments[0].texture = a;
        pass.colorAttachments[0].loadAction = MTLLoadActionClear;
        pass.colorAttachments[0].storeAction = MTLStoreActionStore;
        /* Unequal red and blue catch a BGRA/RGBA channel-order regression. */
        pass.colorAttachments[0].clearColor = MTLClearColorMake(1, 0, 0, 1);
        id<MTLRenderCommandEncoder> render = [cb renderCommandEncoderWithDescriptor:pass];
        assert(render);
        [render endEncoding];
        blit = [cb blitCommandEncoder];
        assert(blit);
        hv_pvg_texture_copy_encode(blit, b, readback, offset, row, YES);
        hv_pvg_texture_copy_encode(blit, canonical, source, offset, row, YES);
        [blit endEncoding];
        complete(cb);
        uint8_t clear[8] = {0, 0, 255, 255}; /* red in BGRA8 */
        if (bpp == 8) { uint16_t half[4] = {0x3c00, 0, 0, 0x3c00}; memcpy(clear, half, sizeof half); }
        for (NSUInteger y = 0; y < h; y++)
            for (NSUInteger x = 0; x < w; x++) memcpy((uint8_t *)expected.mutableBytes + offset + y * row + x * bpp, clear, bpp);
        check_bytes(readback, expected, "cross-pass canonical/view alias");
        NSMutableData *guest_expected = [NSMutableData dataWithLength:length];
        memset(guest_expected.mutableBytes, 0xa5, length);
        for (NSUInteger y = 0; y < h; y++)
            memcpy((uint8_t *)guest_expected.mutableBytes + offset + y * row, (uint8_t *)expected.mutableBytes + offset + y * row, w * bpp);
        check_bytes(source, guest_expected, "GPU writeback with padding intact");

        /* The next exec sees fresh guest pixels, not a cached first upload. */
        pixels(source.contents, offset, row, w, h, bpp, 73);
        pixels(expected.mutableBytes, offset, row, w, h, bpp, 73);
        cb = [queue commandBuffer];
        assert(cb);
        blit = [cb blitCommandEncoder];
        assert(blit);
        hv_pvg_texture_copy_encode(blit, canonical, source, offset, row, NO);
        hv_pvg_texture_copy_encode(blit, b, readback, offset, row, YES);
        [blit endEncoding];
        complete(cb);
        check_bytes(readback, expected, "fresh guest upload");
        if (format == MTLPixelFormatBGRA8Unorm) {
            MTLTextureDescriptor *srgb = [read copy];
            srgb.pixelFormat = MTLPixelFormatBGRA8Unorm_sRGB;
            assert(hv_pvg_surface_copy_compatible(srgb, format, w, h, offset, row, length));
            id<MTLTexture> srgb_view = hv_pvg_texture_copy_view(canonical, srgb);
            assert(srgb_view);
            memset(readback.contents, 0xcc, length);
            cb = [queue commandBuffer];
            assert(cb);
            blit = [cb blitCommandEncoder];
            assert(blit);
            hv_pvg_texture_copy_encode(blit, srgb_view, readback, offset, row, YES);
            [blit endEncoding];
            complete(cb);
            /* A blit preserves stored bytes; it does not sample or encode sRGB. */
            check_bytes(readback, expected, "sRGB view shares the canonical stored bytes");
        }
        printf("PASS: mapped-surface copy format %lu %lux%lu row %lu offset %lu; views, writeback, padding\n",
               (unsigned long)format, (unsigned long)w, (unsigned long)h, (unsigned long)row, (unsigned long)offset);
    }
}

int main(void) {
    alarm(60);
    @autoreleasepool {
        /* Key and descriptor checks run even on a Mac with no exposed GPU. */
        uint32_t pages[] = {0x80001, 0x80005}, same[] = {0x80000, 0x80004}, other[] = {0x80000, 0x80008};
        NSData *key = hv_pvg_surface_copy_key(pages, 2, 16, 96, 12, 3, MTLPixelFormatRGBA16Float);
        assert([key isEqual:hv_pvg_surface_copy_key(same, 2, 16, 96, 12, 3, MTLPixelFormatRGBA16Float)]);
        assert(![key isEqual:hv_pvg_surface_copy_key(other, 2, 16, 96, 12, 3, MTLPixelFormatRGBA16Float)]);
        assert(![key isEqual:hv_pvg_surface_copy_key(same, 2, 32, 96, 12, 3, MTLPixelFormatRGBA16Float)]);
        MTLTextureDescriptor *t = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA16Float width:12 height:3 mipmapped:NO];
        assert(hv_pvg_surface_copy_compatible(t, MTLPixelFormatRGBA16Float, 12, 3, 0, 96, 16384));
        assert(!hv_pvg_surface_copy_compatible(t, MTLPixelFormatRGBA16Float, 13, 3, 0, 96, 16384));
        assert(!hv_pvg_surface_copy_compatible(t, MTLPixelFormatBGRA8Unorm, 12, 3, 0, 96, 16384));
        assert(!hv_pvg_texture_copy_descriptor(t, 4, 96, 16384));
        assert(!hv_pvg_texture_copy_descriptor(t, 0, 8193 * 8, 16384));
        t.mipmapLevelCount = 2;
        assert(!hv_pvg_texture_copy_descriptor(t, 0, 96, 16384));
        t.mipmapLevelCount = 1; t.sampleCount = 2;
        assert(!hv_pvg_texture_copy_descriptor(t, 0, 96, 16384));
        puts("PASS: mapped-surface format, descriptor and complete-page registry keys");
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device || ![device supportsFamily:MTLGPUFamilyApple3]) {
            puts("SKIP: native Metal pixel tests need an exposed Apple3-or-later GPU; no pixel validation ran");
            return 77;
        }
        printf("Metal device: %s\n", device.name.UTF8String);
        id<MTLCommandQueue> queue = [device newCommandQueue];
        assert(queue);
        roundtrip(device, queue, MTLPixelFormatRGBA16Float, 12, 3, 0, 96);
        roundtrip(device, queue, MTLPixelFormatRGBA16Float, 12, 3, 32, 96);
        roundtrip(device, queue, MTLPixelFormatRGBA16Float, 3, 56, 16, 32);
        /* These are synthetic mapped BGRA surfaces. Ordinary linear texture
           objects still do not enter the production fallback. */
        roundtrip(device, queue, MTLPixelFormatBGRA8Unorm, 38, 26, 0, 160);
        roundtrip(device, queue, MTLPixelFormatBGRA8Unorm, 19, 14, 16, 96);
        puts("PASS: all native Metal mapped-surface pixel tests");
    }
    return 0;
}
