#ifndef HV_PVG_TEXTURE_COPY_H
#define HV_PVG_TEXTURE_COPY_H

#include <stdbool.h>
#include <stdint.h>

/* Visible pixels, not padding after the last row, must fit. Division keeps
   guest-controlled dimensions and strides from overflowing the check. */
static inline bool hv_pvg_texture_span_fits(uint64_t width, uint64_t height,
                                          uint64_t pixel_bytes, uint64_t offset,
                                          uint64_t row, uint64_t length) {
    if (!width || !height || !pixel_bytes || !row || offset > length) return false;
    if (width > row / pixel_bytes) return false;
    uint64_t visible_row = width * pixel_bytes;
    uint64_t left = length - offset;
    return visible_row <= left && height - 1 <= (left - visible_row) / row;
}

/* Keep this fallback within conservative Apple3+ limits: at most 8192 pixels
   per dimension or row, and 16-byte buffer alignment (also pixel alignment).
   These cover the small UI textures without widening the replay to other
   layouts. Apple's Metal Feature Set Tables lists >=8192 2D dimensions and
   16-byte texture-to-buffer alignment for these GPU families:
   https://developer.apple.com/metal/Metal-Feature-Set-Tables.pdf */
enum { HV_PVG_COPY_MAX_DIMENSION = 8192, HV_PVG_COPY_ALIGNMENT = 16, HV_PVG_COPY_MAX_BYTES = 1 << 20 };
static inline bool hv_pvg_texture_copy_layout(uint64_t width, uint64_t height,
                                             uint64_t pixel_bytes, uint64_t offset,
                                             uint64_t row, uint64_t length) {
    return hv_pvg_texture_span_fits(width, height, pixel_bytes, offset, row, length) &&
           pixel_bytes <= 16 && width <= HV_PVG_COPY_MAX_DIMENSION && height <= HV_PVG_COPY_MAX_DIMENSION &&
           width <= HV_PVG_COPY_MAX_BYTES / pixel_bytes / height &&
           row / pixel_bytes <= HV_PVG_COPY_MAX_DIMENSION &&
           offset % pixel_bytes == 0 && row % pixel_bytes == 0 &&
           offset % HV_PVG_COPY_ALIGNMENT == 0 && row % HV_PVG_COPY_ALIGNMENT == 0;
}

/* Conservative physical span intersection, including row padding. Different
   layouts that overlap cannot use separate whole-exec copies. Complete page
   sequences matter: looking only at the first page misses partial aliases. */
static inline bool hv_pvg_copy_spans_overlap(const uint32_t *a, uint64_t an, uint64_t ao, uint64_t al,
                                            const uint32_t *b, uint64_t bn, uint64_t bo, uint64_t bl) {
    if (!a || !b || !al || !bl) return false;
    if (an > UINT64_MAX / 16384 || bn > UINT64_MAX / 16384 || ao > an * 16384 || al > an * 16384 - ao ||
        bo > bn * 16384 || bl > bn * 16384 - bo) return true;
    for (uint64_t i = ao / 16384; i <= (ao + al - 1) / 16384; i++) {
        uint64_t as = ((uint64_t)(a[i] & ~1u) << 12) + (ao > i * 16384 ? ao - i * 16384 : 0);
        uint64_t ae = ((uint64_t)(a[i] & ~1u) << 12) + (ao + al - i * 16384 < 16384 ? ao + al - i * 16384 : 16384);
        for (uint64_t j = bo / 16384; j <= (bo + bl - 1) / 16384; j++) {
            uint64_t bs = ((uint64_t)(b[j] & ~1u) << 12) + (bo > j * 16384 ? bo - j * 16384 : 0);
            uint64_t be = ((uint64_t)(b[j] & ~1u) << 12) + (bo + bl - j * 16384 < 16384 ? bo + bl - j * 16384 : 16384);
            if (as < be && bs < ae) return true;
        }
    }
    return false;
}

/* Mapped-surface page numbers use 4 KiB units plus a present bit; ordinary
   task buffers use plain 16 KiB page numbers. Compare their physical spans. */
static inline bool hv_pvg_copy_span_overlaps_buffer(const uint32_t *surface, uint64_t count, uint64_t offset, uint64_t span,
                                                   const uint32_t *buffer, uint64_t buffer_count) {
    if (!surface || !buffer || !span) return false;
    if (count > 128 || offset > count * 16384 || span > count * 16384 - offset) return true;
    for (uint64_t i = offset / 16384; i <= (offset + span - 1) / 16384; i++) {
        uint64_t page = (uint64_t)(surface[i] & ~1u) << 12;
        for (uint64_t j = 0; j < buffer_count; j++)
            if (buffer[j] && page == (uint64_t)buffer[j] << 14) return true;
    }
    return false;
}

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

/* Uncompressed color formats only. Depth, stencil, packed YUV and compressed
   formats need their own copy rules and do not use this fallback. */
static inline NSUInteger hv_pvg_pixel_bytes(MTLPixelFormat f) {
    switch (f) {
    case MTLPixelFormatA8Unorm: case MTLPixelFormatR8Unorm: case MTLPixelFormatR8Unorm_sRGB: case MTLPixelFormatR8Snorm:
    case MTLPixelFormatR8Uint: case MTLPixelFormatR8Sint: return 1;
    case MTLPixelFormatR16Unorm: case MTLPixelFormatR16Snorm: case MTLPixelFormatR16Uint: case MTLPixelFormatR16Sint: case MTLPixelFormatR16Float:
    case MTLPixelFormatRG8Unorm: case MTLPixelFormatRG8Unorm_sRGB: case MTLPixelFormatRG8Snorm: case MTLPixelFormatRG8Uint: case MTLPixelFormatRG8Sint:
    case MTLPixelFormatB5G6R5Unorm: case MTLPixelFormatA1BGR5Unorm: case MTLPixelFormatABGR4Unorm: case MTLPixelFormatBGR5A1Unorm: return 2;
    case MTLPixelFormatR32Uint: case MTLPixelFormatR32Sint: case MTLPixelFormatR32Float: case MTLPixelFormatRG16Unorm: case MTLPixelFormatRG16Snorm:
    case MTLPixelFormatRG16Uint: case MTLPixelFormatRG16Sint: case MTLPixelFormatRG16Float: case MTLPixelFormatRGBA8Unorm: case MTLPixelFormatRGBA8Unorm_sRGB:
    case MTLPixelFormatRGBA8Snorm: case MTLPixelFormatRGBA8Uint: case MTLPixelFormatRGBA8Sint: case MTLPixelFormatBGRA8Unorm: case MTLPixelFormatBGRA8Unorm_sRGB:
    case MTLPixelFormatRGB10A2Unorm: case MTLPixelFormatRGB10A2Uint: case MTLPixelFormatRG11B10Float: case MTLPixelFormatRGB9E5Float:
    case MTLPixelFormatBGR10A2Unorm: return 4;
    case MTLPixelFormatRG32Uint: case MTLPixelFormatRG32Sint: case MTLPixelFormatRG32Float: case MTLPixelFormatRGBA16Unorm: case MTLPixelFormatRGBA16Snorm:
    case MTLPixelFormatRGBA16Uint: case MTLPixelFormatRGBA16Sint: case MTLPixelFormatRGBA16Float: return 8;
    case MTLPixelFormatRGBA32Uint: case MTLPixelFormatRGBA32Sint: case MTLPixelFormatRGBA32Float: return 16;
    default: return 0;
    }
}

static inline BOOL hv_pvg_texture_copy_descriptor(MTLTextureDescriptor *t, uint64_t offset,
                                                 uint64_t row, NSUInteger length) {
    return t.textureType == MTLTextureType2D && t.depth == 1 && t.arrayLength == 1 &&
           t.mipmapLevelCount == 1 && t.sampleCount == 1 &&
           hv_pvg_texture_copy_layout(t.width, t.height, hv_pvg_pixel_bytes(t.pixelFormat), offset, row, length);
}

static inline MTLPixelFormat hv_pvg_surface_copy_format(uint32_t fourcc) {
    if (fourcc == 0x52476841) return MTLPixelFormatRGBA16Float; /* RGhA */
    if (fourcc == 0x42475241) return MTLPixelFormatBGRA8Unorm; /* BGRA */
    return MTLPixelFormatInvalid;
}

static inline BOOL hv_pvg_surface_copy_compatible(MTLTextureDescriptor *t, MTLPixelFormat format,
                                                 NSUInteger width, NSUInteger height, uint64_t offset,
                                                 uint64_t row, NSUInteger length) {
    BOOL compatible = t.pixelFormat == format || (format == MTLPixelFormatBGRA8Unorm && t.pixelFormat == MTLPixelFormatBGRA8Unorm_sRGB);
    MTLTextureUsage usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite | MTLTextureUsageRenderTarget | MTLTextureUsagePixelFormatView;
    return (format == MTLPixelFormatRGBA16Float || format == MTLPixelFormatBGRA8Unorm) && compatible &&
           t.width == width && t.height == height && !(t.usage & ~usage) &&
           hv_pvg_texture_copy_descriptor(t, offset, row, length);
}

static inline NSData *hv_pvg_surface_copy_key(const uint32_t *pages, uint64_t count, uint64_t first,
                                             uint64_t row, uint64_t width, uint64_t height, MTLPixelFormat format) {
    uint64_t layout[] = {count, first, row, width, height, format};
    NSMutableData *key = [NSMutableData dataWithBytes:layout length:sizeof layout];
    for (uint64_t i = 0; i < count; i++) {
        uint32_t page = pages[i] & ~1u;
        [key appendBytes:&page length:sizeof page];
    }
    return key;
}

static inline id<MTLTexture> hv_pvg_texture_copy_create(id<MTLDevice> device, MTLTextureDescriptor *t,
                                                      id<MTLBuffer> buffer, uint64_t offset, uint64_t row) {
    if (!buffer || ![device supportsFamily:MTLGPUFamilyApple3] ||
        (t.pixelFormat != MTLPixelFormatRGBA16Float && t.pixelFormat != MTLPixelFormatBGRA8Unorm) ||
        !hv_pvg_texture_copy_descriptor(t, offset, row, buffer.length)) return nil;
    MTLTextureDescriptor *copy = [t copy];
    copy.storageMode = MTLStorageModePrivate;
    copy.cpuCacheMode = MTLCPUCacheModeDefaultCache;
    copy.hazardTrackingMode = MTLHazardTrackingModeTracked;
    copy.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite | MTLTextureUsageRenderTarget | MTLTextureUsagePixelFormatView;
    copy.swizzle = MTLTextureSwizzleChannelsMake(MTLTextureSwizzleRed, MTLTextureSwizzleGreen, MTLTextureSwizzleBlue, MTLTextureSwizzleAlpha);
    return [device newTextureWithDescriptor:copy];
}

static inline id<MTLTexture> hv_pvg_texture_copy_view(id<MTLTexture> canonical, MTLTextureDescriptor *t) {
    return [canonical newTextureViewWithPixelFormat:t.pixelFormat textureType:MTLTextureType2D
                                            levels:NSMakeRange(0, 1) slices:NSMakeRange(0, 1) swizzle:t.swizzle];
}

/* Encode in the same command buffer as the rendering: before the first use,
   and after the last write, before the completion stamp reaches the guest.
   No CPU wait, temporary IOSurface or row-stride reinterpretation is needed.
   Apple documents source/destination offset and row alignment in pixel bytes:
   https://developer.apple.com/documentation/metal/mtlblitcommandencoder/copy(from:sourceoffset:sourcebytesperrow:sourcebytesperimage:sourcesize:to:destinationslice:destinationlevel:destinationorigin:)
 */
static inline void hv_pvg_texture_copy_encode(id<MTLBlitCommandEncoder> blit, id<MTLTexture> texture,
                                            id<MTLBuffer> buffer, uint64_t offset, uint64_t row, BOOL toBuffer) {
    MTLSize size = MTLSizeMake(texture.width, texture.height, 1);
    if (toBuffer)
        [blit copyFromTexture:texture sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:size
                     toBuffer:buffer destinationOffset:offset destinationBytesPerRow:row destinationBytesPerImage:0];
    else
        [blit copyFromBuffer:buffer sourceOffset:offset sourceBytesPerRow:row sourceBytesPerImage:0 sourceSize:size
                  toTexture:texture destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(0, 0, 0)];
}
#endif
#endif
