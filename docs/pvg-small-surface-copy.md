# Small mapped-surface texture copies

The direct Metal path creates a texture over the guest's buffer. That API
requires the row stride and offset to satisfy the host device's
`minimumLinearTextureAlignmentForPixelFormat:`. A valid guest image can have
tighter rows, such as a 12 × 3 RGBA16Float image with a 96-byte stride. Previously
Henge rejected a direct mapping and bound an unrelated empty texture.

This change provides a limited copy path for **mapped surfaces**, including that
RGBA16Float layout. It does not fix every rendering defect or establish why a
host process terminated. It does not yet support the analogous ordinary linear
texture failures: those can alias directly bound guest buffers within one exec,
which needs more extensive synchronization than this patch implements.

## Supported scope

- Single-plane RGhA/RGBA16Float or BGRA/BGRA8 surfaces on Apple3-or-later GPUs.
- A single 2D image, one mip level, one array slice and one sample; the texture's
  dimensions must match the surface's own description.
- At most 1 MiB of visible pixels per copy, at most 8192 pixels in either
  dimension or the row stride, and at least 16-byte offset/row alignment in
  addition to pixel alignment. The existing source mapping is at most 128
  16 KiB pages. These are conservative fallback limits, not a global Metal
  memory limit; driver allocation and metadata add overhead.
- Valid, fully mapped source pages. Multi-plane IOSurfaces continue to use the
  existing IOSurface path.

The original direct-mapping path remains first. The fallback creates a private
canonical texture and copies the guest pixels into it using a blit in the same
command buffer as the rendering. If the exec marks that resource writable, a
blit copies it back before the completion stamp reaches the guest. The guest row
stride is preserved, and copying does not overwrite row padding. There is no CPU
wait or per-frame IOSurface allocation.

## Aliases and lifetime

Compatible texture views share the canonical texture's storage, so a render
through one view is visible through another in a later pass in the same exec.
Usage flags do not create separate copies. A replay-level registry uses the
complete normalized physical page sequence, first-page offset, row stride,
dimensions and canonical format. Two mappings with the same layout and physical
pages therefore share one copy, including mappings used by different tasks.

The registry has weak values. Live surface objects and their texture views hold
the copy owner; the owner retains its exact source Metal buffer, which retains
the mapped guest pages. The owner does not retain a surface, avoiding a cycle.
Cached child views check their parent object before reuse, including when an old
guest driver replaces a surface under an existing mapping ID.

Different copied layouts, a directly mapped surface, or an ordinary guest buffer
may still overlap the same physical bytes. Such incompatible mixtures are
detected in the exec resource preflight and the job is skipped with
`incompatible copied surface alias: exec skipped before paging`. This check runs
before any paging or host-valid state changes. It avoids pretending that an
end-of-exec copy can correctly implement cross-pass buffer/texture aliasing.
The overlap checks are conservative and include row padding and complete pages
for ordinary buffers; an unsupported mixed job may still omit drawing.

## Validation

Run from the repository root:

```sh
bash tests/run_pvg_texture_copy.sh
```

The portable C test exercises the production layout and alias helpers, including
the affected stride classes, truncated buffers, dimension/stride limits, the
1 MiB bound, partial page aliases, task/surface page-unit conversion and 100,000
comparisons against wider arithmetic for overflow checks.

On macOS, the script also compiles the native test against the same production
helpers before checking for a GPU. With an exposed Apple3-or-later GPU it verifies
nonzero pixel upload, canonical/view sharing across encoders, render writes,
buffer writeback, unchanged padding, a later guest update and compatible sRGB
views. Its images and page lists are synthetic. It does not boot a guest or
contain any user's diagnostic log.

Exit `0` means all tests ran and passed. Exit `77` explicitly means the native
Metal pixel portion was unavailable; it is not a successful GPU verification.
Other nonzero exits are failures. Guest UI behavior and iPadOS 17 driver behavior
still require the test package to be exercised on the device.

## API basis

- [Metal buffer-backed texture requirements](https://developer.apple.com/documentation/metal/mtlbuffer/maketexture(descriptor:offset:bytesperrow:)):
  row and offset use the device's minimum linear texture alignment.
- [Buffer-to-texture blit parameters](https://developer.apple.com/documentation/metal/mtlblitcommandencoder/copy(from:sourceoffset:sourcebytesperrow:sourcebytesperimage:sourcesize:to:destinationslice:destinationlevel:destinationorigin:options:)):
  offset/row are measured in pixel bytes; the row also has a maximum texture-width
  bound. The options form with no options is equivalent to the ordinary form.
- [Metal Feature Set Tables](https://developer.apple.com/metal/Metal-Feature-Set-Tables.pdf):
  the fallback uses conservative dimension limits and the 16-byte
  texture-to-buffer alignment listed for Apple3 and later.
