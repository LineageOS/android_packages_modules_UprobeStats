/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <bpf_helpers.h>

// TODO: import this struct from generic header, access registers via generic
// function
struct pt_regs {
  unsigned long regs[31];
  unsigned long sp;
  unsigned long pc;
  unsigned long pr;
  unsigned long sr;
  unsigned long gbr;
  unsigned long mach;
  unsigned long macl;
  long tra;
};

DEFINE_BPF_RINGBUF_EXT(output_buf, __u64, 4096, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "",
                       PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER,
                       LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/bitmap_constructor_heap", AID_UPROBESTATS, AID_UPROBESTATS, BPF_KPROBE2)
(__unused void* this_ptr, __unused void* buffer_address, __unused __u32 size) {
    __u64* output = bpf_output_buf_reserve();
    if (output == NULL) return 1;
    (*output) = 123;
    bpf_output_buf_submit(output);
    return 0;
}

struct BitmapAllocation {
  __u32 width;
  __u32 height;
  __u32 pixel_storage_type;
};

int load(void *dest, int offset, int length, void *user_space_address) {
  long canonical_address = (long)user_space_address & 0x00FFFFFFFFFFFFFF;
  return bpf_probe_read_user(dest, length,
                             (void *)(canonical_address + offset));
}

DEFINE_BPF_RINGBUF_EXT(output, struct BitmapAllocation, 16 * 1024,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/bitmap_creation", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE3)
(struct pt_regs *ctx) {

  struct BitmapAllocation *output = bpf_output_reserve();
  if (output == NULL)
    return 1;
  output->width = ctx->regs[4];
  output->height = ctx->regs[5];

  uint8_t *bitmap_wrapper_ptr = (uint8_t *)(ctx->regs[3]);
  uint8_t *bitmap_ptr;
  // The first 8 bytes of a BitmapWrapper object is the pointer to the
  // underlying Bitmap.
  load(&bitmap_ptr, 0, 8, bitmap_wrapper_ptr);
  // 0x78 is the offset of pixel_storage_type into a Bitmap object.
  load(&output->pixel_storage_type, 0x78, 4, bitmap_ptr);

  bpf_output_submit(output);
  return 0;
}

LICENSE("GPL");
