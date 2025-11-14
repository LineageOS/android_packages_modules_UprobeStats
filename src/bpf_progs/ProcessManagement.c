/*
 * Copyright 2024 The Android Open Source Project
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

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>

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

struct SetUidTempAllowlistStateRecord {
  __u64 uid;
  bool onAllowlist;
};

DEFINE_BPF_RINGBUF_EXT(output_buf, struct SetUidTempAllowlistStateRecord, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/set_uid_temp_allowlist_state", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE2)
(struct pt_regs *ctx) {
  struct SetUidTempAllowlistStateRecord *output = bpf_output_buf_reserve();
  if (output == NULL)
    return 1;
  output->uid = ctx->regs[2];
  output->onAllowlist = ctx->regs[3];
  bpf_output_buf_submit(output);
  return 0;
}

struct jstring {
  __u64 dummy;
  __u32 count;
  __u32 hash_code;
};

struct UpdateDeviceIdleTempAllowlistRecord {
  int changing_uid;
  bool adding;
  long duration_ms;
  int type;
  int reason_code;
  char reason[256];
  int calling_uid;
};

DEFINE_BPF_RINGBUF_EXT(update_device_idle_temp_allowlist_records,
                       struct UpdateDeviceIdleTempAllowlistRecord, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

// Copies the string content of a Java String object located at <jstring> to
// <dest>.
void recordString(void *jstring, unsigned int max_length, char *dest) {
  // Assumes the following memory layout of a Java String object:
  // byte offset 8-11: count (this is the length of the string * 2)
  // byte offset 12-15: hash_code
  // byte offset 16 and beyond: string content
  __u32 count;
  bpf_probe_read_user(&count, sizeof(count), (uint8_t *)jstring + 8);
  count /= 2;
  bpf_probe_read_user_str(dest, max_length < count + 1 ? max_length : count + 1,
                          (uint8_t *)jstring + 16);
}

// Copies the content of a Java String object to <dest>, where the Java String
// is located at <position> in the method invocation argument list (0-based).
// This only works for the 0th - the 5th arguments. Rest of the arguments need
// to be accessed via stack pointer using the recordStringArgFromSp() function.
void recordStringArg(struct pt_regs *ctx, unsigned int max_length, int position,
                     char *dest) {
  recordString((void *)ctx->regs[2 + position], max_length, dest);
}

// Copies the content of a Java String object to <dest>, where the Java String
// address is located in stack frame.
void recordStringArgFromSp(struct pt_regs *ctx, unsigned int max_length,
                           int sp_offset, char *dest) {
  void *jstring = NULL;
  bpf_probe_read_user(&jstring, 4, (void *)ctx->sp + sp_offset);
  recordString(jstring, max_length, dest);
}

DEFINE_BPF_PROG("uprobe/update_device_idle_temp_allowlist", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE3)
(struct pt_regs *ctx) {
  struct UpdateDeviceIdleTempAllowlistRecord *output =
      bpf_update_device_idle_temp_allowlist_records_reserve();
  if (output == NULL)
    return 1;

  // changing_uid is the 2nd argument, which is located in regs[3].
  output->changing_uid = ctx->regs[3];
  output->adding = ctx->regs[4];
  output->duration_ms = ctx->regs[5];
  output->type = ctx->regs[6];
  output->reason_code = ctx->regs[7];

  // The <reason> argument is located at offset=40 in stack frame. This is
  // calculated as 12 + sizeof(previous arguments). There are 6 preceding
  // arguments all of which is 4 bytes each except for <long durationMs> which
  // is 8 bytes. Therefore the offset is 12 + 5 * 4 + 8 = 40
  recordStringArgFromSp(ctx, 256, 40, output->reason);

  // The <calling_uid> argument follows <reason> immediately and therefore has
  // an offset that's 4 more bytes larger.
  bpf_probe_read_user(&output->calling_uid, 4, (void *)ctx->sp + 44);

  bpf_update_device_idle_temp_allowlist_records_submit(output);
  return 0;
}

struct ProcessChange {
  int pid;
  int uid;
  char process_name[256];
};

DEFINE_BPF_RINGBUF_EXT(process_change_output_buf, struct ProcessChange,
                       4096 * 16, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "",
                       "", PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/set_pid", AID_UPROBESTATS, AID_UPROBESTATS, BPF_KPROBE5)
(struct pt_regs *ctx) {
  struct ProcessChange *output = bpf_process_change_output_buf_reserve();
  if (output == NULL)
    return 1;

  output->pid = (int)ctx->regs[2];
  bpf_probe_read_user(&output->uid, 4, (void *)(ctx->regs[1] + 0xf4));
  void *process_name = 0;
  bpf_probe_read_user(&process_name, 4, (void *)(ctx->regs[1] + 0xa0));
  recordString(process_name, 256, output->process_name);

  bpf_process_change_output_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/make_active", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE4)
(struct pt_regs *ctx) {
  struct ProcessChange *output = bpf_process_change_output_buf_reserve();
  if (output == NULL)
    return 1;

  bpf_probe_read_user(&output->pid, 4, (void *)(ctx->regs[1] + 0xe8));
  bpf_probe_read_user(&output->uid, 4, (void *)(ctx->regs[1] + 0xf4));
  uint8_t *process_name = 0;
  bpf_probe_read_user(&process_name, 4, (void *)(ctx->regs[1] + 0xa0));
  recordString(process_name, 256, output->process_name);

  bpf_process_change_output_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/on_process_active", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE6)
(struct pt_regs *ctx) {
  struct ProcessChange *output = bpf_process_change_output_buf_reserve();
  if (output == NULL)
    return 1;

  uint8_t *process_record_ptr = 0;
  bpf_probe_read_user(&process_record_ptr, 4, (void *)(ctx->regs[1] + 0x8));
  bpf_probe_read_user(&output->pid, 4, (void *)(process_record_ptr + 0xe8));
  bpf_probe_read_user(&output->uid, 4, (void *)(process_record_ptr + 0xf4));
  uint8_t *process_name = 0;
  bpf_probe_read_user(&process_name, 4, (void *)(process_record_ptr + 0xa0));
  recordString(process_name, 256, output->process_name);

  bpf_process_change_output_buf_submit(output);
  return 0;
}

LICENSE("GPL");
