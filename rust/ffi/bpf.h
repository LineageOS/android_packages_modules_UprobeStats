
/*
 * Copyright (C) 2025 The Android Open Source Project
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
#ifndef __UPROBESTATSBPF_H__
#define __UPROBESTATSBPF_H__

#include <sys/types.h>

__BEGIN_DECLS

struct CallTimestamp {
  unsigned int event;
  unsigned long timestampNs;
};

struct CallResult {
  unsigned long pc;
  unsigned long regs[10];
};

struct SetUidTempAllowlistStateRecord {
  __u64 uid;
  bool onAllowlist;
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

struct BindServiceLocked {
  char intent_action[64];
  char intent_package[64];
  char intent_component_name_package[64];
  char intent_component_name_class[64];
  long bind_flags;
  char calling_package[64];
};

struct ComponentEnabledSetting {
  char package_name[64];
  char class_name[64];
  int new_state;
  char calling_package_name[64];
};

struct ProcessChange {
  int pid;
  int uid;
  char process_name[256];
};

struct BitmapAllocation {
  __u32 width;
  __u32 height;
  __u32 pixel_storage_type;
};

int pollRingBuf(const char *mapPath, int timeoutMs, size_t valueSize,
                void (*callback)(const void *, void *), void *cookie);
int bpfPerfEventOpen(const char *filename, int offset, int pid,
                     const char *bpfProgramPath);

__END_DECLS

#endif  // __UPROBESTATSBPF_H__
