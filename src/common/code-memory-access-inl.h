// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_CODE_MEMORY_ACCESS_INL_H_
#define V8_COMMON_CODE_MEMORY_ACCESS_INL_H_


/* JARA: Header for domv and mprotect */
#include <sys/mman.h>
#ifdef MAP_TYPE
#undef MAP_TYPE
#endif
extern "C" {
  #include "src/domv.h"
}
/* End of JARA */

#include "src/common/code-memory-access.h"
#include "src/flags/flags.h"
#include "src/objects/instruction-stream-inl.h"
#include "src/objects/instruction-stream.h"
#include "src/objects/slots-inl.h"
#include "src/objects/tagged.h"
#if V8_HAS_PKU_JIT_WRITE_PROTECT
#include "src/base/platform/memory-protection-key.h"
#endif
#if V8_HAS_PTHREAD_JIT_WRITE_PROTECT
#include "src/base/platform/platform.h"
#endif
#if V8_HAS_BECORE_JIT_WRITE_PROTECT
#include <BrowserEngineCore/BEMemory.h>
#endif

/* JARA: For Dom-V */

// #define LOG_E_H printf("[d8-code-memory-access-inl.h] Enter: %s\n", __PRETTY_FUNCTION__);
#define LOG_E_H
/* End of JARA */

namespace v8 {
namespace internal {

RwxMemoryWriteScope::RwxMemoryWriteScope(const char* comment) {
  LOG_E_H
    //printf("\t%s\n", comment);
  if (!v8_flags.jitless) {
    SetWritable();
  }
}

RwxMemoryWriteScope::~RwxMemoryWriteScope() {
  if (!v8_flags.jitless) {
    SetExecutable();
  }
}

WritableJitAllocation::~WritableJitAllocation() = default;

WritableJitAllocation::WritableJitAllocation(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type,
    JitAllocationSource source)
    : address_(addr),
      // The order of these is important. We need to create the write scope
      // before we lookup the Jit page, since the latter will take a mutex in
      // protected memory.
      write_scope_("WritableJitAllocation"),
      page_ref_(ThreadIsolation::LookupJitPage(addr, size)),
      allocation_(source == JitAllocationSource::kRegister
                      ? page_ref_->RegisterAllocation(addr, size, type)
                      : page_ref_->LookupAllocation(addr, size, type)) {
  LOG_E_H
}

WritableJitAllocation::WritableJitAllocation(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type)
    : address_(addr), allocation_(size, type) {LOG_E_H}

// static
WritableJitAllocation WritableJitAllocation::ForNonExecutableMemory(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type) {
  LOG_E_H
  return WritableJitAllocation(addr, size, type);
}

// static
WritableJitAllocation WritableJitAllocation::ForInstructionStream(
    Tagged<InstructionStream> istream) {
  LOG_E_H
    
  return WritableJitAllocation(
      istream->address(), istream->Size(),
      ThreadIsolation::JitAllocationType::kInstructionStream,
      JitAllocationSource::kLookup);
}

WritableJumpTablePair::WritableJumpTablePair(Address jump_table_address,
                                             size_t jump_table_size,
                                             Address far_jump_table_address,
                                             size_t far_jump_table_size)
    : write_scope_("WritableJumpTablePair"),
      // Always split the pages since we are not guaranteed that the jump table
      // and far jump table are on the same JitPage.
      jump_table_pages_(ThreadIsolation::SplitJitPages(
          far_jump_table_address, far_jump_table_size, jump_table_address,
          jump_table_size)),
      jump_table_(jump_table_pages_.second.LookupAllocation(
          jump_table_address, jump_table_size,
          ThreadIsolation::JitAllocationType::kWasmJumpTable)),
      far_jump_table_(jump_table_pages_.first.LookupAllocation(
          far_jump_table_address, far_jump_table_size,
          ThreadIsolation::JitAllocationType::kWasmFarJumpTable)) {LOG_E_H}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(T value) {
  // This assert is no strict requirement, it just guards against
  // non-implemented functionality.

  LOG_E_H


    /* JARA : Write through domv_write */
  //   printf("domv_write cand1\n");
  // printf("address_: 0x%lx\n", address_);
  
  static_assert(!is_taggable_v<T>);
  domv_write((void *)(address_ + offset), &value, sizeof(value), 0);
  /* End of JARA */

  // static_assert(!is_taggable_v<T>);
  // if constexpr (offset == HeapObject::kMapOffset) {
  //   TaggedField<T, offset>::Relaxed_Store_Map_Word(
  //       HeapObject::FromAddress(address_), value);
  // } else {
  //   WriteMaybeUnalignedValue<T>(address_ + offset, value);
  // }
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(Tagged<T> value, ReleaseStoreTag) {
  // These asserts are no strict requirements, they just guard against
  // non-implemented functionality.

  LOG_E_H
    /* JARA : Write through domv_write */
  //   printf("domv_write cand2\n");
  // printf("address_: 0x%lx\n", address_);
  static_assert(offset != HeapObject::kMapOffset);
  domv_write((void *)(address_ + offset), &value, sizeof(value), 0);
  /* End of JARA */

  //static_assert(offset != HeapObject::kMapOffset);

  // TaggedField<T, offset>::Release_Store(HeapObject::FromAddress(address_),
  //                                       value);
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(Tagged<T> value, RelaxedStoreTag) {

  LOG_E_H
    /* JARA : Write through domv_write */
  //   printf("domv_write cand3\n");
  // printf("address_: 0x%lx\n", address_);
  domv_write((void *)(address_ + offset), &value, sizeof(value), 0);

  /* End of JARA */
 
  // if constexpr (offset == HeapObject::kMapOffset) {
  //   TaggedField<T, offset>::Relaxed_Store_Map_Word(
  //       HeapObject::FromAddress(address_), value);
  // } else {
  //   TaggedField<T, offset>::Relaxed_Store(HeapObject::FromAddress(address_),
  //                                         value);
  // } 
  
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteProtectedPointerHeaderSlot(Tagged<T> value,
                                                            RelaxedStoreTag) {
  LOG_E_H
    /* JARA : Write through domv_write */
  //   printf("domv_write cand P1\n");
  // printf("address_: 0x%lx\n", address_);
  static_assert(offset != HeapObject::kMapOffset);
  domv_write((void *)(address_ + offset), &value, sizeof(value), 0);
  /* End of JARA */
 
  // static_assert(offset != HeapObject::kMapOffset);
  // TaggedField<T, offset, TrustedSpaceCompressionScheme>::Relaxed_Store(
  //     HeapObject::FromAddress(address_), value);
}

template <typename T>
V8_INLINE void WritableJitAllocation::WriteHeaderSlot(Address address, T value,
                                                      RelaxedStoreTag tag) {
  LOG_E_H
  
  CHECK_EQ(allocation_.Type(),
           ThreadIsolation::JitAllocationType::kInstructionStream);
  size_t offset = address - address_;
  Tagged<T> tagged(value);
  switch (offset) {
    case InstructionStream::kCodeOffset:
      WriteProtectedPointerHeaderSlot<T, InstructionStream::kCodeOffset>(tagged,
                                                                         tag);
      break;
    case InstructionStream::kRelocationInfoOffset:
      WriteProtectedPointerHeaderSlot<T,
                                      InstructionStream::kRelocationInfoOffset>(
          tagged, tag);
      break;
    default:
      UNREACHABLE();
  }
}

void WritableJitAllocation::CopyCode(size_t dst_offset, const uint8_t* src,
                                     size_t num_bytes) {
  LOG_E_H
    /* JARA Dom-v write code */
    //printf("\taddress_: 0x%lx\ttarget: 0x%lx\tsrc: %p size: %ld\n", address_, address_ + dst_offset, src, num_bytes);

    if(num_bytes >= 292)
      domv_write((void *)(address_ + dst_offset), (void *)src, num_bytes, 1);
    else
      domv_write((void *)(address_ + dst_offset), (void *)src, num_bytes, 0);
  /* End of JARA */

  //CopyBytes(reinterpret_cast<uint8_t*>(address_ + dst_offset), src, num_bytes);
}

void WritableJitAllocation::CopyData(size_t dst_offset, const uint8_t* src,
                                     size_t num_bytes) {
  LOG_E_H
    /* JARA: Dom-v Write data */
    if(src == NULL) {
      return ;
    }
  //printf("\taddress_: 0x%lx\ttarget: 0x%lx\tsrc: %p size: %ld\n", address_, address_ + dst_offset, src, num_bytes);
    if(num_bytes >= 292)
      domv_write((void *)(address_ + dst_offset), (void *)src, num_bytes, 1);
    else
      domv_write((void *)(address_ + dst_offset), (void *)src, num_bytes, 0);
  /* End of JARA */

  //CopyBytes(reinterpret_cast<uint8_t*>(address_ + dst_offset), src, num_bytes);
}

void WritableJitAllocation::ClearBytes(size_t offset, size_t len) {
  LOG_E_H
    /* JARA: Clear jitpage */
    char temp[len] = {0, };
    domv_write((void *)(address_ + offset), temp, len, 0);
  /* End of JARA */
  
  //memset(reinterpret_cast<void*>(address_ + offset), 0, len);
}

WritableJitPage::~WritableJitPage() = default;

WritableJitPage::WritableJitPage(Address addr, size_t size)
    : write_scope_("WritableJitPage"),
      page_ref_(ThreadIsolation::LookupJitPage(addr, size)) {LOG_E_H}

WritableJitAllocation WritableJitPage::LookupAllocationContaining(
    Address addr) {
  auto pair = page_ref_.AllocationContaining(addr);
  LOG_E_H
  return WritableJitAllocation(pair.first, pair.second.Size(),
                               pair.second.Type());
}

V8_INLINE WritableFreeSpace WritableJitPage::FreeRange(Address addr,
                                                       size_t size) {
  LOG_E_H
  page_ref_.UnregisterRange(addr, size);
  return WritableFreeSpace(addr, size, true);
}

WritableFreeSpace::~WritableFreeSpace() = default;

// static
V8_INLINE WritableFreeSpace
WritableFreeSpace::ForNonExecutableMemory(base::Address addr, size_t size) {
  LOG_E_H
  return WritableFreeSpace(addr, size, false);
}

V8_INLINE WritableFreeSpace::WritableFreeSpace(base::Address addr, size_t size,
                                               bool executable)
    : address_(addr), size_(static_cast<int>(size)), executable_(executable) {}

template <typename T, size_t offset>
void WritableFreeSpace::WriteHeaderSlot(Tagged<T> value,
                                        RelaxedStoreTag) const {

  LOG_E_H

  //   printf("domv_write cand2\n");
  // printf("address_: 0x%lx, exectuable: %d\n", address_, executable_);
 
  /* Origin */
  // Tagged<HeapObject> object = HeapObject::FromAddress(address_);
  // // TODO(v8:13355): add validation before the write.
  // if constexpr (offset == HeapObject::kMapOffset) {
  //   TaggedField<T, offset>::Relaxed_Store_Map_Word(object, value);
  // } else {
  //   TaggedField<T, offset>::Relaxed_Store(object, value);
  // }
  /* End of Origin */

   /* JARA: Write header slot */
  if(executable_)
    domv_write((void *)(address_ + offset), &value, sizeof(value), 0);
  else {
    Tagged<HeapObject> object = HeapObject::FromAddress(address_);
    // TODO(v8:13355): add validation before the write.
    if constexpr (offset == HeapObject::kMapOffset) {
      TaggedField<T, offset>::Relaxed_Store_Map_Word(object, value);
    } else {
      TaggedField<T, offset>::Relaxed_Store(object, value);
    }
  }
  /* End of JARA */
  
}

template <size_t offset>
void WritableFreeSpace::ClearTagged(size_t count) const {
  base::Address start = address_ + offset;
  LOG_E_H
  // TODO(v8:13355): add validation before the write.
  MemsetTagged(ObjectSlot(start), Tagged<Object>(kClearedFreeMemoryValue),
               count);
}

#if V8_HAS_PTHREAD_JIT_WRITE_PROTECT

// static
bool RwxMemoryWriteScope::IsSupported() { return true; }

// static
void RwxMemoryWriteScope::SetWritable() { base::SetJitWriteProtected(0); }

// static
void RwxMemoryWriteScope::SetExecutable() { base::SetJitWriteProtected(1); }

#elif V8_HAS_BECORE_JIT_WRITE_PROTECT

// static
bool RwxMemoryWriteScope::IsSupported() {
  return be_memory_inline_jit_restrict_with_witness_supported() != 0;
}

// static
void RwxMemoryWriteScope::SetWritable() {
  be_memory_inline_jit_restrict_rwx_to_rw_with_witness();
}

// static
void RwxMemoryWriteScope::SetExecutable() {
  be_memory_inline_jit_restrict_rwx_to_rx_with_witness();
}

#elif V8_HAS_PKU_JIT_WRITE_PROTECT
// static
bool RwxMemoryWriteScope::IsSupported() {
  static_assert(base::MemoryProtectionKey::kNoMemoryProtectionKey == -1);
  DCHECK(ThreadIsolation::initialized());
  // TODO(sroettger): can we check this at initialization time instead? The
  // tests won't be able to run with/without pkey support anymore in the same
  // process.
  return v8_flags.memory_protection_keys && ThreadIsolation::pkey() >= 0;
}

// static
void RwxMemoryWriteScope::SetWritable() {
  DCHECK(ThreadIsolation::initialized());
  if (!IsSupported()) return;

  DCHECK_NE(
      base::MemoryProtectionKey::GetKeyPermission(ThreadIsolation::pkey()),
      base::MemoryProtectionKey::kNoRestrictions);

  base::MemoryProtectionKey::SetPermissionsForKey(
      ThreadIsolation::pkey(), base::MemoryProtectionKey::kNoRestrictions);
}

// static
void RwxMemoryWriteScope::SetExecutable() {
  DCHECK(ThreadIsolation::initialized());
  if (!IsSupported()) return;

  DCHECK_EQ(
      base::MemoryProtectionKey::GetKeyPermission(ThreadIsolation::pkey()),
      base::MemoryProtectionKey::kNoRestrictions);

  base::MemoryProtectionKey::SetPermissionsForKey(
      ThreadIsolation::pkey(), base::MemoryProtectionKey::kDisableWrite);
}

#else  // !V8_HAS_PTHREAD_JIT_WRITE_PROTECT && !V8_TRY_USE_PKU_JIT_WRITE_PROTECT

  /* JARA: Support Dom-V protection */
// static
  bool RwxMemoryWriteScope::IsSupported() {
    return ThreadIsolation::vmid() >= 0;
    //return false;
  }

// static
  void RwxMemoryWriteScope::SetWritable() {
  DCHECK(ThreadIsolation::initialized());
  if (!IsSupported()) return;

  //printf("Dom-v enter: %d\n", ThreadIsolation::vmid());
    domv_enter(ThreadIsolation::vmid());
    //printf("address: 0x%lx, size: 0x%lx\n", ThreadIsolation::JitPageReference::Address(), ThreadIsolation::JitPageReference::Size());
    //mprotect((void *)address, size, PROT_READ | PROT_EXEC);
    //mprotect((void *)0x3fe7d40000, 0x40000, PROT_READ | PROT_WRITE);
  }

// static
  void RwxMemoryWriteScope::SetExecutable() {
  DCHECK(ThreadIsolation::initialized());
  if (!IsSupported()) return;

  //printf("Dom-v exit\n");
    domv_exit();
    //printf("address: 0x%lx, size: 0x%lx\n", 0x003fe7d40000, ThreadIsolation::JitPageReference::Size());
    //mprotect((void *)0x3fe7d40000, 0x40000, PROT_READ | PROT_EXEC);
  }

#endif  // V8_HAS_PTHREAD_JIT_WRITE_PROTECT

}  // namespace internal
}  // namespace v8

#endif  // V8_COMMON_CODE_MEMORY_ACCESS_INL_H_
