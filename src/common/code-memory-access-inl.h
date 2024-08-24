// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_CODE_MEMORY_ACCESS_INL_H_
#define V8_COMMON_CODE_MEMORY_ACCESS_INL_H_

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
#if V8_TARGET_ARCH_RISCV64
extern "C" {
  #include "src/common/verse.h"
}
#endif

// #define LOG_E printf("[common/code-memory-access-inl.h] Enter: %s\n", __FUNCTION__)
// #define LOG_O printf("[common/code-memory-access-inl.h] Exit: %s\n", __FUNCTION__)

#define LOG_E
#define LOG_O

namespace v8 {
namespace internal {

ThreadIsolation::~ThreadIsolation() {
  LOG_E;
  verse_destroy(0);
  LOG_O;
}

RwxMemoryWriteScope::RwxMemoryWriteScope(const char* comment) {
  LOG_E;
  //printf("\t%s\n", comment);
  if (!v8_flags.jitless) {
    SetWritable();
  }
  LOG_O;
}

RwxMemoryWriteScope::~RwxMemoryWriteScope() {
  LOG_E;
  if (!v8_flags.jitless) {
    SetExecutable();
  }
  LOG_O;
}

WritableJitAllocation::~WritableJitAllocation() {
  LOG_E;
  if(!write_scope_) {
    return ;
  }
  if(address_ + size() > ROUND_DOWN_TO_PAGE_SIZE(address_) + ROUND_UP_TO_PAGE_SIZE(this->size())) {
    mprotect((void *) ROUND_DOWN_TO_PAGE_SIZE(address_), ROUND_UP_TO_PAGE_SIZE(this->size()) + PAGE_SIZE, PROT_READ |PROT_WRITE| PROT_EXEC);
    verse_munmap(ROUND_DOWN_TO_PAGE_SIZE(address_), ROUND_UP_TO_PAGE_SIZE(this->size()) + PAGE_SIZE);
  }
  else {
    mprotect((void *) ROUND_DOWN_TO_PAGE_SIZE(address_), ROUND_UP_TO_PAGE_SIZE(this->size()), PROT_READ |PROT_WRITE| PROT_EXEC);
    verse_munmap(ROUND_DOWN_TO_PAGE_SIZE(address_), ROUND_UP_TO_PAGE_SIZE(this->size()));
  }
  LOG_O;
} //= default;
  

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
  // verse_enter(0);
  LOG_E;
  /*
  printf("\tAddr: 0x%lx\tSize: 0x%zx\n", addr, size);
  printf("\tAligned Addr: 0x%lx\tAligned Size: 0x%zx\n", ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_UP_TO_PAGE_SIZE(size));
  */

  if(addr + size > ROUND_DOWN_TO_PAGE_SIZE(addr) + ROUND_UP_TO_PAGE_SIZE(size)) {
    mprotect((void *)ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_UP_TO_PAGE_SIZE(size) + PAGE_SIZE, PROT_READ|PROT_EXEC);
    verse_mmap(ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_UP_TO_PAGE_SIZE(size) + PAGE_SIZE, PROT_READ|PROT_WRITE);
  }
  else {
    mprotect((void *)ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_UP_TO_PAGE_SIZE(size), PROT_READ|PROT_EXEC);
    verse_mmap(ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_DOWN_TO_PAGE_SIZE(addr), ROUND_UP_TO_PAGE_SIZE(size), PROT_READ|PROT_WRITE);
  }
  LOG_O;
  // verse_exit(0);
}

WritableJitAllocation::WritableJitAllocation(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type)
  : address_(addr), allocation_(size, type) {}

// static
WritableJitAllocation WritableJitAllocation::ForNonExecutableMemory(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type) {
  // printf("NonExecutableMemory WriteableJitAllocation\n");
  return WritableJitAllocation(addr, size, type);
}

// static
WritableJitAllocation WritableJitAllocation::ForInstructionStream(
    Tagged<InstructionStream> istream) {
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
          ThreadIsolation::JitAllocationType::kWasmFarJumpTable)) {}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(T value) {
  // This assert is no strict requirement, it just guards against
  // non-implemented functionality.
  LOG_E;
  // printf("\tFirst\n");
  static_assert(!is_taggable_v<T>);

  if constexpr (offset == HeapObject::kMapOffset) {
    verse_write((void *)address_, &value, sizeof(value));
    /*
    TaggedField<T, offset>::Relaxed_Store_Map_Word(
        HeapObject::FromAddress(address_), value);
    */
  } else {
    verse_write((void *)(address_ + offset), &value, sizeof(value));
    /*
    WriteMaybeUnalignedValue<T>(address_ + offset, value);
    */
  }
  LOG_O;
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(Tagged<T> value, ReleaseStoreTag) {
  // These asserts are no strict requirements, they just guard against
  // non-implemented functionality.
  LOG_E;
  // printf("\tSecond\n");
  static_assert(offset != HeapObject::kMapOffset);

  verse_write((void *)(address_ + offset), &value, sizeof(value));
  /*
  TaggedField<T, offset>::Release_Store(HeapObject::FromAddress(address_),
                                        value);
  */
  LOG_O;
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(Tagged<T> value, RelaxedStoreTag) {
  LOG_E;
  // printf("\tThird\n");
  if constexpr (offset == HeapObject::kMapOffset) {
    verse_write((void *)(address_ + offset), &value, sizeof(value));
    /*
    TaggedField<T, offset>::Relaxed_Store_Map_Word(
        HeapObject::FromAddress(address_), value);
    */
  } else {
    verse_write((void *)(address_ + offset), &value, sizeof(value));
    /*
    TaggedField<T, offset>::Relaxed_Store(HeapObject::FromAddress(address_),
                                          value);
    */
  }
  LOG_O;
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteProtectedPointerHeaderSlot(Tagged<T> value,
                                                            RelaxedStoreTag) {
  LOG_E;
  static_assert(offset != HeapObject::kMapOffset);

  /*
  printf("\taddress_ : 0x%llx\n", address_);
  printf("\toffset: 0x%x\n", offset);
  printf("\tvalue_of_the_address: 0x%llx\n", *(unsigned long long *)address_);
  printf("\tvalue_of_the_addr+offset: 0x%llx\n", *(unsigned long long *)(address_ + offset));
  printf("\tValue: 0x%x\n", value);

  auto t = TaggedField<T, offset, TrustedSpaceCompressionScheme>::Relaxed_Load(HeapObject::FromAddress(address_));
  printf("0x%lx\n", t);
  */

  verse_write((void *)(address_ + offset), &value, sizeof(value));

  /*
  t = TaggedField<T, offset, TrustedSpaceCompressionScheme>::Relaxed_Load(HeapObject::FromAddress(address_));
  printf("0x%lx\n", t);

  printf("\tTarget: 0x%llx\n", *(unsigned long long *)address_);
  printf("\tTarget: 0x%llx\n", *(unsigned long long *)(address_ + offset));
  */
    /*
  TaggedField<T, offset, TrustedSpaceCompressionScheme>::Relaxed_Store(
      HeapObject::FromAddress(address_), value);
    */
  LOG_O;
}

template <typename T>
V8_INLINE void WritableJitAllocation::WriteHeaderSlot(Address address, T value,
                                                      RelaxedStoreTag tag) {
  LOG_E;
  //printf("\tForth\n");
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
  LOG_O;
}

void WritableJitAllocation::CopyCode(size_t dst_offset, const uint8_t* src,
                                     size_t num_bytes) {
  LOG_E;
  
  // verse_enter(0);
  // char tmp[num_bytes];
  verse_write((void *)(address_ + dst_offset), (void *)src, num_bytes);
  // CopyBytes(reinterpret_cast<uint8_t*>(tmp), reinterpret_cast<uint8_t*>(address_ + dst_offset), num_bytes);
  // printf("Written code : 0x%lx, 0x%s\n", address_ + dst_offset, tmp);
  // verse_exit(1);

  LOG_O;

  //CopyBytes(reinterpret_cast<uint8_t*>(address_ + dst_offset), src, num_bytes);
}

void WritableJitAllocation::CopyData(size_t dst_offset, const uint8_t* src,
                                     size_t num_bytes) {
  LOG_E;
  // verse_enter(0);
  verse_write((void *)(address_ + dst_offset), (void *) src, num_bytes);
  // verse_exit(1);
  //CopyBytes(reinterpret_cast<uint8_t*>(address_ + dst_offset), src, num_bytes);
  LOG_O;
}

void WritableJitAllocation::ClearBytes(size_t offset, size_t len) {
  LOG_E;
  /*
  printf("\taddress: 0x%lx\n", address_);
  printf("\tsize: 0x%lx\n", this->size());
  printf("\toffset: 0x%lx\n", offset);
  */
  if(address_ + this->size() <= address_ + offset) {
    // printf("\tsize over\n");
    memset(reinterpret_cast<void*>(address_ + offset), 0, len);
  }
  else {
    // clear Mem
    unsigned char tmp = 0;
    // unsigned char ret = 0;
    // verse_read((__u64)(address_ + offset), &ret, sizeof(ret));
    // printf("\tRet : 0x%lx\n", ret);
    for (size_t i=0; i<len; i+=sizeof(tmp)) {
      if(address_ + offset + i >= address_ + size()) {
	break;
      }
      verse_write((void *)(address_ + offset + i), &tmp, sizeof(tmp));
    }
    // verse_read((__u64)(address_ + offset), &ret, sizeof(ret));
    // printf("\tRet : 0x%lx\n", ret);
  }
  LOG_O;
}

WritableJitPage::~WritableJitPage() = default;

WritableJitPage::WritableJitPage(Address addr, size_t size)
    : write_scope_("WritableJitPage"),
      page_ref_(ThreadIsolation::LookupJitPage(addr, size)) {}

WritableJitAllocation WritableJitPage::LookupAllocationContaining(
    Address addr) {
  auto pair = page_ref_.AllocationContaining(addr);
  return WritableJitAllocation(pair.first, pair.second.Size(),
                               pair.second.Type());
}

V8_INLINE WritableFreeSpace WritableJitPage::FreeRange(Address addr,
                                                       size_t size) {
  page_ref_.UnregisterRange(addr, size);
  return WritableFreeSpace(addr, size, true);
}

WritableFreeSpace::~WritableFreeSpace() = default;

// static
V8_INLINE WritableFreeSpace
WritableFreeSpace::ForNonExecutableMemory(base::Address addr, size_t size) {
  return WritableFreeSpace(addr, size, false);
}

V8_INLINE WritableFreeSpace::WritableFreeSpace(base::Address addr, size_t size,
                                               bool executable)
    : address_(addr), size_(static_cast<int>(size)), executable_(executable) {}

template <typename T, size_t offset>
void WritableFreeSpace::WriteHeaderSlot(Tagged<T> value,
                                        RelaxedStoreTag) const {
  LOG_E;
  //printf("\tFifth\n");
  Tagged<HeapObject> object = HeapObject::FromAddress(address_);
  // TODO(v8:13355): add validation before the write.
  if constexpr (offset == HeapObject::kMapOffset) {
    TaggedField<T, offset>::Relaxed_Store_Map_Word(object, value);
  } else {
    TaggedField<T, offset>::Relaxed_Store(object, value);
  }
  LOG_O;
}

template <size_t offset>
void WritableFreeSpace::ClearTagged(size_t count) const {
  base::Address start = address_ + offset;
  // TODO(v8:13355): add validation before the write.
  LOG_E;
  MemsetTagged(ObjectSlot(start), Tagged<Object>(kClearedFreeMemoryValue),
               count);
  LOG_O;
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

#elif V8_TARGET_ARCH_RISCV64
  //static
  bool RwxMemoryWriteScope::IsSupported() {return true;}

  //static
  void RwxMemoryWriteScope::SetWritable()
  {
    LOG_E;
    verse_enter(-1);
    LOG_O;
  }

  //static
  void RwxMemoryWriteScope::SetExecutable()
  {
    LOG_E;
    verse_exit();
    LOG_O;
  }
  
#else  // !V8_HAS_PTHREAD_JIT_WRITE_PROTECT && !V8_TRY_USE_PKU_JIT_WRITE_PROTECT

// static
bool RwxMemoryWriteScope::IsSupported() { return false; }

// static
  void RwxMemoryWriteScope::SetWritable() {}

// static
  void RwxMemoryWriteScope::SetExecutable() {}

#endif  // V8_HAS_PTHREAD_JIT_WRITE_PROTECT

}  // namespace internal
}  // namespace v8

#endif  // V8_COMMON_CODE_MEMORY_ACCESS_INL_H_
