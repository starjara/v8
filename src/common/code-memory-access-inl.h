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
  // #include "src/common/verse.h"
  #include <sys/mman.h>
#undef MAP_TYPE
  //#define LOG_E printf("[common/code-memory-access-inl.h] Enter: %s\n", __func__);
  //#define LOG_O printf("[common/code-memory-access-inl.h] Exit: %s\n", __func__);
  #define LOG_E
  #define LOG_O
}
#endif

namespace v8 {
namespace internal {

RwxMemoryWriteScope::RwxMemoryWriteScope(const char* comment) {
  if (!v8_flags.jitless) {

#if V8_TARGET_ARCH_RISCV64
    LOG_E
      //printf("\t%s\n", comment);
      /*
    if(this->scope == NULL) {
      printf("scope not initialzed\n");
      return ;
    }
    if(this->scope->address() == 0) {
      printf("address not initizlied\n");
      return ;
    }
      */
    /*
    if(address_ == 0 || size_ == 0) {
      return ;
    }
    void *addr = (void *)address_;
    printf("\taddress_: 0x%lx\n", address_);

    size_t size = size_;
    printf("\tsize_: 0x%lx\n", size_);
    SetWritable(addr, size);
    */
#else
    SetWritable();
#endif
  }
}

RwxMemoryWriteScope::~RwxMemoryWriteScope() {
  if (!v8_flags.jitless) {
 #if V8_TARGET_ARCH_RISCV64
    LOG_E
      /*
    if(this->scope == NULL) {
      printf("scope not initialzed\n");
      return ;
    }
    if(this->scope->address() == 0) {
      printf("address not initizlied\n");
      return ;
    } 
    void *addr = (void *)(this->scope->address());
    printf("0x%lx\n", (unsigned long)addr);
    
    size_t size = this->scope->size();
    printf("0x%lx\n", size);
      */
    void *addr = (void *)address_;
    //printf("\t0x%lx\n", address_);

    size_t size = size_;
    //printf("\t0x%lx\n", size_);
    SetExecutable(addr, size);
#else
   SetExecutable();
#endif
  }
}

  WritableJitAllocation::~WritableJitAllocation() {
    LOG_E
      /*
      if(write_scope_) {
	//printf("\tHave write scope\n");
	//printf("\tAddr: 0x%lx\tSize: 0x%lx\n", this->address(), this->size());
	//printf("\tPage Addr: 0x%lx\tPage Size: 0x%lx\n", page_ref_->Address(), page_ref_->Size());
	//mprotect((void *)this->address(), this->size(), PROT_READ | PROT_EXEC);
	//mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_EXEC | PROT_READ);
      }
      else
      //printf("No WriteScope\n");
      */
  }//= default;

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
		  : page_ref_->LookupAllocation(addr, size, type)) { LOG_E
    /*
	printf("\tWith write scope\n");
	printf("\tAddr: 0x%lx\tSize: 0x%lx\n", this->address(), this->size());
	printf("\tPage Addr: 0x%lx\tPage Size: 0x%lx\n", page_ref_->Address(), page_ref_->Size());
    */
	write_scope_->SetInit(page_ref_->Address(), page_ref_->Size());
	//mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_WRITE | PROT_READ | PROT_EXEC);
}

WritableJitAllocation::WritableJitAllocation(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type)
  : address_(addr), allocation_(size, type) { LOG_E
    /*
	printf("\tWithout write scope\n");
	printf("\tAddr: 0x%lx\tSize: 0x%lx\n", this->address(), this->size());
    */
    //mprotect((void *)addr, size, PROT_WRITE | PROT_READ | PROT_EXEC);
}

// static
WritableJitAllocation WritableJitAllocation::ForNonExecutableMemory(
    Address addr, size_t size, ThreadIsolation::JitAllocationType type) {
      LOG_E
	/*
	printf("\tNonExecutable\n");
	printf("\tAddr: 0x%lx\tSize: 0x%lx\n", addr, size);
	*/
  return WritableJitAllocation(addr, size, type);
}

// static
WritableJitAllocation WritableJitAllocation::ForInstructionStream(
    Tagged<InstructionStream> istream) {
      LOG_E
	//printf("\tInstructionStream\n");
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
  static_assert(!is_taggable_v<T>);
      LOG_E
	//printf("First\n");
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  if constexpr (offset == HeapObject::kMapOffset) {
    TaggedField<T, offset>::Relaxed_Store_Map_Word(
        HeapObject::FromAddress(address_), value);
  } else {
    WriteMaybeUnalignedValue<T>(address_ + offset, value);
  }
  //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(Tagged<T> value, ReleaseStoreTag) {
  // These asserts are no strict requirements, they just guard against
  // non-implemented functionality.
      LOG_E
	//printf("Second\n");
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  static_assert(offset != HeapObject::kMapOffset);

  TaggedField<T, offset>::Release_Store(HeapObject::FromAddress(address_),
                                        value);
  //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteHeaderSlot(Tagged<T> value, RelaxedStoreTag) {
  LOG_E
    //printf("Third\n");
  // mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  if constexpr (offset == HeapObject::kMapOffset) {
    TaggedField<T, offset>::Relaxed_Store_Map_Word(
        HeapObject::FromAddress(address_), value);
  } else {
    TaggedField<T, offset>::Relaxed_Store(HeapObject::FromAddress(address_),
                                          value);
  }
  //   mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
  LOG_O
}

template <typename T, size_t offset>
void WritableJitAllocation::WriteProtectedPointerHeaderSlot(Tagged<T> value,
                                                            RelaxedStoreTag) {
      LOG_E
	//mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  static_assert(offset != HeapObject::kMapOffset);
  TaggedField<T, offset, TrustedSpaceCompressionScheme>::Relaxed_Store(
      HeapObject::FromAddress(address_), value);
  //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

template <typename T>
V8_INLINE void WritableJitAllocation::WriteHeaderSlot(Address address, T value,
                                                      RelaxedStoreTag tag) {
      LOG_E
	//printf("Fourth\n");
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
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
  // mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

void WritableJitAllocation::CopyCode(size_t dst_offset, const uint8_t* src,
                                     size_t num_bytes) {
      LOG_E
	//mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  CopyBytes(reinterpret_cast<uint8_t*>(address_ + dst_offset), src, num_bytes);
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

void WritableJitAllocation::CopyData(size_t dst_offset, const uint8_t* src,
                                     size_t num_bytes) {
      LOG_E
	//mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  CopyBytes(reinterpret_cast<uint8_t*>(address_ + dst_offset), src, num_bytes);
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      //printf("End of the CopyData\n");
      LOG_O
}

void WritableJitAllocation::ClearBytes(size_t offset, size_t len) {
      LOG_E
	//mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  memset(reinterpret_cast<void*>(address_ + offset), 0, len);
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

WritableJitPage::~WritableJitPage() = default;

WritableJitPage::WritableJitPage(Address addr, size_t size)
    : write_scope_("WritableJitPage"),
      page_ref_(ThreadIsolation::LookupJitPage(addr, size)) {write_scope_.SetInit(page_ref_.Address(), page_ref_.Size());}

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
      LOG_E
	//printf("Here\n");
	//printf("\taddr: 0x%lx\tsize: 0x%lx\n", this->address_, this->size_);
      /*
      {
      if(this->Executable()) {
	mprotect((void *)this->address_, this->size_, PROT_READ | PROT_EXEC | PROT_WRITE);
      }
      else {
	mprotect((void *)this->address_, this->size_, PROT_READ | PROT_WRITE);
      }
      }
      */
      //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC | PROT_WRITE);
  Tagged<HeapObject> object = HeapObject::FromAddress(address_);
  // TODO(v8:13355): add validation before the write.
  if constexpr (offset == HeapObject::kMapOffset) {
    TaggedField<T, offset>::Relaxed_Store_Map_Word(object, value);
  } else {
    TaggedField<T, offset>::Relaxed_Store(object, value);
  }
  //mprotect((void *)page_ref_->Address(), page_ref_->Size(), PROT_READ | PROT_EXEC );
      LOG_O
}

template <size_t offset>
void WritableFreeSpace::ClearTagged(size_t count) const {
  base::Address start = address_ + offset;
  // TODO(v8:13355): add validation before the write.
      LOG_E
  MemsetTagged(ObjectSlot(start), Tagged<Object>(kClearedFreeMemoryValue),
               count);
      LOG_O
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
bool RwxMemoryWriteScope::IsSupported() { return true; }

// static
  void RwxMemoryWriteScope::SetWritable() {
    LOG_E
      //printf("Nothing\n");
  }
  void RwxMemoryWriteScope::SetWritable(void *addr, size_t size) {
    LOG_E
      //printf("\tAddr: 0x%lx\tSize: 0x%lx\n", addr, size);
      mprotect(addr, size, PROT_READ | PROT_EXEC | PROT_WRITE);
    LOG_O
  }


//static
  void RwxMemoryWriteScope::SetExecutable() {
    LOG_E
      //printf("Nothing\n");
  }
  void RwxMemoryWriteScope::SetExecutable(void *addr, size_t size) {
    LOG_E
      //printf("\tAddr: 0x%lx\tSize: 0x%lx\n", addr, size);
      mprotect(addr, size, PROT_READ | PROT_EXEC);
    LOG_O
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
