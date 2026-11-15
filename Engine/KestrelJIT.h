#ifndef KESTREL_JIT_H
#define KESTREL_JIT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Executes a generated leaf function of type uint32_t f(void).
/// Retained for the original tiny end-to-end translator self-test.
int kestrel_jit_execute(const uint32_t *words, size_t word_count, uint32_t *result);

/// Executes a translated x86_64 basic block using this context layout:
/// words 0...15 = GPRs, word 16 = RIP, word 17 = RFLAGS.
/// The generated AArch64 function has signature int f(uint64_t *context).
int kestrel_jit_execute_block(const uint32_t *words, size_t word_count, uint64_t *context_words);

/// Legacy single-region executor retained for ABI compatibility with the
/// earliest prototype. Current translated blocks use the sparse page-table ABI
/// below and must not be executed through this entry point.
int kestrel_jit_execute_block_with_memory(const uint32_t *words,
                                         size_t word_count,
                                         uint64_t *context_words,
                                         uint8_t *guest_memory,
                                         uint64_t guest_base,
                                         uint64_t guest_size,
                                         int32_t *block_result);

/// Executes a translated block against a sparse, multi-region guest page table.
/// Arrays are sorted by guest page base. `host_pages[i]` points at a stable
/// 4 KiB backing allocation; permissions use bit 0=read, 1=write, 2=execute.
/// The JIT's C memory helpers validate every byte/page before reading or
/// writing. Per-page generations and the write count are returned to Swift.
int kestrel_jit_execute_block_with_pages(const uint32_t *words,
                                         size_t word_count,
                                         uint64_t *context_words,
                                         const uint64_t *page_bases,
                                         uint8_t *const *host_pages,
                                         const uint8_t *page_permissions,
                                         uint64_t *page_generations,
                                         size_t page_count,
                                         uint64_t *write_count_out,
                                         uint64_t *fault_address_out,
                                         uint8_t *fault_permission_out,
                                         int32_t *block_result);

/// Addresses and layout information embedded into translated ARM64 blocks.
uintptr_t kestrel_guest_memory_read_helper_address(void);
uintptr_t kestrel_guest_memory_write_helper_address(void);
size_t kestrel_guest_memory_fault_offset(void);

/// Address embedded into generated AArch64 code for exact x86 arithmetic flags.
uintptr_t kestrel_x64_flag_helper_address(void);

#ifdef __cplusplus
}
#endif

#endif /* KESTREL_JIT_H */
