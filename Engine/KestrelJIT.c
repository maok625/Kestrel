#include "KestrelJIT.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#else
#error "Kestrel's native JIT executor requires macOS MAP_JIT."
#endif

#if !defined(__arm64__)
#error "Kestrel's native JIT executor currently targets Apple Silicon arm64 only."
#endif

#define KESTREL_JIT_CAPACITY (256u * 1024u)
#define KESTREL_CONTEXT_RFLAGS_WORD 17u

static void *g_jit_region = MAP_FAILED;
/// Bytes at the start of the arena that may be non-zero. Everything past this
/// offset is guaranteed to be zero, so a call only has to clear the tail left
/// behind by a previously executed (longer) block instead of the whole arena.
static size_t g_jit_dirty_bytes = 0;
static int g_jit_init_error = 0;
static pthread_once_t g_jit_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_jit_lock = PTHREAD_MUTEX_INITIALIZER;

static void kestrel_initialize_jit_region(void) {
    const int flags = MAP_PRIVATE | MAP_ANON | MAP_JIT;
    g_jit_region = mmap(NULL,
                        KESTREL_JIT_CAPACITY,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        flags,
                        -1,
                        0);
    if (g_jit_region == MAP_FAILED) {
        g_jit_init_error = errno != 0 ? errno : ENOMEM;
    }
}

static int kestrel_prepare_code(const uint32_t *words, size_t word_count, size_t *byte_count_out) {
    if (words == NULL || word_count == 0 || byte_count_out == NULL) {
        return EINVAL;
    }
    if (word_count > KESTREL_JIT_CAPACITY / sizeof(uint32_t)) {
        return E2BIG;
    }

    const int once_status = pthread_once(&g_jit_once, kestrel_initialize_jit_region);
    if (once_status != 0) {
        return once_status;
    }
    if (g_jit_init_error != 0) {
        return g_jit_init_error;
    }

    const int lock_status = pthread_mutex_lock(&g_jit_lock);
    if (lock_status != 0) {
        return lock_status;
    }

    const size_t byte_count = word_count * sizeof(uint32_t);
    // This is the sole persistent MAP_JIT arena. It contains translated host
    // instructions only, never guest x86_64 code or guest virtual addresses.
    pthread_jit_write_protect_np(0);
    memcpy(g_jit_region, words, byte_count);
    // Zero only the stale tail of a previous, longer block so that running off
    // the end of the new block still hits an all-zero (UDF) word.
    const size_t previous_dirty_bytes = g_jit_dirty_bytes;
    if (previous_dirty_bytes > byte_count) {
        memset((uint8_t *)g_jit_region + byte_count, 0, previous_dirty_bytes - byte_count);
    }
    g_jit_dirty_bytes = byte_count;
    sys_icache_invalidate(g_jit_region, previous_dirty_bytes > byte_count ? previous_dirty_bytes : byte_count);
    pthread_jit_write_protect_np(1);

    *byte_count_out = byte_count;
    return 0; // The caller owns g_jit_lock until execution completes.
}

static void kestrel_finish_execution(void) {
    (void)pthread_mutex_unlock(&g_jit_lock);
}

int kestrel_jit_execute(const uint32_t *words, size_t word_count, uint32_t *result) {
    if (result == NULL) {
        return EINVAL;
    }
    size_t byte_count = 0;
    const int status = kestrel_prepare_code(words, word_count, &byte_count);
    if (status != 0) {
        return status;
    }
    (void)byte_count;

    typedef uint32_t (*kestrel_generated_function)(void);
    kestrel_generated_function function = (kestrel_generated_function)g_jit_region;
    *result = function();

    kestrel_finish_execution();
    return 0;
}

int kestrel_jit_execute_block(const uint32_t *words, size_t word_count, uint64_t *context_words) {
    if (context_words == NULL) {
        return EINVAL;
    }
    size_t byte_count = 0;
    const int status = kestrel_prepare_code(words, word_count, &byte_count);
    if (status != 0) {
        return status;
    }
    (void)byte_count;

    typedef int (*kestrel_translated_block)(uint64_t *);
    kestrel_translated_block function = (kestrel_translated_block)g_jit_region;
    const int result = function(context_words);

    kestrel_finish_execution();
    return result;
}

int kestrel_jit_execute_block_with_memory(const uint32_t *words,
                                         size_t word_count,
                                         uint64_t *context_words,
                                         uint8_t *guest_memory,
                                         uint64_t guest_base,
                                         uint64_t guest_size,
                                         int32_t *block_result) {
    if (context_words == NULL || guest_memory == NULL || guest_size == 0u || block_result == NULL) {
        return EINVAL;
    }
    if (guest_size > UINT64_MAX - guest_base) {
        return EOVERFLOW;
    }

    size_t byte_count = 0;
    const int status = kestrel_prepare_code(words, word_count, &byte_count);
    if (status != 0) {
        return status;
    }
    (void)byte_count;

    typedef int32_t (*kestrel_translated_block)(uint64_t *, uint8_t *, uint64_t, uint64_t);
    kestrel_translated_block function = (kestrel_translated_block)g_jit_region;
    *block_result = function(context_words, guest_memory, guest_base, guest_size);

    kestrel_finish_execution();
    return 0;
}

// MARK: Sparse guest-memory ABI used by generated ARM64 blocks.

#define KESTREL_GUEST_PAGE_SIZE UINT64_C(4096)
#define KESTREL_GUEST_PERMISSION_READ  UINT8_C(0x01)
#define KESTREL_GUEST_PERMISSION_WRITE UINT8_C(0x02)
#define KESTREL_GUEST_PERMISSION_EXEC  UINT8_C(0x04)

typedef struct {
    const uint64_t *page_bases;
    uint8_t *const *host_pages;
    const uint8_t *page_permissions;
    uint64_t *page_generations;
    size_t page_count;
    int32_t fault;
    uint64_t write_count;
    uint64_t fault_address;
    uint8_t fault_permission;
} KestrelGuestMemoryView;

_Static_assert(offsetof(KestrelGuestMemoryView, fault) == 40,
               "Generated ARM64 code expects the guest-memory fault field at offset 40");

static size_t kestrel_find_guest_page(const KestrelGuestMemoryView *view, uint64_t page_base) {
    size_t low = 0;
    size_t high = view->page_count;
    while (low < high) {
        const size_t middle = low + (high - low) / 2;
        const uint64_t candidate = view->page_bases[middle];
        if (candidate < page_base) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low < view->page_count && view->page_bases[low] == page_base) {
        return low;
    }
    return SIZE_MAX;
}

/// Validates an entire scalar access before any byte is read or written. This
/// preserves all-or-nothing semantics for cross-page stores.
static int kestrel_resolve_guest_span(KestrelGuestMemoryView *view,
                                      uint64_t guest_address,
                                      uint32_t byte_count,
                                      uint8_t required_permission,
                                      size_t page_indices[2],
                                      size_t *page_index_count) {
    if (view == NULL || byte_count == 0u || byte_count > 8u ||
        guest_address > UINT64_MAX - (uint64_t)(byte_count - 1u)) {
        if (view != NULL) {
            view->fault = 1;
            view->fault_address = guest_address;
            view->fault_permission = required_permission;
        }
        return EFAULT;
    }

    const uint64_t first_page = guest_address & ~(KESTREL_GUEST_PAGE_SIZE - 1u);
    const uint64_t last_address = guest_address + (uint64_t)byte_count - 1u;
    const uint64_t last_page = last_address & ~(KESTREL_GUEST_PAGE_SIZE - 1u);
    const size_t first_index = kestrel_find_guest_page(view, first_page);
    if (first_index == SIZE_MAX) {
        // A missing page may be backed lazily by Swift if this address belongs
        // to a registered demand-zero image/stack/heap range. Fault code 2 is
        // distinct from a protection fault (code 1).
        view->fault = 2;
        view->fault_address = first_page;
        view->fault_permission = required_permission;
        return EFAULT;
    }
    if ((view->page_permissions[first_index] & required_permission) != required_permission) {
        view->fault = 1;
        view->fault_address = guest_address;
        view->fault_permission = required_permission;
        return EFAULT;
    }

    page_indices[0] = first_index;
    *page_index_count = 1u;
    if (last_page != first_page) {
        const size_t second_index = kestrel_find_guest_page(view, last_page);
        if (second_index == SIZE_MAX) {
            view->fault = 2;
            view->fault_address = last_page;
            view->fault_permission = required_permission;
            return EFAULT;
        }
        if ((view->page_permissions[second_index] & required_permission) != required_permission) {
            view->fault = 1;
            view->fault_address = last_address;
            view->fault_permission = required_permission;
            return EFAULT;
        }
        page_indices[1] = second_index;
        *page_index_count = 2u;
    }
    return 0;
}

static uint64_t kestrel_guest_memory_read(KestrelGuestMemoryView *view,
                                         uint64_t guest_address,
                                         uint32_t byte_count) {
    size_t page_indices[2] = {0u, 0u};
    size_t page_index_count = 0u;
    if (kestrel_resolve_guest_span(view, guest_address, byte_count,
                                   KESTREL_GUEST_PERMISSION_READ,
                                   page_indices, &page_index_count) != 0) {
        return 0u;
    }

    uint64_t value = 0u;
    for (uint32_t byte_index = 0u; byte_index < byte_count; ++byte_index) {
        const uint64_t current_address = guest_address + byte_index;
        const uint64_t page_base = current_address & ~(KESTREL_GUEST_PAGE_SIZE - 1u);
        const size_t page_slot = page_base == view->page_bases[page_indices[0]]
            ? page_indices[0] : page_indices[page_index_count - 1u];
        const size_t page_offset = (size_t)(current_address - page_base);
        value |= (uint64_t)view->host_pages[page_slot][page_offset] << (byte_index * 8u);
    }
    return value;
}

static int32_t kestrel_guest_memory_write(KestrelGuestMemoryView *view,
                                          uint64_t guest_address,
                                          uint64_t value,
                                          uint32_t byte_count) {
    size_t page_indices[2] = {0u, 0u};
    size_t page_index_count = 0u;
    if (kestrel_resolve_guest_span(view, guest_address, byte_count,
                                   KESTREL_GUEST_PERMISSION_WRITE,
                                   page_indices, &page_index_count) != 0) {
        return EFAULT;
    }

    // The complete range has been validated. Only now mutate guest bytes.
    for (uint32_t byte_index = 0u; byte_index < byte_count; ++byte_index) {
        const uint64_t current_address = guest_address + byte_index;
        const uint64_t page_base = current_address & ~(KESTREL_GUEST_PAGE_SIZE - 1u);
        const size_t page_slot = page_base == view->page_bases[page_indices[0]]
            ? page_indices[0] : page_indices[page_index_count - 1u];
        const size_t page_offset = (size_t)(current_address - page_base);
        view->host_pages[page_slot][page_offset] = (uint8_t)(value >> (byte_index * 8u));
    }

    for (size_t index = 0; index < page_index_count; ++index) {
        view->page_generations[page_indices[index]] += 1u;
    }
    view->write_count += 1u;
    return 0;
}

uintptr_t kestrel_guest_memory_read_helper_address(void) {
    return (uintptr_t)&kestrel_guest_memory_read;
}

uintptr_t kestrel_guest_memory_write_helper_address(void) {
    return (uintptr_t)&kestrel_guest_memory_write;
}

size_t kestrel_guest_memory_fault_offset(void) {
    return offsetof(KestrelGuestMemoryView, fault);
}

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
                                         int32_t *block_result) {
    if (context_words == NULL || block_result == NULL || write_count_out == NULL ||
        fault_address_out == NULL || fault_permission_out == NULL) {
        return EINVAL;
    }
    if (page_count > 0u && (page_bases == NULL || host_pages == NULL ||
                            page_permissions == NULL || page_generations == NULL)) {
        return EINVAL;
    }

    for (size_t index = 0; index < page_count; ++index) {
        if (page_bases[index] % KESTREL_GUEST_PAGE_SIZE != 0u ||
            host_pages[index] == NULL || (page_permissions[index] & ~UINT8_C(0x07)) != 0u ||
            (index > 0u && page_bases[index - 1u] >= page_bases[index])) {
            return EINVAL;
        }
    }

    size_t byte_count = 0u;
    const int status = kestrel_prepare_code(words, word_count, &byte_count);
    if (status != 0) {
        return status;
    }
    (void)byte_count;

    KestrelGuestMemoryView view = {
        .page_bases = page_bases,
        .host_pages = host_pages,
        .page_permissions = page_permissions,
        .page_generations = page_generations,
        .page_count = page_count,
        .fault = 0,
        .write_count = 0u,
        .fault_address = 0u,
        .fault_permission = 0u
    };

    typedef int32_t (*kestrel_sparse_translated_block)(uint64_t *, KestrelGuestMemoryView *);
    kestrel_sparse_translated_block function = (kestrel_sparse_translated_block)g_jit_region;
    *block_result = function(context_words, &view);
    *write_count_out = view.write_count;
    *fault_address_out = view.fault_address;
    *fault_permission_out = view.fault_permission;
    if (view.fault == 2) {
        *block_result = 3; // Swift may resolve one demand-zero page and retry.
    } else if (view.fault != 0) {
        *block_result = 2; // protection or invalid guest-memory fault.
    }

    kestrel_finish_execution();
    return 0;
}

static uint64_t kestrel_width_mask(uint32_t width) {
    if (width >= 64u) {
        return UINT64_MAX;
    }
    if (width == 0u) {
        return 0u;
    }
    return (UINT64_C(1) << width) - 1u;
}

static int kestrel_even_parity(uint8_t value) {
    return (__builtin_popcount((unsigned)value) & 1) == 0;
}

/// kind: 0=ADD, 1=SUB/CMP, 2=logical XOR.
/// The arithmetic itself is emitted as native AArch64 instructions. This
/// helper only writes architecturally exact x86 CF/PF/AF/ZF/SF/OF into RFLAGS.
static void kestrel_x64_update_flags(uint64_t *context_words,
                                     uint64_t lhs,
                                     uint64_t rhs,
                                     uint64_t result,
                                     uint32_t width,
                                     uint32_t kind) {
    if (context_words == NULL || width == 0u || width > 64u || kind > 2u) {
        return;
    }

    const uint64_t mask = kestrel_width_mask(width);
    const uint64_t sign_bit = UINT64_C(1) << (width - 1u);
    const uint64_t a = lhs & mask;
    const uint64_t b = rhs & mask;
    const uint64_t r = result & mask;

    const uint64_t CF = UINT64_C(1) << 0;
    const uint64_t PF = UINT64_C(1) << 2;
    const uint64_t AF = UINT64_C(1) << 4;
    const uint64_t ZF = UINT64_C(1) << 6;
    const uint64_t SF = UINT64_C(1) << 7;
    const uint64_t OF = UINT64_C(1) << 11;
    const uint64_t arithmetic_mask = CF | PF | AF | ZF | SF | OF;

    uint64_t flags = context_words[KESTREL_CONTEXT_RFLAGS_WORD] & ~arithmetic_mask;
    if (kestrel_even_parity((uint8_t)r)) {
        flags |= PF;
    }
    if (r == 0u) {
        flags |= ZF;
    }
    if ((r & sign_bit) != 0u) {
        flags |= SF;
    }

    if (kind == 0u) {
        const __uint128_t sum = (__uint128_t)a + (__uint128_t)b;
        if ((sum >> width) != 0u) {
            flags |= CF;
        }
        if (((~(a ^ b) & (a ^ r)) & sign_bit) != 0u) {
            flags |= OF;
        }
        if (((a ^ b ^ r) & UINT64_C(0x10)) != 0u) {
            flags |= AF;
        }
    } else if (kind == 1u) {
        if (a < b) {
            flags |= CF;
        }
        if ((((a ^ b) & (a ^ r)) & sign_bit) != 0u) {
            flags |= OF;
        }
        if (((a ^ b ^ r) & UINT64_C(0x10)) != 0u) {
            flags |= AF;
        }
    } else {
        // XOR defines CF=0 and OF=0; AF is undefined, so retain its old value.
        flags |= context_words[KESTREL_CONTEXT_RFLAGS_WORD] & AF;
    }

    context_words[KESTREL_CONTEXT_RFLAGS_WORD] = flags | UINT64_C(0x2);
}

uintptr_t kestrel_x64_flag_helper_address(void) {
    return (uintptr_t)&kestrel_x64_update_flags;
}
