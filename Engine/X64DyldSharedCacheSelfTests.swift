import Foundation

enum X64DyldSharedCacheSelfTests {
    static func run() throws -> [String] {
        var passed: [String] = []

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            try expect(cache.magic.contains("x86_64"), "cache architecture magic")
            try expect(cache.mappings.count == 2, "mapping count")
            try expect(cache.images.count == 2, "image count")
            try expect(cache.x86_64ImageCount == 2, "x86_64 image header count")
            try expect(cache.images[0].fileType == 6 || cache.images[1].fileType == 6, "MH_DYLIB cache image header")
            passed.append("x86_64 shared-cache header, mapping table and image-info array parse")
        }

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            guard let location = X64DyldSharedCacheReader.fileLocation(
                forVMAddress: 0x7FFF_0000_0000 + 0x123,
                mappings: cache.mappings
            ) else { throw failure("VM address was not translated through the cache mapping") }
            try expect(location.fileOffset == 0x1123, "VM-to-file offset")
            passed.append("Shared-cache VM addresses translate to validated on-disk mapping offsets")
        }

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependencies = [
                X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load),
                X64MachODylibDependency(ordinal: 2, installName: "/usr/lib/libMissing.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            ]
            let matches = cache.matchDependencies(dependencies)
            try expect(matches.count == 2, "dependency match count")
            try expect(matches[0].image?.machHeaderAddress == 0x7FFF_0000_0000, "exact install-name match")
            try expect(matches[1].image == nil, "missing dependency should remain unresolved")
            passed.append("Dependency install names match exact cached image paths without basename guessing")
        }

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let bytes = try cache.readVMBytes(atVMAddress: 0x7FFF_0000_0FF8, count: 16)
            try expect(bytes.count == 16, "cross-mapping VM read length")
            try expect(bytes[8] == 0xCF && bytes[9] == 0xFA && bytes[10] == 0xED && bytes[11] == 0xFE, "next mapping Mach-O header bytes")
            passed.append("Shared-cache VM reader retrieves Mach-O bytes through the validated backing mapping")
        }

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependencies = [
                X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load),
                X64MachODylibDependency(ordinal: 2, installName: "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            ]
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: dependencies)
            try expect(plan.images.count == 2, "cached dependency image plan count")
            try expect(plan.totalSegmentCount == 2, "cached segment plan count")
            try expect(plan.executableSegmentCount == 2, "executable segment inventory")
            try expect(plan.totalVirtualBytes == 0x2000, "cached segment virtual byte count")
            try expect(plan.images[0].segmentPlans[0].name == "__TEXT", "cached __TEXT segment name")
            passed.append("Cached dependency Mach-O load commands produce exact segment and page-rounded mapping plans")
        }

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            var rejected = false
            do {
                _ = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency], maximumVirtualBytes: 0x0FFF)
            } catch {
                rejected = error.localizedDescription.contains("16 GiB preflight limit")
            }
            try expect(rejected, "preflight virtual-size safety limit")
            passed.append("Cached-image mapping preflight enforces its aggregate virtual-size safety limit")
        }

        do {
            // Reproduces the real Rosetta-cache libSystem segment's
            // non-page-multiple Mach-O vmsize at a guest-page-aligned start.
            let url = try makeCacheFile(segmentVMSize: 0x1BAE)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency])
            let segment = try unwrap(plan.images.first?.segmentPlans.first, "unaligned-size segment plan")
            try expect(segment.virtualSize == 0x1BAE, "preserve exact LC_SEGMENT_64 vmsize")
            try expect(segment.pageRoundedSize == 0x2000, "round reservation to complete 4 KiB guest pages")
            try expect(plan.totalVirtualBytes == 0x1BAE, "exact total segment bytes")
            try expect(plan.totalPageRoundedReservationBytes == 0x2000, "page-rounded reservation accounting")
            passed.append("Valid non-page-multiple Mach-O segment sizes are accepted when their complete guest-page reservation is cache-backed")
        }

        do {
            // Reproduces a compacted shared-cache segment whose exact start is
            // inside a guest page: __DATA_CONST vmaddr=...A640, vmsize=0x3C8.
            let url = try makeCacheFile(segmentVMSize: 0x3C8, segmentVMAddressOffset: 0x640)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency])
            let segment = try unwrap(plan.images.first?.segmentPlans.first, "unaligned-start segment plan")
            try expect(segment.virtualAddress == 0x7FFF_0000_0640, "preserve exact unaligned segment start")
            try expect(segment.virtualSize == 0x3C8, "preserve exact unaligned segment size")
            try expect(segment.pageRoundedAddress == 0x7FFF_0000_0000, "round guest page start down")
            try expect(segment.pageRoundedSize == 0x1000, "round guest page end up")
            try expect(plan.totalVirtualBytes == 0x3C8, "unaligned exact bytes are not inflated")
            try expect(plan.totalPageRoundedReservationBytes == 0x1000, "only containing guest page is reserved")
            passed.append("Sub-page-aligned shared-cache segment starts and sizes are accepted with exact bytes preserved and guest pages rounded outward")
        }

        do {
            // Two adjacent exact segments occupy different byte ranges in one
            // guest page, as can happen in a compacted dyld shared cache.
            let url = try makeCacheFile(
                segmentVMSize: 0x3C8,
                segmentVMAddressOffset: 0x640,
                secondSegmentVMAddressOffset: 0xA08,
                secondSegmentVMSize: 0x300
            )
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency])
            try expect(plan.totalSegmentCount == 2, "two compacted segments parsed")
            try expect(plan.totalVirtualBytes == 0x6C8, "sum exact adjacent segment bytes")
            try expect(plan.totalPageRoundedReservationBytes == 0x1000, "one shared guest page counted once")
            try expect(plan.images[0].pageRoundedReservationBytes == 0x1000, "per-image page union counted once")
            passed.append("Byte-adjacent shared-cache segments may share a guest page without double-counting its reservation")
        }

        do {
            // Two separate cache images have disjoint exact segments but share
            // one 4 KiB guest page. The global plan must not double-count it.
            let url = try makeCacheFile(
                segmentVMSize: 0x3C8,
                segmentVMAddressOffset: 0x1640,
                secondImageSegmentVMAddressOffset: 0x1A08,
                secondImageSegmentVMSize: 0x300
            )
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependencies = [
                X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load),
                X64MachODylibDependency(ordinal: 2, installName: "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            ]
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: dependencies)
            try expect(plan.images.count == 2, "two cached images planned")
            try expect(plan.images[0].pageRoundedReservationBytes == 0x1000, "first image page reservation")
            try expect(plan.images[1].pageRoundedReservationBytes == 0x1000, "second image page reservation")
            try expect(plan.totalPageRoundedReservationBytes == 0x1000, "global shared page deduplicated")
            passed.append("Guest-page reservation accounting deduplicates one page shared by distinct cached images")
        }

        do {
            let url = try makeCacheFile(segmentVMSize: 0x1BAE, truncateAfterFirstMapping: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            var rejected = false
            do { _ = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency]) }
            catch { rejected = error.localizedDescription.contains("guest page range") && error.localizedDescription.contains("not fully covered") }
            try expect(rejected, "page-rounded cache coverage")
            passed.append("Page-rounded segment coverage still rejects cache mappings that end inside the guest reservation page span")
        }

        do {
            let url = try makeCacheFile(invalidSegmentMapping: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            var rejected = false
            do { _ = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency]) }
            catch { rejected = error.localizedDescription.contains("guest page range") && error.localizedDescription.contains("not fully covered") }
            try expect(rejected, "out-of-mapping cached segment must be rejected")
            passed.append("Cached-image segment ranges outside validated cache mappings are rejected during preflight")
        }

        do {
            let url = try makeCacheFile(magic: "dyld_v1  arm64e")
            defer { try? FileManager.default.removeItem(at: url) }
            var rejected = false
            do { _ = try X64DyldSharedCacheReader.open(url) }
            catch X64DyldSharedCacheError.unsupportedArchitecture { rejected = true }
            try expect(rejected, "ARM64 cache must not be treated as x86_64")
            passed.append("ARM64 shared caches are rejected rather than used for x86_64 guest dependencies")
        }

        do {
            let url = try makeCacheFile(magic: "dyld_v1  x86_64h")
            defer { try? FileManager.default.removeItem(at: url) }
            var rejected = false
            do { _ = try X64DyldSharedCacheReader.open(url) }
            catch X64DyldSharedCacheError.unsupportedArchitecture { rejected = true }
            try expect(rejected, "x86_64h cache must not be silently substituted for baseline x86_64")
            passed.append("x86_64h shared caches are not substituted for the baseline x86_64 cache")
        }

        do {
            let paths = X64DyldSharedCacheReader.defaultCandidatePaths()
            let fullRosetta = "/System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld/dyld_shared_cache_x86_64"
            let reducedRosetta = "/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64"
            try expect(paths.first == fullRosetta, "full Rosetta cache should be preferred")
            try expect(paths.count > 1 && paths[1] == reducedRosetta, "reduced x86Support cache should be second")
            try expect(paths.contains("/System/Volumes/Preboot/Cryptexes/Incoming/Rosetta/System/Library/dyld/dyld_shared_cache_x86_64"), "staged Rosetta cache candidate")
            try expect(paths.contains("/System/Library/dyld/dyld_shared_cache_x86_64"), "legacy system cache candidate")
            passed.append("Default discovery searches full and reduced Rosetta Cryptex caches before legacy OS cache paths")
        }

        do {
            let wrongArchitectureURL = try makeCacheFile(magic: "dyld_v1  arm64e")
            let validRosettaURL = try makeCacheFile()
            defer {
                try? FileManager.default.removeItem(at: wrongArchitectureURL)
                try? FileManager.default.removeItem(at: validRosettaURL)
            }
            let cache = try X64DyldSharedCacheReader.discoverDefault(candidates: [wrongArchitectureURL, validRosettaURL])
            try expect(cache.url.path == validRosettaURL.standardizedFileURL.path, "discovery must continue after rejecting a non-x86_64 cache")
            passed.append("Discovery skips an existing ARM64 cache candidate and continues to the valid x86_64 Rosetta candidate")
        }

        do {
            let firstURL = try makeCacheFile(magic: "dyld_v1  arm64e")
            let secondURL = try makeCacheFile(magic: "dyld_v1  x86_64h")
            defer {
                try? FileManager.default.removeItem(at: firstURL)
                try? FileManager.default.removeItem(at: secondURL)
            }
            var diagnostic = ""
            do {
                _ = try X64DyldSharedCacheReader.discoverDefault(candidates: [firstURL, secondURL])
            } catch {
                diagnostic = error.localizedDescription
            }
            try expect(diagnostic.contains(firstURL.lastPathComponent), "diagnostic should include first rejected candidate")
            try expect(diagnostic.contains(secondURL.lastPathComponent), "diagnostic should include second rejected candidate")
            try expect(diagnostic.contains("baseline x86_64"), "diagnostic should explain architecture mismatch")
            passed.append("When all existing candidates are incompatible, discovery reports every rejection instead of hiding the cause")
        }

        do {
            let url = try makeCacheFile(invalidMapping: true)
            defer { try? FileManager.default.removeItem(at: url) }
            var rejected = false
            do { _ = try X64DyldSharedCacheReader.open(url) }
            catch { rejected = true }
            try expect(rejected, "out-of-file mapping must be rejected")
            passed.append("Out-of-file cache mappings are rejected before image lookup")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let slideInfo = try unwrap(try X64DyldSharedCacheReader.analyzeSlideInfo(in: cache).first, "v2 slide-info summary")
            try expect(cache.slideMappings.count == 1, "mapping-with-slide record count")
            try expect(slideInfo.version == 2, "slide-info version")
            try expect(slideInfo.pageSize == 4096 && slideInfo.pageCount == 1, "slide-info guest page geometry")
            try expect(slideInfo.pagesWithRebases == 0 && slideInfo.chainCount == 0, "no-rebase page should be empty")
            passed.append("Modern mapping-with-slide records and version-2 slide-info headers/page tables parse")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true, slideInfoHasChain: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let slideInfo = try unwrap(try X64DyldSharedCacheReader.analyzeSlideInfo(in: cache).first, "decoded v2 slide-info summary")
            try expect(slideInfo.pagesWithRebases == 1, "one page contains rebases")
            try expect(slideInfo.chainCount == 1, "single direct chain")
            try expect(slideInfo.rebasingPointerCount == 2, "two nonzero pointer locations")
            passed.append("Version-2 direct pointer chains are walked and their rebasing locations counted without modifying cache bytes")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true, slideInfoUsesExtras: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let slideInfo = try unwrap(try X64DyldSharedCacheReader.analyzeSlideInfo(in: cache).first, "v2 extra-chain summary")
            try expect(slideInfo.chainCount == 2, "two extra chain starts")
            try expect(slideInfo.rebasingPointerCount == 2, "two extra-chain pointers")
            passed.append("Version-2 page-extras entries and per-page multiple chains are decoded with END validation")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true, slideInfoHasChain: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency])
            var guestMemory = try X64GuestVirtualMemory()
            let summary = try X64DyldSharedCacheMaterializer.materialize(
                cache: cache,
                plan: plan,
                into: &guestMemory,
                cacheSlideAmount: 0
            )
            let pageAddress: UInt64 = 0x7FFF_0000_0000
            try expect(summary.imageCount == 1 && summary.pageCount == 1, "single dependency page materialized")
            try expect(summary.byteCount == 0x1000 && summary.rebasedPointerCount == 2, "guest page bytes and v2 pointer count")
            try expect(guestMemory.isCommitted(address: pageAddress), "cache page committed in guest VM")
            try expect(guestMemory.permissions(at: pageAddress) == .readExecute, "cache mapping RX protection applied")
            try expect(try guestMemory.readUnsigned(at: pageAddress + 0x800, byteCount: 8) == 0x7FFF_0000_1000, "first pointer rebuilt using v2 value-add")
            try expect(try guestMemory.readUnsigned(at: pageAddress + 0x808, byteCount: 8) == 0x7FFF_0000_2000, "terminal pointer rebuilt using v2 value-add")
            let unchangedSource = try cache.readVMBytes(atVMAddress: pageAddress + 0x800, count: 8)
            let sourceWord = unchangedSource.enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << ($1.offset * 8)) }
            try expect(sourceWord == 0x8000_0000_0000_1000, "source shared-cache bytes remain unchanged")
            var writeDenied = false
            do { try guestMemory.writeUnsigned(0xAA, at: pageAddress, byteCount: 1) }
            catch { writeDenied = true }
            try expect(writeDenied, "materialized cache RX page rejects guest writes")

            var explicitlySlidMemory = try X64GuestVirtualMemory()
            let explicitlySlidSummary = try X64DyldSharedCacheMaterializer.materialize(
                cache: cache,
                plan: plan,
                into: &explicitlySlidMemory,
                cacheSlideAmount: 0x2000
            )
            try expect(explicitlySlidSummary.cacheSlideAmount == 0x2000, "nonzero cache slide is recorded")
            try expect(try explicitlySlidMemory.readUnsigned(at: pageAddress + 0x800, byteCount: 8) == 0x7FFF_0000_3000, "explicit cache slide is added after value-add")
            passed.append("Selected cache pages are privately copied, v2 value-add/slide reconstructed, source bytes preserved, and cache VM protections installed")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true, slideInfoHasChain: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let dependency = X64MachODylibDependency(ordinal: 1, installName: "/usr/lib/libSystem.B.dylib", timestamp: 0, currentVersion: 0, compatibilityVersion: 0, kind: .load)
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: [dependency])
            var guestMemory = try X64GuestVirtualMemory()
            _ = try guestMemory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .image)
            var rejected = false
            do {
                _ = try X64DyldSharedCacheMaterializer.materialize(cache: cache, plan: plan, into: &guestMemory)
            } catch { rejected = true }
            try expect(rejected, "materializer must reject guest address collisions")
            try expect(guestMemory.reservedRegionCount == 1 && guestMemory.committedPageCount == 0, "failed transaction leaves original guest memory unchanged")
            passed.append("Shared-cache materialization rolls back completely when a guest address reservation collides")
        }

        do {
            let url = try makeCacheFile()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let overLimitBytes: UInt64 = 2 * 1024 * 1024 * 1024 + 0x1000
            let segment = X64DyldSharedCacheImageSegmentPlan(
                name: "__TEXT",
                virtualAddress: 0x7FFF_0000_0000,
                virtualSize: overLimitBytes,
                pageRoundedAddress: 0x7FFF_0000_0000,
                pageRoundedSize: overLimitBytes,
                maximumProtection: 0x5,
                initialProtection: 0x5
            )
            let image = X64DyldSharedCacheImagePlan(
                installName: "/usr/lib/libSynthetic.dylib",
                machHeaderAddress: 0x7FFF_0000_0000,
                segmentPlans: [segment]
            )
            let oversizedPlan = X64DyldSharedCacheMappingPlan(
                cacheUUID: cache.uuid,
                images: [image],
                slideInfoSummaries: [],
                reservedMappingCount: 1,
                totalVirtualBytes: overLimitBytes,
                totalPageRoundedReservationBytes: overLimitBytes,
                executableSegmentCount: 1,
                linkeditSegmentCount: 0
            )
            var guestMemory = try X64GuestVirtualMemory()
            var rejected = false
            do {
                _ = try X64DyldSharedCacheMaterializer.materialize(
                    cache: cache,
                    plan: oversizedPlan,
                    into: &guestMemory
                )
            } catch {
                rejected = error.localizedDescription.contains("2 GiB allocation safety limit")
            }
            try expect(rejected, "materializer must enforce the 2 GiB backing-allocation limit")
            try expect(guestMemory.reservedRegionCount == 0 && guestMemory.committedPageCount == 0, "over-limit plan must not mutate guest memory")
            passed.append("Shared-cache materialization rejects plans above the 2 GiB host-backing ceiling before allocating pages")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true, slideInfoVersion: 3)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            var rejected = false
            do { _ = try X64DyldSharedCacheReader.analyzeSlideInfo(in: cache) }
            catch X64DyldSharedCacheError.unsupportedFormat(let message) { rejected = message.contains("version 3") }
            try expect(rejected, "unsupported slide-info versions must fail closed")
            passed.append("Unknown/non-v2 shared-cache slide-info formats are rejected explicitly rather than misdecoded")
        }

        do {
            let url = try makeCacheFile(includeSlideInfo: true, invalidSlideInfoRange: true)
            defer { try? FileManager.default.removeItem(at: url) }
            var rejected = false
            do { _ = try X64DyldSharedCacheReader.open(url) }
            catch { rejected = error.localizedDescription.contains("slide-info file range") }
            try expect(rejected, "out-of-file slide-info ranges must be rejected during cache inventory")
            passed.append("Slide-info blob offsets and sizes are checked against their own primary/subcache backing files")
        }

        do {
            let url = try makeCacheFileWithExports()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            guard let image = cache.images.first else { throw failure("synthetic cached image record") }
            let metadata = try X64DyldSharedCacheImageMetadataReader.read(cache: cache, image: image)
            try expect(metadata.dependencies.isEmpty, "cached image dependency list")
            try expect(metadata.exports.count == 1, "cached export trie count")
            try expect(metadata.exports[0].symbolName == "_puts", "cached export name")
            try expect(metadata.exports[0].addressOffset == 0x100, "cached export image-relative address")
            try expect(metadata.exportTrieByteCount == 14, "cached export trie byte count")
            passed.append("Cached image reader translates __LINKEDIT export offsets through cache VM mappings and decodes export tries")
        }

        do {
            let url = try makeCacheFileWithExports()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable())
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_0000, byteCount: 0x1000, permissions: .readExecute)
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(resolution.resolvedImportCount == 1, "cached import resolution count")
            try expect(resolution.resolver.resolve(symbol: "_puts", dependency: image.dependencies[0]) == 0x7FFF_0000_0100, "dependency-qualified cached export resolution")
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: resolution.resolver, requireAllBindingsResolved: true)
            try expect(loaded.unresolvedBindSymbols.isEmpty, "no unresolved cached import")
            try expect(try memory.readUnsigned(at: image.bindActions[0].location, byteCount: 8) == 0x7FFF_0000_0100, "cached export pointer written to direct import slot")
            passed.append("Cached two-level export resolution feeds the Mach-O binder using a guest address, never a host pointer")
        }

        do {
            let url = try makeCacheFileWithExports(stubAndResolver: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            var regularMemory = try X64GuestVirtualMemory()
            try regularMemory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .shared)
            try regularMemory.commit(at: 0x7FFF_0000_0000, byteCount: 0x1000, permissions: .readExecute)
            let regularImage = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable())
            let regularResolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: regularImage,
                guestMemory: regularMemory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(regularResolution.resolvedImportCount == 1, "non-lazy STUB_AND_RESOLVER export resolves")
            try expect(
                regularResolution.resolver.resolve(symbol: "_puts", dependency: regularImage.dependencies[0]) == 0x7FFF_0000_0100,
                "non-lazy bind uses the export's stub offset, not its resolver offset"
            )

            var lazyMemory = try X64GuestVirtualMemory()
            try lazyMemory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .shared)
            try lazyMemory.commit(at: 0x7FFF_0000_0000, byteCount: 0x1000, permissions: .readExecute)
            let lazyImage = try X64MachOParser.parse(
                data: X64MachOLoaderSelfTests.makeBoundThinExecutable(bindStream: .lazy)
            )
            let lazyResolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: lazyImage,
                guestMemory: lazyMemory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(lazyImage.lazyBindActions.count == 1, "lazy STUB_AND_RESOLVER fixture stream")
            try expect(lazyResolution.resolvedImportCount == 0, "lazy STUB_AND_RESOLVER is not eagerly bound to its stub")
            try expect(lazyResolution.unresolvedImportCount == 1, "lazy resolver remains explicitly unresolved")
            passed.append("STUB_AND_RESOLVER exports use their stub for non-lazy binds; lazy binds remain unresolved until guest resolver execution is supported")
        }

        do {
            let url = try makeCacheFileWithLoadCommandReexport()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let parentPath = "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation"
            let providerPath = "/System/Library/PrivateFrameworks/AVFCapture.framework/Versions/A/AVFCapture"
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable(installName: parentPath))
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_1000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_1000, byteCount: 0x1000, permissions: .readExecute)
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(resolution.resolvedImportCount == 1, "LC_REEXPORT_DYLIB symbol resolution count")
            try expect(
                resolution.resolver.resolveExact(symbol: "_puts", installName: parentPath) == 0x7FFF_0000_1100,
                "symbol is re-exported through the declared parent dependency"
            )
            try expect(cache.images.contains(where: { $0.installName == providerPath }), "reexported provider is a cached image")
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: resolution.resolver, requireAllBindingsResolved: true)
            try expect(loaded.boundFixupCount == 1, "LC_REEXPORT_DYLIB bind fixup applied")
            try expect(
                try memory.readUnsigned(at: image.bindActions[0].location, byteCount: 8) == 0x7FFF_0000_1100,
                "reexported guest address is written to the import slot"
            )
            passed.append("Two-level lookup follows LC_REEXPORT_DYLIB dependencies when the declared image has no own export-trie entry")
        }

        do {
            let url = try makeCacheFileWithLoadCommandReexport()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let parentPath = "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation"
            let providerPath = "/System/Library/PrivateFrameworks/AVFCapture.framework/Versions/A/AVFCapture"
            let roots = [
                X64MachODylibDependency(
                    ordinal: 1,
                    installName: parentPath,
                    timestamp: 0,
                    currentVersion: 0,
                    compatibilityVersion: 0,
                    kind: .load
                )
            ]
            let selection = try X64DyldSharedCacheReexportPlanner.select(cache: cache, roots: roots)
            try expect(selection.rootImageCount == 1, "one direct dependency image selected")
            try expect(selection.installNames == [parentPath, providerPath], "only the exact reexport provider is added after the direct dependency")
            try expect(!selection.truncated && selection.missingInstallNames.isEmpty, "complete reexport selection")

            let mappingDependencies = selection.installNames.enumerated().map { index, installName in
                X64MachODylibDependency(
                    ordinal: index + 1,
                    installName: installName,
                    timestamp: 0,
                    currentVersion: 0,
                    compatibilityVersion: 0,
                    kind: .load
                )
            }
            let plan = try X64DyldSharedCacheImageMapper.makePlan(cache: cache, dependencies: mappingDependencies)
            try expect(plan.images.count == 2, "both direct and reexport provider images are preflighted")
            try expect(plan.totalPageRoundedReservationBytes == 0x3000, "shared-cache backing includes the provider's executable and linkedit pages")
            passed.append("Materialization preflight includes bounded LC_REEXPORT_DYLIB providers so their guest export addresses can be resolved")
        }

        do {
            let url = try makeCacheFileWithLoadCommandReexport(reexport: false)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let parentPath = "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation"
            let providerPath = "/System/Library/PrivateFrameworks/AVFCapture.framework/Versions/A/AVFCapture"
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable(installName: parentPath))
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_1000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_1000, byteCount: 0x1000, permissions: .readExecute)
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(resolution.resolvedImportCount == 0, "ordinary dependency must not satisfy a two-level import")
            try expect(resolution.candidateProvidersBySymbol["_puts"]?.contains(providerPath) == true, "non-reexport provider is reported as a candidate")
            try expect(resolution.unresolvedByDependency[parentPath] == 1, "unresolved symbols are grouped by declared dependency")
            let diagnostic = resolution.unresolvedBindingDiagnostics.first
            try expect(diagnostic?.libraryOrdinal == 1, "unresolved diagnostic preserves the original library ordinal")
            try expect(diagnostic?.dependencyInstallName == parentPath, "unresolved diagnostic preserves the exact declared provider")
            try expect(diagnostic?.stream == "regular", "unresolved diagnostic preserves the bind-stream kind")
            try expect(
                diagnostic?.candidateRoutes.first?.contains("LC_LOAD_DYLIB") == true,
                "diagnostic identifies the non-reexport dependency edge"
            )
            passed.append("Unresolved two-level imports report the exact dependency ordinal and candidate path without binding through LC_LOAD_DYLIB")
        }

        do {
            let url = try makeCacheFileWithLoadCommandReexport(setNoReexportsFlag: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let parentPath = "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation"
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable(installName: parentPath))
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_1000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_1000, byteCount: 0x1000, permissions: .readExecute)
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(resolution.resolvedImportCount == 1, "explicit LC_REEXPORT_DYLIB remains authoritative at runtime")
            try expect(
                resolution.resolver.resolveExact(symbol: "_puts", installName: parentPath) == 0x7FFF_0000_1100,
                "MH_NO_REEXPORTED_DYLIBS does not override the runtime load-command graph"
            )
            passed.append("Runtime reexport lookup follows explicit LC_REEXPORT_DYLIB commands; MH_NO_REEXPORTED_DYLIBS is not treated as a runtime veto")
        }

        do {
            let url = try makeCacheFileWithExports()
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable(libraryOrdinal: -2))
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_0000, byteCount: 0x1000, permissions: .readExecute)
            var exactThunkResolver = X64MachOSymbolResolver()
            exactThunkResolver.register(symbol: "_puts", address: 0x7FFF_0000_0180, installName: "/usr/lib/libSystem.B.dylib")
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: exactThunkResolver
            )
            try expect(image.bindActions.first?.libraryOrdinal == -2, "flat-lookup special ordinal parse")
            try expect(resolution.flatLookupResolvedCount == 1, "flat-lookup resolution count")
            try expect(resolution.resolver.resolve(symbol: "_puts", dependency: nil) == 0x7FFF_0000_0180, "flat lookup honors exact guest thunk before cached export")
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: resolution.resolver, requireAllBindingsResolved: true)
            try expect(loaded.boundFixupCount == 1, "flat-lookup guest bind count")
            try expect(try memory.readUnsigned(at: image.bindActions[0].location, byteCount: 8) == 0x7FFF_0000_0180, "exact guest thunk pointer written to flat import slot")
            passed.append("BIND_SPECIAL_DYLIB_FLAT_LOOKUP resolves in deterministic dependency load order using guest export addresses")
        }

        do {
            let url = try makeCacheFileWithExports(weakDefinition: true)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable(libraryOrdinal: -3))
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_0000, byteCount: 0x1000, permissions: .readExecute)
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: X64MachOSymbolResolver()
            )
            try expect(image.bindActions.first?.libraryOrdinal == -3, "weak-lookup special ordinal parse")
            try expect(resolution.weakLookupResolvedCount == 1, "weak-lookup resolution count")
            try expect(resolution.resolver.resolveWeak(symbol: "_puts") == 0x7FFF_0000_0100, "weak lookup resolves weak definition")
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: resolution.resolver, requireAllBindingsResolved: true)
            try expect(loaded.boundFixupCount == 1, "weak-lookup guest bind count")
            passed.append("BIND_SPECIAL_DYLIB_WEAK_LOOKUP accepts weak definitions and writes only mapped guest addresses")
        }

        do {
            let url = try makeCacheFileWithExports(weakDefinition: false)
            defer { try? FileManager.default.removeItem(at: url) }
            let cache = try X64DyldSharedCacheReader.open(url)
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable(libraryOrdinal: -3))
            var memory = try X64GuestVirtualMemory()
            try memory.reserve(at: 0x7FFF_0000_0000, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: 0x7FFF_0000_0000, byteCount: 0x1000, permissions: .readExecute)
            var strongBaseResolver = X64MachOSymbolResolver()
            strongBaseResolver.register(symbol: "_puts", address: 0x7FFF_0000_0200)
            let resolution = try X64DyldSharedCacheImportResolver.build(
                cache: cache,
                executable: image,
                guestMemory: memory,
                baseResolver: strongBaseResolver
            )
            try expect(resolution.weakLookupResolvedCount == 0, "weak lookup must not select a strong-only export")
            try expect(resolution.resolver.resolveWeak(symbol: "_puts") == nil, "strong-only export absent from weak lookup namespace")
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: resolution.resolver)
            try expect(loaded.unresolvedBindSymbols == ["_puts"], "a strong global resolver entry must not satisfy weak lookup")
            passed.append("BIND_SPECIAL_DYLIB_WEAK_LOOKUP does not accidentally select a non-weak export")
        }

        do {
            // This layered diamond graph has exponentially many distinct
            // simple paths from the root to the target, but only 66 images.
            // A route finder that stores a separate visited Set per path can
            // consume unbounded memory; the global-visited BFS must visit each
            // image at most once.
            var graph: [String: [X64MachODylibDependency]] = [:]
            func edge(_ ordinal: Int, _ path: String, _ kind: X64MachODylibKind) -> X64MachODylibDependency {
                X64MachODylibDependency(
                    ordinal: ordinal,
                    installName: path,
                    timestamp: 0,
                    currentVersion: 0,
                    compatibilityVersion: 0,
                    kind: kind
                )
            }
            let layers = 32
            for layer in 0..<layers {
                for branch in ["A", "B"] {
                    let source = "L\(layer)\(branch)"
                    graph[source] = [
                        edge(1, "L\(layer + 1)A", .load),
                        edge(2, "L\(layer + 1)B", .reexport)
                    ]
                }
            }
            graph["L\(layers)A"] = []
            graph["L\(layers)B"] = []

            let route = X64DyldDependencyRouteFinder.find(
                from: "L0A",
                to: "L\(layers)A",
                dependenciesByImage: graph,
                maximumVisitedImages: 128
            )
            try expect(route != nil, "route finder reaches a target in a layered diamond graph")
            try expect(route!.visitedImageCount <= graph.count, "each graph image is visited no more than once")
            try expect(route!.description.contains("LC_LOAD_DYLIB"), "route retains load-command edge provenance")
            try expect(route!.description.contains("L32A"), "route ends at the requested provider")
            let cappedRoute = X64DyldDependencyRouteFinder.find(
                from: "L0A",
                to: "L\(layers)A",
                dependenciesByImage: graph,
                maximumVisitedImages: 1
            )
            try expect(cappedRoute == nil, "route finder respects its hard visited-image ceiling")
            passed.append("Dependency-route diagnostics use bounded O(images + edges) BFS instead of enumerating exponentially many simple paths")
        }

        return passed
    }

    private static func makeCacheFileWithLoadCommandReexport(
        setNoReexportsFlag: Bool = false,
        reexport: Bool = true
    ) throws -> URL {
        let url = try makeCacheFile()
        var data = try Data(contentsOf: url)
        let base: UInt64 = 0x7FFF_0000_0000
        let parentPath = "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation"
        let providerPath = "/System/Library/PrivateFrameworks/AVFCapture.framework/Versions/A/AVFCapture"

        // Extend the second cache mapping by one page for the provider's
        // __LINKEDIT and export trie. It starts at guest base + 0x1000 and
        // backing-file offset 0x2000.
        data.writeLE64(0x2000, at: 0x400 + 32 + 8)
        data.writeLE64(0x3000, at: 232) // sharedRegionSize
        writeImageInfo(&data, offset: 0x500, address: base, pathOffset: 0x700, path: parentPath)
        writeImageInfo(&data, offset: 0x520, address: base + 0x1000, pathOffset: 0x780, path: providerPath)

        func writeHeader(at offset: Int, commandCount: UInt32, commandBytes: UInt32, flags: UInt32 = 0) {
            data.writeLE32(0xFEED_FACF, at: offset)
            data.writeLE32(0x0100_0007, at: offset + 4) // CPU_TYPE_X86_64
            data.writeLE32(3, at: offset + 8) // CPU_SUBTYPE_X86_64_ALL
            data.writeLE32(0x6, at: offset + 12) // MH_DYLIB
            data.writeLE32(commandCount, at: offset + 16)
            data.writeLE32(commandBytes, at: offset + 20)
            data.writeLE32(flags, at: offset + 24)
            data.writeLE32(0, at: offset + 28)
        }

        func writeSegment(
            _ name: String,
            vmAddress: UInt64,
            vmSize: UInt64,
            fileOffset: UInt64,
            fileSize: UInt64,
            protection: UInt32,
            at offset: Int
        ) {
            data.writeLE32(0x19, at: offset) // LC_SEGMENT_64
            data.writeLE32(72, at: offset + 4)
            let nameBytes = Array(name.utf8.prefix(16))
            data.replaceSubrange((offset + 8)..<(offset + 8 + nameBytes.count), with: nameBytes)
            data.writeLE64(vmAddress, at: offset + 24)
            data.writeLE64(vmSize, at: offset + 32)
            data.writeLE64(fileOffset, at: offset + 40)
            data.writeLE64(fileSize, at: offset + 48)
            data.writeLE32(protection, at: offset + 56)
            data.writeLE32(protection, at: offset + 60)
            data.writeLE32(0, at: offset + 64)
            data.writeLE32(0, at: offset + 68)
        }

        // Parent framework: __TEXT plus one reexport or ordinary dependency edge.
        let parentHeader = 0x1000
        let reexportBytes = Array(providerPath.utf8) + [0]
        let paddedReexportBytes = (reexportBytes.count + 7) & ~7
        let reexportCommandSize = 24 + paddedReexportBytes
        writeHeader(
            at: parentHeader,
            commandCount: 2,
            commandBytes: UInt32(72 + reexportCommandSize),
            flags: setNoReexportsFlag ? 0x0010_0000 : 0
        )
        writeSegment("__TEXT", vmAddress: base, vmSize: 0x1000, fileOffset: 0, fileSize: 0x1000, protection: 5, at: parentHeader + 32)
        let reexportCommand = parentHeader + 32 + 72
        data.writeLE32(reexport ? 0x8000_001F : 0x0C, at: reexportCommand) // LC_REEXPORT_DYLIB or LC_LOAD_DYLIB
        data.writeLE32(UInt32(reexportCommandSize), at: reexportCommand + 4)
        data.writeLE32(24, at: reexportCommand + 8) // lc_str.offset
        data.writeLE32(0, at: reexportCommand + 12)
        data.writeLE32(0x1_0000, at: reexportCommand + 16)
        data.writeLE32(0x1_0000, at: reexportCommand + 20)
        data.replaceSubrange(
            (reexportCommand + 24)..<(reexportCommand + 24 + reexportBytes.count),
            with: reexportBytes
        )

        // Provider dylib: executable __TEXT at +0x1000, __LINKEDIT at +0x2000.
        let providerHeader = 0x2000
        writeHeader(at: providerHeader, commandCount: 3, commandBytes: 160)
        writeSegment("__TEXT", vmAddress: base + 0x1000, vmSize: 0x1000, fileOffset: 0, fileSize: 0x1000, protection: 5, at: providerHeader + 32)
        writeSegment("__LINKEDIT", vmAddress: base + 0x2000, vmSize: 0x1000, fileOffset: 0x1000, fileSize: 0x1000, protection: 1, at: providerHeader + 104)
        let exportsCommand = providerHeader + 176
        data.writeLE32(0x8000_0033, at: exportsCommand) // LC_DYLD_EXPORTS_TRIE
        data.writeLE32(16, at: exportsCommand + 4)
        data.writeLE32(0x1000, at: exportsCommand + 8) // __LINKEDIT-relative dataoff
        data.writeLE32(14, at: exportsCommand + 12)

        let trie: [UInt8] = [0x00, 0x01, 0x5F, 0x70, 0x75, 0x74, 0x73, 0x00, 0x09, 0x03, 0x00, 0x80, 0x02, 0x00]
        data.replaceSubrange(0x3000..<(0x3000 + trie.count), with: trie)
        try data.write(to: url, options: .atomic)
        return url
    }

    private static func makeCacheFileWithExports(
        weakDefinition: Bool = false,
        stubAndResolver: Bool = false
    ) throws -> URL {
        let url = try makeCacheFile()
        var data = try Data(contentsOf: url)
        // Only the first cached image is used by this fixture. Its __TEXT
        // occupies the first mapping and __LINKEDIT the second mapping.
        data.writeLE32(1, at: 452) // imagesCount
        let header = 0x1000
        data.writeLE32(3, at: header + 16) // ncmds
        data.writeLE32(160, at: header + 20) // sizeofcmds
        var cursor = header + 32

        func writeSegment(_ name: String, vmAddress: UInt64, fileOffset: UInt64, fileSize: UInt64, into data: inout Data, at offset: Int) {
            data.writeLE32(0x19, at: offset)
            data.writeLE32(72, at: offset + 4)
            let nameBytes = Array(name.utf8)
            data.replaceSubrange((offset + 8)..<(offset + 8 + nameBytes.count), with: nameBytes)
            data.writeLE64(vmAddress, at: offset + 24)
            data.writeLE64(0x1000, at: offset + 32)
            data.writeLE64(fileOffset, at: offset + 40)
            data.writeLE64(fileSize, at: offset + 48)
            data.writeLE32(7, at: offset + 56)
            data.writeLE32(name == "__TEXT" ? 5 : 1, at: offset + 60)
            data.writeLE32(0, at: offset + 64)
            data.writeLE32(0, at: offset + 68)
        }
        writeSegment("__TEXT", vmAddress: 0x7FFF_0000_0000, fileOffset: 0, fileSize: 0x1000, into: &data, at: cursor)
        cursor += 72
        writeSegment("__LINKEDIT", vmAddress: 0x7FFF_0000_1000, fileOffset: 0x2000, fileSize: 0x1000, into: &data, at: cursor)
        cursor += 72
        data.writeLE32(0x8000_0033, at: cursor) // LC_DYLD_EXPORTS_TRIE
        data.writeLE32(16, at: cursor + 4)
        data.writeLE32(0x2000, at: cursor + 8)
        // Root -> "_puts" -> regular export at __TEXT + 0x100, or a
        // STUB_AND_RESOLVER export with stub +0x100 and resolver +0x200.
        let exportFlags = UInt8((weakDefinition ? 0x04 : 0x00) | (stubAndResolver ? 0x10 : 0x00))
        var trie: [UInt8] = [0x00, 0x01, 0x5F, 0x70, 0x75, 0x74, 0x73, 0x00, 0x09]
        if stubAndResolver {
            trie.append(contentsOf: [0x05, exportFlags, 0x80, 0x02, 0x80, 0x04, 0x00])
        } else {
            trie.append(contentsOf: [0x03, exportFlags, 0x80, 0x02, 0x00])
        }
        data.writeLE32(UInt32(trie.count), at: cursor + 12)
        data.replaceSubrange(0x2000..<(0x2000 + trie.count), with: trie)
        try data.write(to: url, options: .atomic)
        return url
    }

    private static func makeCacheFile(
        magic: String = "dyld_v1  x86_64",
        invalidMapping: Bool = false,
        invalidSegmentMapping: Bool = false,
        segmentVMSize: UInt64 = 0x1000,
        segmentVMAddressOffset: UInt64 = 0,
        secondSegmentVMAddressOffset: UInt64? = nil,
        secondSegmentVMSize: UInt64 = 0,
        secondImageSegmentVMAddressOffset: UInt64? = nil,
        secondImageSegmentVMSize: UInt64 = 0,
        truncateAfterFirstMapping: Bool = false,
        includeSlideInfo: Bool = false,
        slideInfoVersion: UInt32 = 2,
        slideInfoHasChain: Bool = false,
        slideInfoUsesExtras: Bool = false,
        invalidSlideInfoRange: Bool = false
    ) throws -> URL {
        var data = Data(repeating: 0, count: 0x4000)
        let magicBytes = Array(magic.utf8.prefix(16))
        data.replaceSubrange(0..<magicBytes.count, with: magicBytes)
        data.writeLE32(0x400, at: 16) // mappingOffset
        data.writeLE32(2, at: 20) // mappingCount
        data.writeLE64(0x7FFF_0000_0000, at: 32) // dyldBaseAddress
        for index in 0..<16 { data[88 + index] = UInt8(index + 1) }
        data.writeLE64(1, at: 104) // production cache
        data.writeLE32(1, at: 216) // macOS platform
        data.writeLE64(0x7FFF_0000_0000, at: 224) // sharedRegionStart
        data.writeLE64(0x2000, at: 232) // sharedRegionSize
        data.writeLE32(0x500, at: 448) // imagesOffset
        data.writeLE32(2, at: 452) // imagesCount
        data.writeLE32(0, at: 392) // no subcaches
        data.writeLE32(0, at: 396)

        let mapping = 0x400
        data.writeLE64(0x7FFF_0000_0000, at: mapping)
        data.writeLE64(truncateAfterFirstMapping ? segmentVMSize : 0x1000, at: mapping + 8)
        data.writeLE64(invalidMapping ? 0x5000 : 0x1000, at: mapping + 16)
        data.writeLE32(5, at: mapping + 24)
        data.writeLE32(5, at: mapping + 28)
        data.writeLE64(0x7FFF_0000_0000 + (truncateAfterFirstMapping ? 0x2000 : 0x1000), at: mapping + 32)
        data.writeLE64(0x1000, at: mapping + 40)
        data.writeLE64(truncateAfterFirstMapping ? 0x3000 : 0x2000, at: mapping + 48)
        data.writeLE32(5, at: mapping + 56)
        data.writeLE32(5, at: mapping + 60)

        writeImageInfo(&data, offset: 0x500, address: 0x7FFF_0000_0000, pathOffset: 0x700, path: "/usr/lib/libSystem.B.dylib")
        writeImageInfo(&data, offset: 0x520, address: 0x7FFF_0000_1000, pathOffset: 0x740, path: "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation")
        writeMachHeader(
            &data,
            offset: 0x1000,
            vmAddress: invalidSegmentMapping ? 0x7FFF_0000_4000 : 0x7FFF_0000_0000 + segmentVMAddressOffset,
            vmSize: segmentVMSize,
            secondSegment: secondSegmentVMAddressOffset.map { (0x7FFF_0000_0000 + $0, secondSegmentVMSize) }
        )
        writeMachHeader(
            &data,
            offset: 0x2000,
            vmAddress: secondImageSegmentVMAddressOffset.map { 0x7FFF_0000_0000 + $0 } ?? 0x7FFF_0000_1000,
            vmSize: secondImageSegmentVMSize == 0 ? 0x1000 : secondImageSegmentVMSize
        )

        if includeSlideInfo {
            let mappingWithSlide = 0x800
            let slideInfoOffset = 0x900
            data.writeLE32(UInt32(mappingWithSlide), at: 312)
            data.writeLE32(1, at: 316)
            data.writeLE64(0x7FFF_0000_0000, at: mappingWithSlide)
            data.writeLE64(0x1000, at: mappingWithSlide + 8)
            data.writeLE64(0x1000, at: mappingWithSlide + 16)
            data.writeLE64(UInt64(slideInfoOffset), at: mappingWithSlide + 24)
            data.writeLE64(invalidSlideInfoRange ? 0x10000 : UInt64(slideInfoUsesExtras ? 46 : 42), at: mappingWithSlide + 32)
            data.writeLE64(0, at: mappingWithSlide + 40) // flags
            data.writeLE32(5, at: mappingWithSlide + 48)
            data.writeLE32(5, at: mappingWithSlide + 52)

            data.writeLE32(slideInfoVersion, at: slideInfoOffset)
            data.writeLE32(0x1000, at: slideInfoOffset + 4) // page_size
            data.writeLE32(40, at: slideInfoOffset + 8) // page_starts_offset
            data.writeLE32(1, at: slideInfoOffset + 12) // page_starts_count
            data.writeLE32(slideInfoUsesExtras ? 42 : 42, at: slideInfoOffset + 16) // page_extras_offset
            data.writeLE32(slideInfoUsesExtras ? 2 : 0, at: slideInfoOffset + 20) // page_extras_count
            data.writeLE64(0xC000_0000_0000_0000, at: slideInfoOffset + 24) // delta_mask
            data.writeLE64(0x7FFF_0000_0000, at: slideInfoOffset + 32) // x86_64 value_add = cache base

            if slideInfoUsesExtras {
                data.writeLE16(0x8000, at: slideInfoOffset + 40) // first page start points to extras[0]
                data.writeLE16(0x0200, at: slideInfoOffset + 42) // chain at 0x800
                data.writeLE16(0x8202, at: slideInfoOffset + 44) // chain at 0x808, last extra
                data.writeLE64(0x1000, at: 0x1800)
                data.writeLE64(0x2000, at: 0x1808)
            } else if slideInfoHasChain {
                data.writeLE16(0x0200, at: slideInfoOffset + 40) // chain at 0x800
                data.writeLE64(0x8000_0000_0000_1000, at: 0x1800) // delta=8, rebased pointer
                data.writeLE64(0x2000, at: 0x1808) // terminal pointer
            } else {
                data.writeLE16(0x4000, at: slideInfoOffset + 40) // DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE
            }
        }

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("kestrel-dyld-cache-\(UUID().uuidString)")
        try data.write(to: url, options: .atomic)
        return url
    }

    private static func writeImageInfo(_ data: inout Data, offset: Int, address: UInt64, pathOffset: UInt32, path: String) {
        data.writeLE64(address, at: offset)
        data.writeLE64(1_700_000_000, at: offset + 8)
        data.writeLE64(123, at: offset + 16)
        data.writeLE32(pathOffset, at: offset + 24)
        data.writeLE32(0, at: offset + 28)
        let bytes = Array(path.utf8) + [0]
        data.replaceSubrange(Int(pathOffset)..<(Int(pathOffset) + bytes.count), with: bytes)
    }

    private static func writeMachHeader(
        _ data: inout Data,
        offset: Int,
        vmAddress: UInt64,
        vmSize: UInt64 = 0x1000,
        secondSegment: (UInt64, UInt64)? = nil
    ) {
        data.writeLE32(0xFEED_FACF, at: offset)
        data.writeLE32(0x0100_0007, at: offset + 4)
        data.writeLE32(3, at: offset + 8)
        data.writeLE32(6, at: offset + 12) // MH_DYLIB
        data.writeLE32(secondSegment == nil ? 1 : 2, at: offset + 16) // ncmds
        data.writeLE32(secondSegment == nil ? 72 : 144, at: offset + 20) // sizeofcmds
        data.writeLE32(0, at: offset + 24)
        data.writeLE32(0, at: offset + 28)

        writeSegmentCommand(&data, offset: offset + 32, name: "__TEXT", vmAddress: vmAddress, vmSize: vmSize)
        if let secondSegment {
            writeSegmentCommand(&data, offset: offset + 104, name: "__DATA_CONST", vmAddress: secondSegment.0, vmSize: secondSegment.1)
        }
    }

    private static func writeSegmentCommand(_ data: inout Data, offset: Int, name: String, vmAddress: UInt64, vmSize: UInt64) {
        data.writeLE32(0x19, at: offset) // LC_SEGMENT_64
        data.writeLE32(72, at: offset + 4)
        let nameBytes = Array(name.utf8)
        data.replaceSubrange((offset + 8)..<(offset + 8 + nameBytes.count), with: nameBytes)
        data.writeLE64(vmAddress, at: offset + 24)
        data.writeLE64(vmSize, at: offset + 32)
        data.writeLE64(0, at: offset + 40) // source dylib fileoff (not used for cache VM lookup)
        data.writeLE64(0x1000, at: offset + 48)
        data.writeLE32(7, at: offset + 56)
        data.writeLE32(name == "__TEXT" ? 5 : 1, at: offset + 60) // RX text, R data-const
        data.writeLE32(0, at: offset + 64)
        data.writeLE32(0, at: offset + 68)
    }

    private static func unwrap<T>(_ value: T?, _ message: String) throws -> T {
        guard let value else { throw failure(message) }
        return value
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        if !condition { throw failure(message) }
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "X64DyldSharedCacheSelfTests", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

private extension Data {
    mutating func writeLE16(_ value: UInt16, at offset: Int) {
        self[offset] = UInt8(truncatingIfNeeded: value)
        self[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
    }

    mutating func writeLE32(_ value: UInt32, at offset: Int) {
        for index in 0..<4 { self[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    }

    mutating func writeLE64(_ value: UInt64, at offset: Int) {
        for index in 0..<8 { self[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    }
}
