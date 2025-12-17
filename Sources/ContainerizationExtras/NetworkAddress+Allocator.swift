//===----------------------------------------------------------------------===//
// Copyright © 2025 Apple Inc. and the Containerization project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

extension IPv4Address {
    /// Creates an allocator for IPv4 addresses.
    public static func allocator(lower: UInt32, size: Int) throws -> any AddressAllocator<IPv4Address> {
        // NOTE: 2^31 - 1 size limit in the very improbable case that we run on 32-bit.
        guard size > 0 && size < Int.max && 0xffff_ffff - lower >= size - 1 else {
            throw AllocatorError.rangeExceeded
        }
        return IndexedAddressAllocator(
            size: size,
            addressToIndex: { address in
                guard address.value >= lower && address.value - lower <= UInt32(size) else {
                    return nil
                }
                return Int(address.value - lower)
            },
            indexToAddress: { IPv4Address(fromValue: lower + UInt32($0)) }
        )
    }
}

extension UInt16 {
    /// Creates an allocator for TCP/UDP ports and other UInt16 values.
    public static func allocator(lower: UInt16, size: Int) throws -> any AddressAllocator<UInt16> {
        guard 0xffff - lower + 1 >= size else {
            throw AllocatorError.rangeExceeded
        }

        return IndexedAddressAllocator(
            size: size,
            addressToIndex: { address in
                guard address >= lower && address <= lower + UInt16(size) else {
                    return nil
                }
                return Int(address - lower)
            },
            indexToAddress: { lower + UInt16($0) }
        )
    }
}

extension UInt32 {
    /// Creates an allocator for vsock ports, or any UInt32 values.
    public static func allocator(lower: UInt32, size: Int) throws -> any AddressAllocator<UInt32> {
        guard 0xffff_ffff - lower + 1 >= size else {
            throw AllocatorError.rangeExceeded
        }

        return IndexedAddressAllocator(
            size: size,
            addressToIndex: { address in
                guard address >= lower && address <= lower + UInt32(size) else {
                    return nil
                }
                return Int(address - lower)
            },
            indexToAddress: { lower + UInt32($0) }
        )
    }

    /// Creates a rotating allocator for vsock ports, or any UInt32 values.
    public static func rotatingAllocator(lower: UInt32, size: UInt32) throws -> any AddressAllocator<UInt32> {
        guard 0xffff_ffff - lower + 1 >= size else {
            throw AllocatorError.rangeExceeded
        }

        return RotatingAddressAllocator(
            size: size,
            addressToIndex: { address in
                guard address >= lower && address <= lower + UInt32(size) else {
                    return nil
                }
                return Int(address - lower)
            },
            indexToAddress: { lower + UInt32($0) }
        )
    }
}

extension Character {
    private static let deviceLetters = Array("abcdefghijklmnopqrstuvwxyz")

    /// Creates an allocator for block device tags, or any character values.
    /// NOTE: This is limited to 26 devices (a-z). For more devices, use String.blockDeviceTagAllocator().
    public static func blockDeviceTagAllocator() -> any AddressAllocator<Character> {
        IndexedAddressAllocator(
            size: Self.deviceLetters.count,
            addressToIndex: { address in
                Self.deviceLetters.firstIndex(of: address)
            },
            indexToAddress: { Self.deviceLetters[$0] }
        )
    }
}

extension String {
    private static let deviceLetters = Array("abcdefghijklmnopqrstuvwxyz")

    /// Converts an index to a block device tag string (Excel-style column naming).
    /// Index 0-25 → "a"-"z", 26-51 → "aa"-"az", 52-77 → "ba"-"bz", etc.
    private static func indexToDeviceTag(_ index: Int) -> String {
        var result = ""
        var n = index

        // First, handle indices 0-25 as single letters
        if n < 26 {
            return String(deviceLetters[n])
        }

        // For indices >= 26, we use two-letter combinations
        // 26-51 → aa-az, 52-77 → ba-bz, etc.
        n -= 26  // Adjust so 26 becomes 0
        let firstLetter = deviceLetters[n / 26]
        let secondLetter = deviceLetters[n % 26]
        result = String(firstLetter) + String(secondLetter)

        return result
    }

    /// Converts a block device tag string back to an index.
    private static func deviceTagToIndex(_ tag: String) -> Int? {
        let chars = Array(tag)

        if chars.count == 1 {
            // Single letter: a=0, b=1, ..., z=25
            guard let index = deviceLetters.firstIndex(of: chars[0]) else {
                return nil
            }
            return index
        } else if chars.count == 2 {
            // Two letters: aa=26, ab=27, ..., az=51, ba=52, etc.
            guard let first = deviceLetters.firstIndex(of: chars[0]),
                  let second = deviceLetters.firstIndex(of: chars[1]) else {
                return nil
            }
            return 26 + (first * 26) + second
        }

        return nil
    }

    /// Creates an allocator for block device tags using string values.
    /// Supports up to 702 devices: a-z (26) + aa-zz (676) = 702 total.
    public static func blockDeviceTagAllocator() -> any AddressAllocator<String> {
        // Support single letters (a-z) plus two-letter combinations (aa-zz)
        // Total: 26 + (26 * 26) = 26 + 676 = 702 devices
        let maxDevices = 26 + (26 * 26)

        return IndexedAddressAllocator(
            size: maxDevices,
            addressToIndex: { address in
                deviceTagToIndex(address)
            },
            indexToAddress: { indexToDeviceTag($0) }
        )
    }
}
