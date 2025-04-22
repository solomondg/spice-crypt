# SPDX-FileCopyrightText: © 2025 Bayou Bits Technologies, LLC
# SPDX-FileCopyrightText: © 2025 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# This source code is proprietary and confidential.  It is provided under the
# terms of a written license agreement between BAYOU BITS TECHNOLOGIES, LLC
# and the recipient.  Any unauthorized use, copying, modification, or
# distribution is strictly prohibited.
#
# Authorized representatives of the licensed recipient may request a copy of
# the written license agreement via email at joe.sylve@gmail.com.

import numpy as np
from spice_crypt.des import LTSpiceDES

class CryptoState:
    def __init__(self, table: bytes):
        if len(table) != 1024:
            raise ValueError("crypto table must be exactly 1024 bytes")

        self.crypto_table = table
        self.DES = LTSpiceDES()
        self.reset()

    def reset(self):
        """
        Initializes the cryptographic state using the predefined 1024-byte table
        """
        # Suppress overflow warnings since they're expected in crypto operations
        with np.errstate(over='ignore'):
            # Validate table length
            if len(self.crypto_table) != 1024:
                raise ValueError("Crypto table must be 1024 bytes")
            
            # Convert to numpy array for efficient operations
            bytes_array = np.frombuffer(self.crypto_table, dtype=np.uint8)
            
            # Pass 1: Checksums for even and odd bytes
            even_byte_sum = np.uint32(np.sum(bytes_array[::2])) & 0xFF
            odd_byte_sum = np.uint32(np.sum(bytes_array[1::2])) & 0xFF
            
            # Pass 2: Sum bytes by their position in 4-byte chunks
            byte_group_sums = np.sum(bytes_array.reshape(256, 4), axis=0, dtype=np.uint32)
            byte_sum_result = np.sum(byte_group_sums, dtype=np.uint32)
            
            # Pass 3: Sum 16-bit words by their position in 4-word chunks
            words = np.frombuffer(self.crypto_table, dtype=np.uint16)
            word_group_sums = np.sum(words.reshape(128, 4), axis=0, dtype=np.uint32)
            word_sum_result = np.sum(word_group_sums, dtype=np.uint32)
            
            # Pass 4: Sum 64-bit qwords in 2-qword chunks
            qwords = np.frombuffer(self.crypto_table, dtype=np.uint64)
            qword_group_sums = np.sum(qwords.reshape(64, 2), axis=0, dtype=np.uint64)
            
            # Create combined qword and extract important 16-bit parts
            qword_high_part = np.uint32(qword_group_sums[1] >> 32)
            qword_low_part = np.uint32(qword_group_sums[1] & 0xFFFFFFFF)
            combined_qword = qword_group_sums[0] + ((np.uint64(qword_high_part) << 32) | np.uint64(qword_low_part))
            
            # Extract 16-bit values
            qword_low_word = np.uint32(combined_qword & 0xFFFF)
            qword_high_word = np.uint32((combined_qword >> 32) & 0xFFFF)
            
            # Final XOR transformation
            state_vector = np.array([
                odd_byte_sum,
                even_byte_sum,
                qword_low_word,
                qword_high_word
            ], dtype=np.uint32)
            
            xor_mask = np.array([0x00000054, 0x000000E7, 0x66E22120, 0x20E905C8], dtype=np.uint32)
            final_state = state_vector ^ xor_mask
            
            # Store final results
            self.odd_byte_checksum = final_state[0]
            self.even_byte_checksum = final_state[1]
            self.key_value = (np.uint64(final_state[3]) << 32) | np.uint64(final_state[2])

    def decrypt_block(self, data: bytearray):
        """
        Decrypts a block of data using the cryptographic state and table
        
        Args:
            data: 8-byte block to decrypt
            
        Returns:
            32-bit decrypted result
        """
        crypto_table = self.crypto_table
        # Ensure crypto_table is correct length
        if len(crypto_table) != 0x400:
            raise ValueError("Crypto table must be 1024 bytes")
        
        # Ensure data is correct length
        if len(data) != 8:
            raise ValueError("Data block must be 8 bytes")
        
        # Make a copy of data to modify it
        data_copy = bytearray(data)

        # Update first element of the state and XOR data bytes
        for i in range(8):
            # Update first element by adding second element (with overflow handling)
            self.odd_byte_checksum = np.uint32(self.odd_byte_checksum + self.even_byte_checksum)
            
            # Calculate index into crypto_table
            table_index = (self.odd_byte_checksum % 0x3fd) + 1
            
            # XOR data byte with table byte
            data_copy[i] ^= crypto_table[table_index]
        
        # Decrypt the data
        result = self.DES.crypt(np.uint64(int.from_bytes(data_copy, 'little')), np.uint64(self.key_value), True)
        
        # Return the second 32-bit word from the result
        return result