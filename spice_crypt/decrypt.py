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

import binascii
import re
import io
import os
from typing import Tuple, Optional, Generator
from spice_crypt.crypto_state import CryptoState


class LTSpiceFileParser:
    """Parser for LTSpice encrypted files with efficient streaming support."""
    
    def __init__(self, file_obj, raw_mode=False):
        """
        Initialize the parser with a file object.
        
        Args:
            file_obj: File-like object (text mode) or path to file
            raw_mode: Whether to treat the input as raw hex data
        """
        self.file_obj = file_obj
        self.raw_mode = raw_mode
        self.checksums = None
        self._hex_data_started = False
        self._hex_data_ended = False
        self._buffer = []
        self._crypto_table = None
        self._crypto_state = None
    
    def _read_until_begin(self):
        """Read the file until the 'Begin:' marker is found."""
        if self.raw_mode:
            return
        
        for line in self.file_obj:
            line = line.strip()
            if line.lower().startswith('* begin:'):
                self._hex_data_started = True
                return
    
    def _extract_checksums(self, line):
        """Extract checksums from an End line."""
        end_pattern = r'\*\s*End\s+(\d+)\s+(\d+)'
        end_match = re.search(end_pattern, line, re.IGNORECASE)
        
        if end_match:
            try:
                checksum1 = int(end_match.group(1))
                checksum2 = int(end_match.group(2))
                self.checksums = (checksum1, checksum2)
            except ValueError:
                pass
    
    def _process_hex_chunks(self):
        """Process hex data in chunks and yield blocks to decrypt."""
        # Process the buffer to get initial hex data
        hex_data = []
        
        # Read and process hex data
        for line in self.file_obj:
            line = line.strip()
            
            # Check if we've reached the end marker
            if not self.raw_mode and line.lower().startswith('* end'):
                self._extract_checksums(line)
                self._hex_data_ended = True
                break
            
            # Skip comments in LTSpice format
            if not self.raw_mode and line.startswith('*'):
                continue
            
            # Add hex data to our current chunk
            hex_data.extend(line.split())
            
            # Process complete blocks when we have enough data
            while len(hex_data) >= 8:
                # Get 8 hex values (which will make one 8-byte block)
                hex_block = hex_data[:8]
                hex_data = hex_data[8:]
                
                # Convert hex values to bytes
                try:
                    byte_block = bytes(int(h, 16) for h in hex_block)
                    yield byte_block
                except ValueError as e:
                    raise ValueError(f"Invalid hex data: {' '.join(hex_block)}") from e
        
        # Process any remaining data
        while hex_data:
            # If we don't have a complete block, pad with zeros
            if len(hex_data) < 8:
                hex_block = hex_data + ['00'] * (8 - len(hex_data))
                hex_data = []
            else:
                hex_block = hex_data[:8]
                hex_data = hex_data[8:]
            
            try:
                byte_block = bytes(int(h, 16) for h in hex_block)
                yield byte_block
            except ValueError as e:
                raise ValueError(f"Invalid hex data: {' '.join(hex_block)}") from e
    
    def _initialize_crypto_state(self, table):
        """Initialize the crypto state with the table."""
        self._crypto_table = table
        self._crypto_state = CryptoState(table)
    
    def decrypt_stream(self) -> Generator[bytes, None, Tuple[int, int]]:
        """
        Stream decrypt the file, yielding decrypted chunks.
        
        Returns:
            Generator that yields decrypted chunks
            The final value is the verification tuple (v1, v2)
        """
        # Start processing the file
        if not self.raw_mode:
            self._read_until_begin()
        
        block_count = 0
        table_bytes = bytearray(1024)
        plaintext_crc = 0
        ciphertext = bytearray()
        
        # Process the hex data in chunks
        for byte_block in self._process_hex_chunks():
            # First 1024 bytes (128 blocks) are the crypto table
            if block_count < 128:
                table_bytes[block_count*8:(block_count+1)*8] = byte_block
                block_count += 1
                
                # Once we have the complete table, initialize the crypto state
                if block_count == 128:
                    self._initialize_crypto_state(bytes(table_bytes))
            else:
                # Add to ciphertext for CRC calculation
                ciphertext.extend(byte_block)
                
                # Decrypt the block
                result = self._crypto_state.decrypt_block(byte_block)
                
                # Convert result to bytes
                result_bytes = int(result).to_bytes(4, 'little')
                
                # Update plaintext CRC
                plaintext_crc = binascii.crc32(result_bytes, plaintext_crc)
                
                # Yield the decrypted chunk
                yield result_bytes
        
        # Calculate verification values
        if self._crypto_table:
            v1 = plaintext_crc ^ 0x7a6d2c3a ^ int.from_bytes(self._crypto_table[0x44:0x48], byteorder='little')
            
            ciphertext_crc = binascii.crc32(ciphertext)
            v2 = ciphertext_crc ^ 0x4da77fd3 ^ int.from_bytes(self._crypto_table[0x94:0x98], byteorder='little')
            
            # Check against file checksums if available
            if self.checksums and (v1, v2) != self.checksums:
                print(f"Warning: Checksum mismatch! File: {self.checksums}, Calculated: ({v1}, {v2})")
                
            return (v1, v2)
        
        return (0, 0)


def decrypt_stream(input_file, output_file=None, is_ltspice_file=None) -> Tuple[Optional[str], Tuple[int, int]]:
    """
    Stream decrypt data from input_file to output_file.
    
    Args:
        input_file: File object or path to read from
        output_file: File object or path to write to (if None, returns result as string)
        is_ltspice_file: Boolean indicating if file is in LTSpice format
                         If None, auto-detect based on content
                         
    Returns:
        tuple: (content, verification)
            - content: Decrypted text as string (if output_file is None) or None
            - verification: Tuple of verification values
    """
    # Handle different input types
    close_input = False
    input_path = None
    
    if isinstance(input_file, str) or isinstance(input_file, os.PathLike):
        input_path = input_file
        input_file = open(input_file, 'r')
        close_input = True
    
    try:
        # Auto-detect if file is in LTSpice format if not specified
        if is_ltspice_file is None and input_path:
            # Read first line to check format
            first_line = input_file.readline()
            input_file.seek(0)  # Reset to start of file
            is_ltspice_file = '* LTspice Encrypted File' in first_line or '* Begin:' in first_line
        
        # Create parser
        parser = LTSpiceFileParser(input_file, raw_mode=not is_ltspice_file)
        
        # Initialize output handling
        return_string = output_file is None
        close_output = False
        buffer = io.StringIO() if return_string else None
        
        if output_file and isinstance(output_file, str):
            output_file = open(output_file, 'wb')
            close_output = True
        
        try:
            # Stream decrypt
            if return_string:
                # Collect all chunks in a string buffer
                for chunk in parser.decrypt_stream():
                    buffer.write(chunk.decode('utf-8', errors='replace'))
                verification = parser.decrypt_stream()
                result = buffer.getvalue()
            else:
                # Write directly to output file
                for chunk in parser.decrypt_stream():
                    output_file.write(chunk)
                verification = parser.decrypt_stream()
                result = None
            
            return result, verification
        finally:
            if close_output and output_file:
                output_file.close()
            if buffer:
                buffer.close()
    finally:
        if close_input:
            input_file.close()


def decrypt(data, is_ltspice_file=None):
    """
    Decrypts encrypted data.
    
    Args:
        data: String containing encrypted data, either raw hex or LTSpice file format
        is_ltspice_file: Boolean indicating if the data is in LTSpice file format.
                         If None, auto-detect based on content.
    
    Returns:
        tuple: (plaintext, verification)
            - plaintext: Decrypted text as string
            - verification: Tuple of verification values
    """
    # Auto-detect if data is in LTSpice file format
    if is_ltspice_file is None:
        is_ltspice_file = '* LTspice Encrypted File' in data or '* Begin:' in data
    
    # Use StringIO to avoid changing the interface
    with io.StringIO(data) as input_file:
        return decrypt_stream(input_file, is_ltspice_file=is_ltspice_file)