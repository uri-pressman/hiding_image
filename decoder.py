import struct

# Global signatures to identify which hiding method was used
SIGNATURE_M1 = b"[M1]"
SIGNATURE_M2 = b"[M2]"

def decode_bmp(bmp_path):
    # Open the modified BMP file and read its content as immutable bytes
    with open(bmp_path, 'rb') as f:
        bmp_data = bytes(f.read())

    # Read the recorded file size from the BMP header to check for Method 1
    recorded_size = struct.unpack("<I", bmp_data[2:6])[0]
    actual_size = len(bmp_data)

    # Check if actual file size is larger than recorded size to find appended data
    if actual_size >= recorded_size:
        # Search for the Method 1 signature starting from the end of the file
        sig_index = bmp_data.rfind(SIGNATURE_M1)
        if sig_index != -1:
            # Extract everything that comes immediately after the signature
            secret_data = bmp_data[sig_index + len(SIGNATURE_M1):]
            return 1, secret_data

    # Read the pixel data start position (offset) to begin checking for Method 2
    pixel_offset = struct.unpack("<I", bmp_data[10:14])[0]

    # Initialize variables to collect bits from pixels and reconstruct them into bytes
    extracted_bytes = bytearray()
    current_byte = 0
    bit_count = 0

    # Loop through the pixel bytes to extract the hidden LSB from each one
    for byte_index in range(pixel_offset, len(bmp_data)):
        # Extract the last bit using modulo 2 (returns 1 if odd, 0 if even)
        bit = bmp_data[byte_index] % 2

        # Shift the current byte value up by multiplying by 2, then add the new bit
        current_byte = (current_byte * 2) + bit
        bit_count = bit_count + 1

        # Once 8 bits are collected, save the completed byte and reset the counter
        if bit_count == 8:
            extracted_bytes.append(current_byte)
            current_byte = 0
            bit_count = 0

            # Verify if the first reconstructed bytes match the expected Method 2 signature
            if len(extracted_bytes) == len(SIGNATURE_M2):
                if bytes(extracted_bytes) != SIGNATURE_M2:
                    # Stop scanning immediately if the signature does not match
                    break

            # Check if we successfully reached the null terminator (\x00) marking the end
            if len(extracted_bytes) > len(SIGNATURE_M2) and extracted_bytes[-1] == 0:
                # Remove the signature from the front and the null terminator from the end
                secret_data = extracted_bytes[len(SIGNATURE_M2):-1]
                return 2, bytes(secret_data)

    # Return None if no valid signatures or hidden data could be found in the file
    return None, b"No hidden data found."


if __name__ == "__main__":
    # Decode the file generated with Method 1
    method, data = decode_bmp("output_m1.bmp")
    print(f"Decoder detected Method {method}: {data.decode()}")

    # Decode the file generated with Method 2
    method, data = decode_bmp("output_m2.bmp")
    print(f"Decoder detected Method {method}: {data.decode()}")
