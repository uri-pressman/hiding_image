import struct

# Global signatures to identify which hiding method was used
SIGNATURE_M1 = b"[M1]"
SIGNATURE_M2 = b"[M2]"

def decode_bmp(bmp_path):
    '''
    decode the hidden message or file using the method found in the file
    :param bmp_path: path to image
    :return: the hidden data
    '''
    # Default ret
    ret = None, b"No hidden data found."

    # Open the BMP file
    with open(bmp_path, 'rb') as f:
        bmp_data = bytes(f.read())

    # Read the file size from the BMP header to check for Method 1
    recorded_size = struct.unpack("<I", bmp_data[2:6])[0]
    actual_size = len(bmp_data)

    # Check if actual file size is larger than recorded size to find appended data (Method 1)
    if actual_size >= recorded_size:
        # Search for the Method 1 signature starting from the end of the file
        sig_index = bmp_data.rfind(SIGNATURE_M1)
        if sig_index != -1:
            # Extract everything that comes after the signature
            secret_data = bmp_data[sig_index + len(SIGNATURE_M1):]
            ret = 1, secret_data

    # Read the pixel data start position (offset) (Method 2)
    if ret[0] is None:
        pixel_offset = struct.unpack("<I", bmp_data[10:14])[0]

        # Init Vars
        extracted_bytes = bytearray()
        current_byte = 0
        bit_count = 0

        # Loop through the pixel bytes to extract the hidden LSB from each one
        for byte_index in range(pixel_offset, len(bmp_data)):
            # Extract the last bit using % 2 (1 if odd, 0 if even)
            bit = bmp_data[byte_index] % 2

            # Shift the current byte value up by multiplying by 2, then add the new bit
            current_byte = (current_byte * 2) + bit
            bit_count = bit_count + 1

            # If 8 bits are collected, save the byte and reset the counter
            if bit_count == 8:
                extracted_bytes.append(current_byte)
                current_byte = 0
                bit_count = 0

                # Verify if the first reconstructed bytes match the expected Method 2 signature
                if len(extracted_bytes) == len(SIGNATURE_M2):
                    if bytes(extracted_bytes) != SIGNATURE_M2:
                        # Stop scanning if the signature does not match
                        break

                # Check if we successfully reached "\x00" (end mark)
                if len(extracted_bytes) > len(SIGNATURE_M2) and extracted_bytes[-1] == 0:
                    # Remove the signature from the front and "\x00" from the end
                    secret_data = extracted_bytes[len(SIGNATURE_M2):-1]
                    ret = 2, bytes(secret_data)
                    break

    return ret


if __name__ == "__main__":
    # Decode the file generated with Method 1
    method, data = decode_bmp(r"C:\Users\talmid\Downloads\hidden.bmp")
    print(f"Decoder detected Method {method}: {data.decode()}")

    # Decode the file generated with Method 2
    method, data = decode_bmp(r"C:\Users\talmid\Downloads\hidden2.bmp")
    print(f"Decoder detected Method {method}: {data.decode()}")
