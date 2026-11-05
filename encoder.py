import struct

# Global signatures to identify which hiding method was used
SIGNATURE_M1 = b"[M1]"
SIGNATURE_M2 = b"[M2]"



# Method 1: appending the data to the end

def hide_method_1(bmp_path, output_path, secret_data):
    # Open the BMP file
    with open(bmp_path, 'rb') as f:
        bmp_data = bytearray(f.read())

    # Combine the signature and the secret message
    payload = SIGNATURE_M1 + secret_data

    # Append the entire payload to the end of the original file
    bmp_data.extend(payload)

    # Update the FileSize field in the BMP header (bytes 2 to 5) with the new size
    new_size = len(bmp_data)
    bmp_data[2:6] = struct.pack("<I", new_size)

    # Write the modified bytearray into the new output image file
    with open(output_path, 'wb') as f:
        f.write(bmp_data)
    print(f"[+] Data hidden using Method 1 and saved to {output_path}")


# Method 2: steganography

def hide_method_2(bmp_path, output_path, secret_data):
    # Open the BMP file
    with open(bmp_path, 'rb') as f:
        bmp_data = bytearray(f.read())

    # Read the pixel data start position (offset) from bytes 10 to 13 of the header
    pixel_offset = struct.unpack("<I", bmp_data[10:14])[0]

    # Combine the signature, the secret message, and a null terminator (\x00)
    payload = SIGNATURE_M2 + secret_data + b"\x00"

    # Break down every byte of the payload into a list of 8 bits
    secret_bits = []
    for byte in payload:
        temp_byte = byte
        byte_bits = []
        for i in range(8):
            # Get the bit on the right' then divide by 2 to move to the next bit
            bit = temp_byte % 2
            byte_bits.append(bit)
            temp_byte = temp_byte // 2
        # Reverse the bits because we extracted them from right to left
        byte_bits.reverse()
        secret_bits.extend(byte_bits)

    # Check if the pixel array has enough space
    available_space = len(bmp_data) - pixel_offset
    if len(secret_bits) > available_space:
        raise ValueError("The image is too small to contain this secret data!")

    # Insert each secret bit into the least significant bit (LSB)
    for idx, bit in enumerate(secret_bits):
        byte_index = pixel_offset + idx
        # Clear the original last bit by making it even, then add our secret bit
        if bmp_data[byte_index] % 2 == 1:
            bmp_data[byte_index] = bmp_data[byte_index] - 1
        bmp_data[byte_index] = bmp_data[byte_index] + bit

    # Write the modified steganographic bytearray into the new output image file
    with open(output_path, 'wb') as f:
        f.write(bmp_data)
    print(f"[+] Data hidden using Method 2 and saved to {output_path}")


if __name__ == "__main__":
    # Create a basic dummy BMP file structure for testing purposes
    dummy_bmp_header = b'BM' + struct.pack("<I", 54 + 100) + b'\x00\x00\x00\x00' + struct.pack("<I",
                                                                                               54) + b'\x28\x00\x00\x00\x0a\x00\x00\x00\x0a\x00\x00\x00\x01\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    dummy_pixels = b'\x00' * 100
    with open("test.bmp", "wb") as f:
        f.write(dummy_bmp_header + dummy_pixels)

    text_to_hide = b"Hello, this is a secret message!"

    # Hide using Method 1
    hide_method_1("test.bmp", "output_m1.bmp", text_to_hide)

    # Hide using Method 2
    hide_method_2("test.bmp", "output_m2.bmp", text_to_hide)
