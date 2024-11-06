import argparse
from cryptography.fernet import Fernet


def generate_key(output_file):
    # Generate and save encryption key
    key = Fernet.generate_key()
    with open(output_file, "wb") as key_file:
        key_file.write(key)
    print(f"Key generated and saved to {output_file}")


def load_key(key_file):
    # Read encryption key from file
    with open(key_file, "rb") as file:
        return file.read()


def encrypt_file(input_file, key_file, output_file):
    # Encrypt given file with help of key
    key = load_key(key_file)
    fernet = Fernet(key)

    # Read the contents of the file to be encrypted
    with open(input_file, "rb") as file:
        original_data = file.read()
    
    # Encrypt data
    encrypted_data = fernet.encrypt(original_data)


    # Save encrypted data to file
    with open(output_file, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    print(f"File {input_file} has been encrypted and saved to {output_file}")


def decrypt_file(input_file, key_file, output_file):
    try:
        # Decrypt a encrypted file with help of key
        key = load_key(key_file)
        fernet = Fernet(key)

        # Read content of decrypted file
        with open(input_file, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_data)

        # Write decrypted data to new file
        with open(output_file, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        print(f"File {input_file} have decrypted and saved to {output_file}")

    except FileNotFoundError as e:
        print(f"error: File {e.filename} not found")
    except PermissionError:
        print(f"error: Lacks permission to write to {output_file}")
    except Exception as e:
        print(f"Failed to decrypt file. error: {e}")
        

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files with a symmetric key")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Subparser to generate key
    parser_key = subparsers.add_parser("generate_key", help="Generate and save encryption key")
    parser_key.add_argument("output_file", help="Path to file where the key should get saved")


    # Subparser to encrypt a file
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a file")
    parser_encrypt.add_argument("input_file", help="Path to file to encrypt")
    parser_encrypt.add_argument("key_file", help="Path to file with encryption key")
    parser_encrypt.add_argument("output_file", help="Path to file where encrypted data should be saved")


    # Subparser to decrypt a file
    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a file")
    parser_decrypt.add_argument("input_file", help="Path to the file to decrypt")
    parser_decrypt.add_argument("key_file", help="Path to file with encryption key")
    parser_decrypt.add_argument("output_file", help="Path to file where decrypted data should be saved")

    args = parser.parse_args()

    if args.command == "generate_key":
        generate_key(args.output_file)
    elif args.command == "encrypt":
        encrypt_file(args.input_file, args.key_file, args.output_file)
    elif args.command == "decrypt":
        decrypt_file(args.input_file, args.key_file, args.output_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()