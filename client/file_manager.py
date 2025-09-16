import os
import shutil

class FileManager:
    """Handles data storage and retrieval using a magic header to detect encryption."""
    
    MAGIC_HEADER = b'ENC!'  # 4-byte header to mark encrypted files

    def __init__(self, file: str|None, base_dir='./locker'):
        self.file = file
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def read_file(self):
        """Reads the file as bytes."""
        try:
            with open(self.file, 'rb') as file:
                return file.read()
        except FileNotFoundError:
            print("Error: File not found.")
            exit()
        except Exception as e:
            print(f"Error reading file: {e}")
            exit()

    def write_file(self, content: bytes, add_header=False):
        """Writes bytes to the file. Optionally adds encryption header."""
        try:
            with open(self.file, 'wb') as file:
                if add_header:
                    file.write(self.MAGIC_HEADER)
                file.write(content)
        except Exception as e:
            print(f"Error writing file: {e}")
            exit()

    def is_already_encrypted(self):
        """Checks if the file starts with the magic header."""
        try:
            with open(self.file, 'rb') as file:
                header = file.read(len(self.MAGIC_HEADER))
                return header == self.MAGIC_HEADER
        except Exception as e:
            print(f"Error checking encryption status: {e}")
            return False

    def strip_header(self):
        """Removes the magic header from the file, if present."""
        if not self.is_already_encrypted():
            print("File is not encrypted.")
            return

        try:
            with open(self.file, 'rb') as file:
                file.read(len(self.MAGIC_HEADER))  # Skip header
                content = file.read()

            with open(self.file, 'wb') as file:
                file.write(content)
            print("Magic header removed.")
        except Exception as e:
            print(f"Error stripping header: {e}")

    def storage(self, email):
        sub_dir = email
        full_path = os.path.join(self.base_dir, sub_dir)
                
        # Create the storage directory if it doesn't exist
        os.makedirs(full_path, exist_ok=True)

        return full_path
    
    def move_file(self, src_file_location, destination):
        shutil.move(src_file_location, destination)


if __name__ == "__main__":
    fm = FileManager("shoppingList.txt")
    data = fm.read_file()

    if not fm.is_already_encrypted():
        fm.write_file(data, add_header=True)
        print("File marked as encrypted.")
    else:
        print("File is already encrypted.")
