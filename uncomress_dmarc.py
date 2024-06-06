import os
import gzip
import zipfile
import shutil

def decompress_gzip_files(directory):
    # Iterate over all files in the specified directory
    for filename in os.listdir(directory):
        if filename.endswith(".gz"):
            # Construct the full path to the file
            file_path = os.path.join(directory, filename)
            # Create the output path by removing the .gz extension
            output_path = os.path.join(directory, filename[:-3])

            # Decompress the file
            with gzip.open(file_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        
        elif filename.endswith(".zip"):
            file_path = os.path.join(directory, filename)
            with zipfile.ZipFile(file_path) as zip_ref:
                zip_ref.extractall(directory)

            print(f"Decompressed: {output_path}")

# Specify the directory containing the .gz files
data_directory = 'data/'  # Change this to your directory path
decompress_gzip_files(data_directory)
