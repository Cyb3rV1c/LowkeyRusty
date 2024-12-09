#include <iostream>
#include <fstream>
#include <vector>
#include <string>

void xor_encrypt_file(const std::string& input_file, const std::string& output_file, const std::string& key) {
    // Open the input file in binary mode
    std::ifstream infile(input_file, std::ios::binary);
    if (!infile) {
        std::cerr << "Error: Unable to open input file: " << input_file << std::endl;
        return;
    }

    // Read the file contents into a vector
    std::vector<char> buffer((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    infile.close();

    // Perform XOR encryption
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] ^= key[i % key.size()];
    }

    // Open the output file in binary mode
    std::ofstream outfile(output_file, std::ios::binary);
    if (!outfile) {
        std::cerr << "Error: Unable to open output file: " << output_file << std::endl;
        return;
    }

    // Write the encrypted data to the output file
    outfile.write(buffer.data(), buffer.size());
    outfile.close();

    std::cout << "Encryption successful! Encrypted file saved as: " << output_file << std::endl;
}

int main() {
    // Specify the input and output file paths
    std::string input_file = "C:\\Users\\Anonym\\Desktop\\Proj\\beacon\\shell.bin";
    std::string output_file = "C:\\Users\\Anonym\\Desktop\\Proj\\beacon\\shell_out.bin";

    // Define the XOR key
    std::string key = "Randomkey";

    // Encrypt the file
    xor_encrypt_file(input_file, output_file, key);

    return 0;
}
