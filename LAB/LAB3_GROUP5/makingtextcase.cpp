#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>

using namespace std;

// Define printable characters for random text
const char CHARSET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,!?-()";
const int CHARSET_SIZE = sizeof(CHARSET) - 1;

// Function to generate a random character
char getRandomChar() {
    return CHARSET[rand() % CHARSET_SIZE];
}

// Modified function to handle bytes (B), kilobytes (K), and megabytes (M)
void generateFile(const string& filename, int size, char unit) {
    const int KB = 1024;         // 1KB = 1024 bytes
    const int MB = 1024 * KB;    // 1MB = 1024 KB
    int fileSize;
    
    // Calculate file size based on unit
    switch(toupper(unit)) {
        case 'B':
            fileSize = size;
            break;
        case 'K':
            fileSize = size * KB;
            break;
        case 'M':
            fileSize = size * MB;
            break;
        default:
            cerr << "Invalid unit! Use 'B' for bytes, 'K' for KB, or 'M' for MB.\n";
            return;
    }

    ofstream outFile(filename, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot open file " << filename << " for writing.\n";
        return;
    }

    srand(static_cast<unsigned>(time(0)));

    cout << "Generating file: " << filename << " (" << size << unit << ")...\n";

    // Adjust buffer size for small files
    const int MAX_BUFFER_SIZE = 1024 * 1024; // 1MB
    const int BUFFER_SIZE = min(MAX_BUFFER_SIZE, fileSize);
    char* buffer = new char[BUFFER_SIZE];

    for (int written = 0; written < fileSize; written += BUFFER_SIZE) {
        int chunkSize = min(BUFFER_SIZE, fileSize - written);
        for (int i = 0; i < chunkSize; i++) {
            buffer[i] = getRandomChar();
        }
        outFile.write(buffer, chunkSize);
    }

    delete[] buffer;
    outFile.close();
    cout << "File generated successfully: " << filename << endl;
    cout << "Actual size: " << fileSize << " bytes" << endl;
}

// Modified main function to handle bytes
int main() {
    int size;
    char unit;

    cout << "Enter file size (e.g., 512B for bytes, 10K for KB, 1M for MB): ";
    cin >> size >> unit;

    if (toupper(unit) != 'B' && toupper(unit) != 'K' && toupper(unit) != 'M') {
        cerr << "Invalid size unit! Use 'B' for bytes, 'K' for KB, or 'M' for MB.\n";
        return 1;
    }

    string filename = "random_" + to_string(size) + unit + ".txt";
    generateFile(filename, size, unit);

    return 0;
}
