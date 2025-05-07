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

// Function to generate a file of given size in KB or MB
void generateFile(const string& filename, int size, char unit) {
    const int KB = 1024;         // 1KB = 1024 bytes
    const int MB = 1024 * KB;    // 1MB = 1024 KB
    int fileSize = (unit == 'K') ? (size * KB) : (size * MB);

    ofstream outFile(filename, ios::binary);
    if (!outFile) {
        cerr << "Error: Cannot open file " << filename << " for writing.\n";
        return;
    }

    srand(static_cast<unsigned>(time(0))); // Seed the random generator

    cout << "Generating file: " << filename << " (" << size << unit << "B)...\n";

    // Write data in chunks for efficiency
    const int BUFFER_SIZE = 1024 * 1024; // 1MB buffer for efficiency
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
}

int main() {
    int size;
    char unit;

    cout << "Enter file size (e.g., 10K for 10KB, 1M for 1MB): ";
    cin >> size >> unit;

    if (unit != 'K' && unit != 'M') {
        cerr << "Invalid size unit! Use 'K' for KB or 'M' for MB.\n";
        return 1;
    }

    string filename = "random_" + to_string(size) + unit + ".txt";
    generateFile(filename, size, unit);

    return 0;
}
