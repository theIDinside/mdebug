#include <cctype>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>

static uint32_t WIDTH = 8000;
static uint32_t HEIGHT = 8000;
static uint32_t MAX_ITER = 500;
const int NUM_THREADS = 7;

std::vector<unsigned char> image(WIDTH * HEIGHT * 3); // RGB buffer
std::mutex row_mutex;
int next_row = 0; // Shared state to track the next row to be computed

// Function to compute Mandelbrot value for a pixel
int mandelbrot(double x0, double y0) {
    double x = 0.0, y = 0.0;
    int iter = 0;
    while (x * x + y * y <= 4.0 && iter < MAX_ITER) {
        double temp = x * x - y * y + x0;
        y = 2 * x * y + y0;
        x = temp;
        iter++;
    }
    return iter;
}

// Colorize the pixel based on iteration count
void colorize_pixel(int iter, int x, int y) {
    int index = 3 * (y * WIDTH + x);
    if (iter == MAX_ITER) {
        // Black for points inside the Mandelbrot set
        image[index] = 0;
        image[index + 1] = 0;
        image[index + 2] = 0;
    } else {
        // Gradient color for points outside the Mandelbrot set
        unsigned char color = static_cast<unsigned char>(255 * iter / MAX_ITER);
        image[index] = color;
        image[index + 1] = color;
        image[index + 2] = 255;
    }
}

// Worker thread function
void worker_thread() {
    while (true) {
        int row;
        {
            std::unique_lock<std::mutex> lock(row_mutex);
            if (next_row >= HEIGHT) {
                break;
            }
            row = next_row++;
        }

        // Calculate all pixels in the row
        for (int x = 0; x < WIDTH; x++) {
            double x0 = (x - WIDTH / 2.0) * 4.0 / WIDTH;
            double y0 = (row - HEIGHT / 2.0) * 4.0 / HEIGHT;
            int iter = mandelbrot(x0, y0);
            colorize_pixel(iter, x, row);
        }
    }
}

// Write PPM file
void write_ppm(const std::string &filename) {
    std::ofstream file(filename, std::ios::binary);

    // PPM header
    file << "P6\n" << WIDTH << " " << HEIGHT << "\n255\n";

    // Write pixel data
    file.write(reinterpret_cast<const char *>(image.data()), image.size());

    file.close();
}

int main(int argc, const char** argv) {

    const char* widthXheight = nullptr;
    const char* iterations = nullptr;

    for(auto i = 1; i < argc; ++i) {
        std::string arg{argv[i]};
        for(auto& ch : arg) {
            ch = std::toupper(ch);
        }
        std::string_view argview{arg};
        if(const auto split = argview.find('X'); split != std::string_view::npos) {
            auto width = argview.substr(0, split);
            auto height = argview.substr(split+1);
            uint32_t w = 0, h = 0;
            auto a = std::from_chars(width.begin(), width.end(), w);
            auto b = std::from_chars(height.begin(), height.end(), h);

            if(a.ec != std::errc() || b.ec != std::errc()) {
                printf("invalid <widthXheight> format: %s\nExample usage: 100x100\n", arg.c_str());
                exit(-1);
            }
            WIDTH = w;
            HEIGHT = h;
        } else {
            uint32_t iter = 0;
            auto a = std::from_chars(argview.begin(), argview.end(), iter);
            if(a.ec != std::errc()) {
                printf("iterations formatting wrong: %s\nusage example: mandelbrot 400x600 100", arg.c_str());
                exit(-1);
            }
            MAX_ITER = iter;
        }
    }

    // Start worker threads
    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back(worker_thread);
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }

    // Write the image to a PPM file
    write_ppm("mandelbrot.ppm");

    std::cout << "Mandelbrot image saved as 'mandelbrot.ppm'" << std::endl;
    return 0;
}
