
int main(int argc, char ** argv) {
    float f1;
    float f2 = 1.5;

    double d1;
    double d2 = 1.1 + 2.2;
    double d3 = (double) f2 * 2.0;

    float _1d_arr[10];
    double _2d_arr[10][10];

    for (int i = 0; i < 10; i++) {
        _1d_arr[i] = ((float) i) * 2.5 + f2;

        for (int j = 0; j < 10; j++) {
            _2d_arr[i][j] = ((double) j) + ((double) _1d_arr[i]) + 8.5 + d2;
        }
    }

    return 0;
}
