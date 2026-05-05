#include <stdio.h>
#include <stdlib.h>

static int score_path(int value) {
    int score = 0;

    if ((value & 1) == 0) {
        score += 3;
    } else {
        score += 1;
    }

    switch (value % 5) {
    case 0:
        score += 5;
        break;
    case 1:
    case 2:
        score += 2;
        break;
    default:
        score += 4;
        break;
    }

    for (int i = 0; i < 4; ++i) {
        score += (value >> i) & 1;
    }

    return score;
}

static int transform(int input) {
    int a = score_path(input);
    int b = score_path(input ^ 0x2A);
    int c = (a * 7) ^ (b * 3);
    return (c % 11) + a - b;
}

int main(int argc, char **argv) {
    int input = 1337;

    if (argc > 1) {
        input = atoi(argv[1]);
    }

    printf("control_flow_lab: %d\n", transform(input));
    return 0;
}
