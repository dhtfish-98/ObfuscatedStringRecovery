/* Self-owned, harmless static-analysis fixture. It is compiled but never run. */
const char ordinary_notice[] = "SAFE_NOTICE";

__attribute__((noinline)) void stack_plain(void) {
    volatile unsigned char b[8];
    b[0] = 'H'; b[1] = 'E'; b[2] = 'L'; b[3] = 'L'; b[4] = 'O'; b[5] = 0;
}

__attribute__((noinline)) void stack_encoded(void) {
    volatile unsigned char b[8];
    b[0] = 'W' ^ 0x21; b[1] = 'O' ^ 0x21; b[2] = 'R' ^ 0x21;
    b[3] = 'L' ^ 0x21; b[4] = 'D' ^ 0x21; b[5] = 0x21;
    b[0] ^= 0x21; b[1] ^= 0x21; b[2] ^= 0x21;
    b[3] ^= 0x21; b[4] ^= 0x21; b[5] ^= 0x21;
}

__attribute__((noinline)) void benign_short(void) {
    volatile unsigned char b[4];
    b[0] = 'C'; b[1] = 'A'; b[2] = 'T'; b[3] = 0;
}

__attribute__((noinline)) void benign_nonprintable(void) {
    volatile unsigned char b[8];
    b[0] = 'B'; b[1] = 'A'; b[2] = 1; b[3] = 'D'; b[4] = 0;
}

/* A conditional path is deliberately outside the scanner's straight-line scope. */
__attribute__((noinline)) void unknown_branch(volatile int condition) {
    volatile unsigned char b[8];
    if (condition) {
        b[0] = 'S'; b[1] = 'E'; b[2] = 'C'; b[3] = 'R';
        b[4] = 'E'; b[5] = 'T'; b[6] = 0;
    }
}
