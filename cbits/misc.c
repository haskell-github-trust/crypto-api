/* Fast C implementation of a safe string equality test. */
int c_safeEq(char *x, char *y, int length) {
    int ret = 0, i;
    for (i = 0; i < length; i++)
        ret = ret | x[i] ^ y[i];
    return ret;
}
