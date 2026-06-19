pragma circom 2.0.0;

// RangeCheck64: prove 0 <= x < 2^64 via 64-bit binary decomposition.
// Prevents field-wraparound attacks that would create value from nothing.
//
// Template: RangeCheck64()
// Input:  x  — field element to range-check
// Output: (none — constraint only)

include "../../node_modules/circomlib/circuits/bitify.circom";

template RangeCheck64() {
    signal input x;

    component bits = Num2Bits(64);
    bits.in <== x;
}
