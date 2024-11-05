#!/usr/bin/python -i

# Just some helper functions to convert PPC bits (in the docs) to integer
# values we can actually use in code.

def ppcbit(i):
    return 1 << (63 - i)

def ppcmask(a,b):
    mask = 0
    for i in range(a, b + 1):
        mask += ppcbit(i)
    return mask

def ppcfield(a, b, v):
    return (v & ppcmask(a,b)) >> (63 - b)

def ppcbit32(i):
    return 1 << (31 - i)

def ppcmask32(a,b):
    mask = 0
    for i in range(a, b + 1):
        mask += ppcbit32(i)
    return mask

def ppcfield32(a, b, v):
    return (v & ppcmask32(a,b)) >> (31 - b)
