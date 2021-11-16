/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <stdio.h>
#include <stdint.h>
#include "pch.h"

//Base64url encoding table
static const unsigned char base64urlEncTable[64] =
    {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};

//Base64url decoding table
static const unsigned char base64urlDecTable[128] =
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F,
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


void base64urlEncode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen)
{
  size_t n;
  unsigned char a;
  unsigned char b;
  unsigned char c;
  unsigned char d;
  const unsigned char *p;

  p = (const unsigned char *)input;
  n = inputLen / 3;

  if (inputLen == (n * 3 + 1))
  {
    if (input != NULL && output != NULL)
    {
      a = (p[n * 3] & 0xFC) >> 2;
      b = (p[n * 3] & 0x03) << 4;

      output[n * 4] = base64urlEncTable[a];
      output[n * 4 + 1] = base64urlEncTable[b];
      output[n * 4 + 2] = '\0';
    }

    if (outputLen != NULL)
    {
      *outputLen = n * 4 + 2;
    }
  }
  else if (inputLen == (n * 3 + 2))
  {
    if (input != NULL && output != NULL)
    {
      a = (p[n * 3] & 0xFC) >> 2;
      b = ((p[n * 3] & 0x03) << 4) | ((p[n * 3 + 1] & 0xF0) >> 4);
      c = (p[n * 3 + 1] & 0x0F) << 2;

      output[n * 4] = base64urlEncTable[a];
      output[n * 4 + 1] = base64urlEncTable[b];
      output[n * 4 + 2] = base64urlEncTable[c];
      output[n * 4 + 3] = '\0';
    }

    if (outputLen != NULL)
    {
      *outputLen = n * 4 + 3;
    }
  }
  else
  {
    if (output != NULL)
    {
      output[n * 4] = '\0';
    }

    if (outputLen != NULL)
    {
      *outputLen = n * 4;
    }
  }

  if (input != NULL && output != NULL)
  {
    while (n-- > 0)
    {
      a = (p[n * 3] & 0xFC) >> 2;
      b = ((p[n * 3] & 0x03) << 4) | ((p[n * 3 + 1] & 0xF0) >> 4);
      c = ((p[n * 3 + 1] & 0x0F) << 2) | ((p[n * 3 + 2] & 0xC0) >> 6);
      d = p[n * 3 + 2] & 0x3F;

      output[n * 4] = base64urlEncTable[a];
      output[n * 4 + 1] = base64urlEncTable[b];
      output[n * 4 + 2] = base64urlEncTable[c];
      output[n * 4 + 3] = base64urlEncTable[d];
    }
  }
}

int base64urlDecode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen)
{
  uint32_t value;
  unsigned int c;
  size_t i;
  size_t n;
  unsigned char *p;

  if (input == NULL && inputLen != 0)
    return 1; // Invalid input

  //Check the length of the input string
  if ((inputLen % 4) == 1)
    return 1; // Invalid input

  if (outputLen == NULL)
    return 2; // Invalid output length

  p = (unsigned char *)output;
  n = 0;
  value = 0;

  for (i = 0; i < inputLen; i++)
  {
    c = (unsigned int)input[i];

    if (c < 128 && base64urlDecTable[c] < 64)
    {
      value = (value << 6) | base64urlDecTable[c];

      if ((i % 4) == 3)
      {
        if (p != NULL)
        {
          p[n] = (value >> 16) & 0xFF;
          p[n + 1] = (value >> 8) & 0xFF;
          p[n + 2] = value & 0xFF;
        }

        n += 3;
        value = 0;
      }
    }
    else
    {
      return 3; // invalid character
    }
  }

  if ((inputLen % 4) == 2)
  {
    if (p != NULL)
    {
      p[n] = (value >> 4) & 0xFF;
    }

    n++;
  }
  else if ((inputLen % 4) == 3)
  {
    if (p != NULL)
    {
      p[n] = (value >> 10) & 0xFF;
      p[n + 1] = (value >> 2) & 0xFF;
    }

    n += 2;
  }

  *outputLen = n;
  return 0;
}
