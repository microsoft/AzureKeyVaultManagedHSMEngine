/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#ifndef BASE64URL_H
#define BASE64URL_H

/**
 * @brief Base64url encoding
 * 
 * @param input  Input data to encode
 * @param inputLen Length of the data to encode
 * @param output NULL-terminated string encoded with Base64url algorithm
 * @param outputLen Length of the encoded string (optional parameter)
 */
void base64urlEncode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen);

/**
 * @brief Base64url decoding 
 * 
 * @param input Base64url-encoded string
 * @param inputLen Length of the encoded string
 * @param output Resulting decoded data
 * @param outputLen Length of the decoded data
 * @return 0==Success, Error code 1==invalid inputLen, 2==invalid outputLen, 3==invalid character found 
 */
int base64urlDecode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen);

#endif /* BASE64URL_H */
