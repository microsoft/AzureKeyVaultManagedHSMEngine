#ifndef BASE64LIB_H
#define BASE64LIB_H

/**
 * @brief Find the length for the 
 * 
 * @param bufcoded Length of the data to encode
 * @return Length of the encoded string
 */
int Base64encode_len(int len);

/**
 * @brief Base64url encoding 
 * 
 * @param encoded String encoded with Base64url algorithm
 * @param string Input data to encode
 * @param len Length of the data to encode
 */
void Base64encode(char *encoded, const char *string, int len);

#endif /* BASE64LIB_H */