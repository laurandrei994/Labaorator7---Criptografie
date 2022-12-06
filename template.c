#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

int hex_to_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9) result--;
    return result;
}

int hex_to_ascii(const char c, const char d)
{
	int high = hex_to_int(c) * 16;
	int low = hex_to_int(d);
	return high+low;
}

void printHX(const char* st)
{
	int length = strlen(st);
	if (length % 2 != 0) 
	{
		printf("%s\n", "invalid hex length");
		return;
	}
	int i;
	char buf = 0;
	for(i = 0; i < length; i++) 
	{
		if(i % 2 != 0)
			printf("%c", hex_to_ascii(buf, st[i]));
		else
		    buf = st[i];
	}
	printf("\n");
}

void printBN(char* msg, BIGNUM* a)
{
	/* Use BN_bn2hex(a) for hex string
	 * Use BN_bn2dec(a) for decimal string */

	char* number_str = BN_bn2hex(a);
	printf("%s 0x%s\n", msg, number_str);
	OPENSSL_free(number_str);
}

BIGNUM* get_rsa_priv_key(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
	// given two large prime numbers, compute a private key using the modulo inverse of the totatives of the product p*q

    // ---------------------------- CODE HERE ----------------------------
	BIGNUM* one = BN_new();
	BN_dec2bn(&one, "1");
	
	BIGNUM* p_minus_one = BN_new();
	BN_sub(p_minus_one, p, one);

	BIGNUM* q_minus_one = BN_new();
	BN_sub(q_minus_one, q, one);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* t = BN_new();
	BN_mul(t, p_minus_one, q_minus_one, ctx);

	BIGNUM* private_key = BN_new();
	
	BN_mod_inverse(private_key, t, e, ctx);
	return private_key; 
}

BIGNUM* rsa_encrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key)
{
	// compute the RSA cipher on message, the ciphertext is congruent to: message^e (modulo pub_key)
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* enc = BN_new();
	BN_mod_exp(enc, message, mod, pub_key, ctx);
	BN_CTX_free(ctx);
	return enc;
}

BIGNUM* rsa_decrypt(BIGNUM* enc, BIGNUM* priv_key, BIGNUM* pub_key)
{
	// compute the original message: (message ^ mod) ^ pub_key
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* dec = BN_new();
	BN_mod_exp(dec, enc, priv_key, pub_key, ctx);
	BN_CTX_free(ctx);
	return dec;
}

BIGNUM* rsa_private_key;

int main () 
{
	printf("\n=================================================\n");
	// Task 1 - Deriving a private key
	printf("Task 1 - Deriving a private key\n\n"); 
	
	BIGNUM* p = BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");

	BIGNUM* q = BN_new();
	BN_hex2bn(&q, "E85CED54AF75E53E092113E62F436F4F");

	BIGNUM* e = BN_new();
	BN_hex2bn(&e, "0D88C3");

	rsa_private_key = get_rsa_priv_key(p,q,e);
	printBN("Result: ", rsa_private_key);

	printf("\n=================================================\n");
	// Task 2 - Encrypting a message
	printf("Task 2 - Encrypting a message\n\n");

	BIGNUM* private_key = BN_new();
	BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM* public_key = BN_new();
	BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	BIGNUM* mod_val = BN_new();
	BN_hex2bn(&mod_val, "010001");

	BIGNUM* message = BN_new();
	BN_hex2bn(&message, "4120746f702073656372657421");

	BIGNUM* encryption_value = rsa_encrypt(message, mod_val, public_key);
	BIGNUM* decryption_value = rsa_decrypt(encryption_value, private_key, public_key);

	printHX(BN_bn2hex(decryption_value));

	printf("\n=================================================\n");
	// Task 3 - decrypt a message		
	printf("Task 3 - Decrypt a message\n\n");

	BIGNUM* encrypted_text = BN_new();
	BN_hex2bn(&encrypted_text, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

	BIGNUM* decrypted_text = rsa_decrypt(encrypted_text, private_key, public_key);
	
	printHX(BN_bn2hex(decrypted_text));

	printf("\n=================================================\n");
	// Task 4 - Signing a message
	printf("Task 4 - Signing a message\n\n");

	BIGNUM* message_2000 = BN_new();
	BN_hex2bn(&message_2000, "49206F776520796F752024323030302E");

	BIGNUM* message_3000 = BN_new();
	BN_hex2bn(&message_3000, "49206F776520796F752024333030302E");

	BIGNUM* signature_2000 = rsa_encrypt(message_2000, mod_val, public_key);
	printBN("Result - message_2000: ", signature_2000);

	BIGNUM* signature_3000 = rsa_encrypt(message_3000, mod_val, public_key);
	printBN("Result - message_3000: ", signature_3000);
	
	printf("\n=================================================\n");
	// Task 5 - Verifying a signature
	printf("Task 5 - Verifying a signature\n\n");

	BIGNUM* certificate_body = BN_new();
	BN_hex2bn(&certificate_body, "902677e610fedcdd34780e359692eb7bd199af35115105636aeb623f9e4dd053");
	
	BIGNUM* certificate_signature = BN_new();
	BN_hex2bn(&certificate_signature, "84a89a11a7d8bd0b267e52247bb2559dea30895108876fa9ed10ea5b3e0bc72d47044edd4537c7cabc387fb66a1c65426a73742e5a9785d0cc92e22e3889d90d69fa1b9bf0c16232654f3d98dbdad666da2a5656e31133ece0a5154cea7549f45def15f5121ce6f8fc9b04214bcf63e77cfcaadcfa43d0c0bbf289ea916dcb858e6a9fc8f994bf553d4282384d08a4a70ed3654d3361900d3f80bf823e11cb8f3fce7994691bf2da4bc897b811436d6a2532b9b2ea2262860da3727d4fea573c653b2f2773fc7c16fb0d03a40aed01aba423c68d5f8a21154292c034a220858858988919b11e20ed13205c045564ce9db365fdf68f5e99392115e271aa6a8882");
	
	BIGNUM* certificate_public_key = BN_new();
	BN_hex2bn(&certificate_public_key, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
	
	BIGNUM* certificate_exponent = BN_new();
	BN_hex2bn(&certificate_exponent, "010001");
	
	BIGNUM* certificate_verification = rsa_decrypt(certificate_signature, certificate_exponent, certificate_public_key);
	
	char* certificate_verification_string = BN_bn2hex(certificate_verification);
   	char *result_string;
   	
   	int c = 0;
        while (c < 64) 
        {
      		result_string[c] = certificate_verification_string[strlen(certificate_verification_string) - 64 + c];
      		c++;
   	}
   	result_string[c] = '\0';
   	
   	BIGNUM* result = BN_new();
	BN_hex2bn(&result, result_string);
        
        if(BN_cmp(certificate_body, result) == 0)
        {
 		printf("Verification passed");
 	}

	printf("\n=================================================\n");

}
