#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "pv.h"
 
static float gaussrand_NORMAL(void) {
	static float V1, V2, S;
	static int phase = 0;
	float X;


	if (phase == 0) {
		do {
			float U1 = (float) rand() / RAND_MAX;
			float U2 = (float) rand() / RAND_MAX;


			V1 = 2 * U1 - 1;
			V2 = 2 * U2 - 1;
			S = V1 * V1 + V2 * V2;
		} while (S >= 1 || S == 0);


		X = V1 * sqrt(-2 * log(S) / S);
	} else
		X = V2 * sqrt(-2 * log(S) / S);


	phase = 1 - phase;


	return X;
}


float gaussrand(float mean, float stdc) {
	return mean + gaussrand_NORMAL() * stdc;
}

/*
int main() 
{
	float mean = 0;
	float stdc = 1;
	float data = 0;
	
	for(int i=0; i<100; ++i){
		data = gaussrand(0, 1);
		printf("%f\t", data);
	}
}*/
