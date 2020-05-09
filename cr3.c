/* 
* cr3 Predictable Random Numeric Key Generator (c)  k theis 5/4/2020
*
* LFSR routines derived from A.C./schneier. See page 375 for code, 376 for initial primitive polynomials
*
* The key is composed of 2 groups of 8 hex digits. Group 1 is the starting count, 
* group 2 is the starting value. The actual values are derived from these. When running this
* program you MUST supply all 16 hex digits.
*
* compile with [cc -o cr3 cr3.c -lm -Wall]  on any standard c compiler
* Then link to cr3 with cr3l  (the letter ell) (to generate letters)
* 	ln -s cr3 cr3l
* and link to cr3 with cr3n (to generate numbers)
* 	ln -s cr3 cr3n
* and link to cr3 with cr3h (to generate hexidecimal values)
* 	ln -s cr3 cr3h 
* Calling cr3n will display random numbers in groups of 25 for numeric keys and
* calling cr3l will display random letters [A-Z] in groups of 25. This is used in a vigenere cipher.
* Calling cr3h will display hexidecimal values [0-f].
*
*
* As a test, to generate 3 groups of 25 digits (75 digits) with the key: 0000001100000030
$> ./cr3n 0000001100000030 3
34071 13986 48742 63295 41317 
85250 04428 42196 93633 92673 
76031 21683 15046 53786 65616
$>

* The security of this key generator is in the key. The LFSR routine generates (2^32)-1 digits
* before repeating. By varying the start point and initial start position, this is multiplied by
* ((2^32)-1 * (2^32)-1). The end result is a series of 7.923 ^ 28 1's and 0's before repeating.
* Since the typical message length of most messages is less than 1000 characters and the lifetime
* of the message is typically measured in minutes to hours, the odds of decrypting the message 
* encoded with this key sequence will be small. 
*
* In addition, we use 2 LFSR routines with different taps (both (2^32)-1 in length before repeating)
* and use different starting positions and values for each. We get a 16 bit value from LFSRa and a 16 bit
* value from LFSRb then xor them together to get another 16 bit value. We then get the modulo 10
* result as a single digit and display this digit. It is expected that this will reduce the bias that a
* cryptographer may find. As long as the LFSR routines are unknown and the messages are short, 
* that bias should not be determinable. (The bias would make is easier for a cryptographer to exploit
* the routines and determine the key).
*
* NEVER resue a key. For security each message MUST have a unique key. Destroy the key after
* the message is encrypted. Never disclose the key. The message originator and the message recipient 
* must both have the same key for the message to be useable.
*
* Keep this program secure, and away from public access (websites, ftp servers, etc).
*
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <libgen.h>

static unsigned long ShiftRegistera = 0;
static unsigned long ShiftRegisterb = 0;

/* lfsr #1 */
int LFSRa(void) {	// (32,7,5,2,1)
    ShiftRegistera = (((((ShiftRegistera >> 31)
		    ^ (ShiftRegistera >> 6)
		    ^ (ShiftRegistera >> 4)
		    ^ (ShiftRegistera >> 1)
	 	    ^ ShiftRegistera))
	    	    & 0x00000001)
		    << 31 )
		    | (ShiftRegistera >> 1);
    return ShiftRegistera & 0x00000001;
}

/* lfsr #2 */
int LFSRb(void) {	// (24,4,3,1,0)
    ShiftRegisterb = (((((ShiftRegisterb >> 23)
		    ^ (ShiftRegisterb >> 3)
		    ^ (ShiftRegisterb >> 2)
	 	    ^ ShiftRegisterb))
	    	    & 0x00000001)
		    << 23 )
		    | (ShiftRegisterb >> 1);
    return ShiftRegisterb & 0x00000001;
}


int main(int argc, char **argv) {
    int n, num,  numa, numb, vala, valb;
    unsigned long precount, initvala, initvalb;
    char cntval[9]; char keyval[9];
    int cnt=0;
    int total = 0;
    int maxgroups = 0;

    if (strcmp((basename(argv[0])),"cr3")==0) {
	fprintf(stderr,"Please use cr3h, cr3l or cr3n \n");
	exit(0);
    }

    if ((argc < 2) || (argc > 3)) {
	fprintf(stderr,"Format: %s [32 bit (hex) key] [optional: # of blocks of 25 (default 20)]\n",argv[0]);
	fprintf(stderr,"cr3n produces numeric random characters [0-9], cr3l produces alpha random characters [A-Z]\n");
	fprintf(stderr,"and cr3h produces random hexidecimal values [0-f]\n");
	fprintf(stderr,"Example: %s 0011223380a0f0ed 5 \n",argv[0]);
	fprintf(stderr,"will generate a key 125 chars long using the hex key 0011223380a0f0ed \n");
	exit(-1);
    }

    if (argc == 3) {
	maxgroups = atoi(argv[2]);
    } else {
	maxgroups = 20;
    }    

    // get the pre-count
    cntval[0] = argv[1][0]; cntval[1] = argv[1][1]; cntval[2] = argv[1][2]; cntval[3] = argv[1][3];
    cntval[4] = argv[1][4]; cntval[5] = argv[1][5]; cntval[6] = argv[1][6]; cntval[7] = argv[1][7];
    cntval[8] = '\0';
    precount = strtoul(cntval,0,16);

    // get the key value for a
    keyval[0]=argv[1][12]; keyval[1]=argv[1][14]; keyval[2]=argv[1][10]; keyval[3]=argv[1][11];
    keyval[4] = argv[1][8]; keyval[5] = argv[1][13]; keyval[6] = argv[1][9]; keyval[7] = argv[1][15];
    keyval[8] = '\0';
    initvala = strtoul(keyval,0,16);

    // get the key value for b
    keyval[0]=argv[1][11]; keyval[1]=argv[1][14]; keyval[2]=argv[1][8]; keyval[3]=argv[1][15];
    keyval[4] = argv[1][13]; keyval[5] = argv[1][12]; keyval[6] = argv[1][15]; keyval[7] = argv[1][14];
    keyval[8] = '\0';
    initvalb = strtoul(keyval,0,16);

    // set up initial conditions
    ShiftRegistera = initvala;		// assign initial starting number to a
    ShiftRegisterb = initvalb;		// assign initial starting number to b
    for (n=0; n<precount+109; n++) LFSRa();	// skip n+109 digits
    for (n=0; n<precount+416; n++) LFSRb();	// skip n+416 digits

    if ((ShiftRegistera == 0) || (ShiftRegisterb == 0)) {
	fprintf(stderr,"\nWarning: the key values MUST not be 0. Please run");
	fprintf(stderr,"\nagain with a different key value.\n");
	exit(0);
    }

  // show 500/entered value  0-9 values used for stream
  
  int pspace = 5;			// print space every 5
  while(total < maxgroups) {
    while (cnt < 25) {			// return n values
	numa = 0;
	numb = 0;
	num = 0;
    	for (n=15; n!=-1; n--) {	// get a 16 bit number
	    	vala = LFSRa(); 
	    	numa += pow(2,n) * vala; 
	}
	for (n=15; n!=-1; n--) {	// get a 2nd 16 bit number
		valb = LFSRb();
		numb += pow(2,n) * valb;
	}
	num = numa^numb;		// xor the 2 values
	if ((strcmp(basename(argv[0]),"cr3n"))==0) printf("%d",num%10);		// show a number from 0-9
	if ((strcmp(basename(argv[0]),"cr3l"))==0) printf("%c",(num%26)+'A');	// show a letter from A-Z
	if ((strcmp(basename(argv[0]),"cr3h"))==0) printf("%x",num%16);		// show hex digits 0-f
	pspace -=1;
	if (pspace==0) {
		printf(" ");
		pspace = 5;
	}
	cnt++;
    }
    printf("\n");
    total++;
    cnt = 0;
  }
    exit(0);  	// fin
}

