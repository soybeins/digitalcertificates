#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <math.h>

#define MAX 5012
#define min 128
#define LENGTH 100 
//Made by Renzo P. Lebumfacil

long int prime1=71,prime2=79,n,t;
long int flag,privateKey[LENGTH],publicKey[LENGTH],e[LENGTH],d[LENGTH],temp[LENGTH],m[LENGTH],mess[LENGTH],en[LENGTH],i,j;
char dMess[LENGTH];

// ================ MD5 Algorithm Codes ================= //
typedef union uwb {
	unsigned w;
	unsigned char b[4];
} MD5union;

typedef unsigned DigestArray[4];

unsigned func0(unsigned abcd[]){
	return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}

unsigned func1(unsigned abcd[]){
	return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}

unsigned func2(unsigned abcd[]){
	return  abcd[1] ^ abcd[2] ^ abcd[3];
}

unsigned func3(unsigned abcd[]){
	return abcd[2] ^ (abcd[1] | ~abcd[3]);
}

typedef unsigned(*DgstFctn)(unsigned a[]);

unsigned *calctable(unsigned *k){
	double s, pwr;
	int i;

	pwr = pow(2.0, 32);
	for (i = 0; i<64; i++) {
		s = fabs(sin(1.0 + i));
		k[i] = (unsigned)(s * pwr);
	}
	return k;
}

unsigned rol(unsigned r, short N){
	unsigned  mask1 = (1 << N) - 1;
	return ((r >> (32 - N)) & mask1) | ((r << N) & ~mask1);
}

unsigned* Algorithms_Hash_MD5(char *msg, int mlen){
	static DigestArray h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
	static DgstFctn ff[] = { &func0, &func1, &func2, &func3 };
	static short M[] = { 1, 5, 3, 7 };
	static short O[] = { 0, 1, 5, 0 };
	static short rot0[] = { 7, 12, 17, 22 };
	static short rot1[] = { 5, 9, 14, 20 };
	static short rot2[] = { 4, 11, 16, 23 };
	static short rot3[] = { 6, 10, 15, 21 };
	static short *rots[] = { rot0, rot1, rot2, rot3 };
	static unsigned kspace[64];
	static unsigned *k;

	static DigestArray h;
	DigestArray abcd;
	DgstFctn fctn;
	short m, o, g;
	unsigned f;
	short *rotn;
	union {
		unsigned w[16];
		char     b[64];
	}mm;
	int os = 0;
	int grp, grps, q, p;
	unsigned char *msg2;

	if (k == NULL) k = calctable(kspace);

	for (q = 0; q<4; q++) h[q] = h0[q];

	{
		grps = 1 + (mlen + 8) / 64;
		msg2 = (unsigned char*)malloc(64 * grps);
		memcpy(msg2, msg, mlen);
		msg2[mlen] = (unsigned char)0x80;
		q = mlen + 1;
		while (q < 64 * grps) { msg2[q] = 0; q++; }
		{
			MD5union u;
			u.w = 8 * mlen;
			q -= 8;
			memcpy(msg2 + q, &u.w, 4);
		}
	}

	for (grp = 0; grp<grps; grp++)
	{
		memcpy(mm.b, msg2 + os, 64);
		for (q = 0; q<4; q++) abcd[q] = h[q];
		for (p = 0; p<4; p++) {
			fctn = ff[p];
			rotn = rots[p];
			m = M[p]; o = O[p];
			for (q = 0; q<16; q++) {
				g = (m*q + o) % 16;
				f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p] + mm.w[g], rotn[q % 4]);

				abcd[0] = abcd[3];
				abcd[3] = abcd[2];
				abcd[2] = abcd[1];
				abcd[1] = f;
			}
		}
		for (p = 0; p<4; p++)
			h[p] += abcd[p];
		os += 64;
	}
	return h;
}

char* GetMD5String(char *msg, int mlen){
	char* str=(char*)malloc(sizeof(char)*33);
	strcpy(str, "");
	int j, k;
	unsigned *d = Algorithms_Hash_MD5(msg, strlen(msg));
	MD5union u;
	for (j = 0; j<4; j++) {
		u.w = d[j];
		char s[8];
		sprintf(s, "%02x%02x%02x%02x", u.b[0], u.b[1], u.b[2], u.b[3]);
		strcat(str, s);
	}

	return str;
}
// ================ End of MD5 Algorithm Codes ================= //


// ================ Start of Public and Private Algorithm Codes =============== //
int isPrime(long int pr) {
 
	int i;
	j=sqrt(pr);
 
	for (i=2;i<=j;i++) {
		if( pr % i == 0)
		    return 0;
	}
 
	return 1;
}

long int cd(long int x) {
 
	long int k=1;
	while(1) {
		k=k+t;
		if(k%x==0)
		    return(k/x);
	}
}

void ce() {
 
	int k;
	k=0;
 
	for (i=2;i<t;i++) {
		if(t%i==0)
		    continue;
		flag=isPrime(i);
 
		if( flag==1 && i!=prime1 && i!=prime2 ) {
			e[k] = i;
			flag = cd(e[k]);
			if( flag > 0 ) {
				d[k] = flag;
				k++;
			}
			if( k == 99 )
			    break;
		}
	}
}
 
void encryption(int md5) {
 	FILE* fp;
	long int pt,ct,key=e[0],k,len;
	i=0;
	len=md5;
 
	while(i!=len) {
		pt=m[i];
		privateKey[i] = pt = pt-96;
		k=1;
		for (j=0;j<key;j++) {
			k=k*privateKey[i];
			k=k%n;
		}
		publicKey[i] = temp[i] = k;
		ct=k+96;
		en[i]=ct;
		i++;
	}
	fp = fopen("privateKey.txt","w");
	fwrite(privateKey,sizeof(int),LENGTH,fp);
	fclose(fp); 	
	
	fp = fopen("publicKey.txt","w");
	fwrite(publicKey,sizeof(int),LENGTH,fp);
	fclose(fp); 
	en[i]=-1;
	fp = fopen("cipherText.txt","w");
	fwrite(en,sizeof(int),LENGTH,fp);
	fclose(fp); 
	printf("\n==========================================");
	printf("\nPublic Key File Created Succesfully!");
	printf("\nPrivate Key File Created Succesfully!");
	printf("\nCipher Text File Created Succesfully!");
	printf("\n==========================================");
	//Print Encrypted Message
	printf("\nCipher Text: ");
 
	for (i=0;en[i]!=-1;i++){
		printf("%c",en[i]);	
	}
	printf("\n");

}
 
void decryption() {
 
	long int pt,ct,key=d[0],k;
	i=0;
 
	while(en[i]!=-1) {
		ct=publicKey[i];
		k=1;
		for (j=0;j<key;j++) {
			k=k*ct;
			k=k%n;
		}
		pt=k+96;
		mess[i]=pt;
		i++;
	} 
	mess[i]=-1;
	
	//Print Decrypted Message
//	printf("\nDecrypted Message is: ");
//	for (i=0;mess[i]!=-1;i++){
//		printf("%c",mess[i]);
//	}

}
// ================ End of Public and Private Algorithm Codes =============== //

void display(){
	printf("===== DIGITAL CERTIFICATE SIMULATOR v1.0 =====\n");	
	printf("=====|| Please choose an option ||=====\n");
	printf("=====|| a. Encrypt a file\n");
	printf("=====|| b. Decrypt a file\n");
	printf("=====|| Your Choice:");
}

void getFile(char content[MAX]){
	FILE* fp;	
	char filename[min],buffer[min];
	
	printf("Please enter filename:");
	scanf(" %s",&filename);
	strcat(filename,".txt");
	
	printf("Opening %s.....\n",filename);
	
	fp = fopen(filename,"r");
	
	if(fp!=NULL){
		while(!feof(fp)){
			fgets(buffer,MAX,fp);
			strcat(content,buffer);
		}		
	}else{
		printf("File does not exist!");
	}
	
	fclose(fp);
}

int main(void){
	FILE *fp;
	char content[MAX]="",choice,filename1[min],filename2[min];
	char* md5 = (char*)malloc(sizeof(char)*min);

	display();
	scanf("%c",&choice);

	//Formula for totient
	n=prime1*prime2;
	t=(prime1-1)*(prime2-1);
	ce();

	switch(choice){
		case 'a':
			printf("\n=====|| ENCRYPTION ||=======\n");
			getFile(content);
			printf("==========================================\n");
			printf("File Contents: ");
			puts(content);
			printf("Creating md5 Hash from txt file....\n");
			md5 = GetMD5String(content, strlen(content));
			printf("Your md5 hash:%s",md5);
			
			for ( i=0 ; md5[i]!='\0' ; i++ ){
				m[i]=md5[i];	
			}

			// Encryption
 			encryption(strlen(md5));
						
			break;
		case 'b':
			printf("\n=====|| DECRYPTION ||=======\n");
			printf("=====|| Please enter public key filename:");
			fflush(stdin);
			scanf("%s",&filename1);
			strcat(filename1,".txt");
		
			fp = fopen(filename1,"r");
			fread(publicKey,sizeof(int),LENGTH,fp);
			fclose(fp);
			
			printf("=====|| Please enter cipher text filename:");
			fflush(stdin);
			scanf("%s",&filename2);
			strcat(filename2,".txt");
			fp = fopen(filename2,"r");
			fread(en,sizeof(int),LENGTH,fp);
			fclose(fp);
			printf("=====|| For Data Integrity\n");
			getFile(content);
			md5 = GetMD5String(content, strlen(content));
			printf("Your md5 hash:%s",md5);
			
			//Decryption
			printf("\nPublic Key:");
		 	for(i=0;i<LENGTH;i++){		
				printf("%c",publicKey[i]);
			}
//			strcmp();
			decryption();
			
			printf("\n=====|| Hash Comparation ||=======\n");
			for (i=0;mess[i]!=-1;i++){
				dMess[i] = mess[i];
			}
			printf("\n=====||Original Signature of the Document:\t%s",dMess);
			printf("\n=====||Signature of your Document:\t\t%s\n",md5);
	
			if((strcmp(md5,dMess)) == 0 ){
				printf("\n-------REPORT SUMMARY-------\n");
				printf("File is AUTHENTIC!\n");
				printf("No tampering has occured.\n");
				printf("\nFile Contents: ");
				puts(content);	
				printf("----------------------------\n");
			}else{
				printf("\n-------REPORT SUMMARY-------\n");
				printf("WARNING!!! File has been tampered!");
				printf("\nThe hashes are not similar!\n");
				printf("----------------------------\n");
			}
			
			break;
		default:
			exit(1);
			break;
	}
		
	printf(".\n.\n..\n...\nProgram Success..\nPress any key to continue...");
	getch();

	return 0;
}




