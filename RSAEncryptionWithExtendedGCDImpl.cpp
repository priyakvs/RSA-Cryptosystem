#include<iostream>
#include<stdio.h>
#include<cstdlib>
#include <ctime>
#include <math.h>
#include <vector>
using namespace std;

//Declaration
unsigned long long int p, q, totient, public_key, private_key,bearcat_msg, encrypted_code, decrypted_code;

//GCD
int gcdFactor(unsigned long long int a, unsigned long long int b)
{
unsigned long long int r;
int gcd;
while (b!=0)
{
r = a % b;
a = b;
b = r;
}
gcd = a;
return gcd;
}

//Power function
unsigned long long int getPower(unsigned long long int n, unsigned long long int p,unsigned long long int m )
{
unsigned long long int v=n%m;
for(unsigned long long int i=2;i<=p;i++)
v=(v*n)%m;
return v;
}

//Miller Rabin Primality Test
bool millerRabinTest(int x, int y)
{
int a,b;
a = 2+rand()%(y-2);
unsigned long long int v=a%y;
b = getPower(a,x,y);
if (b!=1 && b!=y-1)
return false;
else if (b == y-1)
return true;
b = (b*b)%y;
if (b!=1)
return false;
else
return true;
return false;
}

//Prime Check
bool isPrime(int n, int k)
{
int m = n - 1;
while (m % 2 == 0)
m/=2;
for (int i=0; i<k;i++)
if (!millerRabinTest(m,n))
return false;
return true;
}

int extendedGCD(int a, int b, int *r, int *s)
{
    
    if (a == 0)
    {
        *r = 0, *s = 1;
        return b;
    }
 
    int r1, s1; 
    int gcd = extendedGCD(b%a, a, &r1, &s1);
 
    *r = s1 - (b/a) * r1;
    *s = r1;
    return gcd;
}

int genratePrivateKey(int a, int m)
{
    int x, y;
    int g = extendedGCD(a, m, &x, &y);
    if (g == 1) {
        // m is added to handle negative x
        int res = (x%m + m) % m;
        // cout << "Modular multiplicative inverse is " << res;
        return res;
    }
}

//BEARCATII Conversion table
 int BEARCATII_Encode(string msg)
{
int c, conversion =0, base = 0, bearcat_msg[msg.size()];
for(int i=0;i<msg.size();i++)
{
c=msg[i];
if(c>96)
bearcat_msg[i]=c-96;
else if(c==32)
bearcat_msg[i]=0;
}

//Base 27 conversion.
int s = msg.size()-1;
for(int i=s;i>=0;i--)
{
base = bearcat_msg[i]*pow(27,s-i);
conversion = conversion + base;
}
return conversion;
}

//RSA Implementation
void RSA_Implementation()
{
unsigned long long int n = p*q;
encrypted_code= getPower(bearcat_msg,public_key,n) ;
decrypted_code= getPower(encrypted_code,private_key,n);

cout<<"RSA Encrypted Code : "<<encrypted_code << endl;
cout<<"RSA Decrytped Code : "<<decrypted_code;

}

//Decrypted code to Original Text
string BEARCATII_Decode(unsigned long long int decryptedCode)
{
vector<int> decodedMessageInInt;
string decryptedMessage;
while(decryptedCode>0)
{
int temp=decryptedCode%27;

decodedMessageInInt.push_back(temp);
decryptedCode /=27;
}

for (int i = decodedMessageInInt.size()-1; i >=0 ; i--)
{
if(decodedMessageInInt.at(i)==0)
decryptedMessage.push_back(' ');
else
{
char temp=(char)(decodedMessageInInt.at(i)+96);
decryptedMessage.push_back(temp);
}
}
cout<<endl<<"\nThe decrypted message is \'"<<decryptedMessage<<"\'";
return decryptedMessage;

}

int main()
{
int k =4, gcd;
string message=" ";
unsigned long long int r;
bool ispPrime = false, isqPrime = false;
srand (time(NULL));

// Genearting p & q of RSA Algorithm
while( !ispPrime ){
   p = rand() % 30 + 1985;
   if( p == 1)
continue;
   ispPrime = isPrime(p,k);
}

while( !isqPrime ){
   q = rand() % 30 + 1985;
   if( q == 1 || q == p)
continue;
   isqPrime = isPrime(q,k);
}

cout<< "Prime number (p) : " << p << endl;
cout<< "Prime number (q) : " << q << endl;
cout<< "First part of public key (n) : " << p*q << endl;

totient = (p-1) * (q-1);
cout<<"Totient value : " << totient <<endl;
cout<< "Enter exponent value in the range 1 < e < totient(n)" <<endl;
cin >> public_key;


gcd = gcdFactor(totient,public_key);
while(gcd != 1)
{
cout<<"Exponent value is a factor of 'n'. Enter a exponent value in the range 1 < e < totient(n)"<<endl;
cin>>public_key;
gcd = gcdFactor(totient,public_key);
}
cout<< "Public key : " << p*q << "\t" << public_key <<endl;

private_key = genratePrivateKey(public_key,totient);

cout<< "Private key : " << private_key << endl;

cin.ignore();
cout <<endl<<"Enter the message for RSA";
getline(cin,message);

bearcat_msg = BEARCATII_Encode(message);
cout<<endl << "BearcatII conversion : "<<bearcat_msg<<endl;

RSA_Implementation();
BEARCATII_Decode(decrypted_code);

return 0;

}
