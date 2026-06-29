#include <windows.h>
#include <string.h>
static void out(const char*s){ OutputDebugStringA(s); }
static void outnum(const char*label,int v){
  char b[64]; int i=0; while(label[i]){b[i]=label[i];i++;}
  char t[16]; int n=0; int neg=v<0; if(neg)v=-v;
  if(v==0)t[n++]='0'; while(v){t[n++]=(char)('0'+v%10); v/=10;}
  if(neg)b[i++]='-'; while(n)b[i++]=t[--n]; b[i++]='\n'; b[i]=0; out(b);
}
int main(void){
  const char* s="P-521:P-384:P-256";
  int hl=0; while(s[hl]) hl++;                 /* hand strlen */
  int cl=(int)strlen(s);                       /* CRT strlen  */
  int n1=0; const char*p=s; for(;;){const char*c=p; while(*c&&*c!=':')c++; n1++; if(!*c)break; p=c+1;}
  int n2=0; p=s; for(;;){const char*c=strchr(p,':'); n2++; if(!c)break; p=c+1;}
  outnum("HANDLEN=",hl); outnum("CRTLEN=",cl);
  outnum("HANDN=",n1);   outnum("CRTN=",n2);
  return 0;
}
