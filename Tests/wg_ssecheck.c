#include <windows.h>
#include <emmintrin.h>
static void outnum(const char*l,unsigned v){
  char b[64]; int i=0; while(l[i]){b[i]=l[i];i++;}
  static const char hx[]="0123456789ABCDEF";
  b[i++]='0';b[i++]='x';
  for(int s=28;s>=0;s-=4) b[i++]=hx[(v>>s)&0xF];
  b[i++]='\n'; b[i]=0; OutputDebugStringA(b);
}
int main(void){
  char a[16]="P-521:P-384:P-25";
  char d[16]="P-521:P-384:P-25";   /* identical */
  char c[16]="P-X21:P-384:P-25";   /* differs at index 2 */
  __m128i va=_mm_loadu_si128((const __m128i*)a);
  __m128i vd=_mm_loadu_si128((const __m128i*)d);
  __m128i vc=_mm_loadu_si128((const __m128i*)c);
  outnum("eq_mask=", (unsigned)_mm_movemask_epi8(_mm_cmpeq_epi8(va,vd))); /* expect 0xFFFF */
  outnum("ne_mask=", (unsigned)_mm_movemask_epi8(_mm_cmpeq_epi8(va,vc))); /* expect 0xFFFB */
  /* find ':' (0x3a) like strchr-SSE would: broadcast and compare */
  __m128i colon=_mm_set1_epi8(0x3a);
  outnum("colon_mask=", (unsigned)_mm_movemask_epi8(_mm_cmpeq_epi8(va,colon))); /* ':' at idx5 -> bit5=0x20 */
  return 0;
}
