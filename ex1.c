//
// Simple inline assembly example
//
// For JOS lab 1 exercise 1
//

#include <stdio.h>

int
main(int argc, char **argv)
{
  int x = 1;
  printf("Hello x = %d\n", x);

  //
  // Put in-line assembly here to increment
  // the value of x by 1 using in-line assembly
  //
  
  // Move 1 to eax, and increment it
  // Move eax to output (by anke)
  __asm __volatile("movl %1, %%eax\n\t"
      "incl %%eax\n\t"
      "movl %%eax, %0"
      :"=r"(x)
      :"r"(x)
      :"%eax"
      );
 
  // We have found the position where the variable x is located 
  // by looking at main() assembly code. (by hykoo)
  // Using rbp register, we updated the value of the variable x
  //
  // So we can simply change the value as following:
  // asm("movl $0x2,-0x4(%rbp)");

  printf("Hello x = %d after increment\n", x);

  if(x == 2){
    printf("OK\n");
  }
  else{
    printf("ERROR\n");
  }
  return 1;
}
