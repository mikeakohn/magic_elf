#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <jni.h>

JNIEXPORT void JNICALL Java_Crash_forceSegfault(JNIEnv *env, jobject obj)
{
  char *s = NULL;

  printf("Testing a core file from a Java crash to be analyzed with magic_elf.\n");
  fflush(stdout);

  *s = 'A';
}

