#include<stdio.h>
#include<shlwapi.h>

void main(){
  char* path = malloc(MAX_PATH);
  memset(path, 0, MAX_PATH);
  GetModuleFileName(0, path, MAX_PATH);
  PathRemoveFileSpec(path);

  printf("PATH %s\n",path);
}


