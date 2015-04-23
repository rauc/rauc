#include <stdio.h>
#include <glib.h>

int main(int argc, char** argv) {
     GList* list = NULL;
     list = g_list_append(list, g_strdup("Hello world!"));
     printf("The first item is '%s'\n", (gchar *)g_list_first(list)->data);
     return 0;
}

