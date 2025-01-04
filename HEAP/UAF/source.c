#include <stdio.h>
#include <stdlib.h>

void use_after_free_demo() {

    // Allocating memory for 10 bytes and assigning the address to pointer variable 'ptr' of type char*

    char *ptr = (char *)malloc(10 * sizeof(char));  // Allocate memory
    if (ptr == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    // Assign some data to the allocated memory
    for (int i = 0; i < 9; i++) {
        ptr[i] = 'A' + i;  // Fill with letters
    }
    ptr[9] = '\0'; // Null terminate

    printf("Before free: %s\n", ptr);

    free(ptr);  // Free the allocated memory
    printf("Memory freed.\n");

    // Access memory after it has been freed
    printf("After free: %s\n", ptr);

    // After freeing memory, the pointer still holds the address of the freed memory but no longer valid
    // or accessible

    // Dangling pointer can be reassigned, leading to undefined behavior
    char *new_ptr = (char *)malloc(10 * sizeof(char));
    for (int i = 0; i < 10; i++) {
        new_ptr[i] = 'Z';  // Fill with Zs
    }

    // Lepas create 'new_ptr' pointer and assigning some characters, the dangling pointer is showing the contents 
    // of new_ptr (UAF vuln)

    printf("New allocation: %s\n", new_ptr);
    printf("Dangling pointer access: %s\n", ptr); // Use after free
}

int main() {
    use_after_free_demo();
    return 0;
}
