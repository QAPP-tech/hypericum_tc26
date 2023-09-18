#include "stack.h"

#include <stdint.h>
#include <stdlib.h>


// A structure to represent a stack
struct stack_node_t
{
    void* data;
    struct stack_node_t* next;
};

struct stack_node_t* stack_create_node(void* data)
{
    struct stack_node_t* node =
        (struct stack_node_t*)calloc(1, sizeof(struct stack_node_t));
    node->data = data;
    node->next = NULL;
    return node;
}


int stack_is_empty(struct stack_node_t* root)
{
    return !root;
}


void stack_push(struct stack_node_t** root, void* data)
{
    struct stack_node_t* stack_node_t = stack_create_node(data);
    stack_node_t->next = *root;
    *root = stack_node_t;
}


void* stack_pop(struct stack_node_t** root)
{
    if (stack_is_empty(*root)) {
        return NULL;
    }
    struct stack_node_t* temp = *root;
    *root = (*root)->next;
    void* popped = temp->data;
    free(temp);

    return popped;
}


void* stack_peek(struct stack_node_t* root)
{
    if (stack_is_empty(root)) {
        return NULL;
    }
    return root->data;
}
