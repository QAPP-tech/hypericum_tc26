#pragma once

// Opaque type to represent a stack
typedef struct stack_node_t stack_root_t;

int stack_is_empty(stack_root_t* root);
void stack_push(stack_root_t** root, void* data);
void* stack_pop(stack_root_t** root);
void* stack_peek(stack_root_t* root);
