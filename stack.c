/*
   This product is distributed under 2-term BSD-license terms

   Copyright (c) 2023, QApp. All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met: 

   1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
