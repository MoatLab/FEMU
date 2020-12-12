#include<stdio.h>
#include<stdlib.h>
#include<glib-object.h>
#include"marshaller.h"

static int singleton = 42;

void foo(gpointer user_data, gpointer data) {
    if (user_data != &singleton) {
        fprintf(stderr, "Invoked foo function was passed incorrect user data.\n");
        exit(1);
    }
}

void bar(gpointer user_data, gint param1, gpointer data) {
    if (param1 != singleton) {
        fprintf(stderr, "Invoked bar function was passed incorrect param1, but %d.\n", param1);
        exit(2);
    }
    if (user_data != &singleton) {
        fprintf(stderr, "Invoked bar function was passed incorrect user data.\n");
        exit(3);
    }
}

gfloat baz(gpointer user_data, gboolean param1, guchar param2, gpointer data) {
    if (param1 != TRUE) {
        fprintf(stderr, "Invoked baz function was passed incorrect param1.\n");
        exit(4);
    }
    if (param2 != singleton) {
        fprintf(stderr, "Invoked baz function was passed incorrect param2.\n");
        exit(5);
    }
    if (user_data != &singleton) {
        fprintf(stderr, "Invoked baz function was passed incorrect user data.\n");
        exit(6);
    }
    return (gfloat)param2;
}

int main(int argc, char **argv) {
    GClosure *cc_foo, *cc_bar, *cc_baz;
    GValue return_value = G_VALUE_INIT;
    GValue param_values[3] = {G_VALUE_INIT, G_VALUE_INIT, G_VALUE_INIT};

    fprintf(stderr, "Invoking foo function.\n");
    cc_foo = g_cclosure_new(G_CALLBACK(foo), NULL, NULL);
    g_closure_set_marshal(cc_foo, g_cclosure_user_marshal_VOID__VOID);
    g_value_init(&param_values[0], G_TYPE_POINTER);
    g_value_set_pointer(&param_values[0], &singleton);
    g_closure_invoke(cc_foo, &return_value, 1, param_values, NULL);
    if (G_VALUE_TYPE(&return_value) != G_TYPE_INVALID) {
        fprintf(stderr, "Invoked foo function did not return empty value, but %s.\n",
                G_VALUE_TYPE_NAME(&return_value));
        return 7;
    }
    g_value_unset(&param_values[0]);
    g_value_unset(&return_value);
    g_closure_unref(cc_foo);

    fprintf(stderr, "Invoking bar function.\n");
    cc_bar = g_cclosure_new(G_CALLBACK(bar), NULL, NULL);
    g_closure_set_marshal(cc_bar, g_cclosure_user_marshal_VOID__INT);
    g_value_init(&param_values[0], G_TYPE_POINTER);
    g_value_set_pointer(&param_values[0], &singleton);
    g_value_init(&param_values[1], G_TYPE_INT);
    g_value_set_int(&param_values[1], 42);
    g_closure_invoke(cc_bar, &return_value, 2, param_values, NULL);
    if (G_VALUE_TYPE(&return_value) != G_TYPE_INVALID) {
        fprintf(stderr, "Invoked bar function did not return empty value.\n");
        return 8;
    }
    g_value_unset(&param_values[0]);
    g_value_unset(&param_values[1]);
    g_value_unset(&return_value);
    g_closure_unref(cc_bar);

    fprintf(stderr, "Invoking baz function.\n");
    cc_baz = g_cclosure_new(G_CALLBACK(baz), NULL, NULL);
    g_closure_set_marshal(cc_baz, g_cclosure_user_marshal_FLOAT__BOOLEAN_UCHAR);
    g_value_init(&param_values[0], G_TYPE_POINTER);
    g_value_set_pointer(&param_values[0], &singleton);
    g_value_init(&param_values[1], G_TYPE_BOOLEAN);
    g_value_set_boolean(&param_values[1], TRUE);
    g_value_init(&param_values[2], G_TYPE_UCHAR);
    g_value_set_uchar(&param_values[2], 42);
    g_value_init(&return_value, G_TYPE_FLOAT);
    g_closure_invoke(cc_baz, &return_value, 3, param_values, NULL);
    if (g_value_get_float(&return_value) != 42.0f) {
        fprintf(stderr, "Invoked baz function did not return expected value.\n");
        return 9;
    }
    g_value_unset(&param_values[0]);
    g_value_unset(&param_values[1]);
    g_value_unset(&param_values[2]);
    g_value_unset(&return_value);
    g_closure_unref(cc_baz);

    fprintf(stderr, "All ok.\n");
    return 0;
}
