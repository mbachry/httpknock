#include <Python.h>
#include <stdio.h>

int nft_run_cmd_from_buffer(__attribute__((unused)) void *nft, __attribute__((unused)) const char *command)
{
    Py_Initialize();

    PyObject *module = PyImport_ImportModule("testlib");
    if (!module) {
        fprintf(stderr, "failed to import testlib\n");
        return -1;
    }
    PyObject *module_dict = PyModule_GetDict(module);
    assert(module_dict != NULL);

    PyObject *func_obj = PyDict_GetItemString(module_dict, "mock_nft_call");
    if (!func_obj) {
        fprintf(stderr, "lookup failed: testlib.mock_nft_call\n");
        goto err;
    }

    int retval = 0;

    PyObject *res = PyObject_CallObject(func_obj, NULL);
    if (!res) {
        fprintf(stderr, "call failed: testlib.mock_nft_call\n");
        PyErr_Print();
        goto err;
    }
    if (res != Py_None)
        retval = -1;
    Py_DecRef(res);

    return retval;

err:
    Py_DecRef(module);
    return -1;
}

const char *nft_ctx_get_output_buffer(__attribute__((unused)) void *nft)
{
    return "{\"nftables\":[{\"insert\":{\"rule\":{\"handle\":1}}}]}";
}
