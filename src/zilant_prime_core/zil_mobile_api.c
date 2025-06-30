/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <Python.h>

int zil_unpack_dir(const char *in, const char *out, const uint8_t *key32) {
    if (!Py_IsInitialized()) {
        Py_Initialize();
    }
    PyObject *module = PyImport_ImportModule("zilant_prime_core.zilfs");
    if (!module) return -1;
    PyObject *func = PyObject_GetAttrString(module, "unpack_dir");
    if (!func) {
        Py_DECREF(module);
        return -1;
    }
    PyObject *pyin = PyUnicode_FromString(in);
    PyObject *pyout = PyUnicode_FromString(out);
    PyObject *pykey = PyBytes_FromStringAndSize((const char *)key32, 32);
    PyObject *args = PyTuple_Pack(3, pyin, pyout, pykey);
    PyObject *res = PyObject_CallObject(func, args);
    int ret = res ? 0 : -1;
    Py_XDECREF(res);
    Py_DECREF(args);
    Py_DECREF(pykey);
    Py_DECREF(pyout);
    Py_DECREF(pyin);
    Py_DECREF(func);
    Py_DECREF(module);
    return ret;
}

static struct PyModuleDef zil_mobile_api_module = {
    PyModuleDef_HEAD_INIT,
    "zil_mobile_api",
    NULL,
    -1,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_zil_mobile_api(void)
{
    return PyModule_Create(&zil_mobile_api_module);
}
