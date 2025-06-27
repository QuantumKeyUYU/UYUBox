/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors */
#include <Python.h>

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "crypto_core", NULL, -1, NULL};

PyMODINIT_FUNC PyInit_crypto_core(void) {
    return PyModule_Create(&module);
}
