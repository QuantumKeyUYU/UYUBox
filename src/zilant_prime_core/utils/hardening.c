/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors */
#include <Python.h>

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "hardening", NULL, -1, NULL};

PyMODINIT_FUNC PyInit_hardening(void) {
    return PyModule_Create(&module);
}
