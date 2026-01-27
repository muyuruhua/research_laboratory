/*
 * afl-plugin-loader.h - Dynamic plugin loading interface for AFL
 */

#ifndef _AFL_PLUGIN_LOADER_H
#define _AFL_PLUGIN_LOADER_H

#include "afl-plugin-api.h"
#include <stdbool.h>

/* Load a plugin from .so file */
int afl_load_plugin(const char* plugin_path);

/* Unload all loaded plugins */
void afl_unload_all_plugins(void);

/* Invoke a hook on all registered plugins */
afl_plugin_decision_t afl_invoke_hook(afl_hook_type_t hook_type, afl_hook_data_t* hook_data);

/* Check if any plugins are loaded */
bool afl_plugins_enabled(void);

/* Get number of loaded plugins */
uint32_t afl_get_plugin_count(void);

#endif /* _AFL_PLUGIN_LOADER_H */
