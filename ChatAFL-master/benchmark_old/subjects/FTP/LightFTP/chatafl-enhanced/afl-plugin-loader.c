/*
 * afl-plugin-loader.c - Dynamic plugin loading implementation for AFL
 * 
 * This module handles runtime loading of .so plugins without modifying
 * the core afl-fuzz.c code. Implements 100% OCP-compliant plugin system.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "afl-plugin-api.h"
#include "types.h"
#include "debug.h"

/* Maximum number of plugins that can be loaded */
#define MAX_PLUGINS 16

/* Plugin handle structure */
typedef struct {
  void* dl_handle;                      /* dlopen handle */
  void* plugin_context;                 /* Plugin-specific context */
  afl_plugin_info_t info;               /* Plugin metadata (local copy) */
  afl_plugin_init_fn_t init_fn;         /* init function pointer */
  afl_plugin_get_info_fn_t get_info_fn; /* get_info function pointer */
  afl_plugin_invoke_hook_fn_t hook_fn;  /* hook invocation function pointer */
  bool initialized;                     /* Whether init was successful */
} plugin_handle_t;

/* Global plugin registry */
static plugin_handle_t g_plugins[MAX_PLUGINS];
static uint32_t g_plugin_count = 0;
static bool g_plugins_enabled = false;

/*******************************************
 * Plugin Loader Implementation            *
 *******************************************/

/*
 * Load a single plugin from .so file
 * Returns: 0 on success, -1 on error
 */
int afl_load_plugin(const char* plugin_path) {
  
  if (g_plugin_count >= MAX_PLUGINS) {
    WARNF("Cannot load plugin: maximum %d plugins already loaded", MAX_PLUGINS);
    return -1;
  }

  if (!plugin_path || strlen(plugin_path) == 0) {
    WARNF("Invalid plugin path");
    return -1;
  }

  plugin_handle_t* plugin = &g_plugins[g_plugin_count];
  memset(plugin, 0, sizeof(plugin_handle_t));

  /* Open the shared library */
  plugin->dl_handle = dlopen(plugin_path, RTLD_LAZY | RTLD_LOCAL);
  if (!plugin->dl_handle) {
    WARNF("Failed to load plugin '%s': %s", plugin_path, dlerror());
    return -1;
  }

  /* Clear any existing error */
  dlerror();

  /* Resolve required symbols */
  plugin->init_fn = (afl_plugin_init_fn_t)dlsym(plugin->dl_handle, "afl_plugin_init");
  plugin->get_info_fn = (afl_plugin_get_info_fn_t)dlsym(plugin->dl_handle, "afl_plugin_get_info");
  plugin->hook_fn = (afl_plugin_invoke_hook_fn_t)dlsym(plugin->dl_handle, "afl_plugin_invoke_hook");

  const char* dl_error = dlerror();
  if (dl_error || !plugin->init_fn || !plugin->get_info_fn || !plugin->hook_fn) {
    WARNF("Plugin '%s' missing required symbols: %s", plugin_path, dl_error ? dl_error : "unknown");
    dlclose(plugin->dl_handle);
    return -1;
  }

  /* Get plugin metadata */
  const afl_plugin_info_t* info = plugin->get_info_fn();
  if (!info) {
    WARNF("Plugin '%s' returned NULL info", plugin_path);
    dlclose(plugin->dl_handle);
    return -1;
  }

  /* Verify API version compatibility */
  if (info->api_version != AFL_PLUGIN_API_VERSION) {
    WARNF("Plugin '%s' API version mismatch: expected %d, got %d",
          plugin_path, AFL_PLUGIN_API_VERSION, info->api_version);
    dlclose(plugin->dl_handle);
    return -1;
  }

  /* Copy plugin info to local storage */
  memcpy(&plugin->info, info, sizeof(afl_plugin_info_t));

  /* Initialize the plugin */
  if (plugin->init_fn(&plugin->plugin_context) != 0) {
    WARNF("Plugin '%s' initialization failed", plugin_path);
    dlclose(plugin->dl_handle);
    return -1;
  }

  plugin->initialized = true;
  g_plugin_count++;
  g_plugins_enabled = true;

  ACTF("Loaded plugin: %s v%s (%s)", 
       plugin->info.name, 
       plugin->info.version,
       plugin->info.description);

  return 0;
}

/*
 * Unload all loaded plugins
 */
void afl_unload_all_plugins(void) {
  
  for (uint32_t i = 0; i < g_plugin_count; i++) {
    plugin_handle_t* plugin = &g_plugins[i];
    
    if (plugin->initialized && plugin->dl_handle) {
      /* Invoke cleanup hook before unloading */
      if (AFL_HOOK_SUBSCRIBED(plugin->info.hook_mask, AFL_HOOK_CLEANUP)) {
        afl_hook_data_t hook_data = {0};
        plugin->hook_fn(AFL_HOOK_CLEANUP, &hook_data, plugin->plugin_context);
      }
      
      dlclose(plugin->dl_handle);
    }
  }

  g_plugin_count = 0;
  g_plugins_enabled = false;
}

/*
 * Invoke a hook on all registered plugins
 * Returns: Collective decision from all plugins
 */
afl_plugin_decision_t afl_invoke_hook(afl_hook_type_t hook_type, afl_hook_data_t* hook_data) {
  
  if (!g_plugins_enabled || hook_type >= AFL_HOOK_MAX) {
    return AFL_DECISION_CONTINUE;
  }

  afl_plugin_decision_t collective_decision = AFL_DECISION_CONTINUE;

  /* Sort plugins by priority (if needed) - for now, invoke in load order */
  for (uint32_t i = 0; i < g_plugin_count; i++) {
    plugin_handle_t* plugin = &g_plugins[i];
    
    if (!plugin->initialized) continue;
    
    /* Check if plugin subscribes to this hook */
    if (!AFL_HOOK_SUBSCRIBED(plugin->info.hook_mask, hook_type)) {
      continue;
    }

    /* Invoke the hook */
    afl_plugin_decision_t decision = plugin->hook_fn(hook_type, hook_data, plugin->plugin_context);

    /* Aggregate decisions (STOP > SKIP > CONTINUE) */
    if (decision == AFL_DECISION_STOP) {
      return AFL_DECISION_STOP;  /* Immediately stop if any plugin says so */
    }
    if (decision == AFL_DECISION_SKIP && collective_decision == AFL_DECISION_CONTINUE) {
      collective_decision = AFL_DECISION_SKIP;
    }
  }

  return collective_decision;
}

/*
 * Check if any plugins are loaded
 */
bool afl_plugins_enabled(void) {
  return g_plugins_enabled;
}

/*
 * Get number of loaded plugins
 */
uint32_t afl_get_plugin_count(void) {
  return g_plugin_count;
}
